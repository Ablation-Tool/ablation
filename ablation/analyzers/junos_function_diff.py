"""Bounded, cacheable comparison of explicitly selected MIPS functions."""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import time
from pathlib import Path

from .insn_mips import Imm, Insn, Mem, Reg
from .isa_mips import BRANCH_COND, CALL_DIRECT, COMPACT_CALL, COMPACT_COND, COMPACT_JUMP, JUMP
from .mips_function import MipsFunction, load_mips_function


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_mips_instruction(insn: Insn, function: MipsFunction) -> str:
    control = insn.mnemonic in BRANCH_COND | CALL_DIRECT | COMPACT_CALL | COMPACT_COND | COMPACT_JUMP | JUMP
    operands = []
    for operand in insn.ops:
        if isinstance(operand, Imm):
            value = operand.value
            if control and function.va <= value < function.va + function.size:
                operands.append(f"local{value - function.va:+#x}")
            elif insn.mnemonic in CALL_DIRECT | COMPACT_CALL:
                operands.append("<external>")
            else:
                operands.append("<imm>")
        elif isinstance(operand, Mem):
            index = f"{operand.index}+" if operand.index else ""
            operands.append(f"<imm>({index}{operand.base})")
        elif isinstance(operand, Reg):
            operands.append(operand.name)
        else:
            operands.append("<symbol>")
    return f"{insn.mnemonic} {','.join(operands)}".strip()


def _side(function: MipsFunction, digest: str) -> dict[str, object]:
    instructions = [normalize_mips_instruction(insn, function) for insn in function.instructions]
    callees = sorted({
        function.symbols.get(insn.imm(-1), hex(insn.imm(-1)))
        for insn in function.instructions
        if insn.mnemonic in CALL_DIRECT | COMPACT_CALL and insn.imm(-1) is not None
    })
    return {
        "path": str(function.path),
        "sha256": digest,
        "name": function.name,
        "va": hex(function.va),
        "size": function.size,
        "instruction_count": len(instructions),
        "signature": hashlib.sha256("\n".join(instructions).encode()).hexdigest(),
        "callees": callees,
        "instructions": instructions,
    }


def compare_functions(
    old: str | Path,
    new: str | Path,
    old_va: int,
    new_va: int,
    old_size: int | None = None,
    new_size: int | None = None,
    max_size: int = 16384,
    timeout: float | None = None,
) -> dict[str, object]:
    started = time.monotonic()
    before = load_mips_function(old, old_va, old_size, max_size)
    if timeout is not None and time.monotonic() - started > timeout:
        raise TimeoutError("Function diff timed out while loading the old function")
    after = load_mips_function(new, new_va, new_size, max_size)
    if timeout is not None and time.monotonic() - started > timeout:
        raise TimeoutError("Function diff timed out while loading the new function")
    old_side = _side(before, file_sha256(old))
    new_side = _side(after, file_sha256(new))
    matcher = difflib.SequenceMatcher(a=old_side["instructions"], b=new_side["instructions"], autojunk=False)
    changes = []
    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        changes.append({
            "kind": tag,
            "old_range": [old_start, old_end],
            "new_range": [new_start, new_end],
            "old": old_side["instructions"][old_start:old_end],
            "new": new_side["instructions"][new_start:new_end],
        })
    equivalent = not changes
    return {
        "schema_version": 1,
        "analysis": "normalized-mips-function-diff",
        "equivalent": equivalent,
        "summary": {
            "old_instructions": len(old_side["instructions"]),
            "new_instructions": len(new_side["instructions"]),
            "matching_instructions": sum(
                old_end - old_start
                for tag, old_start, old_end, _, _ in matcher.get_opcodes()
                if tag == "equal"
            ),
            "change_blocks": len(changes),
        },
        "old": old_side,
        "new": new_side,
        "changes": changes,
        "caveat": "Normalized instruction equality is evidence of similarity, not a proof of semantic equivalence.",
        "elapsed_seconds": round(time.monotonic() - started, 6),
    }


def comparison_cache_key(
    old: str | Path,
    new: str | Path,
    old_va: int,
    new_va: int,
    old_size: int | None,
    new_size: int | None,
) -> str:
    material = {
        "version": 1,
        "old": [file_sha256(old), old_va, old_size],
        "new": [file_sha256(new), new_va, new_size],
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def write_json_atomic(path: str | Path, report: dict[str, object]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(destination)
