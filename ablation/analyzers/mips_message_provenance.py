"""Bounded direct-call discovery and basic-block argument provenance for MIPS."""
from __future__ import annotations

import re
from pathlib import Path

from elftools.elf.elffile import ELFFile

from .insn_mips import Insn
from .isa_mips import Abi, BRANCH_COND, CALL_DIRECT, CALL_INDIRECT, COMPACT_CALL, COMPACT_COND, COMPACT_JUMP, JUMP, abi_for, canon_reg, pretty
from .mips_function import MipsFunction, load_mips_function, mips_symbols


_CONTROL = BRANCH_COND | COMPACT_COND | COMPACT_JUMP | JUMP
_CALLS = CALL_DIRECT | CALL_INDIRECT | COMPACT_CALL
_LOADS = {"lb", "lbu", "lh", "lhu", "lw", "ld", "lwu"}
_STORES = {"sb", "sh", "sw", "sd"}
_BINARY = {
    "addu": "+", "addiu": "+", "daddu": "+", "daddiu": "+",
    "subu": "-", "dsubu": "-", "and": "&", "andi": "&",
    "or": "|", "ori": "|", "xor": "^", "xori": "^",
    "sll": "<<", "srl": ">>", "sra": ">>", "dsll": "<<", "dsrl": ">>",
}


def _operand(insn: Insn, index: int) -> str | None:
    if insn.reg(index) is not None:
        return insn.reg(index)
    if insn.imm(index) is not None:
        return hex(insn.imm(index))
    return None


def _replace(expression: str, register: str, value: str) -> str:
    replacement = value if re.fullmatch(r"(?:\$\d+|[\w-]+)", value) else f"({value})"
    return re.sub(rf"{re.escape(register)}(?![\w])", replacement, expression)


def _display(expression: str) -> str:
    expression = re.sub(r"\$(\d+)\b", lambda match: pretty(match.group(0), Abi.O32), expression)
    while expression.startswith("(") and expression.endswith(")"):
        depth = 0
        wrapped = True
        for index, character in enumerate(expression):
            depth += character == "("
            depth -= character == ")"
            if depth == 0 and index != len(expression) - 1:
                wrapped = False
                break
        if not wrapped:
            break
        expression = expression[1:-1]
    return expression


def _used(expressions: dict[str, str], register: str | None) -> bool:
    return register is not None and any(re.search(rf"{re.escape(register)}(?![\w])", value) for value in expressions.values())


def slice_call_arguments(
    function: MipsFunction,
    call_va: int,
    arguments: tuple[str, ...] = ("$4", "$5", "$6"),
    max_instructions: int = 64,
) -> dict[str, object]:
    if max_instructions < 1 or max_instructions > 4096:
        raise ValueError("Slice instruction budget must be between 1 and 4096")
    registers = tuple(canon_reg(item, Abi.O32) for item in arguments)
    if any(item is None for item in registers) or len(set(registers)) != len(registers):
        raise ValueError("Arguments must be distinct MIPS register names")
    call_index = next((index for index, insn in enumerate(function.instructions) if insn.address == call_va), None)
    if call_index is None or function.instructions[call_index].mnemonic not in _CALLS:
        raise ValueError(f"No call instruction at {call_va:#x} in {function.name}")
    expressions = {register: register for register in registers}
    events = []
    boundary = {"kind": "function_entry", "address": hex(function.va)}
    start = max(0, call_index - max_instructions)
    stop = call_index + 1
    if stop < len(function.instructions) and function.instructions[stop].address == call_va + 4:
        stop += 1
    for index in range(stop - 1, start - 1, -1):
        insn = function.instructions[index]
        if index != call_index and insn.mnemonic in _CONTROL:
            boundary = {"kind": "control_flow", "address": hex(insn.address), "instruction": str(insn)}
            break
        before = expressions.copy()
        if index != call_index and insn.mnemonic in _CALLS:
            for register in abi_for(Abi.O32).caller_saved:
                if _used(expressions, register):
                    expressions = {key: _replace(value, register, f"unknown-after-{insn.address:#x}") for key, value in expressions.items()}
        elif insn.mnemonic in _LOADS and _used(expressions, insn.reg(0)):
            memory = insn.mem(1)
            if memory is None or memory.index:
                replacement = f"unknown-load-{insn.address:#x}"
            else:
                base = memory.base
                location = f"{base}{memory.disp:+#x}"
                replacement = f"{insn.mnemonic}[{location}]"
            expressions = {key: _replace(value, insn.reg(0), replacement) for key, value in expressions.items()}
        elif insn.mnemonic in _STORES:
            memory = insn.mem(1)
            if memory is not None and not memory.index and insn.reg(0) is not None:
                location = f"{memory.base}{memory.disp:+#x}"
                for width in _LOADS:
                    expressions = {key: value.replace(f"{width}[{location}]", f"({insn.reg(0)})") for key, value in expressions.items()}
        elif insn.mnemonic in _BINARY and _used(expressions, insn.reg(0)):
            left, right = _operand(insn, 1), _operand(insn, 2)
            replacement = f"{left} {_BINARY[insn.mnemonic]} {right}" if left is not None and right is not None else f"unknown-{insn.mnemonic}-{insn.address:#x}"
            expressions = {key: _replace(value, insn.reg(0), replacement) for key, value in expressions.items()}
        elif insn.mnemonic in ("move", "movf", "movt") and _used(expressions, insn.reg(0)):
            source = _operand(insn, 1)
            expressions = {key: _replace(value, insn.reg(0), source or f"unknown-move-{insn.address:#x}") for key, value in expressions.items()}
        elif insn.mnemonic == "lui" and _used(expressions, insn.reg(0)):
            value = insn.imm(1)
            replacement = hex((value << 16) & 0xffffffff) if value is not None else f"unknown-lui-{insn.address:#x}"
            expressions = {key: _replace(value, insn.reg(0), replacement) for key, value in expressions.items()}
        elif insn.mnemonic not in _CONTROL | _CALLS | _STORES | {"nop", "jr"} and _used(expressions, insn.reg(0)):
            expressions = {key: _replace(value, insn.reg(0), f"unknown-{insn.mnemonic}-{insn.address:#x}") for key, value in expressions.items()}
        if expressions != before:
            events.append({"address": hex(insn.address), "instruction": str(insn), "expressions": expressions.copy()})
        if len(events) >= max_instructions:
            boundary = {"kind": "event_budget", "address": hex(insn.address)}
            break
    else:
        if start:
            boundary = {"kind": "instruction_budget", "address": hex(function.instructions[start].address)}
    return {
        "function": function.name,
        "function_va": hex(function.va),
        "call_va": hex(call_va),
        "arguments": {pretty(register, Abi.O32): _display(expressions[register]) for register in registers},
        "events": [{**event, "expressions": {pretty(register, Abi.O32): _display(value) for register, value in event["expressions"].items()}} for event in events],
        "boundary": boundary,
        "basic_block_bounded": True,
    }


def direct_call_sites(path: str | Path, target: int, max_results: int = 64) -> list[dict[str, object]]:
    if max_results < 1 or max_results > 4096:
        raise ValueError("Direct-call result limit must be between 1 and 4096")
    source = Path(path)
    data = source.read_bytes()
    results = []
    with open(source, "rb") as stream:
        elf = ELFFile(stream)
        if elf.header.e_machine != "EM_MIPS":
            raise ValueError(f"Not a MIPS ELF: {source}")
        symbols = mips_symbols(elf)
        functions = []
        for section in elf.iter_sections():
            if section.header.sh_type in ("SHT_SYMTAB", "SHT_DYNSYM"):
                functions.extend(
                    (symbol.entry.st_value, symbol.entry.st_size, symbol.name)
                    for symbol in section.iter_symbols()
                    if symbol.entry.st_info.type == "STT_FUNC" and symbol.entry.st_value and symbol.entry.st_shndx != "SHN_UNDEF"
                )
        needle = (0x0c000000 | ((target >> 2) & 0x03ffffff)).to_bytes(4, "little" if elf.little_endian else "big")
        start = 0
        while len(results) < max_results:
            offset = data.find(needle, start)
            if offset < 0:
                break
            start = offset + 1
            for segment in elf.iter_segments():
                if not (segment.header.p_type == "PT_LOAD" and segment.header.p_flags & 1 and segment.header.p_offset <= offset < segment.header.p_offset + segment.header.p_filesz):
                    continue
                va = segment.header.p_vaddr + offset - segment.header.p_offset
                containing = [item for item in functions if item[1] and item[0] <= va < item[0] + item[1]]
                if containing:
                    function_va, size, name = max(containing, key=lambda item: item[0])
                else:
                    prior = max((item for item in functions if item[0] <= va), key=lambda item: item[0], default=(va, 0, symbols.get(va)))
                    function_va, size, name = prior
                results.append({"call_va": va, "function_va": function_va, "function_size": size, "function_name": name or f"sub_{function_va:x}"})
                break
    return results


def analyze_direct_callers(
    path: str | Path,
    target: int,
    arguments: tuple[str, ...] = ("$4", "$5", "$6"),
    max_instructions: int = 64,
    max_results: int = 64,
    max_size: int = 16384,
) -> dict[str, object]:
    sites = direct_call_sites(path, target, max_results)
    reports = []
    for site in sites:
        item = dict(site)
        if not site["function_size"]:
            item["slice"] = {"status": "unknown_function_size"}
        else:
            try:
                function = load_mips_function(path, site["function_va"], site["function_size"], max_size)
                item["slice"] = slice_call_arguments(function, site["call_va"], arguments, max_instructions)
            except ValueError as exc:
                item["slice"] = {"status": "failed", "reason": str(exc)}
        reports.append(item)
    return {
        "schema_version": 1,
        "analysis": "bounded-mips-message-provenance",
        "binary": str(path),
        "target": hex(target),
        "callers": reports,
        "summary": {"direct_callers": len(reports), "result_limit": max_results, "instruction_limit": max_instructions},
        "runtime_unknowns": [
            "Indirect calls and registrations require separate target verification.",
            "Linear slices stop at control-flow joins and do not prove dominance or a missing check on other paths.",
            "Producer credentials, message authorization, and delivered buffer lengths require transport-specific evidence.",
        ],
    }
