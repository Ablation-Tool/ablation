import json
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .image import LoadImage
from .io_utils import ensure_directory, write_text
from .s390 import Instruction, S390Decoder


@dataclass
class FunctionInfo:
    entry_rva: int
    code_rva: int
    name: str | None
    kind: str
    confidence: str
    frame_size: int | None = None
    ppa1_rva: int | None = None
    name_rva: int | None = None
    next_entry_rva: int | None = None
    instructions: list[Instruction] = field(default_factory=list)
    calls: list[int | None] = field(default_factory=list)
    branches: list[int | None] = field(default_factory=list)
    complete: bool | None = None

    def to_dict(self, include_instructions=False):
        result = {
            "entry_rva": self.entry_rva, "code_rva": self.code_rva, "name": self.name,
            "kind": self.kind, "confidence": self.confidence, "frame_size": self.frame_size,
            "ppa1_rva": self.ppa1_rva, "name_rva": self.name_rva,
            "next_entry_rva": self.next_entry_rva, "calls": self.calls,
            "branches": self.branches, "complete": self.complete,
            "instruction_count": len(self.instructions),
            "unknown_instruction_count": sum(not item.known for item in self.instructions),
        }
        if include_instructions:
            result["instructions"] = [item.to_dict() for item in self.instructions]
        return result


@dataclass
class Recovery:
    functions: list[FunctionInfo]
    anchors: list[dict]

    def to_dict(self, include_instructions=False):
        counts = {}
        for function in self.functions:
            counts[function.kind] = counts.get(function.kind, 0) + 1
        return {
            "function_count": len(self.functions), "kind_counts": counts,
            "anchor_count": len(self.anchors), "anchors": self.anchors,
            "functions": [function.to_dict(include_instructions) for function in self.functions],
        }

    def write(self, output_directory, include_instructions=False):
        output = ensure_directory(output_directory)
        result = self.to_dict(include_instructions)
        write_text(output / "functions.json", json.dumps(result, indent=2) + "\n")
        write_text(output / "functions.txt", "".join(
            f'{function.entry_rva:08x} {function.code_rva:08x} {function.kind:16s} '
            f'{function.confidence:16s} {function.name or "-"}\n'
            for function in self.functions
        ))
        disassembly = []
        for function in self.functions:
            disassembly.append(f'; {function.name or "unnamed"} entry={function.entry_rva:#x} code={function.code_rva:#x} kind={function.kind}\n')
            disassembly.extend(instruction.text() + "\n" for instruction in function.instructions)
        write_text(output / "disassembly.txt", "".join(disassembly))
        return output


def _u16(data, offset):
    return struct.unpack_from(">H", data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]


def _s32(data, offset):
    return struct.unpack_from(">i", data, offset)[0]


def ppa_candidates(data):
    result = []
    for entry in range(0, len(data) - 20, 2):
        if data[entry:entry + 3] != b"\x47\xf0\xf0" or data[entry + 5:entry + 8] != b"\xc3\xc5\xc5":
            continue
        ppa1 = entry + _s32(data, entry + 12)
        if not 0 <= ppa1 < len(data):
            continue
        name_offset = ppa1 + data[ppa1] * 2
        if not 0 <= name_offset < len(data) - 2:
            continue
        name_length = _u16(data, name_offset)
        if not 0 < name_length < 65536 or name_offset + 2 + name_length > len(data):
            continue
        name = data[name_offset + 2:name_offset + 2 + name_length].decode("cp500", errors="replace")
        if not name.isprintable():
            continue
        trampoline = data[entry + 16:entry + 20] == b"\x47\xf0\xf0\x01"
        code = entry + data[entry + 3] if trampoline else entry + 16
        if not 0 <= code < len(data):
            continue
        result.append(FunctionInfo(
            entry, code, name, "PPA_LE" if trampoline else "PPA_CPP", "high",
            _u32(data, entry + 8), ppa1, name_offset + 2,
        ))
    result.sort(key=lambda item: item.entry_rva)
    for index, item in enumerate(result):
        if index + 1 < len(result):
            item.next_entry_rva = result[index + 1].entry_rva
    return result


def prolog_candidates(data, decoder):
    result = []
    for address in range(0, len(data) - 4, 2):
        first = data[address]
        second = data[address + 1]
        base = data[address + 2] >> 4
        displacement = data[address + 3]
        save_store = (
            first in (0x50, 0x90) and second >> 4 == 0x0E
            and (
                (base in (0x0D, 0x0F) and ((first == 0x90 and displacement == 0x0C) or (first == 0x50 and displacement == 0x04)))
                or base == 4
            )
        )
        if not save_store:
            continue
        instruction = decoder.decode(data, address)
        if instruction.mnemonic not in ("stm", "st"):
            continue
        kind = "XPLINK_SAVE_STORE" if base == 4 else "SAVE_STORE_PROLOG"
        result.append(FunctionInfo(address, address, None, kind, "medium"))
    return result


def decode_cfg(data, start, decoder, maximum=20000):
    pending = [start]
    block_starts = set()
    instructions = {}
    calls = []
    branches = []
    complete = True
    while pending:
        address = pending.pop()
        if address in block_starts:
            continue
        block_starts.add(address)
        while address not in instructions:
            if len(instructions) >= maximum:
                return list(instructions.values()), calls, branches, False
            if address < 0 or address % 2 or address + 2 > len(data):
                complete = False
                break
            try:
                instruction = decoder.decode(data, address)
            except ValueError:
                complete = False
                break
            instructions[address] = instruction
            address = instruction.end
            if instruction.flow == "call":
                calls.append(instruction.target)
                continue
            if instruction.flow == "conditional_jump":
                branches.append(instruction.target)
                if instruction.target is not None:
                    pending.append(instruction.target)
                continue
            if instruction.flow == "jump":
                branches.append(instruction.target)
                if instruction.target is not None:
                    pending.append(instruction.target)
                break
            if instruction.flow == "return":
                break
    return list(instructions.values()), calls, branches, complete


def recover_functions(image, include_cfg=False, maximum_per_function=20000):
    data = image.text
    decoder = S390Decoder()
    candidates = {}
    for function in ppa_candidates(data):
        candidates[function.entry_rva] = function
    for function in prolog_candidates(data, decoder):
        existing = candidates.get(function.entry_rva)
        if existing is None:
            candidates[function.entry_rva] = function
        elif existing.kind.startswith("PPA"):
            continue
    symbol_names = {}
    for symbol in image.symbols:
        if 0 <= symbol.address < len(data) and symbol.kind in ("SD", "SD_QUAD", "PC", "PC_QUAD", "LR"):
            symbol_names.setdefault(symbol.address, symbol.name)
    for function in candidates.values():
        if function.name is None and function.entry_rva in symbol_names:
            function.name = symbol_names[function.entry_rva]
            function.confidence = "high"
    ordered = [candidates[address] for address in sorted(candidates)]
    if include_cfg:
        for function in ordered:
            instructions, calls, branches, complete = decode_cfg(
                data, function.code_rva, decoder, maximum_per_function,
            )
            function.instructions = instructions
            function.calls = calls
            function.branches = branches
            function.complete = complete
    anchors = [
        {"name": symbol.name, "address": symbol.address, "kind": symbol.kind, "source": symbol.source}
        for symbol in image.symbols
        if 0 <= symbol.address < len(data)
    ]
    if image.entry_rva is not None:
        anchors.append({"name": "container_entry", "address": image.entry_rva, "kind": "ENTRY", "source": "container"})
    anchors.sort(key=lambda item: (item["address"], item["name"]))
    return Recovery(ordered, anchors)
