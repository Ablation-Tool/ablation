"""GOT-aware string cross-references for big- and little-endian MIPS ELF."""
from __future__ import annotations

import capstone
from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile


@dataclass(frozen=True)
class StringXref:
    function_va: int
    instruction_va: int
    register: str
    string_va: int


class MIPSStringXrefResolver:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._data = self.path.read_bytes()
        with open(self.path, "rb") as stream:
            elf = ELFFile(stream)
            text = elf.get_section_by_name(".text")
            if text is None:
                raise ValueError("MIPS binary has no .text section")
            self._text_va = text.header.sh_addr
            self._text_data = text.data()
            self._loads = [segment for segment in elf.iter_segments() if segment.header.p_type == "PT_LOAD"]
            self._rodata_ranges = [
                (section.header.sh_addr, section.header.sh_addr + section.header.sh_size)
                for section in elf.iter_sections()
                if section.name in (".rodata", ".rodata1", ".rdata", "__const", "__cstring")
            ]
        self._big_endian = self._data[5] == 2
        mode = capstone.CS_MODE_MIPS32 | (
            capstone.CS_MODE_BIG_ENDIAN if self._big_endian else capstone.CS_MODE_LITTLE_ENDIAN
        )
        self._decoder = capstone.Cs(capstone.CS_ARCH_MIPS, mode)
        self._decoder.skipdata = True

    def _read32(self, va: int) -> int | None:
        for segment in self._loads:
            start = segment.header.p_vaddr
            if start <= va and va + 4 <= start + segment.header.p_filesz:
                offset = segment.header.p_offset + va - start
                return int.from_bytes(self._data[offset:offset + 4], "big" if self._big_endian else "little")
        return None

    def resolve(self, target_vas: set[int] | None = None) -> list[StringXref]:
        registers: dict[str, int] = {}
        function_va = 0
        prologue_va = 0
        function_is_pic = False
        last_va = 0
        last_mnemonic = ""
        results: list[StringXref] = []

        def relevant(va: int) -> bool:
            if target_vas is not None:
                return va in target_vas
            return any(start <= va < end for start, end in self._rodata_ranges)

        def record(insn, register: str, va: int) -> None:
            if relevant(va):
                results.append(StringXref(function_va, insn.address, register, va))

        for insn in self._decoder.disasm(self._text_data, self._text_va):
            mnemonic = insn.mnemonic
            operands = [part.strip().lstrip("$") for part in insn.op_str.split(",")]
            try:
                if mnemonic == "lui" and len(operands) == 2:
                    if operands[0] == "gp":
                        prologue_va = insn.address
                        registers["t9"] = prologue_va
                    registers[operands[0]] = int(operands[1], 0) << 16
                elif mnemonic in ("addiu", "daddiu") and len(operands) == 3 and operands[0] == "sp" and operands[1] == "sp" and int(operands[2], 0) < 0:
                    if not function_is_pic or insn.address > function_va + 16:
                        function_va = last_va if last_mnemonic == "lui" else insn.address
                        function_is_pic = False
                elif mnemonic in ("addiu", "daddiu") and len(operands) == 3 and operands[1] in registers:
                    registers[operands[0]] = (registers[operands[1]] + int(operands[2], 0)) & 0xFFFFFFFF
                    record(insn, operands[0], registers[operands[0]])
                elif mnemonic == "ori" and len(operands) == 3 and operands[1] in registers:
                    registers[operands[0]] = registers[operands[1]] | int(operands[2], 0)
                    record(insn, operands[0], registers[operands[0]])
                elif mnemonic in ("addu", "daddu") and len(operands) == 3 and operands[1] in registers and operands[2] in registers:
                    registers[operands[0]] = (registers[operands[1]] + registers[operands[2]]) & 0xFFFFFFFF
                    if operands[0] == "gp" and operands[1] == "gp" and operands[2] == "t9":
                        function_va = prologue_va
                        function_is_pic = True
                    record(insn, operands[0], registers[operands[0]])
                elif mnemonic == "move" and len(operands) == 2 and operands[1] in registers:
                    registers[operands[0]] = registers[operands[1]]
                elif mnemonic == "lw" and len(operands) == 2 and "(" in operands[1]:
                    displacement, base = operands[1][:-1].split("(", 1)
                    base = base.lstrip("$")
                    if base in registers:
                        value = self._read32((registers[base] + int(displacement or "0", 0)) & 0xFFFFFFFF)
                        if value is not None:
                            registers[operands[0]] = value
                last_va = insn.address
                last_mnemonic = mnemonic
            except (ValueError, TypeError):
                continue
        return results


def resolve_string_xrefs(path: str | Path, target_vas: set[int] | None = None) -> list[StringXref]:
    return MIPSStringXrefResolver(path).resolve(target_vas)
