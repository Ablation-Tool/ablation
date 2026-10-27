"""Lightweight o32 register and call-site annotation."""
from __future__ import annotations

from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile

from ablation.analyzers.reg_annotator import AnnotationResult, CallSite, RegVal


class MIPSRegAnnotator:
    def __init__(self, ctx):
        self._ctx = ctx
        self._data = Path(ctx.path).read_bytes()
        self._big_endian = self._data[5] == 2
        self._arg_regs = ["a0", "a1", "a2", "a3"]
        mode = capstone.CS_MODE_MIPS32 | (
            capstone.CS_MODE_BIG_ENDIAN if self._big_endian else capstone.CS_MODE_LITTLE_ENDIAN
        )
        self._decoder = capstone.Cs(capstone.CS_ARCH_MIPS, mode)
        with open(ctx.path, "rb") as stream:
            elf = ELFFile(stream)
            self._text = elf.get_section_by_name(".text")
            self._loads = [segment for segment in elf.iter_segments() if segment.header.p_type == "PT_LOAD"]
        if self._text is None:
            raise ValueError("MIPS binary has no .text section")

    @classmethod
    def from_context(cls, ctx) -> "MIPSRegAnnotator":
        return cls(ctx)

    def _read_u32(self, va: int) -> int | None:
        for segment in self._loads:
            start = segment.header.p_vaddr
            if start <= va and va + 4 <= start + segment.header.p_filesz:
                offset = segment.header.p_offset + va - start
                return int.from_bytes(self._data[offset:offset + 4], "big" if self._big_endian else "little")
        return None

    @staticmethod
    def _parts(operands: str) -> list[str]:
        return [part.strip().lstrip("$") for part in operands.split(",")]

    def annotate_calls(
        self,
        func_va: int,
        func_end_va: int,
        window: int = 2048,
        seed_args: bool = True,
    ) -> AnnotationResult:
        text_va = self._text.header.sh_addr
        text_offset = self._text.header.sh_offset
        size = min(func_end_va - func_va, window)
        offset = text_offset + func_va - text_va
        if offset < text_offset or offset + size > text_offset + self._text.header.sh_size:
            return AnnotationResult(func_va, func_end_va, [])
        chunk = self._data[offset:offset + size]
        registers: dict[str, RegVal] = {
            reg: RegVal.arg(index) for index, reg in enumerate(self._arg_regs)
        } if seed_args else {}
        registers["t9"] = RegVal.const(func_va)
        memory: dict[int, RegVal] = {}
        calls: list[CallSite] = []

        def value_at(va: int) -> RegVal:
            string = self._ctx.strings.get(va)
            return RegVal.string(string) if string is not None else RegVal.const(va)

        for insn in self._decoder.disasm(chunk, func_va):
            mnemonic = insn.mnemonic.lower()
            operands = self._parts(insn.op_str)
            if mnemonic == "move" and len(operands) == 2:
                destination, source = operands
                registers[destination] = RegVal.copy(source, registers.get(source))
            elif mnemonic in ("addu", "daddu", "or") and len(operands) == 3:
                destination, source, third = operands
                if third == "zero":
                    registers[destination] = RegVal.copy(source, registers.get(source))
                elif mnemonic in ("addu", "daddu"):
                    left = registers.get(source)
                    right = registers.get(third)
                    if left and right and left.kind == "const" and right.kind == "const":
                        registers[destination] = value_at((left.int_val + right.int_val) & 0xFFFFFFFF)
            elif mnemonic in ("addiu", "daddiu") and len(operands) == 3:
                destination, source, immediate = operands
                try:
                    number = int(immediate, 0)
                except ValueError:
                    continue
                if source == "zero":
                    registers[destination] = RegVal.const(number)
                else:
                    base = registers.get(source)
                    if base and base.kind == "const":
                        registers[destination] = value_at((base.int_val + number) & 0xFFFFFFFF)
            elif mnemonic == "lui" and len(operands) == 2:
                try:
                    registers[operands[0]] = RegVal.const(int(operands[1], 0) << 16)
                except ValueError:
                    pass
            elif mnemonic in ("lw", "sw") and len(operands) == 2:
                register, address = operands
                if "(" not in address or not address.endswith(")"):
                    continue
                displacement, base = address[:-1].split("(", 1)
                base = base.lstrip("$")
                try:
                    number = int(displacement or "0", 0)
                except ValueError:
                    continue
                base_value = registers.get(base)
                if not base_value or base_value.kind != "const":
                    if mnemonic == "lw" and register not in registers:
                        registers[register] = RegVal.mem(address)
                    continue
                effective = (base_value.int_val + number) & 0xFFFFFFFF
                if mnemonic == "sw":
                    memory[effective] = registers.get(register, RegVal.unknown())
                    continue
                if effective in memory:
                    registers[register] = memory[effective]
                    continue
                stored = self._read_u32(effective)
                registers[register] = value_at(stored) if stored is not None else RegVal.mem(address)
            elif mnemonic in ("jal", "jalr"):
                if mnemonic == "jal":
                    try:
                        target = int(operands[0], 0)
                    except ValueError:
                        continue
                else:
                    target_value = registers.get(operands[0])
                    while target_value and target_value.kind == "copy" and target_value.chain:
                        target_value = target_value.chain
                    if not target_value or target_value.kind != "const":
                        continue
                    target = target_value.int_val
                name = self._ctx.name(target)
                calls.append(CallSite(
                    site_va=insn.address,
                    target_va=target,
                    target_name=name,
                    args={reg: registers.get(reg, RegVal.unknown()) for reg in self._arg_regs},
                ))
                registers["v0"] = RegVal.ret(name)
                for reg in self._arg_regs + [f"t{index}" for index in range(10)]:
                    registers.pop(reg, None)
        return AnnotationResult(func_va, func_end_va, calls)
