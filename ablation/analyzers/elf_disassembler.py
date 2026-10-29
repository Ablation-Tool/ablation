"""Byte-backed ELF symbols and Capstone disassembly for native Android libraries."""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection


@dataclass(frozen=True)
class ELFSymbol:
    name: str
    address: int
    size: int
    kind: str
    binding: str
    defined: bool
    thumb: bool = False


@dataclass(frozen=True)
class ELFInstruction:
    address: int
    size: int
    mnemonic: str
    operands: str
    data: bytes
    thumb: bool = False

    def text(self) -> str:
        return f"0x{self.address:08x}:  {self.mnemonic:<10} {self.operands}".rstrip()


@dataclass(frozen=True)
class NativeCall:
    site: int
    target: int
    target_name: str
    indirect: bool = False


class ELFDisassembler:
    """Disassemble ELF32/64 files without requiring a filesystem-backed input."""

    def __init__(self, data: bytes, name: str = "memory.so") -> None:
        if not data.startswith(b"\x7fELF"):
            raise ValueError(f"{name}: not an ELF file")
        self.data = data
        self.name = name
        self._stream = io.BytesIO(data)
        self.elf = ELFFile(self._stream)
        self.endian = "<" if self.elf.little_endian else ">"
        self.bits = self.elf.elfclass
        self.machine = self.elf.header["e_machine"]
        self._symbols: Optional[List[ELFSymbol]] = None
        self._plt: Optional[Dict[int, str]] = None
        self._plt_ranges: List[Tuple[int, int, str]] = []
        self._cs = self._make_capstone()

    @classmethod
    def from_path(cls, path: str | Path) -> "ELFDisassembler":
        binary_path = Path(path)
        return cls(binary_path.read_bytes(), name=binary_path.name)

    @classmethod
    def from_bytes(cls, data: bytes, name: str = "memory.so") -> "ELFDisassembler":
        return cls(data, name=name)

    def _make_capstone(self) -> capstone.Cs:
        mode = capstone.CS_MODE_LITTLE_ENDIAN if self.elf.little_endian else capstone.CS_MODE_BIG_ENDIAN
        machine_modes = {
            "EM_ARM": (capstone.CS_ARCH_ARM, mode | capstone.CS_MODE_ARM),
            "EM_AARCH64": (capstone.CS_ARCH_ARM64, mode),
            "EM_386": (capstone.CS_ARCH_X86, mode | capstone.CS_MODE_32),
            "EM_X86_64": (capstone.CS_ARCH_X86, mode | capstone.CS_MODE_64),
            "EM_MIPS": (capstone.CS_ARCH_MIPS, mode | capstone.CS_MODE_MIPS32),
            "EM_RISCV": (capstone.CS_ARCH_RISCV, mode | capstone.CS_MODE_RISCV64 if self.bits == 64 else mode | capstone.CS_MODE_RISCV32),
        }
        if self.machine not in machine_modes:
            raise ValueError(f"Unsupported ELF architecture: {self.machine}")
        arch, selected_mode = machine_modes[self.machine]
        if self.machine == "EM_MIPS" and self.bits == 64:
            selected_mode = (selected_mode & ~capstone.CS_MODE_MIPS32) | capstone.CS_MODE_MIPS64
        engine = capstone.Cs(arch, selected_mode)
        engine.detail = True
        return engine

    @property
    def architecture(self) -> str:
        return {
            "EM_ARM": "arm32",
            "EM_AARCH64": "arm64",
            "EM_386": "x86_32",
            "EM_X86_64": "x86_64",
            "EM_MIPS": "mips64" if self.bits == 64 else "mips32",
            "EM_RISCV": "riscv64" if self.bits == 64 else "riscv32",
        }.get(self.machine, self.machine)

    def sections(self) -> List[dict]:
        return [
            {
                "name": section.name,
                "address": section["sh_addr"],
                "offset": section["sh_offset"],
                "size": section["sh_size"],
                "flags": section["sh_flags"],
            }
            for section in self.elf.iter_sections()
        ]

    def va_to_offset(self, address: int) -> Optional[int]:
        for segment in self.elf.iter_segments():
            if segment["p_type"] != "PT_LOAD" or not segment["p_filesz"]:
                continue
            start = segment["p_vaddr"]
            if start <= address < start + segment["p_filesz"]:
                return segment["p_offset"] + address - start
        return None

    def read_va(self, address: int, size: int) -> bytes:
        offset = self.va_to_offset(address)
        if offset is None or offset + size > len(self.data):
            raise ValueError(f"Unmapped virtual address range: {address:#x}+{size:#x}")
        return self.data[offset:offset + size]

    def read_pointer(self, address: int) -> int:
        width = self.bits // 8
        return int.from_bytes(self.read_va(address, width), "little" if self.endian == "<" else "big")

    def cstring_at_va(self, address: int, max_size: int = 4096) -> str:
        offset = self.va_to_offset(address)
        if offset is None:
            raise ValueError(f"Unmapped string address: {address:#x}")
        end = self.data.find(b"\x00", offset, min(len(self.data), offset + max_size))
        if end < 0:
            raise ValueError(f"Unterminated string at {address:#x}")
        return self.data[offset:end].decode("utf-8", errors="strict")

    def symbols(self) -> List[ELFSymbol]:
        if self._symbols is not None:
            return self._symbols
        symbols: Dict[Tuple[str, int, str], ELFSymbol] = {}
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                address = symbol["st_value"]
                symbols[(symbol.name, address & ~1, section.name)] = ELFSymbol(
                    name=symbol.name,
                    address=address & ~1 if self.machine == "EM_ARM" else address,
                    size=symbol["st_size"],
                    kind=symbol["st_info"]["type"],
                    binding=symbol["st_info"]["bind"],
                    defined=symbol["st_shndx"] != "SHN_UNDEF",
                    thumb=self.machine == "EM_ARM" and bool(address & 1),
                )
        self._symbols = list(symbols.values())
        return self._symbols

    def exports(self) -> Dict[str, int]:
        return {
            symbol.name: symbol.address
            for symbol in self.symbols()
            if symbol.defined and symbol.name and symbol.binding in ("STB_GLOBAL", "STB_WEAK")
        }

    def function_symbols(self) -> List[ELFSymbol]:
        return sorted(
            (symbol for symbol in self.symbols()
             if symbol.defined and symbol.kind == "STT_FUNC" and symbol.address),
            key=lambda symbol: symbol.address,
        )

    def symbol_for(self, address: int) -> Optional[ELFSymbol]:
        candidates = [
            symbol for symbol in self.function_symbols()
            if symbol.address == (address & ~1)
        ]
        if candidates:
            return candidates[0]
        containing = [
            symbol for symbol in self.function_symbols()
            if symbol.size and symbol.address <= address < symbol.address + symbol.size
        ]
        return containing[0] if containing else None

    def is_thumb(self, address: int) -> bool:
        symbol = self.symbol_for(address)
        return bool(symbol and symbol.thumb)

    def _engine_for(self, thumb: bool) -> capstone.Cs:
        if self.machine != "EM_ARM":
            return self._cs
        engine = capstone.Cs(
            capstone.CS_ARCH_ARM,
            (capstone.CS_MODE_LITTLE_ENDIAN if self.elf.little_endian else capstone.CS_MODE_BIG_ENDIAN)
            | (capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM),
        )
        engine.detail = True
        return engine

    def disassemble(self, address: int, size: int, thumb: Optional[bool] = None) -> List[ELFInstruction]:
        if self.machine == "EM_ARM" and thumb is None:
            thumb = self.is_thumb(address)
        code = self.read_va(address & ~1 if self.machine == "EM_ARM" else address, size)
        address &= ~1 if self.machine == "EM_ARM" else address
        engine = self._engine_for(bool(thumb))
        return [
            ELFInstruction(insn.address, insn.size, insn.mnemonic, insn.op_str, bytes(insn.bytes), bool(thumb))
            for insn in engine.disasm(code, address)
        ]

    def disassemble_function(self, address: int, max_size: int = 0x10000, thumb: Optional[bool] = None) -> List[ELFInstruction]:
        symbol = self.symbol_for(address)
        if symbol is not None:
            address = symbol.address
            size = symbol.size
            thumb = symbol.thumb
        else:
            size = 0
        if not size:
            functions = self.function_symbols()
            following = [candidate.address for candidate in functions if candidate.address > address]
            section_end = None
            for section in self.elf.iter_sections():
                if section["sh_flags"] & 0x4 and section["sh_addr"] <= address < section["sh_addr"] + section["sh_size"]:
                    section_end = section["sh_addr"] + section["sh_size"]
                    break
            size = min(following[0] if following else max_size, section_end - address if section_end else max_size)
            size = min(size, max_size)
        return self.disassemble(address, size, thumb=thumb)

    def _relocation_symbols(self) -> Dict[int, str]:
        got_symbols: Dict[int, str] = {}
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            for relocation in section.iter_relocations():
                if not relocation["r_info_sym"]:
                    continue
                symbol = section.elffile.get_section(section["sh_link"]).get_symbol(relocation["r_info_sym"])
                if symbol.name:
                    got_symbols[relocation["r_offset"]] = symbol.name
        return got_symbols

    def plt_symbols(self) -> Dict[int, str]:
        if self._plt is not None:
            return self._plt
        self._plt = {}
        self._plt_ranges = []
        relocations = self._relocation_symbols()
        section = self.elf.get_section_by_name(".plt")
        if section is None or not relocations:
            return self._plt
        address = section["sh_addr"]
        code = section.data()
        if self.machine == "EM_ARM":
            engine = self._engine_for(False)
            instructions = list(engine.disasm(code, address))
            constants: Dict[str, int] = {}
            stub_start = address
            for insn in instructions:
                if insn.mnemonic == "add" and insn.operands and insn.operands[0].type == capstone.arm.ARM_OP_REG:
                    operands = insn.operands
                    if len(operands) >= 3 and operands[1].type == capstone.arm.ARM_OP_REG and operands[2].type == capstone.arm.ARM_OP_IMM:
                        source = insn.reg_name(operands[1].reg)
                        base = insn.address + 8 if source == "pc" else constants.get(source)
                        if base is not None:
                            immediate = operands[2].imm
                            if len(operands) >= 4 and operands[3].type == capstone.arm.ARM_OP_IMM:
                                rotation = operands[3].imm % 32
                                immediate = ((immediate >> rotation) | (immediate << (32 - rotation))) & 0xFFFFFFFF if rotation else immediate
                            constants[insn.reg_name(operands[0].reg)] = base + immediate
                if insn.mnemonic == "ldr" and len(insn.operands) >= 2:
                    dst, src = insn.operands[:2]
                    if dst.type == capstone.arm.ARM_OP_REG and insn.reg_name(dst.reg) == "pc" and src.type == capstone.arm.ARM_OP_MEM:
                        base = insn.reg_name(src.mem.base)
                        got = (insn.address + 8 if base == "pc" else constants.get(base))
                        if got is not None:
                            got += src.mem.disp
                            name = relocations.get(got)
                            if name:
                                self._plt[stub_start] = name
                                self._plt_ranges.append((stub_start, insn.address + insn.size, name))
                                stub_start = insn.address + insn.size
                                constants.clear()
        elif self.machine in ("EM_386", "EM_X86_64"):
            stub_start = address
            for insn in self._cs.disasm(code, address):
                if insn.mnemonic.startswith("jmp") and insn.operands and insn.operands[0].type == capstone.x86.X86_OP_MEM:
                    mem = insn.operands[0].mem
                    got = None
                    if self.machine == "EM_X86_64" and insn.reg_name(mem.base) == "rip":
                        got = insn.address + insn.size + mem.disp
                    elif self.machine == "EM_386" and not mem.base:
                        got = mem.disp
                    name = relocations.get(got)
                    if name:
                        self._plt[stub_start] = name
                        self._plt_ranges.append((stub_start, insn.address + insn.size, name))
                stub_start = insn.address + insn.size
        return self._plt

    def symbol_name(self, address: int) -> str:
        address &= ~1 if self.machine == "EM_ARM" else address
        self.plt_symbols()
        for start, end, name in self._plt_ranges:
            if start <= address < end:
                return name
        symbol = self.symbol_for(address)
        return symbol.name if symbol and symbol.name else f"sub_{address:x}"

    def direct_calls(self, instructions: List[ELFInstruction]) -> Iterator[NativeCall]:
        for wrapped in instructions:
            raw = next(self._engine_for(wrapped.thumb).disasm(wrapped.data, wrapped.address), None)
            if raw is None or capstone.CS_GRP_CALL not in raw.groups:
                continue
            target = None
            if self.machine in ("EM_ARM", "EM_AARCH64") and raw.operands:
                operand = raw.operands[0]
                if operand.type == capstone.arm.ARM_OP_IMM if self.machine == "EM_ARM" else operand.type == capstone.arm64.ARM64_OP_IMM:
                    target = operand.imm
            elif self.machine in ("EM_386", "EM_X86_64") and raw.operands:
                operand = raw.operands[0]
                if operand.type == capstone.x86.X86_OP_IMM:
                    target = operand.imm
            if target is not None and self.va_to_offset(target) is not None:
                yield NativeCall(wrapped.address, target, self.symbol_name(target))

    def function_call_graph(self) -> List[Tuple[int, int, str]]:
        edges: List[Tuple[int, int, str]] = []
        for symbol in self.function_symbols():
            for call in self.direct_calls(self.disassemble_function(symbol.address)):
                edges.append((symbol.address, call.target, call.target_name))
        return edges
