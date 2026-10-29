"""Bounded MIPS ELF function loading shared by targeted analyzers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile

from .insn_mips import Insn, from_capstone
from .isa_mips import Mode


@dataclass(frozen=True)
class MipsFunction:
    path: Path
    va: int
    size: int
    name: str
    instructions: tuple[Insn, ...]
    symbols: dict[int, str]


def mips_symbols(elf: ELFFile) -> dict[int, str]:
    symbols: dict[int, str] = {}
    for section in elf.iter_sections():
        if section.header.sh_type not in ("SHT_SYMTAB", "SHT_DYNSYM"):
            continue
        for symbol in section.iter_symbols():
            if symbol.entry.st_info.type != "STT_FUNC" or not symbol.name:
                continue
            va = symbol.entry.st_value
            if va and symbol.entry.st_shndx != "SHN_UNDEF":
                symbols.setdefault(va, symbol.name)
    return symbols


def load_mips_function(
    path: str | Path,
    va: int,
    size: int | None = None,
    max_size: int = 16384,
) -> MipsFunction:
    source = Path(path)
    with open(source, "rb") as stream:
        elf = ELFFile(stream)
        if elf.header.e_machine != "EM_MIPS":
            raise ValueError(f"Not a MIPS ELF: {source}")
        symbols = mips_symbols(elf)
        symbol_size = 0
        for section in elf.iter_sections():
            if section.header.sh_type not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                continue
            for symbol in section.iter_symbols():
                if symbol.entry.st_value == va and symbol.entry.st_info.type == "STT_FUNC":
                    symbol_size = max(symbol_size, symbol.entry.st_size)
        segment = next((
            item for item in elf.iter_segments()
            if item.header.p_type == "PT_LOAD"
            and item.header.p_flags & 1
            and item.header.p_vaddr <= va < item.header.p_vaddr + item.header.p_filesz
        ), None)
        if segment is None:
            raise ValueError(f"Address {va:#x} is not in an executable file segment")
        available = segment.header.p_vaddr + segment.header.p_filesz - va
        if size is None:
            later = min((address for address in symbols if address > va), default=va + available)
            size = symbol_size or min(later - va, available)
            if size <= 0:
                size = available
        if size <= 0 or size > max_size:
            raise ValueError(f"Function size must be between 1 and {max_size} bytes")
        if size > available:
            raise ValueError(f"Function at {va:#x} extends beyond its executable segment")
        if size % 4:
            raise ValueError("MIPS function size must be a multiple of four")
        offset = segment.header.p_offset + va - segment.header.p_vaddr
        stream.seek(offset)
        code = stream.read(size)
        little = elf.little_endian
        bits = elf.elfclass
    instructions = tuple(from_capstone(
        code,
        mode=Mode.MIPS32 if bits == 32 else Mode.MIPS64,
        base=va,
        little=little,
    ))
    if not instructions:
        raise ValueError(f"No MIPS instructions decoded at {va:#x}")
    return MipsFunction(source, va, size, symbols.get(va, f"sub_{va:x}"), instructions, symbols)
