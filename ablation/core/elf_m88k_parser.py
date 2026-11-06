"""Parser for big-endian Motorola MC88100 ELF executables."""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, List

from .coff_m88k_parser import M88kCoffBinary, Section, STYP_BSS, STYP_DATA, STYP_TEXT

EM_88K = 0x05
SHT_NOBITS = 8
SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4


def _cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise ValueError("string offset outside input")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated string")
    return data[offset:end].decode("latin1")


def parse(path: str | Path) -> M88kCoffBinary:
    raw = Path(path).read_bytes()
    if len(raw) < 52 or raw[:4] != b"\x7fELF":
        raise ValueError("not an ELF input")
    if raw[4] != 1 or raw[5] != 2:
        raise ValueError("M88K ELF must be 32-bit big-endian")
    fields = struct.unpack_from(">16sHHIIIIIHHHHHH", raw, 0)
    _, elf_type, machine, _version, entry, phoff, shoff, _flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = fields
    if machine != EM_88K:
        raise ValueError(f"not an M88K ELF: machine={machine:#x}")
    if ehsize != 52 or shentsize != 40 or shnum == 0 or shstrndx >= shnum:
        raise ValueError("invalid M88K ELF header")
    headers: List[tuple] = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        if offset + 40 > len(raw):
            raise ValueError("section header outside input")
        headers.append(struct.unpack_from(">10I", raw, offset))
    if shoff + shnum * shentsize > len(raw):
        raise ValueError("section table outside input")
    shstr_header = headers[shstrndx]
    shstr = raw[shstr_header[4]:shstr_header[4] + shstr_header[5]]
    sections: List[Section] = []
    sec_map: Dict[str, Section] = {}
    section_names: List[str] = []
    for header in headers:
        name_index, section_type, flags, address, file_offset, size, _link, _info, _align, _entsize = header
        name = _cstring(shstr, name_index) if name_index else ""
        section_names.append(name)
        if section_type == SHT_NOBITS:
            content = b"\x00" * size
        else:
            if file_offset + size > len(raw):
                raise ValueError(f"section {name!r} outside input")
            content = raw[file_offset:file_offset + size]
        section_flags = STYP_TEXT if flags & SHF_EXECINSTR else STYP_DATA if flags & SHF_WRITE else 0
        if section_type == SHT_NOBITS:
            section_flags |= STYP_BSS
        section = Section(name=name, vaddr=address, size=size, flags=section_flags, data=content)
        sections.append(section)
        sec_map[name] = section

    dynamic_symbols: List[tuple] = []
    dynstr = b""
    if ".dynsym" in sec_map and ".dynstr" in sec_map:
        dynsym = sec_map[".dynsym"].data
        dynstr = sec_map[".dynstr"].data
        for offset in range(0, len(dynsym) - len(dynsym) % 16, 16):
            dynamic_symbols.append(struct.unpack_from(">IIIBBH", dynsym, offset))

    plt: Dict[int, str] = {}
    needed: List[str] = []
    if ".dynamic" in sec_map:
        dynamic = sec_map[".dynamic"].data
        for offset in range(0, len(dynamic) - len(dynamic) % 8, 8):
            tag, value = struct.unpack_from(">iI", dynamic, offset)
            if tag == 0:
                break
            if tag == 1:
                needed.append(_cstring(dynstr, value))

    if ".rela.gotp" in sec_map:
        relocations = sec_map[".rela.gotp"].data
        plt_section = sec_map.get(".plt")
        for offset in range(0, len(relocations) - len(relocations) % 12, 12):
            _r_offset, r_info, r_addend = struct.unpack_from(">III", relocations, offset)
            symbol_index = r_info >> 8
            if symbol_index >= len(dynamic_symbols) or r_addend < 0x0C:
                continue
            st_name = dynamic_symbols[symbol_index][0]
            stub = r_addend - 0x0C
            if plt_section is not None and plt_section.contains_va(stub):
                plt[stub] = _cstring(dynstr, st_name)

    text = sec_map.get(".text")
    data = sec_map.get(".data")
    return M88kCoffBinary(
        path=str(path), entry=entry,
        text_start=text.vaddr if text else 0,
        data_start=data.vaddr if data else 0,
        sections=sections, _sec_map=sec_map, plt=plt, needed=needed,
    )
