"""Strict discovery and extraction of embedded ELF payloads."""

from __future__ import annotations

import struct
from dataclasses import dataclass


MAX_ELF_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_ELF_CANDIDATES = 4096
MAX_TOTAL_PAYLOAD_BYTES = 256 * 1024 * 1024

_ARCHITECTURES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    189: "MicroBlaze",
    243: "RISC-V",
    258: "LoongArch",
}


@dataclass(frozen=True)
class EmbeddedElf:
    offset: int
    architecture: str
    bits: int
    byte_order: str
    payload: bytes


def _parse_elf(data: bytes, offset: int) -> EmbeddedElf | None:
    if offset + 52 > len(data):
        return None
    ident = data[offset:offset + 16]
    if ident[4] not in (1, 2) or ident[5] not in (1, 2) or ident[6] != 1:
        return None
    bits = ident[4] * 32
    byte_order = "little" if ident[5] == 1 else "big"
    endian = "<" if ident[5] == 1 else ">"
    header_format = f"{endian}HHIIIIIHHHHHH" if bits == 32 else f"{endian}HHIQQQIHHHHHH"
    header_size = 52 if bits == 32 else 64
    if offset + header_size > len(data):
        return None
    (
        elf_type, machine, version, _entry, phoff, shoff, _flags, ehsize,
        phentsize, phnum, shentsize, shnum, shstrndx,
    ) = struct.unpack_from(header_format, data, offset + 16)
    if elf_type not in (1, 2, 3, 4) or machine not in _ARCHITECTURES or version != 1:
        return None
    if ehsize != header_size or (shnum and shstrndx >= shnum):
        return None
    expected_phentsize = 32 if bits == 32 else 56
    expected_shentsize = 40 if bits == 32 else 64
    if phnum and phentsize != expected_phentsize:
        return None
    if shnum and shentsize != expected_shentsize:
        return None
    if not phnum and not shnum:
        span = header_size
    else:
        span = header_size
    ph_end = phoff + phentsize * phnum
    sh_end = shoff + shentsize * shnum
    if ph_end > len(data) - offset or sh_end > len(data) - offset:
        return None
    span = max(span, ph_end, sh_end)
    ph_format = f"{endian}IIIIIIII" if bits == 32 else f"{endian}IIQQQQQQ"
    sh_format = f"{endian}IIIIIIIIII" if bits == 32 else f"{endian}IIQQQQIIQQ"
    for index in range(phnum):
        values = struct.unpack_from(ph_format, data, offset + phoff + index * phentsize)
        p_type = values[0]
        file_offset = values[1] if bits == 32 else values[2]
        file_size = values[4] if bits == 32 else values[5]
        if p_type == 1:
            if file_offset + file_size > len(data) - offset:
                return None
            span = max(span, file_offset + file_size)
    for index in range(shnum):
        values = struct.unpack_from(sh_format, data, offset + shoff + index * shentsize)
        section_type = values[1]
        file_offset = values[4] if bits == 32 else values[5]
        size = values[5] if bits == 32 else values[6]
        if section_type != 8:
            if file_offset + size > len(data) - offset:
                return None
            span = max(span, file_offset + size)
    if span > MAX_ELF_PAYLOAD_BYTES:
        return None
    return EmbeddedElf(
        offset=offset,
        architecture=_ARCHITECTURES[machine],
        bits=bits,
        byte_order=byte_order,
        payload=data[offset:offset + span],
    )


def find_embedded_elf(data: bytes) -> list[EmbeddedElf]:
    results: list[EmbeddedElf] = []
    total_payload = 0
    offset = 0
    candidates = 0
    while True:
        offset = data.find(b"\x7fELF", offset)
        if offset < 0:
            break
        candidates += 1
        if candidates > MAX_ELF_CANDIDATES:
            raise ValueError(f"embedded ELF scan exceeds {MAX_ELF_CANDIDATES} candidates")
        result = _parse_elf(data, offset)
        if result is not None:
            total_payload += len(result.payload)
            if total_payload > MAX_TOTAL_PAYLOAD_BYTES:
                raise ValueError("embedded ELF payloads exceed total size limit")
            results.append(result)
        offset += 4
    return results
