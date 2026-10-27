"""MIPS ELF instruction-set and ABI inspection."""
from __future__ import annotations

import struct
from pathlib import Path


def inspect_mips_elf(data: bytes) -> dict[str, object]:
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] not in (1, 2):
        raise ValueError("Not a supported MIPS ELF header")
    endian = ">" if data[5] == 2 else "<"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    if machine != 8:
        raise ValueError("ELF is not MIPS")
    bits = 32 if data[4] == 1 else 64
    flags_offset = 36 if bits == 32 else 48
    flags = struct.unpack_from(endian + "I", data, flags_offset)[0]
    architecture = flags & 0xF0000000
    isa = {
        0x00000000: "mips1",
        0x10000000: "mips2",
        0x20000000: "mips3",
        0x30000000: "mips4",
        0x40000000: "mips5",
        0x50000000: "mips32",
        0x60000000: "mips64",
        0x70000000: "mips32r2",
        0x80000000: "mips64r2",
        0x90000000: "mips32r6",
        0xA0000000: "mips64r6",
    }.get(architecture, "unknown")
    abi = "o32" if bits == 32 else "n32" if flags & 0x20 else "n64"
    return {
        "bits": bits,
        "big_endian": data[5] == 2,
        "flags": flags,
        "isa": isa,
        "abi": abi,
    }


def describe_mips_elf(path: str | Path) -> str:
    info = inspect_mips_elf(Path(path).read_bytes()[:64])
    endian = "big-endian" if info["big_endian"] else "little-endian"
    return f"mips{info['bits']}/{info['abi']} ({info['isa']} instructions, {endian})"
