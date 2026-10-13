"""Parser for Motorola 88000 BCS COFF executables.

The 88K BCS (Binary Compatibility Standard) uses AT&T System V COFF with
magic number 0x016D.  This format predates ELF; LIEF and Capstone do not
support it.  This module provides pure-Python parsing sufficient to extract
section data and metadata for disassembly.

COFF file layout:
  File header    (20 bytes)
  Optional header (f_opthdr bytes, typically 28 for 88K BCS)
  Section headers (f_nscns × 40 bytes each)
  Section data    (at file offsets given in section headers)
  Symbol table    (at f_symptr, f_nsyms entries × 18 bytes)

Reference: MC88100 Programmer's Reference Manual; BCS Rev. 1.1.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

M88K_BCS_MAGIC = 0x016D
_FILE_HDR_FMT = ">HHiiiHH"   # big-endian: magic, nscns, timdat, symptr, nsyms, opthdr, flags
_FILE_HDR_SZ  = 20

_OPT_HDR_FMT = ">HHiiiiII"   # magic, vstamp, tsize, dsize, bsize, entry, text_start, data_start
_OPT_HDR_SZ  = 28

# Section header: s_name(8), s_paddr(4), s_vaddr(4), s_size(4), s_scnptr(4),
#                 s_relptr(4), s_lnnoptr(4), s_nreloc(4), s_nlnno(4), s_flags(4)
# Note: 88K BCS COFF uses 4-byte (long) s_nreloc and s_nlnno, not the 2-byte
# shorts used in some other COFF variants.  Total section header = 44 bytes.
_SCNHDR_FMT = ">8siiiiiiIIi"
_SCNHDR_SZ  = 44

STYP_TEXT  = 0x0020
STYP_DATA  = 0x0040
STYP_BSS   = 0x0080


@dataclass
class Section:
    name:    str
    vaddr:   int
    size:    int
    flags:   int
    data:    bytes = field(repr=False)

    @property
    def is_text(self) -> bool:
        return bool(self.flags & STYP_TEXT)

    @property
    def is_data(self) -> bool:
        return bool(self.flags & STYP_DATA)

    @property
    def va_end(self) -> int:
        return self.vaddr + self.size

    def contains_va(self, va: int) -> bool:
        return self.vaddr <= va < self.va_end

    def read_word(self, va: int) -> int:
        """Read a big-endian 32-bit word at virtual address va."""
        off = va - self.vaddr
        if off < 0 or off + 4 > len(self.data):
            raise IndexError(f"VA {va:#x} out of range for section {self.name!r}")
        return struct.unpack_from(">I", self.data, off)[0]

    def read_bytes(self, va: int, n: int) -> bytes:
        off = va - self.vaddr
        if off < 0 or off + n > len(self.data):
            raise IndexError(f"VA {va:#x}+{n} out of range for section {self.name!r}")
        return self.data[off:off+n]


@dataclass
class M88kCoffBinary:
    path:         str
    entry:        int           # program entry VA
    text_start:   int           # .text base VA
    data_start:   int           # .data base VA
    sections:     List[Section] = field(default_factory=list)
    _sec_map:     Dict[str, Section] = field(default_factory=dict, repr=False)

    def section(self, name: str) -> Optional[Section]:
        return self._sec_map.get(name)

    @property
    def text(self) -> Optional[Section]:
        return self._sec_map.get(".text")

    @property
    def data(self) -> Optional[Section]:
        return self._sec_map.get(".data")

    def va_to_bytes(self, va: int, n: int) -> bytes:
        for sec in self.sections:
            if sec.contains_va(va):
                return sec.read_bytes(va, n)
        raise KeyError(f"no section covers VA {va:#x}")

    def words_at(self, va: int, count: int) -> List[int]:
        """Return count big-endian 32-bit words starting at va."""
        raw = self.va_to_bytes(va, count * 4)
        return [struct.unpack_from(">I", raw, i*4)[0] for i in range(count)]


def parse(path: str | Path) -> M88kCoffBinary:
    """Parse an M88K BCS COFF executable and return an M88kCoffBinary."""
    raw = Path(path).read_bytes()

    if len(raw) < _FILE_HDR_SZ:
        raise ValueError(f"file too short for COFF header: {len(raw)} bytes")

    magic, nscns, timdat, symptr, nsyms, opthdr_sz, flags = struct.unpack_from(
        _FILE_HDR_FMT, raw, 0
    )
    if magic != M88K_BCS_MAGIC:
        raise ValueError(f"not an M88K BCS COFF: magic={magic:#06x}")

    # Optional header
    entry = 0
    text_start = 0
    data_start = 0
    if opthdr_sz >= _OPT_HDR_SZ:
        _, _, tsize, dsize, bsize, entry, text_start, data_start = struct.unpack_from(
            _OPT_HDR_FMT, raw, _FILE_HDR_SZ
        )

    # Section headers
    scn_base = _FILE_HDR_SZ + opthdr_sz
    sections: List[Section] = []
    sec_map: Dict[str, Section] = {}

    for i in range(nscns):
        off = scn_base + i * _SCNHDR_SZ
        name_raw, paddr, vaddr, size, scnptr, relptr, lnnoptr, nreloc, nlnno, scn_flags = (
            struct.unpack_from(_SCNHDR_FMT, raw, off)
        )
        name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")

        if scnptr > 0 and size > 0 and scnptr + size <= len(raw):
            data = raw[scnptr:scnptr + size]
        else:
            data = b"\x00" * size  # BSS or zero-size

        sec = Section(name=name, vaddr=vaddr, size=size, flags=scn_flags, data=data)
        sections.append(sec)
        sec_map[name] = sec

    return M88kCoffBinary(
        path=str(path),
        entry=entry,
        text_start=text_start,
        data_start=data_start,
        sections=sections,
        _sec_map=sec_map,
    )
