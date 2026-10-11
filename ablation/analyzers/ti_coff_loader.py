"""
TI COFF object file and AR archive parser.

Parses Texas Instruments COFF2 object files (.obj) and AR archives (.a) produced
by the TI Code Generation Tools (cl2000, c29clang, tiarmclang).  Extracts symbol
table entries including storage class, value, and section binding.

Supported formats:
    TI COFF2 object file   magic 0x00C2 at bytes 0-1
    Unix AR archive        magic '!<arch>\\n' at bytes 0-7, members are COFF2

Target IDs (f_target_id at bytes 20-21 of COFF2 file header):
    0x0099  TMS320C6000
    0x009C  TMS320C5500
    0x009D  TMS320C2800  (C28x — the NNC F28x target)
    0x00A1  TMS320C5500+

Symbol storage classes (byte 16 of 18-byte symbol table entry):
    C_EXT    2   External definition (strong global)
    C_STAT   3   Static (local)
    C_EXTREF 5   External reference (undefined import)
    C_LABEL  6   Label
    C_UEXT   19  Tentative external definition — TI COFF equivalent of weak symbol
                 A C_UEXT symbol can be overridden by a C_EXT definition at link time.
                 cl2000 maps __attribute__((weak)) to this storage class.

Reference: SPRAAO8 — TI Common Object File Format (April 2009).

Usage::

    from ablation.analyzers.ti_coff_loader import TiCoffLoader

    loader = TiCoffLoader.from_path('/path/to/mod.a')
    for sym in loader.symbols():
        print(sym.name, sym.storage_class_name, hex(sym.value))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

# ---------------------------------------------------------------------------
# Format constants
# ---------------------------------------------------------------------------

_COFF2_MAGIC       = 0x00C2   # TI COFF version 2 (bytes 0-1)
_COFF1_MAGIC       = 0x00C1   # TI COFF version 1 (bytes 0-1)
_AR_MAGIC          = b'!<arch>\n'  # Unix AR archive magic

# f_target_id values (bytes 20-21)
TI_TARGET_C2800    = 0x009D   # TMS320C2800 (C28x)
TI_TARGET_C6000    = 0x0099   # TMS320C6000
TI_TARGET_C5500    = 0x009C   # TMS320C5500
TI_TARGET_C5500P   = 0x00A1   # TMS320C5500+
TI_TARGET_MSP430   = 0x00A0   # MSP430

_TARGET_NAMES = {
    TI_TARGET_C2800:  'TMS320C2800',
    TI_TARGET_C6000:  'TMS320C6000',
    TI_TARGET_C5500:  'TMS320C5500',
    TI_TARGET_C5500P: 'TMS320C5500+',
    TI_TARGET_MSP430: 'MSP430',
}

# Storage class values
C_NULL   =  0
C_EXT    =  2   # External definition (strong global)
C_STAT   =  3   # Static
C_EXTREF =  5   # External reference (undefined import)
C_LABEL  =  6   # Label
C_UEXT   = 19   # Tentative external = TI weak symbol

_SCLASS_NAMES = {
    C_NULL:   'C_NULL',
    C_EXT:    'C_EXT',
    C_STAT:   'C_STAT',
    C_EXTREF: 'C_EXTREF',
    C_LABEL:  'C_LABEL',
    C_UEXT:   'C_UEXT',
}

# COFF2 file header: 22 bytes
# [0:2] f_magic, [2:4] f_nscns, [4:8] f_timdat, [8:12] f_symptr,
# [12:16] f_nsyms, [16:18] f_opthdr, [18:20] f_flags, [20:22] f_target_id
_FH_STRUCT = struct.Struct('<HHIIIHHH')   # 7 fields = 2+2+4+4+4+2+2+2 = 22 bytes

# COFF2 section header: 48 bytes
# [0:8] name, [8:12] paddr, [12:16] vaddr, [16:20] size, [20:24] scnptr,
# [24:28] relptr, [28:32] reserved, [32:36] nreloc, [36:40] nlnno,
# [40:44] flags, [44:46] reserved, [46:48] page
_SH_STRUCT = struct.Struct('<8sIIIIIIIIIHH')  # 12 fields = 48 bytes

# COFF symbol table entry: 18 bytes
# [0:8] name or (0 + stroff), [8:12] value, [12:14] scnum, [14:16] type,
# [16] sclass, [17] numaux
_SYM_STRUCT = struct.Struct('<8sIhHBB')   # 6 fields = 18 bytes

# AR archive member header: 60 bytes
_AR_HDR_STRUCT = struct.Struct('16s12s6s6s8s10s2s')  # 7 fields = 60 bytes
_AR_HDR_SIZE = 60


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CoffSymbol:
    name: str
    value: int
    section_number: int   # 0=undefined external, -1=absolute, 1+=section index
    storage_class: int
    member_name: str = ''  # AR member this came from, if applicable

    @property
    def storage_class_name(self) -> str:
        return _SCLASS_NAMES.get(self.storage_class, f'C_{self.storage_class}')

    @property
    def is_weak(self) -> bool:
        """True if this symbol can be overridden at link time (C_UEXT)."""
        return self.storage_class == C_UEXT

    @property
    def is_global(self) -> bool:
        return self.storage_class == C_EXT

    @property
    def is_defined(self) -> bool:
        """True if the symbol has a definition in this object (section_number > 0)."""
        return self.section_number > 0

    @property
    def is_undefined(self) -> bool:
        return self.section_number == 0 and self.storage_class == C_EXTREF


@dataclass
class CoffFileHeader:
    magic: int
    n_sections: int
    sym_ptr: int     # file offset to symbol table
    n_syms: int
    opt_hdr_size: int
    flags: int
    target_id: int

    @property
    def target_name(self) -> str:
        return _TARGET_NAMES.get(self.target_id, f'0x{self.target_id:04X}')

    @property
    def is_c28x(self) -> bool:
        return self.target_id == TI_TARGET_C2800

    @property
    def is_little_endian(self) -> bool:
        return bool(self.flags & 0x0100)  # F_LENDIAN / F_LITTLE


@dataclass
class TiCoffObject:
    """A parsed TI COFF object file (one member of a .a archive, or a standalone .obj)."""
    member_name: str
    header: CoffFileHeader
    symbols: List[CoffSymbol]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class TiCoffLoader:
    """
    Parses TI COFF2 object files and AR archives (.a).

    Extracts symbol table entries for all members.  For the TiNNCScanner use
    case, the primary interest is C_UEXT symbols (tentative externals = weak)
    and C_EXT symbols (strong globals).
    """

    def __init__(self, data: bytes, path: str = '') -> None:
        self._data = data
        self._path = path
        self._objects: List[TiCoffObject] = []
        self._parsed = False

    @classmethod
    def from_path(cls, path: str | Path) -> 'TiCoffLoader':
        data = Path(path).read_bytes()
        return cls(data, str(path))

    @classmethod
    def from_bytes(cls, data: bytes) -> 'TiCoffLoader':
        return cls(data)

    # ------------------------------------------------------------------

    def parse(self) -> None:
        if self._parsed:
            return
        self._parsed = True
        data = self._data

        if data[:8] == _AR_MAGIC:
            self._objects = list(self._parse_ar(data))
        elif len(data) >= 22:
            magic = struct.unpack_from('<H', data, 0)[0]
            if magic in (_COFF2_MAGIC, _COFF1_MAGIC):
                obj = self._parse_coff_object(data, 0, '<standalone>')
                if obj:
                    self._objects = [obj]

    def symbols(self) -> Iterator[CoffSymbol]:
        self.parse()
        for obj in self._objects:
            yield from obj.symbols

    def objects(self) -> List[TiCoffObject]:
        self.parse()
        return list(self._objects)

    def is_ar(self) -> bool:
        return self._data[:8] == _AR_MAGIC

    def is_coff(self) -> bool:
        if len(self._data) < 2:
            return False
        magic = struct.unpack_from('<H', self._data, 0)[0]
        return magic in (_COFF2_MAGIC, _COFF1_MAGIC)

    # ------------------------------------------------------------------
    # AR parsing
    # ------------------------------------------------------------------

    def _parse_ar(self, data: bytes) -> Iterator[TiCoffObject]:
        offset = 8  # skip magic
        size = len(data)

        while offset + _AR_HDR_SIZE <= size:
            raw = _AR_HDR_STRUCT.unpack_from(data, offset)
            member_name_raw = raw[0].rstrip(b' /')
            file_size_raw = raw[5].rstrip(b' \x00')
            end_magic = raw[6]
            offset += _AR_HDR_SIZE

            if end_magic != b'`\n':
                break

            try:
                member_size = int(file_size_raw)
            except ValueError:
                break

            member_name = member_name_raw.decode('ascii', errors='replace').strip()

            # Skip the AR symbol table members (names start with '/' or '//')
            if not member_name.startswith('/'):
                member_data = data[offset:offset + member_size]
                if len(member_data) >= 22:
                    inner_magic = struct.unpack_from('<H', member_data, 0)[0]
                    if inner_magic in (_COFF2_MAGIC, _COFF1_MAGIC):
                        obj = self._parse_coff_object(member_data, 0, member_name)
                        if obj:
                            yield obj

            offset += member_size
            if offset % 2:
                offset += 1  # AR pads members to even byte boundary

    # ------------------------------------------------------------------
    # COFF object parsing
    # ------------------------------------------------------------------

    def _parse_coff_object(
        self, data: bytes, base: int, member_name: str
    ) -> Optional[TiCoffObject]:
        if base + 22 > len(data):
            return None
        try:
            fh_raw = _FH_STRUCT.unpack_from(data, base)
        except struct.error:
            return None

        magic, n_scns, timdat, symptr, nsyms, opthdr, flags, target_id = fh_raw
        if magic not in (_COFF2_MAGIC, _COFF1_MAGIC):
            return None

        hdr = CoffFileHeader(
            magic=magic,
            n_sections=n_scns,
            sym_ptr=symptr,
            n_syms=nsyms,
            opt_hdr_size=opthdr,
            flags=flags,
            target_id=target_id,
        )

        syms = list(self._parse_symbols(data, base, hdr))
        return TiCoffObject(member_name=member_name, header=hdr, symbols=syms)

    def _parse_symbols(
        self, data: bytes, base: int, hdr: CoffFileHeader
    ) -> Iterator[CoffSymbol]:
        if not hdr.n_syms or not hdr.sym_ptr:
            return

        sym_off = base + hdr.sym_ptr
        strtab_off = sym_off + hdr.n_syms * 18
        strtab_size = struct.unpack_from('<I', data, strtab_off)[0] if strtab_off + 4 <= len(data) else 0

        i = 0
        while i < hdr.n_syms:
            off = sym_off + i * 18
            if off + 18 > len(data):
                break
            try:
                raw = _SYM_STRUCT.unpack_from(data, off)
            except struct.error:
                break

            name_bytes, value, scnum, stype, sclass, numaux = raw

            # Resolve name
            if name_bytes[:4] == b'\x00\x00\x00\x00':
                str_offset = struct.unpack_from('<I', name_bytes, 4)[0]
                name = self._read_strtab(data, strtab_off, strtab_size, str_offset)
            else:
                name = name_bytes.rstrip(b'\x00').decode('ascii', errors='replace')

            if name and not name.startswith('.') and not name.startswith('$'):
                yield CoffSymbol(
                    name=name,
                    value=value,
                    section_number=int(scnum),
                    storage_class=sclass,
                )

            i += 1 + numaux  # skip auxiliary entries

    @staticmethod
    def _read_strtab(
        data: bytes, strtab_off: int, strtab_size: int, offset: int
    ) -> str:
        if not strtab_off or offset < 4 or strtab_off + offset >= len(data):
            return ''
        end = data.find(b'\x00', strtab_off + offset)
        if end == -1:
            return ''
        return data[strtab_off + offset:end].decode('ascii', errors='replace')
