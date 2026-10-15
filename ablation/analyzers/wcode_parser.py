"""
wcode_parser.py: IBM W-Code (XLC internal IR) binary record parser.

W-Code is IBM XLC's proprietary intermediate representation used between the
front-end (xlCentry) and back-end (xlCcode) compilation stages. W-Code records
encode references to IBM compiler builtins — POWER-specific intrinsics, vector
operations, MASS math library calls, and IBM-internal control flow nodes.

This module provides:
  - WCodeRecord: a parsed W-Code binary builtin record
  - WCodeBuiltinCatalog: the builtin descriptor table extracted from xlCentry
  - WCodeParser: scanner for W-Code IR data (e.g., embedded in XLC .o files)

Format discovery:
  RE of xlCentry 16.1.1.3 ppc64le (path: exe/xlCentry in xlc.16.1.1_16.1.1.3-190404_ppc64el.deb)
  WcB_Lookup_Bif @ 0x11d88d00: parses binary W-Code records using lwbrx/lhbrx (byte-reversed
  loads), confirming the on-disk format is big-endian regardless of host endianness.

W-Code binary builtin record format (big-endian on disk):
  +0x00  uint32 BE   type_field_0    compared against WCB table entry +0x00
  +0x04  uint32 BE   type_field_1    compared against WCB table entry +0x08
  +0x08  uint16 BE   type_field_2    compared against WCB table entry (halfword)
  +0x0a  char[]      builtin_name    null-terminated; leading underscores stripped before lookup
  Total: 10 + len(name) + 1 bytes minimum

Short form (length <= 10): skip type-field comparison, name only.

W-Code builtin catalog in xlCentry 16.1.1.3:
  Table base:    TOC - 0x26720 = 0x12601960  (TOC = 0x12628080)
  Entry size:    0x28 bytes (40 bytes)
  Entry count:   2000+ entries
  Entry layout:
    +0x00  uint64 LE   field_0 (type ID or small integer)
    +0x08  uint64 LE   field_8 (parameter info or small integer)
    +0x10  uint64 LE   name_ptr (pointer to null-terminated name string in names pool)
    +0x18  uint32 LE   arch_mask (architecture compatibility ID; 0 = any)
    +0x1c  uint32 LE   pad
    +0x20  uint64 LE   field_20 (additional type info)
  Names pool:  0x11fe6010 (8-byte aligned null-terminated strings; names > 7 chars span blocks)

Hash table (for name lookup):
  Descriptor:  TOC + 0x416c0 = 0x126a96c0  (lhz capacity + ld bucket_array)
  Hash fn:     djb2 variant: h = h * 31 + c  (sldi r7,r0,5; subf r0,r0,r7; add r0,r0,r8)
  Bucket:      16-bit entry index into WCB table (0 = empty slot)
  Collision:   chain following via lhzx probes

Sample builtins:
  fltint, hscmplx, relax, rsqrt, rngchk, single, gcclongdouble, overflow,
  zerodivide, enable, imprecise, store, comment, linecont, reserve, preserve,
  cnv, par, pro, use, private, reduction, nooffset, aix, gnu, lute, large,
  smt, smt2, smt4, smt8, blend, balanced, fold, rrm, maf

Usage:
    from ablation.analyzers.wcode_parser import WCodeParser
    parser = WCodeParser('/path/to/xlCentry')
    catalog = parser.load_catalog()
    rec = WCodeParser.decode_record(b'\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x14\\x00\\x04fltint\\x00')
    if rec:
        info = catalog.lookup(rec)
        print(f"{rec.name!r}: arch_mask={info.arch_mask if info else 'unknown'}")
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class WCodeRecord:
    """A decoded W-Code binary builtin record."""
    type_field_0: int   # +0x00: uint32 BE
    type_field_1: int   # +0x04: uint32 BE
    type_field_2: int   # +0x08: uint16 BE
    name: str           # builtin name (leading underscores stripped)
    raw: bytes          # original bytes including 10-byte header
    short_form: bool    # True if record length <= 10 (type fields not compared)


@dataclass
class WCBEntry:
    """An entry from the W-Code builtin catalog in xlCentry."""
    index: int
    name: str
    arch_mask: int      # architecture compatibility (0 = any POWER)
    field_0: int        # type field at +0x00
    field_8: int        # type field at +0x08
    field_20: int       # type field at +0x20
    name_ptr: int       # VA of name string in xlCentry binary


class WCodeBuiltinCatalog:
    """
    W-Code builtin catalog extracted from an xlCentry binary.

    Contains the 2000+ entry WCB table that maps builtin IDs to descriptors.
    Used to look up type info and architecture requirements for a WCodeRecord.
    """

    # xlCentry 16.1.1.3 ppc64le constants
    XLCENTRY_BASE_VA = 0x10000000
    XLCENTRY_TOC     = 0x12628080
    WCB_TABLE_VA     = 0x12601960   # TOC - 0x20000 - 0x6720
    WCB_ENTRY_SIZE   = 0x28
    NAMES_POOL_VA    = 0x11fe6010

    def __init__(self) -> None:
        self._by_name: Dict[str, WCBEntry] = {}
        self._by_index: Dict[int, WCBEntry] = {}

    @classmethod
    def from_binary(cls, xlcentry_path: str) -> 'WCodeBuiltinCatalog':
        """
        Load the WCB catalog from an xlCentry binary.

        Args:
            xlcentry_path: path to the xlCentry ELF binary (exe/xlCentry from
                           xlc.16.1.1_*.deb).
        """
        catalog = cls()
        data = Path(xlcentry_path).read_bytes()
        base = cls.XLCENTRY_BASE_VA
        table_off = cls.WCB_TABLE_VA - base
        names_off = cls.NAMES_POOL_VA - base

        if table_off < 0 or table_off >= len(data):
            return catalog
        if names_off < 0 or names_off >= len(data):
            return catalog

        def read_name(va: int) -> str:
            off = va - base
            if off < 0 or off >= len(data):
                return ''
            raw = data[off:off+64].split(b'\x00')[0]
            try:
                return raw.decode('ascii', errors='replace')
            except Exception:
                return ''

        for i in range(4096):
            off = table_off + i * cls.WCB_ENTRY_SIZE
            if off + cls.WCB_ENTRY_SIZE > len(data):
                break
            entry_bytes = data[off:off + cls.WCB_ENTRY_SIZE]
            f0   = struct.unpack_from('<Q', entry_bytes, 0)[0]
            f8   = struct.unpack_from('<Q', entry_bytes, 8)[0]
            nptr = struct.unpack_from('<Q', entry_bytes, 16)[0]
            arch_field = struct.unpack_from('<I', entry_bytes, 24)[0]
            f20  = struct.unpack_from('<Q', entry_bytes, 32)[0]

            if nptr == 0 and f0 == 0 and f8 == 0:
                continue  # sparse/empty entry

            # Only trust nptr as a name pointer if it looks like a valid xlCentry VA
            name = ''
            if 0x10000000 <= nptr <= 0x12800000:
                name = read_name(nptr)

            if not name:
                continue

            entry = WCBEntry(
                index=i,
                name=name,
                arch_mask=arch_field,
                field_0=f0,
                field_8=f8,
                field_20=f20,
                name_ptr=nptr,
            )
            catalog._by_index[i] = entry
            catalog._by_name[name] = entry

        return catalog

    def lookup(self, rec: WCodeRecord) -> Optional[WCBEntry]:
        """Find the catalog entry matching a decoded W-Code record by name."""
        return self._by_name.get(rec.name)

    def lookup_name(self, name: str) -> Optional[WCBEntry]:
        """Find the catalog entry for a given builtin name."""
        return self._by_name.get(name)

    def __len__(self) -> int:
        return len(self._by_name)

    def arch_mask_to_name(self, arch_mask: int) -> str:
        """Map an arch_mask integer to a human-readable POWER generation string."""
        _MAP = {
            0: 'any',
            1: 'POWER1',
            2: 'POWER2',
            3: 'POWER3',
            4: 'POWER4',
            5: 'POWER5',
            6: 'POWER6',
            7: 'POWER7',
            8: 'POWER8',
            9: 'POWER9',
            10: 'POWER10',
        }
        return _MAP.get(arch_mask, f'arch_{arch_mask:#x}')


# ──────────────────────────────────────────────────────────────────────────────
# Parser
# ──────────────────────────────────────────────────────────────────────────────

class WCodeParser:
    """
    Parser for W-Code IR data streams.

    W-Code files are IBM XLC's proprietary intermediate representation.
    They are typically embedded in XLC-compiled .o files or generated as
    standalone IR files by invoking xlc with IR output flags.

    The on-disk format is big-endian (even on ppc64le hosts) as confirmed by
    the lwbrx/lhbrx (byte-reversed load) instructions in WcB_Lookup_Bif.
    """

    def __init__(self, xlcentry_path: Optional[str] = None) -> None:
        self._xlcentry = xlcentry_path
        self._catalog: Optional[WCodeBuiltinCatalog] = None

    def load_catalog(self) -> WCodeBuiltinCatalog:
        """Load the WCB builtin catalog from the xlCentry binary."""
        if self._catalog is None:
            if self._xlcentry:
                self._catalog = WCodeBuiltinCatalog.from_binary(self._xlcentry)
            else:
                self._catalog = WCodeBuiltinCatalog()
        return self._catalog

    @staticmethod
    def name_hash(name: str) -> int:
        """
        Compute the W-Code builtin name hash.

        djb2 variant: h = h * 31 + c
        Extracted from WcB_Name_Hash at 0x11d88e40 in xlCentry 16.1.1.3.
        Loop: sldi r7, r0, 5; subf r0, r0, r7; add r0, r0, r8
          => r0 = r0 - (r0 << 5) + char = r0 * (1-32) + char = r0*(-31) + char
          => but with uint32 truncation (slwi r0, r0, 0): h = (h * 31 + c) & 0xFFFFFFFF
        """
        h = 0
        for c in name.encode('ascii', errors='replace'):
            h = ((h * 31) + c) & 0xFFFFFFFF
        return h

    @staticmethod
    def decode_record(data: bytes, offset: int = 0) -> Optional[WCodeRecord]:
        """
        Decode one W-Code binary builtin record from data at the given offset.

        Returns None if the data at offset is not a valid record.
        """
        if offset + 10 >= len(data):
            return None

        avail = len(data) - offset
        short_form = avail <= 10

        if not short_form:
            # Read 10-byte header (all big-endian)
            f0, f1, f2 = struct.unpack_from('>IIH', data, offset)
        else:
            f0, f1, f2 = 0, 0, 0

        name_start = offset + (0 if short_form else 10)
        # Read null-terminated name, stripping leading underscores
        name_end = data.find(b'\x00', name_start)
        if name_end < 0:
            name_end = min(name_start + 64, len(data))
        raw_name = data[name_start:name_end].decode('ascii', errors='replace')
        name = raw_name.lstrip('_')
        if not name:
            return None

        total_len = name_end + 1 - offset
        raw = data[offset:offset + total_len]

        return WCodeRecord(
            type_field_0=f0,
            type_field_1=f1,
            type_field_2=f2,
            name=name,
            raw=raw,
            short_form=short_form,
        )

    def scan(self, data: bytes) -> List[WCodeRecord]:
        """
        Scan a byte stream for W-Code builtin record sequences.

        W-Code IR files contain back-to-back records. This method is a
        best-effort scanner; a proper file-header parser would need the
        W-Code file magic and section layout (not yet fully reversed).

        Returns a list of decoded records found in the stream.
        """
        records: List[WCodeRecord] = []
        offset = 0
        while offset < len(data) - 10:
            rec = self.decode_record(data, offset)
            if rec:
                records.append(rec)
                offset += len(rec.raw)
            else:
                offset += 1
        return records

    def report(self, records: Optional[List[WCodeRecord]] = None,
               data: Optional[bytes] = None) -> str:
        """Produce a human-readable summary of W-Code records."""
        if records is None and data is not None:
            records = self.scan(data)
        if not records:
            return 'No W-Code records found.'

        catalog = self.load_catalog()
        lines = [f'W-Code records: {len(records)}']
        for rec in records:
            entry = catalog.lookup(rec)
            arch = catalog.arch_mask_to_name(entry.arch_mask) if entry else 'unknown'
            lines.append(f'  {rec.name!r:24s} type=({rec.type_field_0:#010x},{rec.type_field_1:#010x},{rec.type_field_2:#06x})'
                         f' arch={arch}')
        return '\n'.join(lines)
