"""
go_x86_strip_scanner.py — Go pclntab function-boundary recovery for stripped x86-64 binaries.

Why this exists
---------------

1. **Gap: BinaryContext yields only 3 func_starts for stripped Go x86-64 binaries.**
   Go's linker (-ldflags="-s -w") strips DWARF and symbol tables but ALWAYS embeds
   the pclntab (.gopclntab) because the runtime needs it for stack unwinding and panic
   output. Stripped binaries have no .gopclntab section header (only .text and .rodata
   survive the strip), so BinaryContext's ELF-based function start extraction fails.
   Result: fos_server (21 MB, Go 1.22.6, x86-64) → 3 func_starts instead of 23,396.

2. **Gap: SemanticSearcher, FuncProfiler, and TaintTracker are useless with 3 boundaries.**
   Every ablation tool that iterates ctx.func_starts to slice function windows gets
   effectively empty coverage. A pclntab-based recovery restores full function coverage.

3. **Gap: pclntab magic bytes and pcHeader layout differ across Go versions.**
   Go 1.2–1.17 use one layout; Go 1.18–1.19 another; Go 1.20+ a third. The pcHeader
   struct in Go 1.20+ (magic 0xfffffff1) stores textStart, funcnameOffset, and pclnOffset
   as separate fields. Without version-aware parsing, magic search produces false positives
   (raw data hits the older byte patterns).

This module resolves all three:
  • Finds pclntab in stripped x86-64 ELF by scanning .rodata for validated pcHeader magic
  • Parses pcHeader for Go 1.20+ (0xfffffff1), 1.18 (0xfffffff0), 1.16 (0xfffffffa),
    and 1.2 (0xfffffffb) layouts
  • Extracts all function start VAs from the function table (entry_rel + textStart)
  • Recovers function names from funcnametab (null-terminated strings at funcoff offsets)
  • patch_context(ctx): adds recovered VAs to ctx.func_starts and sets ctx names

Usage
-----
    from ablation.analyzers.go_x86_strip_scanner import GoX86StripScanner
    from ablation.analyzers.binary_context import BinaryContext

    ctx = BinaryContext.load_or_build('/path/to/stripped_go_binary')
    scanner = GoX86StripScanner.from_context(ctx)
    result = scanner.scan()
    print(result.summary())

    # Patch ctx so all downstream tools see the recovered function boundaries:
    scanner.patch_context(ctx)
    # ctx.func_starts now has all pclntab-recovered VAs
    # ctx.name(va) returns recovered names where available

    # Or without BinaryContext:
    scanner = GoX86StripScanner.from_path('/path/to/binary')
    result = scanner.scan()
    for va, name in sorted(result.funcs.items()):
        print(f'0x{va:x}  {name}')
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Go pclntab magic constants (stored little-endian in x86-64 binaries)
# ---------------------------------------------------------------------------

_MAGIC_GO120 = 0xfffffff1   # Go 1.20+   (pcHeader layout v3)
_MAGIC_GO118 = 0xfffffff0   # Go 1.18–1.19 (pcHeader layout v2)
_MAGIC_GO116 = 0xfffffffa   # Go 1.16–1.17 (pcHeader layout v2)
_MAGIC_GO12  = 0xfffffffb   # Go 1.2–1.15  (pcHeader layout v1)

_MAGIC_VERSIONS = {
    _MAGIC_GO120: 'Go1.20+',
    _MAGIC_GO118: 'Go1.18-1.19',
    _MAGIC_GO116: 'Go1.16-1.17',
    _MAGIC_GO12:  'Go1.2-1.15',
}

_HDR_MAGIC   = struct.Struct('<I')
_HDR_FIELDS  = struct.Struct('<BBBB')    # pad1 pad2 quantum ptrSize
_HDR_I64     = struct.Struct('<q')       # nfunc (int)
_HDR_U64     = struct.Struct('<Q')       # nfiles, uintptr fields
_FUNCTAB_ENT = struct.Struct('<II')      # entryOff, funcoff (Go 1.20+)
_FUNCTAB_ENT_V1 = struct.Struct('<QI')  # entry uintptr + funcoff uint32 (Go 1.2–1.17 64-bit)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class GoScanResult:
    """Results of a pclntab scan on a stripped Go x86-64 binary."""

    binary_path: str

    # All recovered function start VAs (VA → name or '')
    funcs: Dict[int, str] = field(default_factory=dict)

    # Metadata
    go_version: str = ''
    text_start: int = 0
    nfunc: int = 0
    pclntab_file_off: int = 0

    @property
    def func_starts(self) -> List[int]:
        return sorted(self.funcs.keys())

    @property
    def named_funcs(self) -> Dict[int, str]:
        return {va: n for va, n in self.funcs.items() if n}

    def summary(self) -> str:
        named = len(self.named_funcs)
        lines = [
            f"GoScanResult({self.binary_path})",
            f"  Go version : {self.go_version}",
            f"  pclntab    : file offset 0x{self.pclntab_file_off:x}",
            f"  textStart  : 0x{self.text_start:x}",
            f"  nfunc      : {self.nfunc}  (recovered {len(self.funcs)}, named {named})",
        ]
        if self.funcs:
            sample = sorted(self.named_funcs.items())[:5]
            for va, name in sample:
                lines.append(f"    0x{va:x}  {name}")
            if named > 5:
                lines.append(f"    ... ({named - 5} more named)")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class GoX86StripScanner:
    """Recovers function boundaries from pclntab in stripped x86-64 Go ELF binaries.

    Works on binaries where DWARF and .symtab have been stripped but the pclntab
    remains embedded in .rodata (always the case in Go — the runtime requires it).
    """

    def __init__(self, path: str, data: bytes):
        self._path = path
        self._data = data
        self._result: Optional[GoScanResult] = None

    @classmethod
    def from_path(cls, path: str) -> 'GoX86StripScanner':
        data = open(path, 'rb').read()
        return cls(path, data)

    @classmethod
    def from_context(cls, ctx) -> 'GoX86StripScanner':
        return cls.from_path(ctx.path)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def is_go_x86_64(path: str) -> bool:
        """Return True if path is a stripped x86-64 Go ELF binary."""
        try:
            with open(path, 'rb') as f:
                hdr = f.read(20)
            if hdr[:4] != b'\x7fELF':
                return False
            if hdr[4] != 2 or hdr[5] != 1:  # ELFCLASS64, ELFDATA2LSB
                return False
            e_machine = struct.unpack_from('<H', hdr, 18)[0]
            return e_machine == 62  # EM_X86_64
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Core scan
    # ------------------------------------------------------------------

    def scan(self) -> GoScanResult:
        if self._result is not None:
            return self._result

        data = self._data

        # Step 1: find a valid pcHeader by scanning for known magic bytes
        pclntab_off, magic = self._find_pclntab(data)
        if pclntab_off is None:
            result = GoScanResult(binary_path=self._path, go_version='unknown')
            self._result = result
            return result

        go_ver = _MAGIC_VERSIONS[magic]
        result = GoScanResult(
            binary_path=self._path,
            go_version=go_ver,
            pclntab_file_off=pclntab_off,
        )

        # Step 2: parse pcHeader and extract function table
        if magic == _MAGIC_GO120 or magic == _MAGIC_GO118:
            self._parse_v3_header(data, pclntab_off, result)
        elif magic == _MAGIC_GO116:
            self._parse_v2_header(data, pclntab_off, result)
        else:
            self._parse_v1_header(data, pclntab_off, result)

        self._result = result
        return result

    # ------------------------------------------------------------------
    # pcHeader parsing — Go 1.20+ / 1.18 (layout v3)
    # ------------------------------------------------------------------

    def _parse_v3_header(self, data: bytes, off: int, result: GoScanResult) -> None:
        """Parse Go 1.18+ pcHeader layout.

        Layout (little-endian, 64-bit):
          [0:4]   magic     uint32
          [4]     pad1      uint8
          [5]     pad2      uint8
          [6]     minLC     uint8  (instruction size quantum)
          [7]     ptrSize   uint8
          [8:16]  nfunc     int64
          [16:24] nfiles    uint64
          [24:32] textStart uintptr
          [32:40] funcnameOffset uintptr
          [40:48] cuOffset  uintptr
          [48:56] filetabOffset uintptr
          [56:64] pctabOffset uintptr
          [64:72] pclnOffset  uintptr  (function table offset within pclntab)
        """
        if off + 72 > len(data):
            return

        nfunc       = struct.unpack_from('<q', data, off + 8)[0]
        text_start  = struct.unpack_from('<Q', data, off + 24)[0]
        fname_off   = struct.unpack_from('<Q', data, off + 32)[0]   # funcnameOffset
        cu_off      = struct.unpack_from('<Q', data, off + 40)[0]   # cuOffset = funcnametab end
        pcln_off    = struct.unpack_from('<Q', data, off + 64)[0]   # pclnOffset (function table)

        result.nfunc = nfunc
        result.text_start = text_start

        fname_base  = off + fname_off                               # file offset of funcnametab
        ftab_base   = off + pcln_off                                # file offset of function table

        if ftab_base + (nfunc + 1) * 8 > len(data):
            return

        # Build offset→name map from funcnametab (null-terminated strings).
        # Scan through cuOffset (the funcnametab/cutab boundary) to cover the full name space.
        offset_to_name = self._build_name_map(data, fname_base, off + cu_off)

        # Extract function VAs and names from the function table.
        # Each functab entry: {entryOff uint32, funcoff uint32}
        # funcoff is an offset within ftab_base to the _Func struct.
        # _Func layout (Go 1.20+): [0:4] entryOff uint32, [4:8] nameOff int32, ...
        # nameOff is an offset into funcnametab (fname_base).
        for i in range(nfunc):
            entry_rel, funcoff = _FUNCTAB_ENT.unpack_from(data, ftab_base + i * 8)
            va = text_start + entry_rel
            name = ''
            func_file_off = ftab_base + funcoff
            if func_file_off + 8 <= len(data):
                name_off = struct.unpack_from('<i', data, func_file_off + 4)[0]
                if name_off >= 0:
                    name = offset_to_name.get(name_off, '')
            result.funcs[va] = name

    # ------------------------------------------------------------------
    # pcHeader parsing — Go 1.16–1.17 (layout v2, but functab uses 64-bit entries)
    # ------------------------------------------------------------------

    def _parse_v2_header(self, data: bytes, off: int, result: GoScanResult) -> None:
        """Parse Go 1.16–1.17 pcHeader layout (64-bit entries in functab)."""
        if off + 32 > len(data):
            return

        # Go 1.16 pcHeader: magic(4) + pad(2) + quantum(1) + ptrsize(1) + nfunc(8) + nfiles(8)
        nfunc      = struct.unpack_from('<q', data, off + 8)[0]
        # textStart not in pcHeader for Go 1.16 — use 0 (relative entries are absolute VAs)
        result.nfunc = nfunc

        # functab follows the pcHeader at offset 0x20 (or just after nfiles)
        ftab_base = off + 0x20
        for i in range(nfunc):
            entry_va = struct.unpack_from('<Q', data, ftab_base + i * 12)[0]
            result.funcs[entry_va] = ''

    # ------------------------------------------------------------------
    # pcHeader parsing — Go 1.2–1.15 (layout v1, 64-bit ptrs on x86-64)
    # ------------------------------------------------------------------

    def _parse_v1_header(self, data: bytes, off: int, result: GoScanResult) -> None:
        """Parse Go 1.2–1.15 pclntab layout.

        Layout: magic(4) pad(2) quantum(1) ptrsize(1) nfunc(8 on amd64)
        Then nfunc function table entries: (entry uintptr, funcoff uint32) = 12 bytes each.
        """
        if off + 16 > len(data):
            return

        nfunc = struct.unpack_from('<Q', data, off + 8)[0]
        result.nfunc = nfunc
        ftab_base = off + 16

        for i in range(nfunc):
            entry_va = struct.unpack_from('<Q', data, ftab_base + i * 12)[0]
            result.funcs[entry_va] = ''

    # ------------------------------------------------------------------
    # Name map builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_name_map(data: bytes, fname_base: int, fname_limit: int) -> Dict[int, str]:
        """Build a map of byte_offset_in_funcnametab → function_name.

        Scans the funcnametab as a sequence of null-terminated UTF-8 strings.
        Each string's position (relative to fname_base) is its key.
        """
        offset_to_name: Dict[int, str] = {}
        fname_limit = min(fname_limit, len(data))
        pos = fname_base
        while pos < fname_limit:
            start = pos
            end = data.find(b'\x00', pos, fname_limit)
            if end == -1:
                break
            raw = data[start:end]
            if raw:
                try:
                    name = raw.decode('utf-8', errors='replace')
                except Exception:
                    name = ''
                offset_to_name[start - fname_base] = name
            pos = end + 1
        return offset_to_name

    # ------------------------------------------------------------------
    # Magic finder
    # ------------------------------------------------------------------

    @staticmethod
    def _find_pclntab(data: bytes) -> Tuple[Optional[int], Optional[int]]:
        """Scan data for a valid Go pclntab pcHeader.

        Validation: magic match + pad bytes 0 + quantum in {1,2,4} + ptrSize in {4,8}.
        quantum encodes the minimum instruction size for the target arch:
          1 = x86, x86-64
          2 = thumb/thumb2
          4 = arm64, arm32, mips, ppc, riscv, s390x
        Accepting all valid quantum values makes this scanner arch-agnostic.
        Returns (file_offset, magic) or (None, None).
        """
        _VALID_QUANTUM = (1, 2, 4)
        _VALID_PTRSIZE = (4, 8)
        search_magics = [_MAGIC_GO120, _MAGIC_GO118, _MAGIC_GO116, _MAGIC_GO12]
        for magic in search_magics:
            magic_bytes = struct.pack('<I', magic)
            pos = 0
            while True:
                idx = data.find(magic_bytes, pos)
                if idx == -1:
                    break
                if idx + 8 <= len(data):
                    pad1 = data[idx + 4]
                    pad2 = data[idx + 5]
                    quantum = data[idx + 6]
                    ptr_sz  = data[idx + 7]
                    if (pad1 == 0 and pad2 == 0
                            and quantum in _VALID_QUANTUM
                            and ptr_sz in _VALID_PTRSIZE):
                        return idx, magic
                pos = idx + 1
        return None, None

    # ------------------------------------------------------------------
    # BinaryContext patch
    # ------------------------------------------------------------------

    def patch_context(self, ctx) -> int:
        """Add recovered function starts to ctx.func_starts and set names.

        Uses ctx.set_names_bulk() to register all pclntab names in a single
        disk write instead of one write per name.  For binaries with tens of
        thousands of Go functions this is the difference between seconds and hours.

        Returns the number of new VAs added to ctx.func_starts.
        """
        result = self.scan()
        if not result.funcs:
            return 0

        existing = set(ctx.func_starts)
        new_vas = []
        bulk: dict = {}
        for va, name in result.funcs.items():
            if va not in existing:
                new_vas.append(va)
            if name:
                bulk[va] = (name, 'pclntab')

        if bulk:
            ctx.set_names_bulk(bulk)

        ctx.func_starts.extend(new_vas)
        ctx.func_starts.sort()

        if new_vas and hasattr(ctx, 'save_cache'):
            ctx.save_cache()

        return len(new_vas)
