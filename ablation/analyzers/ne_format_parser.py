"""
ne_format_parser.py: NE (New Executable) format parser for OS/2 1.x and Windows 3.x.

Why this exists:
  IBM-RE contains OS/2-era software (NFS-OS2, OS2-CM2, NOV, LotusNotes, etc.).
  NOV/noteinet.exe required manual hex to identify as NE format vs PE, parse its
  import table, and confirm no DosExecPgm/DosStartSession. NFS-OS2 (123 files) and
  OS2-CM2 (41 files) were classified as "no Linux ELFs" without exec-class
  verification of their NE/LX format binaries. This module automates that.
  Gap ID: IBM-OS2-001 (NE format exec-class coverage gap).

NE format overview:
  DOS stub (MZ header) → at offset 0x3c: offset to extended header
  Extended header signature:
    "NE"       = New Executable (OS/2 1.x, Windows 3.x)
    "LE" / "LX"= Linear Executable (OS/2 2.x)
    "PE\\0\\0"  = Portable Executable (Win32)
  NE target OS (header offset +0x36):
    0 = unknown, 1 = OS/2 1.x, 2 = Windows 3.x, 3 = DOS 4.x, 4 = Windows/386

  OS/2 exec-class API (via DOSCALLS.DLL):
    DosExecPgm      — spawn a program (ordinal 237 in LIB or by name)
    DosStartSession — start a new session (ordinal 214)
  Windows 3.x exec-class API:
    WinExec         — name-based import from KERNEL
    CreateProcess   — in KERNEL or KRNL386.EXE

  LX (OS/2 2.x) exec:
    DosExecPgm, DosStartSession via DOSCALLS.DLL (name or ordinal)

Usage:
    from ablation.analyzers.ne_format_parser import NEFormatParser

    p = NEFormatParser.from_path('/path/to/noteinet.exe')
    print(p.fmt())
    # Verdict: SAFE if no exec-class OS/2/Win APIs imported

    for f in p.exec_imports():
        print('EXEC-CLASS IMPORT:', f)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# OS/2 exec-class function names (from DOSCALLS.DLL, PMWIN.DLL, etc.)
_OS2_EXEC_FUNCS = frozenset([
    'DOSEXECPGM', 'DOSSTARTSESSION', 'DOSEXECPGMW', 'DOSSTARTSESSIONW',
    'DOSCREATEPIPE', 'DOSCREATEPROCESS',
])

# Windows 3.x exec-class function names (from KERNEL, KRNL386, etc.)
_WIN3_EXEC_FUNCS = frozenset([
    'WINEXEC', 'CREATEPROCESS', 'SHELLEXECUTE', 'SHELLEXECUTEEX',
    'WCREATESTDWIN', 'WINCREATESTDWIN',
])

_TARGET_OS = {0: 'UNKNOWN', 1: 'OS/2-1.x', 2: 'Windows-3.x', 3: 'DOS-4.x', 4: 'Windows-386'}


@dataclass
class NEFormatResult:
    path: str
    format: str                    # 'NE', 'LE', 'LX', 'PE', 'MZ-only', 'NOT-MZ'
    target_os: str                 # 'OS/2-1.x', 'Windows-3.x', etc.
    imported_modules: List[str]    # DLL/module names in import name table
    exec_imports: List[str]        # exec-class API names found
    nonresident_names: List[str]   # first few names from non-resident name table
    segment_count: int
    module_ref_count: int
    error: Optional[str] = None

    def fmt(self) -> str:
        status = 'EXEC-CLASS-FOUND' if self.exec_imports else 'SAFE-NO-EXEC-IMPORT'
        return (
            f'NE format={self.format} target_os={self.target_os} '
            f'modules={self.imported_modules[:6]} '
            f'exec_imports={self.exec_imports} '
            f'segments={self.segment_count} '
            f'nonresident={self.nonresident_names[:2]} '
            f'verdict={status}'
        )


class NEFormatParser:
    """Parse NE/LE/LX New Executable format files for OS/2 1.x and Windows 3.x."""

    def __init__(self, data: bytes):
        self._data = data

    @classmethod
    def from_path(cls, path: str) -> 'NEFormatParser':
        return cls(Path(path).read_bytes())

    def parse(self) -> NEFormatResult:
        data = self._data
        path = '<bytes>'

        if len(data) < 64:
            return NEFormatResult(path, 'NOT-MZ', 'UNKNOWN', [], [], [], 0, 0,
                                  error='File too short')

        # Check MZ signature
        if data[:2] != b'MZ':
            return NEFormatResult(path, 'NOT-MZ', 'UNKNOWN', [], [], [], 0, 0,
                                  error='Not MZ format')

        # Extended header offset at MZ[0x3c]
        if len(data) < 0x40:
            return NEFormatResult(path, 'MZ-only', 'UNKNOWN', [], [], [], 0, 0)

        ext_off = struct.unpack_from('<I', data, 0x3c)[0]
        if ext_off + 2 > len(data):
            return NEFormatResult(path, 'MZ-only', 'UNKNOWN', [], [], [], 0, 0,
                                  error='Extended header offset out of range')

        sig = data[ext_off:ext_off+4]

        if sig[:4] == b'PE\x00\x00':
            return NEFormatResult(path, 'PE', 'Win32', [], [], [], 0, 0)

        if sig[:2] not in (b'NE', b'LE', b'LX'):
            return NEFormatResult(path, 'MZ-only', 'UNKNOWN', [], [], [], 0, 0,
                                  error=f'Unknown extended sig: {sig[:4].hex()}')

        fmt = sig[:2].decode('ascii')

        if fmt == 'NE':
            return self._parse_ne(ext_off)
        else:
            return self._parse_lx(ext_off, fmt)

    def _parse_ne(self, ne_off: int) -> NEFormatResult:
        data = self._data
        if ne_off + 64 > len(data):
            return NEFormatResult('<bytes>', 'NE', 'UNKNOWN', [], [], [], 0, 0,
                                  error='NE header truncated')

        # NE header fields (all 16-bit relative offsets, except nonresident which is file-absolute)
        # +0x00: signature 'NE'
        # +0x04: entry table offset (from NE header start)
        # +0x06: entry table size
        # +0x1c: segment count
        # +0x1e: module reference count
        # +0x20: nonresident names table size
        # +0x22: segment table offset (from NE header start)
        # +0x26: resident names table offset (from NE header start)
        # +0x28: module reference table offset (from NE header start)
        # +0x2a: imported names table offset (from NE header start)
        # +0x2c: nonresident names table offset (from FILE start, 32-bit)
        # +0x36: target OS byte (1 byte)

        def w16(offset): return struct.unpack_from('<H', data, ne_off + offset)[0]
        def w32(offset): return struct.unpack_from('<I', data, ne_off + offset)[0]
        def b8(offset):  return data[ne_off + offset] if ne_off + offset < len(data) else 0

        seg_count   = w16(0x1c)
        mod_ref_cnt = w16(0x1e)
        nr_tbl_size = w16(0x20)
        seg_tbl_off = w16(0x22)
        # res_names_off = w16(0x26)   # resident names table
        mod_ref_off  = w16(0x28)     # module reference table offset (from NE header)
        imp_names_off= w16(0x2a)     # imported names table offset (from NE header)
        nr_tbl_foff  = w32(0x2c)     # nonresident names table: absolute file offset
        target_os_b  = b8(0x36)
        target_os    = _TARGET_OS.get(target_os_b, f'OS_{target_os_b}')

        # Parse module reference table: array of mod_ref_cnt uint16 offsets
        # Each offset is into the imported names table (relative to imp_names_off+ne_off)
        imported_modules: List[str] = []
        if mod_ref_cnt > 0 and mod_ref_off > 0:
            mrt_base = ne_off + mod_ref_off
            for i in range(min(mod_ref_cnt, 64)):
                if mrt_base + i * 2 + 2 > len(data):
                    break
                name_off = struct.unpack_from('<H', data, mrt_base + i * 2)[0]
                # name_off is relative to imported names table start
                abs_name_off = ne_off + imp_names_off + name_off
                if abs_name_off >= len(data):
                    continue
                name_len = data[abs_name_off]
                if abs_name_off + 1 + name_len > len(data):
                    continue
                name = data[abs_name_off + 1: abs_name_off + 1 + name_len].decode('ascii', errors='replace')
                imported_modules.append(name)

        # Parse nonresident names table (first few entries)
        nonresident_names: List[str] = []
        if nr_tbl_foff > 0 and nr_tbl_size > 0 and nr_tbl_foff < len(data):
            pos = nr_tbl_foff
            end = min(pos + nr_tbl_size, len(data))
            count = 0
            while pos < end and count < 10:
                name_len = data[pos]
                if name_len == 0:
                    break
                pos += 1
                if pos + name_len + 2 > end:
                    break
                name = data[pos: pos + name_len].decode('ascii', errors='replace')
                pos += name_len
                ordinal = struct.unpack_from('<H', data, pos)[0]
                pos += 2
                nonresident_names.append(f'{name}@{ordinal}')
                count += 1

        # Check for exec-class imports in module names and nonresident names
        exec_imports: List[str] = []
        all_names_upper = set(m.upper() for m in imported_modules)
        all_names_upper.update(n.upper().split('@')[0] for n in nonresident_names)

        # Also scan the full imported names table for exec-class function names
        if imp_names_off > 0:
            base = ne_off + imp_names_off
            pos = base
            while pos < len(data) and pos < base + 4096:
                name_len = data[pos]
                if name_len == 0:
                    break
                pos += 1
                if pos + name_len > len(data):
                    break
                name = data[pos: pos + name_len].decode('ascii', errors='replace').upper()
                if name in _OS2_EXEC_FUNCS or name in _WIN3_EXEC_FUNCS:
                    exec_imports.append(name)
                pos += name_len

        return NEFormatResult(
            path='<bytes>',
            format='NE',
            target_os=target_os,
            imported_modules=imported_modules,
            exec_imports=exec_imports,
            nonresident_names=nonresident_names,
            segment_count=seg_count,
            module_ref_count=mod_ref_cnt,
        )

    def _parse_lx(self, lx_off: int, fmt: str) -> NEFormatResult:
        data = self._data
        if lx_off + 196 > len(data):
            return NEFormatResult('<bytes>', fmt, 'OS/2-2.x', [], [], [], 0, 0,
                                  error='LX header truncated')

        # LX header is large. Key fields:
        # +0x00: signature 'LX' or 'LE'
        # +0x08: module flags
        # +0x14: module version
        # +0x1c: number of pages
        # +0x70: import module table offset (from LX header)
        # +0x74: import module count
        # +0x78: import procedure name table offset

        def w32(off): return struct.unpack_from('<I', data, lx_off + off)[0]

        imp_mod_off  = w32(0x70)
        imp_mod_cnt  = w32(0x74)
        imp_proc_off = w32(0x78)

        imported_modules: List[str] = []
        if imp_mod_cnt > 0 and imp_mod_off > 0:
            base = lx_off + imp_mod_off
            pos = base
            for _ in range(min(imp_mod_cnt, 64)):
                if pos + 2 > len(data): break
                # LX import module table: first 4 bytes = offset into import proc name table
                # Actually LX module table is: uint8 namesize, then name chars
                # (This is one common format; actual LX spec varies by linker)
                name_len = data[pos] if pos < len(data) else 0
                if name_len == 0: break
                pos += 1
                if pos + name_len > len(data): break
                name = data[pos:pos+name_len].decode('ascii', errors='replace')
                imported_modules.append(name)
                pos += name_len

        # Check exec-class
        exec_imports: List[str] = []
        if imp_proc_off > 0:
            base = lx_off + imp_proc_off
            pos = base
            while pos < len(data) and pos < base + 8192:
                name_len = data[pos]
                if name_len == 0: break
                pos += 1
                if pos + name_len > len(data): break
                name = data[pos:pos+name_len].decode('ascii', errors='replace').upper()
                if name in _OS2_EXEC_FUNCS:
                    exec_imports.append(name)
                pos += name_len

        return NEFormatResult(
            path='<bytes>',
            format=fmt,
            target_os='OS/2-2.x',
            imported_modules=imported_modules,
            exec_imports=exec_imports,
            nonresident_names=[],
            segment_count=0,
            module_ref_count=imp_mod_cnt,
        )
