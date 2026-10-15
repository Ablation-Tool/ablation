"""Tests for GoX86StripScanner pclntab v3 name recovery (Go 1.20+ format)."""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ablation.analyzers.go_x86_strip_scanner import GoX86StripScanner, GoScanResult


# ---------------------------------------------------------------------------
# Synthetic pclntab builder for v3 (magic 0xfffffff1, Go 1.20+)
# ---------------------------------------------------------------------------

def _build_v3_pclntab(funcs: list[tuple[int, str]], text_start: int = 0x400000) -> bytes:
    """Build a minimal valid Go 1.20+ pclntab for testing.

    funcs: list of (entry_offset_from_text_start, function_name).
    Returns raw pclntab bytes suitable for scanning.
    """
    nfunc = len(funcs)

    # Build funcnametab: null-terminated strings packed together.
    funcnametab = bytearray()
    name_offsets: list[int] = []
    for _, name in funcs:
        name_offsets.append(len(funcnametab))
        funcnametab.extend(name.encode('utf-8') + b'\x00')

    # Layout (all offsets relative to pclntab start):
    #   0x00–0x47: pcHeader (72 bytes)
    #   0x48:      funcnametab
    #   0x48 + len(funcnametab):  align to 8; cuOffset here
    #   <cu_off>:  function table (nfunc+1 entries, 8 bytes each)
    #   <ftab_end>: _Func structs (8 bytes each, only entryOff+nameOff matter)

    fname_off = 0x48
    cu_off = fname_off + len(funcnametab)
    # Align ftab to 8
    if cu_off % 8:
        cu_off += 8 - (cu_off % 8)
    ftab_rel = cu_off   # pclnOffset in pcHeader = offset of function table in pclntab

    # Function table: nfunc+1 entries.
    # funcoff for each entry = offset from ftab_base to the _Func struct.
    # _Func structs follow immediately after the function table.
    ftab_size = (nfunc + 1) * 8
    # _Func structs start right after the function table.
    func_structs_start_in_ftab = ftab_size   # offset from ftab_base
    func_struct_size = 8   # only need entryOff + nameOff for this test

    # Build the function table bytes.
    ftab = bytearray()
    for i, (entry_rel, _) in enumerate(funcs):
        funcoff = func_structs_start_in_ftab + i * func_struct_size
        ftab += struct.pack('<II', entry_rel, funcoff)
    # Sentinel entry (entryOff = last VA + something, funcoff = 0).
    sentinel_entry = (funcs[-1][0] + 0x100) if funcs else 0
    ftab += struct.pack('<II', sentinel_entry, 0)

    # Build _Func struct bytes (just the first 8 bytes per struct).
    func_structs = bytearray()
    for i, (entry_rel, _) in enumerate(funcs):
        name_off = name_offsets[i]
        func_structs += struct.pack('<Ii', entry_rel, name_off)

    # Assemble pclntab.
    pcln = bytearray(fname_off)   # space for pcHeader (72 bytes padded to 0x48)

    # pcHeader fields.
    struct.pack_into('<I', pcln, 0, 0xfffffff1)   # magic
    # pad1, pad2 already 0
    struct.pack_into('<B', pcln, 6, 1)             # quantum = 1
    struct.pack_into('<B', pcln, 7, 8)             # ptrSize = 8
    struct.pack_into('<q', pcln, 8, nfunc)         # nfunc
    struct.pack_into('<Q', pcln, 16, 0)            # nfiles
    struct.pack_into('<Q', pcln, 24, text_start)   # textStart
    struct.pack_into('<Q', pcln, 32, fname_off)    # funcnameOffset
    struct.pack_into('<Q', pcln, 40, cu_off)       # cuOffset
    struct.pack_into('<Q', pcln, 48, cu_off)       # filetabOffset (unused in test)
    struct.pack_into('<Q', pcln, 56, cu_off)       # pctabOffset (unused in test)
    struct.pack_into('<Q', pcln, 64, ftab_rel)     # pclnOffset

    # Append funcnametab (padded to cu_off).
    pcln.extend(bytes(cu_off - fname_off))
    pcln[fname_off:fname_off + len(funcnametab)] = funcnametab

    # Append function table.
    pcln.extend(ftab)

    # Append _Func structs.
    pcln.extend(func_structs)

    return bytes(pcln)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_v3_name_recovery_via_func_struct_nameoff():
    """Names are resolved through _Func.nameOff, not directly from funcoff."""
    funcs = [(0x000, 'runtime.main'), (0x100, 'main.doWork'), (0x200, 'main.helper')]
    pclntab = _build_v3_pclntab(funcs)

    scanner = GoX86StripScanner.__new__(GoX86StripScanner)
    scanner._data = pclntab
    scanner._path = '<synthetic>'
    result = GoScanResult(binary_path='<synthetic>')
    off = 0
    scanner._parse_v3_header(pclntab, off, result)

    text_start = 0x400000
    assert len(result.funcs) == 3
    assert result.funcs[text_start + 0x000] == 'runtime.main'
    assert result.funcs[text_start + 0x100] == 'main.doWork'
    assert result.funcs[text_start + 0x200] == 'main.helper'


def test_v3_sentinel_not_in_result():
    """The nfunc+1 sentinel entry must not appear in result.funcs."""
    funcs = [(0x000, 'pkg.Func')]
    pclntab = _build_v3_pclntab(funcs)

    scanner = GoX86StripScanner.__new__(GoX86StripScanner)
    result = GoScanResult(binary_path='<synthetic>')
    scanner._parse_v3_header(pclntab, 0, result)

    assert len(result.funcs) == 1


def test_v3_nfunc_set_on_result():
    """result.nfunc is set from the pcHeader field."""
    funcs = [(i * 0x80, f'pkg.F{i}') for i in range(5)]
    pclntab = _build_v3_pclntab(funcs)

    scanner = GoX86StripScanner.__new__(GoX86StripScanner)
    result = GoScanResult(binary_path='<synthetic>')
    scanner._parse_v3_header(pclntab, 0, result)

    assert result.nfunc == 5


def test_v3_names_with_suffix_overlap():
    """Funcnametab entries share a blob; offset lookup must return exact string."""
    # 'bar' is a suffix of 'foobar' — both must resolve correctly.
    funcs = [(0x000, 'pkg.foobar'), (0x100, 'pkg.bar')]
    pclntab = _build_v3_pclntab(funcs)

    scanner = GoX86StripScanner.__new__(GoX86StripScanner)
    result = GoScanResult(binary_path='<synthetic>')
    scanner._parse_v3_header(pclntab, 0, result)

    text_start = 0x400000
    assert result.funcs[text_start + 0x000] == 'pkg.foobar'
    assert result.funcs[text_start + 0x100] == 'pkg.bar'


def test_v3_text_start_applied_to_vas():
    """Function VAs = textStart + entryOff."""
    funcs = [(0x000, 'a.Init'), (0x200, 'a.Run')]
    pclntab = _build_v3_pclntab(funcs, text_start=0x600000)

    scanner = GoX86StripScanner.__new__(GoX86StripScanner)
    result = GoScanResult(binary_path='<synthetic>')
    scanner._parse_v3_header(pclntab, 0, result)

    assert 0x600000 in result.funcs
    assert 0x600200 in result.funcs
    assert result.funcs[0x600000] == 'a.Init'
    assert result.funcs[0x600200] == 'a.Run'
