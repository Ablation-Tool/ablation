"""
tests/test_loongarch64_max_not_min_scanner.py

Tests for LA64MaxNotMinScanner.from_system_map() — the kernel/vmlinux constructor
that resolves sink VAs from System.map instead of .rela.plt.

Test strategy
-------------
1. Unit: verify System.map parsing filters correctly (T/t/W/w kept; D/B/R discarded;
   only names present in _SINKS are kept; malformed lines skipped).

2. Integration: build a 20-byte synthetic binary containing the exact 4-instruction
   max-not-min pattern followed by a BL that targets a VA listed in System.map.
   Confirm scan() returns one finding with the expected sink name.

Instruction layout (flat binary, base=0, text_va=0, text_sz=20)
---------------------------------------------------------------
   VA 0:  sltu   $t0(12), $a0(4), $a1(5)   — rcond=12, ra=4, rb=5
   VA 4:  masknez $t1(13), $a1(5), $t0(12) — rtmp1=13
   VA 8:  maskeqz $a0(4),  $a0(4), $t0(12) — rtmp2=4
   VA 12: or     $a0(4),   $a0(4), $t1(13) — rout=4 (kmalloc expects $a0)
   VA 16: bl     0x100                     — BL to kmalloc at VA 0x100

BL encoding verification
   offset_bytes = 0x100 - 16 = 0xf0 = 240 → 60 instructions
   imm26 = 60 (positive, no sign-extension needed)
   lo16  = 60 & 0xffff = 60 = 0x3c
   hi10  = 60 >> 16    = 0
   word  = 0x54000000 | (0x3c << 10) | 0 = 0x5400f000
   check: _bl_target(0x5400f000, 16)
          hi10 = 0x5400f000 & 0x3ff = 0
          lo16 = (0x5400f000 >> 10) & 0xffff = 0x3c
          imm26= (0 << 16) | 0x3c = 60
          target = (16 + 60 * 4) & 0xffffffffffffffff = 256 = 0x100  ✓
"""

import struct
import tempfile
from pathlib import Path

import pytest

from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinScanner


# ---------------------------------------------------------------------------
# Synthetic binary: 5 LA64 instructions in a flat byte blob
# ---------------------------------------------------------------------------
#   sltu   $t0(12), $a0(4), $a1(5)   = 0x0012948c
#   masknez $t1(13), $a1(5), $t0(12) = 0x0013b0ad
#   maskeqz $a0(4),  $a0(4), $t0(12) = 0x00133084
#   or     $a0(4),   $a0(4), $t1(13) = 0x00153484
#   bl     +240 bytes (→ VA 0x100)   = 0x5400f000
_PATTERN_BYTES = struct.pack(
    '<5I',
    0x0012948c,  # sltu   $t0, $a0, $a1
    0x0013b0ad,  # masknez $t1, $a1, $t0
    0x00133084,  # maskeqz $a0, $a0, $t0
    0x00153484,  # or     $a0, $a0, $t1
    0x5400f000,  # bl     0x100
)

_SYSMAP_INTEGRATION = """\
0000000000000100 T kmalloc
0000000000000200 T __kmalloc
0000000000000300 D some_data_sym
0000000000000400 B some_bss_sym
"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _write_tmp(content: str, suffix: str = '.txt') -> str:
    """Write content to a named temp file and return its path."""
    f = tempfile.NamedTemporaryFile(
        mode='w', suffix=suffix, delete=False
    )
    f.write(content)
    f.close()
    return f.name


def _write_tmp_bytes(data: bytes, suffix: str = '.bin') -> str:
    f = tempfile.NamedTemporaryFile(
        mode='wb', suffix=suffix, delete=False
    )
    f.write(data)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# Test 1: System.map filtering
# ---------------------------------------------------------------------------

SYSMAP_FILTER_TEXT = """\
ffff800000000100 T kmalloc
ffff800000000110 t kzalloc
ffff800000000120 W vmalloc
ffff800000000130 w __kmalloc
ffff800000000200 D some_data_symbol
ffff800000000300 B some_bss_symbol
ffff800000000400 R some_rodata
ffff800000000500 T unknown_function_not_in_sinks
ffff800000000600 T memcpy
malformed_line_no_type
"""


def test_sysmap_filtering():
    """
    from_system_map() must keep T/t/W/w entries whose names are in _SINKS
    and discard D/B/R entries and names not in _SINKS.
    """
    bin_path = _write_tmp_bytes(b'\x00' * 4)  # invalid ELF → lief fails → base=0
    sysmap_path = _write_tmp(SYSMAP_FILTER_TEXT)
    try:
        scanner = LA64MaxNotMinScanner.from_system_map(bin_path, sysmap_path)
        plt = scanner._plt

        # T/t/W/w sink entries should be present
        assert 0xffff800000000100 in plt and plt[0xffff800000000100] == 'kmalloc'
        assert 0xffff800000000110 in plt and plt[0xffff800000000110] == 'kzalloc'
        assert 0xffff800000000120 in plt and plt[0xffff800000000120] == 'vmalloc'
        assert 0xffff800000000130 in plt and plt[0xffff800000000130] == '__kmalloc'
        assert 0xffff800000000600 in plt and plt[0xffff800000000600] == 'memcpy'

        # D/B/R entries must be excluded
        assert 0xffff800000000200 not in plt  # D
        assert 0xffff800000000300 not in plt  # B
        assert 0xffff800000000400 not in plt  # R

        # T entry not in _SINKS must be excluded
        assert 0xffff800000000500 not in plt  # unknown_function_not_in_sinks

        # Malformed line must be silently skipped (no crash)
        assert all(isinstance(k, int) for k in plt)
    finally:
        Path(bin_path).unlink(missing_ok=True)
        Path(sysmap_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Test 2: Integration — scan() finds the pattern + kmalloc from System.map
# ---------------------------------------------------------------------------

def test_integration_vmlinux_pattern():
    """
    A flat 20-byte binary whose bytes encode the 4-insn max-not-min pattern
    followed by a BL targeting VA 0x100.  System.map maps 0x100 → kmalloc.
    scan() must return exactly one finding with sink_name='kmalloc'.
    """
    bin_path = _write_tmp_bytes(_PATTERN_BYTES)
    sysmap_path = _write_tmp(_SYSMAP_INTEGRATION)
    try:
        scanner = LA64MaxNotMinScanner.from_system_map(bin_path, sysmap_path)

        # lief will fail (not a valid ELF) → base=0, text_va=0, text_sz=20
        assert scanner._plt.get(0x100) == 'kmalloc'
        assert scanner._plt.get(0x200) == '__kmalloc'

        findings = scanner.scan()
        assert len(findings) == 1, f"Expected 1 finding, got: {findings}"

        f = findings[0]
        assert f.sink_name == 'kmalloc', f"Expected kmalloc, got {f.sink_name!r}"
        assert f.sink_arg == 'size',     f"Expected 'size', got {f.sink_arg!r}"
        assert f.pattern_va == 0,        f"Expected pattern_va=0, got {f.pattern_va}"
        assert f.sink_va == 16,          f"Expected sink_va=16 (BL offset), got {f.sink_va}"
        assert f.compare_op == 'sltu',   f"Expected sltu, got {f.compare_op!r}"
        assert f.fp_class == '',         f"Expected empty fp_class (real finding), got {f.fp_class!r}"
    finally:
        Path(bin_path).unlink(missing_ok=True)
        Path(sysmap_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Test 3: from_system_map() with missing System.map raises FileNotFoundError
# ---------------------------------------------------------------------------

def test_missing_sysmap_raises():
    bin_path = _write_tmp_bytes(b'\x00' * 4)
    try:
        with pytest.raises((FileNotFoundError, OSError)):
            LA64MaxNotMinScanner.from_system_map(
                bin_path,
                '/nonexistent/path/System.map'
            )
    finally:
        Path(bin_path).unlink(missing_ok=True)
