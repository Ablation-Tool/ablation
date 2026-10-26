"""
tests/test_uefi_sink_classifier_la64.py

Tests for UEFISinkClassifierLA64 — gBS dispatch site detection + max-not-min pattern.

Synthetic binary layout (flat, base=0, text_va=0)
--------------------------------------------------
The test binary encodes 7 instructions placed to trigger one AllocatePool finding:

   VA  0: sltu   $t0(12), $a0(4),  $a1(5)    — max-not-min pattern start
   VA  4: masknez $t1(13), $a1(5), $t0(12)
   VA  8: maskeqz $a1(5),  $a0(4), $t0(12)   — rout = $a1 (AllocatePool expects $a1)
   VA 12: or     $a1(5),   $a1(5), $t1(13)
   VA 16: ld.d   $s0(23),  $s1(24), 0x30     — load AllocatePool ptr from gBS+0x30
   VA 20: jirl   $ra(1),   $s0(23), 0        — dispatch call (AllocatePool at VA 20)

ld.d encoding verification
   _MATCH_LDD = 0x28C00000 (bits[31:22] = 163)
   ld.d $s0(23), $s1(24), 0x30 (= 48):
     word = 0x28C00000 | (48 << 10) | (24 << 5) | 23
          = 0x28C00000 | 0xC000   | 0x300   | 0x17
          = 0x28C0C317

jirl encoding verification
   _MATCH_JIRL_TOP6 = 0x4C000000 (top6 = 19)
   jirl $ra(1), $s0(23), 0:
     word = 0x4C000000 | (0 << 10) | (23 << 5) | 1
          = 0x4C000000 | 0 | 0x2E0 | 0x1
          = 0x4C0002E1

sltu/masknez/maskeqz/or: same as test_loongarch64_max_not_min_scanner.py
but with rout = $a1(5) instead of $a0(4) to match AllocatePool size arg.

Pattern instructions with rout=$a1:
   sltu  $t0(12), $a0(4), $a1(5) = 0x0012948c  (unchanged)
   masknez $t1(13), $a1(5), $t0(12) = 0x0013b0ad (unchanged)
   maskeqz $a1(5),  $a0(4), $t0(12):
     rd=$a1=5, rj=$a0=4, rk=$t0=12
     word = 0x00130000 | (12<<10) | (4<<5) | 5
          = 0x00130000 | 0x3000 | 0x80 | 5 = 0x00133085
   or $a1(5), $a1(5), $t1(13):
     rd=$a1=5, rj=$a1=5, rk=$t1=13
     word = 0x00150000 | (13<<10) | (5<<5) | 5
          = 0x00150000 | 0x3400 | 0xa0 | 5 = 0x001534a5
"""

import struct
import tempfile
from pathlib import Path

import pytest

from ablation.analyzers.uefi_sink_classifier_la64 import (
    UEFISinkClassifierLA64, _GBS_SINKS, _ldd_si12,
)


# ---------------------------------------------------------------------------
# Synthetic binary bytes
# ---------------------------------------------------------------------------

_INSNS = [
    0x0012948c,  # sltu   $t0, $a0, $a1  (max-not-min start)
    0x0013b0ad,  # masknez $t1, $a1, $t0
    0x00133085,  # maskeqz $a1, $a0, $t0  (rout=$a1 = AllocatePool size arg)
    0x001534a5,  # or     $a1, $a1, $t1
    0x28C0C317,  # ld.d   $s0(23), $s1(24), 0x30  (AllocatePool ptr from gBS+0x30)
    0x4C0002E1,  # jirl   $ra(1), $s0(23), 0       (AllocatePool dispatch at VA 20)
]

_BINARY = struct.pack('<6I', *_INSNS)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_gbs_sinks_coverage():
    """_GBS_SINKS must contain AllocatePool and AllocatePages with correct arg_pos."""
    assert 0x30 in _GBS_SINKS  # AllocatePool
    assert 0x18 in _GBS_SINKS  # AllocatePages

    ap_name, ap_arg_pos, ap_label = _GBS_SINKS[0x30]
    assert ap_name    == 'AllocatePool'
    assert ap_arg_pos == 1   # $a1 is the size
    assert ap_label   == 'size'

    ap_name, ap_arg_pos, ap_label = _GBS_SINKS[0x18]
    assert ap_name    == 'AllocatePages'
    assert ap_arg_pos == 2   # $a2 is the pages count
    assert ap_label   == 'pages'


def test_ldd_si12_positive():
    """_ldd_si12 correctly extracts positive and negative si12 values."""
    # ld.d rd, rj, 48  (si12 = 48 = 0x30)
    word_pos = 0x28C00000 | (48 << 10) | (1 << 5) | 0
    assert _ldd_si12(word_pos) == 48

    # ld.d rd, rj, -8  (si12 = -8, 12-bit twos complement = 0xFF8)
    word_neg = 0x28C00000 | (0xFF8 << 10) | (1 << 5) | 0
    assert _ldd_si12(word_neg) == -8


def test_dispatch_site_detection():
    """_find_dispatch_sites() identifies the jirl at VA 20 as AllocatePool."""
    scanner = UEFISinkClassifierLA64(_BINARY, text_va=0, text_sz=len(_BINARY))
    dispatch = scanner._find_dispatch_sites()

    assert 20 in dispatch, f"Expected dispatch site at VA 20, got: {list(dispatch.keys())}"
    func_name, arg_pos, arg_label = dispatch[20]
    assert func_name == 'AllocatePool'
    assert arg_pos   == 1   # $a1
    assert arg_label == 'size'


def test_scan_finds_allocate_pool_hit():
    """scan() returns one finding: max-not-min result ($a1) → AllocatePool(size)."""
    scanner = UEFISinkClassifierLA64(_BINARY, text_va=0, text_sz=len(_BINARY))
    findings = scanner.scan()

    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}: {findings}"

    f = findings[0]
    assert f.gbs_func   == 'AllocatePool'
    assert f.sink_arg   == 'size'
    assert f.gbs_offset == 0x30
    assert f.sink_va    == 20    # VA of the jirl
    assert f.pattern_va == 0     # VA of the sltu
    assert f.compare_op == 'sltu'
    assert f.fp_class   == ''    # real finding


def test_report_format():
    """report() produces non-empty string with function name."""
    scanner = UEFISinkClassifierLA64(_BINARY, text_va=0, text_sz=len(_BINARY))
    findings = scanner.scan()
    output   = scanner.report(findings)

    assert 'AllocatePool' in output
    assert 'UEFISinkClassifierLA64' in output


def test_no_findings_on_empty_binary():
    """An all-zero binary produces no findings and no crash."""
    scanner = UEFISinkClassifierLA64(b'\x00' * 32, text_va=0, text_sz=32)
    findings = scanner.scan()
    assert findings == []
    output = scanner.report(findings)
    assert '0 findings' in output


def test_from_path_integration():
    """from_path() reads a file and builds a scanner correctly."""
    tmp = tempfile.NamedTemporaryFile(suffix='.efi', delete=False)
    tmp.write(_BINARY)
    tmp.close()
    try:
        scanner  = UEFISinkClassifierLA64.from_path(tmp.name)
        findings = scanner.scan()
        # Flat file without PE header → base=0, text_va=0, text_sz=len(data)
        assert len(findings) == 1
        assert findings[0].gbs_func == 'AllocatePool'
    finally:
        Path(tmp.name).unlink(missing_ok=True)
