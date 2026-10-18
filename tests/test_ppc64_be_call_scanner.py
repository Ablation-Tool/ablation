"""Unit tests for PPC64BECallScanner.

Tests verify BL instruction detection on hand-encoded PPC64 BE byte sequences
and the scan_calls_to() word sweep without requiring external binary fixtures.
"""

import os
import struct

import pytest

from ablation.analyzers.ppc64_be_call_scanner import (
    PPC64BECallScanner,
    _decode_bl_target,
    _BL_MASK,
    _BL_MATCH,
)

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass


# ── helpers ───────────────────────────────────────────────────────────────────

def _bl(from_va: int, to_va: int) -> int:
    """Encode a PPC64 BL instruction (AA=0, LK=1)."""
    delta = (to_va - from_va) & 0x03FFFFFC
    return 0x48000001 | delta


def _nop() -> int:
    """PPC64 NOP (ori 0,0,0)."""
    return 0x60000000


def _pack(*words: int) -> bytes:
    return b''.join(struct.pack('>I', w & 0xFFFFFFFF) for w in words)


# ── BL opcode mask tests ──────────────────────────────────────────────────────

def test_bl_mask_matches_bl() -> None:
    """The BL mask matches a well-formed BL to a known target."""
    text_va   = 0x10001000
    target_va = 0x10013e00
    word = _bl(text_va, target_va)
    assert (word & _BL_MASK) == _BL_MATCH, f"BL word 0x{word:08x} does not match mask"


def test_bl_mask_rejects_b() -> None:
    """B (branch without link, LK=0) must not match the BL mask."""
    b_word = 0x48000000  # B to offset 0, AA=0, LK=0
    assert (b_word & _BL_MASK) != _BL_MATCH


def test_bl_mask_rejects_nop() -> None:
    """NOP must not match the BL mask."""
    assert (_nop() & _BL_MASK) != _BL_MATCH


def test_bl_mask_rejects_bla() -> None:
    """BLA (absolute, AA=1, LK=1) must not match the relative-BL mask."""
    bla_word = 0x48000003  # AA=1, LK=1
    assert (bla_word & _BL_MASK) != _BL_MATCH


# ── _decode_bl_target tests ───────────────────────────────────────────────────

def test_decode_bl_forward() -> None:
    """Decode a forward BL: target = from_va + positive_offset."""
    from_va   = 0x10001000
    target_va = 0x10013e00
    word = _bl(from_va, target_va)
    result = _decode_bl_target(from_va, word)
    assert result == target_va, f"expected 0x{target_va:x}, got 0x{result:x}"


def test_decode_bl_backward() -> None:
    """Decode a backward BL: target = from_va - offset (signed LI)."""
    from_va   = 0x10013e00
    target_va = 0x10001000
    word = _bl(from_va, target_va)
    result = _decode_bl_target(from_va, word)
    assert result == target_va, f"expected 0x{target_va:x}, got 0x{result:x}"


def test_decode_bl_self_referential() -> None:
    """BL with LI=0 branches to next instruction (offset 0 from VA, but LK set)."""
    from_va = 0x10001000
    # LI=0 means target = from_va + 0*4 = from_va
    word = 0x48000001  # BL, LI=0, AA=0, LK=1
    result = _decode_bl_target(from_va, word)
    assert result == from_va


# ── scan_calls_to integration tests ──────────────────────────────────────────

def _make_scanner_with_text(
    text_bytes: bytes,
    text_va: int = 0x10001000,
) -> PPC64BECallScanner:
    """Construct a PPC64BECallScanner with synthetic .text bytes."""
    scanner = PPC64BECallScanner.__new__(PPC64BECallScanner)
    scanner._path      = '/dev/null'
    scanner._data      = text_bytes
    scanner._text_va   = text_va
    scanner._text_off  = 0
    scanner._text_size = len(text_bytes)
    scanner._plt       = {}
    return scanner


def test_scan_single_bl() -> None:
    """scan_calls_to() finds a single BL targeting plt_va."""
    text_va   = 0x10001000
    plt_va    = 0x10013e00
    bl_offset = 4  # BL is the second word
    bl_va     = text_va + bl_offset

    code = _pack(_nop(), _bl(bl_va, plt_va))
    scanner = _make_scanner_with_text(code, text_va)

    result = scanner.scan_calls_to(plt_va)
    assert result == [bl_va], f"expected [{hex(bl_va)}], got {[hex(v) for v in result]}"


def test_scan_multiple_bl_same_target() -> None:
    """scan_calls_to() finds all three BL instructions targeting the same VA."""
    text_va = 0x10001000
    plt_va  = 0x10013e00
    # Four words: BL, NOP, BL, BL
    bl0 = text_va
    bl2 = text_va + 8
    bl3 = text_va + 12

    code = _pack(
        _bl(bl0, plt_va),
        _nop(),
        _bl(bl2, plt_va),
        _bl(bl3, plt_va),
    )
    scanner = _make_scanner_with_text(code, text_va)
    result = scanner.scan_calls_to(plt_va)
    assert sorted(result) == sorted([bl0, bl2, bl3])


def test_scan_no_bl_to_target() -> None:
    """scan_calls_to() returns empty list when no BL targets plt_va."""
    text_va = 0x10001000
    plt_va  = 0x10013e00
    other   = 0x10014000

    code = _pack(_bl(text_va, other), _nop(), _bl(text_va + 8, other))
    scanner = _make_scanner_with_text(code, text_va)
    result = scanner.scan_calls_to(plt_va)
    assert result == []


def test_scan_empty_text() -> None:
    """scan_calls_to() on a zero-size text section returns empty list."""
    scanner = _make_scanner_with_text(b'', text_va=0x10001000)
    assert scanner.scan_calls_to(0x10013e00) == []


def test_scan_all_sinks_returns_hits() -> None:
    """scan_all_sinks() returns only sinks with registered PLT entries and BL hits."""
    text_va    = 0x10001000
    system_plt = 0x10013e00
    popen_plt  = 0x10013e10

    bl0 = text_va
    bl1 = text_va + 4

    code = _pack(
        _bl(bl0, system_plt),
        _bl(bl1, popen_plt),
    )
    scanner = _make_scanner_with_text(code, text_va)
    scanner._plt = {'system': system_plt, 'popen': popen_plt, 'execve': 0x99999999}

    hits = scanner.scan_all_sinks()
    assert 'system' in hits
    assert 'popen' in hits
    assert 'execve' not in hits   # no BL to that VA
    assert hits['system'] == [bl0]
    assert hits['popen']  == [bl1]


# ── from_path smoke test against a real binary ────────────────────────────────

_REAL_PPC64_SO = '/media/cowboy/research/IBM-RE/xcat-energy/libxcatcim_ppc64.so'


@pytest.mark.skipif(
    not os.path.exists(_REAL_PPC64_SO),
    reason='IBM-RE research drive not mounted',
)
def test_from_path_real_binary_no_crash() -> None:
    """from_path() on a real ppc64 BE shared library must not raise."""
    scanner = PPC64BECallScanner.from_path(_REAL_PPC64_SO)
    # The scanner must have found .text
    assert scanner._text_size > 0, 'no .text section found in real binary'


@pytest.mark.skipif(
    not (os.path.exists(_REAL_PPC64_SO) and _LIEF_OK),
    reason='IBM-RE research drive not mounted or lief missing',
)
def test_scan_all_sinks_real_binary_returns_dict() -> None:
    """scan_all_sinks() on a real binary returns a dict with no exceptions."""
    scanner = PPC64BECallScanner.from_path(_REAL_PPC64_SO)
    hits = scanner.scan_all_sinks()
    assert isinstance(hits, dict)
    # Each value is a non-empty list of ints
    for name, call_vas in hits.items():
        assert isinstance(call_vas, list) and len(call_vas) > 0
        assert all(isinstance(v, int) for v in call_vas)
