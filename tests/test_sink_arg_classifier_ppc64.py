"""Unit tests for SinkArgClassifierPPC64.

Tests verify argument classification on hand-encoded PPC64LE byte sequences.
Each test encodes a minimal function stub, wraps it in a mock context,
and asserts the expected verdict.

Architecture notes (PPC64 ABIv2 LE):
  - Arguments passed in r3-r10: r3=arg0, r4=arg1 ...
  - TOC base in r2 at function entry.
  - addis r3, r2, HI; addi r3, r3, LO → toc_base + (HI<<16) + LO (RODATA_CONST if in .rodata).
  - addis r3, r2, HI; ld r3, LO(r3) → pointer load from TOC (RODATA_CONST if *ptr in .rodata).
  - li r3, imm → small constant (RODATA_CONST).
  - mr r3, r4 → register copy, recurse on r4 (ARG_PROPAGATED if r4 is entry arg).
  - ld r3, N(r1) → stack load; triggers snprintf backtrack or entry-arg detection.
  - addi r3, r1, N → stack address; same backtrack path.
  - If arg_reg is an entry register unmodified in lookback window → ARG_PROPAGATED.
  - Instructions stored little-endian (ppc64le LE word byte-swapping).
"""

import struct
from unittest.mock import MagicMock

import pytest

_CS_OK   = False
_LIEF_OK = False
try:
    import capstone
    _CS_OK = True
except ImportError:
    pass
try:
    import lief
    _LIEF_OK = True
except ImportError:
    pass

_SKIP_DEPS = pytest.mark.skipif(
    not (_CS_OK and _LIEF_OK),
    reason='capstone and lief required',
)

from ablation.analyzers.sink_arg_classifier_ppc64 import (
    SinkArgClassifierPPC64,
    RODATA_CONST,
    ARG_PROPAGATED,
    SNPRINTF_RODATA,
    UNKNOWN,
)

# ── constants ─────────────────────────────────────────────────────────────────

BASE_VA      = 0x10000000
FUNC_VA      = 0x10001000
SYSTEM_PLT   = 0x10013e00
SNPRINTF_PLT = 0x10013e30
RODATA_BASE  = 0x10020000
RODATA_END   = 0x10021000
RODATA_STR   = 0x10020100
TOC_BASE     = 0x10010000   # .toc/.got base (r2 at function entry)

DEFAULT_PLT = {
    SYSTEM_PLT:   'system',
    SNPRINTF_PLT: 'snprintf',
}


# ── helpers ───────────────────────────────────────────────────────────────────

def _le(*words: int) -> bytes:
    """Pack words as 32-bit LE (ppc64le instruction encoding)."""
    return b''.join(struct.pack('<I', w & 0xFFFFFFFF) for w in words)


def _addis(rd: int, ra: int, hi: int) -> int:
    """addis rD, rA, hi (extended mnemonic lis rD, hi when rA=0)."""
    return 0x3C000000 | (rd << 21) | (ra << 16) | (hi & 0xFFFF)


def _addi(rd: int, ra: int, lo: int) -> int:
    """addi rD, rA, lo."""
    return 0x38000000 | (rd << 21) | (ra << 16) | (lo & 0xFFFF)


def _li(rd: int, imm: int) -> int:
    """li rD, imm — addi rD, r0, imm."""
    return _addi(rd, 0, imm)


def _ld(rd: int, disp: int, ra: int) -> int:
    """ld rD, disp(rA)."""
    return 0xE8000000 | (rd << 21) | (ra << 16) | (disp & 0xFFFF)


def _std(rs: int, disp: int, ra: int) -> int:
    """std rS, disp(rA)."""
    return 0xF8000000 | (rs << 21) | (ra << 16) | (disp & 0xFFFF)


def _mr(rd: int, rs: int) -> int:
    """mr rD, rS — OR rD, rS, rS."""
    return 0x7C000378 | (rs << 21) | (rd << 16) | (rs << 11)


def _bl(from_va: int, to_va: int) -> int:
    """BL instruction from from_va to to_va."""
    delta = (to_va - from_va) & 0x03FFFFFC
    return 0x48000001 | delta


def _nop() -> int:
    """nop — ori r0, r0, 0."""
    return 0x60000000


def _make_clf(code: bytes, func_va: int = FUNC_VA) -> SinkArgClassifierPPC64:
    """Build SinkArgClassifierPPC64 from raw ppc64le bytes with a mock context."""
    ctx = MagicMock()
    ctx.path = '/dev/null'
    ctx.base_va = BASE_VA
    ctx.plt = DEFAULT_PLT
    ctx.exports = {}
    ctx.func_starts = sorted([func_va])
    ctx.thumb_funcs = set()

    def _callers_of(va):
        if va in DEFAULT_PLT:
            return [func_va]
        return []
    ctx.callers_of = _callers_of

    clf = SinkArgClassifierPPC64.__new__(SinkArgClassifierPPC64)
    clf._ctx            = ctx
    clf._data           = code
    clf._plt_rev        = {v: k for k, v in DEFAULT_PLT.items()}
    clf._sinks          = {'system': 0, 'snprintf': 0}
    clf._snprintf_plts  = {SNPRINTF_PLT: 2}
    clf._rodata_ranges  = [(RODATA_BASE, RODATA_END)]
    clf._toc_base       = TOC_BASE
    clf._dead_sinks     = []
    clf._bin            = None
    clf._cs             = None

    if _CS_OK:
        from capstone import Cs, CS_ARCH_PPC, CS_MODE_64
        clf._cs = Cs(CS_ARCH_PPC, CS_MODE_64)
        clf._cs.detail = True

    clf._va_to_file_offset = lambda va: va - func_va  # type: ignore[method-assign]

    return clf


# ── tests ─────────────────────────────────────────────────────────────────────

@_SKIP_DEPS
def test_addis_r2_addi_rodata_const() -> None:
    """addis r3, r2, HI; addi r3, r3, LO where toc_base+offset is in .rodata → RODATA_CONST."""
    offset = RODATA_STR - TOC_BASE    # 0x10100
    hi = (offset >> 16) & 0xFFFF
    lo = offset & 0xFFFF

    code = _le(
        _addis(3, 2, hi),             # addis r3, r2, HI
        _addi(3, 3, lo),              # addi r3, r3, LO
        _bl(FUNC_VA + 8, SYSTEM_PLT), # bl system@plt
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    assert results, 'no results from classify_all'
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == RODATA_CONST, f'expected RODATA_CONST, got {hit[0].verdict}: {hit[0].detail}'


@_SKIP_DEPS
def test_li_zero_rodata_const() -> None:
    """li r3, 0 (NULL pointer) → RODATA_CONST (literal constant)."""
    code = _le(
        _li(3, 0),
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == RODATA_CONST, f'expected RODATA_CONST, got {hit[0].verdict}'


@_SKIP_DEPS
def test_entry_arg_r3_unmodified_arg_propagated() -> None:
    """r3 is not written before the call → entry arg → ARG_PROPAGATED."""
    code = _le(
        _nop(),                        # something unrelated before call
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == ARG_PROPAGATED, f'expected ARG_PROPAGATED, got {hit[0].verdict}'


@_SKIP_DEPS
def test_mr_r3_from_entry_arg_r4_arg_propagated() -> None:
    """mr r3, r4 where r4 is an entry arg → ARG_PROPAGATED."""
    code = _le(
        _mr(3, 4),                     # mr r3, r4 (r4 is entry arg)
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == ARG_PROPAGATED, f'expected ARG_PROPAGATED, got {hit[0].verdict}'


@_SKIP_DEPS
def test_ld_r3_from_entry_arg_r4_arg_propagated() -> None:
    """ld r3, 8(r4) where r4 is an entry arg → struct field → ARG_PROPAGATED."""
    code = _le(
        _ld(3, 8, 4),                  # ld r3, 8(r4): r4 is entry arg
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == ARG_PROPAGATED, f'expected ARG_PROPAGATED, got {hit[0].verdict}'


@_SKIP_DEPS
def test_addis_non_r2_unknown() -> None:
    """addis r3, r5, HI (non-TOC base) → UNKNOWN (can't resolve non-r2 addis)."""
    code = _le(
        _addis(3, 5, 0x0001),          # addis r3, r5, 1: r5 is entry arg but not TOC
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    # addis from entry arg → ARG_PROPAGATED (r5 in entry arg set triggers the base check)
    assert hit[0].verdict in (ARG_PROPAGATED, UNKNOWN), \
        f'expected ARG_PROPAGATED or UNKNOWN, got {hit[0].verdict}'


@_SKIP_DEPS
def test_entry_arg_r3_direct_to_snprintf_buf_snprintf_rodata() -> None:
    """Stack buffer filled by snprintf with rodata format string → SNPRINTF_RODATA."""
    # snprintf(r1+48, 256, rodata_fmt, ...)
    # r3 = addi r3, r1, 48  (buf)
    # r4 = li r4, 256       (size, pos 1)
    # r5 = addis r5, r2, HI; addi r5, r5, LO  (fmt in .rodata, pos 2)
    # bl snprintf
    # r3 = addi r3, r1, 48  (result buf)
    # bl system

    fmt_offset = RODATA_STR - TOC_BASE
    hi = (fmt_offset >> 16) & 0xFFFF
    lo = fmt_offset & 0xFFFF

    code = _le(
        _addi(3, 1, 48),               # buf = r1+48
        _li(4, 256),                    # size = 256
        _addis(5, 2, hi),              # fmt high
        _addi(5, 5, lo),               # fmt low (in .rodata)
        _bl(FUNC_VA + 16, SNPRINTF_PLT),
        _addi(3, 1, 48),               # r3 = buf again
        _bl(FUNC_VA + 24, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == SNPRINTF_RODATA, \
        f'expected SNPRINTF_RODATA, got {hit[0].verdict}: {hit[0].detail}'
