"""Unit tests for SinkArgClassifierPPC32.

Tests verify argument classification on hand-encoded PPC32 BE byte sequences.
Each test encodes a minimal function stub, wraps it in a mock context,
and asserts the expected verdict.

Architecture notes (PPC32 System V ELF ABI):
  - Arguments passed in r3-r10: r3=arg0, r4=arg1, r5=arg2 ...
  - lis rX, HI; addi rX, rX, LO → 32-bit immediate (RODATA_CONST if in .rodata).
  - li rX, imm → small constant (RODATA_CONST).
  - mr rX, rY → decoded by Capstone as: or rD, rA, rA (id=843).
  - lwz rX, N(r1) → stack load; triggers snprintf backtrack or entry-arg detection.
  - addi rX, r1, N → stack address; same backtrack path.
  - lwz rX, N(rY) rY!=r1 and rY in {r3..r10} → ARG_PROPAGATED.
  - If arg_reg is an entry register unmodified in lookback window → ARG_PROPAGATED.
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

from ablation.analyzers.sink_arg_classifier_ppc32 import (
    SinkArgClassifierPPC32,
    SinkArgClassifierPPC32BE,
    RODATA_CONST,
    ARG_PROPAGATED,
    SNPRINTF_RODATA,
    UNKNOWN,
)

# ── constants ─────────────────────────────────────────────────────────────────

BASE_VA      = 0x10000000
FUNC_VA      = 0x10001000
SYSTEM_PLT   = 0x10013e00
STRCPY_PLT   = 0x10013e10
SPRINTF_PLT  = 0x10013e20
SNPRINTF_PLT = 0x10013e30
RODATA_BASE  = 0x10020000   # .rodata start
RODATA_END   = 0x10021000
RODATA_STR   = 0x10020100   # a string in .rodata

DEFAULT_PLT = {
    SYSTEM_PLT:   'system',
    STRCPY_PLT:   'strcpy',
    SPRINTF_PLT:  'sprintf',
    SNPRINTF_PLT: 'snprintf',
}


# ── helpers ───────────────────────────────────────────────────────────────────

def _ppc32_be(*words: int) -> bytes:
    """Pack big-endian 32-bit words."""
    return b''.join(struct.pack('>I', w & 0xFFFFFFFF) for w in words)


def _bl(from_va: int, to_va: int) -> int:
    """PPC32 BL instruction: opcode 0x48 | LI<<2 | LK=1."""
    delta = (to_va - from_va) & 0x03FFFFFC
    return 0x48000001 | delta


def _lis(rd: int, hi: int) -> int:
    """lis rD, hi  — addis rD, r0, hi"""
    return (0x3C000000 | (rd << 21) | (hi & 0xFFFF))


def _addi(rd: int, ra: int, lo: int) -> int:
    """addi rD, rA, lo"""
    return (0x38000000 | (rd << 21) | (ra << 16) | (lo & 0xFFFF))


def _li(rd: int, imm: int) -> int:
    """li rD, imm  — addi rD, r0, imm"""
    return _addi(rd, 0, imm)


def _lwz(rd: int, disp: int, ra: int) -> int:
    """lwz rD, disp(rA)"""
    return (0x80000000 | (rd << 21) | (ra << 16) | (disp & 0xFFFF))


def _stw(rs: int, disp: int, ra: int) -> int:
    """stw rS, disp(rA)"""
    return (0x90000000 | (rs << 21) | (ra << 16) | (disp & 0xFFFF))


def _mr(rd: int, rs: int) -> int:
    """mr rD, rS  — PPC OR instruction encoding: opcode=31, extended=444, rs==rb."""
    return (0x7C000378 | (rs << 21) | (rd << 16) | (rs << 11))


def _addi_r1(rd: int, disp: int) -> int:
    """addi rD, r1, disp"""
    return _addi(rd, 1, disp)


def _make_clf(code: bytes, func_va: int = FUNC_VA) -> SinkArgClassifierPPC32:
    """Build classifier from raw PPC32 BE bytes with a mock context."""
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

    clf = SinkArgClassifierPPC32.__new__(SinkArgClassifierPPC32)
    clf._ctx           = ctx
    clf._data          = code
    clf._plt_rev       = {v: k for k, v in DEFAULT_PLT.items()}
    clf._sinks         = {'system': 0, 'strcpy': 0, 'sprintf': 0, 'snprintf': 0}
    clf._snprintf_plts = {}
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]
    clf._dead_sinks    = []
    clf._bin           = None
    clf._cs            = None

    if _CS_OK:
        from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
        clf._cs = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
        clf._cs.detail = True

    # Override _va_to_file_offset: file offset = va - func_va
    clf._va_to_file_offset = lambda va: va - func_va  # type: ignore[method-assign]

    # Wire snprintf PLT
    clf._snprintf_plts = {SNPRINTF_PLT: 2, SPRINTF_PLT: 1}

    return clf


# ── tests ─────────────────────────────────────────────────────────────────────

@_SKIP_DEPS
def test_lis_addi_rodata_rodata_const() -> None:
    """lis r3, HI; addi r3, r3, LO where combined VA is in .rodata → RODATA_CONST."""
    hi = RODATA_STR >> 16
    lo = RODATA_STR & 0xFFFF
    # Must encode low half as signed offset that, when added to (hi<<16), gives RODATA_STR
    # If LO >= 0x8000, lis uses hi+1 and lo becomes negative: (hi+1)<<16 + (lo-0x10000)
    if lo >= 0x8000:
        hi += 1
        lo_signed = lo - 0x10000
    else:
        lo_signed = lo

    code = _ppc32_be(
        _lis(3, hi),
        _addi(3, 3, lo_signed & 0xFFFF),
        _bl(FUNC_VA + 8, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    assert results, 'no results from classify_all'
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system call result'
    assert hit[0].verdict == RODATA_CONST, f'expected RODATA_CONST, got {hit[0].verdict}: {hit[0].detail}'


@_SKIP_DEPS
def test_li_zero_rodata_const() -> None:
    """li r3, 0 (NULL) → RODATA_CONST."""
    code = _ppc32_be(
        _li(3, 0),
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system call result'
    assert hit[0].verdict == RODATA_CONST, f'expected RODATA_CONST, got {hit[0].verdict}'


@_SKIP_DEPS
def test_mr_from_entry_arg_propagated() -> None:
    """mr r3, r5 (from entry r5) → ARG_PROPAGATED."""
    code = _ppc32_be(
        _mr(3, 5),         # mr r3, r5 — decoded: or r3, r5, r5
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system call result'
    assert hit[0].verdict == ARG_PROPAGATED, f'expected ARG_PROPAGATED, got {hit[0].verdict}: {hit[0].detail}'


@_SKIP_DEPS
def test_unmodified_entry_reg_arg_propagated() -> None:
    """r3 never written in window (entry arg) → ARG_PROPAGATED."""
    code = _ppc32_be(
        _li(5, 0x42),            # unrelated: li r5, 0x42
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit
    assert hit[0].verdict == ARG_PROPAGATED, f'expected ARG_PROPAGATED, got {hit[0].verdict}'


@_SKIP_DEPS
def test_lwz_from_entry_reg_struct_arg_propagated() -> None:
    """lwz r3, 0x10(r4) where r4 is entry reg → ARG_PROPAGATED (struct field of arg)."""
    code = _ppc32_be(
        _lwz(3, 0x10, 4),      # lwz r3, 0x10(r4)
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit
    assert hit[0].verdict == ARG_PROPAGATED, f'expected ARG_PROPAGATED, got {hit[0].verdict}'


@_SKIP_DEPS
def test_strcpy_dest_r3_rodata_const() -> None:
    """strcpy(dest=RODATA_STR, src=r4): arg_pos=0 → RODATA_CONST for dest."""
    hi = RODATA_STR >> 16
    lo = RODATA_STR & 0xFFFF
    if lo >= 0x8000:
        hi += 1
        lo_signed = lo - 0x10000
    else:
        lo_signed = lo

    code = _ppc32_be(
        _lis(3, hi),
        _addi(3, 3, lo_signed & 0xFFFF),
        _bl(FUNC_VA + 8, STRCPY_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'strcpy']
    assert hit
    assert hit[0].verdict == RODATA_CONST, f'expected RODATA_CONST, got {hit[0].verdict}'


@_SKIP_DEPS
def test_strcpy_dest_from_entry_arg_propagated() -> None:
    """strcpy(dest=r3_from_entry, src=...): r3 is unmodified entry arg → ARG_PROPAGATED."""
    code = _ppc32_be(
        _li(5, 0),             # unrelated
        _bl(FUNC_VA + 4, STRCPY_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'strcpy']
    assert hit
    assert hit[0].verdict == ARG_PROPAGATED, f'expected ARG_PROPAGATED, got {hit[0].verdict}'


@_SKIP_DEPS
def test_snprintf_rodata_fmt_snprintf_rodata() -> None:
    """snprintf(r3=stack_buf, r4=size, r5=RODATA_fmt) then strcpy(r3=stack_buf) → SNPRINTF_RODATA."""
    hi = RODATA_STR >> 16
    lo = RODATA_STR & 0xFFFF
    if lo >= 0x8000:
        hi += 1
        lo_signed = lo - 0x10000
    else:
        lo_signed = lo

    # Function layout: addi r3,r1,0x10 ; lis r5,hi ; addi r5,r5,lo ; bl snprintf
    #                  addi r3,r1,0x10 ; bl strcpy
    off0 = FUNC_VA
    snprintf_va = off0 + 16  # 4 insns before snprintf bl
    strcpy_va   = off0 + 28  # 3 insns after snprintf bl

    code = _ppc32_be(
        _addi_r1(3, 0x10),         # addi r3, r1, 0x10   [+0]
        _li(4, 64),                # li r4, 64            [+4]
        _lis(5, hi),               # lis r5, hi           [+8]
        _addi(5, 5, lo_signed & 0xFFFF),  # addi r5,r5,lo [+12]
        _bl(snprintf_va, SNPRINTF_PLT),   # bl snprintf   [+16]
        _addi_r1(3, 0x10),         # addi r3, r1, 0x10   [+20]
        _li(4, 0),                 # li r4, 0 (dummy src) [+24]
        _bl(strcpy_va, STRCPY_PLT),       # bl strcpy    [+28]
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'strcpy']
    assert hit, 'no strcpy result'
    assert hit[0].verdict == SNPRINTF_RODATA, f'expected SNPRINTF_RODATA, got {hit[0].verdict}: {hit[0].detail}'


@_SKIP_DEPS
def test_lis_addi_not_rodata_unknown() -> None:
    """lis r3, HI; addi r3, r3, LO with VA outside .rodata → UNKNOWN."""
    non_rodata_va = 0x12000000  # outside RODATA_BASE..RODATA_END
    hi = non_rodata_va >> 16
    lo = non_rodata_va & 0xFFFF

    code = _ppc32_be(
        _lis(3, hi),
        _addi(3, 3, lo),
        _bl(FUNC_VA + 8, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit
    assert hit[0].verdict == UNKNOWN, f'expected UNKNOWN, got {hit[0].verdict}'


@_SKIP_DEPS
def test_lwz_struct_unknown_base_unknown() -> None:
    """lwz r3, 0x20(r30) where r30 is not an entry reg → UNKNOWN."""
    code = _ppc32_be(
        _lwz(3, 0x20, 30),     # lwz r3, 0x20(r30)  — r30 is GOT base, not entry arg
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit
    assert hit[0].verdict == UNKNOWN, f'expected UNKNOWN, got {hit[0].verdict}'


@_SKIP_DEPS
def test_entry_arg_stw_save_detected() -> None:
    """
    stw r3, 8(r1) in prologue + lwz r3, 8(r1) later → entry arg detected via _is_entry_arg_save.
    """
    code = _ppc32_be(
        _stw(3, 8, 1),         # stw r3, 8(r1)  — save arg0 in prologue
        _li(3, 99),            # li r3, 99       — overwrite r3
        _lwz(3, 8, 1),         # lwz r3, 8(r1)   — reload from stack
        _bl(FUNC_VA + 12, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit
    assert hit[0].verdict == ARG_PROPAGATED, f'expected ARG_PROPAGATED, got {hit[0].verdict}: {hit[0].detail}'


# ── SinkArgClassifierPPC32BE canonical-name tests ─────────────────────────────

@_SKIP_DEPS
def test_ppc32be_canonical_name():
    """type(clf).__name__ returns SinkArgClassifierPPC32BE, not the alias."""
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
    ctx = MagicMock()
    ctx.path = '/dev/null'
    ctx.base_va = BASE_VA
    ctx.plt = DEFAULT_PLT
    ctx.exports = {}
    ctx.func_starts = [FUNC_VA]
    ctx.thumb_funcs = set()
    ctx.callers_of = lambda va: [FUNC_VA] if va in DEFAULT_PLT else []
    clf = SinkArgClassifierPPC32BE.__new__(SinkArgClassifierPPC32BE)
    clf._ctx = ctx
    clf._data = b'\x00' * 4
    clf._plt_rev = {}
    clf._sinks = {}
    clf._snprintf_plts = {}
    clf._rodata_ranges = []
    clf._dead_sinks = []
    clf._bin = None
    clf._cs = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
    clf._cs.detail = True
    clf._va_to_file_offset = lambda va: va - FUNC_VA
    assert type(clf).__name__ == 'SinkArgClassifierPPC32BE'


@_SKIP_DEPS
def test_ppc32be_r3_rodata_const():
    """r3-register trace: lis r3, HI / addi r3, r3, LO / bl system → RODATA_CONST.

    PPC32 BE SysV ABI: arg0 is in r3.  _find_reg_for_arg() walks backward from
    the BL and classifies the lis+addi pair as a 32-bit immediate.
    _classify_value() checks if the reconstructed VA is in the .rodata range.
    """
    hi = RODATA_STR >> 16
    lo = RODATA_STR & 0xFFFF
    code = _ppc32_be(
        _lis(3, hi),
        _addi(3, 3, lo),
        _bl(FUNC_VA + 8, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'r3-register trace must find the system call site'
    assert hit[0].verdict == RODATA_CONST, (
        f'expected RODATA_CONST, got {hit[0].verdict}; detail={hit[0].detail}'
    )
