"""Tests for PPC64-SAC-CALLEE-001: callee-saved register classification in
SinkArgClassifierPPC64ELFv2.

Two new helpers added in session 50/51:
- _eval_callee_saved_reg: forward-scan for TOC-relative constants in callee-saved regs
- _is_callee_saved_from_entry_arg: backward-scan for 'mr rX, rY' where rY is entry arg

Integration test verifies the full path for:
  std r26, N(r1)           <- callee-save spill (store, must be skipped)
  mr r26, r3               <- r26 = entry arg r3
  ... (nops)
  ld r3, 0(r26)            <- r3 = *r26 = *r3_entry → ARG_PROPAGATED
  bl system@plt

This is the exact pattern found in libMIOpen.so.1.0 func 0x1c48ca00 (session 50).
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
    not _CS_OK,
    reason='capstone required',
)

from ablation.analyzers.sink_arg_classifier_ppc64_elfv2 import (
    SinkArgClassifierPPC64ELFv2,
)
from ablation.analyzers.sink_arg_classifier import (
    RODATA_CONST,
    ARG_PROPAGATED,
    UNKNOWN,
)

# ── constants ─────────────────────────────────────────────────────────────────

BASE_VA      = 0x10000000
FUNC_VA      = 0x10001000
SYSTEM_PLT   = 0x10013e00
RODATA_BASE  = 0x10020000
RODATA_END   = 0x10021000
TOC_BASE     = 0x10010000   # .got VA
R2_VAL       = TOC_BASE + 0x8000   # r2 = .got + 0x8000 (ELFv2 convention)

# ── encoding helpers ──────────────────────────────────────────────────────────

def _le(*words: int) -> bytes:
    return b''.join(struct.pack('<I', w & 0xFFFFFFFF) for w in words)

def _addis(rd: int, ra: int, hi: int) -> int:
    return 0x3C000000 | (rd << 21) | (ra << 16) | (hi & 0xFFFF)

def _addi(rd: int, ra: int, lo: int) -> int:
    return 0x38000000 | (rd << 21) | (ra << 16) | (lo & 0xFFFF)

def _ld(rd: int, disp: int, ra: int) -> int:
    return 0xE8000000 | (rd << 21) | (ra << 16) | (disp & 0xFFFF)

def _std(rs: int, disp: int, ra: int) -> int:
    return 0xF8000000 | (rs << 21) | (ra << 16) | (disp & 0xFFFF)

def _mr(rd: int, rs: int) -> int:
    return 0x7C000378 | (rs << 21) | (rd << 16) | (rs << 11)

def _bl(from_va: int, to_va: int) -> int:
    delta = (to_va - from_va) & 0x03FFFFFC
    return 0x48000001 | delta

def _nop() -> int:
    return 0x60000000


def _disasm(code: bytes, va: int = FUNC_VA) -> list:
    """Disassemble ppc64le bytes → list of capstone instructions."""
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_64, CS_MODE_LITTLE_ENDIAN
    cs = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    return list(cs.disasm(code, va))


def _make_clf_elfv2(code: bytes) -> SinkArgClassifierPPC64ELFv2:
    """Build a minimal SinkArgClassifierPPC64ELFv2 for classify_all() tests."""
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_64, CS_MODE_LITTLE_ENDIAN

    # ctx.plt maps VA → name (same as BinaryContext.plt: Dict[int, str]).
    PLT_VA_TO_NAME = {SYSTEM_PLT: 'system'}

    ctx = MagicMock()
    ctx.path = '/dev/null'
    ctx.base_va = BASE_VA
    ctx.plt = PLT_VA_TO_NAME
    ctx.exports = {}
    ctx.func_starts = sorted([FUNC_VA])
    ctx.thumb_funcs = set()

    def _callers_of(va):
        if va == SYSTEM_PLT:
            return [FUNC_VA]
        return []
    ctx.callers_of = _callers_of

    clf = SinkArgClassifierPPC64ELFv2.__new__(SinkArgClassifierPPC64ELFv2)
    clf._ctx           = ctx
    clf._data          = code
    # _plt_rev maps name → VA (reversed from ctx.plt).
    clf._plt_rev       = {name: va for va, name in PLT_VA_TO_NAME.items()}
    clf._sinks         = {'system': 0}
    clf._snprintf_plts = {}
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]
    clf._dead_sinks    = []
    clf._bin           = None
    clf._r2            = R2_VAL

    clf._cs = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN)
    clf._cs.detail = True

    clf._va_to_file_offset = lambda va: va - FUNC_VA  # type: ignore[method-assign]

    return clf


# ── helper method tests ────────────────────────────────────────────────────────

@_SKIP_DEPS
def test_eval_callee_saved_reg_addis_addi_returns_va() -> None:
    """addis r26, r2, HI; addi r26, r26, LO → R2_VAL + (HI<<16) + LO."""
    from capstone.ppc_const import PPC_REG_R0
    r26 = PPC_REG_R0 + 26

    offset = 0x800   # arbitrary offset from r2
    hi = (offset >> 16) & 0xFFFF
    lo = offset & 0xFFFF
    code = _le(
        _addis(26, 2, hi),    # addis r26, r2, HI
        _addi(26, 26, lo),    # addi r26, r26, LO
        _nop(),               # use site (idx=2)
    )
    insns = _disasm(code)

    clf = SinkArgClassifierPPC64ELFv2.__new__(SinkArgClassifierPPC64ELFv2)
    clf._r2 = R2_VAL
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]
    clf._data = b''

    result = clf._eval_callee_saved_reg(insns, r26, use_idx=2)
    expected = (R2_VAL + (hi << 16) + lo) & 0xFFFFFFFFFFFFFFFF
    assert result == expected, f'expected {expected:#x}, got {result!r}'


@_SKIP_DEPS
def test_eval_callee_saved_reg_skips_std_spill() -> None:
    """std r26, N(r1) (callee-save spill) must not be treated as a write that
    invalidates the tracked value."""
    from capstone.ppc_const import PPC_REG_R0
    r26 = PPC_REG_R0 + 26

    offset = 0x100
    hi = (offset >> 16) & 0xFFFF
    lo = offset & 0xFFFF
    code = _le(
        _addis(26, 2, hi),          # addis r26, r2, HI
        _addi(26, 26, lo),          # addi r26, r26, LO
        _std(26, 0x800, 1),         # std r26, 0x800(r1) — save to stack
        _nop(),                     # use site (idx=3)
    )
    insns = _disasm(code)

    clf = SinkArgClassifierPPC64ELFv2.__new__(SinkArgClassifierPPC64ELFv2)
    clf._r2 = R2_VAL
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]
    clf._data = b''

    result = clf._eval_callee_saved_reg(insns, r26, use_idx=3)
    expected = (R2_VAL + (hi << 16) + lo) & 0xFFFFFFFFFFFFFFFF
    assert result == expected, (
        f'std spill should not invalidate val; expected {expected:#x}, got {result!r}'
    )


@_SKIP_DEPS
def test_eval_callee_saved_reg_ld_restore_returns_none() -> None:
    """ld r26, 0x800(r1) (callee-save restore) is NOT a TOC-relative load (base=r1)
    → _eval_callee_saved_reg returns None."""
    from capstone.ppc_const import PPC_REG_R0
    r26 = PPC_REG_R0 + 26

    code = _le(
        _ld(26, 0x800, 1),   # ld r26, 0x800(r1) — restore from stack
        _nop(),              # use site (idx=1)
    )
    insns = _disasm(code)

    clf = SinkArgClassifierPPC64ELFv2.__new__(SinkArgClassifierPPC64ELFv2)
    clf._r2 = R2_VAL
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]
    clf._data = b''

    result = clf._eval_callee_saved_reg(insns, r26, use_idx=1)
    assert result is None, f'callee-save restore should return None, got {result!r}'


@_SKIP_DEPS
def test_is_callee_saved_from_entry_arg_mr_detected() -> None:
    """mr r26, r3 (entry arg r3) → True."""
    from capstone.ppc_const import PPC_REG_R0
    r26 = PPC_REG_R0 + 26

    code = _le(
        _mr(26, 3),   # mr r26, r3
        _nop(),       # use site (idx=1)
    )
    insns = _disasm(code)

    clf = SinkArgClassifierPPC64ELFv2.__new__(SinkArgClassifierPPC64ELFv2)
    clf._r2 = R2_VAL
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]

    assert clf._is_callee_saved_from_entry_arg(insns, r26, use_idx=1) is True


@_SKIP_DEPS
def test_is_callee_saved_from_entry_arg_skips_std_spill() -> None:
    """std r26, N(r1) between mr r26, r3 and use site — store is skipped,
    mr is found → True."""
    from capstone.ppc_const import PPC_REG_R0
    r26 = PPC_REG_R0 + 26

    code = _le(
        _std(26, 0x4b0, 1),  # std r26, 0x4b0(r1) — callee-save spill
        _mr(26, 3),          # mr r26, r3
        _nop(),              # use site (idx=2)
    )
    insns = _disasm(code)

    clf = SinkArgClassifierPPC64ELFv2.__new__(SinkArgClassifierPPC64ELFv2)
    clf._r2 = R2_VAL
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]

    assert clf._is_callee_saved_from_entry_arg(insns, r26, use_idx=2) is True


@_SKIP_DEPS
def test_is_callee_saved_from_entry_arg_ld_restore_is_false() -> None:
    """ld r26, 0x800(r1) (callee-save restore, not an entry arg copy) → False."""
    from capstone.ppc_const import PPC_REG_R0
    r26 = PPC_REG_R0 + 26

    code = _le(
        _ld(26, 0x800, 1),  # ld r26, 0x800(r1) — restore (caller's r26)
        _nop(),             # use site (idx=1)
    )
    insns = _disasm(code)

    clf = SinkArgClassifierPPC64ELFv2.__new__(SinkArgClassifierPPC64ELFv2)
    clf._r2 = R2_VAL
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]

    assert clf._is_callee_saved_from_entry_arg(insns, r26, use_idx=1) is False


@_SKIP_DEPS
def test_is_callee_saved_from_entry_arg_non_entry_reg_is_false() -> None:
    """mr r26, r30 (r30 is NOT an entry arg) → False."""
    from capstone.ppc_const import PPC_REG_R0
    r26 = PPC_REG_R0 + 26

    code = _le(
        _mr(26, 30),  # mr r26, r30 (r30 is callee-saved, not entry arg)
        _nop(),       # use site (idx=1)
    )
    insns = _disasm(code)

    clf = SinkArgClassifierPPC64ELFv2.__new__(SinkArgClassifierPPC64ELFv2)
    clf._r2 = R2_VAL
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]

    assert clf._is_callee_saved_from_entry_arg(insns, r26, use_idx=1) is False


# ── integration test: libMIOpen popen pattern ─────────────────────────────────

@_SKIP_DEPS
def test_ld_r3_callee_saved_entry_arg_arg_propagated() -> None:
    """Integration test: the exact libMIOpen popen(UNKNOWN) pattern from session 50.

    std r26, 0x4b0(r1)   <- callee-save r26 to stack (must be skipped)
    mr r26, r3           <- r26 = entry arg r3 (struct ptr from caller)
    nop × 5              <- simulated function body
    ld r3, 0(r26)        <- r3 = *r26 = *r3_entry → ARG_PROPAGATED
    bl system@plt

    Before PPC64-SAC-CALLEE-001: SAC returned UNKNOWN (std was incorrectly treated
    as a write to r26 that set r26's known value to None, or the mr was simply not
    found because _eval_callee_saved_reg didn't handle mr).
    After fix: _is_callee_saved_from_entry_arg detects mr r26,r3 → ARG_PROPAGATED.
    """
    n_nops = 5
    bl_offset = (2 + n_nops + 1) * 4   # bytes from FUNC_VA to BL
    code = _le(
        _std(26, 0x4b0, 1),               # idx 0: callee-save r26
        _mr(26, 3),                        # idx 1: r26 = entry arg r3
        *[_nop() for _ in range(n_nops)],  # idx 2..n_nops+1: filler
        _ld(3, 0, 26),                     # idx n_nops+2: ld r3, 0(r26)
        _bl(FUNC_VA + bl_offset, SYSTEM_PLT),   # idx n_nops+3: bl system
    )
    clf = _make_clf_elfv2(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == ARG_PROPAGATED, (
        f'expected ARG_PROPAGATED, got {hit[0].verdict}: {hit[0].detail}'
    )
