"""Unit tests for SinkArgClassifierARM64.

Tests verify argument classification on hand-encoded AArch64 byte sequences.
Each test encodes a minimal function stub, wires it into a mock context,
and asserts the expected verdict.

Architecture notes (AArch64 AAPCS64):
  - Arguments passed in x0-x7: x0=arg0, x1=arg1, x2=arg2 ...
  - ADRP xR, page; ADD xR, xR, #off → PIC string load (most common AArch64 pattern).
  - MOV x0, x1 disassembles as ORR x0, xzr, x1.
  - STR/STP first operand is the VALUE, not the destination — must not be
    treated as a write to the source register (_STORE_MNEMS exclusion).
  - MOVZ x0, #0 → NULL constant → RODATA_CONST.
"""

import struct
from unittest.mock import MagicMock

import pytest

_CS_OK = False
_LIEF_OK = False
try:
    import capstone  # noqa: F401
    _CS_OK = True
except ImportError:
    pass
try:
    import lief  # noqa: F401
    _LIEF_OK = True
except ImportError:
    pass

_SKIP_DEPS = pytest.mark.skipif(
    not _CS_OK,
    reason='capstone required',
)

from ablation.analyzers.sink_arg_classifier_arm64 import (
    SinkArgClassifierARM64,
    RODATA_CONST,
    ARG_PROPAGATED,
    UNKNOWN,
    SNPRINTF_RODATA,
)

# ── test constants ────────────────────────────────────────────────────────────
BASE_VA      = 0x00000000
FUNC_VA      = 0x10001000
SYSTEM_PLT   = 0x10013e00
STRCPY_PLT   = 0x10013e10
SNPRINTF_PLT = 0x10013e20
RODATA_BASE  = 0x10020000
RODATA_END   = 0x10021000
RODATA_STR   = 0x10020100   # a string in .rodata

DEFAULT_PLT = {
    SYSTEM_PLT:   'system',
    STRCPY_PLT:   'strcpy',
    SNPRINTF_PLT: 'snprintf',
}


# ── AArch64 encoding helpers ──────────────────────────────────────────────────

def _a64(*words: int) -> bytes:
    """Pack AArch64 instructions as little-endian 32-bit words."""
    return b''.join(struct.pack('<I', w & 0xFFFFFFFF) for w in words)


def _adrp(rd: int, from_va: int, target_page_va: int) -> int:
    """
    Encode ADRP xRd, target_page_va with PC=from_va.

    ADRP: [31]=1, [30:29]=immlo, [28:24]=10000, [23:5]=immhi, [4:0]=Rd
    Computes: page_offset = target_page_va - (from_va & ~0xFFF)
    imm21 = page_offset >> 12 (signed 21-bit)
    """
    pc_page = from_va & ~0xFFF
    page_offset = target_page_va - pc_page
    imm21 = page_offset >> 12
    immlo = imm21 & 3
    immhi = (imm21 >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | rd


def _add_imm64(rd: int, rn: int, imm12: int) -> int:
    """ADD xRd, xRn, #imm12 (64-bit)."""
    return 0x91000000 | (imm12 << 10) | (rn << 5) | rd


def _bl(from_va: int, to_va: int) -> int:
    """BL to_va with PC=from_va. Encodes 26-bit signed word offset."""
    delta = (to_va - from_va) >> 2
    return 0x94000000 | (delta & 0x3FFFFFF)


def _movz(rd: int, imm16: int, hw: int = 0) -> int:
    """MOVZ xRd, #imm16, LSL #(hw*16). hw=0 → no shift."""
    return 0xD2800000 | (hw << 21) | (imm16 << 5) | rd


def _mov_reg(rd: int, rm: int) -> int:
    """MOV xRd, xRm — encoded as ORR xRd, xzr, xRm."""
    # ORR (shifted register): [31]=1, [30:29]=01, [28:24]=01010,
    #   [23:22]=00, [21]=0, [20:16]=Rm, [15:10]=0, [9:5]=Rn=xzr=31, [4:0]=Rd
    return 0xAA000000 | (rm << 16) | (31 << 5) | rd


def _str64(rt: int, rn: int, off8: int) -> int:
    """STR xRt, [xRn, #off8] (unsigned offset, must be 8-byte aligned)."""
    return 0xF9000000 | ((off8 // 8) << 10) | (rn << 5) | rt


def _ldr64(rt: int, rn: int, off8: int) -> int:
    """LDR xRt, [xRn, #off8] (unsigned offset, must be 8-byte aligned)."""
    return 0xF9400000 | ((off8 // 8) << 10) | (rn << 5) | rt


# sp and x29 are register 31 in AArch64 instruction encoding
_SP  = 31
_X29 = 29   # frame pointer (Capstone decodes [x29, #N] as X29, not SP)


def _make_clf(
    code: bytes,
    func_va: int = FUNC_VA,
    extra_sinks: dict | None = None,
) -> SinkArgClassifierARM64:
    """Build a mock-context SinkArgClassifierARM64 from raw AArch64 bytes."""
    ctx = MagicMock()
    ctx.path = '/dev/null'
    ctx.base_va = BASE_VA
    ctx.plt = dict(DEFAULT_PLT)
    ctx.exports = {}
    ctx.func_starts = sorted([func_va])

    def _callers_of(name):
        for va, n in DEFAULT_PLT.items():
            if n == name:
                return [func_va]
        return []
    ctx.callers_of = _callers_of

    clf = SinkArgClassifierARM64.__new__(SinkArgClassifierARM64)
    clf._ctx           = ctx
    clf._data          = code
    clf._plt_rev       = {v: k for k, v in DEFAULT_PLT.items()}
    clf._sinks         = {'system': 0, 'strcpy': 0, 'snprintf': 0}
    if extra_sinks:
        clf._sinks.update(extra_sinks)
    clf._snprintf_plts = {SNPRINTF_PLT: 2}   # snprintf x2=fmt
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]
    clf._dead_sinks    = []
    clf._bin           = None
    clf._cs            = None

    if _CS_OK:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        clf._cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        clf._cs.detail = True

    # Map VAs to byte positions: offset = va - func_va
    clf._va_to_file_offset = lambda va: va - func_va  # type: ignore[method-assign]

    return clf


# ── tests ─────────────────────────────────────────────────────────────────────

@_SKIP_DEPS
def test_adrp_add_rodata_const() -> None:
    """ADRP x0, page; ADD x0, x0, #off where combined VA is in .rodata → RODATA_CONST."""
    page_va = RODATA_STR & ~0xFFF   # 0x10020000
    off     = RODATA_STR & 0xFFF    # 0x100
    code = _a64(
        _adrp(0, FUNC_VA,     page_va),        # adrp x0, 0x10020000
        _add_imm64(0, 0, off),                  # add  x0, x0, #0x100
        _bl(FUNC_VA + 8, SYSTEM_PLT),           # bl   system_plt
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    assert results, 'no results'
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == RODATA_CONST, f'got {hit[0].verdict}: {hit[0].detail}'


@_SKIP_DEPS
def test_adrp_add_not_rodata_unknown() -> None:
    """ADRP+ADD where combined VA is outside .rodata → UNKNOWN."""
    non_rodata_page = 0x10030000   # outside RODATA_BASE..RODATA_END
    code = _a64(
        _adrp(0, FUNC_VA, non_rodata_page),
        _add_imm64(0, 0, 0),                    # add x0, x0, #0
        _bl(FUNC_VA + 8, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == UNKNOWN, f'got {hit[0].verdict}'


@_SKIP_DEPS
def test_movz_zero_rodata_const() -> None:
    """MOVZ x0, #0 (NULL) → RODATA_CONST."""
    code = _a64(
        _movz(0, 0),                            # movz x0, #0
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == RODATA_CONST, f'got {hit[0].verdict}'


@_SKIP_DEPS
def test_movz_nonzero_rodata_const() -> None:
    """MOVZ x0, #0x42 → RODATA_CONST (compile-time constant)."""
    code = _a64(
        _movz(0, 0x42),                         # movz x0, #0x42
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == RODATA_CONST, f'got {hit[0].verdict}'


@_SKIP_DEPS
def test_mov_from_entry_reg_arg_propagated() -> None:
    """MOV x0, x1 where x1 is entry register → ARG_PROPAGATED."""
    code = _a64(
        _mov_reg(0, 1),                         # mov x0, x1
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == ARG_PROPAGATED, f'got {hit[0].verdict}: {hit[0].detail}'


@_SKIP_DEPS
def test_entry_arg_save_reload_arg_propagated() -> None:
    """
    Prologue STR x0, [sp, #8]; later LDR x0, [sp, #8] → ARG_PROPAGATED via _is_entry_arg_save.
    """
    code = _a64(
        _str64(0, _SP, 8),                      # str x0, [sp, #8]  (prologue save)
        _movz(1, 5),                            # movz x1, #5       (unrelated)
        _ldr64(0, _SP, 8),                      # ldr x0, [sp, #8]  (reload from stack)
        _bl(FUNC_VA + 12, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == ARG_PROPAGATED, f'got {hit[0].verdict}: {hit[0].detail}'


@_SKIP_DEPS
def test_ldr_struct_from_entry_base_arg_propagated() -> None:
    """LDR x0, [x1, #N] where x1 is entry reg → ARG_PROPAGATED (struct field of arg)."""
    code = _a64(
        _ldr64(0, 1, 16),                       # ldr x0, [x1, #16]
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == ARG_PROPAGATED, f'got {hit[0].verdict}: {hit[0].detail}'


@_SKIP_DEPS
def test_ldr_struct_from_non_entry_unknown() -> None:
    """LDR x0, [x19, #N] where x19 is callee-saved (not entry reg) → UNKNOWN."""
    # x19 = register 19 in instruction encoding
    code = _a64(
        _ldr64(0, 19, 8),                       # ldr x0, [x19, #8]  — x19 not entry reg
        _bl(FUNC_VA + 4, SYSTEM_PLT),
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    assert hit[0].verdict == UNKNOWN, f'got {hit[0].verdict}: {hit[0].detail}'


@_SKIP_DEPS
def test_store_mnemonic_not_treated_as_write() -> None:
    """
    STR x0, [sp, #8] must NOT be treated as a write to x0.

    This tests _STORE_MNEMS exclusion in _writes_reg(). Without the fix,
    STR would be identified as 'writing x0' and the backward trace would
    prematurely terminate at the STR. With the fix, STR is skipped and the
    MOVZ below it is found.

    Layout (going backward from BL):
      index 0: adrp x0, rodata_page   ← ADRP+ADD would give RODATA_CONST
      index 1: add  x0, x0, #off      ← completes ADRP+ADD
      index 2: str  x0, [sp, #8]      ← store; must be skipped by _writes_reg
      index 3: bl   system_plt
    """
    page_va = RODATA_STR & ~0xFFF
    off     = RODATA_STR & 0xFFF
    code = _a64(
        _adrp(0, FUNC_VA,     page_va),         # index 0: adrp
        _add_imm64(0, 0, off),                  # index 1: add
        _str64(0, _SP, 8),                      # index 2: str x0,[sp,#8] — must be skipped
        _bl(FUNC_VA + 12, SYSTEM_PLT),          # index 3: bl system
    )
    clf = _make_clf(code)
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'system']
    assert hit, 'no system result'
    # STR skipped → trace reaches ADRP+ADD → RODATA_CONST
    assert hit[0].verdict == RODATA_CONST, (
        f'expected RODATA_CONST (store exclusion working), got {hit[0].verdict}: {hit[0].detail}'
    )


@_SKIP_DEPS
def test_arg1_classification_x1_reg() -> None:
    """Classify arg position 1 (x1). ADRP+ADD → RODATA_CONST for x1."""
    page_va = RODATA_STR & ~0xFFF
    off     = RODATA_STR & 0xFFF
    # x1 = register 1 in instruction encoding
    code = _a64(
        _adrp(1, FUNC_VA,     page_va),         # adrp x1, rodata_page
        _add_imm64(1, 1, off),                  # add  x1, x1, #off
        _bl(FUNC_VA + 8, STRCPY_PLT),           # bl   strcpy  (arg_pos 0 = x0, need custom)
    )
    # Use strcpy but override its arg_pos to 1 to test x1 tracing
    clf = _make_clf(code)
    clf._sinks['strcpy'] = 1
    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'strcpy']
    assert hit, 'no strcpy result'
    assert hit[0].verdict == RODATA_CONST, f'got {hit[0].verdict}: {hit[0].detail}'


@_SKIP_DEPS
def test_add_sink_custom_arg_pos() -> None:
    """add_sink() registers a custom sink; MOVZ x3, #0 for arg_pos=3 → RODATA_CONST."""
    # Need a custom PLT entry for the custom sink
    CUSTOM_PLT_VA = 0x10013e30
    ctx = MagicMock()
    ctx.path = '/dev/null'
    ctx.base_va = BASE_VA
    ctx.plt = {**DEFAULT_PLT, CUSTOM_PLT_VA: 'custom_exec'}
    ctx.exports = {}
    ctx.func_starts = [FUNC_VA]
    ctx.callers_of = lambda name: [FUNC_VA] if name == 'custom_exec' else []

    clf = SinkArgClassifierARM64.__new__(SinkArgClassifierARM64)
    clf._ctx           = ctx
    clf._data          = b''
    clf._plt_rev       = {v: k for k, v in ctx.plt.items()}
    clf._sinks         = {}
    clf._snprintf_plts = {}
    clf._rodata_ranges = [(RODATA_BASE, RODATA_END)]
    clf._dead_sinks    = []
    clf._bin           = None

    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    clf._cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    clf._cs.detail = True

    # Register custom sink at arg_pos=3 (x3)
    clf.add_sink('custom_exec', arg_pos=3)

    # movz x3, #0 ; bl custom_exec
    code = _a64(
        _movz(3, 0),                            # movz x3, #0
        _bl(FUNC_VA + 4, CUSTOM_PLT_VA),
    )
    clf._data = code
    clf._va_to_file_offset = lambda va: va - FUNC_VA  # type: ignore[method-assign]

    results = clf.classify_all()
    hit = [r for r in results if r.sink_name == 'custom_exec']
    assert hit, 'no custom_exec result'
    assert hit[0].verdict == RODATA_CONST, f'got {hit[0].verdict}'


@_SKIP_DEPS
def test_dispatch_via_sac_for_path(tmp_path) -> None:
    """sac_for_path() on a real AArch64 ELF returns SinkArgClassifierARM64."""
    import lief as _lief
    if not _LIEF_OK:
        pytest.skip('lief required')

    # Build a minimal AArch64 ELF using the existing versalTcpIpbusShim if present
    import os
    shim = '/tmp/cern-wic-extract/versalTcpIpbusShim'
    if not os.path.exists(shim):
        pytest.skip('versalTcpIpbusShim not available')

    from ablation.analyzers.sink_arg_classifier import sac_for_path
    clf = sac_for_path(shim)
    assert type(clf).__name__ == 'SinkArgClassifierARM64'


@_SKIP_DEPS
def test_dispatch_via_sac_for_context() -> None:
    """sac_for_context() on a mock arm64 ctx returns SinkArgClassifierARM64."""
    from ablation.analyzers.sink_arg_classifier import sac_for_context

    ctx = MagicMock()
    ctx.path = '/dev/null'
    ctx.base_va = BASE_VA
    ctx.plt = DEFAULT_PLT
    ctx.exports = {}
    ctx.func_starts = []
    ctx.callers_of = lambda _: []
    ctx.arch = 'arm64'

    clf = sac_for_context(ctx)
    assert type(clf).__name__ == 'SinkArgClassifierARM64'
