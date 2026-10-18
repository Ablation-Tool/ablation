"""Unit tests for SinkArgClassifierS390X.

Tests verify the canonical class name and the %r2 register-trace logic on
hand-encoded s390x byte sequences disassembled by Capstone CS_ARCH_SYSZ.

Architecture notes (s390x System V ELF ABI):
  - arg0 → r2, arg1 → r3, arg2 → r4 (Capstone SYSZ_REG_2, SYSZ_REG_3 …)
  - larl %rX, addr   — PC-relative address load (RODATA_CONST if addr in .rodata)
  - lgr  %rX, %rY   — register copy; if rY is entry-arg (r2-r6) → ARG_PROPAGATED
  - brasl %r14, tgt  — branch-and-link (call instruction, opcode 0xC0/E5)

The tests drive _classify_reg() directly with real Capstone output so that the
register-trace path is exercised without a real s390x binary on disk.
"""

import struct
import pytest

_CS_OK = False
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

from ablation.analyzers.sink_arg_classifier_s390 import (
    SinkArgClassifierS390X,
    SinkArgClassifierS390,
    RODATA_CONST,
    ARG_PROPAGATED,
    UNKNOWN,
)

# ── constants ─────────────────────────────────────────────────────────────────

FUNC_VA      = 0x10000000
SYSTEM_PLT   = 0x10010000
RODATA_STR   = 0x10020100
RODATA_END   = 0x10021000


# ── helpers ───────────────────────────────────────────────────────────────────

def _s390x_larl(rd: int, from_va: int, to_va: int) -> bytes:
    """Encode larl rD, to_va from from_va (6 bytes, big-endian)."""
    off_words = (to_va - from_va) >> 1
    return bytes([0xC0, (rd << 4) | 0x00]) + struct.pack('>i', off_words)


def _s390x_lgr(rd: int, rs: int) -> bytes:
    """Encode lgr rD, rS — register copy (4 bytes)."""
    return bytes([0xB9, 0x04, 0x00, (rd << 4) | rs])


def _s390x_brasl(from_va: int, to_va: int) -> bytes:
    """Encode brasl r14, to_va (6 bytes)."""
    off_words = (to_va - from_va) >> 1
    return bytes([0xC0, 0xE5]) + struct.pack('>i', off_words)


def _disasm(code: bytes, start_va: int):
    """Disassemble s390x bytes and return capstone instruction list."""
    from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
    cs = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    cs.detail = True
    return list(cs.disasm(code, start_va))


def _make_clf(code: bytes) -> SinkArgClassifierS390X:
    """Build a minimal SinkArgClassifierS390X from raw bytes without touching disk."""
    from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
    clf = SinkArgClassifierS390X.__new__(SinkArgClassifierS390X)
    clf._path          = '/dev/null'
    clf._data          = code
    clf._sinks         = {'system': 0}
    clf._snprintf_plts = {}
    clf._rodata_ranges = [(RODATA_STR, RODATA_END)]
    clf._dead_sinks    = []
    clf._func_starts   = [FUNC_VA]
    clf._bin           = None
    clf._is_64bit      = True
    clf._cs            = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    clf._cs.detail     = True
    clf._va_to_file_offset = lambda va: va - FUNC_VA
    return clf


# ── canonical-name tests ───────────────────────────────────────────────────────

def test_s390x_canonical_name():
    """type(clf).__name__ == 'SinkArgClassifierS390X' (not the backward-compat alias)."""
    from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
    clf = SinkArgClassifierS390X.__new__(SinkArgClassifierS390X)
    clf._path = '/dev/null'
    clf._data = b''
    clf._sinks = {}
    clf._snprintf_plts = {}
    clf._rodata_ranges = []
    clf._dead_sinks = []
    clf._func_starts = []
    clf._bin = None
    clf._is_64bit = True
    clf._cs = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    clf._va_to_file_offset = lambda va: va
    assert type(clf).__name__ == 'SinkArgClassifierS390X'


def test_s390x_alias_points_to_canonical():
    """SinkArgClassifierS390 is the backward-compat alias — same class object."""
    assert SinkArgClassifierS390 is SinkArgClassifierS390X


# ── %r2 register-trace tests ──────────────────────────────────────────────────

@_SKIP_DEPS
def test_s390x_r2_larl_rodata_const():
    """r2-register trace: larl %r2, RODATA_ADDR / brasl %r14, system → RODATA_CONST.

    s390x SysV ABI: system()'s arg0 is in r2.  _classify_reg() walks backward
    from the brasl call and finds larl %r2, addr.  If addr is in a .rodata range,
    it returns RODATA_CONST.
    """
    larl  = _s390x_larl(2, FUNC_VA, RODATA_STR)          # larl %r2, RODATA_STR
    brasl = _s390x_brasl(FUNC_VA + len(larl), SYSTEM_PLT) # brasl %r14, system
    code  = larl + brasl

    clf  = _make_clf(code)
    insns = _disasm(code, FUNC_VA)
    assert len(insns) == 2, f'expected 2 insns, got {len(insns)}: {[i.mnemonic for i in insns]}'

    # call_idx=1 (the brasl), target_reg=SYSZ_REG_2 (r2 = arg0)
    from capstone.sysz_const import SYSZ_REG_2
    verdict = clf._classify_reg(insns, call_idx=1, target_reg=SYSZ_REG_2)
    assert verdict == RODATA_CONST, (
        f'larl %r2, rodata → expected RODATA_CONST, got {verdict!r}'
    )


@_SKIP_DEPS
def test_s390x_r2_lgr_arg_propagated():
    """r2-register trace: lgr %r2, %r3 / brasl %r14, system → ARG_PROPAGATED.

    lgr copies entry-arg register r3 into r2.  _classify_reg() sees the lgr,
    checks that the source (r3) is in the entry-arg set (r2-r6), and returns
    ARG_PROPAGATED without further recursion.
    """
    lgr   = _s390x_lgr(2, 3)                              # lgr %r2, %r3
    brasl = _s390x_brasl(FUNC_VA + len(lgr), SYSTEM_PLT)  # brasl %r14, system
    code  = lgr + brasl

    clf  = _make_clf(code)
    insns = _disasm(code, FUNC_VA)
    assert len(insns) == 2, f'expected 2 insns, got {len(insns)}: {[i.mnemonic for i in insns]}'

    from capstone.sysz_const import SYSZ_REG_2
    verdict = clf._classify_reg(insns, call_idx=1, target_reg=SYSZ_REG_2)
    assert verdict == ARG_PROPAGATED, (
        f'lgr %r2, %r3 → expected ARG_PROPAGATED, got {verdict!r}'
    )
