"""Regression tests for SAC _align_func_va cross-boundary attribution bug.

Root cause (fixed 2026-10-26):
  _align_func_va(func_va) built the search window as data[off-512:off+1].
  When func_va IS at an ENDBR64, only byte 0 of the 4-byte ENDBR64 falls
  inside the window, so rfind(ENDBR64) cannot find it.  The search then
  falls back to the previous function's ENDBR64 — causing _classify_function
  to disassemble starting from the PREVIOUS function and to attribute any
  sink call found there back to the previous function's func_va.

Fix: early-exit if data[off:off+4] == ENDBR64 (or data[off:off+1] == PUSH_RBP).
  This prevents any function that already starts at a prologue from triggering
  a backward search.

Observed in the wild (PanGpHipMp 6.3.3-c42):
  Before fix: system@0x5b144 reported under fn@0x5b050 AND fn@0x5b0b0 (7 total sites)
  After fix:  system@0x5b144 reported only under fn@0x5b0b0 (4 total sites)
  Also fixed: execl@0x5ae37 duplicate (2→1) and popen@0x79cb1 duplicate (2→1)
"""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

_CS_OK   = False
_LIEF_OK = False
try:
    import capstone as _cap
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

from ablation.analyzers.sink_arg_classifier import (
    SinkArgClassifier,
    RODATA_CONST,
    UNKNOWN,
    _MAX_FUNC_BYTES,
)

PANGPS_HIPMPM = (
    '/tmp/pangp_re/6.3.3-c42/extracted/opt/paloaltonetworks/globalprotect/PanGpHipMp'
)

# ── VA layout for synthetic test ──────────────────────────────────────────────
# Two adjacent ENDBR64-prefixed functions; fn2 contains the system() call.
# fn2_offset = 0x60 puts fn1's ENDBR64 within _ALIGN_SEARCH_BACK (512) of fn2.

BASE_VA    = 0x400000   # start of data buffer = start of fn1
FN1_VA     = 0x400000   # fn1: ENDBR64 + return (no sink call)
FN2_OFFSET = 0x60       # fn2 starts 0x60 bytes after fn1
FN2_VA     = BASE_VA + FN2_OFFSET  # 0x400060
SYS_PLT    = 0x401020   # system() PLT stub VA
RODATA_VA  = 0x402000   # start of fake .rodata
RODATA_END = 0x403000


def _call_rel32(from_va: int, to_va: int) -> bytes:
    rel = to_va - (from_va + 5)
    return b'\xe8' + struct.pack('<i', rel)


def _build_clf() -> SinkArgClassifier:
    """
    Build a SinkArgClassifier with two adjacent functions:

      fn1 @ FN1_VA (0x400000):
        endbr64                     ← prologue the bug used to jump back to
        push rbp / mov rbp,rsp / pop rbp / ret

      fn2 @ FN2_VA (0x400060):
        endbr64                     ← fn2's own prologue
        lea rdi, [rip + 0x1f95]    ← points to RODATA_VA (0x402000)
        call system_plt (0x401020) ← the sink call
        ret

    Without the fix: _align_func_va(FN2_VA) returns FN1_VA; system call
    gets attributed to fn@0x400000.
    With the fix: returns FN2_VA; system call attributed to fn@0x400060.
    """
    # ── fn1 ──────────────────────────────────────────────────────────────────
    fn1 = (
        b'\xf3\x0f\x1e\xfa'   # endbr64
        b'\x55'                # push rbp
        b'\x48\x89\xe5'        # mov rbp, rsp
        b'\x5d'                # pop rbp
        b'\xc3'                # ret
    )

    # ── fn2 ──────────────────────────────────────────────────────────────────
    # endbr64 at FN2_VA (0x400060)
    fn2_endbr64 = b'\xf3\x0f\x1e\xfa'
    # lea rdi, [rip + disp] at FN2_VA+4 (0x400064), len=7, rip=0x40006b
    # disp = RODATA_VA - 0x40006b = 0x402000 - 0x40006b = 0x1f95
    fn2_lea = b'\x48\x8d\x3d' + struct.pack('<i', RODATA_VA - (FN2_VA + 4 + 7))
    # call system at FN2_VA+4+7 = 0x40006b
    call_va = FN2_VA + 4 + 7
    fn2_call = _call_rel32(call_va, SYS_PLT)
    fn2_ret  = b'\xc3'
    fn2 = fn2_endbr64 + fn2_lea + fn2_call + fn2_ret

    # ── buffer: fn1 at offset 0, fn2 at FN2_OFFSET, rest NOPs ─────────────
    buf = bytearray(0x2000)
    buf[0:len(fn1)] = fn1
    buf[FN2_OFFSET:FN2_OFFSET + len(fn2)] = fn2

    # ── wire up the classifier ────────────────────────────────────────────
    clf = SinkArgClassifier.__new__(SinkArgClassifier)
    clf._path = '/dev/null'
    clf._data = bytes(buf)
    clf._plt  = {SYS_PLT: 'system'}
    clf._plt_rev = {'system': SYS_PLT}
    clf._rodata = [(RODATA_VA, RODATA_END)]
    clf._func_starts = [FN1_VA, FN2_VA]
    clf._sinks = {'system': 0}
    clf._snprintf_plts = {}
    clf._plt_caller_counts = {SYS_PLT: 1}
    clf._dead_sinks = []
    clf._bin = None
    clf._va_to_file_offset = lambda va: va - BASE_VA

    cs = _cap.Cs(_cap.CS_ARCH_X86, _cap.CS_MODE_64)
    cs.detail = True
    clf._md = cs
    return clf


# ── unit tests: synthetic two-function binary ─────────────────────────────────

@_SKIP_DEPS
class TestEndbr64Attribution:
    @pytest.fixture(autouse=True)
    def _setup(self):
        self._clf = _build_clf()
        self._results = self._clf.classify_all()

    def test_exactly_one_result(self):
        assert len(self._results) == 1, (
            f'expected 1 result, got {len(self._results)}: '
            f'{[r.fmt() for r in self._results]}'
        )

    def test_attributed_to_fn2_not_fn1(self):
        r = self._results[0]
        assert r.func_va == FN2_VA, (
            f'system call attributed to fn@{hex(r.func_va)}, '
            f'expected fn@{hex(FN2_VA)} — cross-boundary attribution bug not fixed'
        )

    def test_fn1_has_no_findings(self):
        fn1_results = [r for r in self._results if r.func_va == FN1_VA]
        assert fn1_results == [], (
            f'fn@{hex(FN1_VA)} should have no findings, got: '
            f'{[r.fmt() for r in fn1_results]}'
        )

    def test_call_va_correct(self):
        expected_call_va = FN2_VA + 4 + 7   # after endbr64 (4) + lea (7)
        assert self._results[0].call_va == expected_call_va

    def test_verdict_rodata_const(self):
        assert self._results[0].verdict == RODATA_CONST


# ── integration tests: PanGpHipMp 6.3.3-c42 ─────────────────────────────────

def _has_hipmpm():
    return Path(PANGPS_HIPMPM).exists()


@pytest.mark.skipif(not _has_hipmpm(), reason='PanGpHipMp 6.3.3-c42 binary not extracted')
class TestPanGpHipMpAttribution:
    """
    Before fix: 7 results (duplicates across fn boundaries).
    After fix:  4 results (each call site attributed once, to its real owner).
    """

    @pytest.fixture(autouse=True)
    def _setup(self):
        from ablation.analyzers.binary_context import BinaryContext
        ctx = BinaryContext.load_or_build(PANGPS_HIPMPM)
        clf = SinkArgClassifier.from_context(ctx)
        self._results = clf.classify_all()

    def test_total_site_count(self):
        assert len(self._results) == 4, (
            f'expected 4 (was 7 before fix), got {len(self._results)}: '
            + ', '.join(r.fmt() for r in self._results)
        )

    def test_system_call_attributed_to_fn_5b0b0_not_5b050(self):
        sys_results = [r for r in self._results if r.sink_name == 'system']
        assert len(sys_results) == 1
        r = sys_results[0]
        assert r.call_va == 0x5b144
        assert r.func_va == 0x5b0b0, (
            f'system@0x5b144 attributed to fn@{hex(r.func_va)}, '
            f'expected fn@0x5b0b0 (was fn@0x5b050 before fix)'
        )

    def test_no_system_false_attribution_to_fn_5b050(self):
        false_results = [r for r in self._results
                         if r.sink_name == 'system' and r.func_va == 0x5b050]
        assert false_results == [], (
            f'false attribution to fn@0x5b050 still present: '
            f'{[r.fmt() for r in false_results]}'
        )

    def test_execl_appears_exactly_once(self):
        execl_results = [r for r in self._results if r.sink_name == 'execl']
        assert len(execl_results) == 1, (
            f'execl should appear once (was 2 before fix), '
            f'got {len(execl_results)}'
        )

    def test_popen_linux_system_cmd_appears_exactly_once(self):
        popen_fn79c80 = [r for r in self._results
                         if r.sink_name == 'popen' and r.func_va == 0x79c80]
        assert len(popen_fn79c80) == 1

    def test_no_popen_false_attribution_to_fn_79c60(self):
        false_results = [r for r in self._results
                         if r.sink_name == 'popen' and r.func_va == 0x79c60]
        assert false_results == [], (
            f'false popen attribution to fn@0x79c60 still present: '
            f'{[r.fmt() for r in false_results]}'
        )
