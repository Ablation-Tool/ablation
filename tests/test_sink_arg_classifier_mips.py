"""Unit and integration tests for SinkArgClassifierMIPS.

Unit tests use mock objects and direct method calls.
Integration tests require the cwWtpd binary at CWWTPD_PATH; they are skipped
if the file does not exist.
"""

import struct
from pathlib import Path
from unittest.mock import MagicMock
import pytest

CWWTPD_PATH = '/tmp/fap_mips/rootfs/sbin/cwWtpd'
_SKIP_IF_NO_BIN = pytest.mark.skipif(
    not Path(CWWTPD_PATH).exists(),
    reason='cwWtpd binary not present',
)

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

_SKIP_IF_NO_DEPS = pytest.mark.skipif(
    not (_CS_OK and _LIEF_OK),
    reason='capstone and lief required',
)

from ablation.analyzers.sink_arg_classifier_mips import (
    SinkArgClassifierMIPS,
    _R_GP, _R_A0, _R_A1, _R_T9, _R_FP, _R_ZERO,
    RODATA_CONST, ARG_PROPAGATED, SNPRINTF_RODATA, UNKNOWN,
)


# ── helpers ────────────────────────────────────────────────────────────────────

def _make_mock_ctx(plt=None, exports=None, func_starts=None, path='/dev/null'):
    ctx = MagicMock()
    ctx.path = path
    ctx.plt = plt or {}
    ctx.exports = exports or {}
    ctx.func_starts = func_starts or []
    ctx.callers_of.return_value = []
    return ctx


def _make_clf_from_mock(plt=None, exports=None, func_starts=None):
    ctx = _make_mock_ctx(plt=plt, exports=exports, func_starts=func_starts)
    clf = SinkArgClassifierMIPS.__new__(SinkArgClassifierMIPS)
    clf._ctx = ctx
    clf._big_endian = True
    clf._data = b'\x00' * 0x10000
    clf._plt_rev = {v: k for k, v in (plt or {}).items()}
    clf._sinks = {'system': 0}
    clf._snprintf_plts = {}
    clf._gp = 0x1000
    clf._got = {}
    clf._got_va = 0xF00
    clf._rodata_ranges = [(0x5000, 0x8000)]
    clf._dead_sinks = []
    clf._bin = None
    clf._cs = None
    if _CS_OK:
        from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN
        clf._cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
        clf._cs.detail = True
    return clf


# ── unit tests — helpers ───────────────────────────────────────────────────────

def test_is_rodata_in_range():
    clf = _make_clf_from_mock()
    clf._rodata_ranges = [(0x5000, 0x8000)]
    assert clf._is_rodata(0x5000)
    assert clf._is_rodata(0x7FFF)
    assert not clf._is_rodata(0x8000)
    assert not clf._is_rodata(0x4FFF)


def test_resolve_got_returns_value():
    clf = _make_clf_from_mock()
    clf._gp = 0x1000
    clf._got = {0x1000 + (-16 & 0xFFFF) % 0x10000: 0x6000}
    clf._got[0x1000 - 16] = 0x6000
    result = clf._resolve_got(-16)
    assert result == 0x6000


def test_resolve_got_out_of_range():
    clf = _make_clf_from_mock()
    clf._gp = 0x1000
    clf._got = {}
    assert clf._resolve_got(-999) is None


def test_resolve_got_zero_gp():
    clf = _make_clf_from_mock()
    clf._gp = 0
    assert clf._resolve_got(0) is None


@pytest.mark.skipif(not _CS_OK, reason='capstone required')
def test_writes_reg_detects_destination():
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN
    clf = _make_clf_from_mock()
    cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
    cs.detail = True
    # ADDIU $a0, $zero, 5  (opcode: 24040005)
    insns = list(cs.disasm(bytes.fromhex('24040005'), 0))
    assert insns
    assert clf._writes_reg(insns[0], _R_A0)
    assert not clf._writes_reg(insns[0], _R_A1)


@pytest.mark.skipif(not _CS_OK, reason='capstone required')
def test_trace_arg_addiu_zero_is_rodata_const():
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN
    clf = _make_clf_from_mock()
    cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
    cs.detail = True
    # JALR $t9 (0320f809) preceded by ADDIU $a0, $zero, 0 (24040000)
    code = bytes.fromhex('24040000') + bytes.fromhex('0320f809')
    insns = list(cs.disasm(code, 0))
    # insns[0] = ADDIU $a0, $zero, 0; insns[1] = JALR $t9
    verdict, detail = clf._trace_arg(insns, 1, _R_A0, depth=0)
    assert verdict == RODATA_CONST
    assert 'constant' in detail.lower() or 'addiu' in detail.lower()


@pytest.mark.skipif(not _CS_OK, reason='capstone required')
def test_trace_arg_lw_from_gp_resolves_to_rodata():
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN
    clf = _make_clf_from_mock()
    clf._gp = 0x1000
    clf._got[0x1000 - 4] = 0x6000  # GOT entry at $gp-4 = 0x6000 (in .rodata 0x5000-0x8000)
    clf._rodata_ranges = [(0x5000, 0x8000)]
    cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
    cs.detail = True
    # LW $a0, -4($gp) = 8f84fffc; JALR $t9 = 0320f809
    code = bytes.fromhex('8f84fffc') + bytes.fromhex('0320f809')
    insns = list(cs.disasm(code, 0))
    verdict, detail = clf._trace_arg(insns, 1, _R_A0, depth=0)
    assert verdict == RODATA_CONST
    assert '0x6000' in detail


@pytest.mark.skipif(not _CS_OK, reason='capstone required')
def test_trace_arg_lw_then_addiu_resolves_to_rodata():
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN
    clf = _make_clf_from_mock()
    clf._gp = 0x1000
    clf._got[0x1000 - 8] = 0x5000  # GOT[-8] = 0x5000 (section base)
    clf._rodata_ranges = [(0x5000, 0x8000)]
    cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
    cs.detail = True
    # LW $v0, -8($gp) = 8f82fff8
    # ADDIU $a0, $v0, 0x40 = 24440040  (→ 0x5000+0x40=0x5040, in .rodata)
    # JALR $t9 = 0320f809
    # encoding: ADDIU rt=$a0(4), rs=$v0(2), imm=0x40 → 001001_00010_00100_0000000001000000
    code = bytes.fromhex('8f82fff8') + bytes.fromhex('24440040') + bytes.fromhex('0320f809')
    insns = list(cs.disasm(code, 0))
    # insns: LW $v0, ADDIU $a0, JALR
    verdict, detail = clf._trace_arg(insns, 2, _R_A0, depth=0)
    assert verdict == RODATA_CONST
    assert '0x5040' in detail


# ── unit tests — find_sink_plts ───────────────────────────────────────────────

def test_find_sink_plts_uses_plt_rev():
    clf = _make_clf_from_mock(plt={0xABCD: 'system'})
    clf._ctx.callers_of.return_value = [(0x1000, 'f')]
    plts = clf._find_sink_plts()
    assert 0xABCD in plts
    assert plts[0xABCD] == ('system', 0)


def test_find_sink_plts_falls_back_to_exports():
    clf = _make_clf_from_mock(exports={'cwSysCmdRun': 0x6991EC})
    clf._sinks['cwSysCmdRun'] = 0
    clf._ctx.callers_of.side_effect = lambda name: [(0x1000, 'f')] if name == 'cwSysCmdRun' else []
    plts = clf._find_sink_plts()
    assert 0x6991EC in plts


def test_find_sink_plts_marks_dead_sinks():
    clf = _make_clf_from_mock(plt={0xABCD: 'system'})
    clf._ctx.callers_of.return_value = []
    clf._find_sink_plts()
    assert 'system' in clf._dead_sinks


def test_find_sink_plts_skips_unknown_symbols():
    clf = _make_clf_from_mock()  # empty plt and exports
    plts = clf._find_sink_plts()
    assert plts == {}


# ── integration tests — cwWtpd ────────────────────────────────────────────────

@_SKIP_IF_NO_BIN
@_SKIP_IF_NO_DEPS
def test_integration_loads_successfully():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(CWWTPD_PATH)
    clf = SinkArgClassifierMIPS.from_context(ctx)
    assert clf._gp == 0x100101d0, 'gp mismatch'
    assert len(clf._got) > 100
    assert clf._rodata_ranges


@_SKIP_IF_NO_BIN
@_SKIP_IF_NO_DEPS
def test_integration_classify_system_finds_rodata():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(CWWTPD_PATH)
    clf = SinkArgClassifierMIPS.from_context(ctx)
    results = clf.classify_all()
    rodata = [r for r in results if r.verdict == RODATA_CONST and r.sink_name == 'system']
    assert len(rodata) >= 4, 'capwap_cwb_main_vf system() rodata calls expected'


@_SKIP_IF_NO_BIN
@_SKIP_IF_NO_DEPS
def test_integration_cwsyscmdrun_finds_fap_cwmips1_callsite():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(CWWTPD_PATH)
    clf = SinkArgClassifierMIPS.from_context(ctx)
    clf.add_sink('cwSysCmdRun', arg_pos=0)
    results = clf.classify_all()
    csr = [r for r in results if r.sink_name == 'cwSysCmdRun']
    assert len(csr) > 0, 'cwSysCmdRun call sites expected'
    # FAP-CWMIPS-1: cwWtpUpdateVspAdminPasswd (0x467788) → cwSysCmdRun at 0x4679bc
    # Format string is RODATA_CONST at 0x6ecb68
    fa1 = [r for r in csr if r.func_va == 0x467788 and r.call_va == 0x4679bc]
    assert fa1, 'FAP-CWMIPS-1 call site not found'
    assert fa1[0].verdict == RODATA_CONST
    assert '6ecb68' in fa1[0].detail


@_SKIP_IF_NO_BIN
@_SKIP_IF_NO_DEPS
def test_integration_popen_arg_propagated():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(CWWTPD_PATH)
    clf = SinkArgClassifierMIPS.from_context(ctx)
    results = clf.classify_all()
    # cwWtpPrintCmdOutput (0x473c60) calls popen with ARG_PROPAGATED
    prop = [r for r in results
            if r.sink_name == 'popen' and r.func_va == 0x473c60
            and r.verdict == ARG_PROPAGATED]
    assert prop, 'cwWtpPrintCmdOutput popen ARG_PROPAGATED not found'


@_SKIP_IF_NO_BIN
@_SKIP_IF_NO_DEPS
def test_integration_report_runs_without_error():
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(CWWTPD_PATH)
    clf = SinkArgClassifierMIPS.from_context(ctx)
    results = clf.classify_all()
    report = clf.report(results)
    assert 'sink_arg_classifier_mips' in report
    assert 'call site' in report
