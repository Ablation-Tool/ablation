"""
Tests for ReloSinkArgClassifier.

Fixtures: tests/fixtures/ppc32_relo/rpc0http.o

Known facts about rpc0http.o::rpc_http_svc_get (confirmed byte-verification):
  - strcpy(arg0): destination = r30 (heap allocation, set from r3 after blrl)
    Expected: ARG_PROPAGATED (false-positive due to return-value ambiguity, documented LOW finding)
  - strcpy(arg1): source = "GET" string literal in .rodata
    Expected: RODATA_CONST
  - No exec-class sinks (system, popen, execve) in the object.
"""

from __future__ import annotations

import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent / 'fixtures' / 'ppc32_relo'
RPC_HTTP = FIXTURES / 'rpc0http.o'


def _skip_if_missing(path: Path):
    return pytest.mark.skipif(not path.exists(), reason=f'fixture missing: {path}')


@pytest.fixture(scope='session')
def roc():
    from ablation.analyzers.relo_object_context import ReloObjectContext
    return ReloObjectContext.from_path(str(RPC_HTTP))


@pytest.fixture(scope='session')
def clf(roc):
    from ablation.analyzers.relo_sink_arg_classifier import ReloSinkArgClassifier
    return ReloSinkArgClassifier.from_context(roc)


# ── call site detection ────────────────────────────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_classify_fn_returns_results_for_rpc_http(clf):
    results = clf.classify_fn('rpc_http_svc_get')
    assert len(results) >= 1


@_skip_if_missing(RPC_HTTP)
def test_classify_fn_finds_strcpy_call(clf):
    results = clf.classify_fn('rpc_http_svc_get')
    sink_names = {r.sink_name for r in results}
    assert 'strcpy' in sink_names, f'strcpy not in results: {sink_names}'


@_skip_if_missing(RPC_HTTP)
def test_classify_fn_strcpy_call_va_correct(clf):
    results = clf.classify_fn('rpc_http_svc_get')
    strcpy_calls = [r for r in results if r.sink_name == 'strcpy']
    assert len(strcpy_calls) >= 1
    # bctrl for strcpy is at section-relative offset 0x16c (confirmed byte-verification)
    call_vas = {r.call_va for r in strcpy_calls}
    assert 0x16c in call_vas, f'expected 0x16c in call VAs: {sorted(call_vas):#010x}'


# ── arg0 verdict (destination): ARG_PROPAGATED ────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_strcpy_arg0_is_arg_propagated(roc):
    from ablation.analyzers.relo_sink_arg_classifier import ReloSinkArgClassifier
    from ablation.analyzers.sink_arg_classifier import ARG_PROPAGATED
    clf = ReloSinkArgClassifier.from_context(roc)
    clf._sinks['strcpy'] = 0
    results = clf.classify_fn('rpc_http_svc_get')
    strcpy = [r for r in results if r.sink_name == 'strcpy']
    assert len(strcpy) == 1
    assert strcpy[0].verdict == ARG_PROPAGATED


# ── arg1 verdict (source): RODATA_CONST ─────────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_strcpy_arg1_is_rodata_const(roc):
    from ablation.analyzers.relo_sink_arg_classifier import ReloSinkArgClassifier
    from ablation.analyzers.sink_arg_classifier import RODATA_CONST
    clf = ReloSinkArgClassifier.from_context(roc)
    clf._sinks['strcpy'] = 1
    results = clf.classify_fn('rpc_http_svc_get')
    strcpy = [r for r in results if r.sink_name == 'strcpy']
    assert len(strcpy) == 1
    assert strcpy[0].verdict == RODATA_CONST


# ── classify_all ──────────────────────────────────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_classify_all_produces_results(clf):
    results = clf.classify_all()
    assert len(results) >= 1


@_skip_if_missing(RPC_HTTP)
def test_classify_all_includes_rpc_http_svc_get(clf):
    from ablation.analyzers.relo_object_context import ReloObjectContext
    ctx = ReloObjectContext.from_path(str(RPC_HTTP))
    fn = ctx._func_by_name['rpc_http_svc_get']
    results = clf.classify_all()
    func_offsets = {r.func_va for r in results}
    assert fn.offset in func_offsets


# ── report ────────────────────────────────────────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_report_contains_summary(clf):
    results = clf.classify_all()
    report = clf.report(results)
    assert 'Summary:' in report


@_skip_if_missing(RPC_HTTP)
def test_report_empty_results(clf):
    report = clf.report([])
    assert 'no results' in report.lower()


# ── add_sink ─────────────────────────────────────────────────────────────────

@_skip_if_missing(RPC_HTTP)
def test_add_sink_then_classify(roc):
    from ablation.analyzers.relo_sink_arg_classifier import ReloSinkArgClassifier
    clf = ReloSinkArgClassifier.from_context(roc)
    clf.add_sink('SsQmemAlloc', arg_pos=0)
    # Just ensure no crash; SsQmemAlloc is not in the default sink list
    # and has no matching rela, so 0 results is expected
    results = clf.classify_fn('rpc_http_svc_get')
    # strcpy should still be found
    strcpy_results = [r for r in results if r.sink_name == 'strcpy']
    assert len(strcpy_results) >= 1
