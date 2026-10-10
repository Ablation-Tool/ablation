"""Tests for RH850TaintTracker and GHS symbol normaliser."""
import pytest

from ablation.analyzers.taint_tracker_rh850 import (
    RH850TaintTracker,
    TaintFindingRH850,
    _ghs_c_name,
    _ghs_name_in,
    _ghs_strip_underscore,
    _dedup_rh850,
)
from ablation.analyzers.taint_tracker_v850 import TaintFindingV850


# ---------------------------------------------------------------------------
# GHS symbol normaliser
# ---------------------------------------------------------------------------

def test_ghs_strip_underscore_strips():
    assert _ghs_strip_underscore('_recv') == 'recv'

def test_ghs_strip_underscore_keeps_double():
    # __vtbl is a double-underscore prefix — not a Renesas assembler prefix
    assert _ghs_strip_underscore('__vtblFoo') == '__vtblFoo'

def test_ghs_c_name_plain():
    assert _ghs_c_name('memcpy') == 'memcpy'
    assert _ghs_c_name('recv')   == 'recv'

def test_ghs_c_name_renesas_prefix():
    assert _ghs_c_name('_memcpy') == 'memcpy'
    assert _ghs_c_name('_recv')   == 'recv'

def test_ghs_c_name_constructor():
    assert _ghs_c_name('Foo__ct')    == 'Foo'
    assert _ghs_c_name('Foo__ctFv')  == 'Foo'
    assert _ghs_c_name('Socket__ct') == 'Socket'

def test_ghs_c_name_destructor():
    assert _ghs_c_name('Bar__dt')    == 'Bar'
    assert _ghs_c_name('Bar__dtFv')  == 'Bar'

def test_ghs_c_name_vtable():
    assert _ghs_c_name('__vtblFoo')    == 'Foo'
    assert _ghs_c_name('__vtblSocket') == 'Socket'

def test_ghs_c_name_no_mangle():
    # A symbol with no GHS pattern passes through
    assert _ghs_c_name('malloc') == 'malloc'

def test_ghs_name_in_plain():
    assert _ghs_name_in('recv', frozenset({'recv'}))
    assert not _ghs_name_in('malloc', frozenset({'recv'}))

def test_ghs_name_in_underscore_prefix():
    assert _ghs_name_in('_recv', frozenset({'recv'}))

def test_ghs_name_in_none_safe():
    # empty string should not match anything
    assert not _ghs_name_in('', frozenset({'recv', 'memcpy'}))


# ---------------------------------------------------------------------------
# TaintFindingRH850
# ---------------------------------------------------------------------------

def _make_v850_finding(**kwargs):
    defaults = dict(func_va=0x100, func_name='fn', sink_va=0x200,
                    sink_name='memcpy', tainted_args=['r6'],
                    source_name='recv', severity='HIGH')
    defaults.update(kwargs)
    return TaintFindingV850(**defaults)


def test_finding_from_v850_defaults():
    f = TaintFindingRH850.from_v850(_make_v850_finding())
    assert f.double_is_32bit is True
    assert f.func_va == 0x100
    assert f.sink_name == 'memcpy'

def test_finding_from_v850_double_64():
    f = TaintFindingRH850.from_v850(_make_v850_finding(), double_is_32bit=False)
    assert f.double_is_32bit is False

def test_finding_str_double_32():
    f = TaintFindingRH850(0x100, 'fn', 0x200, 'memcpy', ['r6'], 'recv', 'HIGH', True)
    s = str(f)
    assert '[double=32b]' in s
    assert 'memcpy' in s
    assert 'HIGH' in s

def test_finding_str_double_64():
    f = TaintFindingRH850(0x100, 'fn', 0x200, 'memcpy', ['r6'], 'recv', 'HIGH', False)
    assert '[double=64b]' in str(f)

def test_finding_critical_severity():
    f = TaintFindingRH850(0x100, 'fn', 0x200, 'system', ['r6'], 'recv', 'CRITICAL', True)
    assert 'CRITICAL' in str(f)


# ---------------------------------------------------------------------------
# _dedup_rh850
# ---------------------------------------------------------------------------

def test_dedup_removes_duplicates():
    f1 = TaintFindingRH850(0x100, 'fn', 0x200, 'memcpy', ['r6'], 'recv')
    f2 = TaintFindingRH850(0x100, 'fn', 0x200, 'memcpy', ['r7'], 'recv')  # same key
    f3 = TaintFindingRH850(0x100, 'fn', 0x300, 'memcpy', ['r6'], 'recv')  # different sink_va
    out = _dedup_rh850([f1, f2, f3])
    assert len(out) == 2

def test_dedup_empty():
    assert _dedup_rh850([]) == []


# ---------------------------------------------------------------------------
# RH850TaintTracker constructors
# ---------------------------------------------------------------------------

def test_from_bytes_constructs():
    data = bytes(256)
    tracker = RH850TaintTracker.from_bytes(data, base_va=0x0)
    assert tracker is not None
    assert tracker._double_is_32bit is True

def test_from_bytes_double_64():
    data = bytes(256)
    tracker = RH850TaintTracker.from_bytes(data, base_va=0x0, double_is_32bit=False)
    assert tracker._double_is_32bit is False

def test_from_bytes_run_no_crash():
    """run() on all-zero bytes should return an empty list without crashing."""
    data = bytes(256)
    tracker = RH850TaintTracker.from_bytes(data, base_va=0x0)
    findings = tracker.run()
    assert isinstance(findings, list)

def test_scan_function_no_crash():
    """scan_function on all-zero bytes should return an empty list."""
    data = bytes(256)
    tracker = RH850TaintTracker.from_bytes(data, base_va=0x0)
    findings = tracker.scan_function(0x0, 0x100, init_labels={'test'})
    assert isinstance(findings, list)

def test_scan_function_registers_name():
    """scan_function with func_name should register it in _syms."""
    data = bytes(256)
    tracker = RH850TaintTracker.from_bytes(data, base_va=0x0)
    tracker.scan_function(0x10, 0x40, func_name='my_func')
    assert tracker._syms.get(0x10) == 'my_func'

def test_report_no_findings():
    data = bytes(256)
    tracker = RH850TaintTracker.from_bytes(data)
    assert 'no findings' in tracker.report([])

def test_report_header_double_32b():
    data = bytes(256)
    tracker = RH850TaintTracker.from_bytes(data, double_is_32bit=True)
    f = TaintFindingRH850(0x10, 'fn', 0x20, 'strcpy', ['r6'], 'recv')
    s = tracker.report([f])
    assert 'double=32b' in s

def test_report_header_double_64b():
    data = bytes(256)
    tracker = RH850TaintTracker.from_bytes(data, double_is_32bit=False)
    f = TaintFindingRH850(0x10, 'fn', 0x20, 'strcpy', ['r6'], 'recv', double_is_32bit=False)
    s = tracker.report([f])
    assert 'double=64b' in s
