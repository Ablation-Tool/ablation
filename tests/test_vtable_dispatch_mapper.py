"""
Tests for VtableDispatchMapper.

Uses PanGPS 6.3.3 build 674 (the same binary used to discover the module gap).
Verified facts about PanGPS vtables:
  - CheckHip@0x156210 is in at least one vtable (confirmed via manual rela.dyn scan)
  - VtableDispatchMapper must find >= 1 vtable containing 0x156210
  - Total vtable count for a 5MB C++ binary should be substantial (> 10)
  - All slot function VAs must point into the TEXT section

If the fixture is absent the tests are skipped automatically.
"""

from __future__ import annotations

import pytest
from pathlib import Path

PANGPS = Path('/tmp/pangp_re/6.3.3-c42/opt/paloaltonetworks/globalprotect/PanGPS')
_SKIP = pytest.mark.skipif(not PANGPS.exists(), reason='PanGPS fixture not present')

CHECKHIP_VA = 0x156210


@pytest.fixture(scope='session')
def mapper():
    from ablation.analyzers.vtable_dispatch_mapper import VtableDispatchMapper
    return VtableDispatchMapper.from_path(str(PANGPS))


@_SKIP
def test_mapper_finds_vtables(mapper):
    assert len(mapper.all_vtables()) > 10, "expected substantial vtable count for C++ binary"


@_SKIP
def test_checkhip_in_vtable(mapper):
    slots = mapper.callers_via_vtable(CHECKHIP_VA)
    assert len(slots) >= 1, f"CheckHip@{CHECKHIP_VA:#x} not found in any vtable"


@_SKIP
def test_checkhip_slot_index_positive(mapper):
    slots = mapper.callers_via_vtable(CHECKHIP_VA)
    for s in slots:
        assert s.slot_index >= 0
        assert s.vtable_va > 0
        assert s.func_va == CHECKHIP_VA


@_SKIP
def test_vtable_slots_point_into_text(mapper):
    from ablation.analyzers.vtable_dispatch_mapper import VtableDispatchMapper
    for vt in mapper.all_vtables():
        for fn_va in vt.slots:
            assert mapper._text_start <= fn_va < mapper._text_end, (
                f"vtable slot {fn_va:#x} outside TEXT "
                f"[{mapper._text_start:#x}, {mapper._text_end:#x})"
            )


@_SKIP
def test_vtable_at_returns_correct_vtable(mapper):
    slots = mapper.callers_via_vtable(CHECKHIP_VA)
    vt_va = slots[0].vtable_va
    vt = mapper.vtable_at(vt_va)
    assert vt is not None
    assert vt.va == vt_va
    assert CHECKHIP_VA in vt.slots


@_SKIP
def test_vtable_containing_returns_slot(mapper):
    result = mapper.vtable_containing(CHECKHIP_VA)
    assert result is not None
    vt, slot = result
    assert vt.slots[slot] == CHECKHIP_VA


@_SKIP
def test_report_is_non_empty_string(mapper):
    r = mapper.report()
    assert isinstance(r, str)
    assert 'vtable' in r.lower()
    assert len(r) > 50


@_SKIP
def test_function_with_callers_not_in_vtable_still_findable(mapper):
    # A function that IS in a vtable should be findable; one that is not
    # should return an empty list — not raise.
    slots = mapper.callers_via_vtable(0x0)  # VA 0 is never a real function
    assert slots == []


@_SKIP
def test_min_vtable_size_respected(mapper):
    from ablation.analyzers.vtable_dispatch_mapper import MIN_VTABLE_SLOTS
    for vt in mapper.all_vtables():
        assert vt.size >= MIN_VTABLE_SLOTS
