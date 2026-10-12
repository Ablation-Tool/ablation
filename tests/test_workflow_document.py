"""Tests for WorkflowDocument and StageCommitment."""
import json
import pytest

from ablation.analyzers.workflow_document import (
    Stage,
    StageTransition,
    WorkflowDocument,
    _validate_instance,
)
from ablation.analyzers.stage_commitment import CommitmentRecord, StageCommitment


# ---------------------------------------------------------------------------
# _validate_instance
# ---------------------------------------------------------------------------

def test_validate_instance_all_valid():
    schema = {
        "required": ["a", "b"],
        "properties": {"a": {"type": "str"}, "b": {"type": "int"}},
    }
    assert _validate_instance(schema, {"a": "x", "b": 1}) == []


def test_validate_instance_missing_required():
    schema = {"required": ["a", "b"], "properties": {}}
    errors = _validate_instance(schema, {"a": "x"})
    assert any("missing" in e and "'b'" in e for e in errors)


def test_validate_instance_wrong_type():
    schema = {
        "required": ["n"],
        "properties": {"n": {"type": "int"}},
    }
    errors = _validate_instance(schema, {"n": "not-an-int"})
    assert any("'n'" in e for e in errors)


def test_validate_instance_float_accepts_int():
    schema = {"required": ["x"], "properties": {"x": {"type": "float"}}}
    assert _validate_instance(schema, {"x": 3}) == []
    assert _validate_instance(schema, {"x": 3.14}) == []


def test_validate_instance_optional_field_skipped():
    schema = {
        "required": ["a"],
        "properties": {"a": {"type": "str"}, "b": {"type": "int"}},
    }
    # 'b' is in properties but not in required — absence should be fine
    assert _validate_instance(schema, {"a": "ok"}) == []


# ---------------------------------------------------------------------------
# WorkflowDocument basic operations
# ---------------------------------------------------------------------------

def _make_simple_doc():
    stages = [
        Stage(
            name="alpha",
            schema={
                "required": ["x"],
                "properties": {"x": {"type": "str"}},
            },
            routing=["beta"],
        ),
        Stage(
            name="beta",
            schema={"required": ["y"], "properties": {"y": {"type": "int"}}},
            routing=[],
        ),
    ]
    return WorkflowDocument(stages, doc_id="test/doc")


def test_current_returns_first_stage():
    doc = _make_simple_doc()
    assert doc.current().name == "alpha"


def test_advance_valid_moves_to_next():
    doc = _make_simple_doc()
    routing = doc.advance({"x": "hello"}, producer_id="s1")
    assert routing == ["beta"]
    assert doc.current().name == "beta"


def test_advance_invalid_raises():
    doc = _make_simple_doc()
    with pytest.raises(ValueError, match="validation failed"):
        doc.advance({"x": 42})  # x must be str


def test_advance_terminal_returns_empty():
    doc = _make_simple_doc()
    doc.advance({"x": "ok"})
    routing = doc.advance({"y": 7})
    assert routing == []


def test_validate_without_advancing():
    doc = _make_simple_doc()
    assert doc.validate("alpha", {"x": "ok"}) == []
    assert doc.validate("alpha", {"x": 99}) != []


def test_validate_unknown_stage():
    doc = _make_simple_doc()
    errors = doc.validate("nonexistent", {})
    assert any("unknown stage" in e for e in errors)


def test_dirty_since_commit_clean():
    doc = _make_simple_doc()
    doc.advance({"x": "ok"})
    assert not doc.dirty_since_commit()


def test_dirty_since_commit_detects_mutation():
    doc = _make_simple_doc()
    doc.advance({"x": "ok"})
    # Mutate the committed stage's instance directly
    doc.stages[0].instance["x"] = "tampered"
    assert doc.dirty_since_commit()


def test_empty_stages_raises():
    with pytest.raises(ValueError):
        WorkflowDocument([])


def test_transition_log_populated():
    doc = _make_simple_doc()
    doc.advance({"x": "ok"}, producer_id="p1")
    assert len(doc.log) == 1
    t = doc.log[0]
    assert t.from_stage == "alpha"
    assert t.to_stage == "beta"
    assert t.producer_id == "p1"


# ---------------------------------------------------------------------------
# WorkflowDocument serialisation
# ---------------------------------------------------------------------------

def test_round_trip_json():
    doc = _make_simple_doc()
    doc.advance({"x": "hello"}, producer_id="s1")
    restored = WorkflowDocument.from_json(doc.to_json())
    assert restored.doc_id == doc.doc_id
    assert restored.current().name == "beta"
    assert len(restored.log) == 1
    assert not restored.dirty_since_commit()


def test_round_trip_preserves_committed_snapshot():
    doc = _make_simple_doc()
    doc.advance({"x": "hello"})
    # Mutate before round-trip; dirty should survive
    doc.stages[0].instance["x"] = "changed"
    s = doc.to_json()
    restored = WorkflowDocument.from_json(s)
    assert restored.dirty_since_commit()


# ---------------------------------------------------------------------------
# WorkflowDocument.for_re_session
# ---------------------------------------------------------------------------

def test_for_re_session_stage_count():
    doc = WorkflowDocument.for_re_session("cisco", "fmc")
    assert len(doc.stages) == 6
    assert doc.stages[0].name == "triage"
    assert doc.stages[5].name == "registration"


def test_for_re_session_triage_schema():
    doc = WorkflowDocument.for_re_session("cisco", "fmc")
    triage = {
        "binary_hash": "abc", "arch": "arm64", "bits": 64,
        "section_count": 8, "string_count": 1200, "plt_count": 340,
    }
    assert doc.validate("triage", triage) == []


def test_for_re_session_triage_missing_field():
    doc = WorkflowDocument.for_re_session("cisco", "fmc")
    errors = doc.validate("triage", {"binary_hash": "abc", "arch": "arm64"})
    assert errors  # missing bits, section_count, etc.


def test_for_re_session_empty_vendor_raises():
    with pytest.raises(ValueError):
        WorkflowDocument.for_re_session("", "fmc")


def test_for_re_session_doc_id():
    doc = WorkflowDocument.for_re_session("huawei", "ne8000")
    assert doc.doc_id == "huawei/ne8000"


def test_for_re_session_full_advance():
    doc = WorkflowDocument.for_re_session("cisco", "fmc")
    instances = [
        {
            "binary_hash": "deadbeef", "arch": "arm64", "bits": 64,
            "section_count": 9, "string_count": 1400, "plt_count": 320,
        },
        {"query": "buffer overflow", "candidates": [{"va": 0x1000, "score": 0.9}]},
        {
            "va": 0x1000, "name": "parse_input",
            "complexity": 12, "call_count": 3, "caller_count": 5,
        },
        {
            "source_va": 0x800, "sink_va": 0x1000,
            "path_length": 3, "taint_regs": ["x0", "x1"],
        },
        {
            "va": 0x1000, "cwe": "CWE-121", "severity": "HIGH",
            "title": "Stack Overflow", "description": "desc", "byte_proof": "ff ff",
        },
        {"finding_id": 42, "forge_gate_passed": True},
    ]
    for inst in instances:
        routing = doc.advance(inst)
    assert routing == []  # terminal
    assert all(s.committed for s in doc.stages)


# ---------------------------------------------------------------------------
# WorkflowDocument.report
# ---------------------------------------------------------------------------

def test_report_contains_stage_names():
    doc = _make_simple_doc()
    r = doc.report()
    assert "alpha" in r
    assert "beta" in r


def test_report_shows_current():
    doc = _make_simple_doc()
    assert "CURRENT" in doc.report()


# ---------------------------------------------------------------------------
# StageCommitment basic operations
# ---------------------------------------------------------------------------

def _make_sc():
    return StageCommitment(doc_id="test/doc")


def test_commit_returns_record():
    sc = _make_sc()
    instance = {"x": "hello"}
    rec = sc.commit("alpha", instance, producer="p1")
    assert rec.stage_name == "alpha"
    assert rec.producer == "p1"
    assert rec.lock_mode == "no-lock"
    assert rec.content_hash


def test_commit_invalid_lock_mode_raises():
    sc = _make_sc()
    with pytest.raises(ValueError):
        sc.commit("alpha", {}, producer="p1", lock_mode="frozen")


def test_commit_empty_producer_raises():
    sc = _make_sc()
    with pytest.raises(ValueError):
        sc.commit("alpha", {}, producer="")


def test_verify_ok():
    sc = _make_sc()
    instance = {"x": "hello"}
    sc.commit("alpha", instance, producer="p1")
    ok, reason = sc.verify("alpha", instance)
    assert ok
    assert reason == "ok"


def test_verify_tampered():
    sc = _make_sc()
    instance = {"x": "hello"}
    sc.commit("alpha", instance, producer="p1")
    mutated = {"x": "tampered"}
    ok, reason = sc.verify("alpha", mutated)
    assert not ok
    assert "mutated" in reason


def test_verify_no_commitment():
    sc = _make_sc()
    ok, reason = sc.verify("alpha", {})
    assert not ok
    assert "no commitment" in reason


def test_approve_no_revision():
    sc = _make_sc()
    instance = {"x": "hello"}
    sc.commit("alpha", instance, producer="p1")
    sc.approve("alpha", approver="p2")
    ok, reason = sc.verify("alpha", instance)
    assert ok
    assert reason == "ok"


def test_approve_with_revision():
    sc = _make_sc()
    original = {"x": "hello"}
    revised = {"x": "world"}
    sc.commit("alpha", original, producer="p1")
    sc.approve("alpha", approver="p2", revised_instance=revised)
    # Both original and approved revision are valid chain states.
    # Original returns "ok" (it was committed); revised returns "ok (approved revision)".
    ok_orig, reason_orig = sc.verify("alpha", original)
    ok_rev, reason_rev = sc.verify("alpha", revised)
    assert ok_orig
    assert reason_orig == "ok"
    assert ok_rev
    assert "approved revision" in reason_rev


def test_approve_tamper_after_approval():
    sc = _make_sc()
    original = {"x": "hello"}
    sc.commit("alpha", original, producer="p1")
    sc.approve("alpha", approver="p2")
    ok, reason = sc.verify("alpha", {"x": "evil"})
    assert not ok


def test_approve_unknown_stage_raises():
    sc = _make_sc()
    with pytest.raises(KeyError):
        sc.approve("nonexistent", approver="p2")


def test_approve_empty_approver_raises():
    sc = _make_sc()
    sc.commit("alpha", {"x": 1}, producer="p1")
    with pytest.raises(ValueError):
        sc.approve("alpha", approver="")


# ---------------------------------------------------------------------------
# StageCommitment serialisation
# ---------------------------------------------------------------------------

def test_stage_commitment_round_trip():
    sc = _make_sc()
    instance = {"x": "hello"}
    sc.commit("alpha", instance, producer="p1")
    sc.approve("alpha", approver="p2")
    restored = StageCommitment.from_json(sc.to_json())
    ok, reason = restored.verify("alpha", instance)
    assert ok


def test_stage_commitment_round_trip_with_revision():
    sc = _make_sc()
    original = {"x": "hello"}
    revised = {"x": "world"}
    sc.commit("alpha", original, producer="p1")
    sc.approve("alpha", approver="p2", revised_instance=revised)
    restored = StageCommitment.from_json(sc.to_json())
    ok, reason = restored.verify("alpha", revised)
    assert ok
    assert "approved revision" in reason


# ---------------------------------------------------------------------------
# StageCommitment.audit_trail
# ---------------------------------------------------------------------------

def test_audit_trail_empty():
    sc = _make_sc()
    trail = sc.audit_trail()
    assert "no commitments" in trail


def test_audit_trail_shows_stages():
    sc = _make_sc()
    sc.commit("alpha", {"x": 1}, producer="p1")
    sc.commit("beta", {"y": 2}, producer="p1")
    trail = sc.audit_trail()
    assert "alpha" in trail
    assert "beta" in trail
    assert "pending" in trail
