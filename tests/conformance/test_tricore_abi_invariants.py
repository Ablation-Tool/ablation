"""ABI conformance tests for TriCoreTaintTracker.

These tests verify that the tracker's register model matches the
TriCore AURIX EABI specification as documented in:
  docs/known-anomalies/tricore-taint-tracker.md
  docs/module-reference/tricore-taint-tracker.md
  ABLATION-STANDARDS.md §2.3 (ISO-TCL3-ACT-001)

ABI reference: Infineon TriCore AURIX TC1.6.x / TC1.8 C Compiler ABI,
  Infineon Application Note AP32141 "TriCore Architecture Overview".
  Int arg registers:   D[4]-D[7]  (d4, d5, d6, d7)
  Ptr arg registers:   A[4]-A[7]  (a4, a5, a6, a7)
  Int return register: D[2]       (d2)
  Ptr return register: A[2]       (a2)
  Caller-saved:        d0-d7, a2-a7, a11, d15, a15
  Callee-saved:        d8-d15, sp/a10, a12-a15, a0, a1
  Stack pointer:       sp (alias for a10)
"""
import pytest

from ablation.analyzers.taint_tracker_tricore import (
    CLEAN, Taint,
    _TC_INT_ARG, _TC_PTR_ARG, _TC_ARG_REGS, _TC_RET_REGS,
    _TC_CALLER_SAVED, _TC_SP,
    _State,
)

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

pytestmark = pytest.mark.skipif(not HAS_CAPSTONE, reason="capstone not installed")


# ---------------------------------------------------------------------------
# ABI constant correctness
# ---------------------------------------------------------------------------

def test_int_arg_regs_are_d4_through_d7():
    assert set(_TC_INT_ARG) == {"d4", "d5", "d6", "d7"}


def test_ptr_arg_regs_are_a4_through_a7():
    assert set(_TC_PTR_ARG) == {"a4", "a5", "a6", "a7"}


def test_arg_regs_union():
    assert set(_TC_ARG_REGS) == set(_TC_INT_ARG) | set(_TC_PTR_ARG)


def test_arg_regs_count():
    assert len(_TC_ARG_REGS) == 8


def test_ret_regs_are_d2_and_a2():
    assert set(_TC_RET_REGS) == {"d2", "a2"}


def test_sp_name():
    """Capstone reports the stack pointer as 'sp' (alias for A10 in TC ABI)."""
    assert _TC_SP == "sp"


# ---------------------------------------------------------------------------
# CALLER_SAVED invariants
# ---------------------------------------------------------------------------

def test_arg_regs_are_caller_saved():
    """All 8 arg regs must be in CALLER_SAVED; callee may clobber them."""
    for r in _TC_ARG_REGS:
        assert r in _TC_CALLER_SAVED, f"{r} must be in _TC_CALLER_SAVED"


def test_ret_regs_are_caller_saved():
    """D2 and A2 are return regs; the callee writes them, so they are caller-saved."""
    for r in _TC_RET_REGS:
        assert r in _TC_CALLER_SAVED, f"{r} must be in _TC_CALLER_SAVED"


def test_a11_is_caller_saved():
    """A11 is the link register in TC ABI; clobbered by CALL, so caller-saved."""
    assert "a11" in _TC_CALLER_SAVED


def test_callee_saved_regs_not_in_caller_saved():
    """D8-D14 and A10, A12-A14 are callee-saved.

    D15 and A15 are excluded: they serve as implicit 16-bit operand registers in the
    16-bit encoding subset and are conservatively treated as caller-saved by the tracker.
    """
    callee_saved = {f"d{n}" for n in range(8, 15)} | {f"a{n}" for n in range(12, 15)} | {"a10"}
    for r in callee_saved:
        assert r not in _TC_CALLER_SAVED, f"callee-saved reg {r} must NOT be in _TC_CALLER_SAVED"


def test_sp_not_in_caller_saved():
    """Stack pointer must never be caller-saved; the tracker protects it."""
    assert _TC_SP not in _TC_CALLER_SAVED


# ---------------------------------------------------------------------------
# _State: SP protection invariant
# ---------------------------------------------------------------------------

def test_state_sp_never_tainted():
    """The SP register must be protected from taint in _State."""
    s = _State()
    s.set(_TC_SP, Taint(frozenset({"attacker"}), None))
    assert not s.get(_TC_SP).tainted


# ---------------------------------------------------------------------------
# _State: apply_call_effects ABI invariants
# ---------------------------------------------------------------------------

def test_call_effects_clears_all_caller_saved_regs():
    """apply_call_effects must clear every register in _TC_CALLER_SAVED."""
    s = _State()
    for r in _TC_CALLER_SAVED:
        s.set(r, Taint(frozenset({"src"}), None))
    s.apply_call_effects()
    for r in _TC_CALLER_SAVED - {_TC_SP}:
        assert not s.get(r).tainted or r in _TC_RET_REGS, (
            f"{r} should be cleared by call effects unless it received ret-propagated taint"
        )


def test_call_effects_preserves_callee_saved_regs():
    """Callee-saved registers must survive apply_call_effects unchanged.

    D15/A15 are excluded here — they are implicit 16-bit operands and treated as
    caller-saved by the tracker (see _TC_CALLER_SAVED comment).
    """
    callee_saved = {f"d{n}" for n in range(8, 15)} | {f"a{n}" for n in range(12, 15)}
    s = _State()
    for r in callee_saved:
        s.set(r, Taint(frozenset({"data"}), None))
    s.apply_call_effects()
    for r in callee_saved:
        assert s.get(r).tainted, f"callee-saved {r} must survive apply_call_effects"


def test_call_effects_propagates_arg_taint_to_int_ret():
    """Taint in an int arg reg must propagate to D2 after apply_call_effects."""
    s = _State()
    s.set("d4", Taint(frozenset({"net"}), None))
    s.apply_call_effects()
    assert s.get("d2").tainted
    assert "net" in s.get("d2").labels


def test_call_effects_propagates_ptr_arg_taint_to_ptr_ret():
    """Taint in a ptr arg reg must propagate to A2 after apply_call_effects."""
    s = _State()
    s.set("a4", Taint(frozenset({"net"}), None))
    s.apply_call_effects()
    assert s.get("a2").tainted
    assert "net" in s.get("a2").labels


def test_call_effects_no_taint_clears_ret_regs():
    """With no tainted arg regs, D2 and A2 must be clean after apply_call_effects."""
    s = _State()
    s.set("d4", CLEAN)
    s.set("a4", CLEAN)
    s.apply_call_effects()
    assert not s.get("d2").tainted
    assert not s.get("a2").tainted


# ---------------------------------------------------------------------------
# _State: join ABI invariant
# ---------------------------------------------------------------------------

def test_join_accumulates_taint_from_both_paths():
    """join() must not drop taint from either branch — conservative merge."""
    a = _State()
    b = _State()
    a.set("d4", Taint(frozenset({"path_a"}), None))
    b.set("d5", Taint(frozenset({"path_b"}), None))
    c = a.join(b)
    assert c.get("d4").tainted
    assert c.get("d5").tainted


def test_join_clean_register_in_one_branch_stays_tainted():
    """If d4 is tainted in A but clean in B, the join must keep it tainted."""
    a = _State()
    b = _State()
    a.set("d4", Taint(frozenset({"x"}), None))
    # b leaves d4 clean
    c = a.join(b)
    assert c.get("d4").tainted


# ---------------------------------------------------------------------------
# TaintFindingTriCore: tainted_args must reference valid arg registers
# ---------------------------------------------------------------------------

def test_finding_tainted_args_subset_of_arg_regs():
    """tainted_args in a finding must only name valid arg registers."""
    from ablation.analyzers.taint_tracker_tricore import TaintFindingTriCore
    valid = set(_TC_ARG_REGS)
    f = TaintFindingTriCore(
        func_va=0x100, func_name="fn", sink_va=0x200, sink_name="memcpy",
        tainted_args=list(_TC_ARG_REGS), labels=frozenset({"net"}), severity="HIGH",
    )
    for r in f.tainted_args:
        assert r in valid, f"tainted_args entry {r!r} not a valid TC arg register"
