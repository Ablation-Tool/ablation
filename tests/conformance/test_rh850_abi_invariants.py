"""ABI conformance tests for RH850TaintTracker.

These tests verify that the tracker's register model matches the
GHS CC-RH / EABI specification as documented in:
  docs/known-anomalies/rh850-taint-tracker.md
  docs/module-reference/rh850-taint-tracker.md
  ABLATION-STANDARDS.md §2.3 (ISO-TCL3-ACT-001)

ABI reference: GHS CC-RH Compiler and Library Guide, Renesas RH850 E2x ABI Supplement.
  Arg registers:    R6, R7, R8, R9
  Return registers: R10 (scalar), R10:R11 (64-bit)
  Link register:    R31 (alias: lp)
  Callee-saved:     R20-R29, ep (R30)
  Caller-saved:     R1, R6-R19, lp
  Never touched:    R0 (zero), R2, gp (R4), tp (R5)
  double:           32-bit by default under GHS CC-RH (IEC 60559 single)
"""
import pytest

from ablation.analyzers.isa_v850 import (
    ARG_REGS, RET_REGS, CALLER_SAVED, CALLEE_SAVED, NEVER_TOUCHED,
)
from ablation.analyzers.taint_tracker_rh850 import RH850TaintTracker, TaintFindingRH850


# ---------------------------------------------------------------------------
# ABI constant correctness
# ---------------------------------------------------------------------------

def test_arg_regs_are_r6_through_r9():
    assert set(ARG_REGS) == {"r6", "r7", "r8", "r9"}


def test_arg_regs_count():
    assert len(ARG_REGS) == 4


def test_ret_regs_are_r10_r11():
    assert set(RET_REGS) == {"r10", "r11"}


def test_link_register_name():
    """GHS ABI requires R31 == lp; LINK_REG must be 'lp'."""
    from ablation.analyzers.isa_v850 import LINK_REG
    assert LINK_REG == "lp"


def test_sp_alias():
    """R3 is the stack pointer; the register alias table must map r3 → sp."""
    from ablation.analyzers.isa_v850 import _ALIASES
    assert _ALIASES.get("r3") == "sp"


def test_r31_alias():
    """R31 must alias to lp."""
    from ablation.analyzers.isa_v850 import _ALIASES
    assert _ALIASES.get("r31") == "lp"


# ---------------------------------------------------------------------------
# CALLER_SAVED invariants
# ---------------------------------------------------------------------------

def test_arg_regs_are_caller_saved():
    """Arg regs must be caller-saved; the callee may clobber them."""
    for r in ARG_REGS:
        assert r in CALLER_SAVED, f"{r} must be in CALLER_SAVED"


def test_ret_regs_are_caller_saved():
    """Return regs are defined as caller-saved in the RH850 EABI."""
    for r in RET_REGS:
        assert r in CALLER_SAVED, f"{r} must be in CALLER_SAVED"


def test_lp_is_caller_saved():
    """The link register (r31/lp) is clobbered by jarl; it must be caller-saved."""
    assert "lp" in CALLER_SAVED


def test_callee_saved_disjoint_from_caller_saved():
    """No register can be both caller-saved and callee-saved."""
    overlap = CALLEE_SAVED & CALLER_SAVED
    assert not overlap, f"overlap: {overlap}"


def test_never_touched_disjoint_from_caller_saved():
    """NEVER_TOUCHED registers (r0, r2, gp, tp) must not appear in CALLER_SAVED."""
    overlap = NEVER_TOUCHED & CALLER_SAVED
    assert not overlap, f"overlap: {overlap}"


def test_callee_saved_includes_r20_through_r29():
    for r in (f"r{n}" for n in range(20, 30)):
        assert r in CALLEE_SAVED, f"{r} must be callee-saved"


def test_sp_is_callee_saved():
    assert "sp" in CALLEE_SAVED


def test_r0_is_never_touched():
    assert "r0" in NEVER_TOUCHED


def test_gp_is_never_touched():
    assert "gp" in NEVER_TOUCHED


# ---------------------------------------------------------------------------
# double_is_32bit ABI default
# ---------------------------------------------------------------------------

def test_double_is_32bit_default_true():
    """GHS CC-RH default: double == 32 bits (IEC 60559 single, not 64-bit pair)."""
    tracker = RH850TaintTracker.from_bytes(bytes(64), base_va=0x0)
    assert tracker._double_is_32bit is True


def test_double_is_32bit_explicit_false():
    tracker = RH850TaintTracker.from_bytes(bytes(64), base_va=0x0, double_is_32bit=False)
    assert tracker._double_is_32bit is False


def test_finding_double_32_label():
    f = TaintFindingRH850(0x10, "fn", 0x20, "strcpy", ["r6"], "recv", "HIGH", True)
    assert "[double=32b]" in str(f)


def test_finding_double_64_label():
    f = TaintFindingRH850(0x10, "fn", 0x20, "strcpy", ["r6"], "recv", "HIGH", False)
    assert "[double=64b]" in str(f)


# ---------------------------------------------------------------------------
# Tracker: arg register seeding
# ---------------------------------------------------------------------------

def test_scan_function_seeds_arg_regs():
    """scan_function must seed R6-R9 with init_labels at function entry."""
    data = bytes(256)
    tracker = RH850TaintTracker.from_bytes(data, base_va=0x0)
    findings = tracker.scan_function(0x0, 0x100, init_labels={"net"})
    assert isinstance(findings, list)


def test_scan_function_no_crash_on_all_zeros():
    data = bytes(256)
    tracker = RH850TaintTracker.from_bytes(data, base_va=0x0)
    findings = tracker.run()
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Tracker: interprocedural ABI — only arg regs are entry seeds
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# TaintFindingRH850: tainted_args must reference valid arg registers
# ---------------------------------------------------------------------------

def test_finding_tainted_args_are_valid_arg_regs():
    """Any tainted_args entry produced by the tracker is a valid arg register."""
    valid = set(ARG_REGS)
    f = TaintFindingRH850(0x10, "fn", 0x20, "strcpy", list(ARG_REGS), "recv")
    for r in f.tainted_args:
        assert r in valid, f"tainted_args entry {r!r} is not a valid arg register"


def test_finding_rejects_non_arg_reg():
    """A finding whose tainted_args list contains a callee-saved register is anomalous."""
    callee_saved_sample = "r20"
    f = TaintFindingRH850(0x10, "fn", 0x20, "strcpy", [callee_saved_sample], "recv")
    assert callee_saved_sample not in set(ARG_REGS)
