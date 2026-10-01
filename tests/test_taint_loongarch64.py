"""Tests for the LoongArch64 labeled-taint tracker."""
import pytest

from ablation.analyzers.taint_tracker_loongarch64 import (
    CLEAN, Taint, TaintEngine, _handle_syscall_frame, _ESCALATION_NAMES,
)
from ablation.analyzers.insn_loongarch64 import Insn, Reg, Imm, from_loongarch_frame
from ablation.analyzers.isa_loongarch64 import CALLER_SAVED


def insn(mnemonic, op_str, va=0x400000):
    return from_loongarch_frame(va, mnemonic, op_str, 4, 0)


def run(insns_list, taints=(("$a0", "in"),)):
    eng = TaintEngine()
    for r, lbl in taints:
        eng.taint_register(r, lbl)
    eng.run(insns_list)
    return eng


def T(eng, r):
    return eng.state.get(r)


# ---------------------------------------------------------------------------
# 3-register ALU propagation
# ---------------------------------------------------------------------------

def test_add_d_propagates_taint():
    e = run([insn("add.d", "$a1, $a0, $a1")])
    assert T(e, "$a1").tainted


def test_add_d_both_sources_union():
    e = run([insn("add.d", "$a2, $a0, $a1")],
            taints=(("$a0", "src_a"), ("$a1", "src_b")))
    assert T(e, "$a2").labels == {"src_a", "src_b"}


def test_or_with_zero_is_move():
    e = run([insn("or", "$a1, $a0, $zero")])
    assert T(e, "$a1").tainted
    assert not T(e, "$a0").labels - {"in"}


def test_or_clean_with_zero_stays_clean():
    e = run([insn("or", "$a1, $a2, $zero")], taints=())
    assert not T(e, "$a1").tainted


# ---------------------------------------------------------------------------
# Register-immediate ALU propagation
# ---------------------------------------------------------------------------

def test_addi_d_propagates_taint():
    e = run([insn("addi.d", "$a1, $a0, 8")])
    assert T(e, "$a1").tainted


def test_addi_d_clean_stays_clean():
    e = run([insn("addi.d", "$a1, $a2, 8")], taints=())
    assert not T(e, "$a1").tainted


# ---------------------------------------------------------------------------
# andi bound propagation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("imm,expected_bound", [
    ("0xff",   0xFF),
    ("0x7f",   0x7F),
    ("0xfff",  0xFFF),
    ("0",      None),
    ("0x100",  None),
])
def test_andi_bound(imm, expected_bound):
    e = run([insn("andi", f"$a1, $a0, {imm}")])
    assert T(e, "$a1").tainted
    assert T(e, "$a1").bound == expected_bound


def test_andi_does_not_bound_source():
    e = run([insn("andi", "$a1, $a0, 0xff")])
    assert T(e, "$a0").bound is None


def test_andi_bound_preserved_after_and():
    # join() takes max(bound) conservatively; both operands are tainted
    e = run([
        insn("andi", "$a1, $a0, 0xff"),
        insn("andi", "$a2, $a0, 0x0f"),
        insn("and",  "$a1, $a1, $a2"),
    ])
    assert T(e, "$a1").tainted
    assert T(e, "$a1").bound is not None


# ---------------------------------------------------------------------------
# $sp rebase and memory slot tracking
# ---------------------------------------------------------------------------

def test_sp_rebase_store_load_same_slot():
    e = run([
        insn("addi.d", "$sp, $sp, -16"),
        insn("st.d",   "$a0, $sp, 8"),
        insn("ld.d",   "$a1, $sp, 8"),
    ])
    assert T(e, "$a1").tainted


def test_sp_double_rebase_slot_survives():
    # After addi.d $sp,$sp,-16: store at $sp+8 (abs slot A)
    # After addi.d $sp,$sp,-8:  abs slot A is now $sp+16
    e = run([
        insn("addi.d", "$sp, $sp, -16"),
        insn("st.d",   "$a0, $sp, 8"),
        insn("addi.d", "$sp, $sp, -8"),
        insn("ld.d",   "$a1, $sp, 16"),
    ])
    assert T(e, "$a1").tainted


def test_sp_different_slot_is_clean():
    e = run([
        insn("addi.d", "$sp, $sp, -16"),
        insn("st.d",   "$a0, $sp, 8"),
        insn("ld.d",   "$a1, $sp, 0"),
    ])
    assert not T(e, "$a1").tainted


# ---------------------------------------------------------------------------
# IMM mnemonics produce CLEAN (address constants)
# ---------------------------------------------------------------------------

def test_lu12i_w_produces_clean():
    e = run([insn("lu12i.w", "$t0, 0")])
    assert not T(e, "$t0").tainted


def test_pcaddi_produces_clean():
    e = run([insn("pcaddi", "$t0, 0")])
    assert not T(e, "$t0").tainted


# ---------------------------------------------------------------------------
# CSR / IOCSR / float-to-GP register reads always produce CLEAN
# ---------------------------------------------------------------------------

def test_csrrd_clears_taint():
    e = run([insn("csrrd", "$a0, 0")])
    assert not T(e, "$a0").tainted


def test_movfr2gr_d_clears_taint():
    e = run([insn("movfr2gr.d", "$a0, $f0")])
    assert not T(e, "$a0").tainted


def test_rdtime_d_clean():
    e = run([insn("rdtime.d", "$a0, $t0")])
    assert not T(e, "$a0").tainted


# ---------------------------------------------------------------------------
# Callee-saved registers not clobbered by caller-saved wipe
# ---------------------------------------------------------------------------

def test_s0_not_in_caller_saved():
    assert "$s0" not in CALLER_SAVED


def test_callee_saved_survives_caller_clobber():
    eng = TaintEngine()
    eng.taint_register("$s0", "in")
    for r in CALLER_SAVED:
        eng.state.set(r, CLEAN)
    assert eng.state.get("$s0").tainted


# ---------------------------------------------------------------------------
# Syscall source: recvfrom(207) taints $a0
# ---------------------------------------------------------------------------

def test_syscall_recvfrom_taints_a0():
    eng = TaintEngine()
    eng.state.set_const("$a7", 207)
    findings = []
    _handle_syscall_frame(eng, findings, 0x401000, "test_func", 0x401050)
    assert eng.state.get("$a0").tainted
    assert "syscall:network" in eng.state.get("$a0").labels
    assert findings == []


def test_syscall_read_taints_a0():
    eng = TaintEngine()
    eng.state.set_const("$a7", 63)
    findings = []
    _handle_syscall_frame(eng, findings, 0x401000, "test_func", 0x401050)
    assert eng.state.get("$a0").tainted
    assert findings == []


# ---------------------------------------------------------------------------
# Syscall sink: execve(221) emits CRITICAL finding
# ---------------------------------------------------------------------------

def test_syscall_execve_emits_finding():
    eng = TaintEngine()
    eng.taint_register("$a0", "syscall:network")
    eng.taint_register("$a1", "syscall:network")
    eng.state.set_const("$a7", 221)
    findings = []
    _handle_syscall_frame(eng, findings, 0x401000, "test_func", 0x401054)
    assert len(findings) == 1
    assert findings[0].sink_name == "syscall:execve"
    assert findings[0].severity == "CRITICAL"
    assert "$a0" in findings[0].tainted_args


def test_syscall_sink_no_taint_no_finding():
    eng = TaintEngine()
    eng.state.set_const("$a7", 221)
    findings = []
    _handle_syscall_frame(eng, findings, 0x401000, "test_func", 0x401054)
    assert findings == []


# ---------------------------------------------------------------------------
# Syscall escalation: setuid(146) emits CRITICAL finding
# ---------------------------------------------------------------------------

def test_syscall_setuid_escalation():
    eng = TaintEngine()
    eng.taint_register("$a0", "user_input")
    eng.state.set_const("$a7", 146)
    findings = []
    _handle_syscall_frame(eng, findings, 0x401000, "test_func", 0x401060)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "setuid" in findings[0].sink_name


# ---------------------------------------------------------------------------
# Unknown $a7: no crash, caller-saved clobbered
# ---------------------------------------------------------------------------

def test_syscall_unknown_a7_clobbers_caller_saved():
    eng = TaintEngine()
    eng.taint_register("$a0", "in")
    assert "$a7" not in eng.state.consts
    findings = []
    _handle_syscall_frame(eng, findings, 0x401000, "test_func", 0x401070)
    assert not eng.state.get("$a0").tainted
    assert findings == []


def test_syscall_unknown_syscall_number_no_crash():
    eng = TaintEngine()
    eng.state.set_const("$a7", 9999)
    findings = []
    _handle_syscall_frame(eng, findings, 0x401000, "test_func", 0x401080)
    assert not eng.state.get("$a0").tainted


# ---------------------------------------------------------------------------
# _ESCALATION_NAMES content sanity
# ---------------------------------------------------------------------------

def test_escalation_names_has_commit_creds():
    assert "commit_creds" in _ESCALATION_NAMES


def test_escalation_names_has_prepare_kernel_cred():
    assert "prepare_kernel_cred" in _ESCALATION_NAMES


# ---------------------------------------------------------------------------
# Multiple labels merge
# ---------------------------------------------------------------------------

def test_add_d_unions_two_labels():
    e = run(
        [insn("add.d", "$a2, $a0, $a1")],
        taints=(("$a0", "src_a"), ("$a1", "src_b")),
    )
    assert T(e, "$a2").labels == {"src_a", "src_b"}


def test_store_load_preserves_label():
    e = run([
        insn("addi.d", "$sp, $sp, -16"),
        insn("st.d",   "$a0, $sp, 0"),
        insn("ld.d",   "$a1, $sp, 0"),
    ], taints=(("$a0", "netdata"),))
    assert "netdata" in T(e, "$a1").labels
