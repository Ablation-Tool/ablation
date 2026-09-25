"""Tests for the RISC-V labeled-taint tracker, CFG builder, and fixpoint analysis."""
import pytest

from ablation.analyzers.taint_tracker_riscv import CLEAN, Finding, Policy, Taint, TaintEngine, TaintState, Width
from ablation.analyzers.insn_riscv import from_listing
from ablation.analyzers.isa_riscv import isa_for
from ablation.analyzers.cfg_riscv import build_cfg
from ablation.analyzers.analysis_riscv import analyze_cfg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(listing, width=Width.RV64, taints=(("a0", "user"),), policy=None, mem=()):
    eng = TaintEngine(width, policy)
    for r, l in taints:
        eng.taint_register(r, l)
    for b, off, l in mem:
        eng.taint_memory(b, off, l)
    eng.run(list(from_listing(listing)))
    return eng


def kinds(eng_or_result):
    return [f.kind for f in eng_or_result.findings]


def cfg_run(listing, width=Width.RV64, taints=(("a0", "user"),), policy=None):
    init = TaintState(width)
    for r, l in taints:
        init.taint_reg(r, l)
    return analyze_cfg(list(from_listing(listing)), width, initial=init, policy=policy)


# ---------------------------------------------------------------------------
# Copies
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("copy", [
    "mv t0, a0", "c.mv t0, a0", "addi t0, a0, 0", "add t0, a0, zero", "add t0, zero, a0",
    "or t0, a0, zero", "xor t0, zero, a0", "sub t0, a0, zero", "ori t0, a0, 0", "xori t0, a0, 0",
    "andi t0, a0, -1", "andi t0, a0, 0xfff", "slli t0, a0, 0", "sll t0, a0, zero",
])
def test_copy_forms_forward_taint(copy):
    e = run(copy)
    assert e.state.get("t0").labels == {"user"}


def test_copy_preserves_bound():
    e = run("andi a0, a0, 0xff\n mv t0, a0")
    assert e.state.get("t0").bound == 0xFF


def test_narrowing_copy_drops_bound():
    e = run("andi a0, a0, 0xff\n sext.w t0, a0", width=Width.RV64)
    assert e.state.get("t0").tainted and e.state.get("t0").bound is None


def test_mv_from_zero_is_constant():
    e = run("mv a0, zero")
    assert not e.state.get("a0").tainted and e.state.consts["a0"] == 0


def test_commutative_add_reads_op2():
    e = run("add t0, zero, a0")
    assert e.state.get("t0").labels == {"user"}
    e2 = run("add t0, zero, a1")
    assert not e2.state.get("t0").tainted


# ---------------------------------------------------------------------------
# andi bounds
# ---------------------------------------------------------------------------

def test_andi_negative_mask_does_not_bound():
    e = run("andi a0, a0, -16\n add t0, t1, a0\n lb t2, 0(t0)")
    assert e.state.get("a0").bound is None
    assert "tainted-load-address" in kinds(e)


def test_andi_positive_mask_bounds_and_suppresses_report():
    e = run("andi a0, a0, 0xff\n add t0, t1, a0\n lb t2, 0(t0)")
    assert "tainted-load-address" not in kinds(e)
    assert e.state.get("t0").bound == 0xFF


def test_andi_bounds_only_rd():
    e = run("andi t0, a0, 0xff")
    assert e.state.get("t0").bound == 0xFF
    assert e.state.get("a0").bound is None


def test_zext_b_h_w_bounds():
    e = run("zext.b t0, a0\n zext.h t1, a0\n zext.w t2, a0")
    assert e.state.get("t0").bound == 0xFF
    assert e.state.get("t1").bound == 0xFFFF
    assert e.state.get("t2").bound == 0xFFFF_FFFF


def test_sh3add_scales_bound():
    e = run("andi a0, a0, 0xff\n sh3add t0, a0, t1")
    assert e.state.get("t0").bound == 0xFF << 3


# ---------------------------------------------------------------------------
# Call ABI
# ---------------------------------------------------------------------------

def test_call_clobbers_caller_saved_keeps_callee():
    e = run("mv t0, a0\n mv s1, a0\n mv a3, a0\n call 0x20000")
    assert not e.state.get("t0").tainted
    assert e.state.get("s1").labels == {"user"}
    assert not e.state.get("a3").tainted
    assert e.state.get("a0").tainted


def test_call_clean_args_clean_return():
    e = run("mv s1, a0\n mv a0, zero\n call 0x20000")
    assert not e.state.get("a0").tainted and e.state.get("s1").tainted


def test_jal_zero_is_jump_not_call():
    e = run("mv t0, a0\n jal zero, 0x10010")
    assert e.state.get("t0").tainted


def test_c_jal_is_call_on_rv32_only():
    t32 = run("mv t0, a0\n c.jal 0x10010", width=Width.RV32)
    assert not t32.state.get("t0").tainted
    t64 = run("mv t0, a0\n c.jal 0x10010", width=Width.RV64)
    assert "c.jal" in t64.unknown


def test_ret_tainted_ra_reported():
    e = run("mv ra, a0\n ret")
    assert kinds(e) == ["tainted-return-address"]


def test_jalr_indirect_jump():
    for form in ("jalr a0", "jr a0", "c.jalr a0", "c.jr a0"):
        e = run(form)
        assert kinds(e) == ["tainted-indirect-jump"], form


# ---------------------------------------------------------------------------
# Stack frame tracking
# ---------------------------------------------------------------------------

def test_spill_reload_across_sp_adjust():
    e = run("""
        addi sp, sp, -32
        sd   a0, 8(sp)
        addi sp, sp, -16
        ld   t0, 24(sp)
        addi sp, sp, 48
    """)
    assert e.state.get("t0").labels == {"user"}


def test_mv_s0_sp_is_live_alias():
    e = run("""
        addi sp, sp, -32
        mv   s0, sp
        sd   a0, 8(sp)
        ld   t0, 8(s0)
        addi sp, sp, -16
        ld   t1, 8(s0)
        mv   sp, s0
        ld   t2, 8(sp)
    """)
    assert all(e.state.get(r).labels == {"user"} for r in ("t0", "t1", "t2"))


def test_saved_ra_overwrite_reported():
    e = run("""
        addi sp, sp, -16
        sd   ra, 8(sp)
        call 0x20000
        sd   a0, 8(sp)
        ld   ra, 8(sp)
        ret
    """)
    assert "tainted-overwrite-of-saved-ra" in kinds(e)
    assert "tainted-return-address" in kinds(e)


# ---------------------------------------------------------------------------
# Syscall tracing
# ---------------------------------------------------------------------------

def test_read_syscall_taints_stack_buffer():
    e = run("""
        addi sp, sp, -64
        li   a0, 0
        addi a1, sp, 16
        li   a2, 32
        li   a7, 63
        ecall
        lb   t0, 16(sp)
        lb   t1, 47(sp)
        lb   t2, 48(sp)
        mv   t3, a0
    """, taints=())
    assert e.state.get("t0").tainted and e.state.get("t1").tainted
    assert not e.state.get("t2").tainted
    assert e.state.get("t3").tainted


def test_tainted_syscall_arg_reported():
    e = run("li a7, 64\n mv a2, a0\n ecall")
    assert "tainted-syscall-arg" in kinds(e)


def test_tainted_syscall_nr_reported():
    e = run("mv a7, a0\n ecall")
    assert "tainted-syscall-number" in kinds(e)


# ---------------------------------------------------------------------------
# Policy knobs
# ---------------------------------------------------------------------------

def test_branch_reporting_opt_in():
    assert kinds(run("beqz a0, 0x10010")) == []
    assert kinds(run("beqz a0, 0x10010", policy=Policy(report_tainted_branch=True))) == ["tainted-branch-condition"]


def test_fp_copy_propagates():
    e = run("fmv.w.x fa0, a0\n fmv.s fa1, fa0\n fmv.x.w t0, fa1")
    assert e.state.get("t0").tainted


def test_unknown_mnemonic_conservative():
    e = run("frobnicate t0, a0, a1")
    assert e.state.get("t0").tainted and "frobnicate" in e.unknown


# ---------------------------------------------------------------------------
# TaintState lattice
# ---------------------------------------------------------------------------

def test_join_unions_labels():
    a = TaintState(Width.RV64)
    a.taint_reg("t0", "x")
    b = TaintState(Width.RV64)
    b.taint_reg("t0", "y")
    j = a.join(b)
    assert j.get("t0").labels == {"x", "y"}


def test_join_clean_and_bounded_yields_bounded():
    a = TaintState(Width.RV64)
    a.regs["t0"] = Taint(frozenset({"x"}), 0xFF)
    b = TaintState(Width.RV64)   # t0 clean on this path
    j = a.join(b)
    assert j.get("t0").bound == 0xFF


def test_join_two_different_bounds_without_widen_takes_max():
    a = TaintState(Width.RV64); a.regs["t0"] = Taint(frozenset({"x"}), 0x0F)
    b = TaintState(Width.RV64); b.regs["t0"] = Taint(frozenset({"x"}), 0xFF)
    j = a.join(b)
    assert j.get("t0").bound == 0xFF


def test_join_widen_different_bounds_becomes_none():
    a = TaintState(Width.RV64); a.regs["t0"] = Taint(frozenset({"x"}), 0x0F)
    b = TaintState(Width.RV64); b.regs["t0"] = Taint(frozenset({"x"}), 0xFF)
    j = a.join(b, widen=True)
    assert j.get("t0").bound is None


def test_same_as_true_on_equal_states():
    a = TaintState(Width.RV64); a.taint_reg("t0", "x")
    b = a.copy()
    assert a.same_as(b)


def test_same_as_false_after_modification():
    a = TaintState(Width.RV64); a.taint_reg("t0", "x")
    b = a.copy()
    b.taint_reg("t1", "y")
    assert not a.same_as(b)


# ---------------------------------------------------------------------------
# CFG builder
# ---------------------------------------------------------------------------

def test_blocks_split_at_branch_and_target():
    insns = list(from_listing("""
        beqz a0, 0x1000c
        li   t0, 1
        j    0x10010
        li   t0, 2
        add  t1, t0, a0
        ret
    """))
    cfg = build_cfg(insns, isa_for(Width.RV64))
    assert sorted(cfg.blocks) == [0x10000, 0x10004, 0x1000c, 0x10010]
    assert cfg.blocks[0x10000].succs == [0x1000c, 0x10004]
    assert cfg.blocks[0x10010].succs == []


def test_call_falls_through_but_jump_does_not():
    insns = list(from_listing("jal ra, 0x20000\n li t0, 1\n j 0x20000\n li t0, 2"))
    cfg = build_cfg(insns, isa_for(Width.RV64))
    assert cfg.blocks[0x10000].succs == [0x10004]
    assert cfg.blocks[0x10004].succs == []


# ---------------------------------------------------------------------------
# CFG fixpoint: joins
# ---------------------------------------------------------------------------

def test_taint_from_one_path_survives_join():
    res = cfg_run("""
        beqz a1, 0x1000c
        mv   t0, a0
        j    0x10010
        li   t0, 0
        jalr t0
    """)
    assert kinds(res) == ["tainted-indirect-jump"]
    assert res.entry_states[0x10010].get("t0").tainted


def test_bound_join_takes_max():
    res = cfg_run("""
        beqz a1, 0x10010
        andi t0, a0, 0xff
        j    0x10014
        nop
        andi t0, a0, 0xf
        lb   t1, 0(t0)
    """)
    assert res.entry_states[0x10014].get("t0").bound == 0xFF
    assert kinds(res) == []


def test_unbounded_on_one_path_kills_bound():
    res = cfg_run("""
        beqz a1, 0x10010
        andi t0, a0, 0xff
        j    0x10014
        nop
        mv   t0, a0
        lb   t1, 0(t0)
    """)
    assert res.entry_states[0x10014].get("t0").bound is None
    assert kinds(res) == ["tainted-load-address"]


def test_consts_survive_join_only_when_equal():
    res = cfg_run("beqz a1, 0x1000c\n li a7, 63\n j 0x10010\n li a7, 63\n ecall\n lb t0, 0(a1)", taints=())
    assert res.entry_states[0x10010].consts["a7"] == 63
    assert res.exit_states[0x10010].get("t0").tainted


# ---------------------------------------------------------------------------
# CFG fixpoint: loops
# ---------------------------------------------------------------------------

def test_loop_rotates_taint_across_iterations():
    res = cfg_run("""
        mv   t0, a0
        li   t1, 0
        li   t2, 0
        li   a2, 3
        mv   t2, t1
        mv   t1, t0
        addi a2, a2, -1
        bnez a2, 0x10010
        jalr t2
    """)
    assert kinds(res) == ["tainted-indirect-jump"]
    assert res.iterations >= 5


def test_loop_widens_growing_bound():
    res = cfg_run("""
        andi t0, a0, 0xf
        li   t1, 0
        add  t1, t1, t0
        bnez a2, 0x10008
        add  t2, a3, t1
        lb   t3, 0(t2)
    """)
    assert res.iterations < 50
    assert res.entry_states[0x10010].get("t1").bound is None
    assert kinds(res) == ["tainted-load-address"]


def test_loop_stable_bound_stays_bounded():
    res = cfg_run("""
        andi t0, a0, 0xf
        add  t2, a3, t0
        lb   t3, 0(t2)
        bnez a2, 0x10004
        ret
    """)
    assert kinds(res) == []
    assert res.exit_states[0x10004].get("t2").bound == 0xF


def test_stack_slot_survives_loop_and_join():
    res = cfg_run("""
        addi sp, sp, -32
        sd   a0, 8(sp)
        beqz a1, 0x10014
        li   t0, 1
        j    0x10014
        ld   t1, 8(sp)
        jalr t1
    """)
    assert kinds(res) == ["tainted-indirect-jump"]


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

def test_unreachable_blocks_not_analyzed():
    res = cfg_run("j 0x1000c\n mv t0, a0\n jalr t0\n ret")
    assert res.unreachable == [0x10004]
    assert kinds(res) == []


def test_findings_deduplicated_across_revisits():
    res = cfg_run("mv t0, a0\n jalr t0\n bnez a2, 0x10000\n ret")
    assert kinds(res) == ["tainted-indirect-jump"]
