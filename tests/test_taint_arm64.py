"""Tests for the AArch64 labeled-taint tracker."""
import pytest

from ablation.analyzers.taint_tracker_arm64 import CLEAN, Finding, Taint, TaintEngine
from ablation.analyzers.isa_arm64 import FLAGS


def run(listing, taints=(("x0", "in"),)):
    eng = TaintEngine()
    for r, lbl in taints:
        eng.taint_register(r, lbl)
    from ablation.analyzers.insn_arm64 import from_listing
    eng.run(list(from_listing(listing)))
    return eng


def T(eng, r):
    return eng.state.get(r)


def kinds(eng):
    return [f.kind for f in eng.findings]


# ---------------------------------------------------------------------------
# Basic register propagation
# ---------------------------------------------------------------------------

def test_mov_propagates():
    e = run("mov x1, x0")
    assert T(e, "x1").labels == {"in"}


def test_mov_imm_clears():
    e = run("mov x0, #42")
    assert not T(e, "x0").tainted


def test_add_propagates():
    e = run("add x2, x0, x1")
    assert T(e, "x2").labels == {"in"}


def test_add_two_tainted_unions_labels():
    e = run("add x2, x0, x1", taints=(("x0", "a"), ("x1", "b")))
    assert T(e, "x2").labels == {"a", "b"}


def test_sub_propagates():
    e = run("sub x2, x0, #4")
    assert T(e, "x2").labels == {"in"}


def test_orr_with_xzr_is_copy():
    e = run("orr x1, xzr, x0")
    assert T(e, "x1").labels == {"in"}


def test_add_zero_is_copy():
    e = run("add x1, x0, #0")
    assert T(e, "x1").labels == {"in"}


# ---------------------------------------------------------------------------
# W-register zero-extension bound
# ---------------------------------------------------------------------------

def test_w_write_bounds_to_0xffffffff():
    e = run("add w1, w0, #0")
    assert T(e, "x1").bound == 0xFFFF_FFFF


def test_x_write_no_forced_bound():
    # x-form write: no implicit bound from zero-extension
    e = run("add x1, x0, x2")
    assert T(e, "x1").bound is None


def test_ldrb_bounds_to_0xff():
    e = run("""
        str x0, [sp, #-8]!
        ldrb w1, [sp]
    """)
    assert T(e, "x1").bound == 0xFF


def test_ldrh_bounds_to_0xffff():
    e = run("""
        str x0, [sp, #-8]!
        ldrh w1, [sp]
    """)
    assert T(e, "x1").bound == 0xFFFF


# ---------------------------------------------------------------------------
# and/tst bound semantics
# ---------------------------------------------------------------------------

def test_and_positive_mask_bounds():
    e = run("and x1, x0, #0xff")
    assert T(e, "x1").bound == 0xFF and T(e, "x1").tainted


def test_and_alignment_mask_no_bound():
    # 0xfffffffffffffff0 = alignment mask, top bit set -> no useful bound
    e = run("and x1, x0, #-16")
    assert T(e, "x1").bound is None


def test_and_zero_mask_bounds_zero():
    e = run("and x1, x0, #0")
    assert T(e, "x1").bound == 0


def test_and_propagates_taint():
    e = run("and x1, x0, #0xff")
    assert T(e, "x1").tainted


# ---------------------------------------------------------------------------
# Extension mnemonic bounds
# ---------------------------------------------------------------------------

def test_uxtb_bounds_to_0xff():
    e = run("uxtb x1, w0")
    assert T(e, "x1").bound == 0xFF


def test_uxth_bounds_to_0xffff():
    e = run("uxth x1, w0")
    assert T(e, "x1").bound == 0xFFFF


def test_uxtw_bounds_to_0xffffffff():
    e = run("uxtw x1, w0")
    assert T(e, "x1").bound == 0xFFFF_FFFF


def test_ubfx_extracts_bound():
    # ubfx x1, x0, #2, #4 -> bits 2-5 extracted, value in [0, 0xF]
    e = run("ubfx x1, x0, #2, #4")
    assert T(e, "x1").bound == 0xF


# ---------------------------------------------------------------------------
# Memory: store then load propagates
# ---------------------------------------------------------------------------

def test_store_load_same_slot_propagates():
    e = run("""
        str x0, [sp, #-8]!
        ldr x1, [sp]
    """)
    assert T(e, "x1").tainted


def test_load_clean_slot_is_clean():
    e = run("ldr x1, [sp]", taints=())
    assert not T(e, "x1").tainted


def test_load_with_pre_index_propagates():
    e = run("""
        str x0, [sp, #-8]!
        ldr x1, [sp, #0]
    """)
    assert T(e, "x1").tainted


# ---------------------------------------------------------------------------
# ldp/stp pair instructions + lr_slot tracking
# ---------------------------------------------------------------------------

def test_stp_lr_then_corrupt_fires_finding():
    e = run("""
        stp x29, x30, [sp, #-16]!
        str x0, [sp, #8]
        ldp x29, x30, [sp], #16
        ret
    """, taints=(("x0", "net"),))
    assert "tainted-overwrite-of-saved-lr" in kinds(e)
    assert "tainted-return-address" in kinds(e)


def test_stp_lr_clean_restore_no_finding():
    e = run("""
        stp x29, x30, [sp, #-16]!
        ldp x29, x30, [sp], #16
        ret
    """, taints=(("x0", "in"),))
    assert "tainted-return-address" not in kinds(e)


def test_ldp_loads_both_regs():
    e = run("""
        str x0, [sp, #-8]!
        str x0, [sp, #-8]!
        ldp x1, x2, [sp]
    """)
    assert T(e, "x1").tainted
    assert T(e, "x2").tainted


# ---------------------------------------------------------------------------
# Control-flow findings
# ---------------------------------------------------------------------------

def test_ret_via_tainted_lr():
    e = run("mov x30, x0\n ret")
    assert "tainted-return-address" in kinds(e)


def test_br_tainted_is_indirect_jump():
    e = run("br x0")
    assert "tainted-indirect-jump" in kinds(e)


def test_blr_tainted_is_indirect_call():
    e = run("blr x0")
    assert "tainted-indirect-call" in kinds(e)


def test_b_uncond_no_finding():
    e = run("b 0x1000")
    assert not kinds(e)


# ---------------------------------------------------------------------------
# Call ABI modeling
# ---------------------------------------------------------------------------

def test_bl_clobbers_caller_saved():
    e = run("mov x5, x0\n bl 0x5000")
    assert not T(e, "x5").tainted


def test_bl_preserves_callee_saved():
    e = run("mov x19, x0\n bl 0x5000")
    assert T(e, "x19").tainted


def test_bl_propagates_tainted_arg_to_return():
    e = run("bl 0x5000")
    assert T(e, "x0").tainted


def test_bl_clean_args_clean_return():
    e = run("mov x0, #0\n bl 0x5000", taints=(("x0", "in"),))
    assert not T(e, "x0").tainted


# ---------------------------------------------------------------------------
# Frame pointer tracking
# ---------------------------------------------------------------------------

def test_frame_pointer_alias_tracks_stores():
    e = run("""
        sub sp, sp, #32
        mov x29, sp
        str x0, [x29, #8]
        ldr x1, [sp, #8]
    """)
    assert T(e, "x1").tainted


def test_sp_writeback_pre_rebase():
    e = run("""
        str x0, [sp, #-8]!
        ldr x1, [sp]
    """)
    assert T(e, "x1").tainted


def test_sp_writeback_post_rebased():
    e = run("""
        str x0, [sp, #-8]!
        ldr x1, [sp]
        ldr x1, [sp], #8
    """)
    assert T(e, "x1").tainted


# ---------------------------------------------------------------------------
# Shift/extend modifier on source operand
# ---------------------------------------------------------------------------

def test_lsl_modifier_scales_bound():
    e = run("and x1, x0, #0xff\n add x2, x1, x1, lsl #2")
    # x1 bound=0xff; lsl #2 -> operand bound=0x3fc; add -> bound=0x3fc+0xff = bounded
    assert T(e, "x2").bound is not None


def test_uxtw_modifier_caps_bound():
    # xzr + uxtw(x0): only the modified operand is tainted, so result bounded to 0xFFFF_FFFF
    e = run("add x1, xzr, x0, uxtw")
    assert T(e, "x1").bound == 0xFFFF_FFFF


# ---------------------------------------------------------------------------
# Csel / cset
# ---------------------------------------------------------------------------

def test_csel_unions_both_branches():
    e = run("csel x2, x0, x1, eq", taints=(("x0", "a"), ("x1", "b")))
    assert T(e, "x2").labels == {"a", "b"}


def test_cset_bounded_to_1():
    e = run("cmp x0, #0\n cset x1, eq")
    # cset writes 0 or 1, always bounded
    assert T(e, "x1").bound == 1


# ---------------------------------------------------------------------------
# Unknown mnemonic: conservative propagation
# ---------------------------------------------------------------------------

def test_unknown_mnemonic_propagates_taint():
    e = run("frobble x1, x0, x2")
    assert T(e, "x1").tainted and "frobble" in e.unknown


# ---------------------------------------------------------------------------
# Multiple labels / label union
# ---------------------------------------------------------------------------

def test_labels_union_through_two_sources():
    e = run("add x2, x0, x1\n add x3, x2, x4",
            taints=(("x0", "net"), ("x1", "user"), ("x4", "disk")))
    assert T(e, "x3").labels == {"net", "user", "disk"}


# ---------------------------------------------------------------------------
# Syscall tracing (svc / x8 nr)
# ---------------------------------------------------------------------------

def test_svc_read_taints_x0():
    e = run("""
        mov x8, #63
        svc #0
    """, taints=())
    assert T(e, "x0").tainted


def test_svc_tainted_nr_fires_finding():
    e = run("""
        mov x8, x0
        svc #0
    """)
    assert "tainted-syscall-number" in kinds(e)


def test_svc_write_clean():
    e = run("""
        mov x8, #64
        svc #0
    """, taints=())
    # write syscall should not taint return
    assert not T(e, "x0").tainted


# ---------------------------------------------------------------------------
# Store-to-tainted-address finding
# ---------------------------------------------------------------------------

def test_str_to_tainted_address_fires():
    e = run("str x1, [x0]")
    assert "tainted-store-address" in kinds(e)


def test_ldr_from_tainted_address_fires():
    e = run("ldr x1, [x0]")
    assert "tainted-load-address" in kinds(e)


# ---------------------------------------------------------------------------
# fmov: FP copy does not track precision bound
# ---------------------------------------------------------------------------

def test_fmov_propagates_labels():
    e = run("fmov d0, x0")
    assert T(e, "v0").tainted


def test_fmov_back_to_gpr():
    e = run("fmov d0, x0\n fmov x1, d0")
    assert T(e, "x1").tainted
