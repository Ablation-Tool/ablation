"""Tests for the V850 labeled-taint tracker."""
import pytest

from ablation.analyzers.taint_tracker_v850 import CLEAN, Finding, Taint, TaintEngine
from ablation.analyzers.isa_v850 import Variant


def run(listing, variant=Variant.RH850, taints=(("r6", "in"),)):
    eng = TaintEngine(variant)
    for r, lbl in taints:
        eng.taint_register(r, lbl)
    from ablation.analyzers.insn_v850 import from_listing
    eng.run(list(from_listing(listing)))
    return eng


def T(eng, r):
    return eng.state.get(r)


def kinds(eng):
    return [f.kind for f in eng.findings]


# ---------------------------------------------------------------------------
# Destination-last operand order
# ---------------------------------------------------------------------------

def test_mov_writes_last_operand():
    e = run("mov r6, r10")
    assert T(e, "r10").labels == {"in"}


def test_mov_does_not_taint_first_operand():
    e = run("mov r7, r6", taints=(("r6", "in"),))
    assert not T(e, "r6").tainted and not T(e, "r7").tainted


def test_add_in_place_reads_and_writes_last():
    e = run("add r6, r10")
    assert T(e, "r10").tainted
    e2 = run("add r10, r6")
    assert T(e2, "r6").tainted and not T(e2, "r10").tainted


def test_sub_subr_propagate():
    assert T(run("sub r6, r10"), "r10").tainted
    assert T(run("subr r6, r10"), "r10").tainted


# ---------------------------------------------------------------------------
# andi zero-extends: ALWAYS bounds (opposite of RISC-V)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("imm,bound", [
    ("0xff",   0xFF),
    ("0xff00", 0xFF00),
    ("-1",     0xFFFF),    # -1 with 16-bit zero-extend = 0xFFFF, NOT identity
    ("0xffff", 0xFFFF),
    ("0",      0),
])
def test_andi_always_bounds(imm, bound):
    e = run(f"andi {imm}, r6, r10")
    assert T(e, "r10").bound == bound


def test_andi_propagates_taint():
    e = run("andi 0xff, r6, r10")
    assert T(e, "r10").tainted


def test_andi_bounds_rd_not_rs1():
    e = run("andi 0xff, r6, r10")
    assert T(e, "r6").bound is None
    assert T(e, "r10").bound == 0xFF


def test_andi_negative_one_is_not_identity():
    # RISC-V -1 is identity; V850 -1 zero-extends to 0xFFFF (bounded)
    e = run("andi -1, r6, r10")
    assert T(e, "r10").bound == 0xFFFF


def test_and_min_bound_from_two_operands():
    e = run("andi 0xff, r6, r10\n andi 0xf, r6, r11\n and r11, r10")
    assert T(e, "r10").bound == 0xF


# ---------------------------------------------------------------------------
# Shift bound propagation
# ---------------------------------------------------------------------------

def test_shl_scales_bound():
    e = run("andi 0xff, r6, r10\n shl 2, r10")
    assert T(e, "r10").bound == 0xFF << 2


def test_shr_narrows_bound():
    e = run("andi 0xff, r6, r10\n shr 1, r10")
    assert T(e, "r10").bound == 0xFF >> 1


def test_variable_shift_drops_bound():
    e = run("andi 0xff, r6, r10\n shl r7, r10")
    assert T(e, "r10").bound is None


# ---------------------------------------------------------------------------
# zxb/zxh in-place bounds
# ---------------------------------------------------------------------------

def test_zxb_bounds_to_0xff():
    e = run("zxb r6")
    assert T(e, "r6").bound == 0xFF and T(e, "r6").tainted


def test_zxh_bounds_to_0xffff():
    e = run("zxh r6")
    assert T(e, "r6").bound == 0xFFFF


# ---------------------------------------------------------------------------
# Loads clear/propagate taint
# ---------------------------------------------------------------------------

def test_load_from_clean_sp_is_clean():
    e = run("ld.w 4[sp], r10", taints=())
    assert not T(e, "r10").tainted


def test_store_then_load_same_slot_propagates():
    e = run("st.w r6, 4[sp]\n ld.w 4[sp], r10")
    assert T(e, "r10").tainted


def test_ld_bu_bounds_to_0xff():
    e = run("st.w r6, 0[sp]\n ld.bu 0[sp], r10")
    assert T(e, "r10").bound == 0xFF and T(e, "r10").tainted


def test_ld_hu_bounds_to_0xffff():
    e = run("st.w r6, 0[sp]\n ld.hu 0[sp], r10")
    assert T(e, "r10").bound == 0xFFFF and T(e, "r10").tainted


# ---------------------------------------------------------------------------
# prepare / dispose lp-slot tracking
# ---------------------------------------------------------------------------

def test_prepare_dispose_clean_roundtrip():
    e = run("""
        prepare {r20, lp}, 2
        mov r6, r20
        dispose 2, {r20, lp}, [lp]
    """)
    # r20 was saved clean; dispose restores clean value
    assert not T(e, "r20").tainted
    assert kinds(e) == []


def test_prepare_lp_slot_overwrite_detected():
    e = run("""
        prepare {r20, lp}, 0
        st.w r6, 4[sp]
        dispose 0, {r20, lp}, [lp]
    """)
    assert "tainted-overwrite-of-saved-lp" in kinds(e)
    assert "tainted-return-address" in kinds(e)


def test_st_w_directly_over_saved_lp():
    e = run("""
        prepare {lp}, 0
        st.w r6, 0[sp]
        dispose 0, {lp}, [lp]
    """)
    assert "tainted-overwrite-of-saved-lp" in kinds(e)


# ---------------------------------------------------------------------------
# Control-flow findings
# ---------------------------------------------------------------------------

def test_jmp_lp_tainted_is_return_hijack():
    e = run("mov r6, lp\n jmp [lp]")
    assert "tainted-return-address" in kinds(e)


def test_jmp_reg_is_indirect_jump():
    e = run("jmp [r6]")
    assert "tainted-indirect-jump" in kinds(e)


def test_jarl_indirect_tainted_call():
    e = run("jarl [r6], lp")
    assert "tainted-indirect-call" in kinds(e)


# ---------------------------------------------------------------------------
# Call clobbers / ABI modeling
# ---------------------------------------------------------------------------

def test_jarl_clobbers_caller_saved():
    e = run("mov r6, r12\n jarl 0x2000, lp")
    assert not T(e, "r12").tainted


def test_jarl_preserves_callee_saved():
    e = run("mov r6, r20\n jarl 0x2000, lp")
    assert T(e, "r20").tainted


def test_jarl_propagates_tainted_args_to_return():
    e = run("jarl 0x2000, lp")
    assert T(e, "r10").labels == {"in"}


def test_jarl_clean_args_clean_return():
    e = run("mov r0, r6\n jarl 0x2000, lp", taints=(("r6", "in"),))
    assert not T(e, "r10").tainted


# ---------------------------------------------------------------------------
# sp displacement tracking
# ---------------------------------------------------------------------------

def test_sp_delta_tracks_through_addi():
    e = run("add -16, sp\n st.w r6, 4[sp]\n addi -32, sp, sp\n ld.w 36[sp], r10")
    assert T(e, "r10").tainted


def test_frame_pointer_alias():
    e = run("add -16, sp\n mov sp, r29\n st.w r6, 8[r29]\n ld.w 8[sp], r10")
    assert T(e, "r10").tainted


# ---------------------------------------------------------------------------
# Variant-gating
# ---------------------------------------------------------------------------

def test_zxb_unknown_on_base_v850():
    e = run("zxb r6", variant=Variant.V850)
    assert "zxb" in e.unknown


def test_prepare_dispose_v850e_only():
    e = run("prepare {lp}, 0\n dispose 0, {lp}, [lp]", variant=Variant.V850)
    assert "prepare" in e.unknown


def test_unknown_mnemonic_conservative():
    e = run("frob r6, r7, r10")
    assert T(e, "r10").tainted and "frob" in e.unknown


# ---------------------------------------------------------------------------
# Multiple labels
# ---------------------------------------------------------------------------

def test_two_tainted_sources_union_labels():
    e = run("mov r6, r10\n mov r7, r11\n add r11, r10",
            taints=(("r6", "src_a"), ("r7", "src_b")))
    assert T(e, "r10").labels == {"src_a", "src_b"}


def test_andi_bound_with_multiple_labels():
    e = run("andi 0xff, r6, r10",
            taints=(("r6", "src_a"),))
    assert T(e, "r10").bound == 0xFF and "src_a" in T(e, "r10").labels
