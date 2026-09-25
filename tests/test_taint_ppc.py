import pytest

from ablation.analyzers.taint_tracker_ppc_labeled import (
    CLEAN, Finding, Policy, Taint, TaintState, TaintTracker,
)
from ablation.analyzers.insn_ppc import from_listing
from ablation.analyzers.isa_ppc import Abi, Mode


def run(src, mode=Mode.PPC32, taints=(), mem=None, ptee=None, policy=None, little=False):
    t = TaintTracker(mode, policy=policy, little=little)
    for r, l in taints:
        t.taint_register(r, l)
    if mem:
        t.taint_memory(*mem)
    if ptee:
        t.taint_pointee(*ptee)
    t.run(list(from_listing(src, mode)))
    return t


def kinds(t):
    return [f.kind for f in t.findings]


def g(t, r):
    return t.state.get(r)


BUF = ("r3", 0, "buf", 64)


# --- link register / frames ------------------------------------------------------------------------
def test_ppc32_prologue_epilogue_is_silent():
    assert kinds(run("stwu r1, -32(r1)\n mflr r0\n stw r0, 36(r1)\n lwz r4, 0(r3)\n lwz r0, 36(r1)\n mtlr r0\n addi r1, r1, 32\n blr", mem=BUF)) == []


def test_saved_lr_overwrite_then_return():
    src = "stwu r1, -32(r1)\n mflr r0\n stw r0, 36(r1)\n lwz r4, 0(r3)\n stw r4, 36(r1)\n lwz r0, 36(r1)\n mtlr r0\n {epi}\n blr"
    for epi in ("addi r1, r1, 32", "lwz r1, 0(r1)"):
        assert kinds(run(src.format(epi=epi), mem=BUF)) == ["tainted-overwrite-of-saved-ra", "tainted-return-address"], epi


def test_elfv2_frame_with_lr_saved_before_stdu():
    src = "mflr r0\n std r31, -8(r1)\n stdu r1, -48(r1)\n std r0, 64(r1)\n mr r31, r1\n std r3, 32(r31)\n ld r3, 32(r31)\n lbz r4, 1(r3)\n addi r1, r1, 48\n ld r0, 16(r1)\n mtlr r0\n blr"
    t = run(src, Mode.PPC64, mem=BUF, little=True)
    assert kinds(t) == [] and g(t, "r4").bound == 0xFF
    smash = "mflr r0\n stdu r1, -48(r1)\n std r0, 64(r1)\n mr r31, r1\n ld r4, 0(r3)\n std r4, 64(r31)\n addi r1, r1, 48\n ld r0, 16(r1)\n mtlr r0\n blr"
    assert kinds(run(smash, Mode.PPC64, mem=BUF, little=True)) == ["tainted-overwrite-of-saved-ra", "tainted-return-address"]


def test_mtlr_tainted_then_blr():
    assert kinds(run("lwz r4, 0(r3)\n mtlr r4\n blr", mem=BUF)) == ["tainted-return-address"]


def test_ctr_call_and_jump():
    assert kinds(run("lwz r4, 0(r3)\n mtctr r4\n bctrl", mem=BUF)) == ["tainted-indirect-call"]
    assert kinds(run("lwz r4, 0(r3)\n mtctr r4\n bctr", mem=BUF)) == ["tainted-indirect-jump"]
    assert kinds(run("lwz r4, 0(r3)\n mtctr r4\n bctrl\n bctr", mem=BUF)) == ["tainted-indirect-call"]


def test_elfv1_descriptor_call():
    clean = "ld r11, -32000(r2)\n ld r0, 0(r11)\n ld r2, 8(r11)\n ld r11, 16(r11)\n mtctr r0\n bctrl"
    assert kinds(run(clean, Mode.PPC64, mem=BUF)) == []
    bad = "ld r11, 0(r3)\n ld r0, 0(r11)\n ld r2, 8(r11)\n ld r11, 16(r11)\n mtctr r0\n bctrl"
    assert kinds(run(bad, Mode.PPC64, mem=BUF)) == ["tainted-load-address"] * 3 + ["tainted-indirect-call"]


def test_pic_get_pc_bl_is_not_a_call():
    t = run("bl 0x10004\n mflr r30\n lwz r4, 0(r3)", mem=BUF)
    assert g(t, "r4").tainted and not g(t, "r3").tainted


def test_bl_call_abi():
    t = run("lwz r31, 0(r3)\n mr r4, r31\n mr r10, r31\n bl 0x1000", mem=BUF)
    assert g(t, "r3").tainted and g(t, "r4").tainted
    assert g(t, "r31").tainted and not g(t, "r10").tainted
    assert not g(t, "lr").tainted and t.state.consts["lr"] == 0x10010 and "lr" not in t.state.ra_regs


def test_stack_args():
    t = run("stwu r1, -32(r1)\n lwz r4, 40(r1)\n lwz r5, 0(r4)\n slwi r5, r5, 2\n stwx r6, r7, r5", ptee=("r1", 8, "buf", 64))
    assert kinds(t) == ["tainted-store-address"]
    t = run("lwz r4, 0(r3)\n stw r4, 8(r1)\n bl 0x1000", mem=BUF)
    assert g(t, "r3").tainted


def test_stmw_lmw():
    t = run("stwu r1, -48(r1)\n lwz r29, 0(r3)\n stmw r29, 20(r1)\n lmw r29, 20(r1)", mem=BUF)
    assert g(t, "r29").tainted and not g(t, "r30").tainted


# --- bounds -------------------------------------------------------------------------------------
def test_load_widths_ppc32():
    t = run("lbz r4, 0(r3)\n lhz r5, 0(r3)\n lha r6, 0(r3)\n lwz r7, 0(r3)", mem=BUF)
    assert g(t, "r4").bound == 0xFF and g(t, "r5").bound == 0xFFFF and g(t, "r6").bound is None
    assert g(t, "r7").bound is None


def test_load_widths_ppc64():
    t = run("lwz r4, 0(r3)\n lwa r5, 0(r3)\n ld r6, 0(r3)\n lwzx r7, r3, r8", Mode.PPC64, mem=BUF, taints=(("r8", "i"),))
    assert g(t, "r4").bound == 0xFFFFFFFF and g(t, "r5").bound is None and g(t, "r6").bound is None
    assert kinds(t) == ["tainted-load-address"]


def test_rlwinm_family_bounds():
    t = run("lwz r4, 0(r3)\n clrlwi r5, r4, 24\n slwi r6, r5, 2\n srwi r7, r4, 24\n rlwinm r8, r4, 0, 28, 31\n extrwi r9, r4, 8, 4\n rlwinm r10, r4, 3, 5, 10\n rlwinm r11, r4, 0, 28, 3\n rlwimi r12, r5, 0, 24, 31\n slwi r13, r4, 2",
            mem=BUF, taints=(("r12", "v"),))
    assert g(t, "r5").bound == 0xFF and g(t, "r6").bound == 0x3FC and g(t, "r7").bound == 0xFF and g(t, "r8").bound == 0xF
    assert g(t, "r9").bound == 0xFF and g(t, "r10").bound == 0x07E00000
    assert g(t, "r11").bound is None
    assert g(t, "r12").labels == {"buf", "v"} and g(t, "r12").bound is None
    assert g(t, "r13").bound is None


def test_rldic_family_bounds():
    t = run("ld r4, 0(r3)\n clrldi r5, r4, 56\n sldi r6, r5, 3\n srdi r7, r4, 56\n rldicl r8, r4, 0, 32\n clrrdi r9, r5, 2\n extrdi r10, r4, 8, 8\n rldic r11, r5, 4, 40\n sldi r12, r4, 3\n rotldi r13, r5, 8",
            Mode.PPC64, mem=BUF)
    assert g(t, "r5").bound == 0xFF and g(t, "r6").bound == 0x7F8 and g(t, "r7").bound == 0xFF
    assert g(t, "r8").bound == 0xFFFFFFFF and g(t, "r9").bound == 0xFF and g(t, "r10").bound == 0xFF and g(t, "r11").bound == 0xFF0
    assert g(t, "r12").bound is None and g(t, "r13").bound is None


def test_logic_and_arith_bounds():
    t = run("lwz r4, 0(r3)\n andi. r5, r4, 0xff\n ori r6, r5, 0x100\n extsb r7, r5\n neg r8, r5\n mulli r9, r5, 8\n andis. r10, r4, 1\n srawi r11, r5, 2\n cntlzw r12, r4\n subf r13, r5, r5\n subfic r14, r5, 10\n andc r15, r5, r4",
            mem=BUF)
    assert g(t, "r5").bound == 0xFF and g(t, "r6").bound == 0x1FF and g(t, "r9").bound == 0x7F8 and g(t, "r10").bound == 0x10000
    for r in ("r7", "r8", "r11", "r14"):
        assert g(t, r).tainted and g(t, r).bound is None, r
    assert g(t, "r12").bound == 32 and g(t, "r13").bound == 0x1FE and g(t, "r15").bound == 0xFF
    assert g(t, "cr0").tainted


def test_index_bound_downgrades():
    src = "lbz r4, 1(r3)\n slwi r4, r4, 2\n lwzx r5, r6, r4"
    assert kinds(run(src, mem=BUF)) == []
    t = run(src, mem=BUF, policy=Policy(report_bounded=True))
    assert kinds(t) == ["bounded-tainted-load-address"] and "<= 0x3fc" in t.findings[0].detail


# --- condition register, isel, branches ------------------------------------------------------------------
def test_cr_fields_and_branches():
    src = "lwz r4, 0(r3)\n cmpwi cr7, r4, 5\n bcc cr7, 0x100\n cmplwi r4, 3\n bne 0x100\n isel r5, r6, r7, cr7\n add. r8, r4, r6\n mfcr r9"
    t = run(src, mem=BUF, taints=(("r6", "u"),))
    assert g(t, "cr7").tainted and g(t, "cr0").tainted and g(t, "r5").labels == {"u"} and g(t, "r9").tainted
    assert kinds(t) == []
    assert kinds(run(src, mem=BUF, policy=Policy(report_tainted_branch=True))) == ["tainted-branch-condition"] * 3


def test_x_form_and_update_form_addressing():
    t = run("li r5, 8\n lwzx r4, r3, r5\n lbzx r6, r3, r5\n addi r7, r3, -1\n lbzu r8, 1(r7)\n lbzu r9, 1(r7)\n lbz r10, 100(r7)", mem=BUF)
    assert g(t, "r4").tainted and g(t, "r6").bound == 0xFF and g(t, "r8").bound == 0xFF and g(t, "r9").bound == 0xFF
    assert not g(t, "r10").tainted


def test_syscall_read():
    t = run("stwu r1, -80(r1)\n li r0, 3\n li r3, 0\n addi r4, r1, 16\n li r5, 64\n sc\n lbz r6, 20(r1)\n lbz r7, 80(r1)")
    assert g(t, "r3").tainted and g(t, "r6").bound == 0xFF and not g(t, "r7").tainted and not g(t, "cr0").tainted
    t = run("lwz r0, 0(r3)\n lwz r4, 0(r3)\n sc", mem=BUF)
    assert "tainted-syscall-number" in kinds(t) and "tainted-syscall-arg" in kinds(t)


def test_constants_lis_ori_addi():
    t = run("lis r9, 0x1234\n ori r9, r9, 0x5678\n li r10, -1\n addis r11, r10, 1")
    assert t.state.consts["r9"] == 0x12345678 and t.state.consts["r10"] == 0xFFFFFFFF and t.state.consts["r11"] == 0xFFFF


def test_fp_round_trip():
    t = run("lwz r4, 0(r3)\n stw r4, 8(r1)\n lfs f1, 8(r1)\n fadd f2, f1, f3\n stfs f2, 12(r1)\n lwz r5, 12(r1)", mem=BUF)
    assert g(t, "r5").tainted and g(t, "vs1").tainted


# --- lattice ops (copy / join / same_as) -----------------------------------------------------------
def test_taintstate_copy_is_independent():
    t = run("lwz r4, 0(r3)", mem=BUF)
    s = t.state
    c = s.copy()
    c.regs["r4"] = CLEAN
    assert s.get("r4").tainted


def test_taintstate_join_unions_regs():
    t1 = run("lwz r4, 0(r3)", mem=BUF)
    t2 = run("lwz r5, 0(r3)", mem=BUF)
    j = t1.state.join(t2.state)
    assert j.get("r4").tainted and j.get("r5").tainted


def test_taintstate_join_intersects_consts():
    t1 = run("li r4, 42")
    t2 = run("li r4, 99")
    j = t1.state.join(t2.state)
    assert "r4" not in j.consts


def test_taintstate_same_as():
    t = run("lwz r4, 0(r3)", mem=BUF)
    assert t.state.same_as(t.state.copy())
    c = t.state.copy()
    c.regs.clear()
    assert not t.state.same_as(c)


def test_labels_propagate_through_mem():
    t = run("stw r4, 0(r1)\n lwz r5, 0(r1)", taints=(("r4", "a"),))
    assert g(t, "r5").labels == {"a"}


def test_entry_not_function_start_no_lr_ra():
    t = run("lwz r4, 0(r3)\n mtlr r4\n blr", mem=BUF, policy=Policy(entry_is_function_start=False))
    assert kinds(t) == ["tainted-return-address"]


def test_join_unions_ra_regs():
    t1 = TaintTracker(Mode.PPC32)
    t1.state.ra_regs.add("r0")
    t2 = TaintTracker(Mode.PPC32)
    t2.state.ra_regs.add("r4")
    j = t1.state.join(t2.state)
    assert "r0" in j.ra_regs and "r4" in j.ra_regs
