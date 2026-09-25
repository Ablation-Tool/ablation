import pytest

from ablation.analyzers.taint_tracker_arc_labeled import (
    CLEAN, Finding, Policy, Taint, TaintState, TaintTracker,
)
from ablation.analyzers.insn_arc import from_listing
from ablation.analyzers.isa_arc import Mode


def run(src, taints=(), mem=None, ptee=None, policy=None):
    t = TaintTracker(Mode.HS, policy=policy)
    for r, l in taints:
        t.taint_register(r, l)
    if mem:
        t.taint_memory(*mem)
    if ptee:
        t.taint_pointee(*ptee)
    t.run(list(from_listing(src)))
    return t


def kinds(t):
    return [f.kind for f in t.findings]


def g(t, r):
    return t.state.get(t._canon(r))


BUF = ("r0", 0, "buf", 64)


# --- delay slots (opt-in with .d) ---------------------------------------------------------
def test_bl_d_slot_argument_reaches_callee():
    t = run("ld r2,[r0]\n bl.d 0x100\n mov r0,r2", mem=BUF)
    assert g(t, "r0").tainted


def test_bl_without_d_has_no_slot():
    t = run("bl 0x100\n ld r0,[r0]", mem=BUF)
    assert not g(t, "r0").tainted


def test_return_address_after_slot():
    t = run("bl.d 0x100\n nop_s")
    assert t.state.consts["r31"] == 0x10006       # 4-byte bl + 2-byte nop_s slot


def test_pending_transfer_flushed_at_end():
    assert kinds(run("ld r2,[r0]\n jl.d [r2]", mem=BUF)) == ["tainted-indirect-call"]


# --- returns and indirect transfers -----------------------------------------------------------
def test_indirect_call_jump_return():
    assert kinds(run("ld r2,[r0]\n jl_s [r2]", mem=BUF)) == ["tainted-indirect-call"]
    assert kinds(run("ld r2,[r0]\n j [r2]", mem=BUF)) == ["tainted-indirect-jump"]
    assert kinds(run("ld blink,[r0]\n j_s [blink]", mem=BUF)) == ["tainted-return-address"]
    assert kinds(run("ld blink,[r0]\n jeq [blink]", mem=BUF)) == ["tainted-return-address"]


def test_push_pop_blink_smash():
    assert kinds(run("push_s blink\n ld r2,[r0]\n st r2,[sp]\n pop_s blink\n j_s [blink]", mem=BUF)) == ["tainted-overwrite-of-saved-ra", "tainted-return-address"]
    assert kinds(run("push_s blink\n ld r2,[r0]\n pop_s blink\n j_s [blink]", mem=BUF)) == []


def test_enter_leave():
    assert kinds(run("enter_s {r13-r15,fp,blink}\n ld r13,[r0]\n st r13,[fp,-4]\n leave_s {r13-r15,fp,blink,pcl}", mem=BUF)) == []
    assert kinds(run("enter_s {r13,fp,blink}\n ld r2,[r0]\n st r2,[fp,8]\n leave_s {r13,fp,blink,pcl}", mem=BUF)) == ["tainted-overwrite-of-saved-ra", "tainted-return-address"]


def test_branch_indexed():
    t = run("ldb r2,[r0]\n bi [r2]\n ld r3,[r0]\n bih [r3]", mem=BUF, policy=Policy(report_bounded=True))
    assert kinds(t) == ["bounded-tainted-indirect-jump", "tainted-indirect-jump"]


def test_conditional_execution_joins():
    t = run("cmp r1,0\n mov.ne r2,r0\n mov r3,r2", taints=(("r0", "u"), ("r2", "v")))
    assert g(t, "r2").labels == {"u", "v"} == g(t, "r3").labels
    t = run("cmp r1,0\n st.ne r0,[sp]\n ld r2,[sp]", taints=(("r0", "u"),))
    assert g(t, "r2").labels == {"u"}


def test_tainted_branch_opt_in():
    src = "ld r1,[r0]\n brne r1,0,0x40\n cmp r1,3\n beq 0x40\n bbit0 r1,3,0x40"
    assert kinds(run(src, mem=BUF)) == []
    assert kinds(run(src, mem=BUF, policy=Policy(report_tainted_branch=True))) == ["tainted-branch-condition"] * 3


# --- loads, addressing modes, bounds ---------------------------------------------------------------
def test_load_widths():
    t = run("ldb r1,[r0]\n ldh r2,[r0]\n ld r3,[r0]\n ldb.x r4,[r0]\n ldh.x r5,[r0]", mem=BUF)
    assert g(t, "r1").bound == 0xFF and g(t, "r2").bound == 0xFFFF and g(t, "r3").bound is None
    assert g(t, "r4").tainted and g(t, "r4").bound is None and g(t, "r5").bound is None
    assert kinds(t) == []


def test_ab_post_modify_walk():
    t = run("mov r1,r0\n ldb.ab r2,[r1,1]\n ldb.ab r3,[r1,1]\n ldb r4,[r1,100]", mem=BUF)
    assert g(t, "r2").tainted and g(t, "r3").tainted and not g(t, "r4").tainted


def test_aw_pre_modify():
    t = run("mov r1,r0\n ld.aw r2,[r1,4]\n ld r3,[r1]\n ld r4,[r1,60]", mem=BUF)
    assert g(t, "r2").tainted and g(t, "r3").tainted and not g(t, "r4").tainted


def test_as_scaled_register_offset():
    t = run("ldb r1,[r0]\n ld.as r2,[r3,r1]", mem=BUF, policy=Policy(report_bounded=True))
    assert kinds(t) == ["bounded-tainted-load-address"] and "<= 0x3fc" in t.findings[0].detail


def test_bounds():
    t = run("ld r1,[r0]\n bmsk r2,r1,6\n extb r3,r1\n and r4,r1,0xff\n lsr r5,r1,24\n add2 r6,r7,r3\n asl r8,r3,4\n setlt r10,r1,r2\n neg r11,r3\n sexb r12,r3\n bic r13,r3,r1\n max r14,r3,r2\n asr r15,r1,4",
            mem=BUF)
    assert g(t, "r2").bound == 0x7F and g(t, "r3").bound == 0xFF and g(t, "r4").bound == 0xFF
    assert g(t, "r5").bound == 0xFF and g(t, "r6").bound == 0x3FC and g(t, "r8").bound == 0xFF0
    assert g(t, "r10").bound == 1 and g(t, "r11").bound is None and g(t, "r12").bound is None
    assert g(t, "r13").bound == 0xFF and g(t, "r14").bound == 0xFF and g(t, "r15").bound is None


def test_index_bound_downgrades():
    src = "ldb_s r2,[r0,0]\n add2 r2,0x400,r2\n ld r3,[r2,0]"
    assert kinds(run(src, mem=BUF)) == []
    assert kinds(run(src, mem=BUF, policy=Policy(report_bounded=True))) == ["bounded-tainted-load-address"]
    assert kinds(run("ld r2,[r0]\n add2 r2,r1,r2\n st 1,[r2]", mem=BUF)) == ["tainted-store-address"]


def test_pcl_relative_is_clean_constant():
    t = run("ld r2,[pcl,32]\n add r3,pcl,0x100", taints=(("r2", "u"),))
    assert not g(t, "r2").tainted and t.state.consts["r3"] == 0x10004 + 0x100


# --- frame, spills, ABI ------------------------------------------------------------------------------
def test_fp_frame_spill_reload():
    t = run("push_s blink\n st.aw fp,[sp,-4]\n mov_s fp,sp\n sub_s sp,sp,4\n st r0,[fp,-4]\n ld r2,[fp,-4]\n ldb_s r2,[r2,0]\n mov_s sp,fp\n ld.ab fp,[sp,4]\n pop_s blink\n j_s [blink]", mem=BUF)
    assert g(t, "r2").bound == 0xFF and kinds(t) == []


def test_ninth_argument_on_stack():
    assert kinds(run("ld r2,[sp]\n ld r3,[r2]\n add2 r4,r5,r3\n st 0,[r4]", ptee=("sp", 0, "buf", 64))) == ["tainted-store-address"]


def test_call_clobbers_and_propagates():
    t = run("ld r13,[r0]\n mov r12,r13\n mov r1,r13\n bl 0x100", mem=BUF)
    assert g(t, "r13").tainted and not g(t, "r12").tainted and g(t, "r0").tainted and t.state.consts["r31"] == 0x10010


# --- syscalls -------------------------------------------------------------------------------------------
def test_trap_s_read():
    t = run("sub sp,sp,64\n mov r8,63\n mov r0,0\n mov r1,sp\n mov r2,64\n trap_s 0\n ldb r3,[sp,5]\n ldb r4,[sp,64]")
    assert g(t, "r0").tainted and g(t, "r3").bound == 0xFF and not g(t, "r4").tainted


def test_tainted_syscall_number_and_arg():
    t = run("ld r8,[r0]\n ld r1,[r0]\n trap_s 0", mem=BUF)
    assert "tainted-syscall-number" in kinds(t) and "tainted-syscall-arg" in kinds(t)


def test_flag_setting_and_cmp_taint_flags():
    t = run("ld r1,[r0]\n cmp r1,0", mem=BUF)
    assert t.state.get("status32").tainted
    t = run("ld r1,[r0]\n add.f r2,r1,1", mem=BUF)
    assert t.state.get("status32").tainted


# --- lattice ops (copy / join / same_as) -----------------------------------------------------------
def test_taintstate_copy_is_independent():
    t = run("ld r2,[r0]", mem=BUF)
    s = t.state
    c = s.copy()
    c.regs["r2"] = CLEAN
    assert s.get("r2").tainted


def test_taintstate_join_unions_regs():
    t1 = run("ld r2,[r0]", mem=BUF)
    t2 = run("ld r3,[r0]", mem=BUF)
    j = t1.state.join(t2.state)
    assert j.get("r2").tainted and j.get("r3").tainted


def test_taintstate_join_intersects_consts():
    t1 = run("mov r4,42")
    t2 = run("mov r4,99")
    j = t1.state.join(t2.state)
    assert "r4" not in j.consts


def test_taintstate_same_as():
    t = run("ld r2,[r0]", mem=BUF)
    assert t.state.same_as(t.state.copy())
    c = t.state.copy()
    c.regs.clear()
    assert not t.state.same_as(c)


def test_labels_propagate_through_mem():
    t = run("st r4,[sp]\n ld r5,[sp]", taints=(("r4", "a"),))
    assert g(t, "r5").labels == {"a"}


def test_join_unions_ra_regs():
    t1 = TaintTracker(Mode.HS)
    t1.state.ra_regs.add("r2")
    t2 = TaintTracker(Mode.HS)
    t2.state.ra_regs.add("r3")
    j = t1.state.join(t2.state)
    assert "r2" in j.ra_regs and "r3" in j.ra_regs
