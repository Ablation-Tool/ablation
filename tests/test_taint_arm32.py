"""ARM32 / Thumb-2 labeled-taint tracker tests (UAL listings at base 0x10000)."""
import pytest

from ablation.analyzers.insn_arm32 import from_listing, make_insn
from ablation.analyzers.isa_arm32 import Abi, Mode
from ablation.analyzers.taint_tracker_arm32_labeled import Policy, TaintState, TaintTracker


def run(src, mode=Mode.ARM, taints=(), mem=None, ptee=None, policy=None):
    t = TaintTracker(mode, policy=policy)
    for r, l in taints:
        t.taint_register(r, l)
    if mem is not None:
        t.taint_memory(*mem)
    if ptee is not None:
        t.taint_pointee(*ptee)
    t.run(list(from_listing(src, mode)))
    return t


def kinds(t):
    return [f.kind for f in t.findings]


BUF = ("r0", 0, "buf", 64)


# --- loads, bounds ---------------------------------------------------------------

def test_load_widths_bound():
    t = run("ldrb r1, [r0]\n ldrh r2, [r0]\n ldr r3, [r0]\n ldrsb r4, [r0]\n ldrsh r5, [r0]", mem=BUF)
    g = t.state.get
    assert g("r1").bound == 0xFF
    assert g("r2").bound == 0xFFFF
    assert g("r3").bound is None
    assert g("r4").tainted and g("r4").bound is None
    assert g("r5").tainted and g("r5").bound is None
    assert kinds(t) == []


def test_clean_pointer_tainted_bytes():
    t = run("ldr r1, [r0, #8]\n ldr r2, [r0, #100]", mem=BUF)
    assert t.state.get("r1").tainted
    assert not t.state.get("r2").tainted


def test_index_bound_suppresses_finding():
    src = "ldrb r1, [r0]\n ldr r2, [r3, r1, lsl #2]"
    assert kinds(run(src, mem=BUF)) == []
    t = run(src, mem=BUF, policy=Policy(report_bounded=True))
    assert kinds(t) == ["bounded-tainted-load-address"]
    assert "<= 0x3fc" in t.findings[0].detail


def test_unbounded_index_reported():
    assert kinds(run("ldr r1, [r0]\n ldr r2, [r3, r1, lsl #2]", mem=BUF)) == ["tainted-load-address"]
    assert kinds(run("ldr r1, [r0]\n str r2, [r3, r1, lsl #2]", mem=BUF)) == ["tainted-store-address"]


def test_and_bic_ubfx_uxt_lsl_bounds():
    t = run(
        "ldr r1, [r0]\n"
        "and r2, r1, #0xff\n"
        "bic r3, r2, #0x0f\n"
        "ubfx r4, r1, #3, #5\n"
        "uxth r5, r1\n"
        "lsl r6, r5, #2\n"
        "and r7, r1, #0xff000000\n"
        "uxtab r8, r9, r1",
        mem=BUF,
    )
    g = t.state.get
    assert g("r2").bound == 0xFF
    assert g("r3").bound == 0xFF
    assert g("r4").bound == 0x1F
    assert g("r5").bound == 0xFFFF
    assert g("r6").bound == 0x3FFFC
    assert g("r7").tainted and g("r7").bound is None
    assert g("r8").bound == 0xFF


def test_bound_dropping():
    t = run(
        "ldrb r1, [r0]\n"
        "mvn r2, r1\n"
        "mul r3, r1, r1\n"
        "sxtb r4, r1\n"
        "lsl r5, r1, r1\n"
        "rsb r6, r1, #0\n"
        "add r7, r1, r9",
        mem=BUF,
        taints=(("r9", "u"),),
    )
    for r in ("r2", "r3", "r4", "r5", "r6", "r7"):
        assert t.state.get(r).tainted and t.state.get(r).bound is None, r


def test_add_sums_bounds_and_shifted_operand():
    t = run(
        "ldrb r1, [r0]\n"
        "ldrb r2, [r0, #1]\n"
        "add r3, r1, r2, lsl #8\n"
        "add r4, r1, r2, lsl r5",
        mem=BUF,
    )
    assert t.state.get("r3").bound == 0xFF + (0xFF << 8)
    assert t.state.get("r4").bound is None


# --- zero idioms / constants -------------------------------------------------------

def test_mov_imm_clears_and_records_constant():
    t = run("mov r1, #0\n movw r2, #0x1234\n movt r2, #0x5678", taints=(("r1", "u"), ("r2", "u")))
    assert not t.state.get("r1").tainted
    assert not t.state.get("r2").tainted
    assert t.state.consts["r2"] == 0x56781234


def test_eor_same_register_stays_tainted():
    # ARM eor r,r,r is not a zero idiom (unlike x86 xor eax,eax)
    t = run("eor r1, r1, r1", taints=(("r1", "u"),))
    assert t.state.get("r1").tainted


# --- stack, frame, spills -----------------------------------------------------------

def test_push_pop_roundtrip_and_layout():
    t = run("push {r4, lr}\n ldr r5, [sp]\n ldr r6, [sp, #4]\n pop {r4, lr}", taints=(("r4", "u"),))
    assert t.state.get("r5").tainted
    assert not t.state.get("r6").tainted
    assert t.state.get("r4").tainted


def test_pointer_fact_survives_spill_reload_via_r11_frame():
    t = run(
        "push {r11, lr}\n"
        "mov r11, sp\n"
        "sub sp, sp, #8\n"
        "str r0, [sp, #4]\n"
        "ldr r1, [sp, #4]\n"
        "ldrb r2, [r1]",
        mem=BUF,
    )
    assert t.state.get("r2").labels == {"buf"}
    assert t.state.get("r2").bound == 0xFF


def test_pointer_fact_survives_thumb_r7_frame():
    t = run(
        "push {r7, lr}\n"
        "sub sp, #8\n"
        "add r7, sp, #0\n"
        "str r0, [r7, #4]\n"
        "ldr r0, [r7, #4]\n"
        "ldr r1, [r0]\n"
        "ldr r2, [r3, r1, lsl #2]",
        Mode.THUMB,
        mem=BUF,
    )
    assert kinds(t) == ["tainted-load-address"]


def test_thumb_epilogue_restores_frame():
    t = run(
        "push {r7, lr}\n"
        "sub sp, #16\n"
        "add r7, sp, #0\n"
        "ldr r1, [r0]\n"
        "str r1, [r7, #20]\n"
        "add sp, r7, #16\n"
        "pop {r7, pc}",
        Mode.THUMB,
        mem=BUF,
    )
    assert kinds(t) == ["tainted-overwrite-of-saved-ra", "tainted-return-address"]


def test_stm_ldm_through_derived_pointer():
    t = run(
        "sub sp, sp, #16\n"
        "mov r4, sp\n"
        "ldrb r1, [r0]\n"
        "stmia r4, {r1, r2}\n"
        "ldmia r4, {r5, r6}",
        mem=BUF,
    )
    assert t.state.get("r5").bound == 0xFF
    assert not t.state.get("r6").tainted


def test_ldm_writeback_and_db_layout():
    t = run(
        "sub sp, sp, #16\n"
        "mov r4, sp\n"
        "ldrb r1, [r0]\n"
        "stmdb r4!, {r1, r2}\n"
        "ldmia r4!, {r5, r6}",
        mem=BUF,
    )
    assert t.state.get("r5").tainted
    assert not t.state.get("r6").tainted


def test_post_indexed_walk_keeps_region():
    t = run(
        "mov r1, r0\n"
        "ldrb r2, [r1], #1\n"
        "ldrb r3, [r1], #1\n"
        "ldrb r4, [r1, #100]",
        mem=BUF,
    )
    assert t.state.get("r2").tainted
    assert t.state.get("r3").tainted
    assert not t.state.get("r4").tainted


def test_taint_pointee_fifth_argument_on_stack():
    t = run(
        "ldr r4, [sp]\n"
        "ldr r5, [r4]\n"
        "str r6, [r7, r5, lsl #2]",
        ptee=("sp", 0, "buf", 64),
    )
    assert kinds(t) == ["tainted-store-address"]


# --- control flow ----------------------------------------------------------------

def test_indirect_call_and_jump():
    assert kinds(run("ldr r1, [r0]\n blx r1", mem=BUF)) == ["tainted-indirect-call"]
    assert kinds(run("ldr r1, [r0]\n bx r1", mem=BUF)) == ["tainted-indirect-jump"]
    assert kinds(run("ldr r1, [r0]\n mov pc, r1", mem=BUF)) == ["tainted-indirect-jump"]
    assert kinds(run("ldr r2, [r0]\n ldr pc, [r1, r2, lsl #2]", mem=BUF)) == ["tainted-load-address", "tainted-indirect-jump"]


def test_return_address_corruption():
    assert kinds(run("push {r4, lr}\n ldr r4, [r0]\n str r4, [sp, #4]\n pop {r4, pc}", mem=BUF)) == ["tainted-overwrite-of-saved-ra", "tainted-return-address"]
    assert kinds(run("ldr lr, [r0]\n bx lr", mem=BUF)) == ["tainted-return-address"]
    assert kinds(run("push {lr}\n ldr r1, [r0]\n str r1, [sp]\n ldr pc, [sp], #4", mem=BUF)) == ["tainted-overwrite-of-saved-ra", "tainted-return-address"]


def test_clean_return_is_silent():
    assert kinds(run("push {r4, lr}\n ldr r4, [r0]\n pop {r4, pc}", mem=BUF)) == []


def test_table_branch():
    t = run(
        "ldrb r1, [r0]\n"
        "tbb [pc, r1]\n"
        "ldr r2, [r0]\n"
        "tbh [pc, r2, lsl #1]",
        Mode.THUMB,
        mem=BUF,
        policy=Policy(report_bounded=True),
    )
    assert kinds(t) == ["bounded-tainted-indirect-jump", "tainted-indirect-jump"]


def test_conditional_execution_is_path_insensitive():
    t = run("cmp r1, #0\n it eq\n moveq r2, r0\n mov r3, r2", Mode.THUMB, taints=(("r0", "u"), ("r2", "v")))
    assert t.state.get("r2").labels == {"u", "v"}
    assert t.state.get("r3").labels == {"u", "v"}

    t = run("cmp r1, #0\n addeq r2, r2, r0", taints=(("r0", "u"),))
    assert t.state.get("r2").labels == {"u"}

    t = run("cmp r1, #0\n it ne\n strne r0, [sp]\n ldr r2, [sp]", Mode.THUMB, taints=(("r0", "u"),))
    assert t.state.get("r2").labels == {"u"}


def test_tainted_branch_condition_opt_in():
    src = "ldr r1, [r0]\n cmp r1, #4\n bhi 0x100\n cbz r1, 0x100"
    assert kinds(run(src, Mode.THUMB, mem=BUF)) == []
    assert kinds(run(src, Mode.THUMB, mem=BUF, policy=Policy(report_tainted_branch=True))) == ["tainted-branch-condition"] * 2


# --- calls / ABI -----------------------------------------------------------------

def test_bl_clobbers_caller_saved_and_propagates_args():
    t = run("ldr r4, [r0]\n mov r1, r4\n mov r12, r4\n mov r5, lr\n bl 0x1000", mem=BUF)
    g = t.state.get
    assert g("r0").tainted and g("r1").tainted
    assert g("r4").tainted and not g("r12").tainted
    assert t.state.consts["lr"] == 0x10014
    assert not g("r2").tainted


def test_calls_propagate_stack_args():
    t = run("ldr r4, [r0]\n str r4, [sp]\n bl 0x1000", mem=BUF)
    assert t.state.get("r0").tainted


def test_soft_float_abi_has_no_fp_args():
    t = TaintTracker(Mode.ARM, Abi.AAPCS)
    t.taint_register("s0", "f")
    t.run(list(from_listing("bl 0x1000")))
    assert not t.state.get("r0").tainted


# --- syscalls --------------------------------------------------------------------

def test_eabi_read_taints_buffer_and_return():
    t = run(
        "sub sp, sp, #64\n"
        "mov r0, #0\n"
        "mov r1, sp\n"
        "mov r2, #64\n"
        "mov r7, #3\n"
        "svc #0\n"
        "ldrb r3, [sp, #5]\n"
        "ldrb r4, [sp, #64]\n"
        "ldr r5, [r6, r3, lsl #2]",
        policy=Policy(report_bounded=True),
    )
    g = t.state.get
    assert g("r0").tainted
    assert g("r3").bound == 0xFF
    assert not g("r4").tainted
    assert kinds(t) == ["bounded-tainted-load-address"]


def test_read_into_heap_pointer_via_copied_register():
    t = run(
        "mov r1, r4\n"
        "mov r2, #16\n"
        "mov r7, #3\n"
        "svc #0\n"
        "ldrb r3, [r4, #2]\n"
        "ldrb r5, [r4, #16]",
    )
    assert t.state.get("r3").tainted
    assert not t.state.get("r5").tainted


def test_oabi_swi_number_in_instruction():
    t = run("mov r1, sp\n mov r2, #8\n swi #0x900003\n ldr r3, [sp]")
    assert t.state.get("r3").tainted


def test_tainted_syscall_number_and_args():
    t = run("ldr r7, [r0]\n ldr r1, [r0]\n svc #0", mem=BUF)
    assert "tainted-syscall-number" in kinds(t)
    assert "tainted-syscall-arg" in kinds(t)


def test_syscall_number_from_literal_pool():
    i = make_insn(0x10000, "ldr", "r7, [pc, #8]", Mode.ARM, 4)
    i.literal = 3
    t = TaintTracker(Mode.ARM)
    t.run([i] + list(from_listing("mov r1, sp\n mov r2, #8\n svc #0\n ldr r3, [sp]", base=0x10004)))
    assert t.state.get("r3").tainted


# --- VFP -------------------------------------------------------------------------

def test_vfp_lane_aliasing_and_moves():
    t = run("vmov s1, r1\n vmov r2, s1\n vmov r3, s0", taints=(("r1", "u"),))
    assert t.state.get("r2").tainted
    assert t.state.get("r3").tainted  # s0 and s1 share d0/q0

    t = run("vldr d0, [r0]\n vmov r1, r2, d0", mem=BUF)
    assert t.state.get("r1").tainted
    assert t.state.get("r2").tainted


def test_vpush_vpop_roundtrip():
    t = run(
        "vmov s16, r1\n"
        "vpush {d8-d9}\n"
        "vmov s16, r2\n"
        "vpop {d8-d9}\n"
        "vmov r3, s16",
        taints=(("r1", "u"),),
    )
    assert t.state.get("r3").labels == {"u"}


# --- lattice ops -----------------------------------------------------------------

def test_taintstate_copy_is_independent():
    t = TaintTracker(Mode.ARM)
    t.taint_register("r0", "x")
    orig = t.state.copy()
    t.taint_register("r1", "y")
    assert not orig.regs.get("r1")


def test_taintstate_join_unions_labels():
    a = TaintState(Mode.ARM)
    b = TaintState(Mode.ARM)
    a.taint_reg("r0", "x")
    b.taint_reg("r0", "y")
    j = a.join(b)
    assert j.regs["r0"].labels == {"x", "y"}


def test_taintstate_join_unions_ra_regs():
    a = TaintState(Mode.ARM)
    b = TaintState(Mode.ARM)
    a.ra_regs.add("lr")
    j = a.join(b)
    assert "lr" in j.ra_regs


def test_taintstate_join_unions_ra_slots():
    a = TaintState(Mode.ARM)
    b = TaintState(Mode.ARM)
    a.ra_slots.add(("sp", 0))
    b.ra_slots.add(("sp", 4))
    j = a.join(b)
    assert ("sp", 0) in j.ra_slots
    assert ("sp", 4) in j.ra_slots


def test_taintstate_same_as_detects_reg_diff():
    a = TaintState(Mode.ARM)
    b = TaintState(Mode.ARM)
    a.taint_reg("r0", "x")
    assert not a.same_as(b)


def test_taintstate_same_as_detects_ra_regs_diff():
    a = TaintState(Mode.ARM)
    b = TaintState(Mode.ARM)
    a.ra_regs.add("lr")
    assert not a.same_as(b)


def test_taintstate_same_as_equal_states():
    a = TaintState(Mode.ARM)
    b = TaintState(Mode.ARM)
    a.taint_reg("r1", "t")
    b.taint_reg("r1", "t")
    a.ra_regs.add("lr")
    b.ra_regs.add("lr")
    assert a.same_as(b)


# --- multi-label propagation -----------------------------------------------------

def test_two_labels_merged_in_add():
    t = run("add r2, r0, r1", taints=(("r0", "a"), ("r1", "b")))
    assert t.state.get("r2").labels == {"a", "b"}


def test_labels_propagate_through_mem():
    # store tainted value to stack, load it back; sp is always a tracked region
    t = run("str r0, [sp]\n ldr r2, [sp]", taints=(("r0", "a"),))
    assert t.state.get("r2").labels == {"a"}


def test_clean_clear_removes_taint():
    t = run("mov r0, #0", taints=(("r0", "u"),))
    assert not t.state.get("r0").tainted


def test_thumb_mode_basic_propagation():
    t = run("add r1, r0, #1\n lsl r2, r1, #2", Mode.THUMB, taints=(("r0", "u"),))
    assert t.state.get("r1").tainted
    assert t.state.get("r2").tainted


def test_entry_is_not_function_start_no_ra_reg():
    # With entry_is_function_start=False, lr is not tracked as RA;
    # a tainted indirect branch via r3 (not lr) is still "indirect-jump"
    t = TaintTracker(Mode.ARM, policy=Policy(entry_is_function_start=False))
    t.taint_register("r0", "u")
    t.run(list(from_listing("mov r3, r0\n bx r3")))
    assert kinds(t) == ["tainted-indirect-jump"]


def test_tainted_store_addr_not_reported_for_clean_addr():
    t = run("mov r1, #0\n str r0, [r1]", taints=(("r0", "u"),))
    assert "tainted-store-address" not in kinds(t)
