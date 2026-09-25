"""MIPS32 / MIPS64 labeled-taint tracker tests (UAL listings at base 0x10000)."""
import pytest

from ablation.analyzers.insn_mips import from_listing
from ablation.analyzers.isa_mips import Abi, Mode
from ablation.analyzers.taint_tracker_mips_labeled import Policy, TaintState, TaintTracker


def run(src, mode=Mode.MIPS32, taints=(), mem=None, ptee=None, policy=None):
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


def g(t, r):
    return t.state.get(t._canon(r))


BUF = ("$a0", 0, "buf", 64)


# --- delay slots ------------------------------------------------------------------

def test_argument_set_in_jalr_delay_slot_reaches_callee():
    t = run("lw $t0, 0($a0)\n jalr $t9\n move $a0, $t0\n nop", mem=BUF)
    assert g(t, "$v0").tainted
    assert not g(t, "$a0").tainted  # a0 clobbered after call


def test_without_slot_arg_not_seen():
    t = run("jalr $t9\n nop\n lw $a0, 0($a0)", mem=BUF)
    assert not g(t, "$v0").tainted


def test_jr_ra_with_sp_restore_in_slot():
    assert kinds(run(
        "addiu $sp, $sp, -32\n sw $ra, 28($sp)\n lw $ra, 28($sp)\n jr $ra\n addiu $sp, $sp, 32",
        mem=BUF,
    )) == []


def test_branch_likely_slot_is_joined():
    t = run("beql $t1, $t2, 0x100\n move $t3, $t0", taints=(("$t0", "u"), ("$t3", "v")))
    assert g(t, "$t3").labels == {"u", "v"}
    t = run("beq $t1, $t2, 0x100\n move $t3, $t0", taints=(("$t0", "u"), ("$t3", "v")))
    assert g(t, "$t3").labels == {"u"}  # ordinary slot always executes


def test_pending_transfer_flushed_at_end_of_stream():
    t = run("lw $t9, 0($a0)\n jr $t9", mem=BUF)
    assert kinds(t) == ["tainted-indirect-jump"]


def test_compact_branch_has_no_slot():
    t = run("balc 0x100\n lw $a0, 0($a0)", mem=BUF)
    assert not g(t, "$v0").tainted


# --- returns / indirect transfers -------------------------------------------------

def test_return_address_corruption():
    src = (
        "addiu $sp, $sp, -32\n"
        "sw $ra, 28($sp)\n"
        "lw $t0, 0($a0)\n"
        "sw $t0, 28($sp)\n"
        "lw $ra, 28($sp)\n"
        "jr $ra\n"
        "addiu $sp, $sp, 32"
    )
    assert kinds(run(src, mem=BUF)) == ["tainted-overwrite-of-saved-ra", "tainted-return-address"]


def test_clean_prologue_epilogue_is_silent():
    src = (
        "addiu $sp, $sp, -32\n"
        "sw $ra, 28($sp)\n"
        "sw $fp, 24($sp)\n"
        "move $fp, $sp\n"
        "lw $t0, 0($a0)\n"
        "move $sp, $fp\n"
        "lw $ra, 28($sp)\n"
        "lw $fp, 24($sp)\n"
        "jr $ra\n"
        "addiu $sp, $sp, 32"
    )
    assert kinds(run(src, mem=BUF)) == []


def test_indirect_call_and_jump():
    assert kinds(run("lw $t9, 0($a0)\n jalr $t9\n nop", mem=BUF)) == ["tainted-indirect-call"]
    assert kinds(run("lw $t9, 0($a0)\n jr $t9\n nop", mem=BUF)) == ["tainted-indirect-jump"]
    assert kinds(run("lw $t9, -32752($gp)\n jalr $t9\n nop", mem=BUF)) == []  # PIC/GOT: clean


def test_o32_pic_call_propagates_args():
    t = run("lw $t9, -32752($gp)\n lw $a0, 0($a0)\n jalr $t9\n nop", mem=BUF)
    assert g(t, "$v0").tainted
    assert not g(t, "$t9").tainted


# --- loads, bounds, MIPS64 narrowing ---------------------------------------------

def test_load_widths():
    t = run("lbu $t0, 0($a0)\n lhu $t1, 0($a0)\n lw $t2, 0($a0)\n lb $t3, 0($a0)\n lh $t4, 0($a0)", mem=BUF)
    assert g(t, "$t0").bound == 0xFF
    assert g(t, "$t1").bound == 0xFFFF
    assert g(t, "$t2").bound is None
    assert g(t, "$t3").tainted and g(t, "$t3").bound is None
    assert g(t, "$t4").tainted and g(t, "$t4").bound is None
    assert kinds(t) == []


def test_mips64_addu_zero_is_not_a_copy_of_pointer():
    t = run(
        "addu $t1, $a0, $zero\n"
        "daddu $t2, $a0, $zero\n"
        "or $t3, $a0, $zero\n"
        "ld $a4, 8($t1)\n"
        "ld $a5, 8($t2)\n"
        "ld $a6, 8($t3)",
        Mode.MIPS64, mem=BUF,
    )
    assert not g(t, "$a4").tainted  # addu sign-extends: not a pointer copy
    assert g(t, "$a5").tainted      # daddu is a full copy
    assert g(t, "$a6").tainted      # or is a full copy


def test_mips64_narrowing_keeps_small_bounds_only():
    t = run(
        "lbu $t0, 0($a0)\n"
        "addu $t1, $t0, $t0\n"
        "lwu $t2, 0($a0)\n"
        "addu $t3, $t2, $zero\n"
        "lw $a4, 0($a0)\n"
        "sll $a5, $t0, 2",
        Mode.MIPS64, mem=BUF,
    )
    assert g(t, "$t1").bound == 0x1FE       # < 2**31: survives
    assert g(t, "$t2").bound == 0xFFFFFFFF  # lwu: zero-extended
    assert g(t, "$t3").bound is None        # addu of bit-31-set value
    assert g(t, "$a4").bound is None        # lw sign-extends
    assert g(t, "$a5").bound == 0xFF << 2


def test_mips32_lw_is_identity():
    t = run("lbu $t0, 0($a0)\n sw $t0, 0($sp)\n lw $t1, 0($sp)", mem=BUF)
    assert g(t, "$t1").bound == 0xFF


def test_bounds():
    t = run(
        "lw $t0, 0($a0)\n"
        "andi $t1, $t0, 0xff\n"
        "ext $t2, $t0, 4, 5\n"
        "sll $t3, $t1, 2\n"
        "srl $t4, $t0, 24\n"
        "sltiu $t5, $t0, 10\n"
        "negu $t6, $t1\n"
        "seb $t7, $t1\n"
        "sra $s0, $t0, 24\n"
        "ori $s1, $t1, 0x100",
        mem=BUF,
    )
    assert g(t, "$t1").bound == 0xFF
    assert g(t, "$t2").bound == 0x1F
    assert g(t, "$t3").bound == 0x3FC
    assert g(t, "$t4").bound == 0xFF   # srl of unbounded word: (32-24) bits
    assert g(t, "$t5").bound == 1
    assert g(t, "$t6").bound is None and g(t, "$t7").bound is None
    assert g(t, "$s0").bound is None
    assert g(t, "$s1").bound == 0x1FF


def test_index_bound_downgrades_finding():
    src = "lbu $t0, 0($a0)\n sll $t0, $t0, 2\n addu $t1, $t2, $t0\n lw $t3, 0($t1)"
    assert kinds(run(src, mem=BUF)) == []
    t = run(src, mem=BUF, policy=Policy(report_bounded=True))
    assert kinds(t) == ["bounded-tainted-load-address"]
    assert "<= 0x3fc" in t.findings[0].detail
    assert kinds(run("lw $t0, 0($a0)\n sll $t0, $t0, 2\n addu $t1, $t2, $t0\n sw $zero, 0($t1)", mem=BUF)) == ["tainted-store-address"]


# --- constants, stack, spills ----------------------------------------------------

def test_lui_ori_constant_and_li():
    t = run("lui $v0, 0x1234\n ori $v0, $v0, 0x5678\n li $t0, 4003\n li $t1, 0x12345")
    assert t.state.consts["$2"] == 0x12345678
    assert t.state.consts["$8"] == 4003
    assert t.state.consts["$9"] == 0x12345


def test_frame_pointer_spill_reload():
    t = run(
        "addiu $sp, $sp, -32\n"
        "sw $fp, 24($sp)\n"
        "move $fp, $sp\n"
        "sw $a0, 20($fp)\n"
        "lw $t0, 20($fp)\n"
        "lbu $t1, 0($t0)",
        mem=BUF,
    )
    assert g(t, "$t1").labels == {"buf"}
    assert g(t, "$t1").bound == 0xFF


def test_sp_restored_through_fp_rebases_frame():
    t = run(
        "addiu $sp, $sp, -32\n"
        "sw $ra, 28($sp)\n"
        "move $fp, $sp\n"
        "addiu $sp, $sp, -16\n"
        "move $sp, $fp\n"
        "lw $ra, 28($sp)\n"
        "jr $ra\n"
        "addiu $sp, $sp, 32",
    )
    assert kinds(t) == []
    assert "$31" in t.state.ra_regs


def test_mips64_frame_uses_sd_ld():
    t = run(
        "daddiu $sp, $sp, -32\n"
        "sd $ra, 24($sp)\n"
        "sd $a0, 16($sp)\n"
        "ld $t0, 16($sp)\n"
        "ld $t1, 0($t0)\n"
        "ld $ra, 24($sp)\n"
        "jr $ra\n"
        "daddiu $sp, $sp, 32",
        Mode.MIPS64, mem=BUF,
    )
    assert g(t, "$t1").tainted
    assert kinds(t) == []


def test_o32_fifth_argument_on_stack():
    t = run(
        "lw $t0, 16($sp)\n"
        "lw $t1, 0($t0)\n"
        "sll $t1, $t1, 2\n"
        "addu $t2, $t3, $t1\n"
        "sw $zero, 0($t2)",
        ptee=("$sp", 16, "buf", 64),
    )
    assert kinds(t) == ["tainted-store-address"]


def test_call_reads_o32_stack_args():
    t = run("lw $t0, 0($a0)\n sw $t0, 16($sp)\n jal 0x1000\n nop", mem=BUF)
    assert g(t, "$v0").tainted


def test_call_clobbers_and_preserves():
    t = run("lw $s0, 0($a0)\n move $t0, $s0\n move $a1, $s0\n jal 0x1000\n nop", mem=BUF)
    assert g(t, "$s0").tainted
    assert not g(t, "$t0").tainted
    assert g(t, "$v0").tainted
    assert t.state.consts["$31"] == 0x10014  # return address: after the delay slot


# --- syscalls ---------------------------------------------------------------------

def test_o32_read_syscall():
    t = run(
        "addiu $sp, $sp, -64\n"
        "li $v0, 4003\n"
        "move $a0, $zero\n"
        "move $a1, $sp\n"
        "li $a2, 64\n"
        "syscall\n"
        "lbu $t0, 5($sp)\n"
        "lbu $t1, 64($sp)",
    )
    assert g(t, "$v0").tainted
    assert g(t, "$t0").bound == 0xFF
    assert not g(t, "$t1").tainted
    assert not g(t, "$a3").tainted


def test_n64_read_syscall_number():
    t = run(
        "daddiu $sp, $sp, -64\n"
        "li $v0, 5000\n"
        "move $a0, $zero\n"
        "move $a1, $sp\n"
        "li $a2, 64\n"
        "syscall\n"
        "lbu $t0, 5($sp)",
        Mode.MIPS64,
    )
    assert g(t, "$t0").tainted
    t2 = run(
        "daddiu $sp, $sp, -64\n"
        "li $v0, 4003\n"
        "move $a1, $sp\n"
        "li $a2, 64\n"
        "syscall\n"
        "lbu $t0, 5($sp)",
        Mode.MIPS64,
    )
    assert not g(t2, "$t0").tainted  # o32 number is meaningless on n64


def test_read_into_copied_heap_pointer():
    t = run(
        "move $a1, $s0\n"
        "li $a2, 16\n"
        "li $v0, 4003\n"
        "syscall\n"
        "lbu $t0, 1($s0)\n"
        "lbu $t1, 16($s0)",
    )
    assert g(t, "$t0").tainted
    assert not g(t, "$t1").tainted


def test_tainted_syscall_number_and_arg():
    t = run("lw $v0, 0($a0)\n lw $a1, 0($a0)\n syscall", mem=BUF)
    assert "tainted-syscall-number" in kinds(t)
    assert "tainted-syscall-arg" in kinds(t)


# --- misc data flow ---------------------------------------------------------------

def test_hilo_and_cmov():
    t = run(
        "lw $t0, 0($a0)\n"
        "mult $t0, $t1\n"
        "mflo $t2\n"
        "mfhi $t3\n"
        "movz $t4, $t0, $t5",
        mem=BUF, taints=(("$t4", "v"),),
    )
    assert g(t, "$t2").tainted
    assert g(t, "$t3").tainted
    assert g(t, "$t4").labels == {"buf", "v"}


def test_tainted_branch_opt_in():
    src = "lw $t0, 0($a0)\n beq $t0, $zero, 0x100\n nop\n bnez $t0, 0x100\n nop"
    assert kinds(run(src, mem=BUF)) == []
    assert kinds(run(src, mem=BUF, policy=Policy(report_tainted_branch=True))) == ["tainted-branch-condition"] * 2


def test_fp_round_trip():
    t = run(
        "lw $t0, 0($a0)\n"
        "mtc1 $t0, $f0\n"
        "cvt.d.w $f2, $f0\n"
        "mfc1 $t1, $f2\n"
        "swc1 $f0, 0($sp)\n"
        "lw $t2, 0($sp)",
        mem=BUF,
    )
    assert g(t, "$t1").tainted
    assert g(t, "$t2").tainted


# --- lattice ops ------------------------------------------------------------------

def test_taintstate_copy_is_independent():
    t = TaintTracker(Mode.MIPS32)
    t.taint_register("$a0", "x")
    orig = t.state.copy()
    t.taint_register("$a1", "y")
    assert not orig.regs.get("$5")


def test_taintstate_join_unions_labels():
    a = TaintState(Mode.MIPS32)
    b = TaintState(Mode.MIPS32)
    a.taint_reg("$4", "x")
    b.taint_reg("$4", "y")
    j = a.join(b)
    assert j.regs["$4"].labels == {"x", "y"}


def test_taintstate_join_unions_ra_regs():
    a = TaintState(Mode.MIPS32)
    b = TaintState(Mode.MIPS32)
    a.ra_regs.add("$31")
    j = a.join(b)
    assert "$31" in j.ra_regs


def test_taintstate_join_unions_ra_slots():
    a = TaintState(Mode.MIPS32)
    b = TaintState(Mode.MIPS32)
    a.ra_slots.add(("$29", 28))
    b.ra_slots.add(("$29", 24))
    j = a.join(b)
    assert ("$29", 28) in j.ra_slots
    assert ("$29", 24) in j.ra_slots


def test_taintstate_same_as_detects_reg_diff():
    a = TaintState(Mode.MIPS32)
    b = TaintState(Mode.MIPS32)
    a.taint_reg("$4", "x")
    assert not a.same_as(b)


def test_taintstate_same_as_equal_states():
    a = TaintState(Mode.MIPS32)
    b = TaintState(Mode.MIPS32)
    a.taint_reg("$4", "t")
    b.taint_reg("$4", "t")
    a.ra_regs.add("$31")
    b.ra_regs.add("$31")
    assert a.same_as(b)


# --- multi-label propagation ------------------------------------------------------

def test_two_labels_merged_in_add():
    t = run("addu $t2, $a0, $a1", taints=(("$a0", "a"), ("$a1", "b")))
    assert g(t, "$t2").labels == {"a", "b"}


def test_clean_clear_removes_taint():
    t = run("move $a0, $zero", taints=(("$a0", "u"),))
    assert not g(t, "$a0").tainted


def test_n64_mode_basic_propagation():
    t = run("daddu $t1, $a0, $zero\n dsll $t2, $t1, 3", Mode.MIPS64, taints=(("$a0", "u"),))
    assert g(t, "$t1").tainted
    assert g(t, "$t2").tainted


def test_entry_is_not_function_start():
    t = TaintTracker(Mode.MIPS32, policy=Policy(entry_is_function_start=False))
    t.taint_register("$t9", "u")
    t.run(list(from_listing("jr $t9\n nop")))
    assert kinds(t) == ["tainted-indirect-jump"]  # $t9 not in ra_regs
