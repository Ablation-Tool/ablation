"""Tests for the x86/x86-64 labeled-taint tracker."""
import pytest

from ablation.analyzers.taint_tracker_x86_labeled import (
    CLEAN, Finding, Policy, Taint, TaintState, TaintTracker,
)
from ablation.analyzers.insn_x86 import from_listing
from ablation.analyzers.isa_x86 import Abi, Mode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(listing, mode=Mode.X64, taints=(("rdi", "user"),), policy=None, mem=()):
    t = TaintTracker(mode, policy=policy)
    for r, l in taints:
        t.taint_register(r, l)
    for b, off, l in mem:
        t.taint_memory(b, off, l)
    t.run(list(from_listing(listing)))
    return t


def run32(listing, taints=(("eax", "user"),), policy=None):
    return run(listing, mode=Mode.X86, taints=taints, policy=policy)


def kinds(t):
    return [f.kind for f in t.findings]


# ---------------------------------------------------------------------------
# Copies
# ---------------------------------------------------------------------------

def test_mov_reg_reg_propagates():
    t = run("mov rax, rdi")
    assert t.state.get("rax").labels == {"user"}


def test_mov_reg_reg_32_zext():
    t = run("mov edi, edi", taints=(("rdi", "user"),))
    assert t.state.get("rdi").labels == {"user"}


def test_movzx_bounds_byte():
    t = run("movzx eax, dil")
    assert t.state.get("rax").bound == 0xFF


def test_movzx_bounds_word():
    t = run("movzx eax, di")
    assert t.state.get("rax").bound == 0xFFFF


def test_movsx_drops_bound():
    t = run("movzx eax, dil\n movsxd rax, eax")
    assert t.state.get("rax").tainted
    assert t.state.get("rax").bound is None


def test_xchg_swaps():
    t = run("xchg rax, rdi", taints=(("rdi", "user"),))
    assert t.state.get("rax").labels == {"user"}
    assert not t.state.get("rdi").tainted


# ---------------------------------------------------------------------------
# Zero idioms
# ---------------------------------------------------------------------------

def test_xor_self_clears():
    t = run("mov rax, rdi\n xor eax, eax")
    assert not t.state.get("rax").tainted


def test_sub_self_clears():
    t = run("mov rax, rdi\n sub rax, rax")
    assert not t.state.get("rax").tainted


def test_xor_self_sets_const_zero():
    t = run("xor eax, eax", taints=())
    # In x64 mode, eax family is rax
    assert t.state.consts.get(t.state.fam("eax")) == 0


# ---------------------------------------------------------------------------
# Bounds (and / shl / shr / imul)
# ---------------------------------------------------------------------------

def test_and_positive_imm_bounds():
    t = run("and rdi, 0xff\n mov rax, rdi")
    assert t.state.get("rax").bound == 0xFF


def test_and_alignment_mask_no_bound():
    t = run("and rsp, -16", taints=(("rsp", "u"),))
    assert t.state.get("rsp").bound is None


def test_shl_scales_bound():
    t = run("and rdi, 0xff\n shl rdi, 3")
    assert t.state.get("rdi").bound == 0xFF << 3


def test_shr_shrinks_bound():
    t = run("and rdi, 0xff\n shr rdi, 2")
    assert t.state.get("rdi").bound == 0xFF >> 2


def test_imul_imm_scales_bound():
    t = run("and rdi, 0xff\n imul rax, rdi, 8")
    assert t.state.get("rax").bound == 0xFF * 8


def test_bounded_load_not_reported():
    t = run("and rdi, 0xff\n add rax, rdi\n mov rbx, [rax]",
            taints=(("rdi", "user"),))
    assert "tainted-load-address" not in kinds(t)


def test_unbounded_load_reported():
    t = run("add rax, rdi\n mov rbx, [rax]",
            taints=(("rdi", "user"),))
    assert "tainted-load-address" in kinds(t)


# ---------------------------------------------------------------------------
# LEA
# ---------------------------------------------------------------------------

def test_lea_tainted_base_propagates_bound():
    t = run("and rdi, 0xff\n lea rax, [rdi + 16]")
    # disp is constant; bound tracks attacker contribution only
    assert t.state.get("rax").bound == 0xFF


def test_lea_rip_relative_is_const():
    t = run("lea rax, [rip + 0x100]", taints=())
    assert t.state.consts.get("rax") is not None


# ---------------------------------------------------------------------------
# Stack frame tracking
# ---------------------------------------------------------------------------

def test_spill_reload():
    t = run("""
        sub   rsp, 32
        mov   [rsp+8], rdi
        sub   rsp, 16
        mov   rax, [rsp+24]
        add   rsp, 48
    """)
    assert t.state.get("rax").labels == {"user"}


def test_rbp_alias():
    t = run("""
        push  rbp
        mov   rbp, rsp
        sub   rsp, 32
        mov   [rbp-8], rdi
        mov   rax, [rbp-8]
    """)
    assert t.state.get("rax").labels == {"user"}


def test_leave_restores_rbp():
    t = run("""
        push  rbp
        mov   rbp, rsp
        sub   rsp, 32
        mov   [rbp-8], rdi
        leave
    """)


def test_saved_ra_overwrite_reported():
    # Entry RA is at (rsp, 0). sub rsp,16 rebases it to (rsp, 16). Write there fires.
    t = run("""
        sub   rsp, 16
        mov   [rsp+16], rdi
    """)
    assert "tainted-overwrite-of-saved-ra" in kinds(t)


# ---------------------------------------------------------------------------
# Push / pop
# ---------------------------------------------------------------------------

def test_push_pop_round_trip():
    t = run("push rdi\n pop rax")
    assert t.state.get("rax").labels == {"user"}


def test_push_imm_is_clean():
    t = run("push 42")
    sp = t.state.mode.sp
    assert not t.state.mem_get(sp, 0).tainted


# ---------------------------------------------------------------------------
# Call ABI
# ---------------------------------------------------------------------------

def test_call_clobbers_caller_saved():
    t = run("mov rcx, rdi\n mov r10, rdi\n call 0x20000")
    assert not t.state.get("rcx").tainted
    assert not t.state.get("r10").tainted


def test_call_preserves_callee_saved():
    t = run("mov rbx, rdi\n call 0x20000")
    assert t.state.get("rbx").labels == {"user"}


def test_call_tainted_arg_taints_return():
    t = run("call 0x20000")
    assert t.state.get("rax").tainted


def test_call_clean_args_clean_return():
    t = run("xor edi, edi\n call 0x20000")
    assert not t.state.get("rax").tainted


def test_indirect_call_reported():
    t = run("call rdi")
    assert "tainted-indirect-call" in kinds(t)


def test_indirect_jump_reported():
    t = run("jmp rdi")
    assert "tainted-indirect-jump" in kinds(t)


# ---------------------------------------------------------------------------
# Return address
# ---------------------------------------------------------------------------

def test_ret_tainted_ra_reported():
    # Write directly over the RA slot (rsp+0 at entry), then ret reads it back.
    t = run("""
        mov   [rsp], rdi
        ret
    """)
    assert "tainted-return-address" in kinds(t)


# ---------------------------------------------------------------------------
# Syscall
# ---------------------------------------------------------------------------

def test_syscall_read_taints_buffer():
    t = run("""
        xor   eax, eax
        xor   edi, edi
        sub   rsp, 64
        lea   rsi, [rsp+16]
        mov   edx, 32
        syscall
        mov   al, [rsp+16]
        mov   bl, [rsp+47]
        mov   cl, [rsp+48]
        mov   rdx, rax
    """, taints=())
    assert t.state.get("al").tainted
    assert t.state.get("bl").tainted
    assert not t.state.get("cl").tainted
    assert t.state.get("rdx").tainted


def test_tainted_syscall_arg_reported():
    t = run("mov eax, 1\n mov rdx, rdi\n syscall")
    assert "tainted-syscall-arg" in kinds(t)


def test_tainted_syscall_nr_reported():
    t = run("mov rax, rdi\n syscall")
    assert "tainted-syscall-number" in kinds(t)


# ---------------------------------------------------------------------------
# int 0x80 (i386 syscall in 64-bit mode)
# ---------------------------------------------------------------------------

def test_int80_uses_i386_table():
    # SYS_read = 3 in i386 table; eax=3 triggers the buffer taint
    t = run("""
        mov   eax, 3
        xor   ebx, ebx
        sub   rsp, 64
        lea   ecx, [rsp+16]
        mov   edx, 32
        int   0x80
        mov   al, [rsp+16]
    """, taints=())
    assert t.state.get("al").tainted


# ---------------------------------------------------------------------------
# String instructions
# ---------------------------------------------------------------------------

def test_rep_movsb_propagates():
    t = run("""
        sub   rsp, 64
        mov   [rsp+8], rdi
        lea   rsi, [rsp+8]
        lea   rdi, [rsp+32]
        mov   ecx, 16
        rep movsb
        mov   rax, [rsp+32]
    """, taints=(("rsi", "user"), ("rdi", "user")))


def test_rep_count_tainted_reported():
    t = run("rep movsb", taints=(("ecx", "user"),),
            policy=Policy(report_rep_count=True))
    assert "tainted-rep-count" in kinds(t)


# ---------------------------------------------------------------------------
# cmov / setcc
# ---------------------------------------------------------------------------

def test_cmovz_merges_both_paths():
    t = run("cmovz rax, rdi", taints=(("rdi", "user"),))
    assert t.state.get("rax").tainted


def test_setne_from_clean_flags():
    t = run("cmp rax, 0\n setne al", taints=())
    assert not t.state.get("rax").tainted


def test_setne_from_tainted_flags():
    t = run("cmp rdi, 0\n setne al")
    assert t.state.get("rax").tainted
    assert t.state.get("rax").bound == 1


# ---------------------------------------------------------------------------
# Widening (cbw / cwde / cdqe / cwd / cdq / cqo)
# ---------------------------------------------------------------------------

def test_cdqe_widens_eax():
    t = run("movzx eax, dil\n cdqe")
    assert t.state.get("rax").tainted


def test_cqo_taints_rdx():
    t = run("mov rax, rdi\n cqo")
    assert t.state.get("rdx").tainted


# ---------------------------------------------------------------------------
# mul / div implicit
# ---------------------------------------------------------------------------

def test_mul_taints_rdx_rax():
    t = run("mul rdi")
    assert t.state.get("rdx").tainted
    assert t.state.get("rax").tainted


def test_div_taints_quotient_remainder():
    t = run("mov rax, rdi\n div rcx", taints=(("rdi", "u"), ("rcx", "v")))
    assert t.state.get("rax").tainted
    assert t.state.get("rdx").tainted


# ---------------------------------------------------------------------------
# Branch condition reporting
# ---------------------------------------------------------------------------

def test_branch_reporting_opt_in():
    assert kinds(run("cmp rdi, 0\n je 0x1000c")) == []
    assert "tainted-branch-condition" in kinds(
        run("cmp rdi, 0\n je 0x1000c", policy=Policy(report_tainted_branch=True))
    )


# ---------------------------------------------------------------------------
# 32-bit mode (i386 cdecl)
# ---------------------------------------------------------------------------

def test_32bit_copy():
    t = run32("mov ecx, eax")
    assert t.state.get("ecx").labels == {"user"}


def test_32bit_stack_spill():
    t = run32("""
        sub   esp, 16
        mov   [esp+4], eax
        mov   ecx, [esp+4]
    """)
    assert t.state.get("ecx").labels == {"user"}


def test_32bit_syscall_read_taints_buffer():
    # SYS_read = 3 in i386 table
    t = run32("""
        mov   eax, 3
        xor   ebx, ebx
        sub   esp, 64
        lea   ecx, [esp+16]
        mov   edx, 32
        int   0x80
        mov   al, [esp+16]
    """, taints=())
    assert t.state.get("eax").tainted


# ---------------------------------------------------------------------------
# TaintState lattice
# ---------------------------------------------------------------------------

def test_join_unions_labels():
    a = TaintState(Mode.X64); a.taint_reg("rax", "x")
    b = TaintState(Mode.X64); b.taint_reg("rax", "y")
    j = a.join(b)
    assert j.get("rax").labels == {"x", "y"}


def test_join_two_bounds_takes_max():
    a = TaintState(Mode.X64); a.regs["rax"] = Taint(frozenset({"x"}), 0x0F)
    b = TaintState(Mode.X64); b.regs["rax"] = Taint(frozenset({"x"}), 0xFF)
    j = a.join(b)
    assert j.get("rax").bound == 0xFF


def test_join_widen_different_bounds_becomes_none():
    a = TaintState(Mode.X64); a.regs["rax"] = Taint(frozenset({"x"}), 0x0F)
    b = TaintState(Mode.X64); b.regs["rax"] = Taint(frozenset({"x"}), 0xFF)
    j = a.join(b, widen=True)
    assert j.get("rax").bound is None


def test_join_mem_union():
    a = TaintState(Mode.X64); a.mem[("rsp", 8)] = Taint(frozenset({"x"}), None)
    b = TaintState(Mode.X64); b.mem[("rsp", 16)] = Taint(frozenset({"y"}), None)
    j = a.join(b)
    assert j.mem_get("rsp", 8).tainted
    assert j.mem_get("rsp", 16).tainted


def test_join_consts_intersect():
    a = TaintState(Mode.X64); a.consts["rax"] = 5
    b = TaintState(Mode.X64); b.consts["rax"] = 7
    j = a.join(b)
    assert "rax" not in j.consts


def test_join_consts_equal_survive():
    a = TaintState(Mode.X64); a.consts["rax"] = 5
    b = TaintState(Mode.X64); b.consts["rax"] = 5
    j = a.join(b)
    assert j.consts.get("rax") == 5


def test_same_as_true_on_copy():
    a = TaintState(Mode.X64); a.taint_reg("rax", "x")
    b = a.copy()
    assert a.same_as(b)


def test_same_as_false_after_modify():
    a = TaintState(Mode.X64); a.taint_reg("rax", "x")
    b = a.copy(); b.taint_reg("rbx", "y")
    assert not a.same_as(b)


def test_copy_is_independent():
    a = TaintState(Mode.X64); a.taint_reg("rax", "x")
    b = a.copy()
    b.taint_reg("rcx", "z")
    assert not a.get("rcx").tainted


# ---------------------------------------------------------------------------
# Policy knobs
# ---------------------------------------------------------------------------

def test_bounded_index_safe_suppresses_load():
    p = Policy(bounded_index_is_safe=True)
    t = run("and rdi, 0xff\n add rax, rdi\n mov rbx, [rax]", policy=p)
    assert "tainted-load-address" not in kinds(t)


def test_bounded_index_unsafe_reports_load():
    p = Policy(bounded_index_is_safe=False)
    t = run("and rdi, 0xff\n add rax, rdi\n mov rbx, [rax]", policy=p)
    assert "tainted-load-address" in kinds(t)


def test_report_bounded_emits_bounded_kind():
    p = Policy(report_bounded=True)
    t = run("and rdi, 0xff\n add rax, rdi\n mov rbx, [rax]", policy=p)
    assert any("bounded-tainted-load-address" in f.kind for f in t.findings)


def test_unknown_mnemonic_conservative():
    t = run("frobnop rax, rdi")
    assert t.state.get("rax").tainted
    assert "frobnop" in t.unknown


# ---------------------------------------------------------------------------
# Win64 ABI
# ---------------------------------------------------------------------------

def test_win64_abi_arg_regs():
    t = TaintTracker(Mode.X64, abi=Abi.WIN64)
    t.taint_register("rcx", "win-user")
    insns = list(from_listing("call 0x20000"))
    t.run(insns)
    assert t.state.get("rax").tainted


def test_win64_preserves_rsi_rdi():
    t = TaintTracker(Mode.X64, abi=Abi.WIN64)
    t.taint_register("rsi", "s")
    t.taint_register("rdi", "s")
    t.run(list(from_listing("call 0x20000")))
    assert t.state.get("rsi").tainted
    assert t.state.get("rdi").tainted


# ---------------------------------------------------------------------------
# Taint through pointer
# ---------------------------------------------------------------------------

def test_taint_memory_slot_and_load():
    t = TaintTracker(Mode.X64)
    t.taint_memory("rsp", 8, "net")
    t.run(list(from_listing("mov rax, [rsp+8]")))
    assert t.state.get("rax").tainted


def test_taint_pointee_cdecl_model():
    t = TaintTracker(Mode.X86)
    t.taint_pointee("esp", 4, "net", length=32)
    insns = list(from_listing("""
        mov   ecx, [esp+4]
        mov   al, [ecx]
    """))
    t.run(insns)
    assert t.state.get("eax").tainted
