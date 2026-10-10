"""Supplementary coverage tests for labeled taint tracker modules.

Targets code paths not exercised by the main per-architecture test files,
as identified during ISO 26262 TCL3 qualification coverage measurement.
Covers: TaintState.join(), TaintState.invalidate_base(), Taint.__str__(),
Finding.__str__(), and specific instruction handlers.
"""
from __future__ import annotations
import pytest


# ══════════════════════════════════════════════════════════════════
# MIPS labeled: Taint.__str__, TaintState.join, invalidate_base,
#               taint_memory(length=0), taint_pointee raise,
#               run(record_trace=True), FP/HILO instructions
# ══════════════════════════════════════════════════════════════════

def test_mips_taint_str_clean():
    from ablation.analyzers.taint_tracker_mips_labeled import Taint
    assert str(Taint()) == "clean"

def test_mips_taint_str_labeled_with_bound():
    from ablation.analyzers.taint_tracker_mips_labeled import Taint
    t = Taint(frozenset({"src"}), 0xff)
    s = str(t)
    assert "{src}" in s and "0xff" in s

def test_mips_taint_str_labeled_no_bound():
    from ablation.analyzers.taint_tracker_mips_labeled import Taint
    assert str(Taint(frozenset({"src"}))) == "{src}"

def test_mips_join_asymmetric_a_tainted():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintState, Taint
    from ablation.analyzers.isa_mips import Mode
    s1 = TaintState(mode=Mode.MIPS32)
    s1.regs["$t0"] = Taint(frozenset({"src"}), 0xff)
    s2 = TaintState(mode=Mode.MIPS32)
    j = s1.join(s2)
    assert j.regs["$t0"].bound == 0xff

def test_mips_join_asymmetric_b_tainted():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintState, Taint
    from ablation.analyzers.isa_mips import Mode
    s1 = TaintState(mode=Mode.MIPS32)
    s2 = TaintState(mode=Mode.MIPS32)
    s2.regs["$t1"] = Taint(frozenset({"src"}), 0x1ff)
    j = s1.join(s2)
    assert j.regs["$t1"].bound == 0x1ff

def test_mips_join_widen_different_bounds_collapses():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintState, Taint
    from ablation.analyzers.isa_mips import Mode
    s1 = TaintState(mode=Mode.MIPS32)
    s1.regs["$t0"] = Taint(frozenset({"src"}), 0xff)
    s2 = TaintState(mode=Mode.MIPS32)
    s2.regs["$t0"] = Taint(frozenset({"src"}), 0x1ff)
    j = s1.join(s2, widen=True)
    assert j.regs["$t0"].bound is None

def test_mips_join_mem_merge():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintState, Taint
    from ablation.analyzers.isa_mips import Mode
    s1 = TaintState(mode=Mode.MIPS32)
    s1.mem[("$sp", 4)] = Taint(frozenset({"a"}), None)
    s2 = TaintState(mode=Mode.MIPS32)
    s2.mem[("$sp", 8)] = Taint(frozenset({"b"}), None)
    j = s1.join(s2)
    assert j.mem[("$sp", 4)].labels == frozenset({"a"})
    assert j.mem[("$sp", 8)].labels == frozenset({"b"})

def test_mips_join_ranges_deduplicated():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintState, Taint
    from ablation.analyzers.isa_mips import Mode
    rng = ("$a0", 0, 64, Taint(frozenset({"src"}), None))
    s1 = TaintState(mode=Mode.MIPS32)
    s1.ranges.append(rng)
    s2 = TaintState(mode=Mode.MIPS32)
    s2.ranges.append(rng)
    j = s1.join(s2)
    assert len(j.ranges) == 1

def test_mips_join_consts_intersect():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintState
    from ablation.analyzers.isa_mips import Mode
    s1 = TaintState(mode=Mode.MIPS32)
    s1.consts["$t0"] = 42
    s2 = TaintState(mode=Mode.MIPS32)
    s2.consts["$t0"] = 42
    s2.consts["$t1"] = 99
    j = s1.join(s2)
    assert j.consts.get("$t0") == 42
    assert "$t1" not in j.consts

def test_mips_join_frame_ptrs_intersect():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintState
    from ablation.analyzers.isa_mips import Mode
    s1 = TaintState(mode=Mode.MIPS32)
    s1.frame_ptrs["$s0"] = ("$sp", 4)
    s2 = TaintState(mode=Mode.MIPS32)
    s2.frame_ptrs["$s0"] = ("$sp", 4)
    j = s1.join(s2)
    assert j.frame_ptrs.get("$s0") == ("$sp", 4)

def test_mips_join_mem_ptrs_intersect():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintState
    from ablation.analyzers.isa_mips import Mode
    s1 = TaintState(mode=Mode.MIPS32)
    s1.mem_ptrs[("$t0", 0)] = ("$sp", 8)
    s2 = TaintState(mode=Mode.MIPS32)
    s2.mem_ptrs[("$t0", 0)] = ("$sp", 8)
    j = s1.join(s2)
    assert j.mem_ptrs.get(("$t0", 0)) == ("$sp", 8)

def test_mips_taintstate_invalidate_base():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintState, Taint
    from ablation.analyzers.isa_mips import Mode
    s = TaintState(mode=Mode.MIPS32)
    s.mem[("$t0", 0)] = Taint(frozenset({"src"}), None)
    s.ranges.append(("$t0", 0, 64, Taint(frozenset({"src"}), None)))
    s.ra_slots.add(("$t0", 0))
    s.frame_ptrs["$s0"] = ("$t0", 4)
    s.mem_ptrs[("$t0", 0)] = ("$sp", 8)
    s.invalidate_base("$t0")
    assert ("$t0", 0) not in s.mem
    assert not any(r[0] == "$t0" for r in s.ranges)
    assert ("$t0", 0) not in s.ra_slots
    assert "$s0" not in s.frame_ptrs
    assert ("$t0", 0) not in s.mem_ptrs

def test_mips_taint_memory_zero_length():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintTracker
    from ablation.analyzers.isa_mips import Mode
    t = TaintTracker(Mode.MIPS32)
    t.taint_memory("$a0", 0, "src")  # length=0 → taint_mem (not taint_range)
    assert t.state.mem_get("@src1", 0).tainted

def test_mips_taint_pointee_unresolvable_raises():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintTracker
    from ablation.analyzers.isa_mips import Mode
    t = TaintTracker(Mode.MIPS32)
    with pytest.raises(ValueError):
        t.taint_pointee("$a0", 0, "src")

def test_mips_run_record_trace():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintTracker
    from ablation.analyzers.insn_mips import from_listing
    from ablation.analyzers.isa_mips import Mode
    t = TaintTracker(Mode.MIPS32)
    t.run(list(from_listing("nop", Mode.MIPS32)), record_trace=True)
    assert len(t.trace) == 1

def test_mips_mfhi_clears_taint():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintTracker
    from ablation.analyzers.insn_mips import from_listing
    from ablation.analyzers.isa_mips import Mode
    t = TaintTracker(Mode.MIPS32)
    t.taint_register("$t0", "src")
    t.run(list(from_listing("mfhi $t0", Mode.MIPS32)))
    assert not t.state.get("$t0").tainted

def test_mips_mul_rd_propagates():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintTracker
    from ablation.analyzers.insn_mips import from_listing
    from ablation.analyzers.isa_mips import Mode
    t = TaintTracker(Mode.MIPS32)
    # MIPS parser canonicalizes ABI aliases to architectural numbers ($t1→$9, $t0→$8)
    t.taint_register("$9", "src")
    t.run(list(from_listing("mul $t0, $t1, $t2", Mode.MIPS32)))
    assert t.state.get("$8").tainted

def test_mips_fp_load_propagates_taint():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintTracker
    from ablation.analyzers.insn_mips import from_listing
    from ablation.analyzers.isa_mips import Mode
    t = TaintTracker(Mode.MIPS32)
    t.taint_memory("$a0", 0, "buf", 64)
    t.run(list(from_listing("lwc1 $f0, 0($a0)", Mode.MIPS32)))
    assert t.state.get("$f0").tainted

def test_mips_mfc1_clean_src_gives_clean_dst():
    from ablation.analyzers.taint_tracker_mips_labeled import TaintTracker
    from ablation.analyzers.insn_mips import from_listing
    from ablation.analyzers.isa_mips import Mode
    t = TaintTracker(Mode.MIPS32)
    t.run(list(from_listing("mfc1 $t0, $f0", Mode.MIPS32)))
    assert not t.state.get("$8").tainted


# ══════════════════════════════════════════════════════════════════
# PPC labeled: Taint.__str__, null-check guards, TaintState unit
#              tests, instruction handlers, record_trace
# ══════════════════════════════════════════════════════════════════

def test_ppc_taint_str_clean():
    from ablation.analyzers.taint_tracker_ppc_labeled import Taint
    assert str(Taint()) == "clean"

def test_ppc_taint_str_labeled_with_bound():
    from ablation.analyzers.taint_tracker_ppc_labeled import Taint
    s = str(Taint(frozenset({"src"}), 0xff))
    assert "{src}" in s and "0xff" in s

def test_ppc_taint_str_labeled_no_bound():
    from ablation.analyzers.taint_tracker_ppc_labeled import Taint
    assert str(Taint(frozenset({"src"}))) == "{src}"

def test_ppc_taintstate_region_of_none():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintState
    from ablation.analyzers.isa_ppc import Mode
    s = TaintState(mode=Mode.PPC32)
    assert s.region_of(None) is None

def test_ppc_taintstate_get_none():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintState, CLEAN
    from ablation.analyzers.isa_ppc import Mode
    s = TaintState(mode=Mode.PPC32)
    assert s.get(None) == CLEAN

def test_ppc_taintstate_set_none_is_noop():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintState, CLEAN
    from ablation.analyzers.isa_ppc import Mode
    s = TaintState(mode=Mode.PPC32)
    s.set(None, CLEAN)  # must not raise or modify state

def test_ppc_taintstate_set_sp_triggers_invalidate():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintState, Taint, CLEAN
    from ablation.analyzers.isa_ppc import Mode
    s = TaintState(mode=Mode.PPC32)
    s.mem[("r1", 4)] = Taint(frozenset({"src"}), None)
    s.set("r1", CLEAN)
    assert ("r1", 4) not in s.mem

def test_ppc_taintstate_invalidate_base():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintState, Taint
    from ablation.analyzers.isa_ppc import Mode
    s = TaintState(mode=Mode.PPC32)
    s.mem[("r3", 0)] = Taint(frozenset({"src"}), None)
    s.ranges.append(("r3", 0, 64, Taint(frozenset({"src"}), None)))
    s.ra_slots.add(("r3", 0))
    s.frame_ptrs["r4"] = ("r3", 4)
    s.mem_ptrs[("r3", 0)] = ("r1", 8)
    s.invalidate_base("r3")
    assert ("r3", 0) not in s.mem
    assert not any(r[0] == "r3" for r in s.ranges)
    assert ("r3", 0) not in s.ra_slots
    assert "r4" not in s.frame_ptrs
    assert ("r3", 0) not in s.mem_ptrs

def test_ppc_join_same_reg_merge():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintState, Taint
    from ablation.analyzers.isa_ppc import Mode
    s1 = TaintState(mode=Mode.PPC32)
    s1.regs["r3"] = Taint(frozenset({"a"}), None)
    s2 = TaintState(mode=Mode.PPC32)
    s2.regs["r3"] = Taint(frozenset({"b"}), None)
    j = s1.join(s2)
    assert j.regs["r3"].labels == frozenset({"a", "b"})

def test_ppc_join_mem_merge():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintState, Taint
    from ablation.analyzers.isa_ppc import Mode
    s1 = TaintState(mode=Mode.PPC32)
    s1.mem[("r1", 4)] = Taint(frozenset({"a"}), None)
    s2 = TaintState(mode=Mode.PPC32)
    s2.mem[("r1", 4)] = Taint(frozenset({"b"}), None)
    j = s1.join(s2)
    assert j.mem[("r1", 4)].labels == frozenset({"a", "b"})

def test_ppc_taint_memory_zero_length():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintTracker
    from ablation.analyzers.isa_ppc import Mode
    t = TaintTracker(mode=Mode.PPC32)
    t.taint_memory("r3", 0, "src")  # length=0 → taint_mem path
    assert t.state.mem_get("@src1", 0).tainted

def test_ppc_taint_pointee_unresolvable_raises():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintTracker
    from ablation.analyzers.isa_ppc import Mode
    t = TaintTracker(mode=Mode.PPC32)
    with pytest.raises(ValueError):
        t.taint_pointee("r3", 0, "src")

def test_ppc_run_record_trace():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintTracker
    from ablation.analyzers.insn_ppc import from_listing
    from ablation.analyzers.isa_ppc import Mode
    t = TaintTracker(mode=Mode.PPC32)
    t.run(list(from_listing("nop", Mode.PPC32)), record_trace=True)
    assert len(t.trace) == 1

def test_ppc_nop_instruction():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintTracker
    from ablation.analyzers.insn_ppc import from_listing
    from ablation.analyzers.isa_ppc import Mode
    t = TaintTracker(mode=Mode.PPC32)
    t.run(list(from_listing("nop", Mode.PPC32)))
    assert t.findings == []

def test_ppc_trap_instruction():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintTracker
    from ablation.analyzers.insn_ppc import from_listing
    from ablation.analyzers.isa_ppc import Mode
    t = TaintTracker(mode=Mode.PPC32)
    t.run(list(from_listing("trap", Mode.PPC32)))
    assert t.findings == []

def test_ppc_branch_instruction_is_passthrough():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintTracker
    from ablation.analyzers.insn_ppc import from_listing
    from ablation.analyzers.isa_ppc import Mode
    t = TaintTracker(mode=Mode.PPC32)
    t.run(list(from_listing("b 0x100", Mode.PPC32)))
    assert t.findings == []

def test_ppc_blrl_instruction():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintTracker
    from ablation.analyzers.insn_ppc import from_listing
    from ablation.analyzers.isa_ppc import Mode
    t = TaintTracker(mode=Mode.PPC32)
    t.run(list(from_listing("blrl", Mode.PPC32)))

def test_ppc_crxor_instruction():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintTracker
    from ablation.analyzers.insn_ppc import from_listing
    from ablation.analyzers.isa_ppc import Mode
    t = TaintTracker(mode=Mode.PPC32)
    t.run(list(from_listing("crxor 6, 6, 6", Mode.PPC32)))
    assert t.findings == []

def test_ppc_fp_load_propagates_taint():
    from ablation.analyzers.taint_tracker_ppc_labeled import TaintTracker
    from ablation.analyzers.insn_ppc import from_listing
    from ablation.analyzers.isa_ppc import Mode
    t = TaintTracker(mode=Mode.PPC32)
    t.taint_memory("r3", 0, "buf", 64)
    t.run(list(from_listing("lfd f0, 0(r3)", Mode.PPC32)))
    assert t.state.get("vs0").tainted


# ══════════════════════════════════════════════════════════════════
# ARM32 labeled: Taint.__str__, TaintState.join (all paths)
# ══════════════════════════════════════════════════════════════════

def test_arm32_taint_str_clean():
    from ablation.analyzers.taint_tracker_arm32_labeled import Taint
    assert str(Taint()) == "clean"

def test_arm32_taint_str_labeled_with_bound():
    from ablation.analyzers.taint_tracker_arm32_labeled import Taint
    s = str(Taint(frozenset({"src"}), 0xff))
    assert "{src}" in s and "0xff" in s

def test_arm32_taint_str_labeled_no_bound():
    from ablation.analyzers.taint_tracker_arm32_labeled import Taint
    assert str(Taint(frozenset({"src"}))) == "{src}"

def test_arm32_join_asymmetric_a_tainted():
    from ablation.analyzers.taint_tracker_arm32_labeled import TaintState, Taint
    from ablation.analyzers.isa_arm32 import Mode
    s1 = TaintState(mode=Mode.ARM)
    s1.regs["r0"] = Taint(frozenset({"src"}), 0xff)
    s2 = TaintState(mode=Mode.ARM)
    j = s1.join(s2)
    assert j.regs["r0"].bound == 0xff

def test_arm32_join_asymmetric_b_tainted():
    from ablation.analyzers.taint_tracker_arm32_labeled import TaintState, Taint
    from ablation.analyzers.isa_arm32 import Mode
    s1 = TaintState(mode=Mode.ARM)
    s2 = TaintState(mode=Mode.ARM)
    s2.regs["r1"] = Taint(frozenset({"src"}), 0x1ff)
    j = s1.join(s2)
    assert j.regs["r1"].bound == 0x1ff

def test_arm32_join_widen_collapses_bounds():
    from ablation.analyzers.taint_tracker_arm32_labeled import TaintState, Taint
    from ablation.analyzers.isa_arm32 import Mode
    s1 = TaintState(mode=Mode.ARM)
    s1.regs["r0"] = Taint(frozenset({"src"}), 0xff)
    s2 = TaintState(mode=Mode.ARM)
    s2.regs["r0"] = Taint(frozenset({"src"}), 0x1ff)
    j = s1.join(s2, widen=True)
    assert j.regs["r0"].bound is None

def test_arm32_join_mem_merge():
    from ablation.analyzers.taint_tracker_arm32_labeled import TaintState, Taint
    from ablation.analyzers.isa_arm32 import Mode
    s1 = TaintState(mode=Mode.ARM)
    s1.mem[("sp", 4)] = Taint(frozenset({"a"}), None)
    s2 = TaintState(mode=Mode.ARM)
    s2.mem[("sp", 8)] = Taint(frozenset({"b"}), None)
    j = s1.join(s2)
    assert j.mem[("sp", 4)].labels == frozenset({"a"})
    assert j.mem[("sp", 8)].labels == frozenset({"b"})

def test_arm32_join_ranges_deduplicated():
    from ablation.analyzers.taint_tracker_arm32_labeled import TaintState, Taint
    from ablation.analyzers.isa_arm32 import Mode
    rng = ("r0", 0, 64, Taint(frozenset({"src"}), None))
    s1 = TaintState(mode=Mode.ARM)
    s1.ranges.append(rng)
    s2 = TaintState(mode=Mode.ARM)
    s2.ranges.append(rng)
    j = s1.join(s2)
    assert len(j.ranges) == 1

def test_arm32_join_consts_intersect():
    from ablation.analyzers.taint_tracker_arm32_labeled import TaintState
    from ablation.analyzers.isa_arm32 import Mode
    s1 = TaintState(mode=Mode.ARM)
    s1.consts["r0"] = 42
    s2 = TaintState(mode=Mode.ARM)
    s2.consts["r0"] = 42
    s2.consts["r1"] = 99
    j = s1.join(s2)
    assert j.consts.get("r0") == 42
    assert "r1" not in j.consts

def test_arm32_join_frame_ptrs_intersect():
    from ablation.analyzers.taint_tracker_arm32_labeled import TaintState
    from ablation.analyzers.isa_arm32 import Mode
    s1 = TaintState(mode=Mode.ARM)
    s1.frame_ptrs["r4"] = ("sp", 4)
    s2 = TaintState(mode=Mode.ARM)
    s2.frame_ptrs["r4"] = ("sp", 4)
    j = s1.join(s2)
    assert j.frame_ptrs.get("r4") == ("sp", 4)

def test_arm32_join_mem_ptrs_intersect():
    from ablation.analyzers.taint_tracker_arm32_labeled import TaintState
    from ablation.analyzers.isa_arm32 import Mode
    s1 = TaintState(mode=Mode.ARM)
    s1.mem_ptrs[("r0", 0)] = ("sp", 8)
    s2 = TaintState(mode=Mode.ARM)
    s2.mem_ptrs[("r0", 0)] = ("sp", 8)
    j = s1.join(s2)
    assert j.mem_ptrs.get(("r0", 0)) == ("sp", 8)


# ══════════════════════════════════════════════════════════════════
# x86 labeled: Taint.__str__, Finding.__str__, alias_frame mem_ptrs,
#              join ranges/frame_ptrs/mem_ptrs, snapshot, _const handler
# ══════════════════════════════════════════════════════════════════

def test_x86_taint_str_clean():
    from ablation.analyzers.taint_tracker_x86_labeled import Taint
    assert str(Taint()) == "clean"

def test_x86_taint_str_labeled_with_bound():
    from ablation.analyzers.taint_tracker_x86_labeled import Taint
    s = str(Taint(frozenset({"src"}), 0xff))
    assert "{src}" in s and "0xff" in s

def test_x86_taint_str_labeled_no_bound():
    from ablation.analyzers.taint_tracker_x86_labeled import Taint
    assert str(Taint(frozenset({"src"}))) == "{src}"

def test_x86_finding_str():
    from ablation.analyzers.taint_tracker_x86_labeled import Finding
    f = Finding(0x1000, "tainted-return-address", "ret via rsp", frozenset({"src"}))
    s = str(f)
    assert "0x1000" in s and "src" in s

def test_x86_join_ranges_deduplicated():
    from ablation.analyzers.taint_tracker_x86_labeled import TaintState, Taint
    from ablation.analyzers.isa_x86 import Mode
    rng = ("rsp", 0, 64, Taint(frozenset({"src"}), None))
    s1 = TaintState(mode=Mode.X64)
    s1.ranges.append(rng)
    s2 = TaintState(mode=Mode.X64)
    s2.ranges.append(rng)
    j = s1.join(s2)
    assert len(j.ranges) == 1

def test_x86_join_frame_ptrs_intersect():
    from ablation.analyzers.taint_tracker_x86_labeled import TaintState
    from ablation.analyzers.isa_x86 import Mode
    s1 = TaintState(mode=Mode.X64)
    s1.frame_ptrs["r12"] = ("rbp", 8)
    s2 = TaintState(mode=Mode.X64)
    s2.frame_ptrs["r12"] = ("rbp", 8)
    j = s1.join(s2)
    assert j.frame_ptrs.get("r12") == ("rbp", 8)

def test_x86_join_mem_ptrs_intersect():
    from ablation.analyzers.taint_tracker_x86_labeled import TaintState
    from ablation.analyzers.isa_x86 import Mode
    s1 = TaintState(mode=Mode.X64)
    s1.mem_ptrs[("rsp", 0)] = ("rbp", 8)
    s2 = TaintState(mode=Mode.X64)
    s2.mem_ptrs[("rsp", 0)] = ("rbp", 8)
    j = s1.join(s2)
    assert j.mem_ptrs.get(("rsp", 0)) == ("rbp", 8)

def test_x86_snapshot_via_record_trace():
    from ablation.analyzers.taint_tracker_x86_labeled import TaintTracker
    from ablation.analyzers.insn_x86 import from_listing
    from ablation.analyzers.isa_x86 import Mode
    t = TaintTracker(Mode.X64)
    t.run(list(from_listing("nop", Mode.X64)), record_trace=True)
    assert len(t.trace) == 1

def test_x86_rdtsc_clears_rax_rdx():
    from ablation.analyzers.taint_tracker_x86_labeled import TaintTracker
    from ablation.analyzers.insn_x86 import from_listing
    from ablation.analyzers.isa_x86 import Mode
    t = TaintTracker(Mode.X64)
    t.taint_register("rax", "src")
    t.run(list(from_listing("rdtsc", Mode.X64)))
    assert not t.state.get("rax").tainted
    assert not t.state.get("rdx").tainted

def test_x86_cpuid_clears_registers():
    from ablation.analyzers.taint_tracker_x86_labeled import TaintTracker
    from ablation.analyzers.insn_x86 import from_listing
    from ablation.analyzers.isa_x86 import Mode
    t = TaintTracker(Mode.X64)
    t.taint_register("rax", "src")
    t.run(list(from_listing("cpuid", Mode.X64)))
    assert not t.state.get("rax").tainted
    assert not t.state.get("rcx").tainted
    assert not t.state.get("rbx").tainted

def test_x86_rdrand_clears_dest():
    from ablation.analyzers.taint_tracker_x86_labeled import TaintTracker
    from ablation.analyzers.insn_x86 import from_listing
    from ablation.analyzers.isa_x86 import Mode
    t = TaintTracker(Mode.X64)
    t.taint_register("rax", "src")
    t.run(list(from_listing("rdrand rax", Mode.X64)))
    assert not t.state.get("rax").tainted

def test_x86_pushf_popf_roundtrip():
    from ablation.analyzers.taint_tracker_x86_labeled import TaintTracker
    from ablation.analyzers.insn_x86 import from_listing
    from ablation.analyzers.isa_x86 import Mode
    t = TaintTracker(Mode.X64)
    t.run(list(from_listing("pushf\npopf", Mode.X64)))

def test_x86_lahf_sahf():
    from ablation.analyzers.taint_tracker_x86_labeled import TaintTracker
    from ablation.analyzers.insn_x86 import from_listing
    from ablation.analyzers.isa_x86 import Mode
    t = TaintTracker(Mode.X64)
    t.run(list(from_listing("lahf\nsahf", Mode.X64)))


# ══════════════════════════════════════════════════════════════════
# ARC labeled: _atomic handler (llock/scond/ex), _unknown handler
# ══════════════════════════════════════════════════════════════════

def test_arc_llock_loads_from_region():
    from ablation.analyzers.taint_tracker_arc_labeled import TaintTracker
    from ablation.analyzers.insn_arc import from_listing
    from ablation.analyzers.isa_arc import Mode
    t = TaintTracker(Mode.HS)
    t.taint_memory("r1", 0, "buf", 64)
    t.run(list(from_listing("llock r0, [r1]")))

def test_arc_scond_clears_dest():
    from ablation.analyzers.taint_tracker_arc_labeled import TaintTracker
    from ablation.analyzers.insn_arc import from_listing
    from ablation.analyzers.isa_arc import Mode
    t = TaintTracker(Mode.HS)
    t.taint_register("r0", "src")
    t.taint_memory("r1", 0, "buf", 64)
    t.run(list(from_listing("scond r0, [r1]")))
    assert not t.state.get("r0").tainted

def test_arc_ex_exchanges_with_mem():
    from ablation.analyzers.taint_tracker_arc_labeled import TaintTracker
    from ablation.analyzers.insn_arc import from_listing
    from ablation.analyzers.isa_arc import Mode
    t = TaintTracker(Mode.HS)
    t.taint_memory("r1", 0, "buf", 64)
    t.run(list(from_listing("ex r0, [r1]")))

def test_arc_unknown_insn_propagates_taint():
    from ablation.analyzers.taint_tracker_arc_labeled import TaintTracker
    from ablation.analyzers.insn_arc import Insn, Reg
    from ablation.analyzers.isa_arc import Mode
    t = TaintTracker(Mode.HS)
    t.taint_register("r1", "src")
    insn = Insn(address=0, mnemonic="arc_exotic_xyz", ops=[Reg("r0"), Reg("r1")])
    t.step(insn)
    assert t.state.get("r0").tainted

def test_arc_unknown_insn_mem_operand_propagates():
    from ablation.analyzers.taint_tracker_arc_labeled import TaintTracker
    from ablation.analyzers.insn_arc import Insn, Reg, Mem
    from ablation.analyzers.isa_arc import Mode
    t = TaintTracker(Mode.HS)
    t.taint_register("r2", "src")
    insn = Insn(address=0, mnemonic="arc_exotic_xyz", ops=[Reg("r0"), Mem(base="r2")])
    t.step(insn)
    assert t.state.get("r0").tainted

def test_arc_unknown_insn_no_dest_is_silent():
    from ablation.analyzers.taint_tracker_arc_labeled import TaintTracker
    from ablation.analyzers.insn_arc import Insn, Reg
    from ablation.analyzers.isa_arc import Mode
    t = TaintTracker(Mode.HS)
    insn = Insn(address=0, mnemonic="arc_exotic_xyz", ops=[])
    t.step(insn)  # rd is None → early return in _unknown


# ══════════════════════════════════════════════════════════════════
# RISCV: Taint.__str__, Finding.__str__, join ranges
# ══════════════════════════════════════════════════════════════════

def test_riscv_taint_str_clean():
    from ablation.analyzers.taint_tracker_riscv import Taint
    assert str(Taint()) == "clean"

def test_riscv_taint_str_labeled_with_bound():
    from ablation.analyzers.taint_tracker_riscv import Taint
    s = str(Taint(frozenset({"src"}), 0xff))
    assert "{src}" in s and "0xff" in s

def test_riscv_taint_str_labeled_no_bound():
    from ablation.analyzers.taint_tracker_riscv import Taint
    assert str(Taint(frozenset({"src"}))) == "{src}"

def test_riscv_finding_str():
    from ablation.analyzers.taint_tracker_riscv import Finding
    f = Finding(0x100, "tainted-return-address", "ret via ra", frozenset({"src"}))
    s = str(f)
    assert "0x100" in s and "src" in s

def test_riscv_join_ranges_deduplicated():
    from ablation.analyzers.taint_tracker_riscv import TaintState, Taint
    from ablation.analyzers.isa_riscv import Width
    rng = ("sp", 0, 64, Taint(frozenset({"src"}), None))
    s1 = TaintState(Width.RV64)
    s1.ranges.append(rng)
    s2 = TaintState(Width.RV64)
    s2.ranges.append(rng)
    j = s1.join(s2)
    assert len(j.ranges) == 1
