"""Forward labeled-taint tracker for ARC EM/HS (ARCv2, 32-bit).

Labeled-taint model: Taint(labels: FrozenSet[str], bound: Optional[int]).
TaintState exposes copy/join/same_as for CFG forward-worklist fixpoint.

ARC specifics: delay slots opt-in (.d suffix), conditional execution joined
path-insensitively, push/pop/enter/leave code-density ops, blink RA tracking.
"""
from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .insn_arc import Imm, Insn, Mem, Reg, RegList
from .isa_arc import (
    ARITH, ATOMIC, AUX_READ, AUX_WRITE, BITMISC, BITOP, BLINK, BRANCH, BRANCH_INDEXED, BRCC, CALL, CMP, COPY, ENTER,
    EXT, FLAGS, FP, INPUT_SYSCALLS, JLI, JUMP, JUMP_LINK, LEAVE, LOAD, LOGIC, LOOP, MUL, NOP, PCL, POP, PUSH, SEXT,
    SHIFT, SP, STORE, SYSCALL, Abi, AbiModel, Mode, abi_for, bmsk_bound, canon_reg, imm_bound, pretty, syscall_model,
)

log = logging.getLogger("taint_tracker_arc_labeled")
Labels = FrozenSet[str]
EMPTY: Labels = frozenset()
MASK = 0xFFFFFFFF


@dataclass(frozen=True)
class Taint:
    labels: Labels = EMPTY
    bound: Optional[int] = None

    @property
    def tainted(self) -> bool:
        return bool(self.labels)

    def __str__(self) -> str:
        if not self.labels:
            return "clean"
        return "{" + ",".join(sorted(self.labels)) + "}" + (f"<={self.bound:#x}" if self.bound is not None else "")


CLEAN = Taint()


def union(*ts: Taint) -> Taint:
    labels: Labels = EMPTY
    for t in ts:
        labels |= t.labels
    return Taint(labels, None)


def summed(*ts: Taint) -> Taint:
    labels: Labels = EMPTY
    bound: Optional[int] = 0
    for t in ts:
        labels |= t.labels
        if t.tainted:
            bound = None if (bound is None or t.bound is None) else bound + t.bound
    return Taint(labels, bound if labels else None)


@dataclass
class Finding:
    address: int
    kind: str
    detail: str
    labels: Labels

    def __str__(self) -> str:
        return f"{self.address:#x} [{self.kind}] {self.detail} <- {{{','.join(sorted(self.labels))}}}"


@dataclass
class Policy:
    taint_through_pointer: bool = True
    calls_propagate_to_return: bool = True
    report_tainted_branch: bool = False
    report_tainted_load_addr: bool = True
    report_tainted_store_addr: bool = True
    report_tainted_store_over_ra: bool = True
    report_syscall_args: bool = True
    bounded_index_is_safe: bool = True
    report_bounded: bool = False
    entry_is_function_start: bool = True


@dataclass
class TaintState:
    regs: Dict[str, Taint] = field(default_factory=dict)
    mem: Dict[Tuple[str, int], Taint] = field(default_factory=dict)
    ranges: List[Tuple[str, int, int, Taint]] = field(default_factory=list)
    consts: Dict[str, int] = field(default_factory=dict)
    frame_ptrs: Dict[str, Tuple[str, int]] = field(default_factory=dict)
    mem_ptrs: Dict[Tuple[str, int], Tuple[str, int]] = field(default_factory=dict)
    ra_slots: Set[Tuple[str, int]] = field(default_factory=set)
    ra_regs: Set[str] = field(default_factory=set)
    eq: Dict[str, Set[str]] = field(default_factory=dict)
    _next_region: int = 0

    def copy(self) -> "TaintState":
        return TaintState(
            regs=dict(self.regs), mem=dict(self.mem),
            ranges=list(self.ranges), consts=dict(self.consts),
            frame_ptrs=dict(self.frame_ptrs), mem_ptrs=dict(self.mem_ptrs),
            ra_slots=set(self.ra_slots), ra_regs=set(self.ra_regs),
            eq={k: set(v) for k, v in self.eq.items()}, _next_region=self._next_region,
        )

    def join(self, other: "TaintState", widen: bool = False) -> "TaintState":
        merged_regs = dict(self.regs)
        for r, t in other.regs.items():
            if r in merged_regs:
                a = merged_regs[r]
                bound = None if (a.bound is None or t.bound is None) else max(a.bound, t.bound)
                merged_regs[r] = Taint(a.labels | t.labels, bound if (a.labels | t.labels) else None)
            else:
                merged_regs[r] = t
        merged_mem = dict(self.mem)
        for k, t in other.mem.items():
            if k in merged_mem:
                merged_mem[k] = Taint(merged_mem[k].labels | t.labels, None)
            else:
                merged_mem[k] = t
        merged_ranges = list(self.ranges) + [r for r in other.ranges if r not in self.ranges]
        merged_consts = {k: v for k, v in self.consts.items() if k in other.consts and other.consts[k] == v}
        merged_frame_ptrs = {k: v for k, v in self.frame_ptrs.items() if k in other.frame_ptrs and other.frame_ptrs[k] == v}
        merged_mem_ptrs = {k: v for k, v in self.mem_ptrs.items() if k in other.mem_ptrs and other.mem_ptrs[k] == v}
        return TaintState(
            regs=merged_regs, mem=merged_mem, ranges=merged_ranges,
            consts=merged_consts, frame_ptrs=merged_frame_ptrs, mem_ptrs=merged_mem_ptrs,
            ra_slots=self.ra_slots | other.ra_slots,
            ra_regs=self.ra_regs | other.ra_regs,
            eq={},
            _next_region=max(self._next_region, other._next_region),
        )

    def same_as(self, other: "TaintState") -> bool:
        return (self.regs == other.regs and self.mem == other.mem
                and sorted(map(repr, self.ranges)) == sorted(map(repr, other.ranges))
                and self.consts == other.consts and self.frame_ptrs == other.frame_ptrs
                and self.mem_ptrs == other.mem_ptrs and self.ra_slots == other.ra_slots
                and self.ra_regs == other.ra_regs)

    def new_region(self, tag: str = "mem") -> str:
        self._next_region += 1
        return f"@{tag}{self._next_region}"

    def point_at(self, reg: str, region: str, off: int = 0) -> None:
        for r in self.eq.get(reg, {reg}):
            self.frame_ptrs[r] = (region, off)

    def region_of(self, reg: Optional[str]) -> Optional[Tuple[str, int]]:
        if reg is None:
            return None
        if reg in self.frame_ptrs:
            return self.frame_ptrs[reg]
        if reg == SP:
            return (SP, 0)
        return None

    def unalias(self, r: str) -> None:
        g = self.eq.pop(r, None)
        if g is not None:
            g.discard(r)

    def alias(self, dst: str, src: str) -> None:
        self.unalias(dst)
        g = self.eq.setdefault(src, {src})
        g.add(dst)
        self.eq[dst] = g

    def get(self, name: Optional[str]) -> Taint:
        if name is None or name in (PCL, "pc"):
            return CLEAN
        return self.regs.get(name, CLEAN)

    def set(self, name: Optional[str], t: Taint) -> None:
        if name is None or name in (PCL, "pc"):
            return
        self.consts.pop(name, None)
        self.frame_ptrs.pop(name, None)
        self.unalias(name)
        self.ra_regs.discard(name)
        if t.tainted or t.bound is not None:
            self.regs[name] = t
        else:
            self.regs.pop(name, None)
        if name == SP:
            self.invalidate_base(SP)

    def taint_reg(self, name: str, label: str) -> None:
        cur = self.regs.get(name, CLEAN)
        self.regs[name] = Taint(cur.labels | {label}, cur.bound)

    def mem_get(self, base: str, off: int) -> Taint:
        t = self.mem.get((base, off), CLEAN)
        for b, lo, hi, rt in self.ranges:
            if b == base and lo <= off < hi:
                t = Taint(t.labels | rt.labels, None)
        return t

    def mem_set(self, base: str, off: int, t: Taint, ptr: Optional[Tuple[str, int]] = None) -> None:
        if t.tainted:
            self.mem[(base, off)] = t
        else:
            self.mem.pop((base, off), None)
        if ptr is not None:
            self.mem_ptrs[(base, off)] = ptr
        else:
            self.mem_ptrs.pop((base, off), None)

    def taint_mem(self, base: str, off: int, label: str) -> None:
        cur = self.mem_get(base, off)
        self.mem[(base, off)] = Taint(cur.labels | {label}, None)

    def taint_range(self, base: str, lo: int, hi: int, label: str) -> None:
        self.ranges.append((base, lo, hi, Taint(frozenset({label}), None)))

    def rebase(self, reg: str, delta: int) -> None:
        def rk(b: str, o: int) -> Tuple[str, int]:
            return (b, o - delta) if b == reg else (b, o)
        self.mem = {rk(b, o): t for (b, o), t in self.mem.items()}
        self.ranges = [((b, lo - delta, hi - delta, t) if b == reg else (b, lo, hi, t)) for (b, lo, hi, t) in self.ranges]
        self.ra_slots = {rk(b, o) for (b, o) in self.ra_slots}
        self.frame_ptrs = {r: rk(b, k) for r, (b, k) in self.frame_ptrs.items()}
        self.mem_ptrs = {rk(b, o): rk(pb, pk) for (b, o), (pb, pk) in self.mem_ptrs.items()}

    def invalidate_base(self, reg: str) -> None:
        self.mem = {k: v for k, v in self.mem.items() if k[0] != reg}
        self.ranges = [r for r in self.ranges if r[0] != reg]
        self.ra_slots = {k for k in self.ra_slots if k[0] != reg}
        self.frame_ptrs = {r: v for r, v in self.frame_ptrs.items() if v[0] != reg}
        self.mem_ptrs = {k: v for k, v in self.mem_ptrs.items() if k[0] != reg and v[0] != reg}

    def snapshot(self) -> Dict[str, str]:
        return {pretty(r): str(t) for r, t in sorted(self.regs.items(), key=lambda kv: (len(kv[0]), kv[0]))}


class TaintTracker:
    def __init__(self, mode: Mode = Mode.HS, abi: Optional[Abi] = None, policy: Optional[Policy] = None):
        self.mode = mode
        self.abi: AbiModel = abi_for(abi or Abi.default_for(mode))
        self.policy = policy or Policy()
        self.sys = syscall_model(mode)
        self.state = TaintState()
        self.findings: List[Finding] = []
        self.trace: List[Tuple[Insn, Dict[str, str]]] = []
        self.unknown: Set[str] = set()
        self._pending: Optional[Insn] = None
        if self.policy.entry_is_function_start:
            self.state.ra_regs.add(BLINK)

    def taint_register(self, reg: str, label: str) -> None:
        self.state.taint_reg(self._canon(reg), label)

    def taint_memory(self, base: str, offset: int, label: str, length: int = 0) -> None:
        st, base = self.state, self._canon(base)
        loc = st.region_of(base)
        if loc is None:
            region = st.new_region(label)
            st.point_at(base, region, 0)
            loc = (region, 0)
        b, k = loc
        if length:
            st.taint_range(b, k + offset, k + offset + length, label)
        else:
            st.taint_mem(b, k + offset, label)

    def taint_pointee(self, base: str, offset: int, label: str, length: int = 1 << 20) -> None:
        st, base = self.state, self._canon(base)
        loc = st.region_of(base)
        if loc is None:
            raise ValueError(f"{base} is not a resolvable region base; taint_memory() it first")
        b, k = loc
        region = st.new_region(label)
        st.mem_ptrs[(b, k + offset)] = (region, 0)
        st.taint_range(region, 0, length, label)

    def run(self, insns: Iterable[Insn], record_trace: bool = False) -> List[Finding]:
        for insn in insns:
            self.step(insn)
            if record_trace:
                self.trace.append((insn, self.state.snapshot()))
        if self._pending is not None:
            self._transfer(self._pending)
            self._pending = None
        return self.findings

    @staticmethod
    def _canon(reg: str) -> str:
        return canon_reg(reg) or reg

    def step(self, insn: Insn) -> None:
        if self._pending is not None:
            branch = self._pending
            self._pending = None
            self._exec_maybe_conditional(insn)
            self._ret_addr = insn.next_ip
            self._transfer(branch)
            return
        m = insn.mnemonic
        if insn.delay and (m in BRANCH or m in CALL or m in JUMP or m in JUMP_LINK or m in BRCC):
            self._branch_condition(insn)
            self._pending = insn
            return
        if m in BRANCH or m in CALL or m in JUMP or m in JUMP_LINK or m in BRCC or m in BRANCH_INDEXED or m in JLI:
            self._branch_condition(insn)
            self._ret_addr = insn.next_ip
            self._transfer(insn)
            return
        self._exec_maybe_conditional(insn)

    def _exec_maybe_conditional(self, insn: Insn) -> None:
        if insn.cond is not None:
            before = copy.deepcopy(self.state)
            self._exec(insn)
            self._merge(before)
        else:
            self._exec(insn)

    def _merge(self, other: TaintState) -> None:
        st = self.state
        for r in set(st.regs) | set(other.regs):
            a, b = st.regs.get(r, CLEAN), other.regs.get(r, CLEAN)
            if a == b:
                continue
            if a.tainted and b.tainted:
                bound = None if (a.bound is None or b.bound is None) else max(a.bound, b.bound)
            else:
                bound = a.bound if a.tainted else b.bound
            t = Taint(a.labels | b.labels, bound)
            if t.tainted or t.bound is not None:
                st.regs[r] = t
            else:
                st.regs.pop(r, None)
        for k in set(st.mem) | set(other.mem):
            a, b = st.mem.get(k, CLEAN), other.mem.get(k, CLEAN)
            if a != b:
                st.mem[k] = Taint(a.labels | b.labels, None)
        for r in other.ranges:
            if r not in st.ranges:
                st.ranges.append(r)
        st.consts = {k: v for k, v in st.consts.items() if other.consts.get(k) == v}
        st.frame_ptrs = {k: v for k, v in st.frame_ptrs.items() if other.frame_ptrs.get(k) == v}
        st.mem_ptrs = {k: v for k, v in st.mem_ptrs.items() if other.mem_ptrs.get(k) == v}
        st.ra_slots &= other.ra_slots
        st.ra_regs &= other.ra_regs
        st.eq = {}

    def _exec(self, insn: Insn) -> None:
        m, st = insn.mnemonic, self.state
        self._cur = insn
        if m in NOP or m in LOOP:
            return
        if m in LOAD:
            self._load(insn)
        elif m in STORE:
            self._store(insn)
        elif m in PUSH:
            self._push(insn.reg(0), insn.imm(0))
        elif m in POP:
            self._pop(insn.reg(0))
        elif m in ENTER:
            self._enter(insn)
        elif m in LEAVE:
            self._leave(insn)
        elif m in COPY:
            self._mov(insn)
        elif m in ARITH or m in LOGIC or m in SHIFT or m in BITOP or m in EXT or m in SEXT or m in BITMISC or m in MUL or m in CMP:
            self._alu(insn)
        elif m in SYSCALL:
            self._syscall(insn)
        elif m in AUX_READ:
            st.set(insn.reg(0), CLEAN)
        elif m in AUX_WRITE:
            pass
        elif m in ATOMIC:
            self._atomic(insn)
        else:
            self._unknown(insn)

    def _src(self, insn: Insn, i: int) -> Taint:
        r = insn.reg(i)
        return self.state.get(r) if r else CLEAN

    def _const(self, insn: Insn, i: int) -> Optional[int]:
        op = insn.ops[i] if i < len(insn.ops) else None
        if isinstance(op, Imm):
            return op.value
        if isinstance(op, Reg):
            if op.name == PCL:
                return insn.pcl
            return self.state.consts.get(op.name)
        return None

    def _ptr_of(self, name: Optional[str]) -> Optional[Tuple[str, int]]:
        st = self.state
        return st.region_of(name) if (name in st.frame_ptrs or name == SP) else None

    def _set(self, name: Optional[str], t: Taint, ptr: Optional[Tuple[str, int]] = None, const: Optional[int] = None) -> None:
        st = self.state
        if name is None or name in (PCL, "pc"):
            return
        if name == SP:
            if ptr is not None and ptr[0] == SP:
                st.rebase(SP, ptr[1])
                st.regs.pop(SP, None)
                return
            st.set(SP, t)
            return
        st.set(name, t)
        if ptr is not None:
            st.frame_ptrs[name] = ptr
        if const is not None:
            st.consts[name] = const & MASK

    def _add_imm_to_reg(self, reg: str, delta: int) -> None:
        st = self.state
        if reg == SP:
            st.rebase(SP, delta)
            c = st.consts.get(SP)
            if c is not None:
                st.consts[SP] = (c + delta) & MASK
            return
        ptr, c, t = st.frame_ptrs.get(reg), st.consts.get(reg), st.get(reg)
        st.set(reg, Taint(t.labels, None) if t.tainted else CLEAN)
        if ptr is not None:
            st.frame_ptrs[reg] = (ptr[0], ptr[1] + delta)
        if c is not None:
            st.consts[reg] = (c + delta) & MASK

    def _find(self, insn: Insn, kind: str, detail: str, labels: Labels) -> None:
        self.findings.append(Finding(insn.address, kind, detail, labels))

    def _find_addr(self, insn: Insn, kind: str, detail: str, t: Taint) -> None:
        p = self.policy
        if p.bounded_index_is_safe and t.bound is not None:
            if p.report_bounded:
                self._find(insn, "bounded-" + kind, f"{detail} (attacker contribution <= {t.bound:#x})", t.labels)
            return
        self._find(insn, kind, detail, t.labels)

    def _effective(self, insn: Insn, mem: Mem, width: int) -> Tuple[Taint, Optional[Tuple[str, int]], int]:
        st = self.state
        scale = width if insn.addr == "as" else 1
        at = st.get(mem.base) if mem.base != PCL else CLEAN
        delta = 0
        if mem.index:
            it = st.get(mem.index)
            if it.tainted and it.bound is not None:
                it = Taint(it.labels, it.bound * scale)
            at = summed(at, it)
            slot = None
            c = st.consts.get(mem.index)
            if c is not None:
                delta = c * scale
                loc = st.region_of(mem.base)
                if loc is not None:
                    slot = (loc[0], loc[1] + (0 if insn.addr == "ab" else delta))
        else:
            delta = mem.disp * scale
            loc = st.region_of(mem.base)
            slot = (loc[0], loc[1] + (0 if insn.addr == "ab" else delta)) if loc is not None else None
        return at, slot, delta

    def _writeback(self, insn: Insn, mem: Mem, delta: int) -> None:
        if insn.addr in ("ab", "aw") and mem.base not in (PCL,):
            if mem.index and self.state.consts.get(mem.index) is None:
                st = self.state
                st.set(mem.base, union(st.get(mem.base), st.get(mem.index)))
            else:
                self._add_imm_to_reg(mem.base, delta)

    def _load(self, insn: Insn) -> None:
        st, p, m = self.state, self.policy, insn.mnemonic
        rd, mem = insn.reg(0), insn.mem(1)
        if rd is None or mem is None:
            return self._unknown(insn)
        width = LOAD[m]
        at, slot, delta = self._effective(insn, mem, width)
        if mem.base == PCL and mem.index is None:
            self._set(rd, CLEAN)
            self._writeback(insn, mem, delta)
            return
        if at.tainted and p.report_tainted_load_addr:
            self._find_addr(insn, "tainted-load-address", f"{m} via {pretty(mem.base)}", at)
        val, ptr, was_ra = CLEAN, None, False
        if slot is not None:
            val = st.mem_get(*slot)
            if width == 4:
                ptr = st.mem_ptrs.get(slot)
                was_ra = slot in st.ra_slots
        if at.tainted and p.taint_through_pointer:
            val = Taint(val.labels | at.labels, None)
        if val.tainted:
            if width < 4 and not insn.signed:
                mx = (1 << (8 * width)) - 1
                val = Taint(val.labels, mx if val.bound is None else min(val.bound, mx))
            elif width < 4:
                val = Taint(val.labels, None)
        self._set(rd, val, ptr)
        if was_ra or rd == BLINK:
            st.ra_regs.add(rd)
        self._writeback(insn, mem, delta)

    def _store(self, insn: Insn) -> None:
        st, p, m = self.state, self.policy, insn.mnemonic
        mem = insn.mem(1)
        if mem is None:
            return self._unknown(insn)
        width = STORE[m]
        src = insn.reg(0)
        t = st.get(src) if src else CLEAN
        at, slot, delta = self._effective(insn, mem, width)
        if at.tainted and p.report_tainted_store_addr:
            self._find_addr(insn, "tainted-store-address", f"{m} via {pretty(mem.base)}", at)
        if slot is not None:
            ptr = self._ptr_of(src) if (src and width == 4) else None
            st.mem_set(slot[0], slot[1], t, ptr)
            if slot in st.ra_slots:
                if t.tainted:
                    if p.report_tainted_store_over_ra:
                        self._find(insn, "tainted-overwrite-of-saved-ra", f"{m} -> {mem}", t.labels)
                else:
                    st.ra_slots.discard(slot)
            elif src in st.ra_regs and width == 4:
                st.ra_slots.add(slot)
        self._writeback(insn, mem, delta)

    def _push(self, reg: Optional[str], imm: Optional[int] = None) -> None:
        st = self.state
        st.rebase(SP, -4)
        c = st.consts.get(SP)
        if c is not None:
            st.consts[SP] = (c - 4) & MASK
        t = st.get(reg) if reg else CLEAN
        st.mem_set(SP, 0, t, self._ptr_of(reg) if reg else None)
        st.ra_slots.discard((SP, 0))
        if reg in st.ra_regs:
            st.ra_slots.add((SP, 0))

    def _pop(self, reg: Optional[str]) -> None:
        st = self.state
        t, ptr, was_ra = st.mem_get(SP, 0), st.mem_ptrs.get((SP, 0)), (SP, 0) in st.ra_slots
        st.mem.pop((SP, 0), None)
        st.mem_ptrs.pop((SP, 0), None)
        st.ra_slots.discard((SP, 0))
        st.rebase(SP, 4)
        c = st.consts.get(SP)
        if c is not None:
            st.consts[SP] = (c + 4) & MASK
        if reg is None:
            return
        self._set(reg, t, ptr)
        if was_ra or reg == BLINK:
            st.ra_regs.add(reg)

    def _enter(self, insn: Insn) -> None:
        rl = insn.reglist(0)
        if rl is None:
            return self._unknown(insn)
        regs = list(rl.regs)
        order = ([BLINK] if BLINK in regs else []) + [r for r in regs if r not in (BLINK, FP)] + ([FP] if FP in regs else [])
        for r in order:
            self._push(r)
        if FP in regs:
            self._set(FP, CLEAN, (SP, 0))

    def _leave(self, insn: Insn) -> None:
        st = self.state
        rl = insn.reglist(0)
        if rl is None:
            return self._unknown(insn)
        regs = list(rl.regs)
        if FP in regs:
            self._set(SP, CLEAN, self._ptr_of(FP) or (SP, 0))
        order = ([FP] if FP in regs else []) + [r for r in reversed(regs) if r not in (BLINK, FP, PCL)] + ([BLINK] if BLINK in regs else [])
        for r in order:
            self._pop(r)
        if PCL in regs:
            t = st.get(BLINK)
            if t.tainted:
                self._find(insn, "tainted-return-address", "leave_s {.., pcl}", t.labels)

    def _atomic(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd, mem = insn.reg(0), insn.mem(1)
        if rd is None or mem is None:
            return self._unknown(insn)
        at = st.get(mem.base)
        if at.tainted:
            self._find_addr(insn, "tainted-load-address" if m != "scond" else "tainted-store-address", f"{m} via {pretty(mem.base)}", at)
        loc = st.region_of(mem.base)
        if m in ("ex", "llock", "llockd"):
            old = st.get(rd)
            val = st.mem_get(loc[0], loc[1] + mem.disp) if loc else CLEAN
            if loc and m == "ex":
                st.mem_set(loc[0], loc[1] + mem.disp, old)
            self._set(rd, union(val, at) if at.tainted else val)
        else:
            if loc:
                st.mem_set(loc[0], loc[1] + mem.disp, st.get(rd))
            self._set(rd, CLEAN)

    def _mov(self, insn: Insn) -> None:
        st = self.state
        rd = insn.reg(0)
        if rd is None or len(insn.ops) != 2:
            return self._unknown(insn)
        src = insn.ops[1]
        t = self._src(insn, 1)
        ptr = const = None
        was_ra = False
        if isinstance(src, Imm):
            const = src.value
        elif isinstance(src, Reg):
            ptr, const = self._ptr_of(src.name), self._const(insn, 1)
            was_ra = src.name in st.ra_regs
        self._set(rd, t, ptr, const)
        if was_ra:
            st.ra_regs.add(rd)
        if isinstance(src, Reg) and src.name not in (SP, PCL) and rd != SP:
            st.alias(rd, src.name)
        if insn.flags:
            st.set(FLAGS, Taint(t.labels, None))

    def _alu(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        n = len(insn.ops)
        dst = insn.ops[0] if n else None
        rd = dst.name if isinstance(dst, Reg) else None
        srcs = list(range(1, n)) if n >= 3 else ([1] if n == 2 else [])
        if n == 2 and m in (ARITH | LOGIC | SHIFT | BITOP | MUL) and m not in ("neg", "abs", "not", "norm", "ffs", "fls", "swap", "swape"):
            srcs = [0, 1]
        parts = [self._src(insn, i) for i in srcs]
        cs_ = [self._const(insn, i) for i in srcs]
        imm = next((insn.imm(i) for i in srcs if insn.imm(i) is not None), None)
        b_t = parts[0] if parts else CLEAN
        labels: Labels = EMPTY
        for t in parts:
            labels |= t.labels
        bound: Optional[int] = None
        const: Optional[int] = None
        ptr: Optional[Tuple[str, int]] = None
        rb = insn.reg(srcs[0]) if srcs else None

        if m in ("add", "adc", "add1", "add2", "add3", "sub", "sbc", "sub1", "sub2", "sub3", "rsub", "adds", "subs"):
            shift = {"add1": 1, "add2": 2, "add3": 3, "sub1": 1, "sub2": 2, "sub3": 3}.get(m, 0)
            if shift and len(parts) > 1 and parts[1].tainted and parts[1].bound is not None:
                parts[1] = Taint(parts[1].labels, parts[1].bound << shift)
            t = summed(*parts)
            bound = t.bound
            if m == "rsub" or (m.startswith("sub") and rb is not None and self._const(insn, srcs[0]) == 0):
                bound = None
            if all(c is not None for c in cs_) and cs_:
                a, c = cs_[0], (cs_[1] if len(cs_) > 1 else 0)
                const = {"add": a + c, "add1": a + (c << 1), "add2": a + (c << 2), "add3": a + (c << 3),
                         "sub": a - c, "rsub": c - a}.get(m)
            if m == "add" and rb is not None and len(srcs) == 2:
                if rd == SP and rb == SP and cs_[1] is not None:
                    self._add_imm_to_reg(SP, cs_[1])
                    if insn.flags:
                        st.set(FLAGS, Taint(labels, None))
                    return
                rc = insn.reg(srcs[1])
                for a, k in ((rb, cs_[1]), (rc, cs_[0])):
                    loc = self._ptr_of(a)
                    if loc is not None and k is not None:
                        ptr = (loc[0], loc[1] + k)
                        break
                if rb == PCL and cs_[1] is not None:
                    const = (insn.pcl + cs_[1]) & MASK
            if m in ("add1", "add2", "add3") and rb is not None and len(srcs) == 2:
                loc = self._ptr_of(rb)
                if loc is not None and cs_[1] is not None:
                    ptr = (loc[0], loc[1] + (cs_[1] << shift))
            t = Taint(t.labels, bound)
        elif m == "and":
            if imm is not None:
                bnd = imm_bound(imm)
                bound = bnd if (bnd is None or b_t.bound is None) else min(bnd, b_t.bound)
            else:
                bs = [t.bound for t in parts if t.tainted and t.bound is not None]
                bound = min(bs) if bs else None
            t = Taint(labels, bound if labels else None)
        elif m == "bic":
            t = Taint(labels, b_t.bound if labels else None)
        elif m in ("or", "xor"):
            t = summed(*parts)
        elif m == "not":
            t = Taint(labels, None)
        elif m == "bmsk":
            bnd = bmsk_bound(imm) if imm is not None else None
            bound = bnd if (bnd is None or b_t.bound is None) else min(bnd, b_t.bound)
            t = Taint(labels, bound if labels else None)
        elif m in ("bset", "bclr", "bxor", "bmskn"):
            t = Taint(labels, None if m != "bclr" else b_t.bound) if labels else CLEAN
        elif m in ("asl", "lsl"):
            if imm is not None and b_t.bound is not None and imm < 32:
                bound = b_t.bound << imm
            t = Taint(labels, bound if labels else None)
            if cs_ and cs_[0] is not None and imm is not None:
                const = (cs_[0] << imm) & MASK
        elif m == "lsr":
            if imm is not None and b_t.bound is not None:
                bound = b_t.bound >> imm
            elif imm is not None and b_t.tainted and imm > 0:
                bound = (1 << (32 - imm)) - 1
            t = Taint(labels, bound if labels else None)
        elif m in ("asr", "ror", "rrc", "rol", "asls", "asrs"):
            t = Taint(labels, (b_t.bound >> imm) if (m == "asr" and imm is not None and b_t.bound is not None) else None)
        elif m in EXT:
            t = Taint(labels, EXT[m] if b_t.bound is None else min(EXT[m], b_t.bound)) if labels else CLEAN
        elif m in SEXT:
            t = Taint(labels, None)
        elif m == "xbfu":
            nbits = ((imm >> 5) & 0x1F) if imm is not None else 0
            t = Taint(labels, (1 << nbits) - 1 if nbits else None) if labels else CLEAN
        elif m in ("norm", "normw", "normh", "ffs", "fls"):
            t = Taint(labels, 32) if labels else CLEAN
        elif m.startswith("set"):
            t = Taint(labels, 1) if labels else CLEAN
        elif m in ("max", "min"):
            bs = [t.bound for t in parts if t.tainted]
            if any(b is None for b in bs):
                bound = None
            else:
                bound = max(bs) if bs else None
            t = Taint(labels, bound if labels else None)
        elif m == "abs":
            t = Taint(labels, b_t.bound)
        elif m == "neg":
            t = Taint(labels, None)
        elif m in MUL:
            t = Taint(labels, None)
            if m in ("mpyd", "mpydu", "mul64", "mulu64", "macd", "macdu"):
                st.set(rd, t)
                if rd is not None and rd.startswith("r") and rd[1:].isdigit():
                    st.set(f"r{int(rd[1:]) + 1}", t)
                return
        else:
            t = Taint(labels, None)

        if insn.flags or m in CMP:
            st.set(FLAGS, Taint(labels, None))
        if rd is None:
            return
        if rd == SP and ptr is None:
            st.set(SP, t)
            return
        self._set(rd, t, ptr, const)

    def _branch_condition(self, insn: Insn) -> None:
        if not self.policy.report_tainted_branch:
            return
        st, m = self.state, insn.mnemonic
        if m in BRCC:
            t = union(*(self._src(insn, i) for i in range(len(insn.ops))))
        elif insn.cond is not None:
            t = st.get(FLAGS)
        else:
            return
        if t.tainted:
            self._find(insn, "tainted-branch-condition", m, t.labels)

    def _transfer(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        if insn.cond is not None and m in (JUMP | JUMP_LINK | CALL):
            before = copy.deepcopy(st)
            self._transfer_uncond(insn)
            self._merge(before)
            return
        self._transfer_uncond(insn)

    def _transfer_uncond(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        if m in CALL or m in JLI:
            self._call(insn, None)
        elif m in JUMP_LINK:
            mem = insn.mem(0)
            self._call(insn, mem.base if mem else None)
        elif m in JUMP:
            mem = insn.mem(0)
            r = mem.base if mem else None
            if r is None:
                return
            t = st.get(r)
            if t.tainted:
                ret = r == BLINK or r in st.ra_regs
                self._find(insn, "tainted-return-address" if ret else "tainted-indirect-jump", f"j [{pretty(r)}]", t.labels)
        elif m in BRANCH_INDEXED:
            mem = insn.mem(0)
            if mem is not None and st.get(mem.base).tainted:
                self._find_addr(insn, "tainted-indirect-jump", f"{m} [{pretty(mem.base)}]", st.get(mem.base))

    def _call(self, insn: Insn, target_reg: Optional[str]) -> None:
        st, p, ab = self.state, self.policy, self.abi
        if target_reg is not None and st.get(target_reg).tainted:
            self._find(insn, "tainted-indirect-call", f"{insn.mnemonic} [{pretty(target_reg)}]", st.get(target_reg).labels)
        arg_labels: Labels = EMPTY
        for r in ab.arg_regs:
            arg_labels |= st.get(r).labels
        for k in range(ab.stack_arg_base, ab.stack_arg_base + 16, 4):
            arg_labels |= st.mem_get(SP, k).labels
        for r in ab.caller_saved:
            st.set(r, CLEAN)
        st.ra_regs.discard(BLINK)
        st.consts[BLINK] = getattr(self, "_ret_addr", insn.next_ip)
        if p.calls_propagate_to_return and arg_labels:
            for r in ab.ret_regs:
                st.set(r, Taint(arg_labels, None))
        st.mem = {k: v for k, v in st.mem.items() if not (k[0] == SP and k[1] < 0)}
        st.ranges = [r for r in st.ranges if not (r[0] == SP and r[2] <= 0)]
        st.mem_ptrs = {k: v for k, v in st.mem_ptrs.items() if not (k[0] == SP and k[1] < 0)}

    def _syscall(self, insn: Insn) -> None:
        st, p, sm = self.state, self.policy, self.sys
        nr = st.consts.get(sm.nr_reg)
        name = sm.numbers.get(nr, f"sys_{nr}") if nr is not None else "sys_?"
        if st.get(sm.nr_reg).tainted:
            self._find(insn, "tainted-syscall-number", name, st.get(sm.nr_reg).labels)
        if p.report_syscall_args:
            for r in sm.arg_regs:
                if st.get(r).tainted:
                    self._find(insn, "tainted-syscall-arg", f"{name}({pretty(r)})", st.get(r).labels)
        if name in INPUT_SYSCALLS:
            label = f"{name}@{insn.address:#x}"
            st.set(sm.ret_reg, Taint(frozenset({label}), None))
            bufreg = sm.arg_regs[1] if name not in ("getcwd", "getrandom") else sm.arg_regs[0]
            lenreg = sm.arg_regs[2] if name not in ("getcwd", "getrandom") else sm.arg_regs[1]
            n = st.consts.get(lenreg)
            loc = st.region_of(bufreg)
            if loc is None:
                region = st.new_region(name)
                st.point_at(bufreg, region, 0)
                loc = (region, 0)
            b, k = loc
            st.taint_range(b, k, k + (n if n is not None else 1 << 20), label)
        else:
            st.set(sm.ret_reg, CLEAN)

    def _unknown(self, insn: Insn) -> None:
        self.unknown.add(insn.mnemonic)
        rd = insn.reg(0)
        if rd is None or rd in (SP, PCL):
            return
        labels: Labels = EMPTY
        for i in range(len(insn.ops)):
            r = insn.reg(i)
            if r:
                labels |= self.state.get(r).labels
            mem = insn.mem(i)
            if mem:
                labels |= self.state.get(mem.base).labels
        self.state.set(rd, Taint(labels, None))
