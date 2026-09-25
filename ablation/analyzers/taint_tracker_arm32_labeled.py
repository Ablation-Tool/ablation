"""Forward labeled-taint tracker for 32-bit ARM (A32) and Thumb-2 (T32) instruction streams.

State
-----
* ``regs``       register family -> Taint. Core registers are whole 32-bit values.
                 VFP s/d registers are lanes of their q family (ARM ARM A2.6.2):
                 a write to s3 merges into q0.
* ``mem``        (region, offset) -> Taint. Stack frame is region named ``sp``.
* ``ranges``     byte ranges of a region that are tainted (syscall input buffers).
* ``mem_ptrs``   slot -> pointer fact it holds (spilled pointer registers).
* ``eq``         register equality classes (full-width copies).
* ``ra_regs``    register families that currently hold the return address.
* ``ra_slots``   frame slots that hold the return address.

Conditional execution (``addeq``, IT blocks) is path-insensitive: the state
after is the join of with-and-without the instruction.

This tracker consumes instruction streams (from_listing / from_objdump /
from_capstone). For binary RE over ELF files use taint_tracker_arm32.py.

Usage:
    from ablation.analyzers.taint_tracker_arm32_labeled import TaintTracker, Mode, Policy
    from ablation.analyzers.insn_arm32 import from_listing

    t = TaintTracker(Mode.THUMB)
    t.taint_memory("r0", 0, "buf", 4096)
    findings = t.run(list(from_listing(text, Mode.THUMB)))
    for f in findings:
        print(f)
"""
from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .insn_arm32 import Imm, Insn, Mem, Reg, RegList, literal_address
from .isa_arm32 import (
    ADR, ARITH, BITFIELD, BRANCH, BRANCH_EXCHANGE, BRANCH_LINK, CBZ, COPY, FLAGS, FLAGS_ONLY, INPUT_SYSCALLS, IT,
    LDM, LOAD, LOAD_DUAL, LOAD_SIGNED, LOAD_WIDTH, LOGIC, MISC_ALU, MOVT, MUL, NOP, NOT_COPY, OABI_BASE, POP, PUSH,
    SEXT, SEXT_ADD, SHIFT, STATUS, STM, STORE, STORE_DUAL, SYSCALL, TABLE_BRANCH, VLDM, VLOAD, VMOV, VPOP, VPUSH,
    VSTM, VSTORE, ZEXT, ZEXT_ADD, Abi, AbiModel, Mode, abi_for, modified_imm_bound, reg_info, syscall_model,
)

log = logging.getLogger("arm32taint")
Labels = FrozenSet[str]
EMPTY: Labels = frozenset()
MASK32 = 0xFFFFFFFF


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
        s = "{" + ",".join(sorted(self.labels)) + "}"
        return s + (f"<={self.bound:#x}" if self.bound is not None else "")


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
    mode: Mode
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

    SP = "sp"

    def new_region(self, tag: str = "mem") -> str:
        self._next_region += 1
        return f"@{tag}{self._next_region}"

    def point_at(self, reg: str, region: str, off: int = 0) -> None:
        fam = self.fam(reg)
        for r in self.eq.get(fam, {fam}):
            self.frame_ptrs[r] = (region, off)

    def region_of(self, reg: Optional[str]) -> Optional[Tuple[str, int]]:
        fam = self.fam(reg)
        if fam in self.frame_ptrs:
            return self.frame_ptrs[fam]
        if fam == self.SP:
            return (self.SP, 0)
        return None

    def unalias(self, fam: str) -> None:
        g = self.eq.pop(fam, None)
        if g is not None:
            g.discard(fam)

    def alias(self, dst: str, src: str) -> None:
        self.unalias(dst)
        g = self.eq.setdefault(src, {src})
        g.add(dst)
        self.eq[dst] = g

    def fam(self, name: Optional[str]) -> Optional[str]:
        if name is None:
            return None
        ri = reg_info(name)
        return ri.family if ri else name

    def get(self, name: Optional[str]) -> Taint:
        if name is None:
            return CLEAN
        ri = reg_info(name)
        if ri is None:
            return self.regs.get(name, CLEAN)
        t = self.regs.get(ri.family, CLEAN)
        if not t.tainted:
            return CLEAN
        if ri.width < 128 and ri.family.startswith("q"):
            return Taint(t.labels, None)
        return t

    def set(self, name: Optional[str], t: Taint) -> None:
        if name is None:
            return
        ri = reg_info(name)
        fam = ri.family if ri else name
        self.consts.pop(fam, None)
        self.frame_ptrs.pop(fam, None)
        self.unalias(fam)
        self.ra_regs.discard(fam)
        if ri is not None and ri.family.startswith("q") and ri.width < 128:
            old = self.regs.get(fam, CLEAN)
            if old.tainted:
                t = Taint(old.labels | t.labels, None)
        if t.tainted or t.bound is not None:
            self.regs[fam] = t
        else:
            self.regs.pop(fam, None)
        if fam == self.SP:
            self.invalidate_base(fam)

    def taint_reg(self, name: str, label: str) -> None:
        fam = self.fam(name)
        cur = self.regs.get(fam, CLEAN)
        self.regs[fam] = Taint(cur.labels | {label}, cur.bound)

    def resolve(self, mem: Mem) -> Tuple[Optional[str], int]:
        if mem.index is not None:
            return None, 0
        loc = self.region_of(mem.base)
        if loc is None:
            return None, 0
        b, k = loc
        return b, k + mem.disp

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
        return {r: str(t) for r, t in sorted(self.regs.items())}

    # ------------------------------------------------------------------
    # Lattice operations (required for flow-sensitive CFG analysis)
    # ------------------------------------------------------------------

    def copy(self) -> "TaintState":
        return TaintState(
            mode=self.mode,
            regs=dict(self.regs),
            mem=dict(self.mem),
            ranges=list(self.ranges),
            consts=dict(self.consts),
            frame_ptrs=dict(self.frame_ptrs),
            mem_ptrs=dict(self.mem_ptrs),
            ra_slots=set(self.ra_slots),
            ra_regs=set(self.ra_regs),
            eq={k: set(v) for k, v in self.eq.items()},
            _next_region=self._next_region,
        )

    def join(self, other: "TaintState", widen: bool = False) -> "TaintState":
        """Conservative join (union). ``widen=True`` collapses differing bounds to None."""
        out = TaintState(mode=self.mode, _next_region=max(self._next_region, other._next_region))
        for fam in set(self.regs) | set(other.regs):
            a = self.regs.get(fam, CLEAN)
            b = other.regs.get(fam, CLEAN)
            if a.tainted and not b.tainted:
                bound: Optional[int] = a.bound
            elif b.tainted and not a.tainted:
                bound = b.bound
            elif a.bound is None or b.bound is None:
                bound = None
            elif widen and a.bound != b.bound:
                bound = None
            else:
                bound = max(a.bound, b.bound)
            t = Taint(a.labels | b.labels, bound)
            if t.tainted or t.bound is not None:
                out.regs[fam] = t
        for k in set(self.mem) | set(other.mem):
            a_t = self.mem.get(k, CLEAN)
            b_t = other.mem.get(k, CLEAN)
            merged = Taint(a_t.labels | b_t.labels, None)
            if merged.tainted:
                out.mem[k] = merged
        seen: Set[tuple] = set()
        for r in self.ranges + other.ranges:
            key = (r[0], r[1], r[2], frozenset(r[3].labels))
            if key not in seen:
                seen.add(key)
                out.ranges.append(r)
        for k in set(self.consts) & set(other.consts):
            if self.consts[k] == other.consts[k]:
                out.consts[k] = self.consts[k]
        for k in set(self.frame_ptrs) & set(other.frame_ptrs):
            if self.frame_ptrs[k] == other.frame_ptrs[k]:
                out.frame_ptrs[k] = self.frame_ptrs[k]
        for k in set(self.mem_ptrs) & set(other.mem_ptrs):
            if self.mem_ptrs[k] == other.mem_ptrs[k]:
                out.mem_ptrs[k] = self.mem_ptrs[k]
        out.ra_slots = self.ra_slots | other.ra_slots
        out.ra_regs = self.ra_regs | other.ra_regs
        return out

    def same_as(self, other: "TaintState") -> bool:
        return (
            self.regs == other.regs
            and self.mem == other.mem
            and sorted(map(repr, self.ranges)) == sorted(map(repr, other.ranges))
            and self.consts == other.consts
            and self.frame_ptrs == other.frame_ptrs
            and self.mem_ptrs == other.mem_ptrs
            and self.ra_slots == other.ra_slots
            and self.ra_regs == other.ra_regs
        )


class TaintTracker:
    def __init__(self, mode: Mode = Mode.ARM, abi: Optional[Abi] = None, policy: Optional[Policy] = None):
        self.mode = mode
        self.abi: AbiModel = abi_for(abi or Abi.default_for(mode))
        self.policy = policy or Policy()
        self.sys = syscall_model(mode)
        self.state = TaintState(mode)
        self.findings: List[Finding] = []
        self.trace: List[Tuple[Insn, Dict[str, str]]] = []
        self.unknown: Set[str] = set()
        self._cur: Optional[Insn] = None
        if self.policy.entry_is_function_start:
            self.state.ra_regs.add("lr")

    # public API ---------------------------------------------------------------

    def taint_register(self, reg: str, label: str) -> None:
        self.state.taint_reg(reg, label)

    def taint_memory(self, base: str, offset: int, label: str, length: int = 0) -> None:
        st = self.state
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
        st = self.state
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
        return self.findings

    # dispatcher ---------------------------------------------------------------

    def step(self, insn: Insn) -> None:
        self._cur = insn
        if insn.conditional and insn.mnemonic not in BRANCH | BRANCH_EXCHANGE | CBZ:
            before = copy.deepcopy(self.state)
            n = len(self.findings)
            self._exec(insn)
            if self.policy.report_tainted_branch and before.get(FLAGS).tainted:
                self.findings.insert(n, Finding(insn.address, "tainted-branch-condition", f"{insn.mnemonic}{insn.cond}", before.get(FLAGS).labels))
            self._merge(before)
            return
        self._exec(insn)

    def _merge(self, other: TaintState) -> None:
        st = self.state
        for fam in set(st.regs) | set(other.regs):
            a, b = st.regs.get(fam, CLEAN), other.regs.get(fam, CLEAN)
            if a == b:
                continue
            bound = None if (a.bound is None or b.bound is None) else max(a.bound, b.bound)
            if a.tainted and not b.tainted:
                bound = a.bound
            elif b.tainted and not a.tainted:
                bound = b.bound
            t = Taint(a.labels | b.labels, bound)
            if t.tainted or t.bound is not None:
                st.regs[fam] = t
            else:
                st.regs.pop(fam, None)
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
        if m in NOP or m in IT:
            return
        if m in PUSH:
            self._push(insn)
        elif m in POP:
            self._pop(insn)
        elif m in LDM:
            self._ldm(insn)
        elif m in STM:
            self._stm(insn)
        elif m in LOAD or m in LOAD_DUAL:
            self._load(insn)
        elif m in STORE or m in STORE_DUAL:
            self._store(insn)
        elif m in BRANCH_LINK:
            self._call(insn)
        elif m in BRANCH_EXCHANGE:
            self._bx(insn)
        elif m in BRANCH or m in CBZ:
            self._branch(insn)
        elif m in TABLE_BRANCH:
            self._table_branch(insn)
        elif m in SYSCALL:
            self._syscall(insn)
        elif m in COPY or m in NOT_COPY:
            self._mov(insn)
        elif m in MOVT:
            self._movt(insn)
        elif m in ZEXT or m in SEXT or m in ZEXT_ADD or m in SEXT_ADD:
            self._extend(insn)
        elif m in ARITH or m in LOGIC or m in SHIFT or m in MUL or m in MISC_ALU:
            self._alu(insn)
        elif m in BITFIELD:
            self._bitfield(insn)
        elif m in FLAGS_ONLY:
            self._flags_only(insn)
        elif m in VPUSH:
            self._vpush(insn)
        elif m in VPOP:
            self._vpop(insn)
        elif m in VLOAD or m in VLDM:
            self._vload(insn)
        elif m in VSTORE or m in VSTM:
            self._vstore(insn)
        elif m in VMOV:
            self._vmov(insn)
        elif m in STATUS:
            self._status(insn)
        elif m.startswith("v"):
            self._generic(insn)
        else:
            self._unknown(insn)

    # operand helpers ----------------------------------------------------------

    def _reg_value(self, r: Reg, insn: Insn) -> Taint:
        st = self.state
        if r.name == "pc":
            return CLEAN
        t = st.get(r.name)
        if not t.tainted:
            return CLEAN
        if r.shift is None:
            return t
        if r.shift_reg is not None:
            return Taint(t.labels | st.get(r.shift_reg).labels, None)
        n = r.shift_imm or 0
        if r.shift == "lsl" and t.bound is not None and n < 32:
            return Taint(t.labels, t.bound << n)
        if r.shift in ("lsr", "asr") and t.bound is not None:
            return Taint(t.labels, t.bound >> n)
        return Taint(t.labels, None)

    def _src(self, insn: Insn, i: int) -> Taint:
        op = insn.ops[i] if i < len(insn.ops) else None
        if isinstance(op, Reg):
            return self._reg_value(op, insn)
        return CLEAN

    def _const(self, insn: Insn, i: int) -> Optional[int]:
        op = insn.ops[i] if i < len(insn.ops) else None
        if isinstance(op, Imm):
            return op.value
        if isinstance(op, Reg) and op.shift is None:
            if op.name == "pc":
                return self.mode.pc_value(insn.address, insn.size)
            return self.state.consts.get(self.state.fam(op.name))
        return None

    def _addr_taint(self, mem: Mem) -> Taint:
        st = self.state
        parts: List[Taint] = []
        if mem.base and mem.base != "pc":
            parts.append(st.get(mem.base))
        if mem.index:
            t = st.get(mem.index)
            if t.tainted and mem.shift == "lsl" and t.bound is not None:
                t = Taint(t.labels, t.bound << mem.shift_imm)
            elif t.tainted and mem.shift:
                t = Taint(t.labels, t.bound >> mem.shift_imm if t.bound is not None and mem.shift in ("lsr", "asr") else None)
            parts.append(t)
        return summed(*parts)

    def _ptr_of(self, name: Optional[str]) -> Optional[Tuple[str, int]]:
        st = self.state
        fam = st.fam(name)
        return st.region_of(name) if (fam in st.frame_ptrs or fam == st.SP) else None

    def _writeback(self, insn: Insn, mem: Mem) -> None:
        if not (mem.writeback or mem.post) or mem.base is None:
            return
        st = self.state
        base = mem.base
        if mem.index is not None:
            t = union(st.get(base), st.get(mem.index))
            self._set_reg(base, t)
            return
        self._add_imm_to_reg(base, mem.disp, insn)

    def _add_imm_to_reg(self, reg: str, delta: int, insn: Insn) -> None:
        st = self.state
        fam = st.fam(reg)
        if fam == st.SP:
            st.rebase(fam, delta)
            c = st.consts.get(fam)
            if c is not None:
                st.consts[fam] = (c + delta) & MASK32
            return
        ptr = st.frame_ptrs.get(fam)
        c = st.consts.get(fam)
        t = st.get(reg)
        st.set(reg, Taint(t.labels, None) if t.tainted else CLEAN)
        if ptr is not None:
            st.frame_ptrs[fam] = (ptr[0], ptr[1] + delta)
        if c is not None:
            st.consts[fam] = (c + delta) & MASK32

    def _set_reg(self, name: str, t: Taint, ptr: Optional[Tuple[str, int]] = None, const: Optional[int] = None) -> None:
        st = self.state
        fam = st.fam(name)
        if fam == "pc":
            return self._pc_write(name, t)
        st.set(name, t)
        if ptr is not None and fam != st.SP:
            st.frame_ptrs[fam] = ptr
        if const is not None:
            st.consts[fam] = const & MASK32

    def _pc_write(self, name: str, t: Taint, how: str = "via register") -> None:
        if t.tainted:
            self._find_last(Finding(self._cur.address, "tainted-indirect-jump", how, t.labels))

    # findings -----------------------------------------------------------------

    def _find(self, insn: Insn, kind: str, detail: str, labels: Labels) -> None:
        self.findings.append(Finding(insn.address, kind, detail, labels))

    def _find_last(self, f: Finding) -> None:
        self.findings.append(f)

    def _find_addr(self, insn: Insn, kind: str, detail: str, t: Taint) -> None:
        p = self.policy
        if p.bounded_index_is_safe and t.bound is not None:
            if p.report_bounded:
                self._find(insn, "bounded-" + kind, f"{detail} (attacker contribution <= {t.bound:#x})", t.labels)
            return
        self._find(insn, kind, detail, t.labels)

    # loads / stores -----------------------------------------------------------

    def _load_value(self, insn: Insn, mem: Mem, width: int, signed: bool, disp_extra: int = 0) -> Tuple[Taint, Optional[Tuple[str, int]], Optional[int]]:
        st, p = self.state, self.policy
        if mem.base == "pc" and mem.index is None:
            c = insn.literal if disp_extra == 0 else None
            return CLEAN, None, c
        at = self._addr_taint(mem)
        if at.tainted and p.report_tainted_load_addr:
            self._find_addr(insn, "tainted-load-address", f"{insn.mnemonic} via {mem}", at)
        eff = Mem(mem.base, mem.index, (mem.disp if not mem.post else 0) + disp_extra, mem.shift, mem.shift_imm, mem.subtracted)
        b, off = st.resolve(eff)
        val, ptr = CLEAN, None
        if b is not None:
            val = st.mem_get(b, off)
            if width == 4:
                ptr = st.mem_ptrs.get((b, off))
        if at.tainted and p.taint_through_pointer:
            val = Taint(val.labels | at.labels, None)
        if val.tainted:
            if width < 4 and not signed:
                val = Taint(val.labels, (1 << (8 * width)) - 1 if val.bound is None else min(val.bound, (1 << (8 * width)) - 1))
            elif width < 4:
                val = Taint(val.labels, None)
        return val, ptr, None

    def _load(self, insn: Insn) -> None:
        m = insn.mnemonic
        dual = m in LOAD_DUAL
        mem = insn.mem(2 if dual else 1)
        if mem is None:
            return self._unknown(insn)
        width = LOAD_WIDTH.get(m, 4) if not dual else 4
        signed = m in LOAD_SIGNED
        regs = [insn.reg(0)] + ([insn.reg(1)] if dual else [])
        for k, rt in enumerate(regs):
            val, ptr, c = self._load_value(insn, mem, width, signed, 4 * k)
            if rt == "pc":
                if val.tainted:
                    self._find(insn, "tainted-indirect-jump", f"ldr pc, {mem}", val.labels)
                continue
            self._set_reg(rt, val, ptr, c)
        self._writeback(insn, mem)

    def _store(self, insn: Insn) -> None:
        m = insn.mnemonic
        dual = m in STORE_DUAL
        ex = m.startswith(("strex", "stlex"))
        first = 1 if ex else 0
        mem = insn.mem(first + (2 if dual else 1))
        if mem is None:
            return self._unknown(insn)
        st, p = self.state, self.policy
        at = self._addr_taint(mem)
        if at.tainted and p.report_tainted_store_addr:
            self._find_addr(insn, "tainted-store-address", f"{m} via {mem}", at)
        regs = [insn.reg(first)] + ([insn.reg(first + 1)] if dual else [])
        for k, rt in enumerate(regs):
            t = st.get(rt) if rt != "pc" else CLEAN
            eff = Mem(mem.base, mem.index, (mem.disp if not mem.post else 0) + 4 * k, mem.shift, mem.shift_imm, mem.subtracted)
            b, off = st.resolve(eff)
            if b is None:
                continue
            width = 1 if m.endswith("b") else 2 if m.endswith("h") else 4
            ptr = self._ptr_of(rt) if width == 4 else None
            st.mem_set(b, off, t, ptr)
            if (b, off) in st.ra_slots:
                if t.tainted:
                    if p.report_tainted_store_over_ra:
                        self._find(insn, "tainted-overwrite-of-saved-ra", f"store -> {mem}", t.labels)
                else:
                    st.ra_slots.discard((b, off))
            elif st.fam(rt) in st.ra_regs and width == 4:
                st.ra_slots.add((b, off))
        if ex:
            self._set_reg(insn.reg(0), CLEAN)
        self._writeback(insn, mem)

    # multiple registers -------------------------------------------------------

    def _push_regs(self, regs: Tuple[str, ...], size: int = 4) -> None:
        st = self.state
        n = len(regs)
        st.rebase(st.SP, -size * n)
        c = st.consts.get(st.SP)
        if c is not None:
            st.consts[st.SP] = (c - size * n) & MASK32
        for i, r in enumerate(regs):
            t = st.get(r) if r != "pc" else CLEAN
            ptr = self._ptr_of(r) if size == 4 else None
            st.mem_set(st.SP, size * i, t, ptr)
            st.ra_slots.discard((st.SP, size * i))
            if st.fam(r) in st.ra_regs:
                st.ra_slots.add((st.SP, size * i))

    def _pop_regs(self, insn: Insn, regs: Tuple[str, ...], size: int = 4) -> None:
        st = self.state
        n = len(regs)
        vals = []
        for i, r in enumerate(regs):
            slot = (st.SP, size * i)
            vals.append((r, st.mem_get(*slot), st.mem_ptrs.get(slot), slot in st.ra_slots))
            st.mem.pop(slot, None)
            st.mem_ptrs.pop(slot, None)
            st.ra_slots.discard(slot)
        st.rebase(st.SP, size * n)
        c = st.consts.get(st.SP)
        if c is not None:
            st.consts[st.SP] = (c + size * n) & MASK32
        for r, t, ptr, was_ra in vals:
            if r == "pc":
                if t.tainted:
                    self._find(insn, "tainted-return-address", "pop {.., pc}" + ("" if was_ra else " (slot not known to hold lr)"), t.labels)
                continue
            if r == "sp":
                st.set("sp", t)
                st.invalidate_base("sp")
                continue
            self._set_reg(r, t, ptr)
            if was_ra:
                st.ra_regs.add(st.fam(r))

    def _push(self, insn: Insn) -> None:
        rl = insn.reglist(0)
        if rl is None:
            return self._unknown(insn)
        self._push_regs(rl.regs)

    def _pop(self, insn: Insn) -> None:
        rl = insn.reglist(0)
        if rl is None:
            return self._unknown(insn)
        self._pop_regs(insn, rl.regs)

    def _vpush(self, insn: Insn) -> None:
        rl = insn.reglist(0)
        if rl:
            self._push_regs(rl.regs, 8 if rl.regs[0].startswith("d") else 4)

    def _vpop(self, insn: Insn) -> None:
        rl = insn.reglist(0)
        if rl:
            self._pop_regs(insn, rl.regs, 8 if rl.regs[0].startswith("d") else 4)

    def _ldm_addrs(self, m: str, n: int) -> List[int]:
        mode = m[-2:]
        if mode == "ia":
            return [4 * i for i in range(n)]
        if mode == "ib":
            return [4 * (i + 1) for i in range(n)]
        if mode == "da":
            return [-4 * (n - 1 - i) for i in range(n)]
        return [-4 * (n - i) for i in range(n)]

    def _ldm(self, insn: Insn) -> None:
        st = self.state
        base, rl = insn.reg(0), insn.reglist(1)
        if base is None or rl is None:
            return self._unknown(insn)
        offs = self._ldm_addrs(insn.mnemonic, len(rl.regs))
        bt = st.get(base)
        if bt.tainted:
            self._find_addr(insn, "tainted-load-address", f"{insn.mnemonic} via {base}", bt)
        loc = st.region_of(base)
        loaded = []
        for r, o in zip(rl.regs, offs):
            val, ptr, ra = CLEAN, None, False
            if loc is not None:
                val = st.mem_get(loc[0], loc[1] + o)
                ptr = st.mem_ptrs.get((loc[0], loc[1] + o))
                ra = (loc[0], loc[1] + o) in st.ra_slots
            if bt.tainted and self.policy.taint_through_pointer:
                val = Taint(val.labels | bt.labels, None)
            loaded.append((r, val, ptr, ra))
        if insn.writeback:
            self._add_imm_to_reg(base, 4 * len(rl.regs) * (1 if insn.mnemonic.endswith(("ia", "ib")) else -1), insn)
        for r, val, ptr, ra in loaded:
            if r == "pc":
                if val.tainted:
                    self._find(insn, "tainted-return-address" if ra else "tainted-indirect-jump", f"{insn.mnemonic} {{.., pc}}", val.labels)
                continue
            if r == base and insn.writeback:
                continue
            self._set_reg(r, val, ptr)
            if ra:
                st.ra_regs.add(st.fam(r))

    def _stm(self, insn: Insn) -> None:
        st = self.state
        base, rl = insn.reg(0), insn.reglist(1)
        if base is None or rl is None:
            return self._unknown(insn)
        offs = self._ldm_addrs(insn.mnemonic, len(rl.regs))
        bt = st.get(base)
        if bt.tainted:
            self._find_addr(insn, "tainted-store-address", f"{insn.mnemonic} via {base}", bt)
        loc = st.region_of(base)
        if loc is not None:
            for r, o in zip(rl.regs, offs):
                slot = (loc[0], loc[1] + o)
                t = st.get(r) if r != "pc" else CLEAN
                st.mem_set(*slot, t, self._ptr_of(r))
                if slot in st.ra_slots:
                    if t.tainted:
                        if self.policy.report_tainted_store_over_ra:
                            self._find(insn, "tainted-overwrite-of-saved-ra", f"{insn.mnemonic} -> {base}", t.labels)
                    else:
                        st.ra_slots.discard(slot)
                elif st.fam(r) in st.ra_regs:
                    st.ra_slots.add(slot)
        if insn.writeback:
            self._add_imm_to_reg(base, 4 * len(rl.regs) * (1 if insn.mnemonic.endswith(("ia", "ib")) else -1), insn)

    # data processing ----------------------------------------------------------

    def _operands(self, insn: Insn) -> Tuple[Optional[str], List[int]]:
        rd = insn.reg(0)
        n = len(insn.ops)
        if insn.mnemonic in ("rrx",) and n == 2:
            return rd, [1]
        if n == 2:
            return rd, [0, 1]
        return rd, list(range(1, n))

    def _mov(self, insn: Insn) -> None:
        st = self.state
        rd = insn.reg(0)
        if rd is None or len(insn.ops) != 2:
            return self._unknown(insn)
        src = insn.ops[1]
        t = self._src(insn, 1)
        if insn.mnemonic in NOT_COPY:
            t = Taint(t.labels, None)
        ptr = const = None
        if isinstance(src, Imm):
            const = (~src.value if insn.mnemonic in NOT_COPY else src.value) & MASK32
        elif isinstance(src, Reg) and src.shift is None and insn.mnemonic in COPY:
            if src.name == "pc":
                const = self.mode.pc_value(insn.address, insn.size)
            else:
                ptr = self._ptr_of(src.name)
                const = st.consts.get(st.fam(src.name))
        if rd == "pc":
            how = "mov pc, lr" if isinstance(src, Reg) and src.name == "lr" else f"mov pc, {src}"
            if t.tainted:
                kind = "tainted-return-address" if isinstance(src, Reg) and (src.name == "lr" or st.fam(src.name) in st.ra_regs) else "tainted-indirect-jump"
                self._find(insn, kind, how, t.labels)
            return
        if rd == "sp":
            if ptr is not None and ptr[0] == st.SP:
                st.rebase(st.SP, ptr[1])
                st.regs.pop(st.SP, None)
                return
            st.set("sp", t)
            return
        was_ra = isinstance(src, Reg) and st.fam(src.name) in st.ra_regs and src.shift is None
        self._set_reg(rd, t, ptr, const)
        if was_ra:
            st.ra_regs.add(st.fam(rd))
        if isinstance(src, Reg) and src.shift is None and insn.mnemonic in COPY and src.name not in ("sp", "pc"):
            st.alias(st.fam(rd), st.fam(src.name))
        if insn.sets_flags:
            st.set(FLAGS, Taint(t.labels, None))

    def _movt(self, insn: Insn) -> None:
        st = self.state
        rd, imm = insn.reg(0), insn.imm(1)
        if rd is None or imm is None:
            return self._unknown(insn)
        old = st.get(rd)
        c = st.consts.get(st.fam(rd))
        st.set(rd, Taint(old.labels, None) if old.tainted else CLEAN)
        if c is not None:
            st.consts[st.fam(rd)] = ((imm & 0xFFFF) << 16) | (c & 0xFFFF)

    def _extend(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd = insn.reg(0)
        if rd is None:
            return self._unknown(insn)
        if m in ZEXT or m in SEXT:
            t = self._src(insn, 1)
            if m in ZEXT:
                b = ZEXT[m]
                t = Taint(t.labels, b if t.bound is None else min(t.bound, b)) if t.tainted else CLEAN
            else:
                t = Taint(t.labels, None) if t.tainted else CLEAN
        else:
            rn, rm = self._src(insn, 1), self._src(insn, 2)
            if m in ZEXT_ADD and rm.tainted:
                rm = Taint(rm.labels, ZEXT_ADD[m] if rm.bound is None else min(rm.bound, ZEXT_ADD[m]))
            elif rm.tainted:
                rm = Taint(rm.labels, None)
            t = summed(rn, rm)
        self._set_reg(rd, t)

    def _alu(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd, srcs = self._operands(insn)
        if rd is None or not srcs:
            return self._unknown(insn)
        parts = [self._src(insn, i) for i in srcs]
        imm = next((insn.ops[i].value for i in srcs if isinstance(insn.ops[i], Imm)), None)
        rn_idx = srcs[0]
        rn = insn.ops[rn_idx] if rn_idx < len(insn.ops) else None
        rn_t = parts[0]
        labels: Labels = EMPTY
        for t in parts:
            labels |= t.labels
        if m in MUL:
            t = Taint(labels, None)
            for i in range(len(insn.ops)):
                r = insn.reg(i)
                if i == 0 or (m in ("smull", "umull", "smlal", "umlal", "umaal", "smlald", "smlsld") and i == 1):
                    if r:
                        self._set_reg(r, t)
            if insn.sets_flags:
                st.set(FLAGS, t)
            return
        bound: Optional[int] = None
        const: Optional[int] = None
        ptr: Optional[Tuple[str, int]] = None
        rn_c = self._const(insn, rn_idx) if rn is not None else None
        rm_c = self._const(insn, srcs[1]) if len(srcs) > 1 else None

        if m in ("add", "sub", "rsb", "adc", "sbc", "rsc"):
            t = summed(*parts)
            bound = t.bound if m not in ("rsb", "rsc") else None
            t = Taint(t.labels, bound)
            if m in ("add", "sub") and isinstance(rn, Reg) and rn.shift is None and imm is not None:
                d = imm if m == "add" else -imm
                if rd == "sp" and rn.name == "sp":
                    self._add_imm_to_reg("sp", d, insn)
                    if insn.sets_flags:
                        st.set(FLAGS, Taint(labels, None))
                    return
                loc = self._ptr_of(rn.name)
                if loc is not None:
                    ptr = (loc[0], loc[1] + d)
                if rn.name == "pc":
                    const = (self.mode.pc_value(insn.address, insn.size, align=(self.mode is Mode.THUMB)) + d) & MASK32
            if rn_c is not None and rm_c is not None:
                a, b = rn_c, rm_c
                const_val = {"add": a + b, "sub": a - b, "rsb": b - a}.get(m, None)
                const = const_val & MASK32 if const_val is not None else None
            if rd == "sp" and isinstance(rn, Reg) and rn.name != "sp":
                loc = self._ptr_of(rn.name)
                if loc is not None and loc[0] == st.SP and imm is not None:
                    st.rebase(st.SP, loc[1] + (imm if m == "add" else -imm))
                    st.regs.pop(st.SP, None)
                    return
        elif m == "and":
            if imm is not None:
                b_val = modified_imm_bound(imm)
                bound = b_val if b_val is None or rn_t.bound is None else min(b_val, rn_t.bound)
            else:
                bs = [t.bound for t in parts if t.tainted and t.bound is not None]
                bound = min(bs) if bs else None
            t = Taint(labels, bound if labels else None)
        elif m == "bic":
            t = Taint(labels, rn_t.bound if labels else None)
        elif m in ("orr", "eor", "orn"):
            t = summed(*parts)
            bound = t.bound if m != "orn" else None
            t = Taint(labels, bound if labels else None)
        elif m in SHIFT:
            src_t = parts[0]
            n = imm
            if m == "lsl" and n is not None and src_t.bound is not None and n < 32:
                bound = src_t.bound << n
            elif m in ("lsr", "asr") and n is not None and src_t.bound is not None:
                bound = src_t.bound >> n
            elif m == "rrx" and src_t.bound is not None:
                bound = src_t.bound >> 1
            t = Taint(labels, bound if labels else None)
            if n is not None and rn_c is not None:
                const = {"lsl": (rn_c << n) & MASK32, "lsr": (rn_c & MASK32) >> n,
                         "asr": (rn_c - (1 << 32) if rn_c & 0x80000000 else rn_c) >> n & MASK32,
                         "ror": ((rn_c >> n) | (rn_c << (32 - n))) & MASK32}.get(m)
        elif m == "clz":
            t = Taint(labels, 32 if labels else None)
        elif m in ("rev", "rev16", "revsh", "rbit"):
            t = Taint(labels, None)
        elif m in ("usat", "ssat"):
            sat = insn.imm(1)
            t = Taint(labels, ((1 << sat) - 1) if (sat is not None and m == "usat" and labels) else None)
        else:
            t = Taint(labels, None)

        if rd == "pc":
            if t.tainted:
                self._find(insn, "tainted-indirect-jump", f"{m} pc, ...", t.labels)
            return
        if rd == "sp":
            st.set("sp", t)
            return
        self._set_reg(rd, t, ptr, const)
        if insn.sets_flags:
            st.set(FLAGS, Taint(labels, None))

    def _bitfield(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd = insn.reg(0)
        if rd is None:
            return self._unknown(insn)
        if m == "ubfx":
            t = self._src(insn, 1)
            w = insn.imm(3) or 32
            t = Taint(t.labels, (1 << w) - 1) if t.tainted else CLEAN
        elif m == "sbfx":
            t = self._src(insn, 1)
            t = Taint(t.labels, None) if t.tainted else CLEAN
        elif m == "bfi":
            t = union(st.get(rd), self._src(insn, 1))
        else:
            old = st.get(rd)
            t = Taint(old.labels, old.bound) if old.tainted else CLEAN
        self._set_reg(rd, t)

    def _flags_only(self, insn: Insn) -> None:
        labels: Labels = EMPTY
        for i in range(len(insn.ops)):
            labels |= self._src(insn, i).labels
        self.state.set(FLAGS, Taint(labels, None))

    def _status(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        if m in ("mrs", "vmrs") and insn.reg(0):
            if insn.reg(0) == "apsr_nzcv":
                return
            st.set(insn.reg(0), Taint(st.get(FLAGS).labels, None) if st.get(FLAGS).tainted else CLEAN)
        elif m in ("msr", "vmsr"):
            st.set(FLAGS, Taint(self._src(insn, len(insn.ops) - 1).labels, None))

    # VFP -----------------------------------------------------------------------

    def _vload(self, insn: Insn) -> None:
        st = self.state
        if insn.mnemonic in VLDM:
            base, rl = insn.reg(0), insn.reglist(1)
            if base is None or rl is None:
                return self._unknown(insn)
            bt = st.get(base)
            if bt.tainted:
                self._find_addr(insn, "tainted-load-address", f"{insn.mnemonic} via {base}", bt)
            loc = st.region_of(base)
            size = 8 if rl.regs[0].startswith("d") else 4
            for i, r in enumerate(rl.regs):
                val = st.mem_get(loc[0], loc[1] + size * i) if loc else CLEAN
                st.set(r, union(val, bt) if bt.tainted else val)
            if insn.writeback:
                self._add_imm_to_reg(base, size * len(rl.regs), insn)
            return
        mem = insn.mem(len(insn.ops) - 1)
        if mem is None:
            return self._generic(insn)
        at = self._addr_taint(mem)
        if at.tainted:
            self._find_addr(insn, "tainted-load-address", f"{insn.mnemonic} via {mem}", at)
        b, off = st.resolve(mem)
        val = st.mem_get(b, off) if b is not None else CLEAN
        if at.tainted and self.policy.taint_through_pointer:
            val = union(val, at)
        for i in range(len(insn.ops) - 1):
            if insn.reg(i):
                st.set(insn.reg(i), val)
        self._writeback(insn, mem)

    def _vstore(self, insn: Insn) -> None:
        st = self.state
        if insn.mnemonic in VSTM:
            base, rl = insn.reg(0), insn.reglist(1)
            if base is None or rl is None:
                return self._unknown(insn)
            bt = st.get(base)
            if bt.tainted:
                self._find_addr(insn, "tainted-store-address", f"{insn.mnemonic} via {base}", bt)
            loc = st.region_of(base)
            size = 8 if rl.regs[0].startswith("d") else 4
            if loc:
                for i, r in enumerate(rl.regs):
                    st.mem_set(loc[0], loc[1] + size * i, st.get(r))
            if insn.writeback:
                self._add_imm_to_reg(base, size * len(rl.regs), insn)
            return
        mem = insn.mem(len(insn.ops) - 1)
        if mem is None:
            return self._generic(insn)
        at = self._addr_taint(mem)
        if at.tainted:
            self._find_addr(insn, "tainted-store-address", f"{insn.mnemonic} via {mem}", at)
        b, off = st.resolve(mem)
        if b is not None:
            t = union(*(st.get(insn.reg(i)) for i in range(len(insn.ops) - 1) if insn.reg(i)))
            st.mem_set(b, off, t)
        self._writeback(insn, mem)

    def _vmov(self, insn: Insn) -> None:
        st = self.state
        n = len(insn.ops)
        if n == 2:
            src = self._src(insn, 1)
            if insn.reg(0):
                st.set(insn.reg(0), Taint(src.labels, None) if src.tainted else CLEAN)
        elif n == 3:
            if insn.reg(0) and insn.reg(1) and insn.reg(2) and insn.reg(2).startswith("d"):
                t = st.get(insn.reg(2))
                st.set(insn.reg(0), Taint(t.labels, None) if t.tainted else CLEAN)
                st.set(insn.reg(1), Taint(t.labels, None) if t.tainted else CLEAN)
            elif insn.reg(0):
                st.set(insn.reg(0), union(self._src(insn, 1), self._src(insn, 2)))
        else:
            self._generic(insn)

    def _generic(self, insn: Insn) -> None:
        st = self.state
        rd = insn.reg(0)
        if rd is None:
            return
        t = union(*(self._src(insn, i) for i in range(1, len(insn.ops))))
        st.set(rd, t)

    # control transfer ----------------------------------------------------------

    def _call(self, insn: Insn) -> None:
        st, p = self.state, self.policy
        op = insn.ops[0] if insn.ops else None
        if isinstance(op, Reg):
            t = st.get(op.name)
            if t.tainted:
                self._find(insn, "tainted-indirect-call", f"{insn.mnemonic} {op.name}", t.labels)
        arg_labels: Labels = EMPTY
        for r in self.abi.arg_regs + self.abi.fp_arg_regs:
            arg_labels |= st.get(r).labels
        for k in range(0, 16, 4):
            arg_labels |= st.mem_get(st.SP, k).labels
        for fam in self.abi.caller_saved:
            st.set(fam, CLEAN)
        st.set(FLAGS, CLEAN)
        st.ra_regs.discard("lr")
        st.consts["lr"] = insn.next_ip | (1 if self.mode is Mode.THUMB else 0)
        if p.calls_propagate_to_return and arg_labels:
            for r in self.abi.ret_regs + self.abi.fp_ret_regs:
                st.set(r, Taint(arg_labels, None))
        st.mem = {k: v for k, v in st.mem.items() if not (k[0] == st.SP and k[1] < 0)}
        st.ranges = [r for r in st.ranges if not (r[0] == st.SP and r[2] <= 0)]
        st.mem_ptrs = {k: v for k, v in st.mem_ptrs.items() if not (k[0] == st.SP and k[1] < 0)}

    def _bx(self, insn: Insn) -> None:
        st = self.state
        r = insn.reg(0)
        if r is None:
            return
        t = st.get(r)
        if t.tainted:
            ret = r == "lr" or st.fam(r) in st.ra_regs
            self._find(insn, "tainted-return-address" if ret else "tainted-indirect-jump", f"bx {r}", t.labels)

    def _branch(self, insn: Insn) -> None:
        if not self.policy.report_tainted_branch:
            return
        st = self.state
        if insn.mnemonic in CBZ:
            t = st.get(insn.reg(0))
        else:
            t = st.get(FLAGS) if insn.conditional else CLEAN
        if t.tainted:
            self._find(insn, "tainted-branch-condition", f"{insn.mnemonic}{insn.cond or ''}", t.labels)

    def _table_branch(self, insn: Insn) -> None:
        mem = insn.mem(0)
        if mem is None or mem.index is None:
            return
        t = self.state.get(mem.index)
        if t.tainted:
            self._find_addr(insn, "tainted-indirect-jump", f"{insn.mnemonic} index {mem.index}", t)

    def _syscall(self, insn: Insn) -> None:
        st, p, sm = self.state, self.policy, self.sys
        imm = insn.imm(0) or 0
        if imm >= OABI_BASE:
            nr: Optional[int] = imm - OABI_BASE
        else:
            nr = st.consts.get(sm.nr_reg)
        name = sm.numbers.get(nr, f"sys_{nr}") if nr is not None else "sys_?"
        if imm < OABI_BASE and st.get(sm.nr_reg).tainted:
            self._find(insn, "tainted-syscall-number", name, st.get(sm.nr_reg).labels)
        if p.report_syscall_args:
            for r in sm.arg_regs:
                if st.get(r).tainted:
                    self._find(insn, "tainted-syscall-arg", f"{name}({r})", st.get(r).labels)
        for fam in sm.clobbered:
            st.set(fam, CLEAN)
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
        if rd is None or rd in ("pc", "sp"):
            return
        labels: Labels = EMPTY
        for i in range(len(insn.ops)):
            labels |= self._src(insn, i).labels
        self.state.set(rd, Taint(labels, None))
