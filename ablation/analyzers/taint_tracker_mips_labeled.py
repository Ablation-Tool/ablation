"""Forward labeled-taint tracker for MIPS32 (o32) and MIPS64 (n64) instruction streams.

State
-----
* ``regs``      canonical register -> Taint. GPRs are whole values; ``hi``/``lo``
                and ``fcc`` are tracked like registers.
* ``mem``       (region, offset) -> Taint. The stack frame is region ``$29`` (sp).
* ``ranges``, ``mem_ptrs``, ``eq``, ``ra_regs``/``ra_slots`` as in armtaint.

MIPS specifics
--------------
* **Branch delay slots.** ``jal``/``jalr``/``jr``/``b*`` (non-Release-6) execute
  the following instruction before transferring control. The tracker defers the
  transfer's effect until after its slot; a branch-likely slot is joined
  path-insensitively.
* **MIPS64 narrowing.** 32-bit-result ops (``addu``, ``sll``, ``lw``, etc.)
  sign-extend from bit 31. A bound survives only if it is below 2**31; pointer
  facts never survive narrowing.
* **Returns.** ``jr $ra`` (and ``jr`` of any register in ra_regs). The saved-ra
  slot is whatever ``sw/sd $ra`` wrote.

Feed instruction streams from ``from_listing`` / ``from_objdump`` / ``from_capstone``
in ``insn_mips``. For binary RE over ELF files use taint_tracker_mips.py.

Usage:
    from ablation.analyzers.taint_tracker_mips_labeled import TaintTracker, Mode, Policy
    from ablation.analyzers.insn_mips import from_listing

    t = TaintTracker(Mode.MIPS32)
    t.taint_memory("$a0", 0, "buf", 4096)
    findings = t.run(list(from_listing(text, Mode.MIPS32)))
"""
from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .insn_mips import Imm, Insn, Mem, Reg
from .isa_mips import (
    A3, ARITH, BITFIELD, BRANCH_COND, BRANCH_LIKELY, CALL_DIRECT, CALL_INDIRECT, COMPACT_CALL, COMPACT_COND,
    COMPACT_JUMP, COND_MOVE, CONST_WRITE, COPY_FULL, FP_BRANCH, FP_LOAD, FP_MOVE_FROM, FP_MOVE_TO, FP_STORE,
    HILO_MOVE, INPUT_SYSCALLS, JUMP, JUMP_REG, LOAD, LOAD_PARTIAL, LOGIC, LUI, MISC, MUL_HILO, MUL_RD, NARROW32, NOP,
    RA, SELECT, SET, SHIFT_IMM, SHIFT_VAR, SIGNEXT, SP, STORE, STORE_COND, SYSCALL, UNKNOWN_WRITE, ZERO, Abi, AbiModel,
    Mode, abi_for, has_delay_slot, is_gpr, pretty, syscall_model,
)

log = logging.getLogger("mipstaint")
Labels = FrozenSet[str]
EMPTY: Labels = frozenset()


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
        if name is None or name == ZERO:
            return CLEAN
        return self.regs.get(name, CLEAN)

    def set(self, name: Optional[str], t: Taint) -> None:
        if name is None or name == ZERO:
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

    def resolve(self, mem: Mem) -> Tuple[Optional[str], int]:
        if mem.index is not None:
            return None, 0
        loc = self.region_of(mem.base)
        if loc is None:
            return None, 0
        return loc[0], loc[1] + mem.disp

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

    def snapshot(self, abi: Abi) -> Dict[str, str]:
        return {pretty(r, abi): str(t) for r, t in sorted(self.regs.items(), key=lambda kv: (len(kv[0]), kv[0]))}

    # ------------------------------------------------------------------
    # Lattice operations for flow-sensitive CFG analysis
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
        for r in set(self.regs) | set(other.regs):
            a = self.regs.get(r, CLEAN)
            b = other.regs.get(r, CLEAN)
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
                out.regs[r] = t
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
    def __init__(self, mode: Mode = Mode.MIPS32, abi: Optional[Abi] = None, policy: Optional[Policy] = None):
        self.mode = mode
        self.abi: AbiModel = abi_for(abi or Abi.default_for(mode))
        self.policy = policy or Policy()
        self.sys = syscall_model(mode)
        self.state = TaintState(mode)
        self.findings: List[Finding] = []
        self.trace: List[Tuple[Insn, Dict[str, str]]] = []
        self.unknown: Set[str] = set()
        self._pending: Optional[Insn] = None
        self._cur: Optional[Insn] = None
        if self.policy.entry_is_function_start:
            self.state.ra_regs.add(RA)

    # public API -------------------------------------------------------

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
                self.trace.append((insn, self.state.snapshot(self.abi.abi)))
        if self._pending is not None:
            self._transfer(self._pending)
            self._pending = None
        return self.findings

    def _canon(self, reg: str) -> str:
        return canon_reg(reg, self.abi.abi) or reg

    # dispatcher -------------------------------------------------------

    def step(self, insn: Insn) -> None:
        if self._pending is not None:
            branch = self._pending
            self._pending = None
            if branch.mnemonic in BRANCH_LIKELY:
                before = copy.deepcopy(self.state)
                self._exec(insn)
                self._merge(before)
            else:
                self._exec(insn)
            self._transfer(branch)
            return
        if has_delay_slot(insn.mnemonic):
            self._branch_condition(insn)
            self._pending = insn
            return
        self._exec(insn)

    def _merge(self, other: TaintState) -> None:
        st = self.state
        for r in set(st.regs) | set(other.regs):
            a, b = st.regs.get(r, CLEAN), other.regs.get(r, CLEAN)
            if a == b:
                continue
            bound = None if (a.tainted and b.tainted and (a.bound is None or b.bound is None)) else \
                (max(a.bound or 0, b.bound or 0) if a.tainted and b.tainted else (a.bound if a.tainted else b.bound))
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
        if m in NOP:
            return
        if m in COMPACT_CALL or m in COMPACT_JUMP or m in COMPACT_COND:
            self._branch_condition(insn)
            self._transfer(insn)
        elif m in LOAD:
            self._load(insn)
        elif m in STORE:
            self._store(insn)
        elif m in COPY_FULL:
            self._copy(insn)
        elif m in LUI:
            self._lui(insn)
        elif m in ARITH or m in LOGIC or m in SHIFT_IMM or m in SHIFT_VAR or m in SET or m in SIGNEXT or m in MISC or m == "li32":
            self._alu(insn)
        elif m in BITFIELD:
            self._bitfield(insn)
        elif m in COND_MOVE or m in SELECT:
            self._cmov(insn)
        elif m in MUL_HILO:
            self._mul_hilo(insn)
        elif m in MUL_RD:
            self._mul_rd(insn)
        elif m in HILO_MOVE:
            self._hilo(insn)
        elif m in SYSCALL:
            self._syscall(insn)
        elif m in CONST_WRITE:
            st.set(insn.reg(0), CLEAN)
        elif m in UNKNOWN_WRITE:
            self._unknown(insn)
        elif m in FP_LOAD:
            self._fp_load(insn)
        elif m in FP_STORE:
            self._fp_store(insn)
        elif m in FP_MOVE_TO or m in FP_MOVE_FROM:
            self._fp_move(insn)
        elif m in ("c.cond", "cmp.cond"):
            self._fp_cmp(insn)
        elif (m.endswith(".fp") or m.startswith(("mov.", "cvt.", "abs.", "neg.", "sqrt.", "trunc.", "round.", "ceil.", "floor.", "madd.", "msub.", "nmadd.", "nmsub.", "sel", "min", "max", "class"))):
            self._generic(insn)
        else:
            self._unknown(insn)

    # helpers ----------------------------------------------------------

    def _narrow(self, t: Taint) -> Taint:
        if self.mode is Mode.MIPS32 or not t.tainted:
            return t
        return Taint(t.labels, t.bound if (t.bound is not None and t.bound < (1 << 31)) else None)

    def _ptr_of(self, name: Optional[str]) -> Optional[Tuple[str, int]]:
        st = self.state
        return st.region_of(name) if (name in st.frame_ptrs or name == SP) else None

    def _const(self, insn: Insn, i: int) -> Optional[int]:
        op = insn.ops[i] if i < len(insn.ops) else None
        if isinstance(op, Imm):
            return op.value
        if isinstance(op, Reg):
            return 0 if op.name == ZERO else self.state.consts.get(op.name)
        return None

    def _set(self, name: Optional[str], t: Taint, ptr: Optional[Tuple[str, int]] = None, const: Optional[int] = None) -> None:
        st = self.state
        if name is None or name == ZERO:
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
            st.consts[name] = const & self.mode.mask

    def _add_imm_to_reg(self, reg: str, delta: int) -> None:
        st = self.state
        if reg == SP:
            st.rebase(SP, delta)
            c = st.consts.get(SP)
            if c is not None:
                st.consts[SP] = (c + delta) & self.mode.mask
            return
        ptr, c, t = st.frame_ptrs.get(reg), st.consts.get(reg), st.get(reg)
        st.set(reg, Taint(t.labels, None) if t.tainted else CLEAN)
        if ptr is not None:
            st.frame_ptrs[reg] = (ptr[0], ptr[1] + delta)
        if c is not None:
            st.consts[reg] = (c + delta) & self.mode.mask

    def _find(self, insn: Insn, kind: str, detail: str, labels: Labels) -> None:
        self.findings.append(Finding(insn.address, kind, detail, labels))

    def _find_addr(self, insn: Insn, kind: str, detail: str, t: Taint) -> None:
        p = self.policy
        if p.bounded_index_is_safe and t.bound is not None:
            if p.report_bounded:
                self._find(insn, "bounded-" + kind, f"{detail} (attacker contribution <= {t.bound:#x})", t.labels)
            return
        self._find(insn, kind, detail, t.labels)

    def _p(self, r: Optional[str]) -> str:
        return pretty(r, self.abi.abi) if r else "?"

    # loads / stores ---------------------------------------------------

    def _load(self, insn: Insn) -> None:
        st, p, m = self.state, self.policy, insn.mnemonic
        rt, mem = insn.reg(0), insn.mem(1)
        if rt is None or mem is None:
            return self._unknown(insn)
        width, signed = LOAD[m]
        at = st.get(mem.base) if mem.base != ZERO else CLEAN
        if mem.index:
            at = summed(at, st.get(mem.index))
        if at.tainted and p.report_tainted_load_addr:
            self._find_addr(insn, "tainted-load-address", f"{m} via {self._p(mem.base)}", at)
        b, off = st.resolve(mem)
        val, ptr = CLEAN, None
        if b is not None:
            val = st.mem_get(b, off)
            if width == self.mode.ptr_bytes:
                ptr = st.mem_ptrs.get((b, off))
        if at.tainted and p.taint_through_pointer:
            val = Taint(val.labels | at.labels, None)
        if val.tainted:
            if m in LOAD_PARTIAL:
                val = union(val, st.get(rt))
            elif not signed and width < 8:
                mx = (1 << (8 * width)) - 1
                val = Taint(val.labels, mx if val.bound is None else min(val.bound, mx))
            elif signed and width < 4:
                val = Taint(val.labels, None)
            elif width == 4:
                val = self._narrow(val)
        was_ra = b is not None and (b, off) in st.ra_slots and width == self.mode.ptr_bytes
        self._set(rt, val, ptr)
        if was_ra or rt == RA:
            st.ra_regs.add(rt)

    def _store(self, insn: Insn) -> None:
        st, p, m = self.state, self.policy, insn.mnemonic
        rt, mem = insn.reg(0), insn.mem(1)
        if rt is None or mem is None:
            return self._unknown(insn)
        width = STORE[m]
        at = st.get(mem.base) if mem.base != ZERO else CLEAN
        if at.tainted and p.report_tainted_store_addr:
            self._find_addr(insn, "tainted-store-address", f"{m} via {self._p(mem.base)}", at)
        t = st.get(rt)
        b, off = st.resolve(mem)
        if b is not None:
            ptr = self._ptr_of(rt) if width == self.mode.ptr_bytes else None
            st.mem_set(b, off, t, ptr)
            if (b, off) in st.ra_slots:
                if t.tainted:
                    if p.report_tainted_store_over_ra:
                        self._find(insn, "tainted-overwrite-of-saved-ra", f"{m} -> {mem.disp}({self._p(mem.base)})", t.labels)
                else:
                    st.ra_slots.discard((b, off))
            elif rt in st.ra_regs and width == self.mode.ptr_bytes:
                st.ra_slots.add((b, off))
        if m in STORE_COND:
            st.set(rt, CLEAN)

    # data processing --------------------------------------------------

    def _copy(self, insn: Insn) -> None:
        st = self.state
        rd, rs = insn.reg(0), insn.reg(1)
        if rd is None or rs is None:
            return self._unknown(insn)
        if insn.mnemonic in ("or", "daddu", "dadd") and len(insn.ops) == 3 and insn.reg(2) != ZERO and insn.reg(1) != ZERO:
            return self._alu(insn)
        if insn.mnemonic in ("or", "daddu", "dadd") and insn.reg(1) == ZERO:
            rs = insn.reg(2)
        t = st.get(rs)
        was_ra = rs in st.ra_regs
        self._set(rd, t, self._ptr_of(rs), 0 if rs == ZERO else st.consts.get(rs))
        if was_ra:
            st.ra_regs.add(rd)
        if rs not in (ZERO, SP) and rd != SP:
            st.alias(rd, rs)

    def _lui(self, insn: Insn) -> None:
        rd, imm = insn.reg(0), insn.imm(1)
        if rd is None or imm is None:
            return self._unknown(insn)
        v = (imm & 0xFFFF) << 16
        if self.mode is Mode.MIPS64 and v & 0x80000000:
            v |= 0xFFFFFFFF00000000
        self._set(rd, CLEAN, None, v)

    def _alu(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd = insn.reg(0)
        if rd is None:
            return self._unknown(insn)
        n = len(insn.ops)
        srcs = list(range(1, n)) if n >= 3 else [0, 1]
        parts = [st.get(insn.reg(i)) if insn.reg(i) else CLEAN for i in srcs]
        imm = next((insn.imm(i) for i in srcs if insn.imm(i) is not None), None)
        rs = insn.reg(srcs[0])
        rs_t = parts[0]
        labels: Labels = EMPTY
        for t in parts:
            labels |= t.labels
        bound: Optional[int] = None
        const: Optional[int] = None
        ptr: Optional[Tuple[str, int]] = None
        cs_ = [self._const(insn, i) for i in srcs]

        if m in ARITH or m == "li32":
            t = summed(*parts)
            bound = t.bound
            if m in ("sub", "subu", "dsub", "dsubu") and rs == ZERO:
                bound = None
            t = Taint(t.labels, bound)
            if all(c is not None for c in cs_):
                a, b = cs_[0], cs_[1] if len(cs_) > 1 else 0
                const = (a + b) if m not in ("sub", "subu", "dsub", "dsubu") else (a - b)
            if m in ("addiu", "daddiu", "addi", "daddi") and imm is not None and rs is not None:
                if rd == SP and rs == SP:
                    self._add_imm_to_reg(SP, imm)
                    return
                loc = self._ptr_of(rs)
                if loc is not None:
                    ptr = (loc[0], loc[1] + imm)
            elif m in ("addu", "daddu", "add", "dadd") and n == 3:
                r1, r2 = insn.reg(1), insn.reg(2)
                for a, b_r in ((r1, r2), (r2, r1)):
                    loc = self._ptr_of(a)
                    try:
                        cb = self._const(insn, insn.ops.index(Reg(b_r))) if b_r else None
                    except ValueError:
                        cb = None
                    if loc is not None and cb is not None:
                        ptr = (loc[0], loc[1] + cb)
                        break
                if rd == SP and ptr is not None and ptr[0] == SP:
                    self._set(SP, CLEAN, ptr)
                    return
        elif m == "andi":
            bound = imm if imm is not None else None
            if rs_t.bound is not None and bound is not None:
                bound = min(bound, rs_t.bound)
            t = Taint(labels, bound if labels else None)
            if cs_[0] is not None and imm is not None:
                const = cs_[0] & imm
        elif m == "and":
            bs = [t.bound for t in parts if t.tainted and t.bound is not None]
            t = Taint(labels, min(bs) if bs else None)
        elif m in ("ori", "xori"):
            t = Taint(labels, (rs_t.bound + imm) if (rs_t.bound is not None and imm is not None and labels) else None)
            if cs_[0] is not None and imm is not None:
                const = (cs_[0] | imm) if m == "ori" else (cs_[0] ^ imm)
        elif m in ("or", "xor"):
            t = summed(*parts)
        elif m == "nor":
            t = Taint(labels, None)
        elif m in SHIFT_IMM:
            sh = (imm or 0) + (32 if m.endswith("32") else 0)
            if m in ("sll", "dsll", "dsll32") and rs_t.bound is not None:
                bound = rs_t.bound << sh
            elif m in ("srl", "sra", "dsrl", "dsra", "dsrl32", "dsra32") and rs_t.bound is not None:
                bound = rs_t.bound >> sh
            elif m in ("srl", "dsrl", "dsrl32") and rs_t.tainted and sh > 0:
                width = 32 if m == "srl" else 64
                bound = (1 << (width - sh)) - 1
            t = Taint(labels, bound if labels else None)
            if cs_[0] is not None:
                c = cs_[0] & self.mode.mask
                const = {"sll": (c << sh), "dsll": (c << sh), "dsll32": (c << sh),
                         "srl": c >> sh, "dsrl": c >> sh, "dsrl32": c >> sh}.get(m)
        elif m in SHIFT_VAR:
            t = Taint(labels, None)
        elif m in SET:
            t = Taint(labels, 1 if labels else None)
        elif m in SIGNEXT:
            t = Taint(labels, None)
        elif m in ("clz", "clo", "dclz", "dclo"):
            t = Taint(labels, (64 if m.startswith("d") else 32) if labels else None)
        else:
            t = Taint(labels, None)

        if m in NARROW32:
            t = self._narrow(t)
            ptr = None
        elif t.tainted and t.bound != bound and bound is not None:
            t = Taint(t.labels, bound)
        if rd == SP and (m not in ARITH):
            st.set(SP, t)
            return
        self._set(rd, t, ptr, const)

    def _bitfield(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd, rs = insn.reg(0), insn.reg(1)
        if rd is None or rs is None:
            return self._unknown(insn)
        size = insn.imm(3) or 32
        if m.startswith(("ext", "dext")):
            if m in ("dextm",):
                size += 32
            t = st.get(rs)
            t = Taint(t.labels, (1 << size) - 1) if t.tainted else CLEAN
        else:
            t = union(st.get(rd), st.get(rs))
        self._set(rd, self._narrow(t) if m in NARROW32 else t)

    def _cmov(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd, rs, rt = insn.reg(0), insn.reg(1), insn.reg(2)
        if rd is None:
            return self._unknown(insn)
        if m in COND_MOVE:
            old, new = st.get(rd), st.get(rs)
            t = Taint(old.labels | new.labels, None if (old.tainted and new.tainted) else (new.bound if new.tainted else old.bound))
            if self.policy.report_tainted_branch and st.get(rt).tainted:
                self._find(insn, "tainted-branch-condition", f"{m} on {self._p(rt)}", st.get(rt).labels)
        else:
            t = st.get(rs)
        self._set(rd, t)

    def _mul_hilo(self, insn: Insn) -> None:
        st = self.state
        t = union(*(st.get(insn.reg(i)) for i in range(len(insn.ops)) if insn.reg(i)))
        if insn.mnemonic.startswith(("madd", "msub")):
            t = union(t, st.get("hi"), st.get("lo"))
        st.set("hi", t)
        st.set("lo", t)

    def _mul_rd(self, insn: Insn) -> None:
        st = self.state
        rd = insn.reg(0)
        t = union(*(st.get(insn.reg(i)) for i in range(1, len(insn.ops)) if insn.reg(i)))
        self._set(rd, self._narrow(t) if insn.mnemonic in NARROW32 else t)

    def _hilo(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        r = insn.reg(0)
        if m == "mfhi":
            self._set(r, st.get("hi"))
        elif m == "mflo":
            self._set(r, st.get("lo"))
        elif m == "mthi":
            st.set("hi", st.get(r))
        else:
            st.set("lo", st.get(r))

    # FP ---------------------------------------------------------------

    def _fp_load(self, insn: Insn) -> None:
        st = self.state
        ft, mem = insn.reg(0), insn.mem(1)
        if ft is None or mem is None:
            return self._unknown(insn)
        at = st.get(mem.base)
        if mem.index:
            at = summed(at, st.get(mem.index))
        if at.tainted:
            self._find_addr(insn, "tainted-load-address", f"{insn.mnemonic} via {self._p(mem.base)}", at)
        b, off = st.resolve(mem)
        val = st.mem_get(b, off) if b is not None else CLEAN
        st.set(ft, union(val, at) if (at.tainted and self.policy.taint_through_pointer) else Taint(val.labels, None) if val.tainted else CLEAN)

    def _fp_store(self, insn: Insn) -> None:
        st = self.state
        ft, mem = insn.reg(0), insn.mem(1)
        if ft is None or mem is None:
            return self._unknown(insn)
        at = st.get(mem.base)
        if at.tainted:
            self._find_addr(insn, "tainted-store-address", f"{insn.mnemonic} via {self._p(mem.base)}", at)
        b, off = st.resolve(mem)
        if b is not None:
            st.mem_set(b, off, st.get(ft))

    def _fp_move(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rt, fs = insn.reg(0), insn.reg(1)
        if rt is None or fs is None:
            return self._unknown(insn)
        if m in FP_MOVE_TO:
            st.set(fs, Taint(st.get(rt).labels, None) if st.get(rt).tainted else CLEAN)
        else:
            t = st.get(fs)
            self._set(rt, self._narrow(Taint(t.labels, None)) if t.tainted else CLEAN)

    def _fp_cmp(self, insn: Insn) -> None:
        st = self.state
        regs = [insn.reg(i) for i in range(len(insn.ops)) if insn.reg(i)]
        t = union(*(st.get(r) for r in regs))
        if insn.mnemonic == "cmp.cond":
            st.set(regs[0], t)
        else:
            st.set("fcc", t)

    def _generic(self, insn: Insn) -> None:
        st = self.state
        rd = insn.reg(0)
        if rd is None:
            return
        st.set(rd, union(*(st.get(insn.reg(i)) for i in range(1, len(insn.ops)) if insn.reg(i))))

    # control transfer -------------------------------------------------

    def _branch_condition(self, insn: Insn) -> None:
        if not self.policy.report_tainted_branch:
            return
        st, m = self.state, insn.mnemonic
        if m in BRANCH_COND or m in COMPACT_COND:
            t = union(*(st.get(insn.reg(i)) for i in range(len(insn.ops)) if insn.reg(i)))
        elif m in FP_BRANCH:
            t = st.get("fcc") if m in ("bc1t", "bc1f", "bc1tl", "bc1fl") else st.get(insn.reg(0))
        else:
            return
        if t.tainted:
            self._find(insn, "tainted-branch-condition", m, t.labels)

    def _transfer(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        if m in CALL_DIRECT or m in COMPACT_CALL:
            self._call(insn, None)
        elif m in CALL_INDIRECT or m == "jialc":
            self._call(insn, insn.reg(1) if len(insn.ops) == 2 else insn.reg(0))
        elif m in JUMP_REG or m == "jic" or m == "jrc":
            r = insn.reg(0)
            t = st.get(r)
            if t.tainted:
                ret = r == RA or r in st.ra_regs
                self._find(insn, "tainted-return-address" if ret else "tainted-indirect-jump", f"{m} {self._p(r)}", t.labels)

    def _call(self, insn: Insn, target_reg: Optional[str]) -> None:
        st, p, ab = self.state, self.policy, self.abi
        if target_reg is not None and st.get(target_reg).tainted:
            self._find(insn, "tainted-indirect-call", f"{insn.mnemonic} {self._p(target_reg)}", st.get(target_reg).labels)
        arg_labels: Labels = EMPTY
        for r in ab.arg_regs + ab.fp_arg_regs:
            arg_labels |= st.get(r).labels
        for k in range(ab.stack_arg_base, ab.stack_arg_base + 4 * self.mode.ptr_bytes, self.mode.ptr_bytes):
            arg_labels |= st.mem_get(SP, k).labels
        link = insn.reg(0) if (insn.mnemonic in CALL_INDIRECT and len(insn.ops) == 2) else RA
        for r in ab.caller_saved:
            st.set(r, CLEAN)
        st.ra_regs.discard(link)
        st.consts[link] = insn.next_ip + (4 if has_delay_slot(insn.mnemonic) else 0)
        if p.calls_propagate_to_return and arg_labels:
            for r in ab.ret_regs + ab.fp_ret_regs:
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
                    self._find(insn, "tainted-syscall-arg", f"{name}({self._p(r)})", st.get(r).labels)
        st.set(sm.err_reg, CLEAN)
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
        if rd is None or rd in (ZERO, SP):
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


# convenience re-export so callers can do `from .isa_mips import canon_reg`
from .isa_mips import canon_reg  # noqa: E402,F401
