"""Forward labeled-taint tracker for 32-/64-bit PowerPC.

Labeled-taint model: Taint(labels: FrozenSet[str], bound: Optional[int]).
TaintState exposes copy/join/same_as for CFG forward-worklist fixpoint.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .insn_ppc import Imm, Insn, Mem, Reg
from .isa_ppc import (
    ARITH, BCC, BCC_CTR, BCC_CTRL, BCC_LR, BDNZ, BRANCH, CALL, CALL_CTR, CALL_LR, CMP, COPY, COUNT, CR_LOGIC, CR_MOVE,
    FP_LOAD, FP_MOVE_GPR, FP_STORE, INPUT_SYSCALLS, INSERT, ISEL, JUMP_CTR, LI, LOAD, LOAD_MULTI, LOGIC, MISC, MUL_DIV,
    NOP, RETURN, ROTATE_D, ROTATE_W, SHIFT_SIGNED_IMM, SHIFT_VAR, SIGNEXT, SP, SPR_MOVE, STORE, STORE_MULTI, SYSCALL,
    Abi, AbiModel, Mode, abi_for, canon_reg, family, is_gpr, mask32, syscall_model,
)

log = logging.getLogger("taint_tracker_ppc_labeled")
Labels = FrozenSet[str]
EMPTY: Labels = frozenset()
M32, M64 = 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF


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


def capped(t: Taint, mx: int) -> Taint:
    if not t.tainted:
        return CLEAN
    return Taint(t.labels, mx if t.bound is None else min(t.bound, mx))


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

    def copy(self) -> "TaintState":
        return TaintState(
            mode=self.mode, regs=dict(self.regs), mem=dict(self.mem),
            ranges=list(self.ranges), consts=dict(self.consts),
            frame_ptrs=dict(self.frame_ptrs), mem_ptrs=dict(self.mem_ptrs),
            ra_slots=set(self.ra_slots), ra_regs=set(self.ra_regs),
            eq={k: set(v) for k, v in self.eq.items()}, _next_region=self._next_region,
        )

    def join(self, other: "TaintState", widen: bool = False) -> "TaintState":
        merged_regs = dict(self.regs)
        for r, t in other.regs.items():
            if r in merged_regs:
                merged_regs[r] = Taint(merged_regs[r].labels | t.labels, None)
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
            mode=self.mode,
            regs=merged_regs,
            mem=merged_mem,
            ranges=merged_ranges,
            consts=merged_consts,
            frame_ptrs=merged_frame_ptrs,
            mem_ptrs=merged_mem_ptrs,
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
        if name is None:
            return CLEAN
        return self.regs.get(family(name), CLEAN)

    def set(self, name: Optional[str], t: Taint) -> None:
        if name is None:
            return
        fam = family(name)
        self.consts.pop(fam, None)
        self.frame_ptrs.pop(fam, None)
        self.unalias(fam)
        self.ra_regs.discard(fam)
        if t.tainted or t.bound is not None:
            self.regs[fam] = t
        else:
            self.regs.pop(fam, None)
        if fam == SP:
            self.invalidate_base(SP)

    def taint_reg(self, name: str, label: str) -> None:
        fam = family(name)
        cur = self.regs.get(fam, CLEAN)
        self.regs[fam] = Taint(cur.labels | {label}, cur.bound)

    def resolve(self, mem: Mem) -> Tuple[Optional[str], int]:
        if mem.index is None:
            loc = self.region_of(mem.base)
            return (loc[0], loc[1] + mem.disp) if loc else (None, 0)
        for a, b in ((mem.base, mem.index), (mem.index, mem.base)):
            loc = self.region_of(a)
            c = 0 if b is None else self.consts.get(b)
            if loc is not None and c is not None:
                return loc[0], loc[1] + c
        return None, 0

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
        return {r: str(t) for r, t in sorted(self.regs.items(), key=lambda kv: (len(kv[0]), kv[0]))}


class TaintTracker:
    def __init__(self, mode: Mode = Mode.PPC64, abi: Optional[Abi] = None, policy: Optional[Policy] = None, little: bool = False):
        self.mode = mode
        self.abi: AbiModel = abi_for(abi or Abi.default_for(mode, little))
        self.policy = policy or Policy()
        self.sys = syscall_model(mode)
        self.state = TaintState(mode)
        self.findings: List[Finding] = []
        self.trace: List[Tuple[Insn, Dict[str, str]]] = []
        self.unknown: Set[str] = set()
        if self.policy.entry_is_function_start:
            self.state.ra_regs.add("lr")

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
        return self.findings

    def _canon(self, reg: str) -> str:
        return canon_reg(reg) or reg

    def step(self, insn: Insn) -> None:
        m, st = insn.mnemonic, self.state
        self._cur = insn
        if m in NOP or m == "trap":
            return
        if m in LOAD:
            self._load(insn)
        elif m in STORE:
            self._store(insn)
        elif m in LOAD_MULTI:
            self._lmw(insn)
        elif m in STORE_MULTI:
            self._stmw(insn)
        elif m in COPY:
            self._mr(insn)
        elif m in LI:
            self._li(insn)
        elif m in ARITH or m in MUL_DIV or m in LOGIC or m in SHIFT_VAR or m in SHIFT_SIGNED_IMM or m in SIGNEXT or m in COUNT or m in MISC:
            self._alu(insn)
        elif m in ROTATE_W or m in ROTATE_D or m in INSERT:
            self._rotate(insn)
        elif m in ISEL:
            self._isel(insn)
        elif m in CMP:
            self._cmp(insn)
        elif m == "crlogic" or m in CR_LOGIC:
            self._crlogic(insn)
        elif m in CR_MOVE:
            self._crmove(insn)
        elif m in SPR_MOVE:
            self._spr(insn)
        elif m in CALL:
            tgt = insn.imm(0)
            if tgt is not None and tgt == insn.next_ip:
                st.set("lr", CLEAN)
                st.consts["lr"] = insn.next_ip
            else:
                self._call(insn, None)
        elif m in CALL_CTR or m == "bccctrl":
            self._call(insn, "ctr")
        elif m in CALL_LR or m == "bcclrl":
            self._call(insn, "lr")
        elif m in RETURN or m in BCC_LR:
            self._return(insn)
        elif m in JUMP_CTR or m in BCC_CTR:
            self._bctr(insn)
        elif m in BCC or m == "bccl" or m in BDNZ or m == "bdnzl":
            self._bcc(insn)
        elif m in BRANCH:
            pass
        elif m in SYSCALL:
            self._syscall(insn)
        elif m in FP_LOAD:
            self._fp_load(insn)
        elif m in FP_STORE:
            self._fp_store(insn)
        elif m in FP_MOVE_GPR:
            self._fp_move(insn)
        elif m.startswith(("f", "v", "x")) and m not in ("fcmpu", "fcmpo"):
            self._generic(insn)
        else:
            self._unknown(insn)

    def _ptr_of(self, name: Optional[str]) -> Optional[Tuple[str, int]]:
        st = self.state
        return st.region_of(name) if (name in st.frame_ptrs or name == SP) else None

    def _const(self, insn: Insn, i: int) -> Optional[int]:
        op = insn.ops[i] if i < len(insn.ops) else None
        if isinstance(op, Imm):
            return op.value
        if isinstance(op, Reg):
            return self.state.consts.get(op.name)
        return None

    def _src(self, insn: Insn, i: int) -> Taint:
        op = insn.ops[i] if i < len(insn.ops) else None
        return self.state.get(op.name) if isinstance(op, Reg) else CLEAN

    def _set(self, name: Optional[str], t: Taint, ptr: Optional[Tuple[str, int]] = None, const: Optional[int] = None) -> None:
        st = self.state
        if name is None:
            return
        if name == SP:
            if ptr is not None and ptr[0] == SP:
                st.rebase(SP, ptr[1])
                st.regs.pop(SP, None)
                return
            st.set(SP, t)
            return
        if t.bound is not None and t.bound >= (1 << (self.mode.bits - 1)):
            t = Taint(t.labels, None)
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

    def _addr_taint(self, mem: Mem) -> Taint:
        st = self.state
        parts = [st.get(r) for r in (mem.base, mem.index) if r]
        return summed(*parts)

    def _record(self, insn: Insn, labels: Labels) -> None:
        if insn.record:
            self.state.set("cr0", Taint(labels, None))

    def _zext32(self, t: Taint) -> Taint:
        return capped(t, M32) if (t.tainted and self.mode is Mode.PPC64) else t

    def _load(self, insn: Insn) -> None:
        st, p, m = self.state, self.policy, insn.mnemonic
        rt, mem = insn.reg(0), insn.mem(1)
        if rt is None or mem is None:
            return self._unknown(insn)
        width, signed, update = LOAD[m]
        at = self._addr_taint(mem)
        if at.tainted and p.report_tainted_load_addr:
            self._find_addr(insn, "tainted-load-address", f"{m} via {mem}", at)
        b, off = st.resolve(mem)
        val, ptr = CLEAN, None
        if b is not None:
            val = st.mem_get(b, off)
            if width == self.mode.ptr_bytes:
                ptr = st.mem_ptrs.get((b, off))
        if at.tainted and p.taint_through_pointer:
            val = Taint(val.labels | at.labels, None)
        if val.tainted:
            if signed:
                val = Taint(val.labels, None)
            elif width < self.mode.ptr_bytes:
                val = capped(val, (1 << (8 * width)) - 1)
        was_ra = b is not None and (b, off) in st.ra_slots and width == self.mode.ptr_bytes
        self._set(rt, val, ptr)
        if was_ra:
            st.ra_regs.add(rt)
        if update and mem.base:
            if mem.index is None:
                self._add_imm_to_reg(mem.base, mem.disp)
            else:
                st.set(mem.base, union(st.get(mem.base), st.get(mem.index)))

    def _store(self, insn: Insn) -> None:
        st, p, m = self.state, self.policy, insn.mnemonic
        rs, mem = insn.reg(0), insn.mem(1)
        if rs is None or mem is None:
            return self._unknown(insn)
        width, update = STORE[m]
        at = self._addr_taint(mem)
        if at.tainted and p.report_tainted_store_addr:
            self._find_addr(insn, "tainted-store-address", f"{m} via {mem}", at)
        t = st.get(rs)
        b, off = st.resolve(mem)
        if b is not None:
            ptr = self._ptr_of(rs) if width == self.mode.ptr_bytes else None
            st.mem_set(b, off, t, ptr)
            if (b, off) in st.ra_slots:
                if t.tainted:
                    if p.report_tainted_store_over_ra:
                        self._find(insn, "tainted-overwrite-of-saved-ra", f"{m} -> {mem}", t.labels)
                else:
                    st.ra_slots.discard((b, off))
            elif rs in st.ra_regs and width == self.mode.ptr_bytes:
                st.ra_slots.add((b, off))
        if m in ("stwcx", "stdcx", "stbcx", "sthcx"):
            st.set("cr0", CLEAN)
        if update and mem.base:
            if mem.index is None:
                self._add_imm_to_reg(mem.base, mem.disp)
            else:
                st.set(mem.base, union(st.get(mem.base), st.get(mem.index)))

    def _lmw(self, insn: Insn) -> None:
        st = self.state
        rt, mem = insn.reg(0), insn.mem(1)
        if rt is None or mem is None:
            return self._unknown(insn)
        at = self._addr_taint(mem)
        if at.tainted:
            self._find_addr(insn, "tainted-load-address", f"lmw via {mem}", at)
        b, off = st.resolve(mem)
        for k, r in enumerate(range(int(rt[1:]), 32)):
            slot = (b, off + 4 * k) if b is not None else None
            val = st.mem_get(*slot) if slot else CLEAN
            if at.tainted:
                val = union(val, at)
            was_ra = slot in st.ra_slots if slot else False
            self._set(f"r{r}", val, st.mem_ptrs.get(slot) if (slot and self.mode is Mode.PPC32) else None)
            if was_ra:
                st.ra_regs.add(f"r{r}")

    def _stmw(self, insn: Insn) -> None:
        st = self.state
        rs, mem = insn.reg(0), insn.mem(1)
        if rs is None or mem is None:
            return self._unknown(insn)
        at = self._addr_taint(mem)
        if at.tainted:
            self._find_addr(insn, "tainted-store-address", f"stmw via {mem}", at)
        b, off = st.resolve(mem)
        if b is None:
            return
        for k, r in enumerate(range(int(rs[1:]), 32)):
            name = f"r{r}"
            slot = (b, off + 4 * k)
            t = st.get(name)
            st.mem_set(*slot, t, self._ptr_of(name) if self.mode is Mode.PPC32 else None)
            if slot in st.ra_slots and t.tainted and self.policy.report_tainted_store_over_ra:
                self._find(insn, "tainted-overwrite-of-saved-ra", f"stmw -> {mem}", t.labels)
            elif name in st.ra_regs:
                st.ra_slots.add(slot)

    def _mr(self, insn: Insn) -> None:
        st = self.state
        rd, rs = insn.reg(0), insn.reg(1)
        if rd is None or rs is None:
            return self._unknown(insn)
        t = st.get(rs)
        was_ra = rs in st.ra_regs
        self._set(rd, t, self._ptr_of(rs), st.consts.get(rs))
        if was_ra:
            st.ra_regs.add(rd)
        if rs != SP and rd != SP:
            st.alias(rd, rs)
        self._record(insn, t.labels)

    def _li(self, insn: Insn) -> None:
        rd, imm = insn.reg(0), insn.imm(1)
        if rd is None or imm is None:
            return self._unknown(insn)
        v = imm if insn.mnemonic == "li" else (imm << 16)
        self._set(rd, CLEAN, None, v & self.mode.mask)

    def _alu(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd = insn.reg(0)
        if rd is None:
            return self._unknown(insn)
        n = len(insn.ops)
        srcs = list(range(1, n))
        parts = [self._src(insn, i) for i in srcs]
        imm = next((insn.imm(i) for i in srcs if insn.imm(i) is not None), None)
        ra = insn.reg(1)
        ra_t = parts[0] if parts else CLEAN
        labels: Labels = EMPTY
        for t in parts:
            labels |= t.labels
        cs_ = [self._const(insn, i) for i in srcs]
        const: Optional[int] = None
        ptr: Optional[Tuple[str, int]] = None
        t = Taint(labels, None)

        if m in ("add", "addc", "adde", "addo", "addco", "addeo", "addi", "addic", "addis"):
            t = summed(*parts)
            k = imm if imm is not None else 0
            if m == "addis":
                k <<= 16
            if m in ("addi", "addis", "addic") and ra is not None and imm is not None:
                if rd == SP and ra == SP:
                    self._add_imm_to_reg(SP, k)
                    self._record(insn, labels)
                    return
                loc = self._ptr_of(ra)
                if loc is not None:
                    ptr = (loc[0], loc[1] + k)
                if cs_[0] is not None:
                    const = cs_[0] + k
            elif m in ("add", "addc") and n == 3:
                r1, r2 = insn.reg(1), insn.reg(2)
                for a, b in ((r1, r2), (r2, r1)):
                    loc, cb = self._ptr_of(a), st.consts.get(b) if b else None
                    if loc is not None and cb is not None:
                        ptr = (loc[0], loc[1] + cb)
                        break
                if all(c is not None for c in cs_):
                    const = cs_[0] + cs_[1]
                if rd == SP and ptr is not None and ptr[0] == SP:
                    self._set(SP, CLEAN, ptr)
                    return
            if m in ("adde", "addeo", "addco"):
                t = union(t, st.get("xer"))
        elif m in ("addme", "addze", "subfme", "subfze"):
            t = union(ra_t, st.get("xer"))
        elif m in ("subf", "subfc", "subfe", "subfo"):
            t = summed(*parts)
            if m == "subfe":
                t = union(t, st.get("xer"))
            if all(c is not None for c in cs_) and n == 3:
                const = cs_[1] - cs_[0]
            if n == 3 and isinstance(insn.ops[2], Reg):
                loc, c0 = self._ptr_of(insn.reg(2)), cs_[0]
                if loc is not None and c0 is not None:
                    ptr = (loc[0], loc[1] - c0)
        elif m in ("subfic", "neg", "nego"):
            t = Taint(labels, None)
            if m == "subfic" and cs_[0] is not None and imm is not None:
                const = imm - cs_[0]
        elif m == "mulli":
            t = Taint(labels, (ra_t.bound * imm) if (ra_t.bound is not None and imm is not None and imm > 0 and labels) else None)
            if cs_[0] is not None and imm is not None:
                const = cs_[0] * imm
        elif m in MUL_DIV:
            t = Taint(labels, None)
            if m.startswith("div") and ra_t.bound is not None and labels:
                t = Taint(labels, ra_t.bound)
        elif m == "and":
            bs = [x.bound for x in parts if x.tainted and x.bound is not None]
            t = Taint(labels, min(bs) if bs else None)
        elif m == "andc":
            t = Taint(labels, ra_t.bound if labels else None)
        elif m in ("andi", "andis"):
            k = imm if m == "andi" else (imm << 16)
            t = Taint(labels, (min(k, ra_t.bound) if ra_t.bound is not None else k) if labels else None)
            if cs_[0] is not None:
                const = cs_[0] & k
        elif m in ("or", "xor"):
            t = summed(*parts)
            if all(c is not None for c in cs_):
                const = (cs_[0] | cs_[1]) if m == "or" else (cs_[0] ^ cs_[1])
        elif m in ("ori", "oris", "xori", "xoris"):
            k = imm if m in ("ori", "xori") else (imm << 16)
            t = Taint(labels, (ra_t.bound + k) if (ra_t.bound is not None and labels) else None)
            if cs_[0] is not None:
                const = (cs_[0] | k) if m in ("ori", "oris") else (cs_[0] ^ k)
        elif m in ("nand", "nor", "eqv", "orc"):
            t = Taint(labels, None)
        elif m in ("slw", "srw"):
            t = Taint(labels, M32) if labels else CLEAN
        elif m in ("sld", "srd", "sraw", "srad"):
            t = Taint(labels, None)
        elif m in SHIFT_SIGNED_IMM:
            t = Taint(labels, None)
        elif m in SIGNEXT:
            t = Taint(labels, None)
        elif m in COUNT:
            t = Taint(labels, COUNT[m] if labels else None)
        else:
            t = Taint(labels, None)

        self._set(rd, t, ptr, const)
        self._record(insn, labels)
        if m.endswith(("o", "c")) and m in ARITH:
            st.set("xer", Taint(labels, None))

    def _rotate(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd, rs = insn.reg(0), insn.reg(1)
        if rd is None or rs is None:
            return self._unknown(insn)
        src = st.get(rs)
        b = src.bound
        labels = src.labels
        if m in INSERT:
            t = union(st.get(rd), src)
            self._set(rd, t)
            return self._record(insn, t.labels)
        if not src.tainted and not (m in ("rlwnm", "rldcl", "rldcr") and self._src(insn, 2).tainted):
            self._set(rd, CLEAN)
            return self._record(insn, EMPTY)
        bound: Optional[int] = None
        if m == "rlwinm":
            sh, mb, me = insn.imm(2) or 0, insn.imm(3) or 0, insn.imm(4) or 31
            mask = mask32(mb, me)
            if mb <= me:
                bound = mask
                if b is not None:
                    if sh == 0:
                        bound = min(mask, b)
                    elif me == 31 and sh + mb == 32:
                        bound = min(mask, b >> mb)
                    elif mb == 0 and me == 31 - sh:
                        bound = min(mask, b << sh)
        elif m == "rlwnm":
            mb, me = insn.imm(3) or 0, insn.imm(4) or 31
            labels = labels | self._src(insn, 2).labels
            bound = mask32(mb, me) if mb <= me else None
        elif m == "rldicl":
            sh, mb = insn.imm(2) or 0, insn.imm(3) or 0
            mask = (1 << (64 - mb)) - 1
            bound = mask
            if b is not None:
                if sh == 0:
                    bound = min(mask, b)
                elif sh + mb == 64:
                    bound = min(mask, b >> mb)
        elif m == "rldicr":
            sh, me = insn.imm(2) or 0, insn.imm(3) or 63
            if sh == 0:
                bound = b
            elif me == 63 - sh and b is not None:
                bound = b << sh
        elif m == "rldic":
            sh, mb = insn.imm(2) or 0, insn.imm(3) or 0
            width = 64 - mb - sh
            mask = ((1 << width) - 1) << sh if width > 0 else 0
            bound = min(mask, b << sh) if b is not None else mask
        elif m == "rldcl":
            mb = insn.imm(3) or 0
            labels = labels | self._src(insn, 2).labels
            bound = (1 << (64 - mb)) - 1
        else:
            labels = labels | self._src(insn, 2).labels
            bound = None
        if m in ("rlwinm", "rlwnm") and bound is not None:
            bound = min(bound, M32)
        t = Taint(labels, bound if labels else None)
        self._set(rd, t)
        self._record(insn, labels)

    def _isel(self, insn: Insn) -> None:
        st = self.state
        rd = insn.reg(0)
        if rd is None:
            return self._unknown(insn)
        a, b = self._src(insn, 1), self._src(insn, 2)
        cr = insn.reg(3)
        if self.policy.report_tainted_branch and cr and st.get(cr).tainted:
            self._find(insn, "tainted-branch-condition", f"isel on {cr}", st.get(cr).labels)
        bound = None if (a.tainted and b.tainted and (a.bound is None or b.bound is None)) else \
            (max(a.bound or 0, b.bound or 0) if (a.tainted and b.tainted) else (a.bound if a.tainted else b.bound))
        self._set(rd, Taint(a.labels | b.labels, bound))

    def _cmp(self, insn: Insn) -> None:
        st = self.state
        regs = [insn.reg(i) for i in range(len(insn.ops)) if insn.reg(i)]
        cr = regs[0] if regs and regs[0].startswith("cr") else "cr0"
        srcs = [r for r in regs if not r.startswith("cr")]
        st.set(cr, union(*(st.get(r) for r in srcs)))

    def _crlogic(self, insn: Insn) -> None:
        st = self.state
        regs = [insn.reg(i) for i in range(len(insn.ops)) if insn.reg(i)]
        if not regs:
            return
        if len(regs) == 1:
            st.set(regs[0], CLEAN if insn.raw.startswith(("crclr", "crset")) else st.get(regs[0]))
            return
        st.set(regs[0], union(*(st.get(r) for r in regs[1:])) if len(regs) > 1 else CLEAN)

    def _crmove(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        if m == "mcrf":
            st.set(insn.reg(0), st.get(insn.reg(1)))
        elif m in ("mfcr", "mfocrf"):
            st.set(insn.reg(0), union(*(st.get(f"cr{i}") for i in range(8))))
        elif m in ("mtcrf", "mtocrf"):
            mask, rs = insn.imm(0) or 0xFF, insn.reg(1)
            t = st.get(rs)
            for i in range(8):
                if mask & (0x80 >> i):
                    st.set(f"cr{i}", Taint(t.labels, None) if t.tainted else CLEAN)
        elif m == "mcrxr":
            st.set(insn.reg(0), st.get("xer"))
        elif m == "mcrfs":
            st.set(insn.reg(0), CLEAN)

    def _spr(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        r = insn.reg(0)
        if r is None:
            return self._unknown(insn)
        if m == "mflr":
            was_ra = "lr" in st.ra_regs
            self._set(r, st.get("lr"), None, st.consts.get("lr"))
            if was_ra:
                st.ra_regs.add(r)
        elif m == "mtlr":
            was_ra = r in st.ra_regs
            st.set("lr", st.get(r))
            if st.consts.get(r) is not None:
                st.consts["lr"] = st.consts[r]
            if was_ra:
                st.ra_regs.add("lr")
        elif m == "mfctr":
            was_ra = "ctr" in st.ra_regs
            self._set(r, st.get("ctr"))
            if was_ra:
                st.ra_regs.add(r)
        elif m == "mtctr":
            was_ra = r in st.ra_regs
            st.set("ctr", st.get(r))
            if was_ra:
                st.ra_regs.add("ctr")
        elif m == "mfxer":
            self._set(r, st.get("xer"))
        elif m == "mtxer":
            st.set("xer", st.get(r))
        elif m in ("mftb", "mftbu", "mfvrsave"):
            self._set(r, CLEAN)
        elif m in ("mfspr",):
            self._set(r, CLEAN)
        elif m in ("mtspr", "mtvrsave"):
            pass

    def _fp_load(self, insn: Insn) -> None:
        st = self.state
        ft, mem = insn.reg(0), insn.mem(1)
        if ft is None or mem is None:
            return self._unknown(insn)
        at = self._addr_taint(mem)
        if at.tainted:
            self._find_addr(insn, "tainted-load-address", f"{insn.mnemonic} via {mem}", at)
        b, off = st.resolve(mem)
        val = st.mem_get(b, off) if b is not None else CLEAN
        if at.tainted and self.policy.taint_through_pointer:
            val = union(val, at)
        st.set(ft, Taint(val.labels, None) if val.tainted else CLEAN)
        if insn.mnemonic.endswith("u") and mem.base and mem.index is None:
            self._add_imm_to_reg(mem.base, mem.disp)

    def _fp_store(self, insn: Insn) -> None:
        st = self.state
        fs, mem = insn.reg(0), insn.mem(1)
        if fs is None or mem is None:
            return self._unknown(insn)
        at = self._addr_taint(mem)
        if at.tainted:
            self._find_addr(insn, "tainted-store-address", f"{insn.mnemonic} via {mem}", at)
        b, off = st.resolve(mem)
        if b is not None:
            st.mem_set(b, off, st.get(fs))
        if insn.mnemonic.endswith("u") and mem.base and mem.index is None:
            self._add_imm_to_reg(mem.base, mem.disp)

    def _fp_move(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        a, b = insn.reg(0), insn.reg(1)
        if a is None or b is None:
            return self._unknown(insn)
        if m.startswith("mt"):
            st.set(a, union(*(st.get(insn.reg(i)) for i in range(1, len(insn.ops)) if insn.reg(i))))
        else:
            t = st.get(b)
            self._set(a, Taint(t.labels, None) if t.tainted else CLEAN)

    def _generic(self, insn: Insn) -> None:
        st = self.state
        rd = insn.reg(0)
        if rd is None:
            return
        st.set(rd, union(*(self._src(insn, i) for i in range(1, len(insn.ops)))))

    def _bcc(self, insn: Insn) -> None:
        if insn.mnemonic in ("bccl", "bdnzl"):
            return self._call(insn, None)
        if not self.policy.report_tainted_branch:
            return
        st = self.state
        t = st.get("ctr") if insn.mnemonic == "bdnz" else st.get(insn.reg(0) or "cr0")
        if t.tainted:
            self._find(insn, "tainted-branch-condition", insn.mnemonic + (f" {insn.reg(0)}" if insn.reg(0) else ""), t.labels)

    def _return(self, insn: Insn) -> None:
        st = self.state
        if insn.mnemonic == "bcclr" and self.policy.report_tainted_branch and st.get(insn.reg(0) or "cr0").tainted:
            self._find(insn, "tainted-branch-condition", "bcclr", st.get(insn.reg(0) or "cr0").labels)
        t = st.get("lr")
        if t.tainted:
            self._find(insn, "tainted-return-address", insn.mnemonic, t.labels)

    def _bctr(self, insn: Insn) -> None:
        st = self.state
        t = st.get("ctr")
        if t.tainted:
            kind = "tainted-return-address" if "ctr" in st.ra_regs else "tainted-indirect-jump"
            self._find(insn, kind, f"{insn.mnemonic} via ctr", t.labels)

    def _call(self, insn: Insn, via: Optional[str]) -> None:
        st, p, ab = self.state, self.policy, self.abi
        if via is not None and st.get(via).tainted:
            self._find(insn, "tainted-indirect-call", f"{insn.mnemonic} via {via}", st.get(via).labels)
        arg_labels: Labels = EMPTY
        for r in ab.arg_regs + ab.fp_arg_regs:
            arg_labels |= st.get(r).labels
        for k in range(ab.stack_arg_base, ab.stack_arg_base + 4 * self.mode.ptr_bytes, self.mode.ptr_bytes):
            arg_labels |= st.mem_get(SP, k).labels
        for r in ab.caller_saved:
            st.set(r, CLEAN)
        st.ra_regs.discard("lr")
        st.consts["lr"] = insn.next_ip
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
                    self._find(insn, "tainted-syscall-arg", f"{name}({r})", st.get(r).labels)
        st.set("cr0", CLEAN)
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
        if rd is None or rd == SP:
            return
        labels: Labels = EMPTY
        for i in range(len(insn.ops)):
            r = insn.reg(i)
            if r:
                labels |= self.state.get(r).labels
            mem = insn.mem(i)
            if mem:
                labels |= self._addr_taint(mem).labels
        self.state.set(rd, Taint(labels, None))
