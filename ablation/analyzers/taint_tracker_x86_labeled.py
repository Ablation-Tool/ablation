"""Forward labeled-taint tracker for x86 / x86-64 instruction streams.

State
-----
* ``regs``       register family -> Taint. Sub-registers alias their family:
                 32-bit write in 64-bit mode zero-extends (SDM Vol.1 §3.4.1.1);
                 8/16-bit writes merge with the existing taint.
* ``mem``        (sp|bp family, disp) -> Taint: symbolic frame slots, rebased
                 across push/pop/sub rsp/leave, aliased on ``mov rbp, rsp``.
* ``ranges``     byte ranges (syscall input buffers, rep movs targets).
* ``consts``     known constants (mov r, imm; lea r,[rip+d]; zero idioms).
* ``frame_ptrs`` register -> (region, disp) for pointers derived from sp/bp.
* ``mem_ptrs``   slot -> pointer fact it holds (spilled pointer registers).
* ``ra_slots``   frame slots holding a return address.
* ``eq``         register equality class (full-width copies).

``bound`` on a Taint is the maximum attacker-controlled contribution to the
value: ``movzx eax, dl`` gives 0xff; ``lea rax,[rbx+rax*8]`` with clean rbx
gives 0xff*8; multiply by unknown or unbounded add resets it.

This tracker consumes instruction streams (from_listing / from_objdump /
from_capstone). For binary RE over ELF files use taint_tracker_x86.py.

Usage:
    from ablation.analyzers.taint_tracker_x86_labeled import TaintTracker, Mode, Abi, Policy
    from ablation.analyzers.insn_x86 import from_listing

    t = TaintTracker(Mode.X64)
    t.taint_register("rdi", "user")
    findings = t.run(from_listing(text))
    for f in findings:
        print(f)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .insn_x86 import Imm, Insn, Mem, Reg, rip_relative_target
from .isa_x86 import (
    ALU1, ALU2, CALL, CONST, COPY, DIV_IMPLICIT, FLAGS, FLAGS_ONLY, INPUT_SYSCALLS, JMP, LEA, LOOP,
    MUL_IMPLICIT, NOP, POP, PUSH, RET, SEXT_COPY, SHIFT, STRING, SWAP, SYSCALL, WIDEN_RAX, WIDEN_RDX,
    ZERO_IDIOM, ZEXT_COPY, Abi, AbiModel, Mode, abi_for, imm_bound_after_and, reg_info, syscall_model,
)

log = logging.getLogger("x86taint")
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
        s = "{" + ",".join(sorted(self.labels)) + "}"
        return s + (f"<={self.bound:#x}" if self.bound is not None else "")


CLEAN = Taint()


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
    report_rep_count: bool = True
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
    eq: Dict[str, Set[str]] = field(default_factory=dict)
    _next_region: int = 0

    @property
    def frame_bases(self) -> Tuple[str, str]:
        return (self.mode.sp, self.mode.bp)

    def new_region(self, tag: str = "mem") -> str:
        self._next_region += 1
        return f"@{tag}{self._next_region}"

    def point_at(self, reg: str, region: str, off: int = 0) -> None:
        fam = self.fam(reg)
        for r in self.eq.get(fam, {fam}):
            self.frame_ptrs[r] = (region, off)

    def unalias(self, fam: str) -> None:
        g = self.eq.pop(fam, None)
        if g is not None:
            g.discard(fam)

    def alias(self, dst: str, src: str) -> None:
        self.unalias(dst)
        g = self.eq.setdefault(src, {src})
        g.add(dst)
        self.eq[dst] = g

    def region_of(self, reg: Optional[str]) -> Optional[Tuple[str, int]]:
        fam = self.fam(reg)
        if fam in self.frame_ptrs:
            return self.frame_ptrs[fam]
        if fam in self.frame_bases:
            return (fam, 0)
        return None

    def fam(self, name: Optional[str]) -> Optional[str]:
        if name is None:
            return None
        ri = reg_info(name, self.mode)
        return ri.family if ri else name

    def get(self, name: Optional[str]) -> Taint:
        if name is None:
            return CLEAN
        ri = reg_info(name, self.mode)
        if ri is None:
            return self.regs.get(name, CLEAN)
        t = self.regs.get(ri.family, CLEAN)
        if not t.tainted:
            return CLEAN
        if ri.width < self.mode.bits and ri.low == 0 and not ri.family.startswith(("xmm", "mm", "st", "k")):
            b = ri.mask if t.bound is None else min(t.bound, ri.mask)
            return Taint(t.labels, b)
        if ri.low > 0:
            return Taint(t.labels, 0xFF)
        return t

    def set(self, name: Optional[str], t: Taint) -> None:
        if name is None:
            return
        ri = reg_info(name, self.mode)
        fam = ri.family if ri else name
        self.consts.pop(fam, None)
        self.frame_ptrs.pop(fam, None)
        self.unalias(fam)
        if (ri is not None and ri.width < self.mode.bits
                and not (self.mode is Mode.X64 and ri.width == 32 and ri.family != FLAGS)
                and ri.family not in (FLAGS,)
                and not ri.family.startswith(("xmm", "mm", "st", "k"))):
            old = self.regs.get(fam, CLEAN)
            if old.tainted:
                t = Taint(old.labels | t.labels, None)
        if t.tainted or t.bound is not None:
            self.regs[fam] = t
        else:
            self.regs.pop(fam, None)
        if fam in self.frame_bases:
            self.invalidate_base(fam)

    def set_full(self, fam: str, t: Taint) -> None:
        self.consts.pop(fam, None)
        self.frame_ptrs.pop(fam, None)
        self.unalias(fam)
        if t.tainted or t.bound is not None:
            self.regs[fam] = t
        else:
            self.regs.pop(fam, None)

    def taint_reg(self, name: str, label: str) -> None:
        fam = self.fam(name)
        cur = self.regs.get(fam, CLEAN)
        self.regs[fam] = Taint(cur.labels | {label}, cur.bound)

    def resolve(self, mem: Mem) -> Tuple[Optional[str], int]:
        if mem.index is not None:
            return None, 0
        base = self.fam(mem.base)
        if base in self.frame_ptrs:
            b, k = self.frame_ptrs[base]
            return b, k + mem.disp
        if base in self.frame_bases:
            return base, mem.disp
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

    def alias_frame(self, dst: str, src: str) -> None:
        self.invalidate_base(dst)
        for (b, o), t in list(self.mem.items()):
            if b == src:
                self.mem[(dst, o)] = t
        self.ranges += [(dst, lo, hi, t) for (b, lo, hi, t) in self.ranges if b == src]
        self.ra_slots |= {(dst, o) for (b, o) in self.ra_slots if b == src}
        for (b, o), v in list(self.mem_ptrs.items()):
            if b == src:
                self.mem_ptrs[(dst, o)] = v

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
            eq={k: set(v) for k, v in self.eq.items()},
            _next_region=self._next_region,
        )

    def join(self, other: "TaintState", widen: bool = False) -> "TaintState":
        """Conservative join (union). ``widen=True`` collapses differing bounds to None."""
        out = TaintState(mode=self.mode, _next_region=max(self._next_region, other._next_region))
        for fam in set(self.regs) | set(other.regs):
            a = self.regs.get(fam, CLEAN)
            b = other.regs.get(fam, CLEAN)
            ab = 0 if not a.tainted else a.bound
            bb = 0 if not b.tainted else b.bound
            if ab is None or bb is None:
                bound: Optional[int] = None
            elif widen and ab != bb:
                bound = None
            else:
                bound = max(ab, bb)
            t = Taint(a.labels | b.labels, bound)
            if t.tainted or t.bound is not None:
                out.regs[fam] = t
        for k in set(self.mem) | set(other.mem):
            a_t = self.mem.get(k, CLEAN)
            b_t = other.mem.get(k, CLEAN)
            merged = Taint(a_t.labels | b_t.labels, None)
            if merged.tainted:
                out.mem[k] = merged
        # ranges: union (deduplicated)
        seen: Set[tuple] = set()
        for r in self.ranges + other.ranges:
            key = (r[0], r[1], r[2], frozenset(r[3].labels))
            if key not in seen:
                seen.add(key)
                out.ranges.append(r)
        # consts: intersect (only values both paths agree on)
        for k in set(self.consts) & set(other.consts):
            if self.consts[k] == other.consts[k]:
                out.consts[k] = self.consts[k]
        # frame_ptrs: intersect (pointer fact must hold on both paths)
        for k in set(self.frame_ptrs) & set(other.frame_ptrs):
            if self.frame_ptrs[k] == other.frame_ptrs[k]:
                out.frame_ptrs[k] = self.frame_ptrs[k]
        # mem_ptrs: intersect
        for k in set(self.mem_ptrs) & set(other.mem_ptrs):
            if self.mem_ptrs[k] == other.mem_ptrs[k]:
                out.mem_ptrs[k] = self.mem_ptrs[k]
        out.ra_slots = self.ra_slots | other.ra_slots
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
        )


class TaintTracker:
    def __init__(self, mode: Mode = Mode.X64, abi: Optional[Abi] = None, policy: Optional[Policy] = None):
        self.mode = mode
        self.abi: AbiModel = abi_for(abi or Abi.default_for(mode))
        if self.abi.mode is not mode:
            raise ValueError(f"ABI {self.abi.abi.value} is not valid for mode {mode.value}")
        self.policy = policy or Policy()
        self.sys = syscall_model(mode)
        self.state = TaintState(mode)
        self.findings: List[Finding] = []
        self.trace: List[Tuple[Insn, Dict[str, str]]] = []
        self.unknown: Set[str] = set()
        if self.policy.entry_is_function_start:
            self.state.ra_slots.add((mode.sp, 0))

    # public API -----------------------------------------------------------

    def taint_register(self, reg: str, label: str) -> None:
        self.state.taint_reg(reg, label)

    def taint_memory(self, base: str, offset: int, label: str, length: int = 0) -> None:
        """Taint ``length`` bytes (or one slot) at ``[base + offset]``."""
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
        """``[base + offset]`` holds a *pointer* to ``length`` tainted bytes (cdecl pattern)."""
        st = self.state
        loc = st.region_of(base)
        if loc is None:
            raise ValueError(f"{base} is not a resolvable frame/region base")
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

    # dispatcher -----------------------------------------------------------

    def step(self, insn: Insn) -> None:
        m, st = insn.mnemonic, self.state
        if m in NOP:
            if m == "leave":
                self._leave(insn)
            return
        if m in RET:
            self._ret(insn)
        elif m in CALL:
            self._call(insn)
        elif m in JMP:
            self._jmp(insn)
        elif m.startswith("j") and m not in ("jmp",) or m in LOOP:
            self._jcc(insn)
        elif m in SYSCALL:
            self._syscall(insn)
        elif m in PUSH:
            self._push(insn)
        elif m in POP:
            self._pop(insn)
        elif m in STRING:
            self._string(insn)
        elif m in COPY or m in ZEXT_COPY or m in SEXT_COPY:
            self._mov(insn)
        elif m.startswith("cmov"):
            self._cmov(insn)
        elif m.startswith("set"):
            self._setcc(insn)
        elif m in SWAP:
            self._xchg(insn)
        elif m in LEA:
            self._lea(insn)
        elif m in FLAGS_ONLY:
            self._flags_only(insn)
        elif m in WIDEN_RAX:
            src_bits = {"cbw": 8, "cwde": 16, "cdqe": 32}[m]
            t = st.get({"cbw": "al", "cwde": "ax", "cdqe": "eax"}[m])
            keep = t.bound if (t.bound is not None and t.bound < (1 << (src_bits - 1))) else None
            st.set_full(st.fam("eax"), Taint(t.labels, keep))
        elif m in WIDEN_RDX:
            st.set_full(st.fam("edx"), Taint(st.get(st.fam("eax")).labels, None))
        elif m in MUL_IMPLICIT and len(insn.ops) == 1:
            t = Taint(self._src_taint(insn, 0).labels | st.get(st.fam("eax")).labels, None)
            st.set_full(st.fam("eax"), t)
            st.set_full(st.fam("edx"), t)
            st.set_full(FLAGS, t)
        elif m in DIV_IMPLICIT:
            t = Taint(self._src_taint(insn, 0).labels | st.get(st.fam("eax")).labels | st.get(st.fam("edx")).labels, None)
            st.set_full(st.fam("eax"), t)
            st.set_full(st.fam("edx"), t)
        elif m in ALU1:
            self._alu1(insn)
        elif m in ALU2:
            self._alu2(insn)
        elif m in CONST:
            self._const(insn)
        else:
            self._unknown(insn)

    # operand helpers ------------------------------------------------------

    def _addr_taint(self, mem: Mem) -> Taint:
        st = self.state
        parts = []
        if mem.base:
            parts.append((st.get(mem.base), 1))
        if mem.index:
            parts.append((st.get(mem.index), mem.scale))
        labels: Labels = EMPTY
        bound: Optional[int] = 0
        for t, scale in parts:
            labels |= t.labels
            if t.tainted:
                bound = None if (bound is None or t.bound is None) else bound + t.bound * scale
        return Taint(labels, bound if labels else None)

    def _src_taint(self, insn: Insn, i: int, report: bool = True) -> Taint:
        st, p = self.state, self.policy
        op = insn.ops[i] if i < len(insn.ops) else None
        if isinstance(op, Reg):
            return st.get(op.name)
        if isinstance(op, Imm) or op is None:
            return CLEAN
        if isinstance(op, Mem):
            at = self._addr_taint(op)
            if at.tainted and report and p.report_tainted_load_addr:
                self._find_addr(insn, "tainted-load-address", f"load via {op}", at)
            b, off = st.resolve(op)
            val = st.mem_get(b, off) if b is not None else CLEAN
            if at.tainted and p.taint_through_pointer:
                val = Taint(val.labels | at.labels, None)
            return val
        return CLEAN

    def _write(self, insn: Insn, i: int, t: Taint, ptr: Optional[Tuple[str, int]] = None) -> None:
        st, p = self.state, self.policy
        op = insn.ops[i]
        if isinstance(op, Reg):
            st.set(op.name, t)
            return
        if isinstance(op, Mem):
            at = self._addr_taint(op)
            if at.tainted and p.report_tainted_store_addr:
                self._find_addr(insn, "tainted-store-address", f"store via {op}", at)
            b, off = st.resolve(op)
            if b is None:
                return
            st.mem_set(b, off, t, ptr)
            if (b, off) in st.ra_slots:
                st.ra_slots.discard((b, off))
                if t.tainted and p.report_tainted_store_over_ra:
                    self._find(insn, "tainted-overwrite-of-saved-ra", f"store -> {op}", t.labels)

    def _const_of(self, insn: Insn, i: int) -> Optional[int]:
        op = insn.ops[i] if i < len(insn.ops) else None
        if isinstance(op, Imm):
            return op.value
        if isinstance(op, Reg):
            return self.state.consts.get(self.state.fam(op.name))
        return None

    # transfer functions ---------------------------------------------------

    def _mov(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        if len(insn.ops) != 2:
            return self._unknown(insn)
        dst, src = insn.ops[0], insn.ops[1]
        t = self._src_taint(insn, 1)
        if m in ZEXT_COPY:
            width = getattr(src, "size", 0) or (1 if isinstance(src, Mem) and src.size == 1 else 0)
            b = (1 << (8 * width)) - 1 if width else None
            t = Taint(t.labels, b if t.bound is None else min(t.bound, b) if b else t.bound)
        elif m in SEXT_COPY:
            t = Taint(t.labels, None)
        full = m in COPY and isinstance(src, (Reg, Mem)) and self._is_ptr_width(src)
        src_ptr: Optional[Tuple[str, int]] = None
        if full and isinstance(src, Reg):
            src_ptr = st.region_of(src.name) if st.fam(src.name) in st.frame_ptrs or st.fam(src.name) in st.frame_bases else None
        elif full and isinstance(src, Mem):
            b, off = st.resolve(src)
            if b is not None:
                src_ptr = st.mem_ptrs.get((b, off))
        self._write(insn, 0, t, ptr=src_ptr if isinstance(dst, Mem) and self._is_ptr_width(dst) else None)
        if isinstance(dst, Reg):
            fam = st.fam(dst.name)
            c = self._const_of(insn, 1)
            if isinstance(src, Imm):
                st.consts[fam] = src.value & ((1 << self.mode.bits) - 1)
            elif isinstance(src, Reg) and m in COPY:
                sf = st.fam(src.name)
                if c is not None:
                    st.consts[fam] = c
                if fam in st.frame_bases and sf in st.frame_bases and fam != sf:
                    st.alias_frame(fam, sf)
                    st.consts.pop(fam, None)
                elif src_ptr is not None and fam not in st.frame_bases:
                    st.frame_ptrs[fam] = src_ptr
                if full and fam not in st.frame_bases and sf not in st.frame_bases and fam != sf:
                    st.alias(fam, sf)
            elif isinstance(src, Mem) and m in COPY:
                if src_ptr is not None and fam not in st.frame_bases and self._is_ptr_width(dst):
                    st.frame_ptrs[fam] = src_ptr
                tgt = rip_relative_target(insn, src, self.mode)
                if tgt is not None:
                    log.debug("%s loads from %#x", insn, tgt)

    def _is_ptr_width(self, op) -> bool:
        if isinstance(op, Reg):
            ri = reg_info(op.name, self.mode)
            return ri is not None and ri.width == self.mode.bits
        if isinstance(op, Mem):
            return op.size in (0, self.mode.ptr_bytes)
        return False

    def _cmov(self, insn: Insn) -> None:
        old = self._src_taint(insn, 0, report=False)
        new = self._src_taint(insn, 1)
        self._write(insn, 0, Taint(old.labels | new.labels, None))
        if self.policy.report_tainted_branch and self.state.get(FLAGS).tainted:
            self._find(insn, "tainted-branch-condition", insn.mnemonic, self.state.get(FLAGS).labels)

    def _setcc(self, insn: Insn) -> None:
        f = self.state.get(FLAGS)
        self._write(insn, 0, Taint(f.labels, 1 if f.tainted else None))

    def _xchg(self, insn: Insn) -> None:
        a, b = self._src_taint(insn, 0), self._src_taint(insn, 1)
        self._write(insn, 0, b)
        self._write(insn, 1, a)

    def _lea(self, insn: Insn) -> None:
        st = self.state
        dst, mem = insn.reg(0), insn.mem(1)
        if dst is None or mem is None:
            return self._unknown(insn)
        st.set(dst, self._addr_taint(mem))
        fam = st.fam(dst)
        tgt = rip_relative_target(insn, mem, self.mode)
        if tgt is not None:
            st.consts[fam] = tgt
        elif mem.index is None and mem.base is not None:
            bf = st.fam(mem.base)
            if bf in st.frame_bases:
                st.frame_ptrs[fam] = (bf, mem.disp)
            elif bf in st.frame_ptrs:
                b, k = st.frame_ptrs[bf]
                st.frame_ptrs[fam] = (b, k + mem.disp)
            elif bf in st.consts:
                st.consts[fam] = (st.consts[bf] + mem.disp) & ((1 << self.mode.bits) - 1)

    def _flags_only(self, insn: Insn) -> None:
        labels: Labels = EMPTY
        for i in range(len(insn.ops)):
            labels |= self._src_taint(insn, i).labels
        self.state.set_full(FLAGS, Taint(labels, None))

    def _alu1(self, insn: Insn) -> None:
        t = self._src_taint(insn, 0)
        self._write(insn, 0, Taint(t.labels, t.bound if insn.mnemonic in ("inc", "dec") else None))
        self.state.set_full(FLAGS, Taint(t.labels, None))

    def _alu2(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        n = len(insn.ops)
        if n < 2:
            return self._unknown(insn)
        dst = insn.ops[0]
        if (m in ZERO_IDIOM and n == 2 and isinstance(dst, Reg) and isinstance(insn.ops[1], Reg)
                and st.fam(dst.name) == st.fam(insn.ops[1].name) and dst.size == insn.ops[1].size):
            fam = st.fam(dst.name)
            width = reg_info(dst.name, self.mode).width
            if width >= 32 or not st.regs.get(fam, CLEAN).tainted:
                st.set_full(fam, CLEAN)
                st.consts[fam] = 0
            else:
                st.set(dst.name, CLEAN)
            st.set_full(FLAGS, CLEAN)
            return
        if (m in ("add", "sub") and n == 2 and isinstance(dst, Reg) and st.fam(dst.name) in st.frame_bases
                and isinstance(insn.ops[1], Imm)):
            fam = st.fam(dst.name)
            delta = insn.ops[1].value if m == "add" else -insn.ops[1].value
            st.rebase(fam, delta)
            old = st.regs.get(fam, CLEAN)
            c = st.consts.get(fam)
            if old.tainted:
                st.regs[fam] = Taint(old.labels, None)
            if c is not None:
                st.consts[fam] = (c + delta) & ((1 << self.mode.bits) - 1)
            st.set_full(FLAGS, Taint(old.labels, None))
            return
        derived = None
        if (m in ("add", "sub") and n == 2 and isinstance(dst, Reg) and isinstance(insn.ops[1], Imm)
                and st.fam(dst.name) in st.frame_ptrs
                and reg_info(dst.name, self.mode).width == self.mode.bits):
            b, k = st.frame_ptrs[st.fam(dst.name)]
            derived = (b, k + (insn.ops[1].value if m == "add" else -insn.ops[1].value))
        srcs = list(range(1, n)) if n == 3 else [0, 1]
        old = self._src_taint(insn, 0, report=False)
        old_c = self._const_of(insn, 0)
        parts = [self._src_taint(insn, i) for i in srcs]
        labels: Labels = EMPTY
        for t in parts:
            labels |= t.labels
        tainted = [t for t in parts if t.tainted]
        all_bounded = bool(tainted) and all(t.bound is not None for t in tainted)
        bound: Optional[int] = None
        imm = insn.imm(n - 1)
        width = (reg_info(dst.name, self.mode).width if isinstance(dst, Reg)
                 else (dst.size * 8 if isinstance(dst, Mem) and dst.size else self.mode.bits))

        if m == "and":
            if imm is not None and old.tainted:
                bound = imm_bound_after_and(imm, width)
                if bound is not None and old.bound is not None:
                    bound = min(bound, old.bound)
            else:
                bs = [t.bound for t in tainted if t.bound is not None]
                bound = min(bs) if bs else None
        elif m in ("add", "adc", "sub", "sbb", "or", "xor", "xadd", "adcx", "adox") and all_bounded:
            bound = sum(t.bound for t in tainted)
        elif m in ("shl", "sal", "shlx") and imm is not None and old.bound is not None and imm < 32:
            bound = old.bound << imm
        elif m in ("shr", "sar", "shrx", "sarx") and imm is not None and old.bound is not None:
            bound = old.bound >> imm
        elif m == "imul" and imm is not None and all_bounded and imm > 0:
            bound = sum(t.bound for t in tainted) * imm
        elif m == "andn" and n == 3:
            bound = parts[1].bound
        elif m in ("bzhi", "bextr") and all_bounded:
            bound = min(t.bound for t in tainted)
        elif m in ("lzcnt", "tzcnt", "popcnt", "bsf", "bsr") and labels:
            bound = width
        elif m == "pmovmskb" and labels:
            bound = 0xFFFF
        elif m in SHIFT and imm is None:
            bound = None

        self._write(insn, 0, Taint(labels, bound))
        if derived is not None:
            st.frame_ptrs[st.fam(dst.name)] = derived
        if m not in ("bswap",):
            st.set_full(FLAGS, Taint(labels, None))
        if isinstance(dst, Reg) and imm is not None and n == 2 and m in ("add", "sub") and old_c is not None:
            fam = st.fam(dst.name)
            st.consts[fam] = (old_c + (imm if m == "add" else -imm)) & ((1 << self.mode.bits) - 1)

    def _const(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        if m in ("rdtsc", "rdtscp", "cpuid"):
            for r in ("eax", "edx") + (("ecx", "ebx") if m == "cpuid" else ()):
                st.set_full(st.fam(r), CLEAN)
        elif m in ("rdrand", "rdseed") and insn.reg(0):
            st.set(insn.reg(0), CLEAN)
        elif m in ("pushf", "pushfq"):
            self._push_value(st.get(FLAGS))
        elif m in ("popf", "popfq"):
            st.set_full(FLAGS, self._pop_value()[0])
        elif m == "lahf":
            st.set("ah", st.get(FLAGS))
        elif m == "sahf":
            st.set_full(FLAGS, st.get("ah"))

    # stack ------------------------------------------------------------------

    def _push_value(self, t: Taint, is_ra: bool = False, ptr: Optional[Tuple[str, int]] = None) -> None:
        st, sp, n = self.state, self.mode.sp, self.mode.ptr_bytes
        st.rebase(sp, -n)
        c = st.consts.get(sp)
        if c is not None:
            st.consts[sp] = c - n
        st.mem_set(sp, 0, t, ptr)
        st.ra_slots.discard((sp, 0))
        if is_ra:
            st.ra_slots.add((sp, 0))

    def _pop_value(self) -> Tuple[Taint, Optional[Tuple[str, int]]]:
        st, sp, n = self.state, self.mode.sp, self.mode.ptr_bytes
        t = st.mem_get(sp, 0)
        ptr = st.mem_ptrs.pop((sp, 0), None)
        st.mem.pop((sp, 0), None)
        st.ra_slots.discard((sp, 0))
        st.rebase(sp, n)
        c = st.consts.get(sp)
        if c is not None:
            st.consts[sp] = c + n
        return t, ptr

    def _push(self, insn: Insn) -> None:
        st = self.state
        op = insn.ops[0] if insn.ops else None
        ptr = None
        if isinstance(op, Reg) and self._is_ptr_width(op):
            ptr = st.region_of(op.name) if st.fam(op.name) in st.frame_ptrs or st.fam(op.name) in st.frame_bases else None
        elif isinstance(op, Mem):
            b, off = st.resolve(op)
            ptr = st.mem_ptrs.get((b, off)) if b is not None else None
        self._push_value(self._src_taint(insn, 0), ptr=ptr)

    def _pop(self, insn: Insn) -> None:
        st = self.state
        t, ptr = self._pop_value()
        op = insn.ops[0]
        if isinstance(op, Reg):
            fam = st.fam(op.name)
            if fam == self.mode.sp:
                st.set_full(fam, t)
                st.invalidate_base(fam)
                return
            st.set(op.name, t)
            if ptr is not None and fam not in st.frame_bases and self._is_ptr_width(op):
                st.frame_ptrs[fam] = ptr
        else:
            self._write(insn, 0, t, ptr)

    def _leave(self, insn: Insn) -> None:
        st, sp, bp = self.state, self.mode.sp, self.mode.bp
        st.alias_frame(sp, bp)
        st.set_full(sp, st.get(bp))
        t, _ = self._pop_value()
        st.set(bp, t)

    # control transfer -------------------------------------------------------

    def _target_taint(self, insn: Insn) -> Tuple[Taint, str]:
        op = insn.ops[0] if insn.ops else None
        if isinstance(op, Reg):
            return self.state.get(op.name), f"via {op.name}"
        if isinstance(op, Mem):
            at = self._addr_taint(op)
            if at.tainted:
                return at, f"via address {op}"
            return self._src_taint(insn, 0, report=False), f"via slot {op}"
        return CLEAN, "direct"

    def _call(self, insn: Insn) -> None:
        st, p = self.state, self.policy
        t, how = self._target_taint(insn)
        if t.tainted:
            self._find(insn, "tainted-indirect-call", how, t.labels)
        arg_labels: Labels = EMPTY
        for r in self.abi.arg_regs + self.abi.fp_arg_regs:
            arg_labels |= st.get(r).labels
        if self.abi.abi is Abi.CDECL32:
            for k in range(0, 8 * self.mode.ptr_bytes, self.mode.ptr_bytes):
                arg_labels |= st.mem_get(self.mode.sp, k).labels
        for fam in self.abi.caller_saved:
            st.set_full(fam, CLEAN)
        st.set_full(FLAGS, CLEAN)
        if p.calls_propagate_to_return and arg_labels:
            for r in self.abi.ret_regs + self.abi.fp_ret_regs:
                st.set_full(r, Taint(arg_labels, None))
        sp = self.mode.sp
        st.mem = {k: v for k, v in st.mem.items() if not (k[0] == sp and k[1] < 0)}
        st.ranges = [r for r in st.ranges if not (r[0] == sp and r[2] <= 0)]
        st.mem_ptrs = {k: v for k, v in st.mem_ptrs.items() if not (k[0] == sp and k[1] < 0)}

    def _jmp(self, insn: Insn) -> None:
        t, how = self._target_taint(insn)
        if t.tainted:
            self._find(insn, "tainted-indirect-jump", how, t.labels)

    def _jcc(self, insn: Insn) -> None:
        if not self.policy.report_tainted_branch:
            return
        st = self.state
        t = st.get(FLAGS)
        if insn.mnemonic in LOOP:
            t = Taint(t.labels | st.get(st.fam("ecx")).labels, None)
        if t.tainted:
            self._find(insn, "tainted-branch-condition", insn.mnemonic, t.labels)

    def _ret(self, insn: Insn) -> None:
        st, sp = self.state, self.mode.sp
        t = st.mem_get(sp, 0)
        if t.tainted:
            self._find(insn, "tainted-return-address", f"[{sp}]", t.labels)
        self._pop_value()
        extra = insn.imm(0)
        if extra:
            st.rebase(sp, extra)

    def _syscall(self, insn: Insn) -> None:
        st, p, sm = self.state, self.policy, self.sys
        if insn.mnemonic == "int" and insn.imm(0) != 0x80:
            return
        if insn.mnemonic in ("int", "sysenter") and self.mode is Mode.X64:
            log.debug("32-bit syscall gate in 64-bit mode at %#x; using i386 table", insn.address)
            sm = syscall_model(Mode.X86)
        nr = st.consts.get(st.fam(sm.nr_reg))
        name = sm.numbers.get(nr, f"sys_{nr}") if nr is not None else "sys_?"
        if st.get(sm.nr_reg).tainted:
            self._find(insn, "tainted-syscall-number", name, st.get(sm.nr_reg).labels)
        if p.report_syscall_args:
            for r in sm.arg_regs:
                if st.get(r).tainted:
                    self._find(insn, "tainted-syscall-arg", f"{name}({r})", st.get(r).labels)
        for fam in sm.clobbered:
            st.set_full(fam, CLEAN)
        if name in INPUT_SYSCALLS:
            label = f"{name}@{insn.address:#x}"
            st.set_full(st.fam(sm.ret_reg), Taint(frozenset({label}), None))
            bufreg = st.fam(sm.arg_regs[1] if name not in ("getcwd", "getrandom") else sm.arg_regs[0])
            lenreg = st.fam(sm.arg_regs[2] if name not in ("getcwd", "getrandom") else sm.arg_regs[1])
            n = st.consts.get(lenreg)
            loc = st.region_of(bufreg)
            if loc is None:
                region = st.new_region(name)
                st.point_at(bufreg, region, 0)
                loc = (region, 0)
            b, k = loc
            st.taint_range(b, k, k + (n if n is not None else 1 << 20), label)
        else:
            st.set_full(st.fam(sm.ret_reg), CLEAN)

    def _string(self, insn: Insn) -> None:
        st, p = self.state, self.policy
        m = insn.mnemonic
        si, di, cx, ax = (st.fam(r) for r in ("esi", "edi", "ecx", "eax"))
        if insn.rep and p.report_rep_count and st.get(cx).tainted:
            self._find(insn, "tainted-rep-count", f"rep {m} length in {cx}", st.get(cx).labels)
        for r, kinds in ((si, "tainted-load-address"), (di, "tainted-store-address")):
            if (m.startswith(("movs", "cmps")) or (m.startswith(("stos", "scas")) and r == di)
                    or (m.startswith("lods") and r == si)):
                t = st.get(r)
                if t.tainted:
                    self._find_addr(insn, kinds, f"{m} via {r}", t)
        if m.startswith("movs"):
            src = st.get(si)
            srcval = CLEAN
            if si in st.frame_ptrs:
                b, k = st.frame_ptrs[si]
                srcval = st.mem_get(b, k)
            val = Taint(srcval.labels | (src.labels if p.taint_through_pointer else EMPTY), None)
            if di in st.frame_ptrs and val.tainted:
                b, k = st.frame_ptrs[di]
                n = st.consts.get(cx) if insn.rep else 1
                for lbl in val.labels:
                    st.taint_range(b, k, k + (n if n else 1 << 20), lbl)
        elif m.startswith("stos"):
            val = st.get(ax)
            if di in st.frame_ptrs and val.tainted:
                b, k = st.frame_ptrs[di]
                n = st.consts.get(cx) if insn.rep else 1
                for lbl in val.labels:
                    st.taint_range(b, k, k + (n if n else 1 << 20), lbl)
        elif m.startswith("lods"):
            src = st.get(si)
            val = CLEAN
            if si in st.frame_ptrs:
                b, k = st.frame_ptrs[si]
                val = st.mem_get(b, k)
            st.set_full(ax, Taint(val.labels | (src.labels if p.taint_through_pointer else EMPTY), None))
        elif m.startswith(("cmps", "scas")):
            st.set_full(FLAGS, Taint(st.get(si).labels | st.get(di).labels | st.get(ax).labels, None))
        for r in (si, di):
            st.frame_ptrs.pop(r, None)
            st.consts.pop(r, None)
        if insn.rep:
            st.set_full(cx, CLEAN)
            st.consts[cx] = 0

    def _unknown(self, insn: Insn) -> None:
        self.unknown.add(insn.mnemonic)
        if not insn.ops:
            return
        labels: Labels = EMPTY
        for i in range(len(insn.ops)):
            labels |= self._src_taint(insn, i, report=False).labels
        if isinstance(insn.ops[0], (Reg, Mem)):
            self._write(insn, 0, Taint(labels, None))

    def _find(self, insn: Insn, kind: str, detail: str, labels: Labels) -> None:
        self.findings.append(Finding(insn.address, kind, detail, labels))

    def _find_addr(self, insn: Insn, kind: str, detail: str, t: Taint) -> None:
        p = self.policy
        if p.bounded_index_is_safe and t.bound is not None:
            if p.report_bounded:
                self._find(insn, "bounded-" + kind, f"{detail} (attacker contribution <= {t.bound:#x})", t.labels)
            return
        self._find(insn, kind, detail, t.labels)
