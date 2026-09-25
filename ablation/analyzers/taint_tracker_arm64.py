"""
taint_tracker_arm64.py: AArch64 data-flow taint tracker.

Labeled-taint model: Taint(labels, bound).
Key AArch64 semantics:
  - Every W-register write zero-extends: result is bounded to 0xFFFFFFFF.
  - ``and rd, rn, #imm``: bitmask with top bit set = alignment mask = no bound;
    positive mask = bounds rd.
  - Shift/extend modifiers on source operands scale the bound.
  - ldp/stp pair instructions; pre/post-index writeback.
  - Linux arm64 syscall: x8=nr, x0-x5=args, x0=result; read/recvfrom taints buffer.

Sources: recv/read/readv and Linux svc (read/recvfrom syscalls)
Sinks:   system/execve/strcpy/sprintf/memcpy and other dangerous libc functions

AAPCS64: x0-x7 args, x0-x1 return, x19-x28 callee-saved, x30=lr, x29=fp.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple

from .insn_arm64 import (
    Cond, Imm, Insn, Mem, Reg, Sym,
    from_capstone,
    from_listing as _from_listing,
    from_objdump as _from_objdump,
    make_insn,
)
from .isa_arm64 import (
    ARG_REGS, CALLER_SAVED, FLAGS, FRAME_BASES, FRAME_REG, INPUT_SYSCALLS, ISA, LINK_REG,
    MASK64, RET_REGS, SYSCALL_ARG_REGS, SYSCALL_NR_REG, SYSCALL_RET_REG, SYSCALLS,
    VEC_ARG_REGS, VEC_RET_REGS, access_bytes, and_bound, ext_bound, w_cap,
)

Labels = FrozenSet[str]
EMPTY: Labels = frozenset()

_SOURCE_NAMES: frozenset = frozenset({
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "gets", "getchar", "fgetc",
})
_SINK_NAMES: frozenset = frozenset({
    "system", "execve", "execl", "execvp", "execle", "execvpe", "popen",
    "strcpy", "strcat", "sprintf", "vsprintf", "snprintf", "vsnprintf",
    "memcpy", "memmove", "gets",
})
_PLT_TOL = 16


# ---------------------------------------------------------------------------
# Taint value
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class TaintFindingARM64:
    """Binary-path source-to-sink finding (API matches other ablation trackers)."""
    func_va:      int
    func_name:    str
    sink_va:      int
    sink_name:    str
    tainted_args: List[str]
    source_name:  str
    severity:     str = "HIGH"

    def __str__(self) -> str:
        args = ", ".join(self.tainted_args)
        return (f"[{self.severity}] 0x{self.func_va:x} ({self.func_name}): "
                f"tainted {{{args}}} -> {self.sink_name} @ 0x{self.sink_va:x} "
                f"(source: {self.source_name})")


@dataclass
class Finding:
    """Generic finding from the labeled-taint engine (listing/objdump paths)."""
    address: int
    kind: str
    detail: str
    labels: Labels

    def __str__(self) -> str:
        return f"{self.address:#x} [{self.kind}] {self.detail} <- {{{','.join(sorted(self.labels))}}}"


# ---------------------------------------------------------------------------
# Taint state
# ---------------------------------------------------------------------------

@dataclass
class TaintState:
    regs:       Dict[str, Taint] = field(default_factory=dict)
    mem:        Dict[Tuple[str, int], Taint] = field(default_factory=dict)
    ranges:     List[Tuple[str, int, int, Taint]] = field(default_factory=list)
    consts:     Dict[str, int] = field(default_factory=dict)
    frame_ptrs: Dict[str, Tuple[str, int]] = field(default_factory=dict)
    lr_slots:   Set[Tuple[str, int]] = field(default_factory=set)

    def get(self, r: Optional[str]) -> Taint:
        if r is None or r == "xzr":
            return CLEAN
        return self.regs.get(r, CLEAN)

    def set(self, r: Optional[str], t: Taint) -> None:
        if r is None or r == "xzr":
            return
        if t.tainted or t.bound is not None:
            self.regs[r] = t
        else:
            self.regs.pop(r, None)
        self.consts.pop(r, None)
        self.frame_ptrs.pop(r, None)
        if r in FRAME_BASES:
            self.invalidate_base(r)

    def taint_reg(self, r: str, label: str) -> None:
        cur = self.get(r)
        self.regs[r] = Taint(cur.labels | {label}, cur.bound)

    def resolve(self, base: Optional[str], off: int) -> Tuple[Optional[str], int]:
        if base in self.frame_ptrs:
            b, k = self.frame_ptrs[base]
            return b, k + off
        return base, off

    def mem_get(self, base: str, off: int) -> Taint:
        t = self.mem.get((base, off), CLEAN)
        for b, lo, hi, rt in self.ranges:
            if b == base and lo <= off < hi:
                t = Taint(t.labels | rt.labels, None)
        return t

    def mem_set(self, base: str, off: int, t: Taint) -> None:
        if t.tainted:
            self.mem[(base, off)] = t
        else:
            self.mem.pop((base, off), None)

    def taint_range(self, base: str, lo: int, hi: int, label: str) -> None:
        self.ranges.append((base, lo, hi, Taint(frozenset({label}), None)))

    def rebase(self, reg: str, delta: int) -> None:
        self.mem = {((b, o - delta) if b == reg else (b, o)): t for (b, o), t in self.mem.items()}
        self.ranges = [((b, lo - delta, hi - delta, t) if b == reg else (b, lo, hi, t)) for (b, lo, hi, t) in self.ranges]
        self.lr_slots = {((b, o - delta) if b == reg else (b, o)) for (b, o) in self.lr_slots}
        self.frame_ptrs = {r: ((b, k - delta) if b == reg else (b, k)) for r, (b, k) in self.frame_ptrs.items()}
        if reg in self.consts:
            self.consts[reg] = (self.consts[reg] + delta) & MASK64

    def invalidate_base(self, reg: str) -> None:
        self.mem = {k: v for k, v in self.mem.items() if k[0] != reg}
        self.ranges = [r for r in self.ranges if r[0] != reg]
        self.lr_slots = {k for k in self.lr_slots if k[0] != reg}
        self.frame_ptrs = {r: v for r, v in self.frame_ptrs.items() if v[0] != reg}

    def snapshot(self) -> Dict[str, str]:
        return {r: str(t) for r, t in sorted(self.regs.items())}


# ---------------------------------------------------------------------------
# Labeled-taint engine (listing / objdump / capstone path)
# ---------------------------------------------------------------------------

class TaintEngine:
    """
    Forward labeled-taint tracker over a stream of AArch64 ``Insn`` objects.

    Seed with ``taint_register(r, label)`` then call ``run(insns)``.
    Findings accumulate in ``self.findings``; unknown mnemonics in ``self.unknown``.
    """

    def __init__(self):
        self.isa = ISA
        self.state = TaintState()
        self.findings: List[Finding] = []
        self.unknown: Set[str] = set()

    def taint_register(self, reg: str, label: str) -> None:
        from .isa_arm64 import canon_reg as _canon
        r = _canon(reg)
        self.state.taint_reg(r[0] if r else reg, label)

    def taint_memory(self, base: str, offset: int, label: str) -> None:
        self.state.mem[(base, offset)] = Taint(frozenset({label}), None)

    def run(self, insns: Iterable[Insn]) -> List[Finding]:
        for insn in insns:
            self.step(insn)
        return self.findings

    # ---- helpers -----------------------------------------------------------

    def _src(self, r: Optional[Reg]) -> Taint:
        if r is None:
            return CLEAN
        t = self.state.get(r.name)
        return Taint(t.labels, ext_bound(r.shift, r.amount, t.bound, r.bits))

    def _write(self, r: Optional[Reg], t: Taint) -> None:
        if r is None:
            return
        if r.name.startswith("x") or r.name == "sp":
            t = Taint(t.labels, w_cap(t.bound, r.bits))
        self.state.set(r.name, t)

    def _find(self, insn: Insn, kind: str, detail: str, labels: Labels) -> None:
        self.findings.append(Finding(insn.address, kind, detail, labels))

    def _check_addr(self, insn: Insn, bt: Taint, kind: str, detail: str) -> None:
        if not bt.tainted:
            return
        if bt.bound is not None:
            return
        self._find(insn, kind, detail, bt.labels)

    # ---- dispatcher --------------------------------------------------------

    def step(self, insn: Insn) -> None:
        m, isa = insn.mnemonic, self.isa
        if m in isa.ret_mnems:
            self._ret(insn)
        elif m in isa.call_mnems:
            self._call(insn)
        elif m in isa.indirect_jump_mnems:
            self._indirect_jump(insn)
        elif m in isa.uncond_branch_mnems:
            pass
        elif m in isa.cond_branch_mnems:
            self._cond_branch(insn, self.state.get(FLAGS))
        elif m in isa.reg_branch_mnems:
            self._cond_branch(insn, self._src(insn.reg(0)))
        elif m == "svc":
            self._svc(insn)
        elif m in isa.nop_mnems:
            pass
        elif m in isa.sys_mnems:
            if m == "mrs":
                self._write(insn.reg(0), CLEAN)
        elif m in isa.load_pair_mnems or m in isa.store_pair_mnems:
            self._pair(insn, load=m in isa.load_pair_mnems)
        elif m in isa.load_mnems:
            self._load(insn)
        elif m in isa.store_mnems:
            self._store(insn)
        elif m in isa.atomic_rmw_mnems:
            self._atomic(insn)
        elif m == "mov":
            self._mov(insn)
        elif self._is_copy(insn):
            self._copy(insn, insn.reg(0), self._copy_src(insn))
        elif m in isa.const_mnems:
            self._const(insn)
        elif m in isa.partial_write_mnems:
            self._partial(insn)
        elif m in isa.ext_mnems:
            self._ext(insn)
        elif m in isa.cond_select_mnems:
            self._csel(insn)
        elif m in isa.flag_setting_mnems and m in ("cmp", "cmn", "tst", "ccmp", "ccmn", "fcmp", "fcmpe", "fccmp"):
            self._flags_only(insn)
        elif m in isa.fp_copy_mnems:
            self._write(insn.reg(0), Taint(self._src(insn.reg(1)).labels, None))
        elif m in isa.alu_mnems:
            self._alu(insn)
        else:
            self._unknown(insn)

    # ---- copy detection ----------------------------------------------------

    def _is_copy(self, insn: Insn) -> bool:
        m = insn.mnemonic
        if m not in self.isa.copy_mnems or len(insn.ops) != 3:
            return False
        rd, r1, r2, imm = insn.reg(0), insn.reg(1), insn.reg(2), insn.imm(2)
        if rd is None or r1 is None or (r1.shift is not None) or (r2 is not None and r2.shift is not None):
            return False
        if m in ("add", "sub") and imm == 0:
            return True
        if m in ("lsl", "lsr", "asr", "ror") and imm == 0:
            return True
        if m == "orr":
            return (r1.name == "xzr") != (r2 is not None and r2.name == "xzr")
        if m in ("eor", "sub", "add") and r2 is not None and r2.name == "xzr":
            return True
        return False

    def _copy_src(self, insn: Insn) -> Reg:
        r1, r2 = insn.reg(1), insn.reg(2)
        if insn.mnemonic == "orr" and r1.name == "xzr":
            return r2
        return r1

    # ---- mov ---------------------------------------------------------------

    def _mov(self, insn: Insn) -> None:
        st = self.state
        rd, src, imm = insn.reg(0), insn.reg(1), insn.imm(1)
        if rd is None:
            return
        if imm is not None:
            self._write(rd, CLEAN)
            st.consts[rd.name] = imm & MASK64
            return
        if src is None:
            return
        if rd.name.startswith("v") and src.name.startswith("x"):
            self._partial(insn)
            return
        if src.bits == 128 or rd.bits == 128:
            self._write(rd, Taint(self._src(src).labels, None))
            return
        self._copy(insn, rd, src)

    def _copy(self, insn: Insn, rd: Reg, rs: Reg) -> None:
        st = self.state
        if rs.name == "xzr":
            self._write(rd, CLEAN)
            st.consts[rd.name] = 0
            return
        # mov sp, x29 with x29 = sp+k: sp restores by rebasing
        fp = st.frame_ptrs.get(rs.name)
        if rd.name == "sp" and fp is not None and fp[0] == "sp":
            st.rebase("sp", fp[1])
            return
        self._write(rd, self._src(rs))
        c = st.consts.get(rs.name)
        if c is not None and rd.bits == 64:
            st.consts[rd.name] = c
        # mov x29, sp records a live frame-pointer alias
        if rs.name in FRAME_BASES and rd.name != rs.name and rd.bits == 64:
            st.frame_ptrs[rd.name] = (rs.name, 0)
        elif fp is not None and rd.bits == 64:
            st.frame_ptrs[rd.name] = fp

    # ---- constants ---------------------------------------------------------

    def _const(self, insn: Insn) -> None:
        rd, v = insn.reg(0), insn.imm(1)
        if rd is None:
            return
        self._write(rd, CLEAN)
        if v is not None:
            m = insn.mnemonic
            self.state.consts[rd.name] = ((~v) & MASK64) if m == "movn" else (v & MASK64)

    def _partial(self, insn: Insn) -> None:
        rd = insn.reg(0)
        if rd is None:
            return
        old = self.state.get(rd.name)
        labels = old.labels
        for r in insn.regs()[1:]:
            labels |= self._src(r).labels
        c = self.state.consts.get(rd.name)
        self._write(rd, Taint(labels, None))
        if insn.mnemonic == "movk" and c is not None and insn.imm(1) is not None and not labels:
            v = insn.imm(1)
            shift = (v.bit_length() - 1) // 16 * 16 if v else 0
            self.state.consts[rd.name] = (c & ~(0xFFFF << shift) & MASK64) | (v & MASK64)

    # ---- extensions --------------------------------------------------------

    def _ext(self, insn: Insn) -> None:
        m, rd, rn = insn.mnemonic, insn.reg(0), insn.reg(1)
        if rd is None or rn is None:
            return
        src = self._src(rn)
        bound: Optional[int] = None
        if m in ("uxtb", "uxth", "uxtw"):
            bound = {"uxtb": 0xFF, "uxth": 0xFFFF, "uxtw": 0xFFFF_FFFF}[m]
            if src.bound is not None:
                bound = min(bound, src.bound)
        elif m in ("sxtb", "sxth", "sxtw"):
            bound = ext_bound(m, 0, src.bound, 64)
        elif m in ("ubfx", "ubfiz") and insn.imm(2) is not None and insn.imm(3) is not None:
            lsb, width = insn.imm(2), insn.imm(3)
            bound = (1 << width) - 1
            if m == "ubfiz":
                bound <<= lsb
        elif m == "ubfm" and insn.imm(2) is not None and insn.imm(3) is not None:
            immr, imms = insn.imm(2), insn.imm(3)
            if imms >= immr:
                bound = (1 << (imms - immr + 1)) - 1
            else:
                bound = ((1 << (imms + 1)) - 1) << (rd.bits - immr)
        self._write(rd, Taint(src.labels, bound))

    # ---- csel / cset -------------------------------------------------------

    def _csel(self, insn: Insn) -> None:
        rd = insn.reg(0)
        if rd is None:
            return
        labels = self.state.get(FLAGS).labels
        bound: Optional[int] = None
        srcs = insn.regs()[1:]
        for r in srcs:
            labels |= self._src(r).labels
        if insn.mnemonic in ("cset", "csetm"):
            bound = 1 if insn.mnemonic == "cset" else None
        elif insn.mnemonic == "csel" and len(srcs) == 2:
            bs = [self._src(r).bound for r in srcs]
            if all(b is not None for b in bs):
                bound = max(bs)
        self._write(rd, Taint(labels, bound))

    def _flags_only(self, insn: Insn) -> None:
        labels: Labels = EMPTY
        for r in insn.regs():
            labels |= self._src(r).labels
        if insn.mnemonic in ("ccmp", "ccmn", "fccmp"):
            labels |= self.state.get(FLAGS).labels
        self.state.set(FLAGS, Taint(labels, None))

    # ---- ALU ---------------------------------------------------------------

    def _alu(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd = insn.reg(0)
        if rd is None:
            return
        srcs = insn.regs()[1:]
        imm = next((o.value for o in insn.ops[1:] if isinstance(o, Imm)), None)
        taints = [self._src(r) for r in srcs]
        labels: Labels = EMPTY
        for t in taints:
            labels |= t.labels
        tainted = [t for t in taints if t.tainted]
        all_bounded = bool(tainted) and all(t.bound is not None for t in tainted)
        bound: Optional[int] = None

        # sp / frame arithmetic
        if m in ("add", "sub") and imm is not None and len(srcs) == 1 and srcs[0].shift is None:
            rn = srcs[0]
            delta = imm if m == "add" else -imm
            if rd.name == rn.name and rd.name in FRAME_BASES:
                st.rebase(rd.name, delta)
                if taints[0].tainted:
                    st.regs[rd.name] = Taint(labels, None)
                return
            if rn.name in FRAME_BASES and rd.bits == 64:
                self._write(rd, Taint(labels, None))
                st.frame_ptrs[rd.name] = (rn.name, delta)
                return
            if rn.name in st.frame_ptrs and rd.bits == 64:
                b, k = st.frame_ptrs[rn.name]
                self._write(rd, Taint(labels, None))
                st.frame_ptrs[rd.name] = (b, k + delta)
                return

        if m == "and" and imm is not None:
            bound = and_bound(imm, rd.bits)
            if bound is not None and taints and taints[0].bound is not None:
                bound = min(bound, taints[0].bound)
        elif m in ("and", "ands"):
            bs = [t.bound for t in taints if t.bound is not None]
            bound = min(bs) if bs else None
        elif m in ("bic", "bics") and taints:
            bound = taints[0].bound
        elif m in ("add", "adds", "sub", "subs", "orr", "eor") and all_bounded:
            bound = sum(t.bound for t in tainted)
        elif m in ("lsl", "lsr", "asr") and imm is not None and len(taints) == 1 and taints[0].bound is not None:
            bound = ext_bound(m, imm, taints[0].bound, 64)
        elif m in ("add", "sub") and imm is not None and len(taints) == 1:
            bound = taints[0].bound

        if m in ("adds", "subs", "ands", "bics", "adcs", "sbcs", "negs", "ngcs"):
            st.set(FLAGS, Taint(labels, None))
        self._write(rd, Taint(labels, bound))
        if m == "add" and imm is not None and len(srcs) == 1 and srcs[0].name in st.consts and not labels:
            st.consts[rd.name] = (st.consts[srcs[0].name] + imm) & MASK64

    # ---- memory helpers ----------------------------------------------------

    def _addr(self, mem: Mem) -> Tuple[Taint, Optional[str], int, bool]:
        st = self.state
        bt = st.get(mem.base)
        exact = mem.index is None
        if mem.index is not None:
            it = self._src(mem.index)
            bt = Taint(bt.labels | it.labels, None if it.tainted else None)
        rb, roff = st.resolve(mem.base, mem.offset)
        return bt, rb, roff, exact

    def _writeback(self, mem: Mem) -> None:
        st = self.state
        if mem.writeback == "pre":
            delta = mem.offset
        elif mem.writeback == "post":
            delta = mem.wb_amount
        else:
            return
        if mem.base in FRAME_BASES:
            st.rebase(mem.base, delta)
        elif mem.base in st.frame_ptrs:
            b, k = st.frame_ptrs[mem.base]
            st.frame_ptrs[mem.base] = (b, k + delta)
        elif mem.base in st.consts:
            st.consts[mem.base] = (st.consts[mem.base] + delta) & MASK64

    def _load_value(self, rb: Optional[str], off: int, exact: bool, bt: Taint, nbytes: int, signed: bool) -> Taint:
        st = self.state
        val = st.mem_get(rb, off) if (rb is not None and exact) else CLEAN
        if bt.tainted:
            val = Taint(val.labels | bt.labels, val.bound)
        bound = None if signed or nbytes >= 8 else (1 << (8 * nbytes)) - 1
        if val.bound is not None and bound is not None:
            bound = min(bound, val.bound)
        elif val.bound is not None:
            bound = val.bound
        return Taint(val.labels, bound if val.tainted else None)

    def _load(self, insn: Insn) -> None:
        rd = insn.reg(0)
        mem = insn.first_mem()
        if rd is None:
            return
        if mem is None:
            self._write(rd, CLEAN)
            return
        if mem.writeback == "pre":
            self._writeback(mem)
            mem = Mem(mem.base, 0)
        bt, rb, roff, exact = self._addr(mem)
        self._check_addr(insn, bt, "tainted-load-address", f"{insn.mnemonic} {rd} via {mem}")
        nbytes, signed = access_bytes(insn.mnemonic, rd.bits)
        self._write(rd, self._load_value(rb, roff, exact, bt, nbytes, signed))
        if mem.writeback == "post":
            self._writeback(mem)

    def _store(self, insn: Insn) -> None:
        rt = insn.reg(0)
        mem = insn.first_mem()
        if mem is None:
            return
        if insn.mnemonic in ("stxr", "stlxr", "stxrb", "stxrh", "stlxrb", "stlxrh"):
            self._write(rt, CLEAN)
            rt = insn.reg(1)
        if mem.writeback == "pre":
            self._writeback(mem)
            mem = Mem(mem.base, 0)
        bt, rb, roff, exact = self._addr(mem)
        self._check_addr(insn, bt, "tainted-store-address", f"{insn.mnemonic} {rt} via {mem}")
        if rb is not None and exact:
            self._store_slot(insn, rb, roff, rt)
        if mem.writeback == "post":
            self._writeback(mem)

    def _store_slot(self, insn: Insn, rb: str, off: int, rt: Optional[Reg]) -> None:
        st = self.state
        val = self._src(rt) if rt is not None else CLEAN
        st.mem_set(rb, off, val)
        if rt is not None and rt.name == LINK_REG and rb in FRAME_BASES:
            st.lr_slots.add((rb, off))
        elif (rb, off) in st.lr_slots:
            st.lr_slots.discard((rb, off))
            if val.tainted:
                self._find(insn, "tainted-overwrite-of-saved-lr", f"{rt} -> [{rb}, #{off}]", val.labels)

    def _pair(self, insn: Insn, load: bool) -> None:
        r1, r2 = insn.reg(0), insn.reg(1)
        mem = insn.first_mem()
        if r1 is None or r2 is None or mem is None:
            return
        if insn.mnemonic in ("stxp", "stlxp"):
            self._write(r1, CLEAN)
            r1, r2 = insn.reg(1), insn.reg(2)
        if mem.writeback == "pre":
            self._writeback(mem)
            mem = Mem(mem.base, 0)
        bt, rb, roff, exact = self._addr(mem)
        kind = "tainted-load-address" if load else "tainted-store-address"
        self._check_addr(insn, bt, kind, f"{insn.mnemonic} {r1},{r2} via {mem}")
        nbytes = 4 if insn.mnemonic == "ldpsw" else (r1.bits // 8 if r1 else 8)
        if load:
            self._write(r1, self._load_value(rb, roff, exact, bt, nbytes, insn.mnemonic == "ldpsw"))
            self._write(r2, self._load_value(rb, roff + nbytes, exact, bt, nbytes, insn.mnemonic == "ldpsw"))
        elif rb is not None and exact:
            self._store_slot(insn, rb, roff, r1)
            self._store_slot(insn, rb, roff + nbytes, r2)
        if mem.writeback == "post":
            self._writeback(mem)

    def _atomic(self, insn: Insn) -> None:
        rs, rt, mem = insn.reg(0), insn.reg(1), insn.first_mem()
        if rs is None or rt is None or mem is None:
            return
        bt, rb, roff, exact = self._addr(mem)
        self._check_addr(insn, bt, "tainted-store-address", f"{insn.mnemonic} via {mem}")
        old = self._load_value(rb, roff, exact, bt, rt.bits // 8, False)
        m = insn.mnemonic
        if m.startswith("cas"):
            self._write(rs, old)
            new = Taint(old.labels | self._src(rt).labels, None)
        else:
            new = self._src(rs) if m.startswith("swp") else Taint(old.labels | self._src(rs).labels, None)
            self._write(rt, old)
        if rb is not None and exact:
            self.state.mem_set(rb, roff, new)

    # ---- control flow ------------------------------------------------------

    def _cond_branch(self, insn: Insn, t: Taint) -> None:
        pass

    def _call(self, insn: Insn) -> None:
        st = self.state
        if insn.mnemonic == "bl":
            target = insn.imm(0)
        else:
            rn = insn.reg(0)
            bt = self._src(rn)
            if bt.tainted:
                self._find(insn, "tainted-indirect-call", f"{insn.mnemonic} via {rn}", bt.labels)
            target = st.consts.get(rn.name) if rn else None
        self._call_effects(insn, target)

    def _call_effects(self, insn: Insn, target: Optional[int]) -> None:
        st = self.state
        arg_labels: Labels = EMPTY
        for r in ARG_REGS + VEC_ARG_REGS:
            arg_labels |= st.get(r).labels
        for r in CALLER_SAVED:
            st.set(r, CLEAN)
        st.set(FLAGS, CLEAN)
        if arg_labels:
            for r in RET_REGS + VEC_RET_REGS:
                st.set(r, Taint(arg_labels, None))
        st.set(LINK_REG, CLEAN)
        st.consts[LINK_REG] = (insn.address + insn.size) & MASK64
        st.mem = {k: v for k, v in st.mem.items() if not (k[0] == "sp" and k[1] < 0)}

    def _indirect_jump(self, insn: Insn) -> None:
        rn = insn.reg(0)
        bt = self._src(rn)
        if bt.tainted:
            self._find(insn, "tainted-indirect-jump", f"{insn.mnemonic} via {rn}", bt.labels)

    def _ret(self, insn: Insn) -> None:
        rn = insn.reg(0)
        name = rn.name if rn is not None else LINK_REG
        bt = self.state.get(name)
        if bt.tainted:
            self._find(insn, "tainted-return-address", f"{insn.mnemonic} via {name}", bt.labels)

    def _svc(self, insn: Insn) -> None:
        st = self.state
        nr = st.consts.get(SYSCALL_NR_REG)
        name = SYSCALLS.get(nr, f"sys_{nr}") if nr is not None else "sys_?"
        if st.get(SYSCALL_NR_REG).tainted:
            self._find(insn, "tainted-syscall-number", name, st.get(SYSCALL_NR_REG).labels)
        for r in SYSCALL_ARG_REGS:
            if st.get(r).tainted:
                self._find(insn, "tainted-syscall-arg", f"{name}({r})", st.get(r).labels)
        if name in INPUT_SYSCALLS:
            label = f"{name}@{insn.address:#x}"
            st.set(SYSCALL_RET_REG, Taint(frozenset({label}), None))
            buf = st.frame_ptrs.get("x1")
            n = st.consts.get("x2")
            if buf is not None:
                b, k = buf
                st.taint_range(b, k, k + (n if n is not None else 1 << 20), label)
            else:
                st.taint_range("x1", 0, n if n is not None else 1 << 20, label)
        else:
            st.set(SYSCALL_RET_REG, CLEAN)

    def _unknown(self, insn: Insn) -> None:
        self.unknown.add(insn.mnemonic)
        rd = insn.reg(0)
        if rd is None:
            return
        labels: Labels = EMPTY
        for r in insn.regs()[1:]:
            labels |= self._src(r).labels
        self._write(rd, Taint(labels, None))


# ---------------------------------------------------------------------------
# Binary-path helpers
# ---------------------------------------------------------------------------

def _name_at(symbols: Dict[int, str], va: int, tol: int = _PLT_TOL) -> Optional[str]:
    if va in symbols:
        return symbols[va]
    for off in range(0, tol + 1, 4):
        if va + off in symbols:
            return symbols[va + off]
        if va - off in symbols:
            return symbols[va - off]
    return None


def _load_elf(path: str):
    try:
        import lief
        elf = lief.parse(path)
        if elf is None:
            raise ValueError(f"lief: cannot parse {path}")
        data = Path(path).read_bytes()
        text = elf.get_section(".text")
        if text:
            text_start = text.virtual_address
            text_end   = text_start + text.size
            base_va    = text.virtual_address - text.offset
        else:
            base_va = text_start = 0
            text_end = len(data)
        syms: Dict[int, str] = {}
        for sym in elf.symbols:
            if sym.name and sym.value:
                syms[sym.value] = sym.name
        return data, base_va, text_start, text_end, syms
    except ImportError:
        pass
    from elftools.elf.elffile import ELFFile
    data = Path(path).read_bytes()
    ef = ELFFile(open(path, "rb"))
    text_sh = ef.get_section_by_name(".text")
    if text_sh:
        text_start = text_sh["sh_addr"]
        text_end   = text_start + text_sh["sh_size"]
        base_va    = text_sh["sh_addr"] - text_sh["sh_offset"]
    else:
        base_va = text_start = text_end = 0
        text_end = len(data)
    syms: Dict[int, str] = {}
    for sec in ef.iter_sections():
        if sec.name in (".symtab", ".dynsym"):
            for sym in sec.iter_symbols():
                if sym.name and sym["st_value"]:
                    syms[sym["st_value"]] = sym.name
    return data, base_va, text_start, text_end, syms


# ---------------------------------------------------------------------------
# ARM64TaintTracker: binary-path API
# ---------------------------------------------------------------------------

class ARM64TaintTracker:
    """
    Intraprocedural + interprocedural taint tracker for AArch64 ELF binaries.

    Binary path: capstone disassembly -> TaintEngine.
    Source/sink: recv/read -> x0; system/strcpy -> x0-x7.

    Also exposes:
      run_from_listing(text)  -- listing text path
      run_from_objdump(text)  -- objdump -d text path
    Both return List[Finding] (generic labeled-taint findings).
    """

    def __init__(self, data: bytes, base_va: int, text_start: int, text_end: int,
                 symbols: Dict[int, str]):
        self._data       = data
        self._base_va    = base_va
        self._text_start = text_start
        self._text_end   = text_end
        self._syms       = symbols

    @classmethod
    def from_path(cls, path: str) -> "ARM64TaintTracker":
        data, base_va, text_start, text_end, syms = _load_elf(path)
        return cls(data, base_va, text_start, text_end, syms)

    @classmethod
    def from_context(cls, ctx) -> "ARM64TaintTracker":
        data = Path(ctx.path).read_bytes() if hasattr(ctx, "path") else b""
        base_va    = getattr(ctx, "base_va", 0)
        text_start = getattr(ctx, "text_start", 0)
        text_end   = getattr(ctx, "text_end", len(data))
        syms: Dict[int, str] = {}
        if hasattr(ctx, "plt"):
            syms.update({v: k for k, v in ctx.plt.items()})
        if hasattr(ctx, "exports"):
            syms.update({v: k for k, v in ctx.exports.items()})
        return cls(data, base_va, text_start, text_end, syms)

    # ---- listing / objdump entry points ------------------------------------

    def run_from_listing(self, text: str, label: str = "input") -> List[Finding]:
        eng = TaintEngine()
        for r in ARG_REGS:
            eng.taint_register(r, label)
        return eng.run(_from_listing(text))

    def run_from_objdump(self, text: str, label: str = "input") -> List[Finding]:
        eng = TaintEngine()
        for r in ARG_REGS:
            eng.taint_register(r, label)
        return eng.run(_from_objdump(text))

    # ---- binary scan -------------------------------------------------------

    def _get_func_starts(self) -> List[int]:
        starts: Set[int] = set()
        for va in self._syms:
            if self._text_start <= va < self._text_end:
                starts.add(va)
        if not starts:
            starts.add(self._text_start)
        return sorted(starts)

    def _insns_for_func(self, func_va: int, func_end: int) -> List[Insn]:
        offset = func_va - self._base_va
        length = func_end - func_va
        if offset < 0 or offset + length > len(self._data):
            return []
        snippet = self._data[offset:offset + length]
        return list(from_capstone(snippet, func_va))

    def _scan_func_binary(self, func_va: int, func_end: int,
                          init_labels: Optional[Set[str]] = None) -> List[TaintFindingARM64]:
        func_name = self._syms.get(func_va, f"fn_0x{func_va:x}")
        findings: List[TaintFindingARM64] = []

        eng = TaintEngine()
        if init_labels:
            for r in ARG_REGS:
                for lbl in init_labels:
                    eng.taint_register(r, lbl)

        insns = self._insns_for_func(func_va, func_end)
        for insn in insns:
            m = insn.mnemonic
            if m == "bl":
                target = insn.imm(0)
                callee_name = _name_at(self._syms, target) if target else None
                st = eng.state

                if callee_name in _SOURCE_NAMES:
                    for r in CALLER_SAVED:
                        st.set(r, CLEAN)
                    for r in RET_REGS:
                        st.set(r, Taint(frozenset({callee_name}), None))

                elif callee_name in _SINK_NAMES:
                    tainted_args = [r for r in ARG_REGS if st.get(r).tainted]
                    if tainted_args:
                        labels = frozenset().union(*(st.get(r).labels for r in tainted_args))
                        sev = "CRITICAL" if callee_name in (
                            "system", "execve", "execl", "execvp", "popen") else "HIGH"
                        findings.append(TaintFindingARM64(
                            func_va=func_va, func_name=func_name,
                            sink_va=insn.address, sink_name=callee_name,
                            tainted_args=tainted_args,
                            source_name=next(iter(sorted(labels)), "unknown"),
                            severity=sev,
                        ))
                    eng._call_effects(insn, target)
                else:
                    eng._call_effects(insn, target)
            elif m in ISA.ret_mnems:
                break
            else:
                eng.step(insn)

        return findings

    # ---- public API -------------------------------------------------------

    def run(self) -> List[TaintFindingARM64]:
        starts = self._get_func_starts()
        findings: List[TaintFindingARM64] = []
        for i, fva in enumerate(starts):
            fend = starts[i + 1] if i + 1 < len(starts) else self._text_end
            findings.extend(self._scan_func_binary(fva, fend))
        return findings

    def run_interprocedural(self, depth: int = 4) -> List[TaintFindingARM64]:
        starts   = self._get_func_starts()
        func_end: Dict[int, int] = {}
        for i, fva in enumerate(starts):
            func_end[fva] = starts[i + 1] if i + 1 < len(starts) else self._text_end

        findings: List[TaintFindingARM64] = []
        queue:    List[Tuple[int, int, Set[str]]] = [(fva, depth, set()) for fva in starts]
        visited:  Dict[Tuple, int] = {}

        while queue:
            fva, d, init_labels = queue.pop(0)
            key = (fva,) + tuple(sorted(init_labels))
            if visited.get(key, -1) >= d:
                continue
            visited[key] = d
            fend = func_end.get(fva, self._text_end)
            func_name = self._syms.get(fva, f"fn_0x{fva:x}")

            eng = TaintEngine()
            for r in ARG_REGS:
                for lbl in init_labels:
                    eng.taint_register(r, lbl)

            for insn in self._insns_for_func(fva, fend):
                m = insn.mnemonic
                if m == "bl":
                    target = insn.imm(0)
                    callee_name = _name_at(self._syms, target) if target else None
                    st = eng.state

                    if callee_name in _SOURCE_NAMES:
                        for r in CALLER_SAVED:
                            st.set(r, CLEAN)
                        for r in RET_REGS:
                            st.set(r, Taint(frozenset({callee_name}), None))

                    elif callee_name in _SINK_NAMES:
                        tainted_args = [r for r in ARG_REGS if st.get(r).tainted]
                        if tainted_args:
                            labels = frozenset().union(*(st.get(r).labels for r in tainted_args))
                            sev = "CRITICAL" if callee_name in (
                                "system", "execve", "execl", "execvp", "popen") else "HIGH"
                            findings.append(TaintFindingARM64(
                                func_va=fva, func_name=func_name,
                                sink_va=insn.address, sink_name=callee_name,
                                tainted_args=tainted_args,
                                source_name=next(iter(sorted(labels)), "unknown"),
                                severity=sev,
                            ))
                        eng._call_effects(insn, target)
                    else:
                        tainted_into = [r for r in ARG_REGS if st.get(r).tainted]
                        if d > 0 and tainted_into:
                            callee_labels = set().union(*(st.get(r).labels for r in tainted_into))
                            c_va = target or 0
                            for off in range(0, _PLT_TOL + 1, 4):
                                if c_va + off in func_end:
                                    c_va += off; break
                                if c_va - off in func_end and c_va - off > 0:
                                    c_va -= off; break
                            if c_va in func_end:
                                queue.append((c_va, d - 1, callee_labels))
                        eng._call_effects(insn, target)
                elif m in ISA.ret_mnems:
                    break
                else:
                    eng.step(insn)

        seen: Set[Tuple] = set()
        unique: List[TaintFindingARM64] = []
        for f in findings:
            k = (f.func_va, f.sink_va, f.sink_name)
            if k not in seen:
                seen.add(k)
                unique.append(f)
        return unique

    def report(self, findings: List[TaintFindingARM64]) -> str:
        if not findings:
            return "ARM64 taint: no findings."
        lines = [f"ARM64 taint: {len(findings)} finding(s)\n"]
        for f in sorted(findings, key=lambda x: (x.func_va, x.sink_va)):
            lines.append(str(f))
        return "\n".join(lines)
