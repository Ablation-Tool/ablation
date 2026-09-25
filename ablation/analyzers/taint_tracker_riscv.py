"""Forward labeled-taint tracker for RISC-V (RV32 and RV64).

This is the labeled-taint path for RISC-V. It complements the existing
binary-path trackers (taint_tracker_riscv32/64.py) with:
  - Labeled Taint(labels, bound) model
  - TaintState with copy/join/same_as lattice ops for CFG fixpoint analysis
  - TaintEngine: linear dispatch over an Insn stream
  - analyze_cfg() path via cfg_riscv.py + analysis_riscv.py

Usage (listing path):
    from ablation.analyzers.taint_tracker_riscv import TaintEngine, Width
    from ablation.analyzers.insn_riscv import from_listing
    eng = TaintEngine(Width.RV64)
    eng.taint_register("a0", "user")
    findings = eng.run(from_listing(text))

Usage (CFG fixpoint):
    from ablation.analyzers.analysis_riscv import analyze_cfg
    from ablation.analyzers.taint_tracker_riscv import TaintState, Width
    init = TaintState(Width.RV64); init.taint_reg("a0", "user")
    result = analyze_cfg(insns, Width.RV64, initial=init)

Sources: recv/recvfrom/read/fgets/gets/fread
Sinks:   system/execve/strcpy/sprintf/memcpy/popen

ABI: psABI integer calling convention (a0-a7 args, a0/a1 return, s0-s11 callee-saved).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .insn_riscv import Insn, jal_link_and_target, jalr_link_and_base
from .isa_riscv import (
    ARG_REGS, CALLER_SAVED, FP_ARG_REGS, FP_RET_REGS, INPUT_SYSCALLS,
    RET_REGS, SYSCALL_ARG_REGS, SYSCALL_NR_REG, SYSCALL_RET_REG, SYSCALLS,
    IsaModel, Width, andi_bound, isa_for, norm_imm12,
)

log = logging.getLogger("ablation.taint_riscv")

Labels = FrozenSet[str]
EMPTY: Labels = frozenset()
FRAME_BASES = ("sp", "s0")


@dataclass(frozen=True)
class Taint:
    """Labeled taint value.

    ``labels`` is the set of taint sources. ``bound`` is the maximum
    attacker-controlled contribution to the value: after ``andi t, x, 0xff``
    it is 0xff; after ``add p, base, t`` with a clean ``base`` still 0xff.
    Any amplifying operation with no computable limit resets ``bound`` to None.
    """
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
    bounded_index_is_safe: bool = True


@dataclass
class TaintState:
    width: Width
    regs:       Dict[str, Taint] = field(default_factory=dict)
    mem:        Dict[Tuple[str, int], Taint] = field(default_factory=dict)
    ranges:     List[Tuple[str, int, int, Taint]] = field(default_factory=list)
    consts:     Dict[str, int] = field(default_factory=dict)
    frame_ptrs: Dict[str, Tuple[str, int]] = field(default_factory=dict)
    ra_slots:   Set[Tuple[str, int]] = field(default_factory=set)

    # registers ---------------------------------------------------------------
    def get(self, r: Optional[str]) -> Taint:
        if r is None or r == "zero":
            return CLEAN
        return self.regs.get(r, CLEAN)

    def set(self, r: Optional[str], t: Taint) -> None:
        if r is None or r == "zero":
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

    # memory ------------------------------------------------------------------
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

    def taint_mem(self, base: str, off: int, label: str) -> None:
        cur = self.mem_get(base, off)
        self.mem[(base, off)] = Taint(cur.labels | {label}, None)

    def taint_range(self, base: str, lo: int, hi: int, label: str) -> None:
        self.ranges.append((base, lo, hi, Taint(frozenset({label}), None)))

    def rebase(self, reg: str, delta: int) -> None:
        self.mem = {((b, off - delta) if b == reg else (b, off)): t for (b, off), t in self.mem.items()}
        self.ranges = [((b, lo - delta, hi - delta, t) if b == reg else (b, lo, hi, t)) for (b, lo, hi, t) in self.ranges]
        self.ra_slots = {((b, off - delta) if b == reg else (b, off)) for (b, off) in self.ra_slots}
        self.frame_ptrs = {r: ((b, k - delta) if b == reg else (b, k)) for r, (b, k) in self.frame_ptrs.items()}

    def invalidate_base(self, reg: str) -> None:
        self.mem = {k: v for k, v in self.mem.items() if k[0] != reg}
        self.ranges = [r for r in self.ranges if r[0] != reg]
        self.ra_slots = {k for k in self.ra_slots if k[0] != reg}
        self.frame_ptrs = {r: v for r, v in self.frame_ptrs.items() if v[0] != reg}

    def snapshot(self) -> Dict[str, str]:
        return {r: str(t) for r, t in sorted(self.regs.items())}

    # lattice ops (CFG fixpoint) ----------------------------------------------
    def copy(self) -> "TaintState":
        return TaintState(
            self.width, dict(self.regs), dict(self.mem), list(self.ranges),
            dict(self.consts), dict(self.frame_ptrs), set(self.ra_slots),
        )

    def join(self, other: "TaintState", widen: bool = False) -> "TaintState":
        """Least upper bound for a control-flow merge.

        Labels: union. Bounds: max (clean side contributes 0); with ``widen``
        a bound that differs between the two sides becomes None so loops that
        grow a bounded value converge. Constants and frame_ptrs survive only
        when both sides agree.
        """
        out = TaintState(self.width)
        for r in set(self.regs) | set(other.regs):
            a, b = self.get(r), other.get(r)
            ab = 0 if not a.tainted else a.bound
            bb = 0 if not b.tainted else b.bound
            if ab is None or bb is None:
                bound = None
            elif widen and ab != bb:
                bound = None
            else:
                bound = max(ab, bb)
            t = Taint(a.labels | b.labels, bound)
            if t.tainted or t.bound is not None:
                out.regs[r] = t
        for k in set(self.mem) | set(other.mem):
            a, b = self.mem.get(k, CLEAN), other.mem.get(k, CLEAN)
            out.mem[k] = Taint(a.labels | b.labels, None)
        seen: Set[tuple] = set()
        for rng in self.ranges + other.ranges:
            key = (rng[0], rng[1], rng[2], rng[3].labels)
            if key not in seen:
                seen.add(key)
                out.ranges.append(rng)
        out.consts = {r: v for r, v in self.consts.items() if other.consts.get(r) == v}
        out.frame_ptrs = {r: v for r, v in self.frame_ptrs.items() if other.frame_ptrs.get(r) == v}
        out.ra_slots = self.ra_slots | other.ra_slots
        return out

    def same_as(self, other: "TaintState") -> bool:
        return (
            self.regs == other.regs and self.mem == other.mem
            and sorted(map(repr, self.ranges)) == sorted(map(repr, other.ranges))
            and self.consts == other.consts and self.frame_ptrs == other.frame_ptrs
            and self.ra_slots == other.ra_slots
        )


class TaintEngine:
    """Forward labeled-taint tracker over a linear :class:`Insn` stream.

    Seed with ``taint_register(r, label)`` then call ``run(insns)``.
    Findings accumulate in ``self.findings``; unknown mnemonics in ``self.unknown``.
    """

    def __init__(self, width: Width = Width.RV64, policy: Optional[Policy] = None):
        self.width = width
        self.isa: IsaModel = isa_for(width)
        self.policy = policy or Policy()
        self.state = TaintState(width)
        self.findings: List[Finding] = []
        self.trace: List[Tuple[Insn, Dict[str, str]]] = []
        self.unknown: Set[str] = set()

    def taint_register(self, reg: str, label: str) -> None:
        self.state.taint_reg(reg, label)

    def taint_memory(self, base: str, offset: int, label: str) -> None:
        self.state.taint_mem(base, offset, label)

    def run(self, insns: Iterable[Insn], record_trace: bool = False) -> List[Finding]:
        for insn in insns:
            self.step(insn)
            if record_trace:
                self.trace.append((insn, self.state.snapshot()))
        return self.findings

    # dispatcher --------------------------------------------------------------
    def step(self, insn: Insn) -> None:
        m, isa, st = insn.mnemonic, self.isa, self.state
        if m in isa.ret_mnems or m in ("jr", "c.jr", "jalr", "c.jalr"):
            self._jalr(insn)
        elif m in isa.call_mnems:
            self._jal(insn)
        elif m in isa.uncond_jump_mnems:
            if m == "tail":
                self._call_effects(insn, link="zero")
        elif m in isa.cond_branch_mnems:
            self._branch(insn)
        elif m == "ecall":
            self._ecall(insn)
        elif m in ("ebreak", "c.ebreak", "fence", "fence.i", "wfi", "mret", "sret"):
            pass
        elif m in isa.load_mnems:
            self._load(insn)
        elif m in isa.store_mnems:
            self._store(insn)
        elif self._is_copy(insn):
            self._copy(insn)
        elif m in isa.narrow_copy_mnems and self._narrow_copy_shape(insn):
            st.set(insn.reg(0), Taint(st.get(insn.reg(1)).labels, None))
        elif m in isa.fp_copy_mnems:
            st.set(insn.reg(0), Taint(st.get(insn.reg(1)).labels, None))
        elif m in isa.const_mnems:
            self._const(insn)
        elif m in isa.alu_ri_mnems:
            self._alu_ri(insn)
        elif m in isa.alu_rr_mnems or m in isa.fp_arith_mnems:
            self._alu_rr(insn)
        elif m in isa.csr_mnems:
            self._csr(insn)
        else:
            self._unknown(insn)

    # classifiers -------------------------------------------------------------
    def _is_copy(self, insn: Insn) -> bool:
        m = insn.mnemonic
        if m not in self.isa.copy_mnems:
            return False
        if m in ("mv", "c.mv"):
            return len(insn.ops) == 2 and insn.reg(0) is not None and insn.reg(1) is not None
        if len(insn.ops) != 3 or insn.reg(0) is None:
            return False
        rs1, rs2, imm = insn.reg(1), insn.reg(2), insn.imm(2)
        if m in ("addi", "ori", "xori", "slli", "srli", "srai"):
            return rs1 is not None and imm == 0
        if m == "andi":
            return rs1 is not None and imm is not None and norm_imm12(imm, self.isa.xlen) == -1
        if m in ("add", "or", "xor"):
            return (rs1 == "zero") != (rs2 == "zero")
        if m in ("sub", "sll", "srl", "sra"):
            return rs1 is not None and rs2 == "zero"
        return False

    def _copy_src(self, insn: Insn) -> Optional[str]:
        m = insn.mnemonic
        if m in ("add", "or", "xor") and insn.reg(1) == "zero":
            return insn.reg(2)
        return insn.reg(1)

    def _narrow_copy_shape(self, insn: Insn) -> bool:
        m = insn.mnemonic
        if m == "sext.w":
            return len(insn.ops) == 2
        if m in ("addiw", "c.addiw"):
            return (insn.imm(2) == 0) if len(insn.ops) == 3 else (insn.imm(1) == 0)
        if m in ("addw", "subw"):
            return insn.reg(2) == "zero"
        return False

    # transfer functions ------------------------------------------------------
    def _copy(self, insn: Insn) -> None:
        st = self.state
        rd, rs = insn.reg(0), self._copy_src(insn)
        if rs == "zero":
            st.set(rd, CLEAN)
            st.consts[rd] = 0
            return
        c, fp = st.consts.get(rs), st.frame_ptrs.get(rs)
        if rd == "sp" and fp is not None and fp[0] == "sp":
            st.rebase("sp", fp[1])
            return
        src = st.get(rs)
        st.set(rd, src)
        if c is not None:
            st.consts[rd] = c
        if rs in FRAME_BASES and rd != rs:
            st.frame_ptrs[rd] = (rs, 0)
        elif fp is not None:
            st.frame_ptrs[rd] = fp

    def _const(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd = insn.reg(0)
        if rd is None:
            return
        st.set(rd, CLEAN)
        v = insn.imm(1)
        mask = (1 << self.isa.xlen) - 1
        if v is None:
            return
        if m in ("li", "c.li", "la", "lla"):
            st.consts[rd] = v & mask
        elif m in ("lui", "c.lui"):
            st.consts[rd] = (v << 12) & mask
        elif m == "auipc":
            st.consts[rd] = (insn.address + (v << 12)) & mask

    def _alu_ri(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        if len(insn.ops) == 2 and insn.reg(0) is not None:
            rd = rs = insn.reg(0)
            imm = insn.imm(1)
        else:
            rd, rs, imm = insn.reg(0), insn.reg(1), insn.imm(2)
        if rd is None:
            return
        src, c = st.get(rs), st.consts.get(rs)

        if m in ("addi", "c.addi", "c.addi16sp") and imm is not None and rd == rs and rd in FRAME_BASES:
            st.rebase(rd, imm)
            if src.tainted:
                st.regs[rd] = Taint(src.labels, None)
            else:
                st.regs.pop(rd, None)
            if c is not None:
                st.consts[rd] = c + imm
            return
        if m in ("addi", "c.addi4spn") and imm is not None and rs in FRAME_BASES and rd != rs:
            st.set(rd, Taint(src.labels, None))
            st.frame_ptrs[rd] = (rs, imm)
            return
        if m == "addi" and imm is not None and rs in st.frame_ptrs and rd != rs:
            b, k = st.frame_ptrs[rs]
            st.set(rd, Taint(src.labels, None))
            st.frame_ptrs[rd] = (b, k + imm)
            return

        if m in ("andi", "c.andi"):
            b = andi_bound(norm_imm12(imm, self.isa.xlen)) if imm is not None else None
            st.set(rd, Taint(src.labels, b))
            return
        fixed = {"zext.b": 0xFF, "zext.h": 0xFFFF, "zext.w": 0xFFFF_FFFF, "slti": 1, "sltiu": 1}
        if m in fixed:
            st.set(rd, Taint(src.labels, fixed[m]))
            return
        if m in ("srli", "srliw", "c.srli") and imm and src.bound is not None:
            st.set(rd, Taint(src.labels, src.bound >> imm))
            return
        if m in ("slli", "c.slli") and imm is not None and src.bound is not None and imm < 32:
            st.set(rd, Taint(src.labels, src.bound << imm))
            return
        if m in ("addi", "c.addi") and src.bound is not None:
            st.set(rd, Taint(src.labels, src.bound))
            return

        st.set(rd, Taint(src.labels, None))
        if m in ("addi", "c.addi") and c is not None and imm is not None:
            st.consts[rd] = (c + imm) & ((1 << self.isa.xlen) - 1)

    def _alu_rr(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        rd = insn.reg(0)
        if rd is None:
            return
        srcs = insn.regs()[1:]
        if len(insn.ops) == 2 and m.startswith("c."):
            srcs = [rd] + srcs
        labels: Labels = EMPTY
        for r in srcs:
            labels |= st.get(r).labels
        bound: Optional[int] = None
        bounds = [st.get(r).bound for r in srcs if st.get(r).bound is not None]
        tainted_srcs = [r for r in srcs if st.get(r).tainted]
        all_bounded = bool(tainted_srcs) and all(st.get(r).bound is not None for r in tainted_srcs)
        if m in ("and", "minu") and bounds:
            bound = min(bounds)
        elif m in ("add", "c.add", "sub", "c.sub", "or", "c.or", "xor", "c.xor", "add.uw") and all_bounded:
            bound = sum(st.get(r).bound for r in tainted_srcs)
        elif m in ("sh1add", "sh2add", "sh3add", "sh1add.uw", "sh2add.uw", "sh3add.uw") and all_bounded and len(srcs) == 2:
            n = int(m[2])
            b1, b2 = st.get(srcs[0]), st.get(srcs[1])
            bound = ((b1.bound << n) if b1.tainted else 0) + (b2.bound if b2.tainted else 0)
        elif m == "andn" and srcs:
            bound = st.get(srcs[0]).bound
        elif m in ("slt", "sltu", "seqz", "snez", "sltz", "sgtz",
                   "feq.s", "flt.s", "fle.s", "feq.d", "flt.d", "fle.d"):
            bound = 1
        st.set(rd, Taint(labels, bound))

    def _csr(self, insn: Insn) -> None:
        rd = insn.reg(0)
        if rd is not None and insn.mnemonic not in ("csrw", "csrs", "csrc", "csrwi", "csrsi", "csrci"):
            self.state.set(rd, CLEAN)

    def _addr(self, insn: Insn, idx: int) -> Tuple[Optional[str], int]:
        mem = insn.mem(idx)
        if mem is not None:
            return mem.base, mem.offset
        if insn.reg(idx) is not None:
            return insn.reg(idx), insn.imm(idx + 1) or 0
        return None, 0

    def _load(self, insn: Insn) -> None:
        st, p = self.state, self.policy
        rd = insn.reg(0)
        base, off = self._addr(insn, 1)
        if rd is None or base is None:
            return
        bt = st.get(base)
        if bt.tainted and p.report_tainted_load_addr and not (p.bounded_index_is_safe and bt.bound is not None):
            self._find(insn, "tainted-load-address", f"load {rd} via {base}+{off}", bt.labels)
        rb, roff = st.resolve(base, off)
        result = st.mem_get(rb, roff) if rb is not None else CLEAN
        if bt.tainted and p.taint_through_pointer:
            result = Taint(result.labels | bt.labels, None)
        st.set(rd, result)

    def _store(self, insn: Insn) -> None:
        st, p = self.state, self.policy
        rs2 = insn.reg(0)
        base, off = self._addr(insn, 1)
        if base is None:
            return
        bt = st.get(base)
        if bt.tainted and p.report_tainted_store_addr and not (p.bounded_index_is_safe and bt.bound is not None):
            self._find(insn, "tainted-store-address", f"store {rs2} via {base}+{off}", bt.labels)
        rb, roff = st.resolve(base, off)
        if rb is None:
            return
        val = st.get(rs2)
        st.mem_set(rb, roff, val)
        if rs2 == "ra" and rb in FRAME_BASES:
            st.ra_slots.add((rb, roff))
        elif (rb, roff) in st.ra_slots:
            st.ra_slots.discard((rb, roff))
            if val.tainted and p.report_tainted_store_over_ra:
                self._find(insn, "tainted-overwrite-of-saved-ra", f"{rs2} -> {roff}({rb})", val.labels)

    def _branch(self, insn: Insn) -> None:
        if not self.policy.report_tainted_branch:
            return
        labels: Labels = EMPTY
        for r in insn.regs():
            labels |= self.state.get(r).labels
        if labels:
            self._find(insn, "tainted-branch-condition", insn.mnemonic, labels)

    # control transfer --------------------------------------------------------
    def _jal(self, insn: Insn) -> None:
        link, target = jal_link_and_target(insn)
        if insn.mnemonic == "call":
            link = "ra"
        if link == "zero":
            return
        self._call_effects(insn, link=link, target=target)

    def _jalr(self, insn: Insn) -> None:
        st = self.state
        link, base, off = jalr_link_and_base(insn)
        bt = st.get(base)
        if bt.tainted:
            kind = "tainted-return-address" if (link == "zero" and base == "ra") else "tainted-indirect-jump"
            self._find(insn, kind, f"{insn.mnemonic} via {base}", bt.labels)
        if link == "zero":
            return
        target = None
        if base in st.consts:
            target = (st.consts[base] + off) & ((1 << self.isa.xlen) - 1)
        self._call_effects(insn, link=link, target=target)

    def _call_effects(self, insn: Insn, link: str, target: Optional[int] = None) -> None:
        st, p = self.state, self.policy
        arg_labels: Labels = EMPTY
        for r in ARG_REGS + FP_ARG_REGS:
            arg_labels |= st.get(r).labels
        for r in CALLER_SAVED:
            st.set(r, CLEAN)
        if p.calls_propagate_to_return and arg_labels:
            for r in RET_REGS + FP_RET_REGS:
                st.set(r, Taint(arg_labels, None))
        if link != "zero":
            st.set(link, CLEAN)
            st.consts[link] = insn.address + insn.size
        st.mem = {k: v for k, v in st.mem.items() if not (k[0] == "sp" and k[1] < 0)}
        if target is not None:
            log.debug("call at %#x -> %#x", insn.address, target)

    def _ecall(self, insn: Insn) -> None:
        st, p = self.state, self.policy
        nr = st.consts.get(SYSCALL_NR_REG)
        name = SYSCALLS.get(nr, f"sys_{nr}") if nr is not None else "sys_?"
        if st.get(SYSCALL_NR_REG).tainted:
            self._find(insn, "tainted-syscall-number", name, st.get(SYSCALL_NR_REG).labels)
        if p.report_syscall_args:
            for r in SYSCALL_ARG_REGS:
                if st.get(r).tainted:
                    self._find(insn, "tainted-syscall-arg", f"{name}({r})", st.get(r).labels)
        if name in INPUT_SYSCALLS:
            label = f"{name}@{insn.address:#x}"
            st.set(SYSCALL_RET_REG, Taint(frozenset({label}), None))
            buf = st.frame_ptrs.get("a1")
            if buf is not None:
                b, k = buf
                n = st.consts.get("a2")
                st.taint_range(b, k, k + (n if n is not None else 1 << 20), label)
            else:
                st.taint_mem("a1", 0, label)
                st.taint_range("a1", 0, 1 << 20, label)
        else:
            st.set(SYSCALL_RET_REG, CLEAN)

    def _unknown(self, insn: Insn) -> None:
        self.unknown.add(insn.mnemonic)
        rd = insn.reg(0)
        if rd is None:
            return
        labels: Labels = EMPTY
        for r in insn.regs()[1:]:
            labels |= self.state.get(r).labels
        self.state.set(rd, Taint(labels, None))

    def _find(self, insn: Insn, kind: str, detail: str, labels: Labels) -> None:
        self.findings.append(Finding(insn.address, kind, detail, labels))
