"""
taint_tracker_v850.py: Renesas V850/RH850 data-flow taint tracker.

Labeled-taint model: Taint(labels: frozenset, bound: Optional[int]).
Mnemonic dispatch via isa_for(variant). andi zero-extends so it always bounds.
prepare/dispose track saved-lp slot for overwrite detection.

ABI: V850 EABI (GCC default)
  r6-r9:  argument registers (4 regs)
  r10-r11: return values, caller-saved
  r20-r29: callee-saved
  r31=lp (link pointer / return address)

Sources: recv/recvfrom/read/fgets/gets/fread (return value in r10)
Sinks:   system/execve/execl/execvp/popen/strcpy/sprintf/snprintf/memcpy/strcat

Targets: Renesas RH850/G3M, RH850/G3MH, V850E2R, V850E3V5, NEC V850ES/SJ3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple, Union

from .insn_v850 import (
    Insn, Mem, Reg, RegList, Sym,
    from_listing as _from_listing,
    from_objdump as _from_objdump,
    from_v850_frames,
    jarl_link_and_target,
    jmp_base,
    make_insn,
)
from .isa_v850 import (
    ABS_BASE, ARG_REGS, CALLER_SAVED, EP_BASE, LINK_REG, MASK32, RET_REGS, Variant,
    isa_for, norm_imm16_sext, norm_imm16_zext, norm_imm5_sext, reg_by_num, reg_num,
)
from .v850_decoder import V850Decoder, V850Frame

Labels = FrozenSet[str]
EMPTY: Labels = frozenset()

_LOAD_BOUND = {"ld.bu": 0xFF, "ld.hu": 0xFFFF, "sld.bu": 0xFF, "sld.hu": 0xFFFF}

# Sources: functions whose return value we treat as attacker-controlled
_SOURCE_NAMES: frozenset = frozenset({
    "recv", "recvfrom", "recvmsg", "read", "fread",
    "fgets", "gets", "getchar", "fgetc",
})

# Sinks: dangerous functions
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
# Finding records
# ---------------------------------------------------------------------------

@dataclass
class TaintFindingV850:
    """Finding from the source-to-sink binary scan (backward-compatible API)."""
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
class State:
    regs:       Dict[str, Taint] = field(default_factory=dict)
    flags:      Taint = CLEAN
    mem:        Dict[Tuple[str, int], Taint] = field(default_factory=dict)
    consts:     Dict[str, int] = field(default_factory=dict)
    frame_ptrs: Dict[str, Tuple[str, int]] = field(default_factory=dict)
    lp_slots:   Set[Tuple[str, int]] = field(default_factory=set)

    def get(self, r: Optional[str]) -> Taint:
        if r is None or r == "r0":
            return CLEAN
        return self.regs.get(r, CLEAN)

    def set(self, r: Optional[str], t: Taint) -> None:
        if r is None or r == "r0":
            return
        if t.tainted or t.bound is not None:
            self.regs[r] = t
        else:
            self.regs.pop(r, None)
        self.consts.pop(r, None)
        self.frame_ptrs.pop(r, None)
        if r == "sp":
            self.invalidate_base("sp")

    def taint_reg(self, r: str, label: str) -> None:
        cur = self.get(r)
        self.regs[r] = Taint(cur.labels | {label}, cur.bound)

    def resolve(self, base: Optional[str], off: int) -> Tuple[Optional[str], int]:
        """Canonical (base, offset) key for a memory reference."""
        if base is None:
            return None, 0
        if base == "r0":
            return ABS_BASE, off & MASK32
        if base in ("sp", EP_BASE):
            return base, off
        if base in self.frame_ptrs:
            b, k = self.frame_ptrs[base]
            return b, k + off
        if base in self.consts:
            return ABS_BASE, (self.consts[base] + off) & MASK32
        return None, 0

    def mem_get(self, base: str, off: int) -> Taint:
        return self.mem.get((base, off), CLEAN)

    def mem_set(self, base: str, off: int, t: Taint) -> None:
        if t.tainted:
            self.mem[(base, off)] = t
        else:
            self.mem.pop((base, off), None)

    def rebase(self, reg: str, delta: int) -> None:
        self.mem = {((b, o - delta) if b == reg else (b, o)): t for (b, o), t in self.mem.items()}
        self.lp_slots = {((b, o - delta) if b == reg else (b, o)) for (b, o) in self.lp_slots}
        self.frame_ptrs = {r: ((b, k - delta) if b == reg else (b, k)) for r, (b, k) in self.frame_ptrs.items()}

    def invalidate_base(self, reg: str) -> None:
        self.mem = {k: v for k, v in self.mem.items() if k[0] != reg}
        self.lp_slots = {k for k in self.lp_slots if k[0] != reg}
        self.frame_ptrs = {r: v for r, v in self.frame_ptrs.items() if v[0] != reg}

    # lattice ops (CFG fixpoint) ------------------------------------------
    def copy(self) -> "State":
        return State(
            dict(self.regs), self.flags, dict(self.mem),
            dict(self.consts), dict(self.frame_ptrs), set(self.lp_slots),
        )

    def join(self, other: "State", widen: bool = False) -> "State":
        """Least upper bound for a control-flow merge."""
        out = State()
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
        fl_a, fl_b = self.flags, other.flags
        out.flags = Taint(fl_a.labels | fl_b.labels, None)
        for k in set(self.mem) | set(other.mem):
            a, b = self.mem.get(k, CLEAN), other.mem.get(k, CLEAN)
            out.mem[k] = Taint(a.labels | b.labels, None)
        out.consts = {r: v for r, v in self.consts.items() if other.consts.get(r) == v}
        out.frame_ptrs = {r: v for r, v in self.frame_ptrs.items() if other.frame_ptrs.get(r) == v}
        out.lp_slots = self.lp_slots | other.lp_slots
        return out

    def same_as(self, other: "State") -> bool:
        return (
            self.regs == other.regs and self.flags == other.flags
            and self.mem == other.mem and self.consts == other.consts
            and self.frame_ptrs == other.frame_ptrs and self.lp_slots == other.lp_slots
        )


# ---------------------------------------------------------------------------
# Labeled-taint engine (listing / objdump path)
# ---------------------------------------------------------------------------

class TaintEngine:
    """
    Forward labeled-taint tracker over a stream of ``Insn`` objects.

    Use ``taint_register(r, label)`` to seed sources, then call ``run(insns)``.
    Findings are accumulated in ``self.findings``; unknown mnemonics in ``self.unknown``.
    """

    def __init__(self, variant: Variant = Variant.RH850):
        self.variant = variant
        self.isa = isa_for(variant)
        self.state = State()
        self.findings: List[Finding] = []
        self.unknown: Set[str] = set()

    def taint_register(self, reg: str, label: str) -> None:
        self.state.taint_reg(reg, label)

    def run(self, insns: Iterable[Insn]) -> List[Finding]:
        for insn in insns:
            self.step(insn)
        return self.findings

    # ---- dispatch ----------------------------------------------------------

    def step(self, insn: Insn) -> None:
        m, isa = insn.mnemonic, self.isa
        if m not in isa.available:
            self._unknown(insn)
        elif m == "mov":
            self._mov(insn)
        elif m in isa.call_mnems:
            self._call(insn)
        elif m == "jmp":
            self._jmp(insn)
        elif m == "jr":
            pass
        elif m in isa.ret_mnems:
            pass
        elif m in isa.cond_branch_mnems:
            self._branch(insn)
        elif m in isa.stack_mnems:
            self._stack(insn)
        elif m in isa.load_mnems:
            self._load(insn)
        elif m in isa.store_mnems:
            self._store(insn)
        elif m in isa.bit_mem_mnems:
            self._bitmem(insn)
        elif m in isa.sysreg_mnems:
            self._sysreg(insn)
        elif m in isa.flag_only_mnems:
            self._flags_from(insn.regs())
        elif m in ("setf", "sasf"):
            self._setf(insn)
        elif m == "switch":
            self._switch(insn)
        elif m in ("trap", "fetrap", "syscall", "rie"):
            self._trap(insn)
        elif m in isa.nop_mnems:
            pass
        elif m in isa.alu_mnems:
            self._alu(insn)
        else:
            self._unknown(insn)

    # ---- helpers -----------------------------------------------------------

    def _flags_from(self, regs: List[str], extra: Taint = CLEAN) -> None:
        labels: Labels = extra.labels
        for r in regs:
            labels |= self.state.get(r).labels
        self.state.flags = Taint(labels, None)

    def _find(self, insn: Insn, kind: str, detail: str, labels: Labels) -> None:
        self.findings.append(Finding(insn.address, kind, detail, labels))

    def _addr_check(self, insn: Insn, base: Optional[str], what: str) -> None:
        bt = self.state.get(base)
        if not bt.tainted:
            return
        # Bounded address (e.g. array index after andi) is safe
        if bt.bound is not None:
            return
        kind = f"tainted-{what}-address"
        self._find(insn, kind, f"{insn.mnemonic} via {base}", bt.labels)

    # ---- mov / constants ---------------------------------------------------

    def _mov(self, insn: Insn) -> None:
        st = self.state
        rd = insn.reg(1)
        if rd is None:
            return
        src = insn.ops[0]
        if isinstance(src, Reg):
            rs = src.name
            if rs == "r0":
                st.set(rd, CLEAN)
                st.consts[rd] = 0
                return
            fp = st.frame_ptrs.get(rs)
            if rd == "sp" and fp is not None and fp[0] == "sp":
                st.rebase("sp", fp[1])
                st.regs.pop("sp", None)
                return
            st.set(rd, st.get(rs))
            c = st.consts.get(rs)
            if c is not None:
                st.consts[rd] = c
            if rs == "sp":
                st.frame_ptrs[rd] = ("sp", 0)
            elif fp is not None:
                st.frame_ptrs[rd] = fp
        elif isinstance(src, Sym):
            st.set(rd, CLEAN)
        else:
            st.set(rd, CLEAN)
            v = insn.imm(0)
            if v is not None:
                st.consts[rd] = v & MASK32

    # ---- ALU ---------------------------------------------------------------

    def _alu(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        ops = insn.ops
        if not ops or not isinstance(ops[-1], Reg):
            return
        rd = ops[-1].name
        srcs = [o.name for o in ops[:-1] if isinstance(o, Reg)]
        imm = next((o.value for o in ops[:-1] if hasattr(o, "value")), None)
        nops = len(ops)

        inplace = nops == 2 and m in (
            "add", "sub", "subr", "mulh", "and", "or", "xor",
            "shl", "shr", "sar", "satadd", "satsub", "satsubr", "divh",
        )
        unary_inplace = nops == 1 and m in ("zxb", "zxh", "sxb", "sxh", "bsh", "bsw", "hsw", "hsh")
        if inplace or unary_inplace:
            srcs = srcs + [rd]
        if m == "not" and nops == 2:
            srcs = [insn.reg(0)]

        # Constant resolution: movhi/movea/addi imm, r0, rd
        if m in ("movhi", "movea", "addi") and nops == 3 and insn.reg(1) == "r0" and imm is not None:
            st.set(rd, CLEAN)
            v = (imm << 16) if m == "movhi" else norm_imm16_sext(imm)
            st.consts[rd] = v & MASK32
            return

        # sp arithmetic
        if rd == "sp" and imm is not None:
            delta = None
            if m == "add" and nops == 2:
                delta = norm_imm5_sext(imm)
            elif m in ("addi", "movea") and nops == 3 and insn.reg(1) == "sp":
                delta = norm_imm16_sext(imm)
            if delta is not None:
                st.rebase("sp", delta)
                st.regs.pop("sp", None)
                c = st.consts.get("sp")
                if c is not None:
                    st.consts["sp"] = (c + delta) & MASK32
                return

        # rd = sp + imm (frame pointer / buffer address derivation)
        if m in ("addi", "movea") and nops == 3 and imm is not None:
            rs1 = insn.reg(1)
            if rs1 == "sp" or rs1 in st.frame_ptrs:
                b, k = st.frame_ptrs.get(rs1, ("sp", 0))
                st.set(rd, Taint(st.get(rs1).labels, None))
                st.frame_ptrs[rd] = (b, k + norm_imm16_sext(imm))
                return

        # Gather taint from sources
        labels: Labels = EMPTY
        for r in srcs:
            labels |= st.get(r).labels
        tainted_srcs = [r for r in srcs if st.get(r).tainted]
        all_bounded = bool(tainted_srcs) and all(st.get(r).bound is not None for r in tainted_srcs)
        src0 = st.get(srcs[0]) if srcs else CLEAN

        bound: Optional[int] = None
        if m == "andi" and imm is not None:
            # V850 andi zero-extends: ALWAYS bounds rd to [0, imm16]; no identity case
            bound = norm_imm16_zext(imm)
            if src0.bound is not None:
                bound = min(bound, src0.bound)
        elif m == "and" and nops == 2:
            bs = [st.get(r).bound for r in srcs if st.get(r).bound is not None]
            bound = min(bs) if bs else None
        elif m == "zxb":
            bound = 0xFF
        elif m == "zxh":
            bound = 0xFFFF
        elif m == "shl" and imm is not None and nops == 2 and src0.bound is not None and imm < 32:
            bound = src0.bound << imm
        elif m == "shr" and imm is not None and nops == 2 and src0.bound is not None:
            bound = src0.bound >> imm
        elif m in ("add", "addi", "movea", "sub", "subr", "satadd", "satsub", "satsubi", "satsubr") and all_bounded:
            bound = sum(st.get(r).bound for r in tainted_srcs)
        elif m == "cmov" and all_bounded:
            bound = max(st.get(r).bound for r in tainted_srcs)
        elif m in ("ori", "xori") and imm is not None and imm == 0:
            bound = src0.bound
        elif m in ("sch0l", "sch0r", "sch1l", "sch1r"):
            bound = 32

        # Constant propagation through clean arithmetic
        c0 = st.consts.get(srcs[0]) if srcs else None
        newc: Optional[int] = None
        if imm is not None and c0 is not None and not labels:
            if m in ("addi", "movea"):
                newc = c0 + norm_imm16_sext(imm)
            elif m == "movhi":
                newc = c0 + (imm << 16)
            elif m == "add" and nops == 2:
                rd_c = st.consts.get(rd)
                newc = None if rd_c is None else rd_c + norm_imm5_sext(imm)
            elif m == "ori":
                newc = c0 | norm_imm16_zext(imm)

        if m in self.isa.twodest_mnems and nops == 3 and insn.reg(1) is not None:
            st.set(insn.reg(1), Taint(labels, None))
            st.set(rd, Taint(labels, None))
        else:
            st.set(rd, Taint(labels, bound))
        if newc is not None:
            st.consts[rd] = newc & MASK32
        if m not in ("movea", "movhi", "addi", "cmov", "bsh", "bsw", "hsw", "hsh", "sxb", "sxh", "zxb", "zxh"):
            self._flags_from(srcs)

    # ---- setf / sasf -------------------------------------------------------

    def _setf(self, insn: Insn) -> None:
        rd = insn.reg(1)
        if rd is None:
            return
        if insn.mnemonic == "sasf":
            self.state.set(rd, Taint(self.state.get(rd).labels, None))
        else:
            self.state.set(rd, Taint(EMPTY, 1))

    # ---- switch ------------------------------------------------------------

    def _switch(self, insn: Insn) -> None:
        r = insn.reg(0)
        t = self.state.get(r)
        if t.tainted:
            self._find(insn, "tainted-switch-index", f"switch {r}", t.labels)

    # ---- memory ------------------------------------------------------------

    def _load(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        mem = insn.mem(0)
        rd = insn.reg(1)
        if mem is None or rd is None:
            return
        self._addr_check(insn, mem.base, "load")
        base, off = st.resolve(mem.base, mem.offset)
        val = st.mem_get(base, off) if base is not None else CLEAN
        bt = st.get(mem.base)
        if bt.tainted:
            val = Taint(val.labels | bt.labels, None)
        bound = _LOAD_BOUND.get(m)
        st.set(rd, Taint(val.labels, bound))
        if m == "ld.dw":
            hi_val = st.mem_get(base, off + 4) if base is not None else CLEAN
            extra = bt.labels if bt.tainted else EMPTY
            st.set(reg_by_num(reg_num(rd) + 1), Taint(hi_val.labels | extra, None))

    def _store(self, insn: Insn) -> None:
        st = self.state
        rs = insn.reg(0)
        mem = insn.mem(1)
        if mem is None:
            return
        self._addr_check(insn, mem.base, "store")
        base, off = st.resolve(mem.base, mem.offset)
        if base is None:
            return
        val = st.get(rs)
        st.mem_set(base, off, val)
        if insn.mnemonic == "st.dw" and rs is not None:
            st.mem_set(base, off + 4, st.get(reg_by_num(reg_num(rs) + 1)))
        # lp-slot tracking
        if rs == LINK_REG and base == "sp":
            st.lp_slots.add((base, off))
        elif (base, off) in st.lp_slots:
            st.lp_slots.discard((base, off))
            if val.tainted:
                self._find(insn, "tainted-overwrite-of-saved-lp", f"{rs} -> {off}[{base}]", val.labels)

    def _bitmem(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        mem = insn.mem(1)
        if mem is None:
            return
        self._addr_check(insn, mem.base, "load" if m == "tst1" else "store")
        base, off = st.resolve(mem.base, mem.offset)
        if base is None:
            return
        slot = st.mem_get(base, off)
        bitreg = insn.reg(0)
        if m == "tst1":
            self._flags_from([bitreg] if bitreg else [], slot)
        elif bitreg is not None and st.get(bitreg).tainted:
            st.mem_set(base, off, Taint(slot.labels | st.get(bitreg).labels, None))

    # ---- system registers --------------------------------------------------

    def _sysreg(self, insn: Insn) -> None:
        st = self.state
        if insn.mnemonic == "ldsr":
            rs = insn.reg(0)
            t = st.get(rs)
            if t.tainted:
                self._find(insn, "tainted-sysreg-write", f"ldsr {rs}", t.labels)
        else:
            rd = insn.reg(1)
            st.set(rd, CLEAN)

    # ---- control transfer --------------------------------------------------

    def _branch(self, insn: Insn) -> None:
        pass

    def _jmp(self, insn: Insn) -> None:
        base = jmp_base(insn)
        t = self.state.get(base)
        if t.tainted:
            kind = "tainted-return-address" if base == LINK_REG else "tainted-indirect-jump"
            self._find(insn, kind, f"jmp [{base}]", t.labels)

    def _call(self, insn: Insn) -> None:
        st = self.state
        if insn.mnemonic == "callt":
            self._call_effects(insn, link=None)
            return
        link, target, ibase = jarl_link_and_target(insn)
        if ibase is not None:
            t = st.get(ibase)
            if t.tainted:
                self._find(insn, "tainted-indirect-call", f"jarl [{ibase}]", t.labels)
        sym = insn.ops[0].text if insn.ops and isinstance(insn.ops[0], Sym) else None
        self._call_effects(insn, link=link)

    def _call_effects(self, insn: Insn, link: Optional[str]) -> None:
        st = self.state
        arg_labels: Labels = EMPTY
        for r in ARG_REGS:
            arg_labels |= st.get(r).labels
        for r in CALLER_SAVED:
            st.set(r, CLEAN)
        if arg_labels:
            for r in RET_REGS:
                st.set(r, Taint(arg_labels, None))
        if link is not None:
            st.set(link, CLEAN)
            st.consts[link] = (insn.address + insn.size) & MASK32
        st.mem = {k: v for k, v in st.mem.items() if not (k[0] == "sp" and k[1] < 0)}
        st.flags = CLEAN

    def _trap(self, insn: Insn) -> None:
        for r in ARG_REGS:
            t = self.state.get(r)
            if t.tainted:
                self._find(insn, "tainted-trap-arg", f"{insn.mnemonic} {r}", t.labels)

    # ---- prepare / dispose / pushsp / popsp --------------------------------

    def _stack(self, insn: Insn) -> None:
        st, m = self.state, insn.mnemonic
        if m == "prepare":
            lst = insn.reglist(0)
            words = insn.imm(1) or 0
            if lst is None:
                return
            n = len(lst.regs)
            st.rebase("sp", -4 * n)
            for i, r in enumerate(lst.regs):
                st.mem_set("sp", 4 * i, st.get(r))
                if r == LINK_REG:
                    st.lp_slots.add(("sp", 4 * i))
            st.rebase("sp", -4 * words)
            c = st.consts.get("sp")
            if c is not None:
                st.consts["sp"] = (c - 4 * (n + words)) & MASK32
        elif m == "dispose":
            words = insn.imm(0) or 0
            lst = insn.reglist(1)
            if lst is None:
                return
            st.rebase("sp", 4 * words)
            for i, r in enumerate(lst.regs):
                slot = st.mem_get("sp", 4 * i)
                st.set(r, Taint(slot.labels, None) if slot.tainted else CLEAN)
                st.consts.pop(r, None)
                st.frame_ptrs.pop(r, None)
            st.rebase("sp", 4 * len(lst.regs))
            c = st.consts.get("sp")
            if c is not None:
                st.consts["sp"] = (c + 4 * (words + len(lst.regs))) & MASK32
            if len(insn.ops) > 2 and isinstance(insn.ops[2], Mem):
                self._jmp(Insn(insn.address, "jmp", [insn.ops[2]], insn.size))
        elif m in ("pushsp", "popsp"):
            lst = insn.reglist(0)
            if lst is None:
                return
            if m == "pushsp":
                n = len(lst.regs)
                st.rebase("sp", -4 * n)
                for i, r in enumerate(lst.regs):
                    st.mem_set("sp", 4 * i, st.get(r))
                    if r == LINK_REG:
                        st.lp_slots.add(("sp", 4 * i))
            else:
                for i, r in enumerate(lst.regs):
                    slot = st.mem_get("sp", 4 * i)
                    st.set(r, Taint(slot.labels, None))
                st.rebase("sp", 4 * len(lst.regs))

    # ---- unknown -----------------------------------------------------------

    def _unknown(self, insn: Insn) -> None:
        self.unknown.add(insn.mnemonic)
        if not insn.ops or not isinstance(insn.ops[-1], Reg):
            return
        rd = insn.ops[-1].name
        labels: Labels = EMPTY
        for r in insn.regs():
            labels |= self.state.get(r).labels
        self.state.set(rd, Taint(labels, None))


# ---------------------------------------------------------------------------
# Binary-path helpers
# ---------------------------------------------------------------------------

def _name_at(symbols: Dict[int, str], va: int, tol: int = _PLT_TOL) -> Optional[str]:
    if va in symbols:
        return symbols[va]
    for off in range(0, tol + 1, 2):
        if va + off in symbols:
            return symbols[va + off]
        if va - off in symbols:
            return symbols[va - off]
    return None


def _load_elf(path: str):
    """Return (data, base_va, text_start, text_end, symbols, endian)."""
    try:
        import lief
        elf = lief.parse(path)
        if elf is None:
            raise ValueError(f"lief: cannot parse {path}")
        endian = "little" if elf.header.identity_data == lief.ELF.ELF_DATA.LSB else "big"
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
        return data, base_va, text_start, text_end, syms, endian
    except ImportError:
        pass

    from elftools.elf.elffile import ELFFile
    data = Path(path).read_bytes()
    ef = ELFFile(open(path, "rb"))
    endian = "little" if ef.little_endian else "big"
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
    return data, base_va, text_start, text_end, syms, endian


# ---------------------------------------------------------------------------
# V850TaintTracker: binary-path API
# ---------------------------------------------------------------------------

class V850TaintTracker:
    """
    Intraprocedural + interprocedural taint tracker for V850 ELF binaries.

    Binary path uses V850Decoder + TaintEngine for labeled-taint analysis.
    Source/sink API matches the original: recv/read -> r10; system/strcpy -> r6-r9.

    Also provides:
      run_from_listing(text)  -- high-fidelity path via GNU as listing
      run_from_objdump(text)  -- high-fidelity path via v850-elf-objdump -d
    Both return List[Finding] (generic labeled-taint findings).
    """

    def __init__(self, data: bytes, base_va: int, text_start: int, text_end: int,
                 symbols: Dict[int, str], endian: str = "little",
                 variant: Variant = Variant.RH850):
        self._data       = data
        self._base_va    = base_va
        self._text_start = text_start
        self._text_end   = text_end
        self._syms       = symbols
        self._dec        = V850Decoder(endian=endian)
        self._variant    = variant
        self._frames_by_va: Optional[Dict[int, V850Frame]] = None

    @classmethod
    def from_path(cls, path: str, variant: Variant = Variant.RH850) -> "V850TaintTracker":
        data, base_va, text_start, text_end, syms, endian = _load_elf(path)
        return cls(data, base_va, text_start, text_end, syms, endian, variant)

    # ---- listing / objdump entry points ------------------------------------

    def run_from_listing(self, text: str, label: str = "input") -> List[Finding]:
        """Run the labeled-taint engine over a GNU as-style listing."""
        eng = TaintEngine(self._variant)
        for r in ARG_REGS:
            eng.taint_register(r, label)
        return eng.run(_from_listing(text))

    def run_from_objdump(self, text: str, label: str = "input") -> List[Finding]:
        """Run the labeled-taint engine over v850-elf-objdump -d output."""
        eng = TaintEngine(self._variant)
        for r in ARG_REGS:
            eng.taint_register(r, label)
        return eng.run(_from_objdump(text))

    # ---- frame cache -------------------------------------------------------

    def _ensure_frames(self) -> Dict[int, V850Frame]:
        if self._frames_by_va is not None:
            return self._frames_by_va
        offset = self._text_start - self._base_va
        length = self._text_end - self._text_start
        snippet = self._data[offset:offset + length]
        frames = self._dec.decode_frames(snippet, self._text_start)
        self._frames_by_va = {f.va: f for f in frames}
        return self._frames_by_va

    # ---- function-start heuristic -----------------------------------------

    def _get_func_starts(self) -> List[int]:
        fv = self._ensure_frames()
        starts: Set[int] = set()
        for va, f in fv.items():
            if f.mnemonic == "prepare":
                starts.add(va)
        for va in self._syms:
            if self._text_start <= va < self._text_end:
                starts.add(va)
        if not starts:
            starts.add(self._text_start)
        return sorted(starts)

    # ---- intraprocedural scan (binary path) --------------------------------

    def _scan_func_binary(self, func_va: int, func_end: int,
                          init_labels: Optional[Set[str]] = None
                          ) -> List[TaintFindingV850]:
        fv = self._ensure_frames()
        func_name = self._syms.get(func_va, f"fn_0x{func_va:x}")
        findings: List[TaintFindingV850] = []

        eng = TaintEngine(self._variant)
        if init_labels:
            for r in ARG_REGS:
                for lbl in init_labels:
                    eng.taint_register(r, lbl)

        va = func_va
        while va < func_end:
            frame = fv.get(va)
            if frame is None:
                va += 2
                continue

            if frame.is_call and frame.target:
                callee_name = _name_at(self._syms, frame.target)
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
                        findings.append(TaintFindingV850(
                            func_va=func_va, func_name=func_name,
                            sink_va=va, sink_name=callee_name,
                            tainted_args=tainted_args,
                            source_name=next(iter(sorted(labels)), "unknown"),
                            severity=sev,
                        ))
                    for r in CALLER_SAVED:
                        st.set(r, CLEAN)

                else:
                    arg_labels: Labels = EMPTY
                    for r in ARG_REGS:
                        arg_labels |= st.get(r).labels
                    for r in CALLER_SAVED:
                        st.set(r, CLEAN)
                    if arg_labels:
                        for r in RET_REGS:
                            st.set(r, Taint(arg_labels, None))

            elif frame.is_ret:
                break

            else:
                insn = make_insn(frame.va, frame.mnemonic, frame.op_str, frame.width)
                eng.step(insn)

            va += frame.width

        return findings

    # ---- public API -------------------------------------------------------

    def run(self) -> List[TaintFindingV850]:
        """Intraprocedural scan: each function scanned independently."""
        starts = self._get_func_starts()
        findings: List[TaintFindingV850] = []
        for i, fva in enumerate(starts):
            fend = starts[i + 1] if i + 1 < len(starts) else self._text_end
            findings.extend(self._scan_func_binary(fva, fend))
        return findings

    def run_interprocedural(self, depth: int = 4) -> List[TaintFindingV850]:
        """
        Interprocedural BFS: follow tainted r6-r9 from callers into callees.
        """
        starts    = self._get_func_starts()
        fv        = self._ensure_frames()
        func_end: Dict[int, int] = {}
        for i, fva in enumerate(starts):
            func_end[fva] = starts[i + 1] if i + 1 < len(starts) else self._text_end

        findings:  List[TaintFindingV850] = []
        queue:     List[Tuple[int, int, Set[str]]] = [(fva, depth, set()) for fva in starts]
        visited:   Dict[Tuple, int] = {}

        while queue:
            fva, d, init_labels = queue.pop(0)
            key = (fva,) + tuple(sorted(init_labels))
            if visited.get(key, -1) >= d:
                continue
            visited[key] = d
            fend = func_end.get(fva, self._text_end)
            func_name = self._syms.get(fva, f"fn_0x{fva:x}")

            eng = TaintEngine(self._variant)
            for r in ARG_REGS:
                for lbl in init_labels:
                    eng.taint_register(r, lbl)

            va = fva
            while va < fend:
                frame = fv.get(va)
                if frame is None:
                    va += 2
                    continue

                if frame.is_call and frame.target:
                    callee_va   = frame.target
                    callee_name = _name_at(self._syms, callee_va)
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
                            findings.append(TaintFindingV850(
                                func_va=fva, func_name=func_name,
                                sink_va=va, sink_name=callee_name,
                                tainted_args=tainted_args,
                                source_name=next(iter(sorted(labels)), "unknown"),
                                severity=sev,
                            ))
                        for r in CALLER_SAVED:
                            st.set(r, CLEAN)

                    else:
                        tainted_into = [r for r in ARG_REGS if st.get(r).tainted]
                        if d > 0 and tainted_into:
                            callee_labels = set().union(*(st.get(r).labels for r in tainted_into))
                            c_va = callee_va
                            for off in range(0, _PLT_TOL + 1, 2):
                                if c_va + off in func_end:
                                    c_va += off; break
                                if c_va - off in func_end and c_va - off >= 0:
                                    c_va -= off; break
                            if c_va in func_end:
                                queue.append((c_va, d - 1, callee_labels))
                        arg_labels: Labels = EMPTY
                        for r in ARG_REGS:
                            arg_labels |= st.get(r).labels
                        for r in CALLER_SAVED:
                            st.set(r, CLEAN)
                        if arg_labels:
                            for r in RET_REGS:
                                st.set(r, Taint(arg_labels, None))

                elif frame.is_ret:
                    break
                else:
                    insn = make_insn(frame.va, frame.mnemonic, frame.op_str, frame.width)
                    eng.step(insn)

                va += frame.width

        seen: Set[Tuple] = set()
        unique: List[TaintFindingV850] = []
        for f in findings:
            k = (f.func_va, f.sink_va, f.sink_name)
            if k not in seen:
                seen.add(k)
                unique.append(f)
        return unique

    def report(self, findings: List[TaintFindingV850]) -> str:
        if not findings:
            return "V850 taint: no findings."
        lines = [f"V850 taint: {len(findings)} finding(s)\n"]
        for f in sorted(findings, key=lambda x: (x.func_va, x.sink_va)):
            lines.append(str(f))
        return "\n".join(lines)
