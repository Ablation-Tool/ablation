"""
taint_tracker_loongarch64.py: LoongArch64 data-flow taint tracker.

Labeled-taint model: Taint(labels: frozenset, bound: Optional[int]).
andi zeros the upper bits of the result and can bound the taint range.
addi.d on $sp is tracked as a frame-offset rebase.

ABI (lp64):
  $a0–$a7:  argument registers (8 regs)
  $a0–$a1:  return values
  $t0–$t8:  caller-saved temporaries
  $ra:      return address (caller-saved; written by bl/jirl)
  $fp/$s0–$s8: callee-saved

Sources: recv/recvfrom/recvmsg/read/fgets/gets/fread (return value in $a0)
Sinks:   system/execve/execl/execvp/execle/execvpe/popen/
         strcpy/strcat/sprintf/vsprintf/snprintf/vsnprintf/memcpy/memmove/gets

Targets: TencentOS 4.6 LoongArch64 binaries — glibc, OpenSSL, QEMU,
         kernel modules, EDK2, GRUB2 EFI, cryptography libraries.
         Corpus: /media/cowboy/research/TencentOS/
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Iterator, List, Optional, Set, Tuple

from .insn_loongarch64 import Imm, Insn, Reg, from_loongarch_frame
from .isa_loongarch64 import (
    ALU3_MNEMS, ALUI_MNEMS, ARG_REGS, ATOMIC_MNEMS, BARRIER_MNEMS,
    CALLER_SAVED, FP_REG, IMM_MNEMS, LOAD_MNEMS, MASK64, NEVER_TOUCHED,
    RA_REG, RET_REGS, SP_REG, STORE_MNEMS, UNARY_MNEMS, ZERO_REG,
    andi_bound, canon_reg,
)
from .loongarch_decoder import LoongArchDecoder, LoongArchFrame

Labels = FrozenSet[str]
EMPTY: Labels = frozenset()

_SOURCE_NAMES: frozenset = frozenset({
    # libc network/file sources
    "recv", "recvfrom", "recvmsg", "read", "fread",
    "fgets", "gets", "getchar", "fgetc",
    # kernel-space sources (copy_from_user family)
    "copy_from_user", "__copy_from_user", "__copy_from_user_inatomic",
    "get_user", "__get_user", "strncpy_from_user", "strnlen_user",
    "nla_get_string", "nla_data", "nlmsg_data",
    "memdup_user", "__memdup_user",
    "skb_get_data", "skb_pull_data",
})

_SINK_NAMES: frozenset = frozenset({
    # libc exec/string sinks
    "system", "execve", "execl", "execvp", "execle", "execvpe", "popen",
    "strcpy", "strcat", "sprintf", "vsprintf", "snprintf", "vsnprintf",
    "memcpy", "memmove", "gets",
    # kernel-space sinks
    "copy_to_user", "__copy_to_user", "put_user", "__put_user",
    "call_usermodehelper", "call_usermodehelper_exec", "kernel_execve",
    "kmalloc", "kzalloc", "vmalloc",
})

# Kernel privilege-escalation primitives — always CRITICAL.
_ESCALATION_NAMES: frozenset = frozenset({
    "commit_creds", "prepare_kernel_cred",
    "set_current_cred", "override_creds",
    "__sys_setuid", "security_setuid",
})

_PLT_TOL = 16


# ---------------------------------------------------------------------------
# Taint value
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Taint:
    labels: Labels = EMPTY
    bound:  Optional[int] = None

    @property
    def tainted(self) -> bool:
        return bool(self.labels)

    def __str__(self) -> str:
        if not self.labels:
            return "clean"
        s = "{" + ",".join(sorted(self.labels)) + "}"
        return s + (f"<={self.bound:#x}" if self.bound is not None else "")

    def join(self, other: "Taint") -> "Taint":
        if not self.labels and not other.labels:
            return CLEAN
        labels = self.labels | other.labels
        if self.bound is not None and other.bound is not None:
            bound: Optional[int] = max(self.bound, other.bound)
        else:
            bound = None
        return Taint(labels, bound)


CLEAN = Taint()


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    address: int
    kind:    str
    detail:  str
    labels:  Labels

    def __str__(self) -> str:
        return (f"{self.address:#x} [{self.kind}] {self.detail} "
                f"<- {{{','.join(sorted(self.labels))}}}")


@dataclass
class TaintFindingLA64:
    """Finding from the source-to-sink interprocedural scan."""
    func_va:      int
    func_name:    str
    sink_va:      int
    sink_name:    str
    tainted_args: List[str]
    source_name:  str
    severity:     str = "HIGH"

    def __str__(self) -> str:
        args = ", ".join(self.tainted_args)
        return (f"[{self.severity}] {self.func_va:#x} ({self.func_name}): "
                f"tainted {{{args}}} -> {self.sink_name} @ {self.sink_va:#x} "
                f"(source: {self.source_name})")


# ---------------------------------------------------------------------------
# Taint state
# ---------------------------------------------------------------------------

@dataclass
class State:
    regs:       Dict[str, Taint] = field(default_factory=dict)
    mem:        Dict[Tuple[str, int], Taint] = field(default_factory=dict)
    consts:     Dict[str, int] = field(default_factory=dict)
    frame_ptrs: Dict[str, Tuple[str, int]] = field(default_factory=dict)

    def get(self, r: Optional[str]) -> Taint:
        if r is None or r == ZERO_REG:
            return CLEAN
        return self.regs.get(r, CLEAN)

    def set(self, r: Optional[str], t: Taint) -> None:
        if r is None or r in NEVER_TOUCHED or r == ZERO_REG:
            return
        if t.tainted or t.bound is not None:
            self.regs[r] = t
        else:
            self.regs.pop(r, None)
        self.consts.pop(r, None)
        self.frame_ptrs.pop(r, None)

    def taint_reg(self, r: str, label: str) -> None:
        cur = self.get(r)
        self.regs[r] = Taint(cur.labels | {label}, cur.bound)

    def set_const(self, r: str, v: int) -> None:
        if r == ZERO_REG or r in NEVER_TOUCHED:
            return
        self.regs.pop(r, None)
        self.consts[r] = v & MASK64
        self.frame_ptrs.pop(r, None)

    def resolve(self, base: Optional[str], off: int) -> Tuple[Optional[str], int]:
        """Canonical (base, offset) key for a memory reference."""
        if base is None:
            return None, 0
        if base == ZERO_REG:
            return "abs", off & MASK64
        if base in (SP_REG, FP_REG):
            return base, off
        if base in self.frame_ptrs:
            b, k = self.frame_ptrs[base]
            return b, k + off
        if base in self.consts:
            return "abs", (self.consts[base] + off) & MASK64
        return None, 0

    def mem_get(self, base: str, off: int) -> Taint:
        return self.mem.get((base, off), CLEAN)

    def mem_set(self, base: str, off: int, t: Taint) -> None:
        if t.tainted:
            self.mem[(base, off)] = t
        else:
            self.mem.pop((base, off), None)

    def rebase(self, reg: str, delta: int) -> None:
        """Adjust all memory keys and frame pointers when reg (usually $sp) changes."""
        self.mem = {((b, o - delta) if b == reg else (b, o)): t
                    for (b, o), t in self.mem.items()}
        self.frame_ptrs = {
            r: ((b, k - delta) if b == reg else (b, k))
            for r, (b, k) in self.frame_ptrs.items()
        }

    def invalidate_base(self, reg: str) -> None:
        self.mem = {k: v for k, v in self.mem.items() if k[0] != reg}
        self.frame_ptrs = {r: v for r, v in self.frame_ptrs.items() if v[0] != reg}

    # lattice ops -------------------------------------------------------

    def copy(self) -> "State":
        return State(dict(self.regs), dict(self.mem),
                     dict(self.consts), dict(self.frame_ptrs))

    def same_as(self, other: "State") -> bool:
        return self.regs == other.regs and self.mem == other.mem

    def join(self, other: "State", widen: bool = False) -> "State":
        out = State()
        for r in set(self.regs) | set(other.regs):
            a, b = self.get(r), other.get(r)
            if a.tainted or b.tainted:
                out.regs[r] = a.join(b)
        for k in set(self.mem) | set(other.mem):
            a, b = self.mem.get(k, CLEAN), other.mem.get(k, CLEAN)
            if a.tainted or b.tainted:
                jt = a.join(b)
                if jt.tainted:
                    out.mem[k] = jt
        if not widen:
            for r in set(self.consts) & set(other.consts):
                if self.consts[r] == other.consts[r]:
                    out.consts[r] = self.consts[r]
        return out


# ---------------------------------------------------------------------------
# Taint propagation engine (single-function step-by-step)
# ---------------------------------------------------------------------------

class TaintEngine:
    """Step through a list of Insn objects, propagating labeled taint.

    Usage:
        eng = TaintEngine()
        eng.taint_register("$a0", "recv")
        eng.run(insns)
        for f in eng.findings:
            print(f)
    """

    def __init__(self) -> None:
        self.state    = State()
        self.findings: List[Finding] = []
        self.unknown:  Set[str] = set()

    def taint_register(self, reg: str, label: str) -> None:
        self.state.taint_reg(reg, label)

    def run(self, insns: List[Insn]) -> List[Finding]:
        for insn in insns:
            self.step(insn)
        return self.findings

    def step(self, insn: Insn) -> None:
        m   = insn.mnemonic
        ops = insn.ops
        st  = self.state

        # --- No-op / barrier ---
        if m in BARRIER_MNEMS or m == ".word":
            return

        # --- Load large immediate: rd = imm (always clean) ---
        if m in IMM_MNEMS:
            rd = insn.reg(0)
            st.set(rd, CLEAN)
            return

        # --- Unary: rd = f(rj) ---
        if m in UNARY_MNEMS:
            rd = insn.reg(0)
            rj = insn.reg(1)
            st.set(rd, st.get(rj))
            return

        # --- 3-register ALU: rd = rj op rk ---
        if m in ALU3_MNEMS:
            rd = insn.reg(0)
            rj = insn.reg(1)
            rk = insn.reg(2)
            tj = st.get(rj)
            tk = st.get(rk)
            # 'or rd, rj, $zero' is 'move'; 'and rd, rj, $zero' clears rd
            if rk == ZERO_REG and m in ("or",):
                st.set(rd, tj)
            elif rj == ZERO_REG and m in ("or",):
                st.set(rd, tk)
            elif rj == ZERO_REG and rk == ZERO_REG:
                st.set(rd, CLEAN)
            else:
                st.set(rd, tj.join(tk))
            return

        # --- Register-immediate ALU: rd = rj op imm ---
        if m in ALUI_MNEMS:
            rd  = insn.reg(0)
            rj  = insn.reg(1)
            imm = insn.imm(2) if len(ops) > 2 else insn.imm(1)
            tj  = st.get(rj)

            if m == "addi.d" and rj == SP_REG and rd == SP_REG and imm is not None:
                # Stack allocation/deallocation: rebase all $sp-relative memory.
                # rebase(delta) applies o - delta.  New $sp = old_sp + imm, so
                # key offsets relative to new $sp = old_offset - imm.  Pass imm.
                st.rebase(SP_REG, imm)
                st.consts.pop(SP_REG, None)
                return

            if m == "addi.d" and rj == SP_REG and rd == FP_REG and imm is not None:
                # Frame pointer setup: $fp = $sp + N
                st.frame_ptrs[FP_REG] = (SP_REG, imm)
                return

            if m in ("andi", "ori", "xori") and imm is not None:
                if m == "andi":
                    bnd = andi_bound(imm)
                    st.set(rd, Taint(tj.labels, bnd if bnd is not None else tj.bound))
                else:
                    st.set(rd, tj)
                return

            if not tj.tainted and imm is not None:
                # constant folding
                if m in ("addi.w", "addi.d") and rj in st.consts:
                    st.set_const(rd, st.consts[rj] + imm)
                    return
                if m == "lu12i.w":
                    st.set_const(rd, (imm << 12) & 0xffffffff)
                    return
                if m == "lu32i.d":
                    existing = st.consts.get(rd, 0)
                    st.set_const(rd, (existing & 0xffffffff) | ((imm << 32) & 0xffffffff00000000))
                    return
                if m == "lu52i.d":
                    existing = st.consts.get(rd, 0)
                    st.set_const(rd, (existing & 0x000fffffffffffff) | ((imm & 0xfff) << 52))
                    return

            st.set(rd, tj)
            return

        # --- Load: rd = mem[rj + imm] ---
        if m in LOAD_MNEMS:
            rd   = insn.reg(0)
            rj   = insn.reg(1)
            imm  = insn.imm(2) if len(ops) > 2 else 0
            base, off = st.resolve(rj, imm or 0)
            if base is not None:
                st.set(rd, st.mem_get(base, off))
            else:
                # Unknown base: conservatively clear rd
                st.set(rd, CLEAN)
            return

        # --- Store: mem[rj + imm] = rd ---
        if m in STORE_MNEMS:
            rd   = insn.reg(0)    # value register
            rj   = insn.reg(1)    # base register
            imm  = insn.imm(2) if len(ops) > 2 else 0
            base, off = st.resolve(rj, imm or 0)
            if base is not None:
                st.mem_set(base, off, st.get(rd))
            return

        # --- Atomic: rd = old_mem[rj]; mem[rj] = rk ---
        if m in ATOMIC_MNEMS:
            rd = insn.reg(0)
            rj = insn.reg(1)
            rk = insn.reg(2)
            base, off = st.resolve(rj, 0)
            if base is not None:
                st.set(rd, st.mem_get(base, off))
                st.mem_set(base, off, st.get(rk).join(st.mem_get(base, off)))
            else:
                st.set(rd, CLEAN)
            return

        # --- CSR read: rd = csr ---
        if m in ("csrrd",):
            rd = insn.reg(0)
            st.set(rd, CLEAN)
            return

        # --- IOCSR read: rd = iocsr[rj] ---
        if m in ("iocsrrd.b", "iocsrrd.h", "iocsrrd.w", "iocsrrd.d"):
            rd = insn.reg(0)
            st.set(rd, CLEAN)
            return

        # --- movgr2fr / movfr2gr (float <-> GP reg moves) ---
        if m in ("movgr2fr.w", "movgr2fr.d", "movgr2frh.w"):
            # taint propagation path: GPR -> FPR (not tracked at GP level)
            return
        if m in ("movfr2gr.s", "movfr2gr.d", "movfrh2gr.s"):
            rd = insn.reg(0)
            st.set(rd, CLEAN)
            return

        # --- movcf2gr: GP reg = condition flag (always clean) ---
        if m in ("movcf2gr",):
            rd = insn.reg(0)
            st.set(rd, CLEAN)
            return

        # --- movgr2cf: condition flag write (no GP taint impact) ---
        if m in ("movgr2cf",):
            return

        # --- rdtimel.w / rdtimeh.w / rdtime.d: timer read -> clean ---
        if m in ("rdtimel.w", "rdtimeh.w", "rdtime.d"):
            rd = insn.reg(0)
            st.set(rd, CLEAN)
            if len(ops) > 1:
                rj = insn.reg(1)
                st.set(rj, CLEAN)
            return

        # --- Float ops: not tracked at GP level ---
        if m.startswith("f") or m.startswith("fcmp"):
            return

        self.unknown.add(m)


# ---------------------------------------------------------------------------
# Syscall frame handler
# ---------------------------------------------------------------------------

def _handle_syscall_frame(
    eng: "TaintEngine",
    findings: list,
    func_va: int,
    func_name: str,
    syscall_va: int,
) -> None:
    """
    Handle a 'syscall 0' frame in the taint scan.

    Reads $a7 from the constant-folding table to identify the syscall number.
    Source syscalls taint $a0 with the syscall label.
    Sink/escalation syscalls emit a finding if any of $a0–$a5 are tainted.
    Unknown $a7: conservatively clobber caller-saved and continue.
    """
    from .syscall_loongarch64 import (
        SYSCALL_ESCALATION, classify_syscall, syscall_label, syscall_severity,
    )
    st = eng.state
    sysno = st.consts.get("$a7")

    if sysno is not None:
        result = classify_syscall(sysno)
        if result is not None:
            name, kind = result
            if kind == "source":
                for r in CALLER_SAVED:
                    st.set(r, CLEAN)
                st.taint_reg("$a0", syscall_label(sysno))
                return
            # sink or escalation
            arg_regs = ("$a0", "$a1", "$a2", "$a3", "$a4", "$a5")
            tainted_args = [r for r in arg_regs if st.get(r).tainted]
            if tainted_args:
                labels = frozenset().union(*(st.get(r).labels for r in tainted_args))
                sev = syscall_severity(sysno)
                findings.append(TaintFindingLA64(
                    func_va=func_va, func_name=func_name,
                    sink_va=syscall_va, sink_name=f"syscall:{name}",
                    tainted_args=list(tainted_args),
                    source_name=next(iter(sorted(labels)), "unknown"),
                    severity=sev,
                ))

    # Conservatively clobber caller-saved registers after any syscall
    for r in CALLER_SAVED:
        st.set(r, CLEAN)


# ---------------------------------------------------------------------------
# ELF loader helper (shared with V850 approach)
# ---------------------------------------------------------------------------

def _load_elf(path: str):
    """Return (data, base_va, text_start, text_end, syms, endian).

    syms maps VA -> name for both static symbols and PLT stub addresses.
    PLT entries are merged so that bl <plt_stub_va> resolves directly to the
    imported function name without the ±_PLT_TOL scan.
    """
    try:
        from ablation.core.elf_parser import ELFParser
        elf    = ELFParser(path).parse()
        data   = Path(path).read_bytes()
        endian = "little" if elf.endian == "<" else "big"
        text_sh = elf.get_section(".text")
        if text_sh:
            text_start = text_sh["sh_addr"]
            text_end   = text_start + text_sh["sh_size"]
            base_va    = text_sh["sh_addr"] - text_sh["sh_offset"]
        else:
            base_va = text_start = 0
            text_end = len(data)
        syms: Dict[int, str] = {}
        for sym in elf.dynsyms + elf.symtabs:
            if sym.get("name") and sym.get("st_value"):
                syms[sym["st_value"]] = sym["name"]
        # PLT stub addresses -> imported symbol names (exact, no ±tol scan needed)
        for entry in elf.get_plt_got_table():
            plt_addr_str = entry.get("plt_addr")
            func_name    = entry.get("function")
            if plt_addr_str and func_name:
                try:
                    syms[int(plt_addr_str, 16)] = func_name
                except (ValueError, TypeError):
                    pass
        return data, base_va, text_start, text_end, syms, endian
    except ImportError:
        pass
    except Exception:
        pass

    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection
    except ImportError:
        raise ImportError("pip install pyelftools")

    data = Path(path).read_bytes()
    ef   = ELFFile(open(path, "rb"))
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
    # PLT merging via pyelftools: .rela.plt / .rel.plt
    plt_sh = ef.get_section_by_name(".plt")
    plt_base  = plt_sh["sh_addr"]    if plt_sh else 0
    plt_entsz = plt_sh["sh_entsize"] if plt_sh else 0
    if plt_base and plt_entsz == 0:
        plt_entsz = 16  # LoongArch/AArch64/x86-64 default
    rela_sh = (ef.get_section_by_name(".rela.plt") or
               ef.get_section_by_name(".rel.plt"))
    if rela_sh and plt_base and plt_entsz:
        dynsym_sh = ef.get_section_by_name(".dynsym")
        for plt_idx, rel in enumerate(rela_sh.iter_relocations(), start=2):
            sym_idx = rel["r_info_sym"]
            if dynsym_sh and sym_idx:
                sym = dynsym_sh.get_symbol(sym_idx)
                if sym and sym.name:
                    syms[plt_base + plt_idx * plt_entsz] = sym.name
    return data, base_va, text_start, text_end, syms, endian


def _name_at(syms: Dict[int, str], va: int) -> str:
    name = syms.get(va)
    if name:
        return name
    for off in range(1, _PLT_TOL + 1):
        n = syms.get(va + off) or syms.get(va - off)
        if n:
            return n
    return f"fn_0x{va:x}"


# ---------------------------------------------------------------------------
# LoongArch64TaintTracker: binary-path API
# ---------------------------------------------------------------------------

class LoongArch64TaintTracker:
    """
    Intraprocedural + interprocedural taint tracker for LoongArch64 ELF binaries.

    Decodes with LoongArchDecoder (pure Python, no capstone).
    Source/sink model: recv/read -> $a0; system/strcpy -> $a0-$a7.

    Usage:
        tt = LoongArch64TaintTracker.from_path("libc.so.6.loongarch64")
        findings = tt.run_interprocedural()
        print(tt.report(findings))
    """

    def __init__(self, data: bytes, base_va: int, text_start: int, text_end: int,
                 symbols: Dict[int, str]):
        self._data       = data
        self._base_va    = base_va
        self._text_start = text_start
        self._text_end   = text_end
        self._syms       = symbols
        self._dec        = LoongArchDecoder()
        self._frames_by_va: Optional[Dict[int, LoongArchFrame]] = None
        # Populated by from_path_full(): DWARF high_pc values give precise end VAs.
        # When absent, run_interprocedural() falls back to next-function-start.
        self._dwarf_ends: Dict[int, int] = {}

    @classmethod
    def from_path(cls, path: str) -> "LoongArch64TaintTracker":
        data, base_va, text_start, text_end, syms, _ = _load_elf(path)
        return cls(data, base_va, text_start, text_end, syms)

    @classmethod
    def from_path_full(cls, path: str) -> "LoongArch64TaintTracker":
        """
        Like from_path but augments function boundaries from three sources:

          1. .eh_frame FDE initial_location (present in stripped binaries)
          2. .debug_info DW_TAG_subprogram low_pc / high_pc (requires -g)
          3. .BTF.ext func_info (kernel modules)

        Use instead of from_path when analysing stripped binaries where the
        addi.d prologue heuristic misses leaf or tail-call-optimised functions.
        DWARF high_pc values are stored in self._dwarf_ends and used by
        run_interprocedural() for precise function end VAs.
        """
        data, base_va, text_start, text_end, syms, _ = _load_elf(path)

        try:
            from .dwarf_loongarch64 import (
                extract_eh_frame_starts,
                extract_debug_funcs,
                extract_btf_funcs,
            )
            dwarf_funcs = extract_debug_funcs(path)
            # Merge DWARF-derived names and BTF names into syms
            for va, (name, _end) in dwarf_funcs.items():
                if text_start <= va < text_end:
                    if name and va not in syms:
                        syms[va] = name
                    elif not name and va not in syms:
                        syms[va] = f"fn_{va:x}"
            for va, name in extract_btf_funcs(path).items():
                if text_start <= va < text_end and va not in syms:
                    syms[va] = name
            # eh_frame starts: add anonymous entries so _get_func_starts() picks them up
            for va in extract_eh_frame_starts(path):
                if text_start <= va < text_end and va not in syms:
                    syms[va] = f"fn_{va:x}"
        except Exception:
            dwarf_funcs = {}

        tt = cls(data, base_va, text_start, text_end, syms)
        # Store precise DWARF end VAs for use by run_interprocedural()
        tt._dwarf_ends = {
            va: end
            for va, (_name, end) in dwarf_funcs.items()
            if text_start <= va < text_end and end > va
        }
        return tt

    @classmethod
    def from_system_map(cls, elf_path: str, sysmap_path: str) -> "LoongArch64TaintTracker":
        """
        Like from_path but loads symbol names from a kernel System.map file.
        Use for vmlinux analysis where the binary is stripped but System.map
        provides the canonical VA->name mapping (62k+ functions on TencentOS 6.6.119).

        System.map format per line: <hex_va> <type> <name>
        Only T/t/W/w (text function / weak) entries are injected; data symbols
        (D/d/R/r/B/b/A/a) are excluded since the tracker only resolves call targets.
        System.map entries take precedence over stripped ELF symtab entries.

        Usage:
            tt = LoongArch64TaintTracker.from_system_map(
                '/path/to/vmlinux', '/boot/System.map-6.6.119')
            findings = tt.run_interprocedural()
        """
        data, base_va, text_start, text_end, syms, _ = _load_elf(elf_path)

        sysmap_syms: Dict[int, str] = {}
        try:
            with open(sysmap_path) as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    if parts[1] not in ("T", "t", "W", "w"):
                        continue
                    try:
                        sysmap_syms[int(parts[0], 16)] = parts[2]
                    except (ValueError, IndexError):
                        continue
        except OSError:
            pass

        # System.map takes precedence; ELF syms fill any gaps System.map lacks
        merged: Dict[int, str] = {**syms, **sysmap_syms}
        return cls(data, base_va, text_start, text_end, merged)

    # ---- frame cache -------------------------------------------------------

    def _ensure_frames(self) -> Dict[int, LoongArchFrame]:
        if self._frames_by_va is not None:
            return self._frames_by_va
        offset  = self._text_start - self._base_va
        length  = self._text_end - self._text_start
        snippet = self._data[offset:offset + length]
        frames  = self._dec.decode_frames(snippet, self._text_start)
        self._frames_by_va = {f.va: f for f in frames}
        return self._frames_by_va

    # ---- function-start heuristic -----------------------------------------

    def _get_func_starts(self) -> List[int]:
        fv = self._ensure_frames()
        starts: Set[int] = set()

        # Prologue heuristic: addi.d $sp, $sp, -N  (N > 0)
        for va, f in fv.items():
            if f.mnemonic == "addi.d":
                # op_str like "$sp, $sp, -48"
                parts = [p.strip() for p in f.op_str.split(",")]
                if len(parts) == 3 and parts[0] == "$sp" and parts[1] == "$sp":
                    try:
                        imm = int(parts[2])
                        if imm < 0:
                            starts.add(va)
                    except ValueError:
                        pass

        # Symbol table entries in .text range
        for va in self._syms:
            if self._text_start <= va < self._text_end:
                starts.add(va)

        if not starts:
            starts.add(self._text_start)
        return sorted(starts)

    # ---- intraprocedural scan (binary path) --------------------------------

    def _scan_func_binary(self, func_va: int, func_end: int,
                          init_labels: Optional[Set[str]] = None
                          ) -> List[TaintFindingLA64]:
        fv        = self._ensure_frames()
        func_name = self._syms.get(func_va, f"fn_0x{func_va:x}")
        findings: List[TaintFindingLA64] = []

        eng = TaintEngine()
        if init_labels:
            for r in ARG_REGS:
                for lbl in init_labels:
                    eng.taint_register(r, lbl)

        va = func_va
        while va < func_end:
            frame = fv.get(va)
            if frame is None:
                va += 4
                continue

            if frame.is_call and frame.target:
                callee_name = _name_at(self._syms, frame.target)
                st = eng.state

                if callee_name in _SOURCE_NAMES:
                    for r in CALLER_SAVED:
                        st.set(r, CLEAN)
                    for r in RET_REGS:
                        st.taint_reg(r, callee_name)

                elif callee_name in _ESCALATION_NAMES:
                    tainted_args = [r for r in ARG_REGS if st.get(r).tainted]
                    if tainted_args:
                        labels = frozenset().union(*(st.get(r).labels for r in tainted_args))
                        findings.append(TaintFindingLA64(
                            func_va=func_va, func_name=func_name,
                            sink_va=va, sink_name=callee_name,
                            tainted_args=tainted_args,
                            source_name=next(iter(sorted(labels)), "unknown"),
                            severity="CRITICAL",
                        ))
                    for r in CALLER_SAVED:
                        st.set(r, CLEAN)

                elif callee_name in _SINK_NAMES:
                    tainted_args = [r for r in ARG_REGS if st.get(r).tainted]
                    if tainted_args:
                        labels = frozenset().union(*(st.get(r).labels for r in tainted_args))
                        sev    = ("CRITICAL" if callee_name in
                                  {"system", "execve", "execl", "execvp", "popen",
                                   "kernel_execve", "call_usermodehelper"} else "HIGH")
                        findings.append(TaintFindingLA64(
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

            elif frame.mnemonic == "syscall":
                _handle_syscall_frame(eng, findings, func_va, func_name, va)

            elif frame.mnemonic == "ertn":
                # Exception return — terminates kernel exception handler
                break

            elif frame.mnemonic in ("break", "dbcl"):
                # Unconditional trap — unreachable past this point
                break

            elif frame.is_ret:
                break

            else:
                insn = from_loongarch_frame(frame.va, frame.mnemonic, frame.op_str,
                                            frame.width, frame.insn)
                eng.step(insn)

            va += frame.width

        return findings

    # ---- public API -------------------------------------------------------

    def run(self) -> List[TaintFindingLA64]:
        """Intraprocedural scan: each function is scanned independently."""
        starts   = self._get_func_starts()
        findings: List[TaintFindingLA64] = []
        for i, fva in enumerate(starts):
            fend = (self._dwarf_ends.get(fva)
                    or (starts[i + 1] if i + 1 < len(starts) else self._text_end))
            findings.extend(self._scan_func_binary(fva, fend))
        return findings

    def run_on_function_seeded(
        self,
        func_va: int,
        seed_arg_indices: Optional[List[int]] = None,
        source_label: str = "caller_arg",
        extra_sources: Optional[Set[str]] = None,
    ) -> List[TaintFindingLA64]:
        """
        Seeded intraprocedural scan for library RE: treats the specified
        argument registers as tainted at function entry, then tracks to sinks.

        Useful for shared library analysis where external input arrives through
        function arguments rather than through recv/read call sites.

        Args:
            func_va:          VA of the function to scan.
            seed_arg_indices: Which argument registers to seed (0-7 → $a0-$a7).
                              Defaults to [0,1,2,3,4,5,6,7] (all args tainted).
            source_label:     Taint label applied to seeded registers.
            extra_sources:    Additional function names to treat as taint sources
                              within this function (extends _SOURCE_NAMES locally).
        """
        if seed_arg_indices is None:
            seed_arg_indices = list(range(8))

        starts = self._get_func_starts()
        # Find function end via DWARF or next-start heuristic
        try:
            idx  = starts.index(func_va)
            fend = (self._dwarf_ends.get(func_va)
                    or (starts[idx + 1] if idx + 1 < len(starts) else self._text_end))
        except ValueError:
            # func_va not in starts list — scan up to 4096 bytes as fallback
            fend = func_va + 4096

        labels = {source_label}

        # Temporarily extend _SOURCE_NAMES if requested
        if extra_sources:
            import ablation.analyzers.taint_tracker_loongarch64 as _mod
            orig = _mod._SOURCE_NAMES
            _mod._SOURCE_NAMES = orig | frozenset(extra_sources)
            try:
                return self._scan_func_binary(func_va, fend, init_labels=labels)
            finally:
                _mod._SOURCE_NAMES = orig
        return self._scan_func_binary(func_va, fend, init_labels=labels)

    def run_interprocedural(self, depth: int = 4) -> List[TaintFindingLA64]:
        """
        Interprocedural BFS: follow tainted $a0-$a7 from callers into callees.

        Each callee that receives tainted argument registers is re-scanned with
        those labels as its initial state. Recursion depth bounded by `depth`.
        """
        starts   = self._get_func_starts()
        fv       = self._ensure_frames()
        # Prefer DWARF high_pc (precise); fall back to next-function-start.
        func_end: Dict[int, int] = {
            fva: (self._dwarf_ends.get(fva)
                  or (starts[i + 1] if i + 1 < len(starts) else self._text_end))
            for i, fva in enumerate(starts)
        }

        findings: List[TaintFindingLA64] = []
        queue:    List[Tuple[int, int, Set[str]]] = [
            (fva, depth, set()) for fva in starts
        ]
        visited:  Dict[Tuple, int] = {}

        while queue:
            fva, d, init_labels = queue.pop(0)
            key = (fva,) + tuple(sorted(init_labels))
            if visited.get(key, -1) >= d:
                continue
            visited[key] = d
            fend      = func_end.get(fva, self._text_end)
            func_name = self._syms.get(fva, f"fn_0x{fva:x}")

            eng = TaintEngine()
            for r in ARG_REGS:
                for lbl in init_labels:
                    eng.taint_register(r, lbl)

            va = fva
            while va < fend:
                frame = fv.get(va)
                if frame is None:
                    va += 4
                    continue

                if frame.is_call and frame.target:
                    callee_va   = frame.target
                    callee_name = _name_at(self._syms, callee_va)
                    st = eng.state

                    if callee_name in _SOURCE_NAMES:
                        for r in CALLER_SAVED:
                            st.set(r, CLEAN)
                        for r in RET_REGS:
                            st.taint_reg(r, callee_name)

                    elif callee_name in _ESCALATION_NAMES:
                        tainted_args = [r for r in ARG_REGS if st.get(r).tainted]
                        if tainted_args:
                            labels = frozenset().union(
                                *(st.get(r).labels for r in tainted_args))
                            findings.append(TaintFindingLA64(
                                func_va=fva, func_name=func_name,
                                sink_va=va, sink_name=callee_name,
                                tainted_args=tainted_args,
                                source_name=next(iter(sorted(labels)), "unknown"),
                                severity="CRITICAL",
                            ))
                        for r in CALLER_SAVED:
                            st.set(r, CLEAN)

                    elif callee_name in _SINK_NAMES:
                        tainted_args = [r for r in ARG_REGS if st.get(r).tainted]
                        if tainted_args:
                            labels = frozenset().union(
                                *(st.get(r).labels for r in tainted_args))
                            sev = ("CRITICAL" if callee_name in
                                   {"system", "execve", "execl", "execvp", "popen",
                                    "kernel_execve", "call_usermodehelper"} else "HIGH")
                            findings.append(TaintFindingLA64(
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
                            callee_labels = set().union(
                                *(st.get(r).labels for r in tainted_into))
                            c_va = callee_va
                            for off in range(0, _PLT_TOL + 1, 4):
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

                elif frame.mnemonic == "syscall":
                    _handle_syscall_frame(eng, findings, fva, func_name, va)

                elif frame.mnemonic in ("ertn", "break", "dbcl"):
                    break

                elif frame.is_ret:
                    break
                else:
                    insn = from_loongarch_frame(frame.va, frame.mnemonic,
                                                frame.op_str, frame.width, frame.insn)
                    eng.step(insn)

                va += frame.width

        seen:   Set[Tuple] = set()
        unique: List[TaintFindingLA64] = []
        for f in findings:
            k = (f.func_va, f.sink_va, f.sink_name)
            if k not in seen:
                seen.add(k)
                unique.append(f)
        return unique

    def report(self, findings: List[TaintFindingLA64]) -> str:
        if not findings:
            return "LoongArch64 taint: no findings."
        lines = [f"LoongArch64 taint: {len(findings)} finding(s)\n"]
        for f in sorted(findings, key=lambda x: (x.func_va, x.sink_va)):
            lines.append(str(f))
        return "\n".join(lines)
