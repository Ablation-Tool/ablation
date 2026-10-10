"""
binary_lifter.py — Lift native binary functions to annotated C pseudocode.

Active Architecture Tomography Phase 1: static CFG-based IR emission for
ARM64. DEXLifter (dex_lifter.py) is the structural template.

Architecture support:
    arm64    — full; CFG + register state machine + calling convention
    x86_64   — full; linear disasm + _X86_64State register tracking; PE + ELF
    la64     — stub; planned Phase 1 extension

Usage:
    from ablation.analyzers.binary_lifter import BinaryLifter

    lifter = BinaryLifter.from_path('/path/to/binary')
    print(lifter.lift_function(0x12340))

    # With taint annotations from ARM64TaintTracker:
    findings = ARM64TaintTracker.from_path_full(elf).run_interprocedural()
    lifter = BinaryLifter.from_path(elf).with_taint(findings)
    print(lifter.lift_function(0x12340))

    # Convenience: print a single function
    BinaryLifter.report(elf, 0x12340)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .insn_arm64 import Cond, Imm, Insn, Mem, Reg, Sym, from_capstone
from .cfg_arm64 import Block, CFG, build_cfg


# ── NativeVal: per-register state ─────────────────────────────────────────────

@dataclass
class NativeVal:
    """Current C type + expression for one physical register slot."""
    ctype: str      # "uint64_t", "uint32_t", "uint8_t", "int32_t", "void*", ...
    expr: str       # expression: "arg0", "v3", "0x1234", "*(uint64_t*)v1 + 8"
    is_ptr: bool = False
    tainted: bool = False
    uses: int = 0


_UNKNOWN = NativeVal("uint64_t", "???")

_PARAM_REGS = ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7")
_CALLEE_SAVED = frozenset({"x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","x29"})
_ZERO_REG = frozenset({"xzr", "wzr"})

_COND_OPS: Dict[str, str] = {
    "eq": "==", "ne": "!=",
    "cs": ">=u", "hs": ">=u", "cc": "<u", "lo": "<u",
    "mi": "< 0", "pl": ">= 0",
    "vs": "overflow", "vc": "no_overflow",
    "hi": ">u", "ls": "<=u",
    "ge": ">=", "lt": "<", "gt": ">", "le": "<=",
}


# ── Register canonicalization ──────────────────────────────────────────────────

def _canon(name: str) -> str:
    """Normalize any ARM64 register name to its canonical x-form."""
    n = name.lower()
    if n in ("wzr",):
        return "xzr"
    if n.startswith("w") and n[1:].isdigit():
        return "x" + n[1:]
    if n == "wsp":
        return "sp"
    if n == "fp":
        return "x29"
    if n == "lr":
        return "x30"
    if n == "ip0":
        return "x16"
    if n == "ip1":
        return "x17"
    return n


def _bits(name: str) -> int:
    """Return register width in bits."""
    n = name.lower()
    if n.startswith("b"):
        return 8
    if n.startswith("h"):
        return 16
    if n.startswith("w") or n == "wzr" or n == "wsp":
        return 32
    return 64


def _ctype_from_bits(b: int, signed: bool = False) -> str:
    if b == 8:
        return "int8_t" if signed else "uint8_t"
    if b == 16:
        return "int16_t" if signed else "uint16_t"
    if b == 32:
        return "int32_t" if signed else "uint32_t"
    return "int64_t" if signed else "uint64_t"


def _load_ctype(mnem: str, dst_reg: str) -> str:
    """Infer C type from a load mnemonic."""
    m = mnem.rstrip(".")
    if m in ("ldrb", "ldurb"):
        return "uint8_t"
    if m in ("ldrsb", "ldursb"):
        return "int8_t"
    if m in ("ldrh", "ldurh"):
        return "uint16_t"
    if m in ("ldrsh", "ldursh"):
        return "int16_t"
    if m in ("ldrsw", "ldursw"):
        return "int32_t"
    # Width from destination register
    return _ctype_from_bits(_bits(dst_reg))


def _ptr_cast(ctype: str) -> str:
    return f"({ctype} *)"


# ── Operand expression helpers ─────────────────────────────────────────────────

def _imm_expr(v: int) -> str:
    if v == 0:
        return "0"
    if -256 <= v < 0:
        return str(v)
    if abs(v) < 10:
        return str(v)
    return f"{v:#x}"


def _shift_expr(base_expr: str, reg: Reg) -> str:
    """Apply any shift/extend on a register operand."""
    if not reg.shift or reg.amount == 0:
        return base_expr
    return f"({base_expr} {reg.shift} {reg.amount})"


def _mem_address_expr(mem: Mem, regs: Dict[str, NativeVal]) -> str:
    """Produce the address expression for a Mem operand."""
    base = regs.get(mem.base, NativeVal("uint64_t", mem.base)).expr
    if mem.index is not None:
        idx_canon = _canon(mem.index.name)
        idx = regs.get(idx_canon, NativeVal("uint64_t", mem.index.name)).expr
        idx = _shift_expr(idx, mem.index)
        if mem.offset:
            return f"({base} + {idx} + {_imm_expr(mem.offset)})"
        return f"({base} + {idx})"
    if mem.offset:
        return f"({base} + {_imm_expr(mem.offset)})"
    return base


# ── Section mapping helper ─────────────────────────────────────────────────────

def _build_section_map(binary_path: str) -> List[Tuple[int, int, int]]:
    """Return sorted list of (vaddr, size, file_offset) for each loadable section.

    Handles ELF and PE (Windows game binaries).
    """
    try:
        import lief  # type: ignore
        obj = lief.parse(binary_path)
        if obj is None:
            return []
        secs = []
        if hasattr(lief, "ELF") and isinstance(obj, lief.ELF.Binary):
            for s in obj.sections:
                va, sz, off = int(s.virtual_address), int(s.size), int(s.offset)
                if sz > 0 and va > 0:
                    secs.append((va, sz, off))
        elif hasattr(lief, "PE") and isinstance(obj, lief.PE.Binary):
            # PE: VAs are RVA + image_base; raw_offset is the file offset
            base = obj.optional_header.imagebase
            for s in obj.sections:
                va  = base + int(s.virtual_address)
                sz  = int(s.virtual_size) or int(s.size)
                off = int(s.pointerto_raw_data)
                if sz > 0 and va > base:
                    secs.append((va, sz, off))
        else:
            # Generic fallback: section-based
            for s in obj.sections:
                va  = int(getattr(s, "virtual_address", 0))
                sz  = int(getattr(s, "size", 0))
                off = int(getattr(s, "offset", 0))
                if sz > 0 and va > 0:
                    secs.append((va, sz, off))
        secs.sort()
        return secs
    except Exception:
        return []


def _va_to_offset(va: int, secs: List[Tuple[int, int, int]]) -> Optional[int]:
    for (base, sz, off) in secs:
        if base <= va < base + sz:
            return off + (va - base)
    return None


# ── BinaryLifter ───────────────────────────────────────────────────────────────

class BinaryLifter:
    """Lift native binary functions to annotated C pseudocode.

    Supports ARM64 natively; x86-64 and LoongArch64 are planned stubs.
    """

    def __init__(
        self,
        binary_path: str,
        arch: str = "arm64",
        taint_map: Optional[Dict[int, Set[str]]] = None,
        plt: Optional[Dict[int, str]] = None,
        func_names: Optional[Dict[int, str]] = None,
    ):
        self.path = binary_path
        self.arch = arch.lower()
        self.data = Path(binary_path).read_bytes()
        self._sections = _build_section_map(binary_path)
        self._taint_map: Dict[int, Set[str]] = taint_map or {}
        self._plt: Dict[int, str] = plt or {}
        self._names: Dict[int, str] = func_names or {}

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, binary_path: str, arch: str = "arm64") -> "BinaryLifter":
        return cls(binary_path, arch=arch)

    @classmethod
    def from_context(cls, ctx, arch: str = "arm64") -> "BinaryLifter":
        """Construct from a BinaryContext, inheriting PLT and confirmed names."""
        inst = cls(ctx.binary_path, arch=arch)
        # Populate PLT from XRefGraph if available
        if hasattr(ctx, "xref") and ctx.xref is not None:
            inst._plt = dict(getattr(ctx.xref, "_plt", {}))
        # Populate names from confirmed name overlay
        if hasattr(ctx, "_names"):
            inst._names = dict(ctx._names)
        return inst

    def with_taint(self, findings) -> "BinaryLifter":
        """Return new BinaryLifter with taint regs from TaintFindingARM64 list."""
        taint_map: Dict[int, Set[str]] = {}
        for f in findings:
            fva = getattr(f, "func_va", None) or getattr(f, "function_va", None)
            if fva is None:
                continue
            # Collect all tainted register names mentioned in the finding
            regs: Set[str] = set()
            for attr in ("source_reg", "sink_reg", "taint_reg"):
                r = getattr(f, attr, None)
                if r:
                    regs.add(_canon(str(r)))
            # Also accept a 'tainted_regs' iterable
            for r in getattr(f, "tainted_regs", []):
                regs.add(_canon(str(r)))
            if regs:
                taint_map.setdefault(fva, set()).update(regs)
        import copy
        inst = copy.copy(self)
        inst._taint_map = {**self._taint_map, **taint_map}
        return inst

    # ── Byte extraction ───────────────────────────────────────────────────────

    def _read_va(self, va: int, size: int) -> bytes:
        off = _va_to_offset(va, self._sections)
        if off is None:
            raise ValueError(f"VA {va:#x} not mapped in {Path(self.path).name}")
        return self.data[off: off + size]

    def _func_name(self, va: int) -> str:
        if va in self._names:
            return self._names[va]
        if va in self._plt:
            return self._plt[va]
        return f"fn_{va:x}"

    # ── Public API ────────────────────────────────────────────────────────────

    def lift_function(self, va: int, max_insns: int = 512) -> str:
        """Lift the function at *va* to annotated C pseudocode.

        Args:
            va:        Virtual address of the function entry point.
            max_insns: Upper bound on instructions to disassemble.

        Returns:
            A multi-line string of pseudo-C IR.
        """
        if self.arch == "arm64":
            return self._lift_arm64(va, max_insns)
        if self.arch in ("x86_64", "x86-64", "amd64", "x86"):
            return self._lift_x86_64(va, max_insns)
        if self.arch in ("x86_32", "x86-32", "i386", "i686"):
            return self._lift_x86_32(va, max_insns)
        if self.arch in ("arm32", "arm", "arm-32"):
            return self._lift_arm32(va, max_insns, thumb=False)
        if self.arch in ("thumb", "thumb2", "arm-thumb"):
            return self._lift_arm32(va, max_insns, thumb=True)
        if self.arch in ("mips32", "mips", "mips-32", "mipsbe"):
            return self._lift_mips(va, max_insns, bits=32, little=False)
        if self.arch in ("mips32el", "mipsel", "mips-32-el"):
            return self._lift_mips(va, max_insns, bits=32, little=True)
        if self.arch in ("mips64", "mips-64", "mipsn64"):
            return self._lift_mips(va, max_insns, bits=64, little=False)
        if self.arch in ("mips64el",):
            return self._lift_mips(va, max_insns, bits=64, little=True)
        if self.arch in ("nanomips",):
            return self._lift_nanomips(va, max_insns)
        if self.arch in ("ppc32", "ppc", "powerpc", "ppc-32"):
            return self._lift_ppc(va, max_insns, bits=32)
        if self.arch in ("ppc64", "powerpc64", "ppc-64"):
            return self._lift_ppc(va, max_insns, bits=64)
        if self.arch in ("rv32", "riscv32", "riscv-32"):
            return self._lift_riscv(va, max_insns, bits=32)
        if self.arch in ("rv64", "riscv64", "riscv-64"):
            return self._lift_riscv(va, max_insns, bits=64)
        if self.arch in ("arc", "archs", "arcem", "arc-32"):
            return self._lift_arc(va, max_insns)
        if self.arch in ("v850", "rh850", "v850e2"):
            return self._lift_v850(va, max_insns)
        if self.arch in ("la64", "loongarch64", "loongarch_64", "loongarch-64"):
            return self._lift_loongarch64(va, max_insns)
        if self.arch in ("beam", "erlang", "elixir"):
            return self._lift_beam(va, max_insns)
        return f"// unsupported arch: {self.arch}\n"

    @classmethod
    def report(cls, binary_path: str, va: int, arch: str = "arm64") -> None:
        """Convenience: lift and print a single function."""
        print(cls.from_path(binary_path, arch=arch).lift_function(va))

    # ── ARM64 lifter ──────────────────────────────────────────────────────────

    def _lift_arm64(self, func_va: int, max_insns: int) -> str:
        try:
            code = self._read_va(func_va, max_insns * 4)
        except ValueError as e:
            return f"// {e}\n"

        raw_insns = list(from_capstone(code, func_va))[:max_insns]
        if not raw_insns:
            return f"// no instructions decoded at {func_va:#x}\n"

        try:
            cfg = build_cfg(raw_insns, entry=func_va)
        except Exception as e:
            return f"// CFG build failed: {e}\n"

        tainted_params = self._taint_map.get(func_va, set())
        fname = self._func_name(func_va)
        state = _ARM64State(tainted_params, self._func_name, self._plt)
        lines: List[str] = [f"// {fname} @ {func_va:#x}"]
        lines.append("{")

        visited: Set[int] = set()
        queue: List[int] = [func_va]

        while queue:
            bva = queue.pop(0)
            if bva in visited or bva not in cfg.blocks:
                continue
            visited.add(bva)

            block = cfg.blocks[bva]
            # Emit block label unless it's the entry
            if bva != func_va:
                lines.append(f"  loc_{bva:x}:")

            for insn in block.insns:
                stmt = state.emit(insn)
                if stmt:
                    for s in stmt.splitlines():
                        lines.append("  " + s)

            for succ in block.succs:
                if succ not in visited:
                    queue.append(succ)

        lines.append("}")
        return "\n".join(lines) + "\n"

    # ── x86-64 lifter ─────────────────────────────────────────────────────────

    def _lift_x86_64(self, func_va: int, max_insns: int) -> str:
        import capstone

        # Read up to max_insns * 7 bytes (avg x86_64 insn ~4 bytes, max 15)
        try:
            code = self._read_va(func_va, max_insns * 7)
        except ValueError as e:
            return f"// {e}\n"

        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        insns = list(cs.disasm(code, func_va))[:max_insns]
        if not insns:
            return f"// no instructions decoded at {func_va:#x}\n"

        tainted_params = self._taint_map.get(func_va, set())
        fname = self._func_name(func_va)
        state = _X86_64State(tainted_params, self._func_name, self._plt)

        lines: List[str] = [f"// {fname} @ {func_va:#x}", "{"]

        # Build a quick set of known branch targets for label emission
        branch_targets: Set[int] = set()
        for insn in insns:
            mn = insn.mnemonic.lower()
            if mn in _X86_JCCS or mn == "jmp":
                if insn.operands and insn.operands[0].type == 2:  # X86_OP_IMM
                    branch_targets.add(insn.operands[0].imm)

        for insn in insns:
            if insn.address != func_va and insn.address in branch_targets:
                lines.append(f"  loc_{insn.address:x}:")
            try:
                stmt = state.lift_insn(insn)
            except Exception:
                stmt = f"// {insn.mnemonic} {insn.op_str}"
            if stmt:
                for s in stmt.splitlines():
                    lines.append("  " + s)

        lines.append("}")
        return "\n".join(lines) + "\n"


# ── ARM64 emitter state machine ───────────────────────────────────────────────

class _ARM64State:
    """Per-function mutable state for the ARM64 lifting loop."""

    def __init__(
        self,
        tainted_params: Set[str],
        name_fn,
        plt: Dict[int, str],
    ):
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()  # variable names already emitted as declarations
        self._tainted = tainted_params
        self._cmp: Optional[Tuple[str, str]] = None  # last cmp/tst operands
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt
        # Seed parameter registers
        for i, r in enumerate(_PARAM_REGS):
            tainted = r in tainted_params
            self._regs[r] = NativeVal("uint64_t", f"arg{i}", tainted=tainted)
            self._written.add(r)
            self._declared.add(f"arg{i}")
        self._regs["sp"] = NativeVal("uint64_t", "sp", is_ptr=True)
        self._written.add("sp")
        self._declared.add("sp")
        self._regs["xzr"] = NativeVal("uint64_t", "0")
        self._written.add("xzr")
        # Callee-saved registers: pre-seed so stores/loads show their names
        for r in _CALLEE_SAVED:
            self._regs[r] = NativeVal("uint64_t", r)
            self._written.add(r)
            self._declared.add(r)
        self._regs["x29"] = NativeVal("uint64_t", "fp", is_ptr=True)
        self._declared.add("fp")
        self._regs["x30"] = NativeVal("uint64_t", "lr")
        self._written.add("x30")
        self._declared.add("lr")

    # ── Register access ───────────────────────────────────────────────────────

    def _read(self, reg_name: str) -> NativeVal:
        c = _canon(reg_name)
        if c in _ZERO_REG:
            return NativeVal("uint64_t", "0")
        if c not in self._written:
            # First read before any write — implicit parameter
            if c in _PARAM_REGS:
                tainted = c in self._tainted
                v = NativeVal("uint64_t", f"arg{_PARAM_REGS.index(c)}", tainted=tainted)
            else:
                v = NativeVal("uint64_t", c)  # unknown callee-saved or temp
            self._regs[c] = v
            self._written.add(c)
        v = self._regs.get(c, _UNKNOWN)
        v.uses += 1
        return v

    def _write(self, reg_name: str, val: NativeVal) -> str:
        """Assign val to reg, return the lvalue name (e.g. 'v3')."""
        c = _canon(reg_name)
        if c in _ZERO_REG:
            return "0"
        # Reuse the existing var name if we're overwriting a local variable
        old = self._regs.get(c)
        if old and c in self._written:
            expr = old.expr
            is_local = (
                (expr.startswith("v") and expr[1:].isdigit()) or
                (expr.startswith("arg") and expr[3:].isdigit())
            )
            if is_local:
                self._regs[c] = NativeVal(val.ctype, expr, val.is_ptr, val.tainted)
                return expr
        # New variable
        vname = f"v{self._var_n}"
        self._var_n += 1
        self._regs[c] = NativeVal(val.ctype, vname, val.is_ptr, val.tainted)
        self._written.add(c)
        return vname

    def _decl(self, ctype: str, vname: str, expr: str, taint_ann: str = "") -> str:
        """Emit a declaration or reassignment depending on whether vname is new."""
        if vname in self._declared:
            return f"{vname} = {expr};{taint_ann}"
        self._declared.add(vname)
        return f"{ctype} {vname} = {expr};{taint_ann}"

    def _expr(self, reg_name: str) -> str:
        return self._read(reg_name).expr

    def _is_tainted(self, reg_name: str) -> bool:
        return self._regs.get(_canon(reg_name), _UNKNOWN).tainted

    def _propagate_taint(self, *src_regs: str) -> bool:
        return any(self._is_tainted(r) for r in src_regs)

    # ── Instruction dispatch ───────────────────────────────────────────────────

    def emit(self, insn: Insn) -> str:
        m = insn.mnemonic.lower()

        # ── Branches ──────────────────────────────────────────────────────────
        if m == "ret" or m.startswith("ret"):
            ret_val = self._expr("x0")
            return f"return {ret_val};"

        if m == "b":
            tgt = insn.imm(0)
            if tgt is not None:
                return f"goto loc_{tgt:x};"
            return f"goto *{self._expr(insn.reg(0).name)};"

        if m.startswith("b."):
            cond_code = m[2:]
            tgt = insn.imm(0)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            cond_str = self._cond_expr(cond_code)
            return f"if ({cond_str}) goto {label};"

        if m == "cbz":
            r, tgt = insn.reg(0), insn.imm(1)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            return f"if (!{self._expr(r.name)}) goto {label};"

        if m == "cbnz":
            r, tgt = insn.reg(0), insn.imm(1)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            return f"if ({self._expr(r.name)}) goto {label};"

        if m == "tbz":
            r, bit_imm, tgt = insn.reg(0), insn.imm(1), insn.imm(2)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            return f"if (!({self._expr(r.name)} & {1 << bit_imm:#x})) goto {label};"

        if m == "tbnz":
            r, bit_imm, tgt = insn.reg(0), insn.imm(1), insn.imm(2)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            return f"if ({self._expr(r.name)} & {1 << bit_imm:#x}) goto {label};"

        # ── Calls ──────────────────────────────────────────────────────────────
        if m in ("bl", "blr", "blraa", "blraaz", "blrab", "blrabz"):
            return self._emit_call(insn, m)

        # ── Compare / test (update cmp_state; no output) ─────────────────────
        if m == "cmp":
            a = self._expr(insn.reg(0).name)
            b = self._operand_expr(insn, 1)
            self._cmp = (a, b)
            return f"// cmp {a}, {b}"

        if m == "cmn":
            a = self._expr(insn.reg(0).name)
            b = self._operand_expr(insn, 1)
            self._cmp = (a, f"-({b})")
            return f"// cmn {a}, {b}"

        if m == "tst":
            a = self._expr(insn.reg(0).name)
            b = self._operand_expr(insn, 1)
            self._cmp = (f"({a} & {b})", "0")
            return f"// tst {a}, {b}"

        # ── Load ───────────────────────────────────────────────────────────────
        if m.startswith("ldr") or m.startswith("ldur") or m in ("ldpsw",):
            return self._emit_load(insn, m)

        if m == "ldp":
            return self._emit_ldp(insn)

        # ── Store ──────────────────────────────────────────────────────────────
        if m.startswith("str") or m.startswith("stur"):
            return self._emit_store(insn, m)

        if m == "stp":
            return self._emit_stp(insn)

        # ── Move ───────────────────────────────────────────────────────────────
        if m == "mov":
            dst = insn.reg(0)
            src_expr = self._operand_expr(insn, 1)
            tainted = self._propagate_taint(insn.reg(1).name) if insn.reg(1) else False
            ctype = _ctype_from_bits(_bits(dst.name))
            vname = self._write(dst.name, NativeVal(ctype, src_expr, tainted=tainted))
            if vname == src_expr:
                return ""  # trivial self-assign
            return self._decl(ctype, vname, src_expr)

        if m in ("movz", "movn", "movk"):
            return self._emit_movimm(insn, m)

        # ── Arithmetic ────────────────────────────────────────────────────────
        if m in ("add", "adds", "sub", "subs"):
            return self._emit_binop(insn, m)

        if m in ("mul", "smull", "umull", "mneg"):
            return self._emit_binop(insn, m)

        if m in ("madd", "msub"):
            return self._emit_madd(insn, m)

        if m in ("udiv", "sdiv"):
            op = "/"
            dst = insn.reg(0)
            a = self._expr(insn.reg(1).name)
            b = self._expr(insn.reg(2).name)
            tainted = self._propagate_taint(insn.reg(1).name, insn.reg(2).name)
            ctype = _ctype_from_bits(_bits(dst.name), signed=(m == "sdiv"))
            vname = self._write(dst.name, NativeVal(ctype, f"{a} {op} {b}", tainted=tainted))
            return self._decl(ctype, vname, f"{a} {op} {b}")

        # ── Bitwise ───────────────────────────────────────────────────────────
        if m in ("and", "ands", "orr", "eor", "bic", "orn", "eon"):
            return self._emit_bitwise(insn, m)

        if m in ("lsl", "lsr", "asr", "ror"):
            return self._emit_shift(insn, m)

        # ── Extension / narrowing ─────────────────────────────────────────────
        if m in ("sxtw", "sxth", "sxtb", "sxtx"):
            dst, src = insn.reg(0), insn.reg(1)
            widths = {"sxtb": 8, "sxth": 16, "sxtw": 32, "sxtx": 64}
            w = widths.get(m, 32)
            src_expr = self._expr(src.name)
            cast = _ctype_from_bits(w, signed=True)
            ctype = _ctype_from_bits(_bits(dst.name), signed=True)
            expr = f"(int64_t)({cast}){src_expr}" if w < 64 else src_expr
            tainted = self._propagate_taint(src.name)
            vname = self._write(dst.name, NativeVal(ctype, expr, tainted=tainted))
            return self._decl(ctype, vname, expr)

        if m in ("uxtb", "uxth", "uxtw", "uxtx"):
            dst, src = insn.reg(0), insn.reg(1)
            widths = {"uxtb": 8, "uxth": 16, "uxtw": 32, "uxtx": 64}
            w = widths.get(m, 32)
            cast = _ctype_from_bits(w, signed=False)
            src_expr = self._expr(src.name)
            expr = f"(uint64_t)({cast}){src_expr}" if w < 64 else src_expr
            tainted = self._propagate_taint(src.name)
            ctype = "uint64_t"
            vname = self._write(dst.name, NativeVal(ctype, expr, tainted=tainted))
            return self._decl(ctype, vname, expr)

        # ── Conditional select ────────────────────────────────────────────────
        if m in ("csel", "cset", "csetm", "csinc", "csinv", "csneg"):
            return self._emit_csel(insn, m)

        # ── NEON / FP ─────────────────────────────────────────────────────────
        if m.startswith(("fmov", "fadd", "fsub", "fmul", "fdiv")):
            return f"// {insn.mnemonic} (fp)"

        # ── System / stack maintenance ────────────────────────────────────────
        if m in ("nop", "dmb", "dsb", "isb", "hint"):
            return ""

        if m in ("svc",):
            imm = insn.imm(0)
            return f"syscall({_imm_expr(imm) if imm is not None else '?'});"

        if m == "brk":
            return "/* brk */"

        if m in ("adr", "adrp"):
            dst = insn.reg(0)
            tgt = insn.imm(1)
            expr = f"{tgt:#x}" if tgt is not None else "???"
            vname = self._write(dst.name, NativeVal("void *", expr, is_ptr=True))
            return self._decl("void *", vname, f"(void *){expr}")

        # Fallback: emit raw disassembly as a comment
        ops_str = ", ".join(str(o) for o in insn.ops)
        return f"// {insn.mnemonic} {ops_str}"

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _operand_expr(self, insn: Insn, idx: int) -> str:
        op = insn.ops[idx] if idx < len(insn.ops) else None
        if op is None:
            return "???"
        if isinstance(op, Reg):
            return _shift_expr(self._expr(op.name), op)
        if isinstance(op, Imm):
            return _imm_expr(op.value)
        if isinstance(op, Mem):
            return _mem_address_expr(op, self._regs)
        if isinstance(op, Sym):
            return f"{op.name}"
        return "???"

    def _cond_expr(self, code: str) -> str:
        if self._cmp is None:
            return f"/* {code} */"
        a, b = self._cmp
        op = _COND_OPS.get(code.lower(), code)
        if op in ("<u", ">u", "<=u", ">=u"):
            return f"(unsigned){a} {op[:-1]} (unsigned){b}"
        if op == "< 0":
            return f"{a} < 0"
        if op == ">= 0":
            return f"{a} >= 0"
        return f"{a} {op} {b}"

    def _emit_call(self, insn: Insn, m: str) -> str:
        if m == "bl":
            tgt = insn.imm(0)
            callee = self._name_fn(tgt) if tgt is not None else "???"
        elif insn.reg(0):
            callee = f"*{self._expr(insn.reg(0).name)}"
            tgt = None
        else:
            callee = "???"
            tgt = None

        # Collect live arg registers
        args = []
        for r in _PARAM_REGS:
            if r in self._written:
                args.append(self._expr(r))
        args_str = ", ".join(args) if args else ""

        # Mark x0 as return value; clobber x1-x7
        ret_var = f"v{self._var_n}"
        self._var_n += 1
        is_tainted = any(self._is_tainted(r) for r in _PARAM_REGS)
        self._regs["x0"] = NativeVal("uint64_t", ret_var, tainted=is_tainted)
        self._written.add("x0")
        for r in _PARAM_REGS[1:]:
            self._written.discard(r)

        taint_ann = " /* TAINTED */" if is_tainted else ""
        return self._decl("uint64_t", ret_var, f"{callee}({args_str})", taint_ann)

    def _emit_load(self, insn: Insn, m: str) -> str:
        dst = insn.reg(0)
        mem = insn.first_mem()
        if mem is None or dst is None:
            ops_str = ", ".join(str(o) for o in insn.ops)
            return f"// {insn.mnemonic} {ops_str}"
        ctype = _load_ctype(m, dst.name)
        addr = _mem_address_expr(mem, self._regs)
        src_tainted = self._is_tainted(mem.base)
        taint_ann = " /* TAINTED */" if src_tainted else ""
        expr = f"*({_ptr_cast(ctype)}{addr})"
        vname = self._write(dst.name, NativeVal(ctype, expr, tainted=src_tainted))
        # writeback
        wb = ""
        if mem.writeback == "pre":
            base_expr = self._expr(mem.base)
            off = _imm_expr(mem.offset)
            self._regs[mem.base] = NativeVal("uint64_t", f"({base_expr} + {off})", is_ptr=True)
            wb = f"\n  {mem.base} += {off};"
        elif mem.writeback == "post":
            base_expr = self._expr(mem.base)
            off = _imm_expr(mem.wb_amount)
            self._regs[mem.base] = NativeVal("uint64_t", f"({base_expr} + {off})", is_ptr=True)
            wb = f"\n  {mem.base} += {off};"
        return self._decl(ctype, vname, expr, taint_ann) + wb

    def _emit_ldp(self, insn: Insn) -> str:
        d0, d1 = insn.reg(0), insn.reg(1)
        mem = insn.first_mem()
        if d0 is None or d1 is None or mem is None:
            return f"// ldp ???"
        w = _bits(d0.name)
        ctype = _ctype_from_bits(w)
        pair_sz = w // 8
        addr0 = _mem_address_expr(mem, self._regs)
        addr1_off = mem.offset + pair_sz
        mem1 = Mem(mem.base, addr1_off, mem.index)
        addr1 = _mem_address_expr(mem1, self._regs)
        src_tainted = self._is_tainted(mem.base)
        e0 = f"*({_ptr_cast(ctype)}{addr0})"
        e1 = f"*({_ptr_cast(ctype)}{addr1})"
        v0 = self._write(d0.name, NativeVal(ctype, e0, tainted=src_tainted))
        v1 = self._write(d1.name, NativeVal(ctype, e1, tainted=src_tainted))
        taint_ann = " /* TAINTED */" if src_tainted else ""
        s0 = self._decl(ctype, v0, e0)
        s1 = self._decl(ctype, v1, e1)
        if taint_ann:
            s1 = s1.rstrip(";") + taint_ann + ";"
        return f"{s0}\n{s1}"

    def _emit_store(self, insn: Insn, m: str) -> str:
        src = insn.reg(0)
        mem = insn.first_mem()
        if src is None or mem is None:
            ops_str = ", ".join(str(o) for o in insn.ops)
            return f"// {insn.mnemonic} {ops_str}"
        w = _bits(src.name)
        if "b" in m[3:4] or m.endswith("b"):
            w = 8
        elif "h" in m[3:4] or m.endswith("h"):
            w = 16
        ctype = _ctype_from_bits(w)
        addr = _mem_address_expr(mem, self._regs)
        val = self._expr(src.name)
        taint_ann = " /* TAINTED */" if self._is_tainted(src.name) else ""
        wb = ""
        if mem.writeback == "pre":
            off = _imm_expr(mem.offset)
            self._regs[mem.base] = NativeVal("uint64_t", f"({self._expr(mem.base)} + {off})", is_ptr=True)
            wb = f"\n  {mem.base} += {off};"
        elif mem.writeback == "post":
            off = _imm_expr(mem.wb_amount)
            self._regs[mem.base] = NativeVal("uint64_t", f"({self._expr(mem.base)} + {off})", is_ptr=True)
            wb = f"\n  {mem.base} += {off};"
        return f"*({_ptr_cast(ctype)}{addr}) = {val};{taint_ann}{wb}"

    def _emit_stp(self, insn: Insn) -> str:
        s0, s1 = insn.reg(0), insn.reg(1)
        mem = insn.first_mem()
        if s0 is None or s1 is None or mem is None:
            return f"// stp ???"
        w = _bits(s0.name)
        ctype = _ctype_from_bits(w)
        pair_sz = w // 8
        addr0 = _mem_address_expr(mem, self._regs)
        mem1 = Mem(mem.base, mem.offset + pair_sz, mem.index)
        addr1 = _mem_address_expr(mem1, self._regs)
        v0 = self._expr(s0.name)
        v1 = self._expr(s1.name)
        taint_ann = " /* TAINTED */" if (self._is_tainted(s0.name) or self._is_tainted(s1.name)) else ""
        wb = ""
        if mem.writeback == "pre":
            off = _imm_expr(mem.offset)
            self._regs[mem.base] = NativeVal("uint64_t", f"({self._expr(mem.base)} + {off})", is_ptr=True)
        return f"*({_ptr_cast(ctype)}{addr0}) = {v0}; *({_ptr_cast(ctype)}{addr1}) = {v1};{taint_ann}{wb}"

    def _emit_movimm(self, insn: Insn, m: str) -> str:
        dst = insn.reg(0)
        imm = insn.imm(1)
        if dst is None or imm is None:
            return f"// {insn.mnemonic} ???"
        ctype = _ctype_from_bits(_bits(dst.name))
        if m == "movn":
            expr = _imm_expr(~imm & ((1 << _bits(dst.name)) - 1))
        elif m == "movk":
            # Insert bits into existing value
            # Find shift amount from ops
            shift = 0
            for op in insn.ops[2:]:
                if isinstance(op, Imm):
                    shift = op.value
                    break
            old = self._expr(dst.name)
            mask = ~(0xFFFF << shift) & 0xFFFFFFFFFFFFFFFF
            expr = f"({old} & {mask:#x}) | {(imm << shift):#x}"
        else:
            # movz — find optional shift in ops
            shift = 0
            for op in insn.ops[2:]:
                if isinstance(op, Imm):
                    shift = op.value
                    break
            expr = _imm_expr(imm << shift)
        vname = self._write(dst.name, NativeVal(ctype, expr))
        return self._decl(ctype, vname, expr)

    def _emit_binop(self, insn: Insn, m: str) -> str:
        dst = insn.reg(0)
        a = self._expr(insn.reg(1).name) if insn.reg(1) else "???"
        b = self._operand_expr(insn, 2)
        tainted = self._propagate_taint(
            *[r.name for r in [insn.reg(1), insn.reg(2)] if r]
        )
        op_map = {"add": "+", "adds": "+", "sub": "-", "subs": "-",
                  "mul": "*", "smull": "*", "umull": "*", "mneg": "-"}
        op = op_map.get(m, "+")
        if m == "mneg":
            expr = f"-({a} * {b})"
        else:
            expr = f"{a} {op} {b}"
        signed = m in ("smull",)
        ctype = _ctype_from_bits(_bits(dst.name), signed=signed)
        vname = self._write(dst.name, NativeVal(ctype, expr, tainted=tainted))
        taint_ann = " /* TAINTED */" if tainted else ""
        return self._decl(ctype, vname, expr, taint_ann)

    def _emit_madd(self, insn: Insn, m: str) -> str:
        dst = insn.reg(0)
        a = self._expr(insn.reg(1).name) if insn.reg(1) else "???"
        b = self._expr(insn.reg(2).name) if insn.reg(2) else "???"
        c = self._expr(insn.reg(3).name) if insn.reg(3) else "???"
        tainted = self._propagate_taint(
            *[r.name for r in [insn.reg(1), insn.reg(2), insn.reg(3)] if r]
        )
        expr = f"{a} * {b} + {c}" if m == "madd" else f"{a} * {b} - {c}"
        ctype = _ctype_from_bits(_bits(dst.name))
        vname = self._write(dst.name, NativeVal(ctype, expr, tainted=tainted))
        return self._decl(ctype, vname, expr)

    def _emit_bitwise(self, insn: Insn, m: str) -> str:
        dst = insn.reg(0)
        a = self._expr(insn.reg(1).name) if insn.reg(1) else "???"
        b = self._operand_expr(insn, 2)
        tainted = self._propagate_taint(
            *[r.name for r in [insn.reg(1), insn.reg(2)] if r]
        )
        op_map = {
            "and": "&", "ands": "&", "orr": "|", "eor": "^",
            "bic": "& ~", "orn": "| ~", "eon": "^ ~",
        }
        op = op_map.get(m, "&")
        if op.endswith("~"):
            expr = f"{a} {op}({b})"
        else:
            expr = f"{a} {op} {b}"
        ctype = _ctype_from_bits(_bits(dst.name))
        vname = self._write(dst.name, NativeVal(ctype, expr, tainted=tainted))
        return self._decl(ctype, vname, expr)

    def _emit_shift(self, insn: Insn, m: str) -> str:
        dst = insn.reg(0)
        a = self._expr(insn.reg(1).name) if insn.reg(1) else "???"
        b = self._operand_expr(insn, 2)
        tainted = self._propagate_taint(
            *[r.name for r in [insn.reg(1), insn.reg(2)] if r]
        )
        op_map = {"lsl": "<<", "lsr": ">>", "asr": ">>", "ror": ">>/*ror*/"}
        op = op_map.get(m, "<<")
        signed = m == "asr"
        ctype = _ctype_from_bits(_bits(dst.name), signed=signed)
        expr = f"{a} {op} {b}"
        vname = self._write(dst.name, NativeVal(ctype, expr, tainted=tainted))
        return self._decl(ctype, vname, expr)

    def _emit_csel(self, insn: Insn, m: str) -> str:
        dst = insn.reg(0)
        true_expr = self._expr(insn.reg(1).name) if insn.reg(1) else "1"
        false_expr = self._expr(insn.reg(2).name) if insn.reg(2) else "0"
        # Condition code is in a Cond operand
        cond_code = "??"
        for op in insn.ops:
            if isinstance(op, Cond):
                cond_code = op.code
                break
        cond_str = self._cond_expr(cond_code)
        if m == "cset":
            expr = f"({cond_str}) ? 1 : 0"
        elif m == "csetm":
            expr = f"({cond_str}) ? -1 : 0"
        elif m == "csinc":
            expr = f"({cond_str}) ? {true_expr} : {false_expr} + 1"
        elif m == "csinv":
            expr = f"({cond_str}) ? {true_expr} : ~{false_expr}"
        elif m == "csneg":
            expr = f"({cond_str}) ? {true_expr} : -{false_expr}"
        else:  # csel
            expr = f"({cond_str}) ? {true_expr} : {false_expr}"
        tainted = self._propagate_taint(
            *[r.name for r in [insn.reg(1), insn.reg(2)] if r]
        )
        ctype = _ctype_from_bits(_bits(dst.name))
        vname = self._write(dst.name, NativeVal(ctype, expr, tainted=tainted))
        return self._decl(ctype, vname, expr)


__all__ = ["BinaryLifter", "NativeVal"]


# ── x86-64 support ─────────────────────────────────────────────────────────────

# Canonical 64-bit name for any x86_64 sub-register
_X86_CANON: Dict[str, str] = {}
for _n64, _aliases in [
    ("rax", ("eax", "ax", "al", "ah")),
    ("rbx", ("ebx", "bx", "bl", "bh")),
    ("rcx", ("ecx", "cx", "cl", "ch")),
    ("rdx", ("edx", "dx", "dl", "dh")),
    ("rsi", ("esi", "si", "sil")),
    ("rdi", ("edi", "di", "dil")),
    ("rbp", ("ebp", "bp", "bpl")),
    ("rsp", ("esp", "sp", "spl")),
    ("rip", ("eip",)),
]:
    _X86_CANON[_n64] = _n64
    for _a in _aliases:
        _X86_CANON[_a] = _n64
for _i in range(8, 16):
    _n = f"r{_i}"
    _X86_CANON[_n] = _n
    for _sfx in ("d", "w", "b"):
        _X86_CANON[f"{_n}{_sfx}"] = _n

# bit width from register name
_X86_BITS: Dict[str, int] = {}
for _n in ("rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip"):
    _X86_BITS[_n] = 64
for _n in ("eax","ebx","ecx","edx","esi","edi","ebp","esp","eip"):
    _X86_BITS[_n] = 32
for _n in ("ax","bx","cx","dx","si","di","bp","sp"):
    _X86_BITS[_n] = 16
for _n in ("al","bl","cl","dl","sil","dil","bpl","spl","ah","bh","ch","dh"):
    _X86_BITS[_n] = 8
for _i in range(8, 16):
    _X86_BITS[f"r{_i}"] = 64
    _X86_BITS[f"r{_i}d"] = 32
    _X86_BITS[f"r{_i}w"] = 16
    _X86_BITS[f"r{_i}b"] = 8

_X86_PARAM_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_X86_CALLEE_SAVED = frozenset({"rbx", "rbp", "r12", "r13", "r14", "r15"})

_X86_JCCS = frozenset({
    "je","jz","jne","jnz","jg","jge","jl","jle",
    "ja","jae","jb","jbe","js","jns","jo","jno","jp","jnp",
})
_X86_JCC_OPS: Dict[str, str] = {
    "je": "==", "jz": "==",
    "jne": "!=", "jnz": "!=",
    "jg": ">", "jge": ">=",
    "jl": "<", "jle": "<=",
    "ja": ">u", "jae": ">=u",
    "jb": "<u", "jbe": "<=u",
    "js": "< 0", "jns": ">= 0",
}


def _x86_canon(name: str) -> str:
    return _X86_CANON.get(name.lower(), name.lower())


def _x86_bits(name: str) -> int:
    return _X86_BITS.get(name.lower(), 64)


def _x86_ctype(name: str, signed: bool = False) -> str:
    return _ctype_from_bits(_x86_bits(name), signed)


class _X86_64State:
    """Per-function register state for x86-64 lifting."""

    def __init__(
        self,
        tainted_params: Set[str],
        name_fn,
        plt: Dict[int, str],
    ):
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._cmp_expr: str = ""          # last cmp/test left operand
        self._cmp_rhs: str = ""
        self._var_counter = 0
        self._name_fn = name_fn
        self._plt = plt

        # Seed parameter registers
        for i, reg in enumerate(_X86_PARAM_REGS):
            vname = f"arg{i}"
            tainted = reg in tainted_params
            nv = NativeVal("uint64_t", vname, is_ptr=False, tainted=tainted)
            self._regs[reg] = nv
            self._written.add(reg)
            self._declared.add(vname)

        # Seed callee-saved registers
        for reg in _X86_CALLEE_SAVED:
            self._regs[reg] = NativeVal("uint64_t", reg)
            self._written.add(reg)

        # rbp and rsp
        self._regs["rbp"] = NativeVal("uint64_t", "fp", is_ptr=True)
        self._regs["rsp"] = NativeVal("uint64_t", "sp", is_ptr=True)
        for r in ("rbp", "rsp"):
            self._written.add(r)

    def _alloc(self) -> str:
        self._var_counter += 1
        return f"v{self._var_counter}"

    def _read(self, reg: str) -> NativeVal:
        c = _x86_canon(reg)
        if c not in self._written:
            # First read of an un-seeded register: allocate
            vname = self._alloc()
            nv = NativeVal(_x86_ctype(reg), vname)
            self._regs[c] = nv
            self._written.add(c)
        return self._regs.get(c, NativeVal("uint64_t", c))

    def _write(self, reg: str, nv: NativeVal) -> None:
        c = _x86_canon(reg)
        self._regs[c] = nv
        self._written.add(c)

    def _decl(self, ctype: str, vname: str, expr: str, ann: str = "") -> str:
        if vname in self._declared:
            return f"{vname} = {expr};{ann}"
        self._declared.add(vname)
        return f"{ctype} {vname} = {expr};{ann}"

    def _taint_ann(self, nv: NativeVal) -> str:
        return "  /* TAINTED */" if nv.tainted else ""

    def _mem_expr(self, insn, op) -> str:
        """Format a memory operand as a C pointer expression."""
        import capstone.x86_const as x86c
        m = op.mem
        base_name = insn.reg_name(m.base) if m.base else ""
        idx_name  = insn.reg_name(m.index) if m.index else ""
        base_expr = self._read(_x86_canon(base_name)).expr if base_name else ""
        idx_expr  = self._read(_x86_canon(idx_name)).expr  if idx_name  else ""

        parts = []
        if base_expr and base_expr not in ("0", ""):
            parts.append(base_expr)
        if idx_expr and idx_expr not in ("0", ""):
            scale = m.scale if m.scale > 1 else 1
            parts.append(f"{idx_expr}*{scale}" if scale > 1 else idx_expr)
        if m.disp:
            parts.append(_imm_expr(m.disp))

        if not parts:
            return "0"
        addr = " + ".join(parts)
        if len(parts) > 1:
            addr = f"({addr})"
        return addr

    def lift_insn(self, insn) -> Optional[str]:
        """Lift one Capstone x86_64 instruction to a C statement string, or None."""
        import capstone
        import capstone.x86_const as x86c

        mn = insn.mnemonic.lower()
        ops = insn.operands

        # ── MOV ──────────────────────────────────────────────────────────────
        if mn in ("mov", "movabs"):
            if len(ops) < 2:
                return None
            dst, src = ops[0], ops[1]
            src_expr, src_taint = self._operand_read(insn, src)
            if dst.type == x86c.X86_OP_REG:
                dn = insn.reg_name(dst.reg)
                vname = self._alloc()
                ctype = _x86_ctype(dn)
                nv = NativeVal(ctype, vname, tainted=src_taint)
                self._write(dn, nv)
                return self._decl(ctype, vname, src_expr, self._taint_ann(nv))
            elif dst.type == x86c.X86_OP_MEM:
                addr = self._mem_expr(insn, dst)
                ctype = _x86_ctype("rax") if dst.size == 8 else _ctype_from_bits(dst.size * 8)
                return f"*({ctype}*)({addr}) = {src_expr};"
            return None

        # ── MOVZX / MOVSX ─────────────────────────────────────────────────
        if mn in ("movzx", "movsx", "movsxd"):
            if len(ops) < 2:
                return None
            dst, src = ops[0], ops[1]
            src_expr, src_taint = self._operand_read(insn, src)
            dn = insn.reg_name(dst.reg)
            vname = self._alloc()
            cast = "int64_t" if mn in ("movsx", "movsxd") else "uint64_t"
            nv = NativeVal(_x86_ctype(dn), vname, tainted=src_taint)
            self._write(dn, nv)
            return self._decl(_x86_ctype(dn), vname,
                               f"({cast})({src_expr})", self._taint_ann(nv))

        # ── LEA ──────────────────────────────────────────────────────────────
        if mn == "lea":
            if len(ops) < 2:
                return None
            dst, src = ops[0], ops[1]
            addr = self._mem_expr(insn, src)
            dn = insn.reg_name(dst.reg)
            vname = self._alloc()
            nv = NativeVal("void *", vname, is_ptr=True)
            self._write(dn, nv)
            return self._decl("void *", vname, f"(void *)({addr})")

        # ── Loads ─────────────────────────────────────────────────────────────
        if mn in ("movq",):
            mn = "mov"  # treat movq as mov

        # ── PUSH / POP ────────────────────────────────────────────────────────
        if mn == "push":
            if ops and ops[0].type == x86c.X86_OP_REG:
                return f"// push {insn.reg_name(ops[0].reg)}"
            return None
        if mn == "pop":
            if ops and ops[0].type == x86c.X86_OP_REG:
                dn = insn.reg_name(ops[0].reg)
                vname = self._alloc()
                nv = NativeVal("uint64_t", vname)
                self._write(dn, nv)
                return self._decl("uint64_t", vname, "stack_pop()")
            return None

        # ── Arithmetic: ADD / SUB / AND / OR / XOR / IMUL / SHL / SHR / SAR ──
        if mn in ("add", "sub", "and", "or", "xor", "imul",
                  "shl", "sal", "shr", "sar", "ror", "rol"):
            if len(ops) < 2:
                return None
            dst = ops[0]
            if dst.type != x86c.X86_OP_REG:
                return None
            dn = insn.reg_name(dst.reg)
            lv = self._read(_x86_canon(dn))
            rhs_expr, rhs_taint = self._operand_read(insn, ops[1])
            op_sym = {
                "add": "+", "sub": "-", "and": "&", "or": "|",
                "xor": "^", "shl": "<<", "sal": "<<",
                "shr": ">>", "sar": ">>", "ror": "ror", "rol": "rol",
                "imul": "*",
            }.get(mn, mn)
            # xor reg, reg → zero
            if mn == "xor" and ops[0].reg == ops[1].reg:
                vname = self._alloc()
                nv = NativeVal(_x86_ctype(dn), vname)
                self._write(dn, nv)
                return self._decl(_x86_ctype(dn), vname, "0")
            vname = self._alloc()
            tainted = lv.tainted or rhs_taint
            ctype = _x86_ctype(dn)
            nv = NativeVal(ctype, vname, tainted=tainted)
            self._write(dn, nv)
            ann = self._taint_ann(nv)
            expr = f"{lv.expr} {op_sym} {rhs_expr}"
            return self._decl(ctype, vname, expr, ann)

        # ── INC / DEC / NEG / NOT ─────────────────────────────────────────────
        if mn in ("inc", "dec", "neg", "not"):
            if not ops or ops[0].type != x86c.X86_OP_REG:
                return None
            dn = insn.reg_name(ops[0].reg)
            lv = self._read(_x86_canon(dn))
            vname = self._alloc()
            delta = "+1" if mn == "inc" else ("-1" if mn == "dec" else "")
            if mn == "neg":
                expr = f"-{lv.expr}"
            elif mn == "not":
                expr = f"~{lv.expr}"
            else:
                expr = f"{lv.expr} {delta}"
            nv = NativeVal(lv.ctype, vname, tainted=lv.tainted)
            self._write(dn, nv)
            return self._decl(lv.ctype, vname, expr)

        # ── CMP / TEST ────────────────────────────────────────────────────────
        if mn in ("cmp", "test"):
            if len(ops) < 2:
                return None
            lhs_expr, _ = self._operand_read(insn, ops[0])
            rhs_expr, _ = self._operand_read(insn, ops[1])
            self._cmp_expr = lhs_expr
            self._cmp_rhs  = rhs_expr
            if mn == "test":
                self._cmp_expr = f"({lhs_expr} & {rhs_expr})"
                self._cmp_rhs  = "0"
            return None  # emitted at branch

        # ── Conditional jumps ─────────────────────────────────────────────────
        if mn in _X86_JCCS:
            target = ops[0].imm if ops and ops[0].type == x86c.X86_OP_IMM else 0
            cond_op = _X86_JCC_OPS.get(mn, "?")
            lhs = self._cmp_expr or "cond"
            rhs = self._cmp_rhs  or "0"
            return f"if ({lhs} {cond_op} {rhs}) goto {hex(target)};"

        # ── Unconditional JMP ─────────────────────────────────────────────────
        if mn == "jmp":
            if ops and ops[0].type == x86c.X86_OP_IMM:
                return f"goto {hex(ops[0].imm)};"
            if ops and ops[0].type == x86c.X86_OP_REG:
                return f"goto *{self._read(_x86_canon(insn.reg_name(ops[0].reg))).expr};"
            return "goto *<indirect>;"

        # ── CALL ──────────────────────────────────────────────────────────────
        if mn == "call":
            if not ops:
                return "rax = <indirect_call>();"
            if ops[0].type == x86c.X86_OP_IMM:
                target_va = ops[0].imm
                fname = self._plt.get(target_va) or self._name_fn(target_va)
            elif ops[0].type == x86c.X86_OP_REG:
                fname = self._read(_x86_canon(insn.reg_name(ops[0].reg))).expr
            else:
                fname = "<indirect>"
            args = [self._read(r).expr for r in _X86_PARAM_REGS]
            arg_str = ", ".join(args[:6])
            vname = self._alloc()
            nv = NativeVal("uint64_t", vname)
            self._write("rax", nv)
            # Clobber caller-saved regs after call
            for r in ("rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"):
                self._write(r, NativeVal("uint64_t", f"<clobber>"))
            return self._decl("uint64_t", vname, f"{fname}({arg_str})")

        # ── RET ───────────────────────────────────────────────────────────────
        if mn in ("ret", "retn", "retq"):
            rv = self._read("rax")
            return f"return {rv.expr};"

        # ── NOP / ENDBR / PREFETCH ────────────────────────────────────────────
        if mn in ("nop", "endbr64", "endbr32", "prefetchnta", "prefetcht0",
                  "prefetcht1", "prefetcht2", "lfence", "mfence", "sfence"):
            return None

        # ── Unhandled ─────────────────────────────────────────────────────────
        ops_str = insn.op_str
        return f"// {mn} {ops_str}"

    def _operand_read(self, insn, op) -> tuple:
        """Return (expr_str, is_tainted) for a source operand."""
        import capstone.x86_const as x86c
        if op.type == x86c.X86_OP_IMM:
            return (_imm_expr(op.imm), False)
        if op.type == x86c.X86_OP_REG:
            reg_name = insn.reg_name(op.reg)
            nv = self._read(_x86_canon(reg_name))
            return (nv.expr, nv.tainted)
        if op.type == x86c.X86_OP_MEM:
            addr = self._mem_expr(insn, op)
            size_bits = op.size * 8 if op.size else 64
            ctype = _ctype_from_bits(size_bits)
            return (f"*({ctype}*)({addr})", False)
        return ("???", False)
