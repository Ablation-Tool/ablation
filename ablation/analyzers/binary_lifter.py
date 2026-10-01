"""
binary_lifter.py — Lift native binary functions to annotated C pseudocode.

Active Architecture Tomography Phase 1: static CFG-based IR emission for
ARM64. DEXLifter (dex_lifter.py) is the structural template.

Architecture support:
    arm64    — full; CFG + register state machine + calling convention
    x86_64   — stub; planned Phase 1 extension
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
    """Return sorted list of (vaddr, size, file_offset) for each loadable section."""
    try:
        import lief  # type: ignore
        elf = lief.parse(binary_path)
        secs = []
        for s in elf.sections:
            va, sz, off = int(s.virtual_address), int(s.size), int(s.offset)
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
        if self.arch in ("x86_64", "x86-64", "amd64"):
            return f"// x86-64 lifter not yet implemented — use BinaryLifter.arch='arm64'\n"
        if self.arch in ("la64", "loongarch64", "loongarch_64"):
            return f"// LoongArch64 lifter not yet implemented — use BinaryLifter.arch='arm64'\n"
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
