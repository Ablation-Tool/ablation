"""
binary_lifter.py — Lift native binary functions to annotated C pseudocode.

Architecture Tomography: static CFG-based IR emission across 18 ISA variants.
ARM64 and x86-64 are full (register-tracking state machines); all others emit
structural pseudocode (call/return/branch resolved, arithmetic as comments).

Architecture support:
    arm64       — full; CFG + register state machine + calling convention
    x86_64      — full; linear disasm + _X86_64State register tracking; PE + ELF
    x86_32      — structural; Capstone CS_MODE_32; CDECL (stack args, eax return)
    arm32       — structural; insn_arm32 + cfg_arm32; AAPCS r0-r3
    thumb/thumb2— structural; insn_arm32 Thumb mode
    mips32      — structural; insn_mips + cfg_mips; o32 ($a0-$a3)
    mips64      — structural; insn_mips + cfg_mips; n64 ($a0-$a7)
    nanomips    — structural; NanoMIPSDecoder linear walk; o32 ABI
    ppc32       — structural; insn_ppc + cfg_ppc; SysV32 (r3-r10)
    ppc64       — structural; insn_ppc + cfg_ppc; ELFv2 (r3-r10)
    rv32/rv64   — structural; insn_riscv + cfg_riscv; psABI (a0-a7)
    arc/arcem   — structural; requires arc-elf32-objdump in PATH
    v850/rh850  — structural; requires v850-elf-objdump in PATH
    la64        — structural; LoongArchDecoder + cfg_loongarch64; lp64 ($a0-$a7)
    sh2a/sh2    — structural; EcuSH2aDecoder linear walk; Renesas SuperH ABI (R4-R7 args)
    beam        — module summary; BeamContext (no VA space in BEAM bytecode)

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
        if self.arch in ("sh2a", "sh-2a", "sh2"):
            return self._lift_sh2a(va, max_insns)
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

    # ── Shared CFG walker for ablation-native ISA backends ────────────────────

    def _walk_ablation_cfg(self, cfg, func_va: int, emit_fn) -> str:
        """BFS over an ablation CFG; emit_fn(insn) -> str for each instruction."""
        fname = self._func_name(func_va)
        lines: List[str] = [f"// {fname} @ {func_va:#x}", "{"]
        visited: Set[int] = set()
        queue: List[int] = [func_va]
        while queue:
            bva = queue.pop(0)
            if bva in visited or bva not in cfg.blocks:
                continue
            visited.add(bva)
            block = cfg.blocks[bva]
            if bva != func_va:
                lines.append(f"  loc_{bva:x}:")
            for insn in block.insns:
                try:
                    stmt = emit_fn(insn)
                except Exception:
                    ops_str = ", ".join(str(o) for o in getattr(insn, "ops", []))
                    stmt = f"// {insn.mnemonic} {ops_str}"
                if stmt:
                    for s in stmt.splitlines():
                        lines.append("  " + s)
            for succ in block.succs:
                if succ not in visited:
                    queue.append(succ)
        lines.append("}")
        return "\n".join(lines) + "\n"

    # ── x86-32 lifter ─────────────────────────────────────────────────────────

    def _lift_x86_32(self, func_va: int, max_insns: int) -> str:
        import capstone

        try:
            code = self._read_va(func_va, max_insns * 7)
        except ValueError as e:
            return f"// {e}\n"

        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        cs.detail = True
        insns = list(cs.disasm(code, func_va))[:max_insns]
        if not insns:
            return f"// no instructions decoded at {func_va:#x}\n"

        fname = self._func_name(func_va)
        state = _X86_32State(self._func_name, self._plt)
        lines: List[str] = [f"// {fname} @ {func_va:#x}", "{"]

        branch_targets: Set[int] = set()
        for insn in insns:
            mn = insn.mnemonic.lower()
            if mn in _X86_JCCS or mn == "jmp":
                if insn.operands and insn.operands[0].type == 2:
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

    # ── ARM32 lifter ──────────────────────────────────────────────────────────

    def _lift_arm32(self, func_va: int, max_insns: int, thumb: bool = False) -> str:
        from .insn_arm32 import from_capstone as _arm32_cs, Mode as _ARM32Mode
        from .cfg_arm32 import build_cfg as _arm32_cfg

        mode = _ARM32Mode.THUMB if thumb else _ARM32Mode.ARM
        insn_sz = 2 if thumb else 4
        try:
            code = self._read_va(func_va, max_insns * insn_sz)
        except ValueError as e:
            return f"// {e}\n"
        try:
            raw_insns = list(_arm32_cs(code, mode=mode, base=func_va))[:max_insns]
        except Exception as e:
            return f"// ARM32 decode failed: {e}\n"
        if not raw_insns:
            return f"// no instructions decoded at {func_va:#x}\n"
        try:
            cfg = _arm32_cfg(raw_insns, entry=func_va)
        except Exception as e:
            return f"// CFG build failed: {e}\n"
        tainted_params = self._taint_map.get(func_va, set())
        state = _ARM32State(tainted_params, self._func_name, self._plt)
        return self._walk_ablation_cfg(cfg, func_va, state.emit)

    # ── MIPS lifter ───────────────────────────────────────────────────────────

    def _lift_mips(self, func_va: int, max_insns: int, bits: int, little: bool) -> str:
        from .insn_mips import from_capstone as _mips_cs, Mode as _MIPSMode
        from .cfg_mips import build_cfg as _mips_cfg

        mode = _MIPSMode.MIPS32 if bits == 32 else _MIPSMode.MIPS64
        try:
            code = self._read_va(func_va, max_insns * 4)
        except ValueError as e:
            return f"// {e}\n"
        try:
            raw_insns = list(_mips_cs(code, mode=mode, base=func_va, little=little))[:max_insns]
        except Exception as e:
            return f"// MIPS decode failed: {e}\n"
        if not raw_insns:
            return f"// no instructions decoded at {func_va:#x}\n"
        try:
            cfg = _mips_cfg(raw_insns, entry=func_va)
        except Exception as e:
            return f"// CFG build failed: {e}\n"
        tainted_params = self._taint_map.get(func_va, set())
        state = _MIPSState(bits, tainted_params, self._func_name, self._plt)
        return self._walk_ablation_cfg(cfg, func_va, state.emit)

    # ── PPC lifter ────────────────────────────────────────────────────────────

    def _lift_ppc(self, func_va: int, max_insns: int, bits: int) -> str:
        from .insn_ppc import from_capstone as _ppc_cs, Mode as _PPCMode
        from .cfg_ppc import build_cfg as _ppc_cfg

        mode = _PPCMode.PPC32 if bits == 32 else _PPCMode.PPC64
        try:
            code = self._read_va(func_va, max_insns * 4)
        except ValueError as e:
            return f"// {e}\n"
        try:
            raw_insns = list(_ppc_cs(code, mode=mode, base=func_va, little=False))[:max_insns]
        except Exception as e:
            return f"// PPC decode failed: {e}\n"
        if not raw_insns:
            return f"// no instructions decoded at {func_va:#x}\n"
        try:
            cfg = _ppc_cfg(raw_insns, entry=func_va)
        except Exception as e:
            return f"// CFG build failed: {e}\n"
        tainted_params = self._taint_map.get(func_va, set())
        state = _PPCState(bits, tainted_params, self._func_name, self._plt)
        return self._walk_ablation_cfg(cfg, func_va, state.emit)

    # ── RISC-V lifter ─────────────────────────────────────────────────────────

    def _lift_riscv(self, func_va: int, max_insns: int, bits: int) -> str:
        from .insn_riscv import from_capstone as _rv_cs
        from .cfg_riscv import build_cfg as _rv_cfg
        from .isa_riscv import Width, isa_for

        width = Width.RV32 if bits == 32 else Width.RV64
        isa = isa_for(width)
        try:
            code = self._read_va(func_va, max_insns * 4)
        except ValueError as e:
            return f"// {e}\n"
        try:
            raw_insns = list(_rv_cs(code, base=func_va, width_bits=bits))[:max_insns]
        except Exception as e:
            return f"// RISC-V decode failed: {e}\n"
        if not raw_insns:
            return f"// no instructions decoded at {func_va:#x}\n"
        try:
            cfg = _rv_cfg(raw_insns, isa, entry=func_va)
        except Exception as e:
            return f"// CFG build failed: {e}\n"
        tainted_params = self._taint_map.get(func_va, set())
        state = _RISCVState(bits, tainted_params, self._func_name, self._plt)
        return self._walk_ablation_cfg(cfg, func_va, state.emit)

    # ── LoongArch64 lifter (replaces stub) ────────────────────────────────────

    def _lift_loongarch64(self, func_va: int, max_insns: int) -> str:
        try:
            from .loongarch_decoder import LoongArchDecoder
            from .insn_loongarch64 import from_loongarch_frames as _la64_from_frames
            from .cfg_loongarch64 import build_cfg as _la64_cfg
        except ImportError as e:
            return f"// LoongArch64 decoder not available: {e}\n"

        try:
            code = self._read_va(func_va, max_insns * 4)
        except ValueError as e:
            return f"// {e}\n"

        try:
            decoder = LoongArchDecoder()
            frames = list(decoder.decode_frames(code, func_va))[:max_insns]
            raw_insns = list(_la64_from_frames(frames))
        except Exception as e:
            return f"// LA64 decode failed: {e}\n"

        if not raw_insns:
            return f"// no instructions decoded at {func_va:#x}\n"
        try:
            cfg = _la64_cfg(raw_insns, entry=func_va)
        except Exception as e:
            return f"// CFG build failed: {e}\n"
        tainted_params = self._taint_map.get(func_va, set())
        state = _LA64State(tainted_params, self._func_name, self._plt)
        return self._walk_ablation_cfg(cfg, func_va, state.emit)

    # ── nanoMIPS lifter ───────────────────────────────────────────────────────

    def _lift_nanomips(self, func_va: int, max_insns: int) -> str:
        try:
            from .nanomips_decoder import NanoMIPSDecoder
        except ImportError as e:
            return f"// nanoMIPS decoder not available: {e}\n"

        try:
            code = self._read_va(func_va, max_insns * 4)
        except ValueError as e:
            return f"// {e}\n"

        try:
            decoder = NanoMIPSDecoder()
            frames = decoder.decode_frames(code, func_va)[:max_insns]
        except Exception as e:
            return f"// nanoMIPS decode failed: {e}\n"

        if not frames:
            return f"// no instructions decoded at {func_va:#x}\n"

        tainted_params = self._taint_map.get(func_va, set())
        state = _NanoMIPSState(tainted_params, self._func_name, self._plt)
        fname = self._func_name(func_va)
        lines: List[str] = [f"// {fname} @ {func_va:#x}", "{"]
        for frame in frames:
            try:
                stmt = state.emit(frame)
            except Exception:
                stmt = f"// {frame.mnemonic} {frame.op_str}"
            if stmt:
                for s in stmt.splitlines():
                    lines.append("  " + s)
        lines.append("}")
        return "\n".join(lines) + "\n"

    # ── SH-2A lifter ──────────────────────────────────────────────────────────

    def _lift_sh2a(self, func_va: int, max_insns: int) -> str:
        try:
            from .ecu_sh2a_decoder import EcuSH2aDecoder
            from .cfg_sh2a import build_cfg as _sh2a_cfg
            from .structurizer import Structurizer as _Structurizer
        except ImportError as e:
            return f"// SH-2A decoder not available: {e}\n"

        # Flat ECU ROMs have no ELF section map: VA == file offset (base_va=0)
        if self._sections:
            try:
                code = self._read_va(func_va, max_insns * 4)
            except ValueError as e:
                return f"// {e}\n"
        else:
            off = func_va
            code = self.data[off: off + max_insns * 4]

        if not code:
            return f"// no bytes at {func_va:#x}\n"

        try:
            decoder = EcuSH2aDecoder(code, base_va=func_va)
            insns = decoder.disassemble(0, len(code))[:max_insns]
        except Exception as e:
            return f"// SH-2A decode failed: {e}\n"

        if not insns:
            return f"// no instructions decoded at {func_va:#x}\n"

        try:
            cfg = _sh2a_cfg(insns, entry=func_va)
        except Exception as e:
            return f"// SH-2A CFG build failed: {e}\n"

        tainted_params = self._taint_map.get(func_va, set())
        state = _SH2aState(tainted_params, self._func_name, self._plt)
        fname = self._func_name(func_va)

        def _safe_emit(insn):
            try:
                return state.emit(insn)
            except Exception:
                return f"// {insn.mnemonic}"

        # NOTE: _SH2aState is stateful (register/taint tracking). The structurizer
        # calls _safe_emit in RPO/structured order, not original linear order. For
        # functions with non-trivial cross-branch register state, taint propagation
        # may reflect incorrect register values. This is a known limitation; a future
        # SH2aCondTracker pass should snapshot register state per branch arm.
        try:
            structurizer = _Structurizer(cfg)
            return structurizer.emit(_safe_emit, func_name=fname) + "\n"
        except Exception as e:
            import warnings
            warnings.warn(
                f"SH-2A structurizer fallback at {func_va:#x}: {e}",
                stacklevel=2,
            )
            # Fall back to linear-walk emit on structurizer failure.
            lines: List[str] = [
                f"// {fname} @ {func_va:#x}  (linear fallback: {e})", "{"
            ]
            for block in sorted(cfg.blocks.values(), key=lambda b: b.start):
                for insn in block.insns:
                    stmt = _safe_emit(insn)
                    if stmt:
                        for s in stmt.splitlines():
                            lines.append("  " + s)
            lines.append("}")
            return "\n".join(lines) + "\n"

    # ── ARC lifter ────────────────────────────────────────────────────────────

    def _lift_arc(self, func_va: int, max_insns: int) -> str:
        import subprocess
        import shutil

        objdump = shutil.which("arc-elf32-objdump") or shutil.which("arc-linux-objdump") or shutil.which("arc-elf-objdump")
        if objdump is None:
            return (
                f"// ARC lifter: no arc-elf32-objdump in PATH.\n"
                f"// Install binutils-arc-linux-gnu or set PATH to include the ARC toolchain.\n"
                f"// Partial: static disassembly requires an objdump capable of ARC.\n"
            )

        from .insn_arc import from_objdump as _arc_objdump
        from .cfg_arc import build_cfg as _arc_cfg

        try:
            result = subprocess.run(
                [objdump, "-d", "--start-address", hex(func_va),
                 "--stop-address", hex(func_va + max_insns * 8),
                 self.path],
                capture_output=True, text=True, timeout=15,
            )
            text = result.stdout
        except Exception as e:
            return f"// objdump failed: {e}\n"

        try:
            raw_insns = list(_arc_objdump(text))[:max_insns]
        except Exception as e:
            return f"// ARC objdump parse failed: {e}\n"

        if not raw_insns:
            return f"// no instructions decoded at {func_va:#x} (check that VA is within the binary)\n"

        try:
            cfg = _arc_cfg(raw_insns, entry=func_va)
        except Exception as e:
            return f"// CFG build failed: {e}\n"

        tainted_params = self._taint_map.get(func_va, set())
        state = _ARCState(tainted_params, self._func_name, self._plt)
        return self._walk_ablation_cfg(cfg, func_va, state.emit)

    # ── V850 lifter ───────────────────────────────────────────────────────────

    def _lift_v850(self, func_va: int, max_insns: int) -> str:
        import subprocess
        import shutil

        objdump = (
            shutil.which("v850-elf-objdump") or
            shutil.which("v850-unknown-elf-objdump") or
            shutil.which("v850-linux-gnu-objdump")
        )
        if objdump is None:
            return (
                f"// V850 lifter: no v850-elf-objdump in PATH.\n"
                f"// Install binutils-v850-elf or set PATH to include the V850 toolchain.\n"
            )

        from .insn_v850 import from_objdump as _v850_objdump
        from .cfg_v850 import build_cfg as _v850_cfg

        try:
            result = subprocess.run(
                [objdump, "-d", "--start-address", hex(func_va),
                 "--stop-address", hex(func_va + max_insns * 6),
                 self.path],
                capture_output=True, text=True, timeout=15,
            )
            text = result.stdout
        except Exception as e:
            return f"// objdump failed: {e}\n"

        try:
            raw_insns = list(_v850_objdump(text))[:max_insns]
        except Exception as e:
            return f"// V850 objdump parse failed: {e}\n"

        if not raw_insns:
            return f"// no instructions decoded at {func_va:#x} (check that VA is within the binary)\n"

        try:
            cfg = _v850_cfg(raw_insns, entry=func_va)
        except Exception as e:
            return f"// CFG build failed: {e}\n"

        tainted_params = self._taint_map.get(func_va, set())
        state = _V850State(tainted_params, self._func_name, self._plt)
        return self._walk_ablation_cfg(cfg, func_va, state.emit)

    # ── BEAM lifter ───────────────────────────────────────────────────────────

    def _lift_beam(self, func_va: int, max_insns: int) -> str:
        """Lift BEAM bytecode to pseudo-IR.

        BEAM is a register VM — there is no linear VA space.  The lifter
        decodes the Code chunk and emits function-level IR for every exported
        and local function in the module.  Pass va=0 (the default) to get the
        full module IR; any other va value is currently ignored.

        Falls back to a module-level summary if the Code chunk cannot be
        decoded (e.g. heavily obfuscated or very old OTP format).
        """
        try:
            from pathlib import Path as _Path
            from .beam_context import BeamContext, BEAMLifter, _split_chunks
        except ImportError as e:
            return f"// BEAM context not available: {e}\n"

        try:
            ctx = BeamContext.from_path(self.path)
        except Exception as e:
            return f"// BEAM parse failed: {e}\n"

        # Attempt function-level IR via BEAMLifter
        try:
            raw        = _Path(self.path).read_bytes()
            chunks     = _split_chunks(raw)
            code_bytes = chunks.get('Code', b'')
            if code_bytes:
                lifter = BEAMLifter.from_context(ctx, code_bytes)
                return lifter.lift()
        except Exception:
            pass

        # Module-summary fallback
        lines: List[str] = [
            f"% BEAM module: {ctx.module_name}  (Code chunk decode failed)",
            f"% OTP: {ctx.is_otp}",
            "{",
        ]
        if ctx.exports:
            lines.append("  % exports:")
            for ex in ctx.exports:
                lines.append(f"  %   {ex}")
        dangerous = ctx.dangerous_imports()
        if dangerous:
            lines.append("  % dangerous imports:")
            for imp in dangerous:
                lines.append(f"  %   {imp}  /* TAINTED */")
        if ctx.atoms:
            sample = ctx.atoms[:16]
            lines.append(f"  % atoms (first {len(sample)} of {len(ctx.atoms)}):")
            for atom in sample:
                lines.append(f"  %   {atom!r}")
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


# ── x86-32 state (CDECL: stack args, return in eax) ──────────────────────────

class _X86_32State:
    """Per-function register state for x86-32 CDECL lifting.

    CDECL passes all arguments on the stack, so we seed no param registers.
    Return value lives in EAX.
    """

    # x86-32 canonical register map: sub-register -> 32-bit root
    _CANON32: Dict[str, str] = {}
    for _root32, _aliases32 in [
        ("eax", ("ax", "al", "ah")),
        ("ebx", ("bx", "bl", "bh")),
        ("ecx", ("cx", "cl", "ch")),
        ("edx", ("dx", "dl", "dh")),
        ("esi", ("si",)), ("edi", ("di",)),
        ("ebp", ("bp",)), ("esp", ("sp",)),
    ]:
        _CANON32[_root32] = _root32
        for _a32 in _aliases32:
            _CANON32[_a32] = _root32

    _BITS32: Dict[str, int] = {}
    for _r32 in ("eax","ebx","ecx","edx","esi","edi","ebp","esp","eip"):
        _BITS32[_r32] = 32
    for _r16 in ("ax","bx","cx","dx","si","di","bp","sp"):
        _BITS32[_r16] = 16
    for _r8 in ("al","bl","cl","dl","ah","bh","ch","dh","sil","dil","bpl","spl"):
        _BITS32[_r8] = 8

    def __init__(self, name_fn, plt: Dict[int, str]):
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._cmp_expr = ""
        self._cmp_rhs = ""
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt
        # Seed frame / stack pointers
        for r, expr in (("ebp", "fp"), ("esp", "sp")):
            self._regs[r] = NativeVal("uint32_t", expr, is_ptr=True)
            self._written.add(r)
            self._declared.add(expr)

    def _canon(self, reg: str) -> str:
        return self._CANON32.get(reg.lower(), reg.lower())

    def _bits(self, reg: str) -> int:
        return self._BITS32.get(reg.lower(), 32)

    def _alloc(self) -> str:
        n = f"v{self._var_n}"
        self._var_n += 1
        return n

    def _read(self, reg: str) -> NativeVal:
        c = self._canon(reg)
        if c not in self._written:
            nv = NativeVal(_ctype_from_bits(self._bits(reg)), c)
            self._regs[c] = nv
            self._written.add(c)
        return self._regs.get(c, NativeVal("uint32_t", reg))

    def _write(self, reg: str, nv: NativeVal) -> None:
        c = self._canon(reg)
        self._regs[c] = nv
        self._written.add(c)

    def _decl(self, ctype: str, vname: str, expr: str, ann: str = "") -> str:
        if vname in self._declared:
            return f"{vname} = {expr};{ann}"
        self._declared.add(vname)
        return f"{ctype} {vname} = {expr};{ann}"

    def _mem_expr(self, insn, op) -> str:
        import capstone.x86_const as x86c
        m = op.mem
        base_name = insn.reg_name(m.base) if m.base else ""
        idx_name  = insn.reg_name(m.index) if m.index else ""
        base_expr = self._read(self._canon(base_name)).expr if base_name else ""
        idx_expr  = self._read(self._canon(idx_name)).expr  if idx_name  else ""
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
        return f"({addr})" if len(parts) > 1 else addr

    def lift_insn(self, insn) -> Optional[str]:
        import capstone.x86_const as x86c

        mn = insn.mnemonic.lower()
        ops = insn.operands

        if mn in ("mov", "movabs"):
            if len(ops) < 2:
                return None
            dst, src = ops[0], ops[1]
            src_expr, _ = self._operand_read(insn, src)
            if dst.type == x86c.X86_OP_REG:
                dn = insn.reg_name(dst.reg)
                vname = self._alloc()
                ctype = _ctype_from_bits(self._bits(dn))
                nv = NativeVal(ctype, vname)
                self._write(dn, nv)
                return self._decl(ctype, vname, src_expr)
            elif dst.type == x86c.X86_OP_MEM:
                addr = self._mem_expr(insn, dst)
                ctype = _ctype_from_bits(dst.size * 8 if dst.size else 32)
                return f"*({ctype}*)({addr}) = {src_expr};"
            return None

        if mn in ("movzx", "movsx"):
            if len(ops) < 2:
                return None
            dst, src = ops[0], ops[1]
            src_expr, _ = self._operand_read(insn, src)
            dn = insn.reg_name(dst.reg)
            vname = self._alloc()
            cast = "int32_t" if mn == "movsx" else "uint32_t"
            nv = NativeVal(_ctype_from_bits(self._bits(dn)), vname)
            self._write(dn, nv)
            return self._decl(_ctype_from_bits(self._bits(dn)), vname, f"({cast})({src_expr})")

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

        if mn in ("add", "sub", "and", "or", "xor", "imul", "shl", "sal", "shr", "sar"):
            if not ops or ops[0].type != x86c.X86_OP_REG:
                return None
            dn = insn.reg_name(ops[0].reg)
            lv = self._read(self._canon(dn))
            if len(ops) < 2:
                return None
            rhs_expr, _ = self._operand_read(insn, ops[1])
            op_sym = {"add":"+","sub":"-","and":"&","or":"|","xor":"^",
                      "shl":"<<","sal":"<<","shr":">>","sar":">>","imul":"*"}.get(mn, mn)
            if mn == "xor" and ops[0].reg == ops[1].reg:
                vname = self._alloc()
                nv = NativeVal(_ctype_from_bits(self._bits(dn)), vname)
                self._write(dn, nv)
                return self._decl(_ctype_from_bits(self._bits(dn)), vname, "0")
            vname = self._alloc()
            ctype = _ctype_from_bits(self._bits(dn))
            nv = NativeVal(ctype, vname)
            self._write(dn, nv)
            return self._decl(ctype, vname, f"{lv.expr} {op_sym} {rhs_expr}")

        if mn in ("inc", "dec", "neg", "not"):
            if not ops or ops[0].type != x86c.X86_OP_REG:
                return None
            dn = insn.reg_name(ops[0].reg)
            lv = self._read(self._canon(dn))
            vname = self._alloc()
            expr = f"{lv.expr}+1" if mn=="inc" else (f"{lv.expr}-1" if mn=="dec" else
                   f"-{lv.expr}" if mn=="neg" else f"~{lv.expr}")
            nv = NativeVal(lv.ctype, vname)
            self._write(dn, nv)
            return self._decl(lv.ctype, vname, expr)

        if mn == "push":
            if ops and ops[0].type == x86c.X86_OP_REG:
                return f"// push {insn.reg_name(ops[0].reg)}"
            return None

        if mn == "pop":
            if ops and ops[0].type == x86c.X86_OP_REG:
                dn = insn.reg_name(ops[0].reg)
                vname = self._alloc()
                nv = NativeVal("uint32_t", vname)
                self._write(dn, nv)
                return self._decl("uint32_t", vname, "stack_pop()")
            return None

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
            return None

        if mn in _X86_JCCS:
            target = ops[0].imm if ops and ops[0].type == x86c.X86_OP_IMM else 0
            cond_op = _X86_JCC_OPS.get(mn, "?")
            lhs = self._cmp_expr or "cond"
            rhs = self._cmp_rhs  or "0"
            return f"if ({lhs} {cond_op} {rhs}) goto {hex(target)};"

        if mn == "jmp":
            if ops and ops[0].type == x86c.X86_OP_IMM:
                return f"goto {hex(ops[0].imm)};"
            if ops and ops[0].type == x86c.X86_OP_REG:
                return f"goto *{self._read(self._canon(insn.reg_name(ops[0].reg))).expr};"
            return "goto *<indirect>;"

        if mn == "call":
            if not ops:
                return "eax = <indirect_call>();"
            if ops[0].type == x86c.X86_OP_IMM:
                target_va = ops[0].imm
                fname = self._plt.get(target_va) or self._name_fn(target_va)
            elif ops[0].type == x86c.X86_OP_REG:
                fname = self._read(self._canon(insn.reg_name(ops[0].reg))).expr
            else:
                fname = "<indirect>"
            vname = self._alloc()
            nv = NativeVal("uint32_t", vname)
            self._write("eax", nv)
            for r in ("ecx", "edx"):
                self._write(r, NativeVal("uint32_t", "<clobber>"))
            return self._decl("uint32_t", vname, f"{fname}(...)")

        if mn in ("ret", "retn", "retf"):
            rv = self._read("eax")
            return f"return {rv.expr};"

        if mn in ("nop", "endbr32", "prefetchnta", "prefetcht0", "lfence", "mfence", "sfence"):
            return None

        return f"// {mn} {insn.op_str}"

    def _operand_read(self, insn, op) -> tuple:
        import capstone.x86_const as x86c
        if op.type == x86c.X86_OP_IMM:
            return (_imm_expr(op.imm), False)
        if op.type == x86c.X86_OP_REG:
            reg_name = insn.reg_name(op.reg)
            nv = self._read(self._canon(reg_name))
            return (nv.expr, nv.tainted)
        if op.type == x86c.X86_OP_MEM:
            addr = self._mem_expr(insn, op)
            size_bits = op.size * 8 if op.size else 32
            ctype = _ctype_from_bits(size_bits)
            return (f"*({ctype}*)({addr})", False)
        return ("???", False)


# ── Ablation ISA emit-function factories ──────────────────────────────────────

def _ablation_ops_str(insn) -> str:
    """Format insn.ops as a comma-separated string for fallback comments."""
    return ", ".join(str(o) for o in getattr(insn, "ops", []))


def _ablation_mem_addr(mem, regs: Dict[str, NativeVal]) -> str:
    """Memory address expression for ablation-native Mem objects (.disp or .offset)."""
    if getattr(mem, 'base', None) is None:
        return "???"
    base_expr = regs.get(mem.base, NativeVal("uint64_t", mem.base)).expr
    disp = getattr(mem, 'disp', getattr(mem, 'offset', 0))
    if disp:
        return f"({base_expr} + {_imm_expr(disp)})"
    return base_expr


# ── ARM32 / Thumb full decompiler ─────────────────────────────────────────────

class _ARM32State:
    """Per-function register-tracking state for ARM32/Thumb full decompiler.

    AAPCS: r0-r3 args, r0 return. Conditional execution encoded in insn.cond.
    """
    _PARAM_REGS = ("r0", "r1", "r2", "r3")
    _RETURN_REG = "r0"

    _COND_OPS: Dict[str, str] = {
        "eq": "==", "ne": "!=",
        "lt": "<",  "gt": ">", "le": "<=", "ge": ">=",
        "cs": ">=u", "hs": ">=u", "cc": "<u", "lo": "<u",
        "hi": ">u",  "ls": "<=u",
        "mi": "< 0", "pl": ">= 0",
    }

    _LOAD_W: Dict[str, tuple] = {
        "ldr": (32, False), "ldrt": (32, False),
        "ldrb": (8, False),  "ldrbt": (8, False),
        "ldrh": (16, False), "ldrht": (16, False),
        "ldrsb": (8, True),  "ldrsbt": (8, True),
        "ldrsh": (16, True), "ldrsht": (16, True),
    }
    _STORE_W: Dict[str, int] = {
        "str": 32, "strt": 32,
        "strb": 8,  "strbt": 8,
        "strh": 16, "strht": 16,
    }
    _ARITH: Dict[str, str] = {
        "add": "+", "adds": "+", "adc": "+", "adcs": "+",
        "sub": "-", "subs": "-", "sbc": "-", "sbcs": "-",
        "mul": "*", "muls": "*", "mla": "*",
        "and": "&", "ands": "&",
        "bic": "& ~", "bics": "& ~",
        "orr": "|", "orrs": "|",
        "eor": "^", "eors": "^",
        "lsl": "<<", "lsls": "<<",
        "lsr": ">>", "lsrs": ">>",
        "asr": ">>", "asrs": ">>",
        "ror": ">>/*ror*/",
    }

    def __init__(self, tainted_params: Set[str], name_fn, plt: Dict[int, str]):
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._cmp: Optional[Tuple[str, str]] = None
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt

        for i, r in enumerate(self._PARAM_REGS):
            nv = NativeVal("uint32_t", f"arg{i}", tainted=(r in tainted_params))
            self._regs[r] = nv
            self._written.add(r)
            self._declared.add(f"arg{i}")
        self._regs["sp"] = NativeVal("uint32_t", "sp", is_ptr=True)
        self._regs["lr"] = NativeVal("uint32_t", "lr")
        for r in ("sp", "lr"):
            self._written.add(r); self._declared.add(r)
        for r in (f"r{i}" for i in range(4, 13)):
            self._regs[r] = NativeVal("uint32_t", r)
            self._written.add(r); self._declared.add(r)

    def _alloc(self) -> str:
        n = f"v{self._var_n}"; self._var_n += 1; return n

    def _read(self, reg: str) -> NativeVal:
        if reg not in self._written:
            self._regs[reg] = NativeVal("uint32_t", reg)
            self._written.add(reg)
        return self._regs.get(reg, _UNKNOWN)

    def _write(self, reg: str, nv: NativeVal) -> str:
        old = self._regs.get(reg)
        if old and reg in self._written:
            e = old.expr
            if (e.startswith("v") and e[1:].isdigit()) or (e.startswith("arg") and e[3:].isdigit()):
                self._regs[reg] = NativeVal(nv.ctype, e, nv.is_ptr, nv.tainted); return e
        vn = self._alloc()
        self._regs[reg] = NativeVal(nv.ctype, vn, nv.is_ptr, nv.tainted)
        self._written.add(reg); return vn

    def _decl(self, ctype: str, vn: str, expr: str, ann: str = "") -> str:
        if vn in self._declared:
            return f"{vn} = {expr};{ann}"
        self._declared.add(vn); return f"{ctype} {vn} = {expr};{ann}"

    def _tainted(self, *regs: str) -> bool:
        return any(self._regs.get(r, _UNKNOWN).tainted for r in regs)

    def _op_expr(self, op) -> Tuple[str, bool]:
        if hasattr(op, 'value'):
            return _imm_expr(op.value), False
        if hasattr(op, 'name'):
            nv = self._read(op.name); return nv.expr, nv.tainted
        return str(op), False

    def _cond_expr(self, cond: Optional[str]) -> str:
        if not cond or self._cmp is None:
            return f"/* {cond or 'al'} */"
        a, b = self._cmp
        op = self._COND_OPS.get(cond, cond)
        if op.endswith("u"):
            return f"(unsigned){a} {op[:-1]} (unsigned){b}"
        if op in ("< 0", ">= 0"):
            return f"{a} {op}"
        return f"{a} {op} {b}"

    def emit(self, insn) -> str:
        m = insn.mnemonic.lower()
        cond = getattr(insn, "cond", None)

        # Return
        if m == "bx" and insn.reg(0) == "lr":
            return f"return {self._read(self._RETURN_REG).expr};"
        if m == "pop":
            rl = insn.reglist(0) if hasattr(insn, "reglist") else None
            if rl and "pc" in getattr(rl, "regs", ()):
                return f"return {self._read(self._RETURN_REG).expr};"

        # Call
        if m in ("bl", "blx", "blxns"):
            tgt = insn.imm(0)
            callee = self._name_fn(tgt) if tgt is not None else (
                f"*{self._read(insn.reg(0)).expr}" if insn.reg(0) else "???")
            args_str = ", ".join(self._read(r).expr for r in self._PARAM_REGS)
            vn = self._alloc()
            is_t = self._tainted(*self._PARAM_REGS)
            self._regs["r0"] = NativeVal("uint32_t", vn, tainted=is_t)
            self._written.add("r0")
            ann = " /* TAINTED */" if is_t else ""
            stmt = self._decl("uint32_t", vn, f"{callee}({args_str})", ann)
            return (f"if ({self._cond_expr(cond)}) " + stmt) if cond else stmt

        # Unconditional branch
        if m == "b" and cond is None:
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else "goto *???;"

        # Conditional branch
        if m == "b" and cond:
            tgt = insn.imm(0)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            return f"if ({self._cond_expr(cond)}) goto {label};"

        # Compare
        if m in ("cmp", "cmn", "tst", "teq"):
            a = self._read(insn.reg(0) or "r0").expr if insn.reg(0) else "???"
            b, _ = self._op_expr(insn.ops[1]) if len(insn.ops) > 1 else ("0", False)
            self._cmp = (a, f"-({b})") if m == "cmn" else (
                (f"({a} & {b})", "0") if m == "tst" else
                (f"({a} ^ {b})", "0") if m == "teq" else (a, b))
            return f"// {m} {a}, {b}"

        # Load
        if m in self._LOAD_W:
            dst = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if dst is None or mem is None:
                return f"// {m} ???"
            bits, signed = self._LOAD_W[m]
            ctype = _ctype_from_bits(bits, signed)
            addr = _ablation_mem_addr(mem, self._regs)
            tainted = self._tainted(mem.base) if mem.base else False
            expr = f"*({_ptr_cast(ctype)}{addr})"
            vn = self._write(dst, NativeVal(ctype, expr, tainted=tainted))
            result = self._decl(ctype, vn, expr, " /* TAINTED */" if tainted else "")
            if getattr(mem, 'writeback', False) or getattr(mem, 'post', False):
                disp = getattr(mem, 'disp', 0)
                if disp and mem.base:
                    bv = self._read(mem.base).expr
                    wb_vn = self._write(mem.base, NativeVal("uint32_t", f"({bv} + {_imm_expr(disp)})", is_ptr=True))
                    result += f"\n{wb_vn} = {bv} + {_imm_expr(disp)};"
            return result

        # Store
        if m in self._STORE_W:
            src = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if src is None or mem is None:
                return f"// {m} ???"
            bits = self._STORE_W[m]
            addr = _ablation_mem_addr(mem, self._regs)
            return f"*({_ptr_cast(_ctype_from_bits(bits))}{addr}) = {self._read(src).expr};{' /* TAINTED */' if self._tainted(src) else ''}"

        # Move
        if m in ("mov", "movs", "mvn", "mvns", "movw", "movt"):
            dst = insn.reg(0)
            if dst is None or len(insn.ops) < 2:
                return f"// {m} ???"
            src_expr, tainted = self._op_expr(insn.ops[1])
            if m in ("mvn", "mvns"):
                src_expr = f"~({src_expr})"
            vn = self._write(dst, NativeVal("uint32_t", src_expr, tainted=tainted))
            return self._decl("uint32_t", vn, src_expr, " /* TAINTED */" if tainted else "")

        # Arithmetic
        if m in self._ARITH:
            dst = insn.reg(0)
            if dst is None:
                return f"// {m} ???"
            src1 = insn.reg(1) or dst
            a = self._read(src1).expr
            b, b_tainted = self._op_expr(insn.ops[2]) if len(insn.ops) > 2 else self._op_expr(insn.ops[1]) if len(insn.ops) > 1 else ("0", False)
            tainted = self._tainted(src1) or b_tainted
            op = self._ARITH[m]
            expr = f"{b} - {a}" if m == "rsb" else (f"{a} {op[:-2]}({b})" if op.endswith("~") else f"{a} {op} {b}")
            vn = self._write(dst, NativeVal("uint32_t", expr, tainted=tainted))
            return self._decl("uint32_t", vn, expr, " /* TAINTED */" if tainted else "")

        # NOP / barriers
        if m in ("nop", "nop.w", "dmb", "dsb", "isb", "wfi", "sev", "sevl", "yield"):
            return ""

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"


# ── MIPS32 / MIPS64 full decompiler ──────────────────────────────────────────

class _MIPSState:
    """Per-function register-tracking state for MIPS32 (o32) and MIPS64 (n64).

    Registers use ablation canonical $N form. Params: $4-$7 (o32) / $4-$11 (n64).
    Return: $2. Zero: $0. RA: $31.
    """
    _ZERO = frozenset({"$0"})
    _RETURN = "$2"
    _RA = "$31"
    _SP = "$29"

    _JCC = frozenset({"beq","bne","blt","bge","bltu","bgeu","beql","bnel",
                      "bgtz","bltz","bgez","blez","bgtzl","bltzl","bgezl","blezl",
                      "beqz","bnez"})
    _CALLS = frozenset({"jal","jalr","bal","bltzal","bgezal","bltzall","bgezall"})

    _LOAD_W: Dict[str, tuple] = {
        "lw": (32, False), "lwu": (32, False), "lwl": (32, False), "lwr": (32, False),
        "lh": (16, True),  "lhu": (16, False),
        "lb": (8,  True),  "lbu": (8,  False),
        "ld": (64, False), "ldl": (64, False), "ldr": (64, False),
    }
    _STORE_W: Dict[str, int] = {
        "sw": 32, "swl": 32, "swr": 32,
        "sh": 16, "sb": 8,
        "sd": 64, "sdl": 64, "sdr": 64,
    }
    _ARITH: Dict[str, str] = {
        "add": "+",  "addu": "+",  "addi": "+",  "addiu": "+",
        "dadd":"+",  "daddu":"+",  "daddi":"+",  "daddiu":"+",
        "sub": "-",  "subu": "-",  "dsub": "-",  "dsubu": "-",
        "mul": "*",  "mulu": "*",
        "and": "&",  "andi": "&",
        "or":  "|",  "ori":  "|",
        "xor": "^",  "xori": "^",
        "nor": "|~", "sll": "<<",  "srl": ">>",  "sra": ">>",
        "sllv":"<<", "srlv":">>",  "srav":">>",
        "dsll":"<<", "dsrl":">>",  "dsra":">>",
        "dsllv":"<<","dsrlv":">>", "dsrav":">>",
        "slt": "<",  "sltu":"<u",  "slti":"<",   "sltiu":"<u",
    }

    def __init__(self, bits: int, tainted_params: Set[str], name_fn, plt: Dict[int, str]):
        self._bits = bits
        self._ctype = f"uint{bits}_t"
        self._param_regs = tuple(f"${i}" for i in range(4, 8 if bits == 32 else 12))
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._cmp: Optional[Tuple[str, str]] = None
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt

        for i, r in enumerate(self._param_regs):
            nv = NativeVal(self._ctype, f"arg{i}", tainted=(r in tainted_params))
            self._regs[r] = nv; self._written.add(r); self._declared.add(f"arg{i}")
        self._regs["$0"] = NativeVal(self._ctype, "0")
        self._written.add("$0")
        for r in (self._SP, "$28", "$30", "$31"):
            self._regs[r] = NativeVal(self._ctype, r)
            self._written.add(r); self._declared.add(r)

    def _alloc(self) -> str:
        n = f"v{self._var_n}"; self._var_n += 1; return n

    def _read(self, reg: str) -> NativeVal:
        if reg in self._ZERO:
            return NativeVal(self._ctype, "0")
        if reg not in self._written:
            self._regs[reg] = NativeVal(self._ctype, reg)
            self._written.add(reg)
        return self._regs.get(reg, _UNKNOWN)

    def _write(self, reg: str, nv: NativeVal) -> str:
        if reg in self._ZERO:
            return "0"
        old = self._regs.get(reg)
        if old and reg in self._written:
            e = old.expr
            if (e.startswith("v") and e[1:].isdigit()) or (e.startswith("arg") and e[3:].isdigit()):
                self._regs[reg] = NativeVal(nv.ctype, e, nv.is_ptr, nv.tainted); return e
        vn = self._alloc()
        self._regs[reg] = NativeVal(nv.ctype, vn, nv.is_ptr, nv.tainted)
        self._written.add(reg); return vn

    def _decl(self, ctype: str, vn: str, expr: str, ann: str = "") -> str:
        if vn in self._declared:
            return f"{vn} = {expr};{ann}"
        self._declared.add(vn); return f"{ctype} {vn} = {expr};{ann}"

    def _tainted(self, *regs: str) -> bool:
        return any(self._regs.get(r, _UNKNOWN).tainted for r in regs)

    def emit(self, insn) -> str:
        m = insn.mnemonic.lower()

        # Return
        if m in ("jr", "jr.hb", "jalr") and insn.reg(0) in (self._RA, "$31"):
            return f"return {self._read(self._RETURN).expr};"

        # Call
        if m in self._CALLS:
            tgt = insn.imm(0)
            callee = self._name_fn(tgt) if tgt is not None else (
                f"*{self._read(insn.reg(0)).expr}" if insn.reg(0) else "???")
            args_str = ", ".join(self._read(r).expr for r in self._param_regs)
            vn = self._alloc()
            is_t = self._tainted(*self._param_regs)
            self._regs[self._RETURN] = NativeVal(self._ctype, vn, tainted=is_t)
            self._written.add(self._RETURN)
            ann = " /* TAINTED */" if is_t else ""
            return self._decl(self._ctype, vn, f"{callee}({args_str})", ann)

        # Unconditional jump
        if m in ("j", "b"):
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else "goto *???;"

        # Conditional branches — MIPS branches embed comparison registers
        if m in self._JCC:
            r0 = insn.reg(0)
            r1 = insn.reg(1) if m not in ("beqz","bnez","bgtz","bltz","bgez","blez",
                                           "bgtzl","bltzl","bgezl","blezl") else None
            tgt = insn.imm(0) or insn.imm(1) or insn.imm(2)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            a = self._read(r0).expr if r0 else "???"
            if r1:
                b = self._read(r1).expr
                op = {"beq":"==","bne":"!=","blt":"<","bge":">=",
                      "bltu":"<u","bgeu":">=u","beql":"==","bnel":"!="}.get(m,"??")
                if "u" in op:
                    cond_str = f"(unsigned){a} {op[:-1]} (unsigned){b}"
                else:
                    cond_str = f"{a} {op} {b}"
            else:
                op = {"bgtz":">","bltz":"<","bgez":">=","blez":"<=",
                      "bgtzl":">","bltzl":"<","bgezl":">=","blezl":"<=",
                      "beqz":"==","bnez":"!="}.get(m,"??")
                cond_str = f"{a} {op} 0"
            return f"if ({cond_str}) goto {label};"

        # Load
        if m in self._LOAD_W:
            dst = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if dst is None or mem is None:
                return f"// {m} ???"
            bits, signed = self._LOAD_W[m]
            ctype = _ctype_from_bits(bits, signed)
            addr = _ablation_mem_addr(mem, self._regs)
            tainted = self._tainted(mem.base) if mem.base else False
            expr = f"*({_ptr_cast(ctype)}{addr})"
            vn = self._write(dst, NativeVal(ctype, expr, tainted=tainted))
            return self._decl(ctype, vn, expr, " /* TAINTED */" if tainted else "")

        # Store
        if m in self._STORE_W:
            src = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if src is None or mem is None:
                return f"// {m} ???"
            ctype = _ctype_from_bits(self._STORE_W[m])
            addr = _ablation_mem_addr(mem, self._regs)
            return f"*({_ptr_cast(ctype)}{addr}) = {self._read(src).expr};{' /* TAINTED */' if self._tainted(src) else ''}"

        # Move pseudos
        if m in ("move", "dmove"):
            dst, src = insn.reg(0), insn.reg(1) or "$0"
            if dst:
                nv_src = self._read(src)
                vn = self._write(dst, NativeVal(self._ctype, nv_src.expr, tainted=nv_src.tainted))
                return self._decl(self._ctype, vn, nv_src.expr, " /* TAINTED */" if nv_src.tainted else "")

        # Load immediate
        if m in ("li", "dli", "li32"):
            dst, imm = insn.reg(0), insn.imm(1) or insn.imm(2)
            if dst and imm is not None:
                vn = self._write(dst, NativeVal(self._ctype, _imm_expr(imm)))
                return self._decl(self._ctype, vn, _imm_expr(imm))

        # Load upper (lui/dli high half)
        if m in ("lui", "dlui", "aui"):
            dst, imm = insn.reg(0), insn.imm(1)
            if dst and imm is not None:
                expr = _imm_expr(imm << 16)
                vn = self._write(dst, NativeVal(self._ctype, expr))
                return self._decl(self._ctype, vn, expr)

        # Arithmetic
        if m in self._ARITH:
            dst = insn.reg(0)
            if dst is None:
                return f"// {m} ???"
            r1 = insn.reg(1) or dst
            a = self._read(r1).expr
            op2 = insn.ops[2] if len(insn.ops) > 2 else (insn.ops[1] if len(insn.ops) > 1 else None)
            if op2 is None:
                b, b_t = "0", False
            elif hasattr(op2, 'value'):
                b, b_t = _imm_expr(op2.value), False
            elif hasattr(op2, 'name'):
                nv2 = self._read(op2.name); b, b_t = nv2.expr, nv2.tainted
            else:
                b, b_t = str(op2), False
            tainted = self._tainted(r1) or b_t
            op_sym = self._ARITH[m]
            if op_sym == "|~":
                expr = f"~({a} | {b})"  # NOR
            elif op_sym.endswith("u"):
                expr = f"(unsigned){a} {op_sym[:-1]} (unsigned){b}"
            else:
                expr = f"{a} {op_sym} {b}"
            vn = self._write(dst, NativeVal(self._ctype, expr, tainted=tainted))
            return self._decl(self._ctype, vn, expr, " /* TAINTED */" if tainted else "")

        # NOP / sync
        if m in ("nop", "ssnop", "ehb", "sync", "pause"):
            return ""

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"


# ── PPC32 / PPC64 full decompiler ─────────────────────────────────────────────

class _PPCState:
    """Per-function register-tracking state for PPC32/PPC64 (SysV/ELFv2).

    Registers use ablation canonical rN form. Params: r3-r10. Return: r3.
    """
    _RETURN = "r3"
    _SP = "r1"
    _CALLS = frozenset({"bl","bla","bctrl","blrl","bcl","bcla","bclrl"})
    _JCC = frozenset({"beq","bne","blt","bgt","ble","bge","bun","bnu","bso","bns",
                      "beqlr","bnelr","bltlr","bgtlr","blelr","bgelr",
                      "bdnz","bdz","bc","bca"})

    _LOAD_W: Dict[str, tuple] = {
        "lwz": (32, False), "lwzu": (32, False), "lwzx": (32, False), "lwzux": (32, False),
        "lwa": (32, True),  "lwax": (32, True),
        "lhz": (16, False), "lhzu": (16, False), "lhzx": (16, False),
        "lha": (16, True),  "lhau": (16, True),  "lhax": (16, True),
        "lbz": (8,  False), "lbzu": (8,  False),  "lbzx": (8,  False),
        "ld":  (64, False), "ldu": (64, False), "ldx": (64, False),
    }
    _STORE_W: Dict[str, int] = {
        "stw": 32, "stwu": 32, "stwx": 32,
        "sth": 16, "sthu": 16, "sthx": 16,
        "stb": 8,  "stbu": 8,  "stbx": 8,
        "std": 64, "stdu": 64, "stdx": 64,
    }
    _ARITH: Dict[str, str] = {
        "add": "+",   "addi": "+",   "addis": "+",  "addc": "+",  "adde": "+",
        "addo": "+",  "addco": "+",
        "sub": "-",   "subi": "-",   "subf": "-",   "subfc": "-", "subfe": "-",
        "subfic": "-",
        "mullw": "*", "mulhw": "*",  "mulhwu": "*",
        "mulld": "*", "mulhd": "*",  "mulhdu": "*",
        "and": "&",   "andi.": "&",  "andis.": "&",
        "or":  "|",   "ori":  "|",   "oris":  "|",
        "xor": "^",   "xori": "^",   "xoris": "^",
        "slw": "<<",  "srw": ">>",   "sraw": ">>",
        "sld": "<<",  "srd": ">>",   "srad": ">>",
        "slwi": "<<", "srwi": ">>",  "srawi": ">>",
        "sldi": "<<", "srdi": ">>",  "sradi": ">>",
        "rlwinm": "<<", "rlwimi": "|",
    }
    _CMP = frozenset({"cmp","cmpi","cmpw","cmpwi","cmpl","cmpli","cmplw","cmplwi",
                      "cmpd","cmpdi","cmpld","cmpldi"})

    def __init__(self, bits: int, tainted_params: Set[str], name_fn, plt: Dict[int, str]):
        self._bits = bits
        self._ctype = f"uint{bits}_t"
        self._param_regs = tuple(f"r{i}" for i in range(3, 11))
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._cmp: Optional[Tuple[str, str]] = None
        self._cmp_signed = True
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt

        for i, r in enumerate(self._param_regs):
            nv = NativeVal(self._ctype, f"arg{i}", tainted=(r in tainted_params))
            self._regs[r] = nv; self._written.add(r); self._declared.add(f"arg{i}")
        self._regs[self._SP] = NativeVal(self._ctype, "sp", is_ptr=True)
        self._written.add(self._SP); self._declared.add("sp")
        for r in ("lr", "ctr"):
            self._regs[r] = NativeVal(self._ctype, r)
            self._written.add(r); self._declared.add(r)
        for r in (f"r{i}" for i in range(13, 32)):
            self._regs[r] = NativeVal(self._ctype, r)
            self._written.add(r); self._declared.add(r)

    def _alloc(self) -> str:
        n = f"v{self._var_n}"; self._var_n += 1; return n

    def _read(self, reg: str) -> NativeVal:
        if reg not in self._written:
            self._regs[reg] = NativeVal(self._ctype, reg)
            self._written.add(reg)
        return self._regs.get(reg, _UNKNOWN)

    def _write(self, reg: str, nv: NativeVal) -> str:
        old = self._regs.get(reg)
        if old and reg in self._written:
            e = old.expr
            if (e.startswith("v") and e[1:].isdigit()) or (e.startswith("arg") and e[3:].isdigit()):
                self._regs[reg] = NativeVal(nv.ctype, e, nv.is_ptr, nv.tainted); return e
        vn = self._alloc()
        self._regs[reg] = NativeVal(nv.ctype, vn, nv.is_ptr, nv.tainted)
        self._written.add(reg); return vn

    def _decl(self, ctype: str, vn: str, expr: str, ann: str = "") -> str:
        if vn in self._declared:
            return f"{vn} = {expr};{ann}"
        self._declared.add(vn); return f"{ctype} {vn} = {expr};{ann}"

    def _tainted(self, *regs: str) -> bool:
        return any(self._regs.get(r, _UNKNOWN).tainted for r in regs)

    def _cond_expr(self, m: str) -> str:
        if self._cmp is None:
            return f"/* {m} */"
        a, b = self._cmp
        op = {"beq": "==", "bne": "!=", "blt": "<", "bgt": ">", "ble": "<=", "bge": ">=",
              "bun": "overflow", "bso": "overflow", "bnu": "no_overflow", "bns": "no_overflow"}.get(m, "??")
        if not self._cmp_signed and op in ("<", ">", "<=", ">="):
            return f"(unsigned){a} {op} (unsigned){b}"
        return f"{a} {op} {b}"

    def emit(self, insn) -> str:
        m = insn.mnemonic.lower()

        # Return
        if m in ("blr", "blrl"):
            return f"return {self._read(self._RETURN).expr};"

        # Calls
        if m in self._CALLS:
            tgt = insn.imm(0)
            if tgt is not None:
                callee = self._name_fn(tgt)
            elif "ctr" in m:
                callee = f"*{self._read('ctr').expr}"
            elif "lr" in m:
                callee = f"*{self._read('lr').expr}"
            else:
                callee = "???"
            args_str = ", ".join(self._read(r).expr for r in self._param_regs)
            vn = self._alloc()
            is_t = self._tainted(*self._param_regs)
            self._regs[self._RETURN] = NativeVal(self._ctype, vn, tainted=is_t)
            self._written.add(self._RETURN)
            ann = " /* TAINTED */" if is_t else ""
            return self._decl(self._ctype, vn, f"{callee}({args_str})", ann)

        # Unconditional branch
        if m in ("b", "ba"):
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else "goto *???;"

        # Conditional branches
        if m in self._JCC or m.startswith("bdnz") or m.startswith("bdz"):
            tgt = insn.imm(0) or insn.imm(1) or insn.imm(2)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            base_m = m.rstrip("+-")
            cond_str = self._cond_expr(base_m)
            if m.startswith("bdnz"):
                cond_str = "--ctr != 0"
            elif m.startswith("bdz"):
                cond_str = "ctr == 0"
            return f"if ({cond_str}) goto {label};"

        # Compare
        if m in self._CMP:
            r1 = insn.reg(0) or insn.reg(1) or "r3"
            op2 = insn.ops[-1] if insn.ops else None
            a = self._read(r1).expr
            b = (_imm_expr(op2.value) if hasattr(op2, 'value') else
                 self._read(op2.name).expr if hasattr(op2, 'name') else "0") if op2 else "0"
            self._cmp = (a, b)
            self._cmp_signed = "l" not in m or m in ("cmpld","cmpldi","cmplw","cmplwi")
            return f"// {m} {a}, {b}"

        # Load
        if m in self._LOAD_W:
            dst = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if dst is None or mem is None:
                return f"// {m} ???"
            bits, signed = self._LOAD_W[m]
            ctype = _ctype_from_bits(bits, signed)
            addr = _ablation_mem_addr(mem, self._regs)
            tainted = self._tainted(mem.base) if mem.base else False
            expr = f"*({_ptr_cast(ctype)}{addr})"
            vn = self._write(dst, NativeVal(ctype, expr, tainted=tainted))
            result = self._decl(ctype, vn, expr, " /* TAINTED */" if tainted else "")
            if m.endswith("u") and mem.base:
                disp = getattr(mem, 'disp', 0)
                if disp:
                    bv = self._read(mem.base).expr
                    wb_vn = self._write(mem.base, NativeVal(self._ctype, f"({bv} + {_imm_expr(disp)})", is_ptr=True))
                    result += f"\n{wb_vn} = {bv} + {_imm_expr(disp)};"
            return result

        # Store
        if m in self._STORE_W:
            src = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if src is None or mem is None:
                return f"// {m} ???"
            ctype = _ctype_from_bits(self._STORE_W[m])
            addr = _ablation_mem_addr(mem, self._regs)
            result = f"*({_ptr_cast(ctype)}{addr}) = {self._read(src).expr};{' /* TAINTED */' if self._tainted(src) else ''}"
            if m.endswith("u") and mem.base:
                disp = getattr(mem, 'disp', 0)
                if disp:
                    bv = self._read(mem.base).expr
                    wb_vn = self._write(mem.base, NativeVal(self._ctype, f"({bv} + {_imm_expr(disp)})", is_ptr=True))
                    result += f"\n{wb_vn} = {bv} + {_imm_expr(disp)};"
            return result

        # Move register
        if m in ("mr", "mr.", "fmr"):
            dst, src = insn.reg(0), insn.reg(1)
            if dst and src:
                nv_src = self._read(src)
                vn = self._write(dst, NativeVal(self._ctype, nv_src.expr, tainted=nv_src.tainted))
                return self._decl(self._ctype, vn, nv_src.expr, " /* TAINTED */" if nv_src.tainted else "")

        # Load immediate
        if m == "li":
            dst, imm = insn.reg(0), insn.imm(1)
            if dst and imm is not None:
                vn = self._write(dst, NativeVal(self._ctype, _imm_expr(imm)))
                return self._decl(self._ctype, vn, _imm_expr(imm))

        if m in ("lis", "addis") and insn.reg(1) in ("r0", None):
            dst, imm = insn.reg(0), insn.imm(2) or insn.imm(1)
            if dst and imm is not None:
                expr = _imm_expr(imm << 16)
                vn = self._write(dst, NativeVal(self._ctype, expr))
                return self._decl(self._ctype, vn, expr)

        # Arithmetic
        if m in self._ARITH:
            dst = insn.reg(0)
            if dst is None:
                return f"// {m} ???"
            src1 = insn.reg(1) or dst
            a = self._read(src1).expr
            op3 = insn.ops[2] if len(insn.ops) > 2 else (insn.ops[1] if len(insn.ops) > 1 else None)
            if op3 is None:
                b, b_t = "0", False
            elif hasattr(op3, 'value'):
                b, b_t = _imm_expr(op3.value), False
            elif hasattr(op3, 'name'):
                nv3 = self._read(op3.name); b, b_t = nv3.expr, nv3.tainted
            else:
                b, b_t = str(op3), False
            tainted = self._tainted(src1) or b_t
            op_sym = self._ARITH[m]
            expr = f"{a} {op_sym} {b}"
            vn = self._write(dst, NativeVal(self._ctype, expr, tainted=tainted))
            return self._decl(self._ctype, vn, expr, " /* TAINTED */" if tainted else "")

        # NOP / sync
        if m in ("nop", "ori", "sync", "lwsync", "isync", "eieio"):
            if m == "ori" and insn.reg(0) == insn.reg(1) and insn.imm(2) == 0:
                return ""  # ori rN, rN, 0 = nop
        if m == "nop":
            return ""

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"


# ── RISC-V 32 / 64 full decompiler ────────────────────────────────────────────

class _RISCVState:
    """Per-function register-tracking state for RISC-V 32/64 (psABI).

    Registers use ABI names: zero, ra, sp, a0-a7, t0-t6, s0-s11.
    Mem objects use .offset field. Calls: jal ra / jalr ra.
    """
    _ZERO = frozenset({"zero", "x0"})
    _RETURN = "a0"
    _RA = "ra"
    _SP = "sp"
    _PARAM_REGS = ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7")

    _LOAD_W: Dict[str, tuple] = {
        "lw":  (32, True),  "lwu": (32, False),
        "lh":  (16, True),  "lhu": (16, False),
        "lb":  (8,  True),  "lbu": (8,  False),
        "ld":  (64, False),
        "c.lw":  (32, True), "c.ld": (64, False),
    }
    _STORE_W: Dict[str, int] = {
        "sw": 32, "sh": 16, "sb": 8, "sd": 64,
        "c.sw": 32, "c.sd": 64,
    }
    _ARITH: Dict[str, str] = {
        "add": "+",   "addi": "+",   "addw": "+",  "addiw": "+",
        "sub": "-",   "subw": "-",
        "mul": "*",   "mulw": "*",   "mulh": "*",  "mulhu": "*",  "mulhsu": "*",
        "div": "/",   "divu": "/",   "divw": "/",  "divuw": "/",
        "rem": "%",   "remu": "%",   "remw": "%",  "remuw": "%",
        "and": "&",   "andi": "&",
        "or":  "|",   "ori":  "|",
        "xor": "^",   "xori": "^",
        "sll": "<<",  "slli": "<<",  "sllw": "<<", "slliw": "<<",
        "srl": ">>",  "srli": ">>",  "srlw": ">>", "srliw": ">>",
        "sra": ">>",  "srai": ">>",  "sraw": ">>", "sraiw": ">>",
        "slt": "<",   "slti": "<",   "sltu": "<u", "sltiu": "<u",
        "min": "<?",  "max": ">?",   "minu": "<?u","maxu": ">?u",
    }
    _JCC = frozenset({"beq","bne","blt","bge","bltu","bgeu","beqz","bnez"})
    _JCC_OPS = {"beq":"==","bne":"!=","blt":"<","bge":">=","bltu":"<u","bgeu":">=u",
                "beqz":"==","bnez":"!="}

    def __init__(self, bits: int, tainted_params: Set[str], name_fn, plt: Dict[int, str]):
        self._bits = bits
        self._ctype = f"uint{bits}_t"
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt

        for r in self._ZERO:
            self._regs[r] = NativeVal(self._ctype, "0")
            self._written.add(r)
        for i, r in enumerate(self._PARAM_REGS):
            nv = NativeVal(self._ctype, f"arg{i}", tainted=(r in tainted_params))
            self._regs[r] = nv; self._written.add(r); self._declared.add(f"arg{i}")
        self._regs[self._SP] = NativeVal(self._ctype, "sp", is_ptr=True)
        self._written.add(self._SP); self._declared.add("sp")
        for r in ("ra", "gp", "tp"):
            self._regs[r] = NativeVal(self._ctype, r)
            self._written.add(r); self._declared.add(r)
        for r in (*(f"s{i}" for i in range(12)), *(f"t{i}" for i in range(7))):
            self._regs[r] = NativeVal(self._ctype, r)
            self._written.add(r); self._declared.add(r)

    def _alloc(self) -> str:
        n = f"v{self._var_n}"; self._var_n += 1; return n

    def _read(self, reg: str) -> NativeVal:
        if reg in self._ZERO:
            return NativeVal(self._ctype, "0")
        if reg not in self._written:
            self._regs[reg] = NativeVal(self._ctype, reg)
            self._written.add(reg)
        return self._regs.get(reg, _UNKNOWN)

    def _write(self, reg: str, nv: NativeVal) -> str:
        if reg in self._ZERO:
            return "0"
        old = self._regs.get(reg)
        if old and reg in self._written:
            e = old.expr
            if (e.startswith("v") and e[1:].isdigit()) or (e.startswith("arg") and e[3:].isdigit()):
                self._regs[reg] = NativeVal(nv.ctype, e, nv.is_ptr, nv.tainted); return e
        vn = self._alloc()
        self._regs[reg] = NativeVal(nv.ctype, vn, nv.is_ptr, nv.tainted)
        self._written.add(reg); return vn

    def _decl(self, ctype: str, vn: str, expr: str, ann: str = "") -> str:
        if vn in self._declared:
            return f"{vn} = {expr};{ann}"
        self._declared.add(vn); return f"{ctype} {vn} = {expr};{ann}"

    def _tainted(self, *regs: str) -> bool:
        return any(self._regs.get(r, _UNKNOWN).tainted for r in regs)

    def _is_return(self, insn) -> bool:
        m = insn.mnemonic.lower()
        if m == "ret":
            return True
        if m == "jalr":
            r0, r1 = insn.reg(0), insn.reg(1)
            if r0 in self._ZERO and r1 == self._RA:
                return True
            if r0 == self._RA and r1 in self._ZERO:
                return True
        return False

    def _is_call(self, insn) -> bool:
        m = insn.mnemonic.lower()
        if m in ("call", "tail"):
            return True
        if m == "jal" and insn.reg(0) == self._RA:
            return True
        if m == "jalr" and insn.reg(0) == self._RA:
            return True
        return False

    def emit(self, insn) -> str:
        m = insn.mnemonic.lower()

        if self._is_return(insn):
            return f"return {self._read(self._RETURN).expr};"

        if self._is_call(insn):
            tgt = insn.imm(0) or insn.imm(1)
            if tgt is not None:
                callee = self._name_fn(tgt)
            elif insn.reg(1):
                callee = f"*{self._read(insn.reg(1)).expr}"
            else:
                callee = "???"
            args_str = ", ".join(self._read(r).expr for r in self._PARAM_REGS)
            vn = self._alloc()
            is_t = self._tainted(*self._PARAM_REGS)
            self._regs[self._RETURN] = NativeVal(self._ctype, vn, tainted=is_t)
            self._written.add(self._RETURN)
            ann = " /* TAINTED */" if is_t else ""
            return self._decl(self._ctype, vn, f"{callee}({args_str})", ann)

        # Unconditional jump
        if m in ("j", "c.j"):
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else "goto *???;"

        if m == "jal" and insn.reg(0) in self._ZERO:
            tgt = insn.imm(1) or insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else "goto *???;"

        # Conditional branches — RISC-V encodes comparison registers directly
        if m in self._JCC:
            r0 = insn.reg(0)
            r1 = insn.reg(1) if m not in ("beqz", "bnez") else None
            tgt = insn.imm(0) or insn.imm(1) or insn.imm(2)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            a = self._read(r0).expr if r0 else "???"
            op = self._JCC_OPS.get(m, "??")
            if r1:
                b = self._read(r1).expr
                if "u" in op:
                    cond_str = f"(unsigned){a} {op[:-1]} (unsigned){b}"
                else:
                    cond_str = f"{a} {op} {b}"
            else:
                cond_str = f"{a} {op} 0"
            return f"if ({cond_str}) goto {label};"

        # Load
        if m in self._LOAD_W:
            dst = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if dst is None or mem is None:
                return f"// {m} ???"
            bits, signed = self._LOAD_W[m]
            ctype = _ctype_from_bits(bits, signed)
            addr = _ablation_mem_addr(mem, self._regs)
            tainted = self._tainted(mem.base) if mem.base else False
            expr = f"*({_ptr_cast(ctype)}{addr})"
            vn = self._write(dst, NativeVal(ctype, expr, tainted=tainted))
            return self._decl(ctype, vn, expr, " /* TAINTED */" if tainted else "")

        # Store
        if m in self._STORE_W:
            src = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if src is None or mem is None:
                return f"// {m} ???"
            ctype = _ctype_from_bits(self._STORE_W[m])
            addr = _ablation_mem_addr(mem, self._regs)
            return f"*({_ptr_cast(ctype)}{addr}) = {self._read(src).expr};{' /* TAINTED */' if self._tainted(src) else ''}"

        # Move pseudos
        if m in ("mv", "c.mv"):
            dst, src = insn.reg(0), insn.reg(1) or "zero"
            if dst:
                nv_src = self._read(src)
                vn = self._write(dst, NativeVal(self._ctype, nv_src.expr, tainted=nv_src.tainted))
                return self._decl(self._ctype, vn, nv_src.expr, " /* TAINTED */" if nv_src.tainted else "")

        # Load immediate
        if m in ("li", "c.li", "c.lui"):
            dst, imm = insn.reg(0), insn.imm(1) or insn.imm(2)
            if dst and imm is not None:
                vn = self._write(dst, NativeVal(self._ctype, _imm_expr(imm)))
                return self._decl(self._ctype, vn, _imm_expr(imm))

        # Load address (auipc+addi pair)
        if m in ("la", "lla"):
            dst = insn.reg(0); tgt = insn.imm(1)
            if dst and tgt is not None:
                expr = f"(void *){tgt:#x}"
                vn = self._write(dst, NativeVal("void *", expr, is_ptr=True))
                return self._decl("void *", vn, expr)

        # Arithmetic
        if m in self._ARITH:
            dst = insn.reg(0)
            if dst is None:
                return f"// {m} ???"
            src1 = insn.reg(1) or dst
            a = self._read(src1).expr
            op2 = insn.ops[2] if len(insn.ops) > 2 else (insn.ops[1] if len(insn.ops) > 1 else None)
            if op2 is None:
                b, b_t = "0", False
            elif hasattr(op2, 'value'):
                b, b_t = _imm_expr(op2.value), False
            elif hasattr(op2, 'name'):
                nv2 = self._read(op2.name); b, b_t = nv2.expr, nv2.tainted
            else:
                b, b_t = str(op2), False
            tainted = self._tainted(src1) or b_t
            op_sym = self._ARITH[m]
            ctype = self._ctype
            if op_sym.endswith("u"):
                expr = f"(unsigned){a} {op_sym[:-1]} (unsigned){b}"
            elif op_sym.startswith("<?"):
                expr = f"(({a}) < ({b}) ? ({a}) : ({b}))"
            elif op_sym.startswith(">?"):
                expr = f"(({a}) > ({b}) ? ({a}) : ({b}))"
            else:
                expr = f"{a} {op_sym} {b}"
            vn = self._write(dst, NativeVal(ctype, expr, tainted=tainted))
            return self._decl(ctype, vn, expr, " /* TAINTED */" if tainted else "")

        # NOP / fence
        if m in ("nop", "fence", "fence.i", "c.nop", "pause"):
            return ""

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"


# ── LoongArch64 full decompiler ───────────────────────────────────────────────

class _LA64State:
    """Per-function register-tracking state for LoongArch64 (lp64 ABI).

    Registers: $zero, $ra, $sp, $a0-$a7, $t0-$t8, $fp, $s0-$s8.
    Mem objects use .disp field.
    """
    _ZERO = frozenset({"$zero", "$r0"})
    _RETURN = "$a0"
    _RA = "$ra"
    _SP = "$sp"
    _PARAM_REGS = tuple(f"$a{i}" for i in range(8))

    _LOAD_W: Dict[str, tuple] = {
        "ld.b":  (8,  True),  "ld.bu": (8,  False),
        "ld.h":  (16, True),  "ld.hu": (16, False),
        "ld.w":  (32, True),  "ld.wu": (32, False),
        "ld.d":  (64, False),
        "ldx.b": (8,  True),  "ldx.bu":(8,  False),
        "ldx.h": (16, True),  "ldx.hu":(16, False),
        "ldx.w": (32, True),  "ldx.wu":(32, False),
        "ldx.d": (64, False),
        "ldptr.w":(32, True), "ldptr.d":(64, False),
    }
    _STORE_W: Dict[str, int] = {
        "st.b": 8,  "st.h": 16,  "st.w": 32,  "st.d": 64,
        "stx.b":8,  "stx.h":16,  "stx.w":32,  "stx.d":64,
        "stptr.w":32, "stptr.d":64,
    }
    _ARITH: Dict[str, str] = {
        "add.w": "+",  "add.d": "+",  "addi.w": "+",  "addi.d": "+",
        "sub.w": "-",  "sub.d": "-",
        "mul.w": "*",  "mul.d": "*",  "mulh.w": "*",  "mulh.wu": "*",
        "mulh.d": "*", "mulh.du": "*",
        "div.w": "/",  "div.wu": "/", "div.d": "/",  "div.du": "/",
        "mod.w": "%",  "mod.wu": "%", "mod.d": "%",  "mod.du": "%",
        "and":  "&",   "andi": "&",
        "or":   "|",   "ori":  "|",
        "xor":  "^",   "xori": "^",
        "nor":  "|~",
        "sll.w": "<<", "sll.d": "<<", "slli.w": "<<", "slli.d": "<<",
        "srl.w": ">>", "srl.d": ">>", "srli.w": ">>", "srli.d": ">>",
        "sra.w": ">>", "sra.d": ">>", "srai.w": ">>", "srai.d": ">>",
        "slt":  "<",   "sltu":  "<u", "slti":  "<",   "sltui": "<u",
    }
    _JCC = frozenset({"beq","bne","blt","bge","bltu","bgeu","beqz","bnez","bceqz","bcnez"})
    _JCC_OPS = {"beq":"==","bne":"!=","blt":"<","bge":">=","bltu":"<u","bgeu":">=u",
                "beqz":"==","bnez":"!="}

    def __init__(self, tainted_params: Set[str], name_fn, plt: Dict[int, str]):
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt

        for r in self._ZERO:
            self._regs[r] = NativeVal("uint64_t", "0"); self._written.add(r)
        for i, r in enumerate(self._PARAM_REGS):
            nv = NativeVal("uint64_t", f"arg{i}", tainted=(r in tainted_params))
            self._regs[r] = nv; self._written.add(r); self._declared.add(f"arg{i}")
        self._regs[self._SP] = NativeVal("uint64_t", "sp", is_ptr=True)
        self._written.add(self._SP); self._declared.add("sp")
        for r in ("$ra", "$fp", "$tp"):
            self._regs[r] = NativeVal("uint64_t", r)
            self._written.add(r); self._declared.add(r)
        for r in (*(f"$t{i}" for i in range(9)), *(f"$s{i}" for i in range(9))):
            self._regs[r] = NativeVal("uint64_t", r)
            self._written.add(r); self._declared.add(r)

    def _alloc(self) -> str:
        n = f"v{self._var_n}"; self._var_n += 1; return n

    def _read(self, reg: str) -> NativeVal:
        if reg in self._ZERO:
            return NativeVal("uint64_t", "0")
        if reg not in self._written:
            self._regs[reg] = NativeVal("uint64_t", reg); self._written.add(reg)
        return self._regs.get(reg, _UNKNOWN)

    def _write(self, reg: str, nv: NativeVal) -> str:
        if reg in self._ZERO:
            return "0"
        old = self._regs.get(reg)
        if old and reg in self._written:
            e = old.expr
            if (e.startswith("v") and e[1:].isdigit()) or (e.startswith("arg") and e[3:].isdigit()):
                self._regs[reg] = NativeVal(nv.ctype, e, nv.is_ptr, nv.tainted); return e
        vn = self._alloc()
        self._regs[reg] = NativeVal(nv.ctype, vn, nv.is_ptr, nv.tainted)
        self._written.add(reg); return vn

    def _decl(self, ctype: str, vn: str, expr: str, ann: str = "") -> str:
        if vn in self._declared:
            return f"{vn} = {expr};{ann}"
        self._declared.add(vn); return f"{ctype} {vn} = {expr};{ann}"

    def _tainted(self, *regs: str) -> bool:
        return any(self._regs.get(r, _UNKNOWN).tainted for r in regs)

    def _is_return(self, insn) -> bool:
        m = insn.mnemonic.lower()
        if m != "jirl":
            return False
        r0 = insn.reg(0); r1 = insn.reg(1)
        return r0 in self._ZERO and r1 in ("$ra", "$r1")

    def _is_call(self, insn) -> bool:
        m = insn.mnemonic.lower()
        if m == "bl":
            return True
        if m == "jirl" and insn.reg(0) in ("$ra", "$r1"):
            return True
        return False

    def emit(self, insn) -> str:
        m = insn.mnemonic.lower()

        if self._is_return(insn):
            return f"return {self._read(self._RETURN).expr};"

        if self._is_call(insn):
            tgt = insn.imm(0) or insn.imm(1)
            callee = (self._name_fn(tgt) if tgt is not None else
                      f"*{self._read(insn.reg(1)).expr}" if m == "jirl" and insn.reg(1) else "???")
            args_str = ", ".join(self._read(r).expr for r in self._PARAM_REGS)
            vn = self._alloc()
            is_t = self._tainted(*self._PARAM_REGS)
            self._regs[self._RETURN] = NativeVal("uint64_t", vn, tainted=is_t)
            self._written.add(self._RETURN)
            ann = " /* TAINTED */" if is_t else ""
            return self._decl("uint64_t", vn, f"{callee}({args_str})", ann)

        # Unconditional branch
        if m == "b":
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else "goto *???;"

        # Conditional branches
        if m in self._JCC:
            r0 = insn.reg(0)
            r1 = insn.reg(1) if m not in ("beqz", "bnez", "bceqz", "bcnez") else None
            tgt = insn.imm(0) or insn.imm(1) or insn.imm(2)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            a = self._read(r0).expr if r0 else "???"
            op = self._JCC_OPS.get(m, "??")
            if r1:
                b = self._read(r1).expr
                cond_str = (f"(unsigned){a} {op[:-1]} (unsigned){b}" if "u" in op
                            else f"{a} {op} {b}")
            else:
                cond_str = f"{a} {op} 0"
            return f"if ({cond_str}) goto {label};"

        # Load
        if m in self._LOAD_W:
            dst = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if dst is None or mem is None:
                return f"// {m} ???"
            bits, signed = self._LOAD_W[m]
            ctype = _ctype_from_bits(bits, signed)
            addr = _ablation_mem_addr(mem, self._regs)
            tainted = self._tainted(mem.base) if mem.base else False
            expr = f"*({_ptr_cast(ctype)}{addr})"
            vn = self._write(dst, NativeVal(ctype, expr, tainted=tainted))
            return self._decl(ctype, vn, expr, " /* TAINTED */" if tainted else "")

        # Store
        if m in self._STORE_W:
            src = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if src is None or mem is None:
                return f"// {m} ???"
            ctype = _ctype_from_bits(self._STORE_W[m])
            addr = _ablation_mem_addr(mem, self._regs)
            return f"*({_ptr_cast(ctype)}{addr}) = {self._read(src).expr};{' /* TAINTED */' if self._tainted(src) else ''}"

        # Move / load immediate
        if m in ("move", "ori") and (m == "move" or (insn.reg(1) in self._ZERO and insn.imm(2) == 0)):
            dst, src = insn.reg(0), insn.reg(1) or "$zero"
            if dst:
                nv_src = self._read(src)
                vn = self._write(dst, NativeVal("uint64_t", nv_src.expr, tainted=nv_src.tainted))
                return self._decl("uint64_t", vn, nv_src.expr, " /* TAINTED */" if nv_src.tainted else "")

        if m in ("lu12i.w", "lu32i.d", "lu52i.d", "addi.w", "addi.d") and insn.reg(1) in self._ZERO:
            dst, imm = insn.reg(0), insn.imm(1) or insn.imm(2)
            if dst and imm is not None:
                expr = _imm_expr(imm << (12 if "lu12" in m or "lu32" in m or "lu52" in m else 0))
                vn = self._write(dst, NativeVal("uint64_t", expr))
                return self._decl("uint64_t", vn, expr)

        # Arithmetic
        if m in self._ARITH:
            dst = insn.reg(0)
            if dst is None:
                return f"// {m} ???"
            src1 = insn.reg(1) or dst
            a = self._read(src1).expr
            op2 = insn.ops[2] if len(insn.ops) > 2 else (insn.ops[1] if len(insn.ops) > 1 else None)
            if op2 is None:
                b, b_t = "0", False
            elif hasattr(op2, 'value'):
                b, b_t = _imm_expr(op2.value), False
            elif hasattr(op2, 'name'):
                nv2 = self._read(op2.name); b, b_t = nv2.expr, nv2.tainted
            else:
                b, b_t = str(op2), False
            tainted = self._tainted(src1) or b_t
            op_sym = self._ARITH[m]
            if op_sym == "|~":
                expr = f"~({a} | {b})"
            elif op_sym.endswith("u"):
                expr = f"(unsigned){a} {op_sym[:-1]} (unsigned){b}"
            else:
                expr = f"{a} {op_sym} {b}"
            vn = self._write(dst, NativeVal("uint64_t", expr, tainted=tainted))
            return self._decl("uint64_t", vn, expr, " /* TAINTED */" if tainted else "")

        if m in ("nop",):
            return ""

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"


# ── ARC EM/HS full decompiler ─────────────────────────────────────────────────

class _ARCState:
    """Per-function register-tracking state for ARC EM/HS (ARC GNU ABI).

    Registers: r0-r31, blink. Params: r0-r7. Return: r0. Mem: .disp.
    """
    _PARAM_REGS = tuple(f"r{i}" for i in range(8))
    _RETURN = "r0"
    _BLINK = "blink"

    _CALLS = frozenset({"bl", "jl", "bl.d", "jl.d"})
    _JCC = frozenset({"beq","bne","blt","bgt","ble","bge","blo","bhs","bhi","bls",
                      "bbit0","bbit1","breq","brne","brlt","brge","brle","brge"})
    _JCC_OPS = {"beq":"==","bne":"!=","blt":"<","bgt":">","ble":"<=","bge":">=",
                "blo":"<u","bhs":">=u","bhi":">u","bls":"<=u",
                "breq":"==","brne":"!=","brlt":"<","brge":">=","brle":"<=","brgt":">"}

    _LOAD_W: Dict[str, tuple] = {
        "ld":  (32, False), "ld.ab": (32, False), "ld.as": (32, False),
        "ldb": (8,  False), "ldb.x": (8,  True),  "ldb.ab":(8,  False),
        "ldh": (16, False), "ldh.x": (16, True),  "ldh.ab":(16, False),
        "ldd": (64, False),
    }
    _STORE_W: Dict[str, int] = {
        "st": 32, "st.ab": 32, "st.as": 32,
        "stb": 8,  "stb.ab": 8,
        "sth": 16, "sth.ab": 16,
        "std": 64,
    }
    _ARITH: Dict[str, str] = {
        "add": "+",  "add1": "+", "add2": "+", "add3": "+",
        "sub": "-",  "sub1": "-", "sub2": "-", "sub3": "-",
        "mul64": "*","mulu64": "*",
        "and": "&",  "bic": "& ~",
        "or":  "|",
        "xor": "^",
        "asl": "<<", "asr": ">>", "lsr": ">>",
        "ror": ">>/*ror*/",
        "min": "<?", "max": ">?",
    }
    _CMP = frozenset({"cmp", "cmpgt", "cmpge", "cmplt", "cmple", "tst"})

    def __init__(self, tainted_params: Set[str], name_fn, plt: Dict[int, str]):
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._cmp: Optional[Tuple[str, str]] = None
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt

        for i, r in enumerate(self._PARAM_REGS):
            nv = NativeVal("uint32_t", f"arg{i}", tainted=(r in tainted_params))
            self._regs[r] = nv; self._written.add(r); self._declared.add(f"arg{i}")
        self._regs["sp"] = NativeVal("uint32_t", "sp", is_ptr=True)
        self._written.add("sp"); self._declared.add("sp")
        self._regs[self._BLINK] = NativeVal("uint32_t", "blink")
        self._written.add(self._BLINK); self._declared.add("blink")
        for r in (f"r{i}" for i in range(13, 26)):
            self._regs[r] = NativeVal("uint32_t", r)
            self._written.add(r); self._declared.add(r)

    def _alloc(self) -> str:
        n = f"v{self._var_n}"; self._var_n += 1; return n

    def _read(self, reg: str) -> NativeVal:
        if reg not in self._written:
            self._regs[reg] = NativeVal("uint32_t", reg); self._written.add(reg)
        return self._regs.get(reg, _UNKNOWN)

    def _write(self, reg: str, nv: NativeVal) -> str:
        old = self._regs.get(reg)
        if old and reg in self._written:
            e = old.expr
            if (e.startswith("v") and e[1:].isdigit()) or (e.startswith("arg") and e[3:].isdigit()):
                self._regs[reg] = NativeVal(nv.ctype, e, nv.is_ptr, nv.tainted); return e
        vn = self._alloc()
        self._regs[reg] = NativeVal(nv.ctype, vn, nv.is_ptr, nv.tainted)
        self._written.add(reg); return vn

    def _decl(self, ctype: str, vn: str, expr: str, ann: str = "") -> str:
        if vn in self._declared:
            return f"{vn} = {expr};{ann}"
        self._declared.add(vn); return f"{ctype} {vn} = {expr};{ann}"

    def _tainted(self, *regs: str) -> bool:
        return any(self._regs.get(r, _UNKNOWN).tainted for r in regs)

    def _cond_expr(self, m: str) -> str:
        if self._cmp is None:
            return f"/* {m} */"
        a, b = self._cmp
        op = {"beq":"==","bne":"!=","blt":"<","bgt":">","ble":"<=","bge":">=",
              "blo":"<u","bhs":">=u","bhi":">u","bls":"<=u"}.get(m, "??")
        if "u" in op:
            return f"(unsigned){a} {op[:-1]} (unsigned){b}"
        return f"{a} {op} {b}"

    def emit(self, insn) -> str:
        m = insn.mnemonic.lower()

        # Return
        if m in ("j", "j.d", "jl", "jl.d") and insn.reg(0) == self._BLINK:
            return f"return {self._read(self._RETURN).expr};"

        # Call
        if m in self._CALLS:
            tgt = insn.imm(0)
            callee = (self._name_fn(tgt) if tgt is not None else
                      f"*[{self._read(insn.reg(0)).expr}]" if insn.reg(0) else "???")
            args_str = ", ".join(self._read(r).expr for r in self._PARAM_REGS)
            vn = self._alloc()
            is_t = self._tainted(*self._PARAM_REGS)
            self._regs[self._RETURN] = NativeVal("uint32_t", vn, tainted=is_t)
            self._written.add(self._RETURN)
            ann = " /* TAINTED */" if is_t else ""
            return self._decl("uint32_t", vn, f"{callee}({args_str})", ann)

        # Unconditional branch
        if m in ("b", "b.d"):
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else f"goto *{self._read(insn.reg(0)).expr if insn.reg(0) else '???'};"

        # Conditional branches
        if m in self._JCC:
            r0 = insn.reg(0); r1 = insn.reg(1)
            tgt = insn.imm(0) or insn.imm(1)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            if m.startswith("br"):
                a = self._read(r0).expr if r0 else "???"
                b = self._read(r1).expr if r1 else "0"
                op = self._JCC_OPS.get(m, "??")
                cond_str = f"{a} {op} {b}"
            else:
                cond_str = self._cond_expr(m)
            return f"if ({cond_str}) goto {label};"

        # Compare
        if m in self._CMP:
            r0, r1 = insn.reg(0), insn.reg(1)
            a = self._read(r0).expr if r0 else "???"
            b = (self._read(r1).expr if r1 else
                 _imm_expr(insn.imm(1)) if insn.imm(1) is not None else "0")
            if m == "tst":
                self._cmp = (f"({a} & {b})", "0")
            else:
                self._cmp = (a, b)
            return f"// {m} {a}, {b}"

        # Load
        if m in self._LOAD_W:
            dst = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if dst is None or mem is None:
                return f"// {m} ???"
            bits, signed = self._LOAD_W[m]
            ctype = _ctype_from_bits(bits, signed)
            addr = _ablation_mem_addr(mem, self._regs)
            tainted = self._tainted(mem.base) if mem.base else False
            expr = f"*({_ptr_cast(ctype)}{addr})"
            vn = self._write(dst, NativeVal(ctype, expr, tainted=tainted))
            return self._decl(ctype, vn, expr, " /* TAINTED */" if tainted else "")

        # Store
        if m in self._STORE_W:
            src = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if src is None or mem is None:
                return f"// {m} ???"
            ctype = _ctype_from_bits(self._STORE_W[m])
            addr = _ablation_mem_addr(mem, self._regs)
            return f"*({_ptr_cast(ctype)}{addr}) = {self._read(src).expr};{' /* TAINTED */' if self._tainted(src) else ''}"

        # Move
        if m in ("mov", "mov_s"):
            dst = insn.reg(0)
            if dst and len(insn.ops) > 1:
                op2 = insn.ops[1]
                src_expr = (_imm_expr(op2.value) if hasattr(op2, 'value') else
                            self._read(op2.name).expr if hasattr(op2, 'name') else str(op2))
                tainted = self._tainted(op2.name) if hasattr(op2, 'name') else False
                vn = self._write(dst, NativeVal("uint32_t", src_expr, tainted=tainted))
                return self._decl("uint32_t", vn, src_expr, " /* TAINTED */" if tainted else "")

        # Arithmetic
        if m in self._ARITH:
            dst = insn.reg(0)
            if dst is None:
                return f"// {m} ???"
            src1 = insn.reg(1) or dst
            a = self._read(src1).expr
            op2 = insn.ops[2] if len(insn.ops) > 2 else (insn.ops[1] if len(insn.ops) > 1 else None)
            if op2 is None:
                b, b_t = "0", False
            elif hasattr(op2, 'value'):
                b, b_t = _imm_expr(op2.value), False
            elif hasattr(op2, 'name'):
                nv2 = self._read(op2.name); b, b_t = nv2.expr, nv2.tainted
            else:
                b, b_t = str(op2), False
            tainted = self._tainted(src1) or b_t
            op_sym = self._ARITH[m]
            if op_sym == "& ~":
                expr = f"{a} & ~({b})"
            elif op_sym == "<?":
                expr = f"(({a}) < ({b}) ? ({a}) : ({b}))"
            elif op_sym == ">?":
                expr = f"(({a}) > ({b}) ? ({a}) : ({b}))"
            else:
                expr = f"{a} {op_sym} {b}"
            vn = self._write(dst, NativeVal("uint32_t", expr, tainted=tainted))
            return self._decl("uint32_t", vn, expr, " /* TAINTED */" if tainted else "")

        if m == "nop":
            return ""

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"


# ── V850 / RH850 full decompiler ──────────────────────────────────────────────

class _V850State:
    """Per-function register-tracking state for V850/RH850 (CC-RH ABI).

    Registers: r0 (zero), r1 (asm temp), r3 (sp), r6-r9 (args), r10 (return),
    r31 (lp). Mem objects use .offset field.
    """
    _ZERO = frozenset({"r0"})
    _RETURN = "r10"
    _LP = "r31"
    _SP = "r3"
    _PARAM_REGS = ("r6", "r7", "r8", "r9")

    _CALLS = frozenset({"jarl", "call"})
    _JCC = frozenset({"bv","bl","be","bnh","bn","br","blt","ble",
                      "bnv","bnl","bnz","bh","bp","bsa","bge","bgt",
                      "bc","bnc","bt","bf","bz","bvz"})
    _JCC_OPS = {"be":"==","bz":"==","bne":"!=","bnz":"!=",
                "blt":"<","bge":">=","bgt":">","ble":"<=",
                "bl":"<u","bnh":"<=u","bh":">u","bnl":">=u",
                "bn":"< 0","bp":">= 0","bv":"overflow","bnv":"no_overflow"}

    _LOAD_W: Dict[str, tuple] = {
        "ld.w":  (32, False), "ld.h":  (16, True),  "ld.hu": (16, False),
        "ld.b":  (8,  True),  "ld.bu": (8,  False),
        "ld.dw": (64, False),
    }
    _STORE_W: Dict[str, int] = {
        "st.w": 32, "st.h": 16, "st.b": 8, "st.dw": 64,
    }
    _ARITH: Dict[str, str] = {
        "add":  "+",  "addi": "+",  "sub": "-",  "subr": "-",
        "mul":  "*",  "mulu": "*",  "mulh": "*", "mulhi": "*",
        "and":  "&",  "andi": "&",
        "or":   "|",  "ori":  "|",
        "xor":  "^",  "xori": "^",
        "not":  "~",
        "shl":  "<<", "shr":  ">>", "sar":  ">>",
        "shl2": "<<", "shr2": ">>",
    }
    _CMP = frozenset({"cmp", "cmov"})

    def __init__(self, tainted_params: Set[str], name_fn, plt: Dict[int, str]):
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._cmp: Optional[Tuple[str, str]] = None
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt

        self._regs["r0"] = NativeVal("uint32_t", "0"); self._written.add("r0")
        for i, r in enumerate(self._PARAM_REGS):
            nv = NativeVal("uint32_t", f"arg{i}", tainted=(r in tainted_params))
            self._regs[r] = nv; self._written.add(r); self._declared.add(f"arg{i}")
        self._regs[self._RETURN] = NativeVal("uint32_t", "retval")
        self._written.add(self._RETURN); self._declared.add("retval")
        self._regs[self._SP] = NativeVal("uint32_t", "sp", is_ptr=True)
        self._written.add(self._SP); self._declared.add("sp")
        self._regs[self._LP] = NativeVal("uint32_t", "lp")
        self._written.add(self._LP); self._declared.add("lp")
        for r in (f"r{i}" for i in range(20, 31)):
            self._regs[r] = NativeVal("uint32_t", r)
            self._written.add(r); self._declared.add(r)

    def _alloc(self) -> str:
        n = f"v{self._var_n}"; self._var_n += 1; return n

    def _read(self, reg: str) -> NativeVal:
        if reg in self._ZERO:
            return NativeVal("uint32_t", "0")
        if reg not in self._written:
            self._regs[reg] = NativeVal("uint32_t", reg); self._written.add(reg)
        return self._regs.get(reg, _UNKNOWN)

    def _write(self, reg: str, nv: NativeVal) -> str:
        if reg in self._ZERO:
            return "0"
        old = self._regs.get(reg)
        if old and reg in self._written:
            e = old.expr
            if (e.startswith("v") and e[1:].isdigit()) or (e.startswith("arg") and e[3:].isdigit()):
                self._regs[reg] = NativeVal(nv.ctype, e, nv.is_ptr, nv.tainted); return e
        vn = self._alloc()
        self._regs[reg] = NativeVal(nv.ctype, vn, nv.is_ptr, nv.tainted)
        self._written.add(reg); return vn

    def _decl(self, ctype: str, vn: str, expr: str, ann: str = "") -> str:
        if vn in self._declared:
            return f"{vn} = {expr};{ann}"
        self._declared.add(vn); return f"{ctype} {vn} = {expr};{ann}"

    def _tainted(self, *regs: str) -> bool:
        return any(self._regs.get(r, _UNKNOWN).tainted for r in regs)

    def _cond_expr(self, m: str) -> str:
        if self._cmp is None:
            return f"/* {m} */"
        a, b = self._cmp
        op = self._JCC_OPS.get(m, "??")
        if "u" in op:
            return f"(unsigned){a} {op[:-1]} (unsigned){b}"
        if op in ("< 0", ">= 0", "overflow", "no_overflow"):
            return f"{a} {op}"
        return f"{a} {op} {b}"

    def emit(self, insn) -> str:
        m = insn.mnemonic.lower()

        # Return
        if m == "jmp" and insn.reg(0) == self._LP:
            return f"return {self._read(self._RETURN).expr};"

        # Call
        if m in self._CALLS:
            tgt = insn.imm(0) or insn.imm(1)
            callee = (self._name_fn(tgt) if tgt is not None else
                      f"*{self._read(insn.reg(0)).expr}" if insn.reg(0) else "???")
            args_str = ", ".join(self._read(r).expr for r in self._PARAM_REGS)
            vn = self._alloc()
            is_t = self._tainted(*self._PARAM_REGS)
            self._regs[self._RETURN] = NativeVal("uint32_t", vn, tainted=is_t)
            self._written.add(self._RETURN)
            ann = " /* TAINTED */" if is_t else ""
            return self._decl("uint32_t", vn, f"{callee}({args_str})", ann)

        # Unconditional jump
        if m == "jr":
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else f"goto *{self._read(insn.reg(0)).expr if insn.reg(0) else '???'};"

        # Conditional branches
        if m in self._JCC:
            tgt = insn.imm(0)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            return f"if ({self._cond_expr(m)}) goto {label};"

        # Compare
        if m == "cmp":
            r0, r1 = insn.reg(0), insn.reg(1)
            a = self._read(r0).expr if r0 else "???"
            op2 = insn.ops[1] if len(insn.ops) > 1 else None
            b = (self._read(r1).expr if r1 else
                 _imm_expr(op2.value) if op2 and hasattr(op2, 'value') else "0")
            self._cmp = (a, b)
            return f"// cmp {a}, {b}"

        # Load
        if m in self._LOAD_W:
            dst = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if dst is None or mem is None:
                return f"// {m} ???"
            bits, signed = self._LOAD_W[m]
            ctype = _ctype_from_bits(bits, signed)
            addr = _ablation_mem_addr(mem, self._regs)
            tainted = self._tainted(mem.base) if mem.base else False
            expr = f"*({_ptr_cast(ctype)}{addr})"
            vn = self._write(dst, NativeVal(ctype, expr, tainted=tainted))
            return self._decl(ctype, vn, expr, " /* TAINTED */" if tainted else "")

        # Store
        if m in self._STORE_W:
            src = insn.reg(0)
            mem = insn.mem(1) if len(insn.ops) > 1 else insn.mem(0)
            if src is None or mem is None:
                return f"// {m} ???"
            ctype = _ctype_from_bits(self._STORE_W[m])
            addr = _ablation_mem_addr(mem, self._regs)
            return f"*({_ptr_cast(ctype)}{addr}) = {self._read(src).expr};{' /* TAINTED */' if self._tainted(src) else ''}"

        # Move
        if m in ("mov", "movea", "movhi", "movzhi"):
            dst = insn.reg(0)
            if dst and len(insn.ops) > 1:
                op2 = insn.ops[1] if m not in ("movea","movhi","movzhi") else (insn.ops[2] if len(insn.ops) > 2 else insn.ops[1])
                src_expr = (_imm_expr(op2.value) if hasattr(op2, 'value') else
                            self._read(op2.name).expr if hasattr(op2, 'name') else str(op2))
                tainted = self._tainted(op2.name) if hasattr(op2, 'name') else False
                if m == "movhi":
                    src_expr = f"{src_expr} << 16"
                vn = self._write(dst, NativeVal("uint32_t", src_expr, tainted=tainted))
                return self._decl("uint32_t", vn, src_expr, " /* TAINTED */" if tainted else "")

        # Arithmetic
        if m in self._ARITH:
            dst = insn.reg(0)
            if dst is None:
                return f"// {m} ???"
            if m == "not":
                src = insn.reg(1) or dst
                nv_src = self._read(src)
                expr = f"~{nv_src.expr}"
                vn = self._write(dst, NativeVal("uint32_t", expr, tainted=nv_src.tainted))
                return self._decl("uint32_t", vn, expr, " /* TAINTED */" if nv_src.tainted else "")
            src1 = insn.reg(1) or dst
            a = self._read(src1).expr
            op2 = insn.ops[2] if len(insn.ops) > 2 else (insn.ops[1] if len(insn.ops) > 1 else None)
            if op2 is None:
                b, b_t = "0", False
            elif hasattr(op2, 'value'):
                b, b_t = _imm_expr(op2.value), False
            elif hasattr(op2, 'name'):
                nv2 = self._read(op2.name); b, b_t = nv2.expr, nv2.tainted
            else:
                b, b_t = str(op2), False
            tainted = self._tainted(src1) or b_t
            op_sym = self._ARITH[m]
            expr = (f"{b} - {a}" if m == "subr" else f"{a} {op_sym} {b}")
            vn = self._write(dst, NativeVal("uint32_t", expr, tainted=tainted))
            return self._decl("uint32_t", vn, expr, " /* TAINTED */" if tainted else "")

        if m == "nop":
            return ""

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"


# ── nanoMIPS full decompiler ──────────────────────────────────────────────────

class _NanoMIPSState:
    """Per-function register-tracking state for nanoMIPS (o32-compatible ABI).

    NanoFrame objects only have .mnemonic and .op_str (no structured .ops),
    so operands are extracted with regex. Params: $a0-$a3 (canonical: $4-$7).
    Return: $v0 (canonical: $2).
    """
    _PARAM_REGS = ("$a0", "$a1", "$a2", "$a3")
    _RETURN = "$v0"
    _RA_ALIASES = frozenset({"$ra", "$31"})
    _ZERO_ALIASES = frozenset({"$zero", "$0"})

    # MIPS ABI name -> short display name
    _ABI_DISPLAY = {
        "$zero":"$0","$at":"$1","$v0":"$2","$v1":"$3",
        "$a0":"$4","$a1":"$5","$a2":"$6","$a3":"$7",
        "$t0":"$8","$t1":"$9","$t2":"$10","$t3":"$11",
        "$t4":"$12","$t5":"$13","$t6":"$14","$t7":"$15",
        "$s0":"$16","$s1":"$17","$s2":"$18","$s3":"$19",
        "$s4":"$20","$s5":"$21","$s6":"$22","$s7":"$23",
        "$t8":"$24","$t9":"$25","$k0":"$26","$k1":"$27",
        "$gp":"$28","$sp":"$29","$fp":"$30","$ra":"$31",
    }
    # Reverse: numeric -> canonical ABI name for reads
    _FROM_NUMERIC = {v: k for k, v in _ABI_DISPLAY.items()}

    _CALLS = frozenset({"balc","jalrc","jal","bgezalc","bltzalc","jialc"})
    _JCC = frozenset({"beqc","bnec","bltc","bltuc","bgec","bgeuc",
                      "beqzc","bnezc","bltzc","bgezc","bgtzc","blezc",
                      "beq","bne","bltz","bgez"})

    _LOAD_W: Dict[str, tuple] = {
        "lw": (32, False), "lh": (16, True), "lhu": (16, False),
        "lb": (8, True),   "lbu":(8, False),  "ld":  (64, False),
    }
    _STORE_W: Dict[str, int] = {"sw": 32, "sh": 16, "sb": 8, "sd": 64}

    _ARITH: Dict[str, str] = {
        "addiu": "+", "addi": "+", "addu": "+", "add": "+",
        "subu":  "-", "sub":  "-",
        "and":   "&", "or":   "|", "xor":  "^",
        "sll":   "<<","srl":  ">>","sra":  ">>",
        "sllv":  "<<","srlv": ">>","srav": ">>",
        "sltu":  "<u","slt":  "<",
    }

    def __init__(self, tainted_params: Set[str], name_fn, plt: Dict[int, str]):
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt

        for r in self._ZERO_ALIASES:
            self._regs[r] = NativeVal("uint32_t", "0"); self._written.add(r)
        for i, r in enumerate(self._PARAM_REGS):
            nv = NativeVal("uint32_t", f"arg{i}", tainted=(r in tainted_params))
            self._regs[r] = nv; self._written.add(r); self._declared.add(f"arg{i}")
        for r in ("$sp", "$29", "$gp", "$28", "$fp", "$30", "$ra", "$31"):
            self._regs[r] = NativeVal("uint32_t", r)
            self._written.add(r); self._declared.add(r)

    def _alloc(self) -> str:
        n = f"v{self._var_n}"; self._var_n += 1; return n

    def _canon(self, reg: str) -> str:
        reg = reg.strip()
        return self._FROM_NUMERIC.get(reg, reg)

    def _read(self, reg: str) -> NativeVal:
        r = self._canon(reg)
        if r in self._ZERO_ALIASES:
            return NativeVal("uint32_t", "0")
        if r not in self._written:
            self._regs[r] = NativeVal("uint32_t", r); self._written.add(r)
        return self._regs.get(r, _UNKNOWN)

    def _write(self, reg: str, nv: NativeVal) -> str:
        r = self._canon(reg)
        if r in self._ZERO_ALIASES:
            return "0"
        old = self._regs.get(r)
        if old and r in self._written:
            e = old.expr
            if (e.startswith("v") and e[1:].isdigit()) or (e.startswith("arg") and e[3:].isdigit()):
                self._regs[r] = NativeVal(nv.ctype, e, nv.is_ptr, nv.tainted); return e
        vn = self._alloc()
        self._regs[r] = NativeVal(nv.ctype, vn, nv.is_ptr, nv.tainted)
        self._written.add(r); return vn

    def _decl(self, ctype: str, vn: str, expr: str, ann: str = "") -> str:
        if vn in self._declared:
            return f"{vn} = {expr};{ann}"
        self._declared.add(vn); return f"{ctype} {vn} = {expr};{ann}"

    def _tainted(self, *regs: str) -> bool:
        return any(self._regs.get(self._canon(r), _UNKNOWN).tainted for r in regs)

    @staticmethod
    def _parse_ops(op_str: str) -> List[str]:
        import re
        return [t.strip() for t in re.split(r",\s*", op_str.strip()) if t.strip()]

    @staticmethod
    def _parse_mem(tok: str):
        import re
        m = re.match(r"(-?\d+|0x[0-9a-fA-F]+)\((\$\w+)\)$", tok.strip())
        if m:
            return m.group(2), int(m.group(1), 0)
        return None, None

    @staticmethod
    def _find_hex_target(op_str: str) -> Optional[int]:
        import re
        hit = re.search(r"0x([0-9a-fA-F]+)", op_str)
        return int(hit.group(1), 16) if hit else None

    def emit(self, frame) -> str:
        import re
        m = frame.mnemonic.lower()
        op = frame.op_str.strip()

        # Return
        if m in ("jrc", "jr", "jrc16") and any(a in op for a in ("$ra", "$31")):
            return f"return {self._read(self._RETURN).expr};"

        # Call
        if m in self._CALLS:
            tgt = self._find_hex_target(op)
            callee = self._name_fn(tgt) if tgt is not None else op or "???"
            args_str = ", ".join(self._read(r).expr for r in self._PARAM_REGS)
            vn = self._alloc()
            is_t = self._tainted(*self._PARAM_REGS)
            self._regs[self._RETURN] = NativeVal("uint32_t", vn, tainted=is_t)
            ret_canon = self._canon(self._RETURN)
            self._written.add(ret_canon)
            ann = " /* TAINTED */" if is_t else ""
            return self._decl("uint32_t", vn, f"{callee}({args_str})", ann)

        # Unconditional jump
        if m in ("bc", "b"):
            tgt = self._find_hex_target(op)
            return f"goto loc_{tgt:x};" if tgt is not None else f"goto *{op};"

        # Conditional branches
        if m in self._JCC:
            tgt = self._find_hex_target(op)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            parts = self._parse_ops(op)
            if m.endswith("c") and len(parts) >= 2:
                a = self._read(parts[0]).expr
                try:
                    b = self._read(parts[1]).expr if parts[1].startswith("$") else _imm_expr(int(parts[1], 0))
                except (ValueError, IndexError):
                    b = parts[1] if len(parts) > 1 else "0"
                jop = {"beqc":"==","bnec":"!=","bltc":"<","bltuc":"<u",
                       "bgec":">=","bgeuc":">=u","beqzc":"==","bnezc":"!=",
                       "bltzc":"<","bgezc":">=","bgtzc":">","blezc":"<="}.get(m, "??")
                if "u" in jop:
                    cond_str = f"(unsigned){a} {jop[:-1]} (unsigned){b}"
                elif m.endswith("zc"):
                    cond_str = f"{a} {jop} 0"
                else:
                    cond_str = f"{a} {jop} {b}"
            else:
                r0 = parts[0] if parts and parts[0].startswith("$") else None
                a = self._read(r0).expr if r0 else "???"
                jop = {"beq":"==","bne":"!=","bltz":"<","bgez":">="}.get(m, "??")
                cond_str = f"{a} {jop} 0"
            return f"if ({cond_str}) goto {label};"

        # Load
        if m in self._LOAD_W:
            parts = self._parse_ops(op)
            if len(parts) >= 2:
                dst = parts[0]
                base, disp = self._parse_mem(parts[1])
                if base is not None:
                    bits, signed = self._LOAD_W[m]
                    ctype = _ctype_from_bits(bits, signed)
                    base_expr = self._read(base).expr
                    addr = f"({base_expr} + {_imm_expr(disp)})" if disp else base_expr
                    tainted = self._tainted(base)
                    expr = f"*({_ptr_cast(ctype)}{addr})"
                    vn = self._write(dst, NativeVal(ctype, expr, tainted=tainted))
                    return self._decl(ctype, vn, expr, " /* TAINTED */" if tainted else "")

        # Store
        if m in self._STORE_W:
            parts = self._parse_ops(op)
            if len(parts) >= 2:
                src = parts[0]
                base, disp = self._parse_mem(parts[1])
                if base is not None:
                    ctype = _ctype_from_bits(self._STORE_W[m])
                    base_expr = self._read(base).expr
                    addr = f"({base_expr} + {_imm_expr(disp)})" if disp else base_expr
                    return f"*({_ptr_cast(ctype)}{addr}) = {self._read(src).expr};{' /* TAINTED */' if self._tainted(src) else ''}"

        # Move
        if m in ("move", "mov"):
            parts = self._parse_ops(op)
            if len(parts) >= 2:
                dst, src = parts[0], parts[1]
                nv_src = self._read(src)
                vn = self._write(dst, NativeVal("uint32_t", nv_src.expr, tainted=nv_src.tainted))
                return self._decl("uint32_t", vn, nv_src.expr, " /* TAINTED */" if nv_src.tainted else "")

        # Load immediate
        if m in ("li", "li16"):
            parts = self._parse_ops(op)
            if len(parts) >= 2:
                dst = parts[0]
                try:
                    imm = int(parts[1], 0)
                    vn = self._write(dst, NativeVal("uint32_t", _imm_expr(imm)))
                    return self._decl("uint32_t", vn, _imm_expr(imm))
                except ValueError:
                    pass

        # Arithmetic
        if m in self._ARITH:
            parts = self._parse_ops(op)
            if len(parts) >= 2:
                dst = parts[0]
                src1 = parts[1] if parts[1].startswith("$") else dst
                a = self._read(src1).expr
                raw_b = parts[2] if len(parts) > 2 else (parts[1] if not parts[1].startswith("$") else None)
                if raw_b is None:
                    b, b_t = "0", False
                elif raw_b.startswith("$"):
                    nv2 = self._read(raw_b); b, b_t = nv2.expr, nv2.tainted
                else:
                    try:
                        b, b_t = _imm_expr(int(raw_b, 0)), False
                    except ValueError:
                        b, b_t = raw_b, False
                tainted = self._tainted(src1) or b_t
                op_sym = self._ARITH[m]
                if op_sym.endswith("u"):
                    expr = f"(unsigned){a} {op_sym[:-1]} (unsigned){b}"
                else:
                    expr = f"{a} {op_sym} {b}"
                vn = self._write(dst, NativeVal("uint32_t", expr, tainted=tainted))
                return self._decl("uint32_t", vn, expr, " /* TAINTED */" if tainted else "")


def _make_arm32_emit(name_fn, plt: Dict[int, str]):
    """Return an emit closure for ARM32/Thumb-2 (AAPCS: r0-r3 args, r0 return)."""
    _CALL = frozenset({"bl", "blx", "blxns"})
    _var_n = [0]

    def _alloc():
        n = f"v{_var_n[0]}"
        _var_n[0] += 1
        return n

    def emit(insn) -> str:
        m = insn.mnemonic.lower()

        # Return: bx lr
        if m == "bx" and insn.reg(0) == "lr":
            return "return r0;"
        # pop {pc} — register list containing pc
        if m == "pop":
            rl = getattr(insn, "reglist", lambda i: None)(0)
            if rl and "pc" in getattr(rl, "regs", []):
                return "return r0;"

        # Call
        if m in _CALL:
            tgt = insn.imm(0)
            if tgt is not None:
                callee = name_fn(tgt)
            elif insn.reg(0):
                callee = f"*{insn.reg(0)}"
            else:
                callee = "???"
            vn = _alloc()
            return f"uint32_t {vn} = {callee}(r0, r1, r2, r3);"

        # Unconditional branch: b with no condition code (or al)
        if m == "b":
            cond = getattr(insn, "cond", None)
            if cond is None or cond == "al":
                tgt = insn.imm(0)
                return f"goto loc_{tgt:x};" if tgt is not None else f"goto *{insn.reg(0) or '???'};"

        # Conditional branch
        if m == "b":
            cond = getattr(insn, "cond", "??")
            tgt = insn.imm(0)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            return f"if (/* {cond} */) goto {label};"

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"

    return emit


def _make_mips_emit(bits: int, name_fn, plt: Dict[int, str]):
    """Return an emit closure for MIPS32 (o32) or MIPS64 (n64)."""
    _CALL = frozenset({"jal", "jalr", "bal", "bltzal", "bgezal"})
    _JCC = frozenset({"beq","bne","blt","bge","bltu","bgeu",
                      "beqz","bnez","bgtz","bltz","bgez","blez",
                      "beql","bnel","bgezl","bltzl"})
    _param = ("$a0","$a1","$a2","$a3") if bits == 32 else tuple(f"${i}" for i in range(4, 12))
    _ret = "$v0"
    _var_n = [0]

    def _alloc():
        n = f"v{_var_n[0]}"
        _var_n[0] += 1
        return n

    def emit(insn) -> str:
        m = insn.mnemonic.lower()

        # Return: jr $ra or jr $31
        if m in ("jr", "jr.hb") and insn.reg(0) in ("$ra", "$31"):
            return f"return {_ret};"

        # Call
        if m in _CALL:
            tgt = insn.imm(0)
            if tgt is not None:
                callee = name_fn(tgt)
            elif insn.reg(0):
                callee = f"*{insn.reg(0)}"
            else:
                callee = "???"
            vn = _alloc()
            args = ", ".join(_param)
            return f"uint64_t {vn} = {callee}({args});"

        # Unconditional jump
        if m in ("j", "b"):
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else f"goto *{insn.reg(0) or '???'};"

        # Conditional branches
        if m in _JCC:
            tgt = insn.imm(0) or insn.imm(1) or insn.imm(2)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            ops_str = _ablation_ops_str(insn)
            return f"if (/* {m} {ops_str} */) goto {label};"

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"

    return emit


def _make_ppc_emit(name_fn, plt: Dict[int, str]):
    """Return an emit closure for PPC32/PPC64 (SysV/ELFv2: r3-r10 args, r3 return)."""
    _CALL = frozenset({"bl", "bla", "bctrl", "blrl", "bcl", "bcla"})
    _JCC = frozenset({"bc","bca","bcl","bcla",
                      "beq","bne","blt","bgt","ble","bge","bun","bnu",
                      "beqlr","bnelr","bltlr","bgtlr","blelr","bgelr",
                      "bdnz","bdz"})
    _param = tuple(f"r{i}" for i in range(3, 11))
    _var_n = [0]

    def _alloc():
        n = f"v{_var_n[0]}"
        _var_n[0] += 1
        return n

    def emit(insn) -> str:
        m = insn.mnemonic.lower()

        # Return
        if m in ("blr", "blrl"):
            return "return r3;"

        # Call
        if m in _CALL:
            tgt = insn.imm(0)
            if tgt is not None:
                callee = name_fn(tgt)
            else:
                callee = "*(ctr)" if "ctr" in m else "???"
            vn = _alloc()
            args = ", ".join(_param)
            return f"uint64_t {vn} = {callee}({args});"

        # Unconditional branch
        if m in ("b", "ba"):
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else "goto *???;"

        # Conditional branches
        if m in _JCC:
            tgt = insn.imm(0) or insn.imm(1) or insn.imm(2)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            return f"if (/* {m} */) goto {label};"

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"

    return emit


def _make_riscv_emit(name_fn, plt: Dict[int, str]):
    """Return an emit closure for RISC-V 32/64 (psABI: a0-a7 args, a0 return)."""
    _CALL = frozenset({"call", "tail"})
    _JCC = frozenset({"beq","bne","blt","bge","bltu","bgeu","beqz","bnez"})
    _param = tuple(f"a{i}" for i in range(8))
    _var_n = [0]

    def _alloc():
        n = f"v{_var_n[0]}"
        _var_n[0] += 1
        return n

    def _is_call_jalr(insn) -> bool:
        # jalr ra, rj, 0 — direct call through register
        return (insn.mnemonic.lower() == "jalr"
                and insn.reg(0) in ("ra", "x1"))

    def _is_return(insn) -> bool:
        m = insn.mnemonic.lower()
        if m == "ret":
            return True
        # jalr zero/x0, ra/x1, 0 — canonical psABI return
        if m == "jalr" and insn.reg(0) in ("zero", "x0") and insn.reg(1) in ("ra", "x1"):
            return True
        return False

    def emit(insn) -> str:
        m = insn.mnemonic.lower()

        if _is_return(insn):
            return "return a0;"

        if m in _CALL:
            tgt = insn.imm(0) or insn.imm(1)
            callee = name_fn(tgt) if tgt is not None else "???"
            vn = _alloc()
            args = ", ".join(_param)
            return f"uint64_t {vn} = {callee}({args});"

        if _is_call_jalr(insn):
            reg = insn.reg(1) or "???"
            vn = _alloc()
            args = ", ".join(_param)
            return f"uint64_t {vn} = (*{reg})({args});"

        # Unconditional jump: j pseudo (jal x0, offset)
        if m in ("j",):
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else "goto *???;"

        if m == "jal" and insn.reg(0) in ("ra", "x1"):
            tgt = insn.imm(1) or insn.imm(0)
            callee = name_fn(tgt) if tgt is not None else "???"
            vn = _alloc()
            args = ", ".join(_param)
            return f"uint64_t {vn} = {callee}({args});"

        if m in _JCC:
            tgt = insn.imm(0) or insn.imm(1) or insn.imm(2)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            ops_str = _ablation_ops_str(insn)
            return f"if (/* {m} {ops_str} */) goto {label};"

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"

    return emit


def _make_la64_emit(name_fn, plt: Dict[int, str]):
    """Return an emit closure for LoongArch64 (lp64: $a0-$a7 args, $a0 return)."""
    _JCC = frozenset({"beqz","bnez","beq","bne","blt","bge","bltu","bgeu","bceqz","bcnez"})
    _param = tuple(f"$a{i}" for i in range(8))
    _var_n = [0]

    def _alloc():
        n = f"v{_var_n[0]}"
        _var_n[0] += 1
        return n

    def _is_return(insn) -> bool:
        if insn.mnemonic.lower() != "jirl":
            return False
        r0 = insn.reg(0)
        r1 = insn.reg(1)
        # jirl $zero, $ra, 0 — canonical return
        return r0 in ("$zero", "$r0") and r1 in ("$ra", "$r1")

    def _is_call(insn) -> bool:
        m = insn.mnemonic.lower()
        if m == "bl":
            return True
        if m == "jirl" and insn.reg(0) in ("$ra", "$r1"):
            return True
        return False

    def emit(insn) -> str:
        m = insn.mnemonic.lower()

        if _is_return(insn):
            return "return $a0;"

        if _is_call(insn):
            tgt = insn.imm(0) or insn.imm(1)
            if tgt is not None:
                callee = name_fn(tgt)
            elif m == "jirl":
                callee = f"*{insn.reg(1) or '???'}"
            else:
                callee = "???"
            vn = _alloc()
            args = ", ".join(_param)
            return f"uint64_t {vn} = {callee}({args});"

        if m == "b":
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else "goto *???;"

        if m in _JCC:
            tgt = insn.imm(0) or insn.imm(1) or insn.imm(2)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            ops_str = _ablation_ops_str(insn)
            return f"if (/* {m} {ops_str} */) goto {label};"

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"

    return emit


def _make_nanomips_emit(name_fn, plt: Dict[int, str]):
    """Return an emit closure for nanoMIPS (o32-compatible: $a0-$a3 args, $v0 return).

    NanoFrame has .va, .mnemonic, .op_str but no structured .ops.
    """
    _CALL = frozenset({"balc", "jalrc", "jal", "bgezalc", "bltzalc"})
    _JCC = frozenset({"beqc","bnec","bltc","bltuc","bgec","bgeuc",
                      "beqzc","bnezc","bltzc","bgezc","bgtzc","blezc",
                      "beq","bne","bltz","bgez"})
    _var_n = [0]

    def _alloc():
        n = f"v{_var_n[0]}"
        _var_n[0] += 1
        return n

    def emit(frame) -> str:
        m = frame.mnemonic.lower()
        op = frame.op_str

        # Return: jrc $ra or jr $ra
        if m in ("jrc", "jr") and "$ra" in op:
            return "return $v0;"

        # Call
        if m in _CALL:
            # Try to extract target VA from op_str (decimal or hex)
            import re
            hit = re.search(r"0x([0-9a-fA-F]+)", op)
            if hit:
                tgt = int(hit.group(1), 16)
                callee = name_fn(tgt)
            else:
                callee = op.strip() or "???"
            vn = _alloc()
            return f"uint32_t {vn} = {callee}($a0, $a1, $a2, $a3);"

        # Unconditional jump
        if m in ("bc", "b"):
            import re
            hit = re.search(r"0x([0-9a-fA-F]+)", op)
            tgt = int(hit.group(1), 16) if hit else None
            return f"goto loc_{tgt:x};" if tgt is not None else f"goto *{op.strip()};"

        # Conditional branches
        if m in _JCC:
            import re
            hit = re.search(r"0x([0-9a-fA-F]+)", op)
            tgt = int(hit.group(1), 16) if hit else None
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            return f"if (/* {m} {op} */) goto {label};"

        return f"// {frame.mnemonic} {op}"

    return emit


def _make_arc_emit(name_fn, plt: Dict[int, str]):
    """Return an emit closure for ARC EM/HS (ARC GNU ABI: r0-r7 args, r0 return)."""
    _CALL = frozenset({"bl", "jl", "bl.d"})
    _JCC = frozenset({"beq","bne","blt","bgt","ble","bge","blo","bhs","bhi","bls",
                      "brk","bbit0","bbit1","breq","brne","brlt","brge","brlte","brgte"})
    _param = tuple(f"r{i}" for i in range(8))
    _var_n = [0]

    def _alloc():
        n = f"v{_var_n[0]}"
        _var_n[0] += 1
        return n

    def emit(insn) -> str:
        m = insn.mnemonic.lower()

        # Return: j [blink]
        if m in ("j", "j.d") and insn.reg(0) == "blink":
            return "return r0;"

        # Call
        if m in _CALL:
            tgt = insn.imm(0)
            if tgt is not None:
                callee = name_fn(tgt)
            elif insn.reg(0):
                callee = f"*[{insn.reg(0)}]"
            else:
                callee = "???"
            vn = _alloc()
            args = ", ".join(_param)
            return f"uint32_t {vn} = {callee}({args});"

        # Unconditional branch
        if m in ("b", "b.d"):
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else f"goto *{insn.reg(0) or '???'};"

        # Conditional branches
        if m in _JCC:
            tgt = insn.imm(0) or insn.imm(1)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            ops_str = _ablation_ops_str(insn)
            return f"if (/* {m} {ops_str} */) goto {label};"

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"

    return emit


def _make_v850_emit(name_fn, plt: Dict[int, str]):
    """Return an emit closure for V850/RH850 (CC-RH ABI: r6-r9 args, r10 return)."""
    _CALL = frozenset({"jarl", "call"})
    _JCC = frozenset({
        "bv","bl","be","bnh","bn","br","blt","ble",
        "bnv","bnl","bnz","bh","bp","bsa","bge","bgt",
        "bc","bnc","bt","bf",
    })
    _param = ("r6", "r7", "r8", "r9")
    _var_n = [0]

    def _alloc():
        n = f"v{_var_n[0]}"
        _var_n[0] += 1
        return n

    def emit(insn) -> str:
        m = insn.mnemonic.lower()

        # Return: jmp [lp] — indirect jump through link pointer register
        if m == "jmp" and insn.reg(0) == "lp":
            return "return r10;"

        # Call
        if m in _CALL:
            tgt = insn.imm(0) or insn.imm(1)
            if tgt is not None:
                callee = name_fn(tgt)
            elif insn.reg(0):
                callee = f"*{insn.reg(0)}"
            else:
                callee = "???"
            vn = _alloc()
            args = ", ".join(_param)
            return f"uint32_t {vn} = {callee}({args});"

        # Conditional branches
        if m in _JCC:
            tgt = insn.imm(0)
            label = f"loc_{tgt:x}" if tgt is not None else "???"
            return f"if (/* {m} */) goto {label};"

        # Unconditional jump
        if m == "jr":
            tgt = insn.imm(0)
            return f"goto loc_{tgt:x};" if tgt is not None else f"goto *{insn.reg(0) or '???'};"

        return f"// {insn.mnemonic} {_ablation_ops_str(insn)}"

    return emit


# ── _SH2aState ─────────────────────────────────────────────────────────────────


class _SH2aState:
    """Per-function register-tracking state for SH-2A (Renesas SuperH ABI).

    Params: R4-R7 (arg0-arg3). Return: R0. Stack: R15. Link register: PR.
    SH2aInsn has pre-decoded .rd, .rs, .imm, .target, .insn_type fields so
    no regex operand parsing is needed — dispatch is on insn_type directly.
    """

    _PARAM_REGS = ("r4", "r5", "r6", "r7")
    _RETURN = "r0"
    _SP = "r15"

    def __init__(self, tainted_params: Set[str], name_fn, plt: Dict[int, str]):
        self._regs: Dict[str, NativeVal] = {}
        self._written: Set[str] = set()
        self._declared: Set[str] = set()
        self._var_n = 0
        self._name_fn = name_fn
        self._plt = plt

        for i in range(16):
            r = f"r{i}"
            self._regs[r] = NativeVal("uint32_t", r)
            self._written.add(r); self._declared.add(r)

        for i, r in enumerate(self._PARAM_REGS):
            nv = NativeVal("uint32_t", f"arg{i}", tainted=(r in tainted_params))
            self._regs[r] = nv
            self._declared.discard(r); self._declared.add(f"arg{i}")

        self._regs[self._SP] = NativeVal("uint32_t", "sp", is_ptr=True)
        self._declared.add("sp"); self._declared.discard(self._SP)

    def _alloc(self) -> str:
        n = f"v{self._var_n}"; self._var_n += 1; return n

    def _rname(self, n: Optional[int]) -> str:
        return f"r{n}" if n is not None else "???"

    def _read(self, r: str) -> NativeVal:
        return self._regs.get(r, NativeVal("uint32_t", r))

    def _write(self, r: str, nv: NativeVal) -> str:
        old = self._regs.get(r)
        if old:
            e = old.expr
            if (e.startswith("v") and e[1:].isdigit()) or \
               (e.startswith("arg") and e[3:].isdigit()):
                self._regs[r] = NativeVal(nv.ctype, e, nv.is_ptr, nv.tainted)
                return e
        vn = self._alloc()
        self._regs[r] = NativeVal(nv.ctype, vn, nv.is_ptr, nv.tainted)
        self._written.add(r)
        return vn

    def _decl(self, ctype: str, vn: str, expr: str, ann: str = "") -> str:
        if vn in self._declared:
            return f"{vn} = {expr};{ann}"
        self._declared.add(vn); return f"{ctype} {vn} = {expr};{ann}"

    def _tainted(self, *rs: str) -> bool:
        return any(self._regs.get(r, _UNKNOWN).tainted for r in rs)

    def _bits_from_mnem(self, mnemonic: str) -> int:
        if mnemonic.endswith(".b"):
            return 8
        if mnemonic.endswith(".w"):
            return 16
        return 32

    def emit(self, insn: object) -> str:
        itype = insn.insn_type  # type: ignore[attr-defined]
        m = insn.mnemonic.lower()  # type: ignore[attr-defined]

        if itype in ("LR_SAVE", "LR_RESTORE"):
            return f"// {m}"

        if itype == "RETURN":
            return f"return {self._read(self._RETURN).expr};"

        if itype == "CALL":
            tgt = insn.target  # type: ignore[attr-defined]
            rs = insn.rs  # type: ignore[attr-defined]
            if tgt is not None:
                callee = self._name_fn(tgt)
            elif rs is not None:
                callee = f"*{self._read(self._rname(rs)).expr}"
            else:
                callee = "???"
            args_str = ", ".join(self._read(r).expr for r in self._PARAM_REGS)
            vn = self._alloc()
            is_t = self._tainted(*self._PARAM_REGS)
            self._regs[self._RETURN] = NativeVal("uint32_t", vn, tainted=is_t)
            self._written.add(self._RETURN)
            ann = " /* TAINTED */" if is_t else ""
            return self._decl("uint32_t", vn, f"{callee}({args_str})", ann)

        if itype == "BRANCH":
            tgt = insn.target  # type: ignore[attr-defined]
            rs = insn.rs  # type: ignore[attr-defined]
            if tgt is not None:
                if m in ("bra", "braf"):
                    return f"goto loc_{tgt:x};"
                cond = "T" if m.startswith("bt") else "!T"
                return f"if ({cond}) goto loc_{tgt:x};"
            if rs is not None:
                return f"goto *{self._read(self._rname(rs)).expr};"
            return "goto *???;"

        if itype == "LOAD":
            rd = insn.rd  # type: ignore[attr-defined]
            rs = insn.rs  # type: ignore[attr-defined]
            imm = insn.imm  # type: ignore[attr-defined]
            if rd is None or rs is None:
                return f"// {m} ???"
            bits = self._bits_from_mnem(m)
            ctype = _ctype_from_bits(bits, signed=False)
            base_expr = self._read(self._rname(rs)).expr
            addr = f"{base_expr} + {imm:#x}" if imm else base_expr
            tainted = self._tainted(self._rname(rs))
            expr = f"*({_ptr_cast(ctype)}{addr})"
            vn = self._write(self._rname(rd), NativeVal(ctype, expr, tainted=tainted))
            return self._decl(ctype, vn, expr, " /* TAINTED */" if tainted else "")

        if itype == "STORE":
            rd = insn.rd  # type: ignore[attr-defined]
            rs = insn.rs  # type: ignore[attr-defined]
            imm = insn.imm  # type: ignore[attr-defined]
            if rd is None or rs is None:
                return f"// {m} ???"
            bits = self._bits_from_mnem(m)
            ctype = _ctype_from_bits(bits, signed=False)
            base_expr = self._read(self._rname(rd)).expr
            addr = f"{base_expr} + {imm:#x}" if imm else base_expr
            src_expr = self._read(self._rname(rs)).expr
            ann = " /* TAINTED */" if self._tainted(self._rname(rs)) else ""
            return f"*({_ptr_cast(ctype)}{addr}) = {src_expr};{ann}"

        # MISC — emit assignment when operands are present
        rd = insn.rd  # type: ignore[attr-defined]
        rs = insn.rs  # type: ignore[attr-defined]
        imm = insn.imm  # type: ignore[attr-defined]
        if rd is not None and imm is not None and rs is None:
            rn = self._rname(rd)
            vn = self._write(rn, NativeVal("uint32_t", _imm_expr(imm)))
            return self._decl("uint32_t", vn, _imm_expr(imm))
        if rd is not None and rs is not None:
            rn, sn = self._rname(rd), self._rname(rs)
            src_nv = self._read(sn)
            vn = self._write(rn, NativeVal("uint32_t", src_nv.expr, tainted=src_nv.tainted))
            ann = " /* TAINTED */" if src_nv.tainted else ""
            return self._decl("uint32_t", vn, src_nv.expr, ann)
        return f"// {m}"
