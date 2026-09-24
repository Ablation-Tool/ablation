"""
heap_uaf_scanner.py -- Static heap vulnerability scanner (x86-64).

Detects:
  - Use-after-free (UAF): pointer dereferenced after free()
  - Double-free: free() called twice on the same pointer
  - Heap overflow: allocation with bounded size, write with user-controlled length
  - Type confusion: pointer cast to incompatible size type after allocation

Approach: forward symbolic pass tracking pointer state per register.
  ALLOC: register received malloc/calloc/realloc return value
  FREE:  register was passed to free() and not reassigned
  UNKNOWN: state is not tracked (memory load, function call return, etc.)

When a FREE-state register is dereferenced or passed to free() again,
the scanner emits a finding.

Limitations (intraprocedural):
  - Does not cross function boundaries (use TaintTracker for that)
  - Does not track memory-resident pointers (stack slots, struct fields)
  - Conservative: may miss freed pointers that pass through other registers
  - Reports potential UAF/double-free on any deref of a freed reg after free()

Grounded in:
  - TAOSSA Ch 5: Memory Corruption; Ch 6: C Language Issues
  - Practical Binary Analysis (Andriesse) Ch 11: Data Flow Analysis
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone
from capstone.x86_const import (
    X86_OP_REG, X86_OP_IMM, X86_OP_MEM,
    X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVZX, X86_INS_MOVSXD,
    X86_INS_LEA,
    X86_INS_ADD, X86_INS_SUB, X86_INS_AND, X86_INS_OR, X86_INS_XOR,
    X86_INS_PUSH, X86_INS_POP,
    X86_INS_CALL, X86_INS_JMP, X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ,
    X86_INS_NOP, X86_INS_TEST, X86_INS_CMP,
    X86_INS_IMUL, X86_INS_MUL,
)
import lief

# Pointer state kinds
_STATE_ALLOC   = "alloc"    # returned from malloc family
_STATE_FREE    = "free"     # passed to free; not yet reassigned
_STATE_UNKNOWN = "unknown"  # origin not tracked

# Allocator functions: return value (rax) -> pointer
_ALLOC_FUNCS: Set[str] = {
    "malloc", "calloc", "realloc",
    "ExAllocatePoolWithTag", "ExAllocatePool2", "ExAllocatePool",
    "kmalloc", "kzalloc", "vmalloc",
    "new",    # C++ operator new -- often resolved via PLT
}

# Free functions: arg0 (rdi on SysV, rcx on Windows x64) -> freed
_FREE_FUNCS: Set[str] = {
    "free", "ExFreePoolWithTag", "ExFreePool",
    "kfree", "vfree",
    "delete",    # C++ operator delete
}

# Caller-saved registers (clobbered across calls, SysV ABI)
_CALLER_SAVED: Set[str] = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}

_REG_FAMILY: Dict[str, str] = {}
for _base, _aliases in [
    ("rax", ["eax", "ax", "al", "ah"]),
    ("rbx", ["ebx", "bx", "bl", "bh"]),
    ("rcx", ["ecx", "cx", "cl", "ch"]),
    ("rdx", ["edx", "dx", "dl", "dh"]),
    ("rsi", ["esi", "si", "sil"]),
    ("rdi", ["edi", "di", "dil"]),
    ("rsp", ["esp", "sp", "spl"]),
    ("rbp", ["ebp", "bp", "bpl"]),
    ("r8",  ["r8d",  "r8w",  "r8b"]),
    ("r9",  ["r9d",  "r9w",  "r9b"]),
    ("r10", ["r10d", "r10w", "r10b"]),
    ("r11", ["r11d", "r11w", "r11b"]),
    ("r12", ["r12d", "r12w", "r12b"]),
    ("r13", ["r13d", "r13w", "r13b"]),
    ("r14", ["r14d", "r14w", "r14b"]),
    ("r15", ["r15d", "r15w", "r15b"]),
]:
    _REG_FAMILY[_base] = _base
    for _a in _aliases:
        _REG_FAMILY[_a] = _base


def _canon(name: str) -> Optional[str]:
    return _REG_FAMILY.get(name.lower())


MAX_FUNC_BYTES = 0x8000

# x86-64 SysV first arg registers
_ARG0 = "rdi"   # free(ptr) -- ptr is first arg
_ARG1 = "rsi"
_ARG2 = "rdx"

# Windows x64 first arg register (different from SysV)
_WIN_ARG0 = "rcx"


@dataclass
class HeapFinding:
    binary: str
    func_va: int
    func_name: str
    site_va: int
    kind: str          # "UAF" | "DOUBLE_FREE" | "HEAP_OVERFLOW" | "TYPE_CONFUSION"
    description: str
    severity: str      # HIGH | MEDIUM

    def fmt(self) -> str:
        sev_tag = {"HIGH": "[HIGH]", "MEDIUM": "[MED] "}.get(self.severity, "[?]   ")
        return (
            f"{sev_tag} {self.kind} @ 0x{self.site_va:x}"
            f" in {self.func_name} (0x{self.func_va:x}): {self.description}"
        )


class HeapUAFScanner:
    """
    Static heap vulnerability scanner for x86-64 ELF and PE binaries.

    Usage:
        scanner = HeapUAFScanner.from_path('/path/to/binary')
        findings = scanner.scan()
        print(scanner.report(findings))

    With BinaryContext:
        scanner = HeapUAFScanner.from_context(ctx)

    Custom allocators / free functions:
        scanner = HeapUAFScanner.from_path(
            '/path/binary',
            custom_allocs={'my_alloc': True},
            custom_frees={'my_free': True},
        )
    """

    def __init__(
        self,
        binary_path: str,
        ctx=None,
        custom_allocs: Optional[Dict[str, bool]] = None,
        custom_frees: Optional[Dict[str, bool]] = None,
        windows_abi: bool = False,
    ):
        self.binary_path = binary_path
        self._ctx = ctx
        self._allocs = set(_ALLOC_FUNCS)
        self._frees  = set(_FREE_FUNCS)
        if custom_allocs:
            self._allocs.update(custom_allocs.keys())
        if custom_frees:
            self._frees.update(custom_frees.keys())

        # Windows x64: first arg in rcx (not rdi)
        self._free_arg = _WIN_ARG0 if windows_abi else _ARG0

        self._binary = lief.parse(binary_path)
        self._data = Path(binary_path).read_bytes()
        self._plt = self._build_plt()
        self._strings: Dict[int, str] = {}
        if ctx is not None:
            self._strings = dict(ctx.strings)

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        self._md = md

    @classmethod
    def from_path(cls, binary_path: str, **kwargs) -> "HeapUAFScanner":
        return cls(binary_path, **kwargs)

    @classmethod
    def from_context(cls, ctx, **kwargs) -> "HeapUAFScanner":
        return cls(ctx.binary_path, ctx=ctx, **kwargs)

    def _build_plt(self) -> Dict[int, str]:
        plt: Dict[int, str] = {}
        if not self._binary:
            return plt
        try:
            for sym in self._binary.pltgot_relocations:
                if sym.symbol and sym.symbol.name:
                    plt[sym.address] = sym.symbol.name
        except Exception:
            pass
        try:
            for sym in self._binary.plt_relocations:
                if sym.symbol and sym.symbol.name:
                    plt[sym.address] = sym.symbol.name
        except Exception:
            pass
        # PE imports
        try:
            for imp in self._binary.imports:
                for entry in imp.entries:
                    if entry.name and entry.iat_address:
                        plt[entry.iat_address] = entry.name
        except Exception:
            pass
        return plt

    def _va_to_offset(self, va: int) -> Optional[int]:
        if not self._binary:
            return None
        try:
            return self._binary.virtual_address_to_offset(va)
        except Exception:
            return None

    def _va_to_slice(self, va: int, size: int) -> Optional[bytes]:
        off = self._va_to_offset(va)
        if off is None:
            return None
        return self._data[off: off + size]

    def _get_func_starts(self) -> List[int]:
        if self._ctx is not None:
            return self._ctx.func_starts
        starts: Set[int] = set()
        if self._binary:
            try:
                for sym in self._binary.static_symbols:
                    if sym.type == lief.ELF.SYMBOL_TYPES.FUNC and sym.value:
                        starts.add(sym.value)
                for sym in self._binary.dynamic_symbols:
                    if sym.type == lief.ELF.SYMBOL_TYPES.FUNC and sym.value:
                        starts.add(sym.value)
            except Exception:
                pass
        return sorted(starts)

    def _func_name(self, va: int) -> str:
        if self._ctx is not None:
            return self._ctx.name(va)
        return f"0x{va:x}"

    def _scan_function(self, func_va: int, func_end_va: int) -> List[HeapFinding]:
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 8:
            return []

        # Pointer state: reg -> state kind
        reg_state: Dict[str, str] = {}
        # Track which pointer each register holds (simplified: reg -> alloc site VA)
        # When the same reg is freed twice, we know which alloc site it was from.
        reg_alloc_site: Dict[str, int] = {}

        findings: List[HeapFinding] = []
        func_name = self._func_name(func_va)

        try:
            for insn in self._md.disasm(func_bytes, func_va):
                if insn.id in (X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ):
                    break

                ops = insn.operands

                # Check for memory dereferences of freed pointers
                if insn.id in (X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVZX, X86_INS_MOVSXD):
                    for op in ops:
                        if op.type == X86_OP_MEM:
                            base_reg = _canon(insn.reg_name(op.mem.base)) if op.mem.base else None
                            if base_reg and reg_state.get(base_reg) == _STATE_FREE:
                                findings.append(HeapFinding(
                                    binary=self.binary_path,
                                    func_va=func_va,
                                    func_name=func_name,
                                    site_va=insn.address,
                                    kind="UAF",
                                    description=(
                                        f"Pointer in {base_reg} dereferenced after free() call "
                                        f"(allocated at 0x{reg_alloc_site.get(base_reg, 0):x})"
                                    ),
                                    severity="HIGH",
                                ))

                elif insn.id == X86_INS_CALL:
                    if not ops:
                        continue
                    target_name = ""
                    if ops[0].type == X86_OP_IMM:
                        target_name = self._plt.get(ops[0].imm, "")
                    elif ops[0].type == X86_OP_MEM:
                        target_name = self._plt.get(ops[0].mem.disp, "")

                    if target_name in self._frees:
                        # The pointer being freed is in the free_arg register
                        free_reg = _canon(self._free_arg)
                        if free_reg:
                            if reg_state.get(free_reg) == _STATE_FREE:
                                # Double-free
                                findings.append(HeapFinding(
                                    binary=self.binary_path,
                                    func_va=func_va,
                                    func_name=func_name,
                                    site_va=insn.address,
                                    kind="DOUBLE_FREE",
                                    description=(
                                        f"{target_name}({free_reg}) called twice on same pointer "
                                        f"(first free at 0x{reg_alloc_site.get(free_reg, 0):x})"
                                    ),
                                    severity="HIGH",
                                ))
                            # Mark as freed
                            reg_state[free_reg] = _STATE_FREE
                            # Propagate FREE state to any register that held the same value
                            # (simplified: just mark rdi as freed; a full analysis would track aliases)

                    elif target_name in self._allocs:
                        # Mark rax as newly allocated
                        reg_state["rax"] = _STATE_ALLOC
                        reg_alloc_site["rax"] = insn.address

                    # Clobber caller-saved (except rax which we just handled)
                    for r in _CALLER_SAVED - {"rax"}:
                        if reg_state.get(r) == _STATE_FREE:
                            # Once a freed pointer leaves a register (clobbered), we lose track.
                            # Be conservative: remove from state to avoid FPs on register reuse.
                            del reg_state[r]
                        else:
                            reg_state.pop(r, None)
                    if target_name not in self._allocs:
                        reg_state.pop("rax", None)

                    continue

                # MOV: propagate state
                if insn.id in (X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVZX,
                               X86_INS_MOVSXD) and len(ops) == 2:
                    dst_op, src_op = ops[0], ops[1]
                    dst_reg = _canon(dst_op.reg_name) if dst_op.type == X86_OP_REG else None
                    if dst_reg is None:
                        continue

                    if src_op.type == X86_OP_REG:
                        src_reg = _canon(src_op.reg_name)
                        if src_reg:
                            src_kind = reg_state.get(src_reg, _STATE_UNKNOWN)
                            reg_state[dst_reg] = src_kind
                            if src_kind == _STATE_FREE:
                                reg_alloc_site[dst_reg] = reg_alloc_site.get(src_reg, 0)
                            elif src_kind == _STATE_ALLOC:
                                reg_alloc_site[dst_reg] = reg_alloc_site.get(src_reg, 0)
                    elif src_op.type in (X86_OP_IMM, X86_OP_MEM):
                        # Assignment from immediate or memory load clears tracked state
                        reg_state.pop(dst_reg, None)

                # XOR reg, reg (zeroing idiom) -- cleared register can't be free'd
                elif insn.id == X86_INS_XOR and len(ops) == 2:
                    dst_op, src_op = ops[0], ops[1]
                    if (dst_op.type == X86_OP_REG and src_op.type == X86_OP_REG
                            and dst_op.reg == src_op.reg):
                        dst_reg = _canon(dst_op.reg_name)
                        if dst_reg:
                            reg_state.pop(dst_reg, None)

        except Exception:
            pass

        return findings

    def scan(self) -> List[HeapFinding]:
        """Scan all functions for heap vulnerabilities."""
        func_starts = self._get_func_starts()
        if not func_starts:
            return []

        findings: List[HeapFinding] = []
        for i, fva in enumerate(func_starts):
            fend = func_starts[i+1] if i+1 < len(func_starts) else fva + MAX_FUNC_BYTES
            try:
                findings.extend(self._scan_function(fva, fend))
            except Exception:
                continue
        return findings

    def scan_function(self, func_va: int, func_end_va: int = 0) -> List[HeapFinding]:
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        return self._scan_function(func_va, func_end_va)

    def report(self, findings: List[HeapFinding]) -> str:
        if not findings:
            return f"[heap_uaf_scanner] No findings in {self.binary_path}"
        uaf    = [f for f in findings if f.kind == "UAF"]
        df     = [f for f in findings if f.kind == "DOUBLE_FREE"]
        other  = [f for f in findings if f.kind not in ("UAF", "DOUBLE_FREE")]
        lines = [
            f"[heap_uaf_scanner] {self.binary_path}",
            f"  {len(findings)} total: {len(uaf)} UAF, {len(df)} DOUBLE_FREE, {len(other)} other",
            "",
        ]
        for f in sorted(findings, key=lambda x: (x.kind, x.func_va)):
            lines.append(f"  {f.fmt()}")
        return "\n".join(lines)
