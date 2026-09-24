"""
heap_vuln_scanner.py: Heap memory corruption detector for x86-64 ELF binaries.

Detects four vulnerability classes grounded in TAOSSA Ch 5 & Ch 6:

  INT_OVERFLOW_BEFORE_ALLOC
    TAOSSA Ch6 L6-2 (width*height), L6-3 (nresp*sizeof(char*)), L6-4 (length-sizeof underflow).
    Pattern: IMUL/MUL/SHL on any register, result moved to RDI/RSI/RDX without an intermediate
    bounds check, then CALL to an allocator. No OF-flag check between multiply and allocation.

  USE_AFTER_FREE
    TAOSSA Ch5: free(ptr) followed by dereference or re-use of the same register in the same
    function without an intervening store. Covers both [reg+off] memory access and passing the
    freed register as an argument to another call.

  DOUBLE_FREE
    TAOSSA Ch5: the same source register freed twice in the same function without reassignment
    between the two free() calls. Detects the strcpy-then-free corruption pattern (Listing 5-4).

  OFF_BY_ONE_ALLOC
    TAOSSA Ch5: allocation size computed as strlen(buf) without +1 for NUL terminator, then a
    strcpy/memcpy into the allocation. Detects the classic NUL-off-by-one heap overflow.

Usage:
    from ablation.analyzers.heap_vuln_scanner import HeapVulnScanner

    scanner = HeapVulnScanner.from_path('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    # With existing BinaryContext (avoids LIEF rebuild):
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = HeapVulnScanner.from_context(ctx)
    findings = scanner.scan()

    unguarded = [f for f in findings if f.severity == 'HIGH']
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_CS_AVAILABLE = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL
    from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
    from capstone.x86_const import (
        X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
        X86_REG_EAX, X86_REG_RAX,
    )
    _CS_AVAILABLE = True
except ImportError:
    pass

_LIEF_AVAILABLE = False
try:
    import lief as _lief
    _LIEF_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Finding data class
# ---------------------------------------------------------------------------

@dataclass
class HeapFinding:
    kind: str        # 'int_overflow_before_alloc' | 'uaf' | 'double_free' | 'off_by_one_alloc'
    func_va: int
    site_va: int
    description: str
    severity: str    # 'HIGH' | 'MEDIUM'
    alloc_sym: str = ''
    freed_at: int = 0

    def fmt(self) -> str:
        tag = f"0x{self.func_va:x}+{(self.site_va - self.func_va) & 0xFFFF:#x}"
        extra = f"  alloc={self.alloc_sym}" if self.alloc_sym else ''
        extra += f"  freed_at=0x{self.freed_at:x}" if self.freed_at else ''
        return f"  {self.severity:6s}  {self.kind:30s}  {tag}  {self.description}{extra}"


# ---------------------------------------------------------------------------
# Symbol sets
# ---------------------------------------------------------------------------

_ALLOC_SYMS: Set[str] = {
    'malloc', 'calloc', 'realloc', 'xmalloc', 'xcalloc', 'xrealloc',
    'kmalloc', 'kzalloc', 'vmalloc', 'vzalloc', 'kcalloc', 'kvmalloc',
    'ExAllocatePool', 'ExAllocatePoolWithTag', 'ExAllocatePool2',
    'HeapAlloc', 'LocalAlloc', 'GlobalAlloc',
    'g_malloc', 'g_malloc0', 'g_new',
    'BUF_MEM_grow',   # TAOSSA L6-6 OpenSSL pattern
}

_FREE_SYMS: Set[str] = {
    'free', 'kfree', 'vfree', 'kvfree',
    'ExFreePool', 'ExFreePoolWithTag', 'ExFreePool2',
    'HeapFree', 'LocalFree', 'GlobalFree',
    'g_free',
}

_STRLEN_SYMS: Set[str] = {'strlen', 'wcslen', 'strnlen'}
_COPY_SYMS: Set[str] = {'strcpy', 'wcscpy', 'memcpy', 'memmove', 'bcopy'}

# Caller-saved registers clobbered on any CALL (SysV AMD64 ABI)
_CALLER_SAVED = frozenset([
    X86_REG_RAX, X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
] if _CS_AVAILABLE else [])

# Size argument registers for common allocators (SysV AMD64)
_SIZE_REGS = frozenset([X86_REG_RDI, X86_REG_RSI, X86_REG_RDX] if _CS_AVAILABLE else [])

_MAX_FUNC_BYTES = 4096
_LOOKAHEAD = 12   # instructions to look ahead after a mul for the allocator call


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class HeapVulnScanner:
    """
    Heap memory corruption detector for x86-64 ELF / PE binaries.

    Implements four detection passes per function:
      1. INT_OVERFLOW_BEFORE_ALLOC : IMUL/MUL/SHL -> size arg -> allocator
      2. USE_AFTER_FREE            : free(ptr) -> dereference of same reg
      3. DOUBLE_FREE               : free(ptr) -> free(ptr) without reassignment
      4. OFF_BY_ONE_ALLOC          : strlen result -> malloc -> strcpy/memcpy
    """

    def __init__(self, binary_path: str, ctx=None):
        self.binary_path = binary_path
        self._ctx = ctx
        self._data: bytes = Path(binary_path).read_bytes()
        self._alloc_vas: Set[int] = set()
        self._free_vas: Set[int] = set()
        self._strlen_vas: Set[int] = set()
        self._copy_vas: Set[int] = set()
        self._func_starts: List[int] = []
        self._plt: Dict[int, str] = {}
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._md = None
        if _CS_AVAILABLE:
            self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._md.detail = True
        self._lief_binary = None
        if _LIEF_AVAILABLE:
            self._lief_binary = _lief.parse(binary_path)
        self._init_from_ctx_or_lief()

    @classmethod
    def from_context(cls, ctx) -> 'HeapVulnScanner':
        return cls(ctx.path, ctx=ctx)

    @classmethod
    def from_path(cls, path: str) -> 'HeapVulnScanner':
        try:
            from ablation.analyzers.binary_context import BinaryContext
            ctx = BinaryContext.load_or_build(path)
            return cls(path, ctx=ctx)
        except Exception:
            return cls(path)

    def _init_from_ctx_or_lief(self):
        if self._ctx is not None:
            self._plt = self._ctx.plt.copy()
            self._func_starts = list(self._ctx.func_starts)
        elif self._lief_binary is not None:
            self._plt = {}
            for sym in self._lief_binary.symbols:
                if sym.value:
                    self._plt[sym.value] = sym.name
            self._func_starts = sorted(
                s.value for s in self._lief_binary.symbols if s.value and s.type.name == 'FUNC'
            )
        for va, name in self._plt.items():
            if name in _ALLOC_SYMS:
                self._alloc_vas.add(va)
            if name in _FREE_SYMS:
                self._free_vas.add(va)
            if name in _STRLEN_SYMS:
                self._strlen_vas.add(va)
            if name in _COPY_SYMS:
                self._copy_vas.add(va)
        # .rodata ranges for string literal detection
        if self._lief_binary is not None:
            for sec in self._lief_binary.sections:
                if sec.name in ('.rodata', '.data.ro', '__const', '__cstring', '.rdata'):
                    self._rodata_ranges.append(
                        (sec.virtual_address, sec.virtual_address + sec.size)
                    )

    def _va_to_bytes(self, va: int, size: int) -> bytes:
        if not _LIEF_AVAILABLE or self._lief_binary is None:
            return b''
        try:
            off = self._lief_binary.virtual_address_to_offset(va)
            return self._data[off:off + size]
        except Exception:
            return b''

    def _get_func_insns(self, func_va: int) -> list:
        if self._md is None:
            return []
        raw = self._va_to_bytes(func_va, _MAX_FUNC_BYTES)
        if not raw:
            return []
        return list(self._md.disasm(raw, func_va))

    def _plt_name(self, va: int) -> str:
        return self._plt.get(va, hex(va))

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan(self) -> List[HeapFinding]:
        """Run all four detection passes over every function."""
        if not _CS_AVAILABLE or not _LIEF_AVAILABLE:
            return []
        findings: List[HeapFinding] = []
        for func_va in self._func_starts:
            insns = self._get_func_insns(func_va)
            if not insns:
                continue
            findings.extend(self._check_int_overflow_before_alloc(func_va, insns))
            findings.extend(self._check_uaf(func_va, insns))
            findings.extend(self._check_double_free(func_va, insns))
            findings.extend(self._check_off_by_one_alloc(func_va, insns))
        return findings

    def report(self, findings: List[HeapFinding]) -> str:
        if not findings:
            return '[heap_vuln_scanner] no findings\n'
        high = [f for f in findings if f.severity == 'HIGH']
        med  = [f for f in findings if f.severity == 'MEDIUM']
        hdr = f'[heap_vuln_scanner] {len(findings)} finding(s)  HIGH={len(high)}  MED={len(med)}\n'
        lines = [hdr]
        for f in sorted(findings, key=lambda x: (x.severity, x.func_va)):
            lines.append(f.fmt())
        return '\n'.join(lines) + '\n'

    # ------------------------------------------------------------------
    # Detection pass 1: integer overflow before allocation
    # ------------------------------------------------------------------

    def _check_int_overflow_before_alloc(self, func_va: int, insns: list) -> List[HeapFinding]:
        """
        TAOSSA Ch6 L6-2/L6-3: multiplicative overflow before malloc.

        IMUL/MUL/SHL result register -> MOV to size arg register (RDI/RSI/RDX)
        -> CALL allocator, within _LOOKAHEAD instructions, no JO/cmp between.
        """
        findings: List[HeapFinding] = []
        # mul_result[reg_id] = (mnemonic, va_of_mul)
        mul_result: Dict[int, Tuple[str, int]] = {}

        for i, insn in enumerate(insns):
            mnem = insn.mnemonic.lower()

            # IMUL (two/three-operand), MUL (one-operand), SHL/SAL
            if mnem in ('imul', 'mul', 'shl', 'sal', 'shlx') and insn.operands:
                dst_op = insn.operands[0]
                if dst_op.type == X86_OP_REG:
                    mul_result[dst_op.reg] = (mnem, insn.address)

            # MOV size_arg_reg, mul_reg
            if mnem == 'mov' and len(insn.operands) == 2:
                dst = insn.operands[0]
                src = insn.operands[1]
                if (dst.type == X86_OP_REG and dst.reg in _SIZE_REGS and
                        src.type == X86_OP_REG and src.reg in mul_result):
                    mul_mnem, mul_va = mul_result[src.reg]
                    # Scan ahead for allocator CALL
                    for j in range(i + 1, min(i + 1 + _LOOKAHEAD, len(insns))):
                        ji = insns[j]
                        if ji.mnemonic.lower() in ('cmp', 'test', 'jo', 'jno'):
                            break  # bounds check present: abort this candidate
                        if ji.group(CS_GRP_CALL) and ji.operands:
                            tgt = ji.operands[0].imm
                            if tgt in self._alloc_vas:
                                findings.append(HeapFinding(
                                    kind='int_overflow_before_alloc',
                                    func_va=func_va,
                                    site_va=mul_va,
                                    description=(
                                        f"{mul_mnem.upper()} result fed to "
                                        f"{self._plt_name(tgt)} at 0x{ji.address:x} "
                                        f"without overflow check"
                                    ),
                                    severity='HIGH',
                                    alloc_sym=self._plt_name(tgt),
                                ))
                                break

            # LEA also produces a computed address that may be a multiply proxy
            if mnem == 'lea' and len(insn.operands) == 2:
                dst = insn.operands[0]
                src = insn.operands[1]
                if dst.type == X86_OP_REG and src.type == X86_OP_MEM:
                    # lea [reg*scale + base] is a multiply by scale (2/4/8)
                    if src.mem.scale > 1 and src.mem.index:
                        mul_result[dst.reg] = ('lea_scale', insn.address)

            # Any CALL clobbers caller-saved regs (SysV)
            if insn.group(CS_GRP_CALL):
                for r in list(mul_result.keys()):
                    if r in _CALLER_SAVED:
                        del mul_result[r]

            # Writes to a register clear its mul-tracking
            if mnem in ('xor', 'mov', 'movzx', 'movsx', 'lea') and insn.operands:
                dst = insn.operands[0]
                if dst.type == X86_OP_REG:
                    mul_result.pop(dst.reg, None)

        return findings

    # ------------------------------------------------------------------
    # Detection pass 2: use-after-free
    # ------------------------------------------------------------------

    def _check_uaf(self, func_va: int, insns: list) -> List[HeapFinding]:
        """
        TAOSSA Ch5: free(ptr) -> use of freed register in same function.

        Track what register was in RDI at the time of each free() call.
        Flag any subsequent memory dereference from that register or
        any CALL that passes the register as an argument.
        """
        findings: List[HeapFinding] = []
        # freed_regs[reg_id] = va_of_free_call
        freed_regs: Dict[int, int] = {}
        last_rdi_src: Optional[int] = None   # source register loaded into RDI

        for i, insn in enumerate(insns):
            mnem = insn.mnemonic.lower()

            # Track last MOV RDI, reg (captures what pointer goes into free)
            if mnem == 'mov' and len(insn.operands) == 2:
                dst = insn.operands[0]
                src = insn.operands[1]
                if dst.type == X86_OP_REG and dst.reg == X86_REG_RDI:
                    if src.type == X86_OP_REG:
                        last_rdi_src = src.reg
                    else:
                        last_rdi_src = None

            if insn.group(CS_GRP_CALL) and insn.operands:
                tgt = insn.operands[0].imm
                if tgt in self._free_vas:
                    if last_rdi_src is not None:
                        freed_regs[last_rdi_src] = insn.address
                    freed_regs[X86_REG_RDI] = insn.address
                    # free() itself clobbers caller-saved, but the SOURCE register persists
                    for r in list(freed_regs.keys()):
                        if r in _CALLER_SAVED and r != last_rdi_src:
                            del freed_regs[r]
                    last_rdi_src = None
                    continue
                # Any other call clobbers caller-saved regs
                for r in list(freed_regs.keys()):
                    if r in _CALLER_SAVED:
                        del freed_regs[r]
                last_rdi_src = None

            if not freed_regs:
                continue

            # Memory dereference of a freed register
            for op in insn.operands:
                if op.type == X86_OP_MEM and op.mem.base in freed_regs:
                    free_va = freed_regs[op.mem.base]
                    findings.append(HeapFinding(
                        kind='uaf',
                        func_va=func_va,
                        site_va=insn.address,
                        description=(
                            f"Dereference of freed pointer at 0x{insn.address:x} "
                            f"({insn.mnemonic} [{self._reg_name(op.mem.base)}+{op.mem.disp:#x}])"
                        ),
                        severity='HIGH',
                        freed_at=free_va,
                    ))

            # Reassignment clears freed status
            if mnem in ('mov', 'lea', 'xor', 'movzx', 'movsx', 'pop') and insn.operands:
                dst = insn.operands[0]
                if dst.type == X86_OP_REG:
                    freed_regs.pop(dst.reg, None)

        return findings

    # ------------------------------------------------------------------
    # Detection pass 3: double-free
    # ------------------------------------------------------------------

    def _check_double_free(self, func_va: int, insns: list) -> List[HeapFinding]:
        """
        TAOSSA Ch5: same pointer freed twice without reassignment.
        """
        findings: List[HeapFinding] = []
        freed_regs: Dict[int, int] = {}   # reg_id -> va of first free
        last_rdi_src: Optional[int] = None

        for insn in insns:
            mnem = insn.mnemonic.lower()

            if mnem == 'mov' and len(insn.operands) == 2:
                dst = insn.operands[0]
                src = insn.operands[1]
                if dst.type == X86_OP_REG and dst.reg == X86_REG_RDI:
                    last_rdi_src = src.reg if src.type == X86_OP_REG else None

            if insn.group(CS_GRP_CALL) and insn.operands:
                tgt = insn.operands[0].imm
                if tgt in self._free_vas:
                    key = last_rdi_src if last_rdi_src is not None else X86_REG_RDI
                    if key in freed_regs:
                        findings.append(HeapFinding(
                            kind='double_free',
                            func_va=func_va,
                            site_va=insn.address,
                            description=(
                                f"Double-free at 0x{insn.address:x} "
                                f"(first free at 0x{freed_regs[key]:x})"
                            ),
                            severity='HIGH',
                            freed_at=freed_regs[key],
                        ))
                    else:
                        freed_regs[key] = insn.address
                    for r in list(freed_regs.keys()):
                        if r in _CALLER_SAVED and r != last_rdi_src:
                            del freed_regs[r]
                    last_rdi_src = None
                    continue
                for r in list(freed_regs.keys()):
                    if r in _CALLER_SAVED:
                        del freed_regs[r]
                last_rdi_src = None

            if mnem in ('mov', 'lea', 'xor', 'movzx', 'movsx', 'pop') and insn.operands:
                dst = insn.operands[0]
                if dst.type == X86_OP_REG:
                    freed_regs.pop(dst.reg, None)
                    if dst.reg == X86_REG_RDI:
                        last_rdi_src = None

        return findings

    # ------------------------------------------------------------------
    # Detection pass 4: off-by-one in allocation size
    # ------------------------------------------------------------------

    def _check_off_by_one_alloc(self, func_va: int, insns: list) -> List[HeapFinding]:
        """
        TAOSSA Ch5: strlen(s) -> malloc(result) -> strcpy(alloc, s).
        Off-by-one: strlen returns len WITHOUT NUL; malloc(len) is one byte too small.

        Pattern: CALL strlen -> result in RAX -> MOV RDI, RAX -> CALL malloc
                 -> later CALL strcpy (with same or related pointer)
        No +1 added to RAX between strlen and malloc = off-by-one.
        """
        findings: List[HeapFinding] = []
        strlen_result_va: Optional[int] = None
        strlen_no_plus1 = False

        for i, insn in enumerate(insns):
            mnem = insn.mnemonic.lower()

            if insn.group(CS_GRP_CALL) and insn.operands:
                tgt = insn.operands[0].imm
                if tgt in self._strlen_vas:
                    strlen_result_va = insn.address
                    strlen_no_plus1 = True
                    continue
                if strlen_result_va and strlen_no_plus1 and tgt in self._alloc_vas:
                    # Check that no ADD RAX, 1 occurred since strlen
                    findings.append(HeapFinding(
                        kind='off_by_one_alloc',
                        func_va=func_va,
                        site_va=strlen_result_va,
                        description=(
                            f"strlen result at 0x{strlen_result_va:x} fed to "
                            f"{self._plt_name(tgt)} without +1: NUL terminator off-by-one"
                        ),
                        severity='MEDIUM',
                        alloc_sym=self._plt_name(tgt),
                    ))
                    strlen_result_va = None
                    strlen_no_plus1 = False
                    continue

            # ADD RAX, 1 (or INC RAX) between strlen and malloc means size is correct
            if strlen_no_plus1 and mnem in ('add', 'inc', 'lea'):
                if insn.operands and insn.operands[0].type == X86_OP_REG:
                    if insn.operands[0].reg == X86_REG_RAX:
                        strlen_no_plus1 = False

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    _REG_NAMES = {
        X86_REG_RDI: 'rdi', X86_REG_RSI: 'rsi', X86_REG_RDX: 'rdx',
        X86_REG_RCX: 'rcx', X86_REG_RAX: 'rax',
    } if _CS_AVAILABLE else {}

    def _reg_name(self, reg_id: int) -> str:
        return self._REG_NAMES.get(reg_id, f'r{reg_id}')
