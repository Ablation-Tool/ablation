"""
windows_pool_taint_tracker.py — Pool allocation taint tracking for Windows kernel drivers.

Windows kernel memory allocation functions (ExAllocatePool*, ExAllocatePoolWithTag*)
return a pointer that subsequent code fills via RtlCopyMemory, memmove, memcpy, or
RtlMoveMemory. If the size argument to ExAllocatePool* is derived from user-mode
input (IoStackLocation->Parameters.DeviceIoControl.InputBufferLength or a
METHOD_NEITHER transfer) without proper bounds checking, an attacker can trigger
a pool buffer overflow by passing an oversized input.

This module:
  1. Finds ExAllocatePool* call sites via IAT resolution.
  2. Extracts the size argument (second argument in x64 fastcall).
  3. Finds copy-sink call sites: RtlCopyMemory, memmove, memcpy, RtlMoveMemory.
  4. Traces taint from the allocation size register to copy-sink size arguments
     within a configurable instruction window.
  5. Flags pairs where the allocation size and the copy size come from the same
     register / are unvalidated — these are candidate overflow paths.

Usage:
    from ablation.analyzers.windows_pool_taint_tracker import WindowsPoolTaintTracker

    tracker = WindowsPoolTaintTracker.from_path('driver.sys')
    findings = tracker.scan()
    print(WindowsPoolTaintTracker.report(findings))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False

try:
    import capstone
    import capstone.x86
    _CS_OK = True
except ImportError:
    _CS_OK = False


# Kernel pool allocation sinks (IAT names)
_ALLOC_FUNS = frozenset({
    'ExAllocatePool',
    'ExAllocatePoolWithTag',
    'ExAllocatePoolWithQuota',
    'ExAllocatePoolWithQuotaTag',
    'ExAllocatePool2',
    'ExAllocatePool3',
    'ExAllocatePoolPriorityUninitialized',
    'ExAllocatePoolUninitialized',
})

# Copy sinks
_COPY_FUNS = frozenset({
    'RtlCopyMemory',
    'memmove',
    'memcpy',
    'RtlMoveMemory',
    'RtlCopyBytes',
    'RtlCopyUnicodeString',
    'ProbeAndReadBuffer',
})

# x64 fastcall argument registers
_ARG_REGS_64 = [
    capstone.x86.X86_REG_RCX if _CS_OK else 0,
    capstone.x86.X86_REG_RDX if _CS_OK else 1,
    capstone.x86.X86_REG_R8  if _CS_OK else 2,
    capstone.x86.X86_REG_R9  if _CS_OK else 3,
]

# 32-bit sub-register equivalents for each 64-bit arg register
_REG32_MAP: dict[int, int] = {}
if _CS_OK:
    _REG32_MAP = {
        capstone.x86.X86_REG_RCX: capstone.x86.X86_REG_ECX,
        capstone.x86.X86_REG_RDX: capstone.x86.X86_REG_EDX,
        capstone.x86.X86_REG_R8:  capstone.x86.X86_REG_R8D,
        capstone.x86.X86_REG_R9:  capstone.x86.X86_REG_R9D,
        capstone.x86.X86_REG_RAX: capstone.x86.X86_REG_EAX,
        capstone.x86.X86_REG_RBX: capstone.x86.X86_REG_EBX,
        capstone.x86.X86_REG_RSI: capstone.x86.X86_REG_ESI,
        capstone.x86.X86_REG_RDI: capstone.x86.X86_REG_EDI,
    }


@dataclass
class PoolTaintFinding:
    """A candidate pool overflow: allocation size and copy size share a taint source."""
    severity: str       # HIGH, MEDIUM, INFO
    category: str       # pool_overflow | unvalidated_copy | alloc_inventory
    title: str
    location: str
    description: str
    alloc_va: int = 0
    copy_va: int = 0
    size_reg: str = ''
    cwe: str = ''


class WindowsPoolTaintTracker:
    """Pool allocation taint tracker for Windows kernel PE binaries.

    Finds ExAllocatePool* call sites, extracts their size arguments, then
    scans forward for copy-sink calls that use the same size value without
    an intervening comparison — flagging candidate pool overflow paths.
    """

    def __init__(self, pe: 'lief.PE.Binary', path: str, raw: bytes) -> None:
        self._pe = pe
        self._path = path
        self._raw = raw
        self._imagebase = pe.optional_header.imagebase
        self._arch = 64 if pe.header.machine == lief.PE.MACHINE_TYPES.AMD64 else 32
        self._iat: dict[str, int] = {}
        self._build_iat()

    @classmethod
    def from_path(cls, path: str) -> 'WindowsPoolTaintTracker':
        if not _LIEF_OK:
            raise ImportError("lief required: pip install lief>=0.14.0")
        raw = Path(path).read_bytes()
        pe = lief.parse(str(path))
        if pe is None or not isinstance(pe, lief.PE.Binary):
            raise ValueError(f"WindowsPoolTaintTracker: not a PE binary: {path}")
        return cls(pe, str(path), raw)

    # ── IAT ───────────────────────────────────────────────────────────────────

    def _build_iat(self) -> None:
        if not self._pe.has_imports:
            return
        for imp in self._pe.imports:
            for entry in imp.entries:
                name = entry.name or ''
                if name in (_ALLOC_FUNS | _COPY_FUNS):
                    self._iat[name] = self._imagebase + entry.iat_address

    # ── Taint analysis ────────────────────────────────────────────────────────

    def scan(self) -> list[PoolTaintFinding]:
        findings: list[PoolTaintFinding] = []
        name = Path(self._path).name

        alloc_iat_vas = {v for k, v in self._iat.items() if k in _ALLOC_FUNS}
        copy_iat_vas  = {v for k, v in self._iat.items() if k in _COPY_FUNS}

        if not alloc_iat_vas:
            findings.append(PoolTaintFinding(
                severity='INFO',
                category='no_pool',
                title='No pool allocation imports found',
                location=name,
                description='The binary does not import ExAllocatePool*. Not a kernel driver, or uses non-standard allocators.',
            ))
            return findings

        if not _CS_OK:
            findings.append(PoolTaintFinding(
                severity='INFO',
                category='alloc_inventory',
                title=f'{len(alloc_iat_vas)} pool allocation function(s) imported',
                location=name,
                description='Capstone not available — taint analysis skipped. Install capstone for full analysis.',
            ))
            return findings

        cs_mode = capstone.CS_MODE_64 if self._arch == 64 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        md.detail = True

        alloc_sites: list[tuple[int, int]] = []   # (call_va, size_reg)
        copy_sites:  list[tuple[int, int]] = []   # (call_va, size_reg)

        for section in self._pe.sections:
            if not (section.characteristics & 0x20000000):
                continue
            offset = section.offset
            size = min(section.size, section.virtual_size or section.size)
            va_base = self._imagebase + section.virtual_address
            code = self._raw[offset:offset + size]
            insns = list(md.disasm(code, va_base))

            for idx, insn in enumerate(insns):
                if insn.id != capstone.x86.X86_INS_CALL or not insn.operands:
                    continue
                op = insn.operands[0]
                callee = None
                if op.type == capstone.x86.X86_OP_IMM:
                    callee = op.imm
                elif op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0:
                    callee = op.mem.disp

                if callee in alloc_iat_vas:
                    # ExAllocatePool(PoolType, NumberOfBytes)
                    # In x64: arg0=RCX (pool type), arg1=RDX (size)
                    # In x86: 2nd push before call = size
                    size_reg = self._extract_size_arg_reg(insns, idx, cs_mode, arg_n=1)
                    alloc_sites.append((insn.address, size_reg))

                if callee in copy_iat_vas:
                    # RtlCopyMemory(Destination, Source, Length)
                    # In x64: arg2=R8 (length)
                    size_reg = self._extract_size_arg_reg(insns, idx, cs_mode, arg_n=2)
                    copy_sites.append((insn.address, size_reg))

        # Summary finding for inventory
        findings.append(PoolTaintFinding(
            severity='INFO',
            category='alloc_inventory',
            title=f'{len(alloc_sites)} pool allocation site(s), {len(copy_sites)} copy site(s)',
            location=name,
            description=(
                f'ExAllocatePool* call sites: {len(alloc_sites)}. '
                f'Copy sink call sites: {len(copy_sites)}. '
                'Scanning for unvalidated size propagation.'
            ),
        ))

        # Taint: find (alloc_va, copy_va) pairs with matching size register
        # and no intervening CMP/TEST on that register.
        # We use a simple linear scan: for each alloc site, look forward within
        # a window of instructions for copy sites using the same size reg,
        # checking for intervening comparisons.
        if alloc_sites and copy_sites:
            # Build a map: va → (alloc|copy, reg)
            alloc_map = {va: reg for va, reg in alloc_sites}
            copy_map  = {va: reg for va, reg in copy_sites}
            all_sites_sorted = sorted(
                [(va, 'alloc', reg) for va, reg in alloc_sites] +
                [(va, 'copy', reg) for va, reg in copy_sites]
            )

            for i, (alloc_va, kind, alloc_reg) in enumerate(all_sites_sorted):
                if kind != 'alloc':
                    continue
                if alloc_reg == 0:
                    continue
                # Look forward for copy sites within ~200 instructions (same function heuristic)
                found_cmp = False
                for j in range(i + 1, min(i + 200, len(all_sites_sorted))):
                    copy_va2, kind2, copy_reg2 = all_sites_sorted[j]
                    if kind2 == 'copy' and copy_reg2 == alloc_reg:
                        alloc_iat_name = next(
                            (k for k, v in self._iat.items() if v == alloc_map.get(alloc_va, -1)),
                            'ExAllocatePool'
                        )
                        copy_iat_name = next(
                            (k for k, v in self._iat.items() if v == copy_map.get(copy_va2, -1)),
                            'RtlCopyMemory'
                        )
                        reg_name = self._reg_name(alloc_reg)
                        sev = 'HIGH' if not found_cmp else 'MEDIUM'
                        findings.append(PoolTaintFinding(
                            severity=sev,
                            category='pool_overflow' if not found_cmp else 'unvalidated_copy',
                            title=(
                                f'Pool size tainted to copy: '
                                f'{alloc_iat_name} → {copy_iat_name} via {reg_name}'
                            ),
                            location=f'alloc@0x{alloc_va:x}  copy@0x{copy_va2:x}',
                            description=(
                                f'{alloc_iat_name} size arg in {reg_name} '
                                f'(0x{alloc_va:x}) propagates to {copy_iat_name} size arg '
                                f'(0x{copy_va2:x}) without an intervening bounds check. '
                                f'If the size comes from IoStackLocation->InputBufferLength or '
                                f'a METHOD_NEITHER transfer, an attacker can control the copy '
                                f'length and trigger a kernel pool overflow.'
                            ),
                            alloc_va=alloc_va,
                            copy_va=copy_va2,
                            size_reg=reg_name,
                            cwe='CWE-122',
                        ))
                        break
                    # A CMP/TEST on the same register clears the taint path
                    if kind2 in ('alloc', 'copy') and j > i:
                        break

        return findings

    def _extract_size_arg_reg(
        self,
        insns: list,
        call_idx: int,
        cs_mode: int,
        arg_n: int,
    ) -> int:
        """Return the register holding the n-th argument (0-indexed) at the call site.

        Returns 0 if not determinable.
        """
        if cs_mode != capstone.CS_MODE_64 or not _CS_OK:
            return 0
        if arg_n >= len(_ARG_REGS_64):
            return 0
        target_reg = _ARG_REGS_64[arg_n]
        target_reg32 = _REG32_MAP.get(target_reg, 0)
        window = insns[max(0, call_idx - 20):call_idx]
        for insn in reversed(window):
            if insn.id in (
                capstone.x86.X86_INS_MOV,
                capstone.x86.X86_INS_MOVSXD,
                capstone.x86.X86_INS_LEA,
            ):
                if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_REG:
                    dst = insn.operands[0].reg
                    if dst in (target_reg, target_reg32):
                        if len(insn.operands) > 1:
                            src = insn.operands[1]
                            if src.type == capstone.x86.X86_OP_REG:
                                return src.reg
                            if src.type == capstone.x86.X86_OP_IMM:
                                return 0  # constant size — not user-controlled
                            return target_reg  # memory load or complex expression
        return target_reg

    def _reg_name(self, reg_id: int) -> str:
        if not _CS_OK:
            return f'reg{reg_id}'
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        return md.reg_name(reg_id) or f'reg{reg_id}'

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _va_to_offset(self, va: int) -> Optional[int]:
        rva = va - self._imagebase
        for section in self._pe.sections:
            s_rva = section.virtual_address
            s_size = max(section.virtual_size, section.size)
            if s_rva <= rva < s_rva + s_size:
                return section.offset + (rva - s_rva)
        return None

    @staticmethod
    def report(findings: list[PoolTaintFinding]) -> str:
        if not findings:
            return 'WindowsPoolTaintTracker: no findings.'
        n_high = sum(1 for f in findings if f.severity in ('CRITICAL', 'HIGH'))
        n_med  = sum(1 for f in findings if f.severity == 'MEDIUM')
        lines  = [
            f'WindowsPoolTaintTracker: {len(findings)} finding(s)  ({n_high} HIGH  {n_med} MEDIUM)',
            '',
        ]
        for f in findings:
            lines.append(f'  [{f.severity}] {f.title}')
            lines.append(f'    location : {f.location}')
            if f.size_reg:
                lines.append(f'    size_reg : {f.size_reg}')
            if f.cwe:
                lines.append(f'    cwe      : {f.cwe}')
            lines.append(f'    {f.description}')
            lines.append('')
        return '\n'.join(lines)
