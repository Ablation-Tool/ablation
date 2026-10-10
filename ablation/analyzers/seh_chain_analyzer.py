"""
seh_chain_analyzer.py — Structured Exception Handler chain analysis for x86 PE binaries.

x86 (32-bit) Windows uses a stack-linked list of SEH frames. Each frame lives on the
stack at FS:[0] and holds a pointer to a handler function. An attacker who overwrites a
stack SEH frame can redirect execution to an arbitrary address when an exception fires.

SafeSEH (IMAGE_LOAD_CONFIG.SEHandlerTable) defends against this by listing all
legitimate handler functions. An exception dispatch that resolves to a handler not in
the table triggers a process termination instead of calling the handler.

This module:
  1. Checks whether SafeSEH is enabled and how many handlers are registered.
  2. Reads the SafeSEH handler table and cross-references against code exports.
  3. Finds SEH frame setup patterns (push handler; push FS:[0]; mov FS:[0], esp)
     to enumerate where exception handlers are installed at runtime.
  4. Flags handlers referenced in the binary that are not in the SafeSEH table.

Scope: x86 (32-bit) PE only. x64 PE uses table-based EH (.pdata section); SafeSEH
does not apply. The module raises ValueError for non-x86 PE input.

Usage:
    from ablation.analyzers.seh_chain_analyzer import SEHChainAnalyzer

    ana = SEHChainAnalyzer.from_path('legacy_service.exe')
    findings = ana.scan()
    print(SEHChainAnalyzer.report(findings))
    print(f"SafeSEH handlers: {len(ana.safe_seh_handlers())}")
"""

from __future__ import annotations

import struct
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


@dataclass
class SEHFinding:
    """A single SEH-related security finding."""
    severity: str       # HIGH, MEDIUM, LOW, INFO
    category: str       # safesh_disabled | no_handlers | handler_not_in_table |
                        # seh_frame_count | dynamic_handler_count
    title: str
    location: str
    description: str
    va: int = 0
    cwe: str = ""


@dataclass
class SEHFrame:
    """A SEH frame installation site found in code."""
    va: int             # VA of the 'push handler_va' instruction
    handler_va: int     # VA of the handler function
    in_safe_seh: bool   # True if handler_va is in the SafeSEH table


class SEHChainAnalyzer:
    """Structured Exception Handler analysis for x86 PE binaries.

    Reads IMAGE_LOAD_CONFIG to determine if SafeSEH is active, extracts the
    handler table, and scans code sections for SEH frame setup sequences.
    """

    def __init__(self, pe: 'lief.PE.Binary', path: str, raw: bytes) -> None:
        self._pe = pe
        self._path = path
        self._raw = raw
        self._handlers: Optional[list[int]] = None  # SafeSEH table RVAs

    @classmethod
    def from_path(cls, path: str) -> 'SEHChainAnalyzer':
        if not _LIEF_OK:
            raise ImportError("lief required: pip install lief>=0.14.0")
        raw = Path(path).read_bytes()
        pe = lief.parse(str(path))
        if pe is None or not isinstance(pe, lief.PE.Binary):
            raise ValueError(f"SEHChainAnalyzer: not a PE binary: {path}")
        header = pe.header
        if header.machine != lief.PE.MACHINE_TYPES.I386:
            raise ValueError(
                f"SEHChainAnalyzer: x86 (I386) PE required, got {header.machine.name}. "
                "x64 PE uses table-based EH (.pdata); SafeSEH analysis does not apply."
            )
        return cls(pe, str(path), raw)

    # ── SafeSEH table ─────────────────────────────────────────────────────────

    def safe_seh_handlers(self) -> list[int]:
        """Return a list of SafeSEH handler RVAs from IMAGE_LOAD_CONFIG."""
        if self._handlers is not None:
            return self._handlers
        lc = self._pe.load_configuration
        if lc is None:
            self._handlers = []
            return self._handlers

        table_va = int(getattr(lc, 'se_handler_table', 0) or 0)
        count    = int(getattr(lc, 'se_handler_count', 0) or 0)
        imagebase = self._pe.optional_header.imagebase

        handlers: list[int] = []
        if table_va and count:
            offset = self._va_to_offset(table_va)
            if offset is not None:
                for i in range(count):
                    pos = offset + i * 4
                    if pos + 4 <= len(self._raw):
                        (rva,) = struct.unpack_from('<I', self._raw, pos)
                        handlers.append(rva)

        self._handlers = handlers
        return handlers

    # ── SEH frame scan ────────────────────────────────────────────────────────

    def seh_frames(self) -> list[SEHFrame]:
        """Find SEH frame installation sites in code sections.

        Looks for the canonical pattern:
            push <handler_va>      ; push the handler address
            push dword [FS:0]      ; link to previous frame  (64 A1 00 00 00 00)
            mov [FS:0], esp        ; install new frame        (64 89 25 00 00 00 00)
        """
        if not _CS_OK:
            return []

        safe_set = set(self.safe_seh_handlers())
        imagebase = self._pe.optional_header.imagebase
        frames: list[SEHFrame] = []
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True

        for section in self._pe.sections:
            if not (section.characteristics & 0x20000000):  # IMAGE_SCN_CNT_CODE
                continue
            offset = section.offset
            size = min(section.size, section.virtual_size or section.size)
            va = imagebase + section.virtual_address
            code = self._raw[offset:offset + size]

            insns = list(md.disasm(code, va))
            for idx, insn in enumerate(insns):
                # Look for: push <imm32>  followed within 4 insns by FS:[0] access
                if insn.id != capstone.x86.X86_INS_PUSH:
                    continue
                ops = insn.operands
                if not ops or ops[0].type != capstone.x86.X86_OP_IMM:
                    continue
                handler_va_candidate = ops[0].imm
                # Confirm this is likely a handler by checking for FS:[0] access nearby
                window = insns[idx + 1:idx + 5]
                fs_access = any(
                    capstone.x86.X86_REG_FS in (op.mem.segment for op in i.operands
                                                  if op.type == capstone.x86.X86_OP_MEM)
                    for i in window
                )
                if not fs_access:
                    continue
                handler_rva = handler_va_candidate - imagebase
                frames.append(SEHFrame(
                    va=insn.address,
                    handler_va=handler_va_candidate,
                    in_safe_seh=(handler_rva in safe_set),
                ))

        return frames

    # ── Scan ─────────────────────────────────────────────────────────────────

    def scan(self) -> list[SEHFinding]:
        """Return all SEH security findings for the binary."""
        findings: list[SEHFinding] = []
        name = Path(self._path).name
        lc = self._pe.load_configuration
        imagebase = self._pe.optional_header.imagebase

        if lc is None:
            findings.append(SEHFinding(
                severity='HIGH',
                category='safesh_disabled',
                title='No IMAGE_LOAD_CONFIG — SafeSEH absent',
                location=name,
                description=(
                    'The binary has no IMAGE_LOAD_CONFIG directory. SafeSEH cannot '
                    'be enabled without it. Any SEH frame on the stack is a valid '
                    'target for a stack overflow that overwrites the exception handler pointer.'
                ),
                cwe='CWE-693',
            ))
            return findings

        handlers = self.safe_seh_handlers()
        table_va = int(getattr(lc, 'se_handler_table', 0) or 0)
        count    = int(getattr(lc, 'se_handler_count', 0) or 0)

        if not table_va or not count:
            findings.append(SEHFinding(
                severity='HIGH',
                category='safesh_disabled',
                title='SafeSEH not enabled (empty or absent handler table)',
                location=name,
                description=(
                    'IMAGE_LOAD_CONFIG.SEHandlerTable is NULL or SEHandlerCount is 0. '
                    'The binary was not compiled with /SAFESEH. An attacker who overwrites '
                    'an SEH frame on the stack can execute an arbitrary handler address.'
                ),
                cwe='CWE-693',
            ))
        else:
            findings.append(SEHFinding(
                severity='INFO',
                category='safesh_enabled',
                title=f'SafeSEH enabled: {count} registered handler(s)',
                location=name,
                description=(
                    f'IMAGE_LOAD_CONFIG.SEHandlerTable at 0x{table_va:x} lists '
                    f'{count} legitimate handler RVA(s). Exception dispatch rejects '
                    f'any handler not in this table.'
                ),
            ))

        # Check SEH frame installations against the SafeSEH table
        if handlers:
            safe_set = set(handlers)
            frames = self.seh_frames()
            unsafe = [f for f in frames if not f.in_safe_seh]
            if frames:
                findings.append(SEHFinding(
                    severity='INFO',
                    category='seh_frame_count',
                    title=f'{len(frames)} SEH frame installation(s) found in code',
                    location=name,
                    description=(
                        f'{len(frames)} push-handler/push-FS:[0] sequences found. '
                        f'{len(frames) - len(unsafe)} handlers are in the SafeSEH table; '
                        f'{len(unsafe)} are not.'
                    ),
                ))
            for frame in unsafe:
                rva = frame.handler_va - imagebase
                findings.append(SEHFinding(
                    severity='MEDIUM',
                    category='handler_not_in_table',
                    title=f'SEH handler at 0x{frame.handler_va:x} not in SafeSEH table',
                    location=f'push @ 0x{frame.va:x}',
                    description=(
                        f'Handler 0x{frame.handler_va:x} (RVA 0x{rva:x}) is installed as '
                        f'an SEH frame but does not appear in the SafeSEH table. '
                        f'If this is reached by exception dispatch, it may indicate a '
                        f'dynamically computed handler (runtime-generated code or a '
                        f'compiler quirk) — or a legitimate bypass target.'
                    ),
                    va=frame.va,
                    cwe='CWE-693',
                ))

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _va_to_offset(self, va: int) -> Optional[int]:
        imagebase = self._pe.optional_header.imagebase
        rva = va - imagebase
        for section in self._pe.sections:
            s_rva = section.virtual_address
            s_size = max(section.virtual_size, section.size)
            if s_rva <= rva < s_rva + s_size:
                return section.offset + (rva - s_rva)
        return None

    @staticmethod
    def report(findings: list[SEHFinding]) -> str:
        if not findings:
            return 'SEHChainAnalyzer: no findings.'
        n_high = sum(1 for f in findings if f.severity in ('CRITICAL', 'HIGH'))
        n_med  = sum(1 for f in findings if f.severity == 'MEDIUM')
        lines  = [
            f'SEHChainAnalyzer: {len(findings)} finding(s)  '
            f'({n_high} HIGH  {n_med} MEDIUM)',
            '',
        ]
        for f in findings:
            lines.append(f'  [{f.severity}] {f.title}')
            lines.append(f'    location : {f.location}')
            if f.cwe:
                lines.append(f'    cwe      : {f.cwe}')
            lines.append(f'    {f.description}')
            lines.append('')
        return '\n'.join(lines)
