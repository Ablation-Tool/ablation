"""
cfg_bypass_detector.py — Control Flow Guard bypass analysis for Windows PE binaries.

CFG validates indirect call targets against a compiler-built bitmap of valid
function entry points. An address not in that table triggers a CFG violation.
This module finds three classes of bypass opportunity:

  1. CFG is not enabled at all — every indirect call is unprotected.
  2. Export suppression is missing — all exported functions are valid CFG
     call targets even if they were never meant to be, expanding the attacker's
     gadget surface to the entire export table.
  3. Exported functions not in the CFG table — when export suppression IS
     enabled, these specific exports slip through as reachable bypass targets.

Usage:
    from ablation.analyzers.cfg_bypass_detector import CFGBypassDetector

    det = CFGBypassDetector.from_path('ntdll.dll')
    findings = det.scan()
    print(CFGBypassDetector.report(findings))

    cfg = det.cfg_config()
    print(f"CFG enabled: {cfg.cfg_enabled}, {cfg.function_count} protected functions")
    print(f"export suppression: {cfg.export_suppression}")
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


# IMAGE_GUARD_CF_* flag bits (winnt.h)
_FLAG_CF_INSTRUMENTED       = 0x00000100  # CFG enabled
_FLAG_CFW_INSTRUMENTED      = 0x00000200  # CFG write protection
_FLAG_CF_TABLE_PRESENT      = 0x00000400  # function table populated
_FLAG_EXPORT_SUPPRESSION    = 0x00008000  # exports excluded from CFG targets
_FLAG_LONGJUMP_TABLE        = 0x00010000  # longjmp table present
_FLAG_XFG_ENABLED           = 0x00800000  # eXtended Flow Guard (stricter)


@dataclass
class CFGConfig:
    """Parsed CFG configuration from IMAGE_LOAD_CONFIG."""
    cfg_enabled: bool
    guard_flags: int
    function_count: int
    function_table_va: int
    function_table_rvas: list[int] = field(default_factory=list)

    @property
    def instrumented(self) -> bool:
        return bool(self.guard_flags & _FLAG_CF_INSTRUMENTED)

    @property
    def table_present(self) -> bool:
        return bool(self.guard_flags & _FLAG_CF_TABLE_PRESENT)

    @property
    def export_suppression(self) -> bool:
        return bool(self.guard_flags & _FLAG_EXPORT_SUPPRESSION)

    @property
    def longjump_table(self) -> bool:
        return bool(self.guard_flags & _FLAG_LONGJUMP_TABLE)

    @property
    def xfg_enabled(self) -> bool:
        return bool(self.guard_flags & _FLAG_XFG_ENABLED)

    @property
    def entry_stride(self) -> int:
        """Bytes per CFG table entry: 4-byte RVA + optional metadata bytes."""
        return 4 + (self.guard_flags >> 28)


@dataclass
class CFGBypassFinding:
    """A single CFG bypass opportunity or configuration gap."""
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str       # cfg_disabled | cfg_table_absent | no_export_suppression |
                        # export_not_in_table | indirect_call_stats
    title: str
    location: str
    description: str
    va: int = 0
    cwe: str = ""


class CFGBypassDetector:
    """Control Flow Guard bypass analysis for Windows PE binaries.

    Parses IMAGE_LOAD_CONFIG to read CFG flags and the protected function table,
    then cross-references the export table to find functions that an attacker
    can redirect an indirect call toward without triggering a CFG violation.
    """

    def __init__(self, pe: 'lief.PE.Binary', path: str, raw: bytes) -> None:
        self._pe = pe
        self._path = path
        self._raw = raw
        self._cfg: Optional[CFGConfig] = None

    @classmethod
    def from_path(cls, path: str) -> 'CFGBypassDetector':
        if not _LIEF_OK:
            raise ImportError("lief required: pip install lief>=0.14.0")
        raw = Path(path).read_bytes()
        pe = lief.parse(str(path))
        if pe is None or not isinstance(pe, lief.PE.Binary):
            raise ValueError(f"CFGBypassDetector: not a PE binary: {path}")
        return cls(pe, str(path), raw)

    # ── CFG configuration ─────────────────────────────────────────────────────

    def cfg_config(self) -> CFGConfig:
        """Parse IMAGE_LOAD_CONFIG and return the CFG configuration."""
        if self._cfg is not None:
            return self._cfg

        lc = self._pe.load_configuration
        if lc is None:
            self._cfg = CFGConfig(
                cfg_enabled=False, guard_flags=0,
                function_count=0, function_table_va=0,
            )
            return self._cfg

        guard_flags = int(getattr(lc, 'guard_flags', 0) or 0)
        table_va    = int(getattr(lc, 'guard_cf_function_table', 0) or 0)
        count       = int(getattr(lc, 'guard_cf_function_count', 0) or 0)
        cfg_enabled = bool(guard_flags & _FLAG_CF_INSTRUMENTED)

        table_rvas: list[int] = []
        if cfg_enabled and table_va and count:
            stride = 4 + (guard_flags >> 28)
            offset = self._va_to_offset(table_va)
            if offset is not None:
                for i in range(count):
                    pos = offset + i * stride
                    if pos + 4 <= len(self._raw):
                        (rva,) = struct.unpack_from('<I', self._raw, pos)
                        table_rvas.append(rva)

        self._cfg = CFGConfig(
            cfg_enabled=cfg_enabled,
            guard_flags=guard_flags,
            function_count=count,
            function_table_va=table_va,
            function_table_rvas=table_rvas,
        )
        return self._cfg

    # ── Scan ─────────────────────────────────────────────────────────────────

    def scan(self) -> list[CFGBypassFinding]:
        """Return all CFG bypass findings for the binary."""
        findings: list[CFGBypassFinding] = []
        cfg = self.cfg_config()
        imagebase = self._pe.optional_header.imagebase
        name = Path(self._path).name

        if not cfg.cfg_enabled:
            findings.append(CFGBypassFinding(
                severity='HIGH',
                category='cfg_disabled',
                title='CFG not enabled',
                location=name,
                description=(
                    'IMAGE_LOAD_CONFIG.GuardFlags does not include '
                    'IMAGE_GUARD_CF_INSTRUMENTED (0x100). The binary offers no '
                    'indirect call protection. Every function pointer the attacker '
                    'controls is a valid redirection target.'
                ),
                cwe='CWE-693',
            ))
            # No further analysis useful without CFG
            indirect = self._count_indirect_calls()
            if indirect:
                findings.append(CFGBypassFinding(
                    severity='INFO',
                    category='indirect_call_stats',
                    title=f'{indirect} indirect call/jmp-through-register sites',
                    location=name,
                    description=(
                        f'{indirect} indirect control transfers found in code sections. '
                        'None are protected by CFG.'
                    ),
                ))
            return findings

        if not cfg.table_present:
            findings.append(CFGBypassFinding(
                severity='HIGH',
                category='cfg_table_absent',
                title='CFG enabled but function table absent',
                location=name,
                description=(
                    'IMAGE_GUARD_CF_INSTRUMENTED is set but '
                    'IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT (0x400) is not. '
                    'The runtime CFG check uses an empty or missing table, so '
                    'every address passes the check.'
                ),
                cwe='CWE-693',
            ))

        if not cfg.export_suppression:
            n_exports = sum(
                1 for e in self._pe.get_export().entries
                if self._pe.has_exports and not e.is_forwarded
            ) if self._pe.has_exports else 0
            findings.append(CFGBypassFinding(
                severity='MEDIUM',
                category='no_export_suppression',
                title='CFG export suppression not enabled',
                location=name,
                description=(
                    'IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION (0x8000) is not set. '
                    f'All {n_exports} exported functions are valid CFG call targets '
                    'regardless of whether they are in the protected function table, '
                    'giving attackers a wide gadget surface.'
                ),
                cwe='CWE-693',
            ))

        # Exports not in CFG table (only meaningful when export suppression is enabled)
        if cfg.export_suppression and cfg.function_table_rvas and self._pe.has_exports:
            cfg_rva_set = set(cfg.function_table_rvas)
            for exp in self._pe.get_export().entries:
                if exp.is_forwarded or not exp.value:
                    continue
                if exp.value not in cfg_rva_set:
                    va = imagebase + exp.value
                    findings.append(CFGBypassFinding(
                        severity='MEDIUM',
                        category='export_not_in_cfg_table',
                        title=f'Export bypasses CFG: {exp.name}',
                        location=f'{exp.name} @ 0x{va:016x}',
                        description=(
                            f'Export {exp.name!r} (RVA 0x{exp.value:x}) is not in the '
                            f'CFG protected function table. Despite export suppression '
                            f'being enabled, this function can be used as an indirect '
                            f'call target without triggering a CFG violation.'
                        ),
                        va=va,
                        cwe='CWE-693',
                    ))

        # Summary: indirect call count
        indirect = self._count_indirect_calls()
        if indirect:
            findings.append(CFGBypassFinding(
                severity='INFO',
                category='indirect_call_stats',
                title=f'{indirect} indirect call/jmp sites, {cfg.function_count} CFG-protected functions',
                location=name,
                description=(
                    f'Found {indirect} indirect control transfers in code sections. '
                    f'{cfg.function_count} functions are in the CFG table '
                    f'(stride {cfg.entry_stride} bytes per entry). '
                    + ('XFG (eXtended Flow Guard) is also enabled.' if cfg.xfg_enabled else '')
                ),
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

    def _count_indirect_calls(self) -> int:
        """Count indirect call/jmp-through-register sites in all code sections."""
        if not _CS_OK:
            return 0
        cs_mode = capstone.CS_MODE_64 if self._pe.header.machine == lief.PE.MACHINE_TYPES.AMD64 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        md.detail = True
        imagebase = self._pe.optional_header.imagebase
        total = 0
        for section in self._pe.sections:
            if not (section.characteristics & 0x20000000):  # IMAGE_SCN_CNT_CODE
                continue
            offset = section.offset
            size = min(section.size, section.virtual_size or section.size)
            va = imagebase + section.virtual_address
            code = self._raw[offset:offset + size]
            for insn in md.disasm(code, va):
                if insn.id not in (capstone.x86.X86_INS_CALL, capstone.x86.X86_INS_JMP):
                    continue
                if not insn.operands:
                    continue
                op_type = insn.operands[0].type
                if op_type in (capstone.x86.X86_OP_REG, capstone.x86.X86_OP_MEM):
                    total += 1
        return total

    @staticmethod
    def report(findings: list[CFGBypassFinding]) -> str:
        if not findings:
            return 'CFGBypassDetector: no findings.'
        n_high = sum(1 for f in findings if f.severity in ('CRITICAL', 'HIGH'))
        n_med  = sum(1 for f in findings if f.severity == 'MEDIUM')
        lines  = [
            f'CFGBypassDetector: {len(findings)} finding(s)  '
            f'({n_high} HIGH  {n_med} MEDIUM)',
            '',
        ]
        for f in findings:
            lines.append(f'  [{f.severity}] {f.title}')
            lines.append(f'    location : {f.location}')
            lines.append(f'    category : {f.category}')
            if f.cwe:
                lines.append(f'    cwe      : {f.cwe}')
            lines.append(f'    {f.description}')
            lines.append('')
        return '\n'.join(lines)
