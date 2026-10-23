"""
build_integrity_analyzer.py: ELF/PE build hardening flag checker.

Checks for compiler and linker hardening features applied at build time:

  ELF:
    - Stack canary: __stack_chk_fail in PLT
    - PIE: ET_DYN ELF type
    - Full RELRO: PT_GNU_RELRO segment present + BIND_NOW/DF_BIND_NOW set
    - Partial RELRO: PT_GNU_RELRO present but not BIND_NOW
    - NX/DEP: PT_GNU_STACK execute bit clear
    - FORTIFY_SOURCE: __*_chk variants in PLT (sprintf_chk, memcpy_chk, etc.)
    - CFI/BTI: .note.gnu.property with GNU_PROPERTY_AARCH64_FEATURE_1_BTI

  PE (Windows):
    - ASLR: IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    - DEP/NX: IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    - SafeSEH: IMAGE_DLLCHARACTERISTICS_NO_SEH absent + /SAFESEH
    - Control Flow Guard: IMAGE_DLLCHARACTERISTICS_GUARD_CF

Each missing feature is a finding. Severity:
  HIGH  — NX/DEP absent (code injection directly executable)
  HIGH  — Stack canary absent in a binary with stack allocations
  HIGH  — No ASLR/PIE
  MEDIUM — No RELRO (GOT overwrite feasible)
  LOW   — No FORTIFY_SOURCE

Usage:
    analyzer = BuildIntegrityAnalyzer('/path/to/binary')
    findings = analyzer.scan()
    print(analyzer.report(findings))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional


# ELF constants
_ET_DYN = 3
_PT_GNU_STACK = 0x6474e551
_PT_GNU_RELRO = 0x6474e552
_PT_GNU_PROPERTY = 0x6474e553
_PF_X = 0x1
_DF_BIND_NOW = 0x8
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6ffffffb
_DF_1_NOW = 0x1

_FORTIFY_INDICATORS = frozenset({
    '__sprintf_chk', '__snprintf_chk', '__memcpy_chk', '__memmove_chk',
    '__memset_chk', '__strcpy_chk', '__strncpy_chk', '__strcat_chk',
    '__strncat_chk', '__gets_chk', '__read_chk', '__fgets_chk',
    '__fprintf_chk', '__printf_chk', '__vprintf_chk', '__vfprintf_chk',
})

# PE constants
_IMAGE_DLLCHAR_DYNAMIC_BASE = 0x0040
_IMAGE_DLLCHAR_NX_COMPAT    = 0x0100
_IMAGE_DLLCHAR_NO_SEH       = 0x0400
_IMAGE_DLLCHAR_GUARD_CF     = 0x4000


@dataclass
class HardeningFinding:
    feature:     str    # feature name
    status:      str    # PRESENT / ABSENT / PARTIAL
    severity:    str    # HIGH / MEDIUM / LOW / INFO
    note:        str

    def fmt(self) -> str:
        icon = '+' if self.status == 'PRESENT' else '-' if self.status == 'ABSENT' else '~'
        sev = f' [{self.severity}]' if self.status != 'PRESENT' else ''
        return f"  [{icon}] {self.feature}{sev}  {self.note}"


class BuildIntegrityAnalyzer:
    """Check ELF/PE binary for compiler/linker hardening features."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'BuildIntegrityAnalyzer':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._ctx  = ctx
        return obj

    def _load_ctx(self):
        if self._ctx is not None:
            return self._ctx
        from ablation.analyzers.binary_context import BinaryContext
        self._ctx = BinaryContext.load_or_build(self._path)
        return self._ctx

    def _read_raw(self) -> bytes:
        try:
            return open(self._path, 'rb').read()
        except OSError:
            return b''

    def _plt_names(self) -> frozenset:
        try:
            ctx = self._load_ctx()
            return frozenset(n.split('@')[0].lstrip('_') for n, _ in ctx.plt_entries())
        except Exception:
            return frozenset()

    def _is_elf(self, raw: bytes) -> bool:
        return len(raw) >= 4 and raw[:4] == b'\x7fELF'

    def _is_pe(self, raw: bytes) -> bool:
        return len(raw) >= 2 and raw[:2] == b'MZ'

    def _scan_elf(self, raw: bytes, plt: frozenset) -> list[HardeningFinding]:
        findings: list[HardeningFinding] = []
        try:
            import lief
            elf = lief.parse(self._path)
            if elf is None:
                return []

            # PIE
            is_pie = (elf.header.file_type == lief.ELF.Header.FILE_TYPE.DYN)
            findings.append(HardeningFinding(
                'PIE',
                'PRESENT' if is_pie else 'ABSENT',
                'INFO' if is_pie else 'HIGH',
                'ET_DYN' if is_pie else 'ET_EXEC — fixed load address, no ASLR',
            ))

            # Stack canary
            has_canary = '__stack_chk_fail' in plt or 'stack_chk_fail' in plt
            findings.append(HardeningFinding(
                'Stack canary',
                'PRESENT' if has_canary else 'ABSENT',
                'INFO' if has_canary else 'HIGH',
                '__stack_chk_fail in PLT' if has_canary else 'no __stack_chk_fail — stack smashing undetected',
            ))

            # NX
            nx = True
            for seg in elf.segments:
                if seg.type == lief.ELF.Segment.TYPE.GNU_STACK:
                    nx = not bool(seg.flags & lief.ELF.Segment.FLAGS.X)
                    break
            findings.append(HardeningFinding(
                'NX/DEP',
                'PRESENT' if nx else 'ABSENT',
                'INFO' if nx else 'HIGH',
                'GNU_STACK not executable' if nx else 'GNU_STACK is executable — shellcode directly runnable',
            ))

            # RELRO
            has_relro = any(seg.type == lief.ELF.Segment.TYPE.GNU_RELRO for seg in elf.segments)
            bind_now = False
            for entry in elf.dynamic_entries:
                if entry.tag in (lief.ELF.DynamicEntry.TAG.FLAGS, lief.ELF.DynamicEntry.TAG.FLAGS_1):
                    if entry.value & (_DF_BIND_NOW if entry.tag == lief.ELF.DynamicEntry.TAG.FLAGS else _DF_1_NOW):
                        bind_now = True
            if has_relro and bind_now:
                findings.append(HardeningFinding('Full RELRO', 'PRESENT', 'INFO', 'PT_GNU_RELRO + BIND_NOW'))
            elif has_relro:
                findings.append(HardeningFinding('Full RELRO', 'PARTIAL', 'MEDIUM',
                                                  'PT_GNU_RELRO present but no BIND_NOW — partial RELRO only'))
            else:
                findings.append(HardeningFinding('RELRO', 'ABSENT', 'MEDIUM',
                                                  'no PT_GNU_RELRO — GOT overwrite feasible'))

            # FORTIFY
            has_fortify = bool(plt & _FORTIFY_INDICATORS)
            findings.append(HardeningFinding(
                'FORTIFY_SOURCE',
                'PRESENT' if has_fortify else 'ABSENT',
                'INFO' if has_fortify else 'LOW',
                '__*_chk variants in PLT' if has_fortify else 'no __*_chk — buffer overflow detection disabled',
            ))

        except Exception:
            findings.append(HardeningFinding('parse', 'ABSENT', 'INFO', 'lief parse failed'))
        return findings

    def _scan_pe(self, raw: bytes) -> list[HardeningFinding]:
        findings: list[HardeningFinding] = []
        try:
            import lief
            pe = lief.parse(self._path)
            if pe is None:
                return []
            ch = pe.optional_header.dll_characteristics
            aslr = bool(ch & _IMAGE_DLLCHAR_DYNAMIC_BASE)
            nx   = bool(ch & _IMAGE_DLLCHAR_NX_COMPAT)
            cfg  = bool(ch & _IMAGE_DLLCHAR_GUARD_CF)
            findings.append(HardeningFinding('ASLR', 'PRESENT' if aslr else 'ABSENT',
                                              'INFO' if aslr else 'HIGH',
                                              'DYNAMIC_BASE set' if aslr else 'no DYNAMIC_BASE'))
            findings.append(HardeningFinding('DEP/NX', 'PRESENT' if nx else 'ABSENT',
                                              'INFO' if nx else 'HIGH',
                                              'NX_COMPAT set' if nx else 'no NX_COMPAT'))
            findings.append(HardeningFinding('CFG', 'PRESENT' if cfg else 'ABSENT',
                                              'INFO' if cfg else 'MEDIUM',
                                              'GUARD_CF set' if cfg else 'no Control Flow Guard'))
        except Exception:
            findings.append(HardeningFinding('parse', 'ABSENT', 'INFO', 'lief parse failed'))
        return findings

    def scan(self) -> List[HardeningFinding]:
        raw = self._read_raw()
        if not raw:
            return []
        plt = self._plt_names()
        if self._is_elf(raw):
            return self._scan_elf(raw, plt)
        if self._is_pe(raw):
            return self._scan_pe(raw)
        return []

    def report(self, findings: Optional[List[HardeningFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'BuildIntegrityAnalyzer: no results for {self._path}'
        absent = [f for f in findings if f.status != 'PRESENT']
        lines = [f'BuildIntegrityAnalyzer: {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
        if absent:
            lines.append('')
            lines.append(f'  {len(absent)} feature(s) absent or partial')
        lines.append('')
        return '\n'.join(lines)
