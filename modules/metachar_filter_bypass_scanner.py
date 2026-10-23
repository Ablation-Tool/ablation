"""
metachar_filter_bypass_scanner.py: Multi-byte sanitizer bypass detector.

Detects input validation functions that check for shell metacharacters using
single-byte comparisons but lack multi-byte or overlong encoding validation.
The bypass class: a sanitizer rejects the literal byte 0x2F for '/' but the
downstream interpreter (shell, XML parser, URL router) accepts an overlong
UTF-8 or URL-encoded sequence that decodes to '/'.

Detection strategy:
  1. Find functions that compare against shell metacharacter byte values
     (0x2F '/', 0x2E '.', 0x3B ';', etc.) using CMP/TEST instructions.
  2. Check whether those same functions also validate multi-byte sequence
     headers (0xC0, 0xE0, 0xF0 for UTF-8 lead bytes) or percent-encoding
     ('%' == 0x25 followed by hex digits).
  3. If a function checks metacharacter bytes but lacks multi-byte/percent
     validation, flag it as a likely single-byte sanitizer that is bypassable
     via encoding.

Shell metacharacters checked:
  0x00 NUL, 0x09 TAB, 0x0A LF, 0x0D CR,
  0x20 SPACE, 0x21 !, 0x22 ", 0x23 #,
  0x24 $, 0x25 %, 0x26 &, 0x27 ',
  0x28 (, 0x29 ), 0x2A *, 0x2B +,
  0x2C comma, 0x2F /, 0x3A :, 0x3B ;,
  0x3C <, 0x3E >, 0x3F ?, 0x40 @,
  0x5B [, 0x5C backslash, 0x5D ],
  0x60 backtick, 0x7C |, 0x7E ~

Usage:
    scanner = MetacharFilterBypassScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations
from modules._disasm_helper import disasm_func

import re
from dataclasses import dataclass
from typing import List, Optional


# Shell metacharacter byte values that single-byte filters typically check
_METACHAR_BYTES: frozenset = frozenset({
    0x00, 0x09, 0x0A, 0x0D,
    0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B,
    0x2C, 0x2F, 0x3A, 0x3B,
    0x3C, 0x3E, 0x3F, 0x40,
    0x5B, 0x5C, 0x5D, 0x60,
    0x7C, 0x7E,
})

# Multi-byte sequence lead bytes (UTF-8 2/3/4-byte sequences, overlong markers)
_MULTIBYTE_LEAD: frozenset = frozenset({
    0xC0, 0xC1,       # overlong 2-byte (always invalid but decoders accepted them)
    0xC2, 0xDF,       # valid 2-byte lead range
    0xE0, 0xEF,       # 3-byte lead range
    0xF0, 0xF4,       # 4-byte lead range
    0x25,             # '%' for percent-encoding (already in metachar but doubled here for clarity)
})

# Minimum metacharacter CMP hits for a function to be considered a sanitizer
_MIN_METACHAR_CMPS = 3

# Patterns for function name heuristics
_SANITIZE_PAT = re.compile(
    r'(saniti[sz]|filter|escape|strip|clean|valid|check|encod|allow|deny|block)',
    re.I,
)


@dataclass
class MetacharBypassFinding:
    func_va:         int
    func_name:       str
    metachar_hits:   list[int]    # metachar bytes that were CMP'd against
    has_multibyte:   bool         # function also checks for multi-byte leads
    has_exec_sink:   bool         # function also calls exec/system
    severity:        str

    def fmt(self) -> str:
        chars = ', '.join(f'0x{b:02x}' for b in sorted(self.metachar_hits)[:8])
        if len(self.metachar_hits) > 8:
            chars += f' (+{len(self.metachar_hits) - 8} more)'
        mb_note = 'multi-byte check present' if self.has_multibyte else 'NO multi-byte/percent check'
        exec_note = ', calls exec sink' if self.has_exec_sink else ''
        return (f"  {self.severity:6s}  [METACHAR_BYPASS]  {self.func_name} at 0x{self.func_va:x}\n"
                f"         {len(self.metachar_hits)} metachar CMPs: {chars}\n"
                f"         {mb_note}{exec_note}")


class MetacharFilterBypassScanner:
    """Detect single-byte metacharacter sanitizers bypassable via encoding."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'MetacharFilterBypassScanner':
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

    def _plt_exec_set(self, ctx) -> frozenset:
        exec_names = {'system', 'execve', 'execvp', 'execl', 'execle', 'execlp',
                      'popen', 'posix_spawn', 'ShellExecute', 'CreateProcess'}
        va_set: set[int] = set()
        for va, name in ctx.plt.items():
            base = name.split('@')[0].lstrip('_')
            if base in exec_names:
                va_set.add(va)
        return frozenset(va_set)

    def _analyze_func(self, insns: list, exec_vas: frozenset) -> tuple:
        """Returns (metachar_hits, has_multibyte, has_exec_sink)."""
        metachar_hits: set[int] = set()
        has_multibyte = False
        has_exec_sink = False

        for insn in insns:
            mn = insn.mnemonic.lower().split()[0]
            op = insn.op_str.lower()

            # Check for exec sink calls
            if mn in ('call', 'bl', 'blx', 'jalr', 'jal'):
                try:
                    target = int(op.strip().lstrip('#'), 16)
                    if target in exec_vas:
                        has_exec_sink = True
                except (ValueError, AttributeError):
                    pass
                continue

            # Only look at CMP/TEST instructions
            if mn not in ('cmp', 'test', 'cmn', 'tst'):
                continue

            # Extract immediate value from operand
            parts = op.split(',')
            if len(parts) < 2:
                continue
            imm_str = parts[-1].strip().lstrip('#')
            try:
                imm = int(imm_str, 16) if '0x' in imm_str else int(imm_str)
            except ValueError:
                continue

            if 0 <= imm <= 0xFF:
                if imm in _METACHAR_BYTES:
                    metachar_hits.add(imm)
                if imm in _MULTIBYTE_LEAD:
                    has_multibyte = True

        return sorted(metachar_hits), has_multibyte, has_exec_sink

    def scan(self) -> List[MetacharBypassFinding]:
        ctx = self._load_ctx()
        exec_vas = self._plt_exec_set(ctx)
        findings: list[MetacharBypassFinding] = []

        for func_va in ctx.func_starts:
            func_name = ctx.name(func_va)
            insns = list(disasm_func(ctx, func_va))
            metachar_hits, has_multibyte, has_exec_sink = self._analyze_func(insns, exec_vas)

            if len(metachar_hits) < _MIN_METACHAR_CMPS:
                continue

            if has_multibyte:
                continue

            # Sanitizer with only single-byte checks and no multi-byte validation
            is_named_sanitizer = bool(_SANITIZE_PAT.search(func_name))
            if is_named_sanitizer:
                severity = 'HIGH'
            elif has_exec_sink:
                severity = 'HIGH'
            else:
                severity = 'MEDIUM'

            findings.append(MetacharBypassFinding(
                func_va=func_va,
                func_name=func_name,
                metachar_hits=metachar_hits,
                has_multibyte=False,
                has_exec_sink=has_exec_sink,
                severity=severity,
            ))

        findings.sort(key=lambda f: len(f.metachar_hits), reverse=True)
        return findings

    def report(self, findings: Optional[List[MetacharBypassFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'MetacharFilterBypassScanner: no single-byte filter findings in {self._path}'
        lines = [f'MetacharFilterBypassScanner: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
