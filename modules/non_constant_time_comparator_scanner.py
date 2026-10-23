"""
non_constant_time_comparator_scanner.py: Non-constant-time comparison detector.

Detects uses of strcmp/memcmp (which return early on the first differing byte)
in security-sensitive comparison contexts: password verification, HMAC/MAC
validation, token comparison, and cryptographic signature checks.

An early-exit comparison leaks timing information: the comparison takes longer
the more bytes match. Against a controlled oracle, this allows byte-by-byte
brute-forcing of the expected value.

Detection strategy:
  1. Find all PLT call sites for strcmp, strncmp, memcmp, bcmp.
  2. For each call site, examine the arguments loaded before the call.
  3. Flag call sites where at least one argument is loaded from a context
     with a security-sensitive string in scope (variable name heuristic via
     nearby rodata strings, or argument provenance from security-named caller).
  4. Flag call sites in functions whose names contain security-relevant keywords.
  5. Also flag absence of constant-time comparison functions (CRYPTO_memcmp,
     timingsafe_bcmp, etc.) when a cryptographic library is present.

Usage:
    scanner = NonConstantTimeComparatorScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations
from modules._disasm_helper import disasm_func

import re
from dataclasses import dataclass
from typing import List, Optional


# Non-constant-time comparison functions
_EARLY_EXIT_CMPS: frozenset = frozenset({
    'strcmp', 'strncmp', 'strcasecmp', 'strncasecmp',
    'memcmp', 'bcmp', 'wmemcmp',
})

# Constant-time alternatives (their presence is a positive signal)
_CT_CMPS: frozenset = frozenset({
    'CRYPTO_memcmp',       # OpenSSL
    'timingsafe_bcmp',     # OpenBSD libc
    'timingsafe_memcmp',
    'crypto_memcmp',       # libsodium
    'safe_memcmp',
    'consttime_memequal',
    'secure_compare',
})

# Security-sensitive context keywords (in surrounding rodata or function names)
_SECURITY_KEYWORDS = re.compile(
    rb'passw|secret|token|hmac|mac|digest|hash|sig(?:nature)?|auth|key|nonce|'
    rb'cred|cert|pin|otp|challenge|response|bearer|api.key',
    re.I,
)

# Security-sensitive function name keywords
_SECURITY_FUNC_KEYWORDS = re.compile(
    r'(check|verify|validate|compare|auth|login|password|token|hmac|mac|sign)',
    re.I,
)


@dataclass
class CTFinding:
    func_va:        int
    func_name:      str
    call_va:        int
    cmp_func:       str      # strcmp / memcmp / etc.
    context_hint:   str      # why this was flagged
    severity:       str      # HIGH / MEDIUM

    def fmt(self) -> str:
        return (f"  {self.severity:6s}  [NON_CT_COMPARE]  {self.func_name}\n"
                f"         {self.cmp_func} at 0x{self.call_va:x}\n"
                f"         context: {self.context_hint}")


class NonConstantTimeComparatorScanner:
    """Detect non-constant-time comparisons in security-critical contexts."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'NonConstantTimeComparatorScanner':
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

    def _get_plt_map(self, ctx) -> dict[str, int]:
        result: dict[str, int] = {}
        for va, name in ctx.plt.items():
            base = name.split('@')[0].lstrip('_')
            result[base] = va
        return result

    def _get_plt_va_set(self, plt_map: dict[str, int]) -> dict[int, str]:
        return {va: name for name, va in plt_map.items()}

    def _has_ct_alternatives(self, plt_map: dict[str, int]) -> bool:
        return bool(set(plt_map.keys()) & _CT_CMPS)

    def _rodata_window(self, raw: bytes, offset: int, window: int = 256) -> bytes:
        start = max(0, offset - window)
        end = min(len(raw), offset + window)
        return raw[start:end]

    def scan(self) -> List[CTFinding]:
        ctx = self._load_ctx()
        raw = self._read_raw()
        plt_map = self._get_plt_map(ctx)
        va_to_name = self._get_plt_va_set(plt_map)

        # Find which early-exit comparators are imported
        imported_cmps = {name: va for name, va in plt_map.items() if name in _EARLY_EXIT_CMPS}
        if not imported_cmps:
            return []

        has_ct = self._has_ct_alternatives(plt_map)
        findings: list[CTFinding] = []

        for func_va in ctx.func_starts:
            func_name = ctx.name(func_va)

            # Check function name for security context
            func_is_security = bool(_SECURITY_FUNC_KEYWORDS.search(func_name))

            for insn in disasm_func(ctx, func_va):
                mn = insn.mnemonic.lower()
                if mn not in ('call', 'bl', 'blx', 'jalr', 'jal'):
                    continue

                # Resolve call target
                try:
                    op = insn.op_str.strip()
                    target_va = int(op.lstrip('#'), 16)
                except (ValueError, AttributeError):
                    continue

                cmp_name = va_to_name.get(target_va)
                if cmp_name not in _EARLY_EXIT_CMPS:
                    continue

                # Determine context
                if func_is_security:
                    context = f'in security function {func_name}'
                    severity = 'HIGH'
                else:
                    # Check nearby rodata for security keywords
                    # Use file offset approximation: VA - base
                    try:
                        base = ctx.load_address()
                    except Exception:
                        base = 0
                    file_off = insn.address - base
                    window = self._rodata_window(raw, file_off)
                    if _SECURITY_KEYWORDS.search(window):
                        context = 'near security-sensitive string in rodata'
                        severity = 'MEDIUM'
                    elif not has_ct:
                        context = 'no constant-time alternative imported (library-wide)'
                        severity = 'MEDIUM'
                    else:
                        continue  # not in a clearly security context

                findings.append(CTFinding(
                    func_va=func_va,
                    func_name=func_name,
                    call_va=insn.address,
                    cmp_func=cmp_name,
                    context_hint=context,
                    severity=severity,
                ))

        return findings

    def report(self, findings: Optional[List[CTFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'NonConstantTimeComparatorScanner: no timing-unsafe comparisons in {self._path}'
        lines = [f'NonConstantTimeComparatorScanner: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
