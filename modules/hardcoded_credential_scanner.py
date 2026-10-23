"""
hardcoded_credential_scanner.py: Hardcoded credential detector for stripped firmware.

Scans the binary's string table for API keys, tokens, passwords, and private key
material embedded in rodata or data sections.  Findings are independent of taint
analysis and require no architecture-specific support, so they cover every target
Ablation handles.

Pattern classes:
  AWS_ACCESS_KEY      AKIA… 20-char key
  AWS_SECRET_KEY      40-char base64-like string near "secret" or "aws"
  PRIVATE_KEY_PEM     -----BEGIN … PRIVATE KEY-----
  BEARER_TOKEN        "Bearer <token>" literals
  BASIC_AUTH_B64      base64-encoded user:pass in Authorization context
  JWT                 three-part base64url.base64url.base64url
  GENERIC_API_KEY     key=<32+ hex/base64 chars> patterns
  PASSWORD_LITERAL    password= / passwd= / pwd= followed by non-empty value

Usage:
    scanner = HardcodedCredentialScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = HardcodedCredentialScanner.from_context(ctx)
    findings = scanner.scan()
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class CredentialFinding:
    kind:     str    # pattern class name
    value:    str    # matched string (truncated to 80 chars for safety)
    context:  str    # surrounding string for manual review
    va:       int    # virtual address of the string (0 if unknown)
    severity: str    # HIGH / MEDIUM

    def fmt(self) -> str:
        return (f"  {self.severity:6s}  [{self.kind}]  va=0x{self.va:x}\n"
                f"         value:   {self.value!r}\n"
                f"         context: {self.context!r}")


# ── Patterns ───────────────────────────────────────────────────────────────────

# Each entry: (kind, compiled_pattern, severity, group_for_value)
_PATTERNS: list[tuple[str, re.Pattern, str, int]] = [
    ('AWS_ACCESS_KEY',
     re.compile(r'(AKIA[A-Z0-9]{16})', re.ASCII),
     'HIGH', 1),

    ('PRIVATE_KEY_PEM',
     re.compile(r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)', re.ASCII),
     'HIGH', 1),

    ('JWT',
     re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})', re.ASCII),
     'HIGH', 1),

    ('BEARER_TOKEN',
     re.compile(r'(?i)Bearer\s+([A-Za-z0-9\-._~+/]{20,})', re.ASCII),
     'HIGH', 1),

    # password= / passwd= / pwd= followed by a non-trivial value (not just placeholder)
    ('PASSWORD_LITERAL',
     re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*([^\s\x00]{8,})', re.ASCII),
     'HIGH', 1),

    # API key patterns: apikey= / api_key= / token= / secret= followed by value
    ('GENERIC_API_KEY',
     re.compile(r'(?i)(?:api[_\-]?key|apitoken|api[_\-]?secret|secret[_\-]?key|access[_\-]?token)\s*[=:]\s*([A-Za-z0-9\-._+/]{16,})', re.ASCII),
     'HIGH', 1),

    # Basic auth b64: base64 of user:pass is at least 8 chars with = padding
    ('BASIC_AUTH_B64',
     re.compile(r'(?i)(?:Authorization|Basic)\s*[=:]\s*((?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)', re.ASCII),
     'MEDIUM', 1),

    # AWS secret key: 40-char base64-like string near "aws" or "secret"
    ('AWS_SECRET_KEY',
     re.compile(r'(?i)(?:aws[_\-]?secret|secret[_\-]?access[_\-]?key)\s*[=:]\s*([A-Za-z0-9/+=]{40})', re.ASCII),
     'HIGH', 1),

    # Private key material indicators (non-PEM)
    ('PRIVATE_KEY_DER',
     re.compile(r'(PRIVATE KEY|private_key_pem|-----BEGIN CERTIFICATE-----)', re.ASCII),
     'MEDIUM', 1),
]


# ── Scanner ────────────────────────────────────────────────────────────────────

class HardcodedCredentialScanner:
    """Scan a binary's string table for hardcoded credentials and secrets."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'HardcodedCredentialScanner':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._ctx  = ctx
        return obj

    def _get_strings(self) -> list[tuple[int, str]]:
        """Return (va, string) pairs from the binary string table."""
        if self._ctx is not None and hasattr(self._ctx, 'strings'):
            return list(self._ctx.strings())
        # Fallback: extract printable strings from binary directly
        data = Path(self._path).read_bytes()
        results: list[tuple[int, str]] = []
        current: list[int] = []
        start = 0
        for i, b in enumerate(data):
            if 0x20 <= b <= 0x7E:
                if not current:
                    start = i
                current.append(b)
            else:
                if len(current) >= 8:
                    results.append((start, bytes(current).decode('ascii', errors='replace')))
                current = []
        if len(current) >= 8:
            results.append((start, bytes(current).decode('ascii', errors='replace')))
        return results

    def scan(self) -> List[CredentialFinding]:
        findings: list[CredentialFinding] = []
        seen: set[tuple[str, str]] = set()

        for va, s in self._get_strings():
            for kind, pattern, severity, group in _PATTERNS:
                for m in pattern.finditer(s):
                    value = m.group(group)
                    # Skip obvious placeholders
                    if value.lower() in {'password', 'secret', 'changeme', 'your-secret', 'placeholder',
                                         'example', 'xxxx', 'test', 'sample', 'dummy', 'none', 'null', ''}:
                        continue
                    key = (kind, value[:40])
                    if key in seen:
                        continue
                    seen.add(key)
                    context = s[max(0, m.start() - 20):m.end() + 20]
                    findings.append(CredentialFinding(
                        kind=kind,
                        value=value[:80],
                        context=context[:120],
                        va=va,
                        severity=severity,
                    ))

        findings.sort(key=lambda f: (0 if f.severity == 'HIGH' else 1, f.kind))
        return findings

    def report(self, findings: Optional[List[CredentialFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'HardcodedCredentialScanner: no credential findings in {self._path}'
        lines = [f'HardcodedCredentialScanner: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
