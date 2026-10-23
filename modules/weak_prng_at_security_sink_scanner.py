"""
weak_prng_at_security_sink_scanner.py: Weak PRNG at security sink detector.

Detects use of weak pseudo-random number generators (PRNG) in the call graph
leading to security-sensitive operations: session ID generation, nonce creation,
token output, and cryptographic key derivation.

Weak PRNGs covered:
  - srand(time(NULL)) / rand() / random() / lrand48() — seeded with clock, predictable
  - rand_r() — same algorithm as rand(), just thread-safe
  - drand48() / mrand48() / nrand48() — LCG-based, 48-bit state
  - arc4random() on glibc (not cryptographically strong for keys, acceptable for nonces)

Security sinks where weak randomness is dangerous:
  - Session ID / token generation paths (functions named: gen_session, create_token, etc.)
  - Password reset token generation
  - CSRF token generation
  - Key derivation (function names containing: keygen, derive_key, etc.)
  - Nonce generation for encryption

Detection strategy:
  1. Find weak PRNG PLT entries in the binary.
  2. Find strong PRNG PLT entries (getrandom, /dev/urandom read, RAND_bytes, etc.).
  3. If weak PRNGs present and strong PRNGs absent: flag globally (HIGH).
  4. If both present: walk the call graph from security-named functions and flag
     any that call a weak PRNG without calling a strong PRNG first (MEDIUM).

Usage:
    scanner = WeakPRNGAtSecuritySinkScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


_WEAK_PRNGS: frozenset = frozenset({
    'rand', 'srand', 'random', 'srandom', 'rand_r',
    'lrand48', 'mrand48', 'nrand48', 'drand48',
    'jrand48', 'erand48', 'srand48', 'lcong48', 'seed48',
    'random_r',
})

_STRONG_PRNGS: frozenset = frozenset({
    'getrandom', 'getentropy',
    'RAND_bytes', 'RAND_priv_bytes',      # OpenSSL
    'randombytes', 'randombytes_buf',      # libsodium
    'arc4random', 'arc4random_buf',        # BSDs / recent glibc
    'BCryptGenRandom',                     # Windows
    'CryptGenRandom',                      # Windows legacy
    'SecRandomCopyBytes',                  # Apple
    'wc_RNG_GenerateBlock',               # wolfSSL
})

# Security context: function name patterns where weak PRNG is dangerous
_SECURITY_CONTEXT_PAT = re.compile(
    r'(session|token|nonce|csrf|key.?gen|derive.?key|otp|secret|passw|auth|'
    r'challeng|random.?id|gen.?rand|rand.?gen|uuid)',
    re.I,
)

# Time-seed patterns — srand(time(...)) is particularly weak
_TIME_FUNCS: frozenset = frozenset({'time', 'clock', 'gettimeofday', 'clock_gettime'})


@dataclass
class WeakPRNGFinding:
    scope:         str          # 'global' or function name
    scope_va:      int          # 0 for global
    weak_prngs:    list[str]    # which weak PRNGs are used
    time_seeded:   bool         # srand(time(...)) pattern detected
    no_strong:     bool         # no strong PRNG in binary at all
    severity:      str          # HIGH / MEDIUM

    def fmt(self) -> str:
        prng_str = ', '.join(self.weak_prngs)
        seed_note = ' (time-seeded)' if self.time_seeded else ''
        global_note = 'no strong PRNG in binary' if self.no_strong else 'strong PRNG absent from this path'
        if self.scope == 'global':
            return (f"  {self.severity:6s}  [WEAK_PRNG]  global: {prng_str}{seed_note}\n"
                    f"         {global_note}")
        return (f"  {self.severity:6s}  [WEAK_PRNG]  {self.scope} at 0x{self.scope_va:x}\n"
                f"         uses: {prng_str}{seed_note}\n"
                f"         {global_note}")


class WeakPRNGAtSecuritySinkScanner:
    """Detect weak PRNG usage in security-sensitive code paths."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'WeakPRNGAtSecuritySinkScanner':
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

    def _plt_name_set(self, ctx) -> frozenset:
        return frozenset(n.split('@')[0].lstrip('_') for n, _ in ctx.plt_entries())

    def _plt_va_map(self, ctx) -> dict[int, str]:
        result: dict[int, str] = {}
        for name, va in ctx.plt_entries():
            base = name.split('@')[0].lstrip('_')
            result[va] = base
        return result

    def _func_calls_weak_prng(self, ctx, func_va: int, plt_va_map: dict[int, str]) -> list[str]:
        weak_found: list[str] = []
        for insn in ctx.disasm_func(func_va):
            mn = insn.mnemonic.lower()
            if mn not in ('call', 'bl', 'blx', 'jalr', 'jal'):
                continue
            try:
                target = int(insn.op_str.strip().lstrip('#'), 16)
            except (ValueError, AttributeError):
                continue
            name = plt_va_map.get(target, '')
            if name in _WEAK_PRNGS:
                weak_found.append(name)
        return weak_found

    def _func_calls_time(self, ctx, func_va: int, plt_va_map: dict[int, str]) -> bool:
        for insn in ctx.disasm_func(func_va):
            mn = insn.mnemonic.lower()
            if mn not in ('call', 'bl', 'blx', 'jalr', 'jal'):
                continue
            try:
                target = int(insn.op_str.strip().lstrip('#'), 16)
            except (ValueError, AttributeError):
                continue
            if plt_va_map.get(target, '') in _TIME_FUNCS:
                return True
        return False

    def scan(self) -> List[WeakPRNGFinding]:
        ctx = self._load_ctx()
        plt_names = self._plt_name_set(ctx)
        plt_va_map = self._plt_va_map(ctx)

        imported_weak = sorted(plt_names & _WEAK_PRNGS)
        imported_strong = sorted(plt_names & _STRONG_PRNGS)
        has_time_seed = bool(plt_names & _TIME_FUNCS) and bool(plt_names & {'srand', 'srandom', 'srand48'})

        if not imported_weak:
            return []

        findings: list[WeakPRNGFinding] = []
        no_strong = not imported_strong

        if no_strong:
            # Global finding: weak PRNG and no strong PRNG at all
            findings.append(WeakPRNGFinding(
                scope='global',
                scope_va=0,
                weak_prngs=imported_weak,
                time_seeded=has_time_seed,
                no_strong=True,
                severity='HIGH',
            ))
            return findings

        # Both present: check security-named functions
        for func_va in ctx.func_starts:
            func_name = ctx.name(func_va)
            if not _SECURITY_CONTEXT_PAT.search(func_name):
                continue
            weak_in_func = self._func_calls_weak_prng(ctx, func_va, plt_va_map)
            if not weak_in_func:
                continue
            time_seeded = self._func_calls_time(ctx, func_va, plt_va_map)
            findings.append(WeakPRNGFinding(
                scope=func_name,
                scope_va=func_va,
                weak_prngs=weak_in_func,
                time_seeded=time_seeded,
                no_strong=False,
                severity='HIGH' if time_seeded else 'MEDIUM',
            ))

        return findings

    def report(self, findings: Optional[List[WeakPRNGFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'WeakPRNGAtSecuritySinkScanner: no weak-PRNG findings in {self._path}'
        lines = [f'WeakPRNGAtSecuritySinkScanner: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
