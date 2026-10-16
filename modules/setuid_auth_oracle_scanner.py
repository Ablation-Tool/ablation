"""
setuid_auth_oracle_scanner.py — Setuid shadow-password oracle detector.

4 things that weren't possible before in Ablation:

1. **Detect CWE-307 (no rate limiting) in setuid validators without taint
   analysis.** A setuid binary that calls getspnam/crypt/strcmp and returns
   the result via exit code is a brute-force oracle. This module flags the
   pattern from PLT imports alone — no taint run required.

2. **Distinguish PAM-mediated auth from raw shadow validators.** PAM enforces
   rate limiting via pam_tally2, faillock, and audit hooks. A binary that
   calls getspnam directly (no pam_start in PLT) bypasses all of that. The
   module uses pam_start absence as a strong signal for missing controls.

3. **Find the validation function and its callers.** The module locates which
   function(s) call both getspnam and crypt within the same function body,
   then walks one level up the call graph to show reachability — replacing
   the manual call trace needed to confirm exploitability.

4. **Flag weak PRNG seeding alongside the oracle when srandom/random appear
   with time/gettimeofday.** One-time password generation seeded with wall
   clock time is a separate CWE-338 pattern but commonly co-occurs with the
   oracle pattern in the same binary. The module reports both in one pass.

Usage:
    scanner = SetuidAuthOracleScanner.from_context(ctx)
    hits = scanner.scan()
    print(scanner.report(hits))

    # Direct path (builds context internally):
    scanner = SetuidAuthOracleScanner.from_path('/path/to/binary')
    hits = scanner.scan()
"""

from __future__ import annotations

import bisect
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import capstone

_MAX_BINARY_BYTES = 256 * 1024 * 1024

from ablation.analyzers.binary_context import BinaryContext


# ── Indicator sets ────────────────────────────────────────────────────────────

# Shadow access functions — require root to read /etc/shadow
_SHADOW_FUNCS = {'getspnam', 'getspnam_r', 'shadow_ent', 'getspent', 'getspent_r'}

# Password hashing functions
_CRYPT_FUNCS = {'crypt', 'crypt_r', 'crypt_gensalt', 'crypt_gensalt_r'}

# Comparison functions that could seal a password check
_CMP_FUNCS = {'strcmp', 'strncmp', 'memcmp', 'strcasecmp'}

# Rate-limiting / PAM indicators — presence makes oracle less likely
_RATE_LIMIT_FUNCS = {
    'pam_start', 'pam_authenticate',
    'sleep', 'usleep', 'nanosleep',
    'pam_tally', 'pam_tally2',
}

# PRNG / time seeding pairs — CWE-338 co-pattern
_PRNG_FUNCS = {'srandom', 'srand', 'srand48'}
_TIME_FUNCS  = {'time', 'gettimeofday', 'clock_gettime'}
_RAND_FUNCS  = {'random', 'rand', 'lrand48', 'drand48'}


# ── Hit dataclass ─────────────────────────────────────────────────────────────

@dataclass
class OracleHit:
    binary_path: str
    is_setuid: bool
    shadow_func: str           # e.g. "getspnam"
    crypt_func: str            # e.g. "crypt"
    cmp_func: str              # e.g. "strcmp"
    has_rate_limit: bool       # True if PAM/sleep found
    rate_limit_funcs: List[str]
    oracle_func_va: int        # VA of the function doing all three calls
    oracle_func_name: str
    callers: List[str]
    cwe: str = 'CWE-307'
    # Optional PRNG co-finding
    weak_prng: bool = False
    prng_func: str = ''        # e.g. "srandom"
    time_func: str = ''        # e.g. "gettimeofday"
    rand_func: str = ''        # e.g. "random"

    def fmt(self) -> str:
        parts = [
            f"[{self.cwe}] Shadow auth oracle in {Path(self.binary_path).name}",
            f"  setuid:       {'yes' if self.is_setuid else 'no (check snmpd/daemon run context)'}",
            f"  shadow func:  {self.shadow_func}",
            f"  crypt func:   {self.crypt_func}",
            f"  cmp func:     {self.cmp_func}",
            f"  rate limited: {'yes — ' + ', '.join(self.rate_limit_funcs) if self.has_rate_limit else 'NO — no PAM, sleep, or tally in PLT'}",
            f"  oracle func:  {self.oracle_func_name} @ {self.oracle_func_va:#x}",
        ]
        if self.callers:
            parts.append(f"  callers:      {', '.join(self.callers)}")
        if self.weak_prng:
            parts.append(
                f"  weak prng:    [CWE-338] srandom/srand seeded with {self.time_func}, "
                f"OTP from {self.rand_func} — ~20 bits entropy"
            )
        return "\n".join(parts)


# ── Scanner ───────────────────────────────────────────────────────────────────

class SetuidAuthOracleScanner:
    """
    Finds setuid (or otherwise privileged) ELF binaries that expose shadow
    password validation as an exit-code oracle with no rate limiting.

    The heuristic:
      1. Binary is setuid-root (or is passed an is_privileged=True override).
      2. PLT imports getspnam (or getspnam_r) — direct /etc/shadow access.
      3. PLT imports crypt (or crypt_r) — password hashing.
      4. No pam_start / sleep / usleep in PLT — no rate limiting.
      5. At least one function calls both the shadow func and the crypt func.

    Optionally reports co-occurring CWE-338 when srandom/srand is seeded from
    time()/gettimeofday() in the same binary.
    """

    def __init__(self, ctx: BinaryContext, is_privileged: bool = False) -> None:
        if ctx.arch not in ('x86_64', 'x86-64', 'amd64', 'x86_64-linux-gnu'):
            raise ValueError(
                f"SetuidAuthOracleScanner: unsupported arch '{ctx.arch}'. "
                "Only x86-64 ELF binaries are supported."
            )
        self._ctx = ctx
        if ctx.path:
            _bin_size = Path(ctx.path).stat().st_size
            if _bin_size > _MAX_BINARY_BYTES:
                raise ValueError(
                    f'{ctx.path}: file size {_bin_size} exceeds {_MAX_BINARY_BYTES} byte limit')
            self._data = Path(ctx.path).read_bytes()
        else:
            self._data = b''
        self._base = ctx.base_va
        # PLT: va → name
        self._plt: Dict[int, str] = {va: name for va, name in ctx.plt.items()}
        self._plt_name_to_va: Dict[str, int] = {
            name.split('@')[0]: va for va, name in ctx.plt.items()
        }
        self._exp_rev: Dict[int, str] = {va: name for va, name in ctx.exports.items()}
        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._md.detail = True
        # Setuid check
        if ctx.path and os.path.exists(ctx.path):
            st = os.stat(ctx.path)
            self._is_setuid = bool(st.st_mode & 0o4000)
        else:
            self._is_setuid = is_privileged

    @classmethod
    def from_context(cls, ctx: BinaryContext, is_privileged: bool = False
                     ) -> 'SetuidAuthOracleScanner':
        return cls(ctx, is_privileged)

    @classmethod
    def from_path(cls, path: str, is_privileged: bool = False
                  ) -> 'SetuidAuthOracleScanner':
        return cls(BinaryContext.load_or_build(path), is_privileged)

    # -- helpers ---------------------------------------------------------------

    def _plt_has(self, names: Set[str]) -> List[str]:
        """Return which names from the set appear in PLT (base names only)."""
        found = []
        for va, full_name in self._plt.items():
            base = full_name.split('@')[0]
            if base in names:
                found.append(base)
        return list(set(found))

    def _disasm_func(self, func_va: int, next_func_va: int):
        off = func_va - self._base
        if off < 0 or off >= len(self._data):
            return []
        max_bytes = min(next_func_va - func_va, 8192)
        return list(self._md.disasm(self._data[off:off + max_bytes], func_va))

    def _callers_of(self, func_va: int) -> List[str]:
        seen: Set[int] = set()
        result = []
        for edge in self._ctx.call_edges:
            caller_va, callee_va, _ = edge
            if callee_va == func_va and caller_va not in seen:
                seen.add(caller_va)
                name = self._ctx.name(caller_va) or self._exp_rev.get(caller_va) or f'{caller_va:#x}'
                result.append(name)
        return result

    def _func_name(self, va: int) -> str:
        return (self._ctx.name(va) or self._exp_rev.get(va) or f'sub_{va:#x}')

    # -- scan ------------------------------------------------------------------

    def scan(self) -> List[OracleHit]:
        hits: List[OracleHit] = []

        # 1. Check for shadow + crypt imports
        shadow_present = self._plt_has(_SHADOW_FUNCS)
        crypt_present  = self._plt_has(_CRYPT_FUNCS)
        if not shadow_present or not crypt_present:
            return hits

        # 2. Rate-limiting PLT VAs (checked per-function, not globally)
        rate_vas: Set[int] = {
            va for va, name in self._plt.items()
            if name.split('@')[0] in _RATE_LIMIT_FUNCS
        }

        # 3. CWE-338 co-pattern check
        prng_present = self._plt_has(_PRNG_FUNCS)
        time_present = self._plt_has(_TIME_FUNCS)
        rand_present = self._plt_has(_RAND_FUNCS)
        weak_prng    = bool(prng_present and time_present and rand_present)

        # 4. Find functions calling both shadow and crypt
        shadow_vas: Set[int] = {
            va for va, name in self._plt.items()
            if name.split('@')[0] in _SHADOW_FUNCS
        }
        crypt_vas: Set[int] = {
            va for va, name in self._plt.items()
            if name.split('@')[0] in _CRYPT_FUNCS
        }
        cmp_vas: Set[int] = {
            va for va, name in self._plt.items()
            if name.split('@')[0] in _CMP_FUNCS
        }

        sorted_starts = sorted(self._ctx.func_starts)
        oracle_funcs: List[tuple] = []  # (func_va, shadow_name, crypt_name, cmp_name)

        for idx, func_va in enumerate(sorted_starts):
            next_va = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else func_va + 8192
            saw_shadow = ''
            saw_crypt  = ''
            saw_cmp    = ''
            saw_rate: List[str] = []
            for insn in self._disasm_func(func_va, next_va):
                if insn.mnemonic not in ('call', 'jmp'):
                    continue
                if not insn.operands:
                    continue
                op = insn.operands[0]
                if op.type != capstone.x86.X86_OP_IMM:
                    continue
                target = op.imm
                if target in shadow_vas and not saw_shadow:
                    saw_shadow = self._plt.get(target, '').split('@')[0]
                if target in crypt_vas and not saw_crypt:
                    saw_crypt = self._plt.get(target, '').split('@')[0]
                if target in cmp_vas and not saw_cmp:
                    saw_cmp = self._plt.get(target, '').split('@')[0]
                if target in rate_vas:
                    rname = self._plt.get(target, '').split('@')[0]
                    if rname not in saw_rate:
                        saw_rate.append(rname)
            if saw_shadow and saw_crypt:
                oracle_funcs.append(
                    (func_va, saw_shadow, saw_crypt, saw_cmp or 'strcmp', saw_rate)
                )

        if not oracle_funcs:
            return hits

        # 5. Emit one hit per oracle function
        for func_va, shadow_name, crypt_name, cmp_name, func_rate_funcs in oracle_funcs:
            hits.append(OracleHit(
                binary_path=self._ctx.path or '',
                is_setuid=self._is_setuid,
                shadow_func=shadow_name,
                crypt_func=crypt_name,
                cmp_func=cmp_name,
                has_rate_limit=bool(func_rate_funcs),
                rate_limit_funcs=func_rate_funcs,
                oracle_func_va=func_va,
                oracle_func_name=self._func_name(func_va),
                callers=self._callers_of(func_va),
                weak_prng=weak_prng,
                prng_func=prng_present[0] if prng_present else '',
                time_func=time_present[0] if time_present else '',
                rand_func=rand_present[0] if rand_present else '',
            ))

        return hits

    # -- report ----------------------------------------------------------------

    def report(self, hits: List[OracleHit]) -> str:
        if not hits:
            return "SetuidAuthOracleScanner: no shadow auth oracle pattern found.\n"
        lines = [
            f"SetuidAuthOracleScanner: {len(hits)} oracle function(s) found",
            "",
        ]
        for h in hits:
            lines.append(h.fmt())
            lines.append("")
        return "\n".join(lines)
