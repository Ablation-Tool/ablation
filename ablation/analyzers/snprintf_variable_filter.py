"""
snprintf_variable_filter.py: Post-filter for SinkArgClassifier SNPRINTF_RODATA
results that re-classifies findings where the format string contains variable
conversion specifiers (%s, %S, %n, or user-supplied width/precision).

SinkArgClassifier correctly identifies "the format string is in .rodata" as
SNPRINTF_RODATA, but that verdict alone does not rule out injection. A format
string like "/bin/netstat ... '%s'" has a hardcoded skeleton but a variable
argument fill — and if that fill is externally controlled, the sink is still
injectable.

This filter reads the actual format string bytes from the binary, checks for
specifiers that accept string or arbitrary data, and promotes matching results
to SNPRINTF_RODATA_VARIABLE with elevated severity.

Specifiers flagged:
  %s, %S        — string arguments (shell-metacharacter injection vector)
  %n            — write-to-pointer (memory safety)
  %*s, %-*s     — width/precision from argument (indirect control)

Specifiers NOT flagged:
  %d, %i, %u, %x, %o, %f, %g, %e, %c, %p  — numeric/pointer: no string injection

Usage:
    from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
    from ablation.analyzers.snprintf_variable_filter import SnprintfVariableFilter

    sac = SinkArgClassifier.from_context(ctx)
    results = sac.classify_all()

    filt = SnprintfVariableFilter(ctx.path)
    upgraded = filt.apply(results)

    for r in upgraded:
        if r.verdict == 'SNPRINTF_RODATA_VARIABLE':
            print(r.fmt())
"""

from __future__ import annotations

import re
import struct
from copy import copy
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# New verdict string — keeps the SNPRINTF_RODATA base but marks it elevated
SNPRINTF_RODATA_VARIABLE = 'SNPRINTF_RODATA_VARIABLE'

# Regex matching variable-injection-capable format specifiers:
#   %s, %S, %n, %*s, %-*s, %.*s, %<n>$s (positional), etc.
# Excludes %%, %-+0 numeric specs, %c, %p, %d, %i, %u, %x, %o, %f, %g, %e
_VARIABLE_SPEC_RE = re.compile(
    rb'%'
    rb'(?:[0-9*]*\$?)'      # optional positional index or width
    rb'(?:[-+ #0*]*)'       # optional flags
    rb'(?:[0-9*]*)'         # optional width
    rb'(?:\.(?:[0-9*]*))?'  # optional precision
    rb'(?:hh?|ll?|[LzjqtZI])?'  # optional length modifier
    rb'([sSnN])',            # specifier: s/S = string, n/N = write
)


class SnprintfVariableFilter:
    """
    Post-process SinkArgClassifier results, upgrading SNPRINTF_RODATA findings
    where the format string contains a variable conversion specifier.
    """

    def __init__(self, binary_path: str) -> None:
        self._path = binary_path
        self._data = Path(binary_path).read_bytes()

    @classmethod
    def from_context(cls, ctx) -> 'SnprintfVariableFilter':
        return cls(ctx.path)

    def apply(self, results) -> list:
        """
        Return a new list with SNPRINTF_RODATA results upgraded to
        SNPRINTF_RODATA_VARIABLE where the format string contains %s/%S/%n.

        The input list is not modified; upgraded entries are shallow-copied.
        """
        out = []
        for r in results:
            if r.verdict != 'SNPRINTF_RODATA':
                out.append(r)
                continue

            fmt_str = self._extract_format_string(r.detail)
            if fmt_str is None:
                out.append(r)
                continue

            if _VARIABLE_SPEC_RE.search(fmt_str):
                upgraded = copy(r)
                upgraded.verdict  = SNPRINTF_RODATA_VARIABLE
                upgraded.severity = 'HIGH'
                upgraded.detail   = r.detail + f'  fmt={fmt_str!r:.80s}'
                out.append(upgraded)
            else:
                out.append(r)
        return out

    def fmt_string_at(self, va: int) -> Optional[bytes]:
        """Read a null-terminated format string from VA in the binary."""
        if va < 0 or va >= len(self._data):
            return None
        end = self._data.find(b'\x00', va)
        if end == -1:
            return None
        return self._data[va:end]

    def has_variable_specifier(self, fmt_bytes: bytes) -> bool:
        return bool(_VARIABLE_SPEC_RE.search(fmt_bytes))

    # ── internal ──────────────────────────────────────────────────────────────

    def _extract_format_string(self, detail: str) -> Optional[bytes]:
        """
        Parse the VA of the format string from a SinkClassification detail string.

        SAC encodes it as: "... fmt=LEA [rip+0x...] in .rodata" and the actual
        string is embedded if available. Try two strategies:
          1. Parse a fmt=b'...' literal in the detail (if already decoded).
          2. Parse a rip-relative or absolute VA from the detail and read bytes.
        """
        # Strategy 1: detail already contains decoded string
        m = re.search(r"fmt='([^']*)'", detail)
        if m:
            return m.group(1).encode('utf-8', errors='replace')

        # Strategy 2: extract the VA from "LEA [rip+0x<disp>]" in the detail
        # SAC stores the target VA in the detail as part of the description.
        # Typical: "__snprintf_chk(rsp+0x60) fmt=LEA [rip+0x3831e0] in .rodata"
        # Strategy 3: look for any "0x<va>" hex address in the detail that is
        # plausibly a rodata VA (heuristic: > 0x100000 for typical PIE layouts)
        for m in re.finditer(r'0x([0-9a-f]{5,8})', detail):
            va = int(m.group(1), 16)
            s = self.fmt_string_at(va)
            if s and len(s) >= 2 and b'%' in s:
                return s

        return None
