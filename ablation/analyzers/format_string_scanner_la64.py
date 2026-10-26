"""
format_string_scanner_la64.py — Format string vulnerability detector for LoongArch64.

Why this exists
---------------
1. format_string_scanner.py is x86-64 only: it uses Capstone's x86 backend and
   detects .rodata pointers via RIP-relative LEA. There is no Capstone LA64 backend.
   On LA64 binaries it returns 0 results.

2. LA64 uses a two-instruction PC-relative sequence to build .rodata addresses:

     pcaddu12i $rD, imm          →  $rD = PC + imm * 4
     -- or --
     pcalau12i $rD, hi20         →  $rD = (PC & ~0xFFF) + hi20 * 0x1000
     addi.d    $fmt, $rD, lo12   →  $fmt = $rD + lo12

   Both patterns produce a pointer into .rodata.  A LEA scanner cannot detect
   either.  SinkArgClassifierLA64's _trace_arg() already handles both patterns
   (RODATA_CONST verdict) for exec sinks.  This module reuses that infrastructure
   for the printf family.

3. The Alpine LA64 survey (sessions 1–17) found no format string findings, but
   the corpus had no format-string scanner to confirm this.  This module closes
   that gap for future surveys.

Architecture: LoongArch64 lp64d ABI
-------------------------------------
  Argument registers:  $a0–$a7 (indices 4–11 in the 32-GPR file)
  Return register:     $a0
  Instruction width:   32 bits, little-endian

Format argument positions (lp64 ABI)
--------------------------------------
  printf(fmt, ...)               fmt = $a0   arg_pos = 0
  vprintf(fmt, ap)               fmt = $a0   arg_pos = 0
  warn(fmt, ...)                 fmt = $a0   arg_pos = 0
  warnx(fmt, ...)                fmt = $a0   arg_pos = 0
  vwarn(fmt, ap)                 fmt = $a0   arg_pos = 0
  vwarnx(fmt, ap)                fmt = $a0   arg_pos = 0
  fprintf(f, fmt, ...)           fmt = $a1   arg_pos = 1
  sprintf(buf, fmt, ...)         fmt = $a1   arg_pos = 1
  vsprintf(buf, fmt, ap)         fmt = $a1   arg_pos = 1
  asprintf(ptr, fmt, ...)        fmt = $a1   arg_pos = 1
  vasprintf(ptr, fmt, ap)        fmt = $a1   arg_pos = 1
  dprintf(fd, fmt, ...)          fmt = $a1   arg_pos = 1
  vdprintf(fd, fmt, ap)         fmt = $a1   arg_pos = 1
  syslog(pri, fmt, ...)          fmt = $a1   arg_pos = 1
  vsyslog(pri, fmt, ap)          fmt = $a1   arg_pos = 1
  err(eval, fmt, ...)            fmt = $a1   arg_pos = 1
  errx(eval, fmt, ...)           fmt = $a1   arg_pos = 1
  verr(eval, fmt, ap)            fmt = $a1   arg_pos = 1
  verrx(eval, fmt, ap)           fmt = $a1   arg_pos = 1
  snprintf(buf, n, fmt, ...)     fmt = $a2   arg_pos = 2
  vsnprintf(buf, n, fmt, ap)     fmt = $a2   arg_pos = 2

Verdicts (reuse SinkClassification from sink_arg_classifier.py)
-----------------------------------------------------------------
  RODATA_CONST   format string is a .rodata literal — safe, not reported
  ARG_PROPAGATED format arg traces to a function entry register — HIGH (CWE-134)
  UNKNOWN        format arg cannot be resolved — MEDIUM (needs manual review)

Usage
------
  from ablation.analyzers.binary_context import BinaryContext
  from ablation.analyzers.format_string_scanner_la64 import FormatStringScannerLA64

  ctx = BinaryContext.load_or_build('/path/to/la64_binary')
  scanner = FormatStringScannerLA64.from_context(ctx)
  findings = scanner.scan()
  print(scanner.report(findings))

  # Add firmware-specific logging wrappers:
  scanner.add_extra_sink('log_printf', arg_pos=1)   # log_printf(tag, fmt, ...)
  scanner.add_extra_sink('dbg_printf', arg_pos=0)   # dbg_printf(fmt, ...)
  findings = scanner.scan()

Ground truth
-------------
  Alpine 3.24.3 LA64 survey (sessions 1–17): 5,437 packages, 274 packages with exec
  sinks — no format string findings detected.  This module confirms those results
  are not false negatives from a missing scanner.

Module gap history
-------------------
  Session 3532 (TencentOS RE): LoongArch64 FormatStringScanner identified as a gap.
    "LA64 uses pcaddu12i+ld.d for .rodata refs, not RIP-relative LEA."
  This module closes that gap.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ablation.analyzers.sink_arg_classifier import (
    RODATA_CONST,
    ARG_PROPAGATED,
    UNKNOWN,
    SinkClassification,
)
from ablation.analyzers.sink_arg_classifier_loongarch64 import SinkArgClassifierLA64


# ---------------------------------------------------------------------------
# Printf-family sink registry: {function_name: arg_pos_of_fmt}
# ---------------------------------------------------------------------------

_FMT_SINKS: Dict[str, int] = {
    # fmt = $a0 (arg_pos=0)
    'printf':    0,
    'vprintf':   0,
    'warn':      0,
    'warnx':     0,
    'vwarn':     0,
    'vwarnx':    0,
    # fmt = $a1 (arg_pos=1)
    'fprintf':   1,
    'vfprintf':  1,
    'sprintf':   1,
    'vsprintf':  1,
    'asprintf':  1,
    'vasprintf': 1,
    'dprintf':   1,
    'vdprintf':  1,
    'syslog':    1,
    'vsyslog':   1,
    'err':       1,
    'errx':      1,
    'verr':      1,
    'verrx':     1,
    # fmt = $a2 (arg_pos=2)
    'snprintf':  2,
    'vsnprintf': 2,
}


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class FmtFindingLA64:
    func_va:   int
    call_va:   int
    callee:    str
    fmt_arg:   str      # '$a0' / '$a1' / '$a2'
    verdict:   str      # RODATA_CONST | ARG_PROPAGATED | UNKNOWN
    detail:    str
    severity:  str      # 'HIGH' | 'MEDIUM' | 'SAFE'

    def fmt(self) -> str:
        offset = (self.call_va - self.func_va) & 0xFFFF
        return (
            f'  {self.severity:6s}  fmt_string'
            f'  func=0x{self.func_va:x}+0x{offset:x}'
            f'  {self.callee}({self.fmt_arg}?)'
            f'  {self.detail}'
        )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class FormatStringScannerLA64:
    """
    Detect non-constant format string arguments in printf-family calls on LA64.

    Wraps SinkArgClassifierLA64 with a printf-family sink registry instead of
    the default exec-sink registry.  Reuses the same PLT extraction, call site
    discovery, and backward register trace so .rodata detection is consistent.

    SAFE (RODATA_CONST) results are excluded from scan() output.
    """

    def __init__(self, ctx, extra_sinks: Optional[Dict[str, int]] = None):
        self._ctx = ctx
        self._extra_sinks: Dict[str, int] = dict(extra_sinks or {})
        self._clf: Optional[SinkArgClassifierLA64] = None

    @classmethod
    def from_context(cls, ctx) -> 'FormatStringScannerLA64':
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> 'FormatStringScannerLA64':
        from ablation.analyzers.binary_context import BinaryContext
        ctx = BinaryContext.load_or_build(path)
        return cls(ctx)

    def add_extra_sink(self, name: str, arg_pos: int) -> None:
        """Register a firmware-specific printf wrapper not in the default set.

        Example: log_printf(priority, fmt, ...) -> arg_pos=1
        """
        self._extra_sinks[name] = arg_pos
        self._clf = None   # invalidate cached classifier

    def _build_clf(self) -> SinkArgClassifierLA64:
        """Build a SinkArgClassifierLA64 with only fmt sinks registered."""
        clf = SinkArgClassifierLA64.from_context(self._ctx)
        clf._sinks.clear()
        all_sinks = dict(_FMT_SINKS)
        all_sinks.update(self._extra_sinks)
        for name, arg_pos in all_sinks.items():
            clf.add_sink(name, arg_pos)
        return clf

    def scan(self) -> List[FmtFindingLA64]:
        """Scan all printf-family call sites and return non-safe findings.

        RODATA_CONST call sites (hardcoded format strings) are excluded.
        ARG_PROPAGATED -> severity HIGH; UNKNOWN -> severity MEDIUM.
        """
        if self._clf is None:
            self._clf = self._build_clf()

        raw: List[SinkClassification] = self._clf.classify_all()
        findings: List[FmtFindingLA64] = []

        for r in raw:
            if r.verdict == RODATA_CONST:
                continue
            severity = 'HIGH' if r.verdict == ARG_PROPAGATED else 'MEDIUM'
            fmt_arg  = f'$a{r.arg_pos}'
            findings.append(FmtFindingLA64(
                func_va  = r.func_va,
                call_va  = r.call_va,
                callee   = r.sink_name,
                fmt_arg  = fmt_arg,
                verdict  = r.verdict,
                detail   = r.detail,
                severity = severity,
            ))

        findings.sort(key=lambda f: (f.severity, f.func_va))
        return findings

    def report(self, findings: List[FmtFindingLA64]) -> str:
        if not findings:
            return '[FormatStringScannerLA64] 0 findings (all RODATA_CONST or no fmt sinks)\n'
        high = sum(1 for f in findings if f.severity == 'HIGH')
        med  = sum(1 for f in findings if f.severity == 'MEDIUM')
        lines = [
            f'[FormatStringScannerLA64] {len(findings)} finding(s)'
            f'  HIGH={high}  MEDIUM={med}'
        ]
        for f in findings:
            lines.append(f.fmt())
        return '\n'.join(lines) + '\n'
