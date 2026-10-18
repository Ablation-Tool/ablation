"""
caller_arg_resolver.py: one-hop caller-side argument classification for i386 cdecl.

When SinkArgClassifierI386 reports ARG_PROPAGATED at func_va for a system() call
where the argument is [ebp+0x2c] (a function argument), the question becomes:
what value do the CALLERS of func_va actually pass for that argument?

This module answers that question by tracing callers one hop up the call chain.

Gap this fills:
  samlicm (IBM CSM SAM 2.2.0.1): lum_add_nodelocked (func@0x805842b) has an
  ARG_PROPAGATED system() site where arg_pos=0 traces to func_arg_pos=9 ([ebp+0x2c]).
  Manual disassembly of all 3 callers revealed:
    - netls_add_nodelocked (0x80526b6):                 arg9 = push 0 (system(NULL))
    - installTryBuyLicense (0x804d3ba):                  arg9 = push 0 (system(NULL))
    - netls_add_nodelocked_from_certificate (0x80774a4): arg9 = &[ebp-0x7b8] (cert buffer)
  2 of 3 callers are safe (system(NULL) = shell probe, not command execution).
  Manual investigation took ~40 minutes. This module would have classified them
  in seconds and flagged only the cert-path caller for further review.

Verdicts (per caller call site):
  CONST_NULL     — push 0 / push imm32=0: system(NULL) — shell probe, not exploitable
  CONST_NONZERO  — push imm32 ≠ 0 or LEA from .rodata: static string → RODATA_CONST
  ARG_PROPAGATED — push [ebp+N] N>0: value comes from caller's own caller
  STACK_LOCAL    — push [ebp-N] or LEA [ebp-N]: local buffer address
  UNKNOWN        — cannot determine from static analysis within look-back window

Algorithm (i386 cdecl):
  For a call from caller_site_va to func_va with func_arg_pos=P (0-indexed):
    P=0 → last push before call
    P=1 → second-to-last push, etc.
  Walk backwards from call site counting pushes (allowing for sub esp+mov patterns
  and intermediate cleanup: 'add esp, N' after inner calls resets the stack by N bytes,
  so adjust the effective push count accordingly).

Limitations:
  - Looks back at most _LOOKBACK instructions from call site.
  - Does not follow pushes through function calls within the setup sequence.
  - Does not handle tail-call patterns.
  - x86_32 only (cdecl stack-based calling convention).

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.caller_arg_resolver import CallerArgResolver

    ctx = BinaryContext.load_or_build('/path/to/samlicm')
    resolver = CallerArgResolver.from_context(ctx)

    # Resolve what callers pass for arg_pos 9 of lum_add_nodelocked (0x805842b)
    report = resolver.resolve(func_va=0x805842b, func_arg_pos=9)
    print(resolver.fmt_report(report))

    # Convenience: resolve from a SinkClassification with ARG_PROPAGATED verdict
    # when detail contains an [ebp+N] expression (parses N automatically)
    from ablation.analyzers.sink_arg_classifier import ARG_PROPAGATED
    from ablation.analyzers.sink_arg_classifier_x86_32 import SinkArgClassifierI386
    clf = SinkArgClassifierI386.from_context(ctx)
    results = [r for r in clf.classify_all() if r.verdict == ARG_PROPAGATED]
    for r in results:
        rpt = resolver.resolve_from_classification(r)
        print(resolver.fmt_report(rpt))
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_EBP
    _CS_OK = True
except ImportError:
    pass

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

# Verdicts for individual call sites
CONST_NULL     = 'CONST_NULL'      # push 0 → system(NULL)
CONST_NONZERO  = 'CONST_NONZERO'   # push imm ≠ 0
ARG_PROPAGATED = 'ARG_PROPAGATED'  # push [ebp+N] N>0
STACK_LOCAL    = 'STACK_LOCAL'     # push [ebp-N] or lea [ebp-N]
RODATA_CONST   = 'RODATA_CONST'    # push <rodata addr>
UNKNOWN        = 'UNKNOWN'

_LOOKBACK = 100   # max instructions to scan backwards from call site


@dataclass
class CallerSiteResult:
    """Classification of one caller call site."""
    caller_func_va:  int
    call_site_va:    int
    verdict:         str
    detail:          str = ''

    def fmt(self) -> str:
        return (
            f'  caller_func=0x{self.caller_func_va:x}  '
            f'call_site=0x{self.call_site_va:x}  '
            f'{self.verdict:16s}  {self.detail}'
        )


@dataclass
class CallerArgReport:
    """All caller verdicts for one ARG_PROPAGATED site."""
    func_va:       int
    func_arg_pos:  int   # which argument of func_va is being traced
    results:       List[CallerSiteResult] = field(default_factory=list)

    @property
    def all_null(self) -> bool:
        """True if every caller passes a constant NULL — all system(NULL) paths."""
        return bool(self.results) and all(r.verdict == CONST_NULL for r in self.results)

    @property
    def has_exploitable(self) -> bool:
        """True if any caller passes a value that might be attacker-controlled."""
        return any(r.verdict in (ARG_PROPAGATED, STACK_LOCAL, UNKNOWN) for r in self.results)

    @property
    def verdict_summary(self) -> str:
        if not self.results:
            return 'NO_CALLERS'
        counts = {}
        for r in self.results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1
        return ', '.join(f'{v}×{n}' for v, n in sorted(counts.items()))


class CallerArgResolver:
    """
    One-hop caller-side argument classifier for i386 cdecl binaries.

    For an ARG_PROPAGATED finding where a function receives a value at
    argument position P and passes it to a sink, this traces all callers
    of that function to determine what they actually supply at position P.
    """

    def __init__(self, ctx) -> None:
        self._ctx  = ctx
        self._data: bytes = Path(ctx.path).read_bytes()
        self._bin  = None
        self._cs: Optional[Cs] = None
        self._rodata_ranges: List[Tuple[int, int]] = []
        if _CS_OK:
            self._cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self._cs.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(ctx.path)
            self._init_rodata()

    def _init_rodata(self) -> None:
        if self._bin is None:
            return
        for sec in self._bin.sections:
            if sec.name in ('.rodata', '.rodata1', '__const', '.rdata', '__cstring'):
                va_s = int(sec.virtual_address)
                self._rodata_ranges.append((va_s, va_s + int(sec.size)))

    @classmethod
    def from_context(cls, ctx) -> 'CallerArgResolver':
        return cls(ctx)

    # ── core API ──────────────────────────────────────────────────────────────

    def resolve(self, func_va: int, func_arg_pos: int) -> CallerArgReport:
        """
        For every caller of func_va, classify what value they pass for func_arg_pos.

        func_arg_pos is 0-indexed: 0 = first argument ([ebp+8] in callee).

        BinaryContext.call_edges stores (caller_func_va, callee_va, name) where
        caller_func_va is the FUNCTION START, not the call instruction address.
        We scan the caller function to find the actual call instruction first.
        """
        report = CallerArgReport(func_va=func_va, func_arg_pos=func_arg_pos)
        callers = [(src, dst, n) for src, dst, n in self._ctx.call_edges if dst == func_va]
        for caller_func_va, _, _ in callers:
            # Find the actual call instruction within caller_func_va that calls func_va
            actual_call_va = self._find_call_in_func(caller_func_va, func_va)
            if actual_call_va is None:
                report.results.append(CallerSiteResult(
                    caller_func_va=caller_func_va,
                    call_site_va=caller_func_va,
                    verdict=UNKNOWN,
                    detail=f'call to 0x{func_va:x} not found in func@0x{caller_func_va:x}',
                ))
                continue
            result = self._classify_call_site(actual_call_va, func_arg_pos, caller_func_va)
            report.results.append(result)
        return report

    def resolve_from_classification(self, sc) -> CallerArgReport:
        """
        Convenience: derive func_arg_pos from a SinkClassification's detail string.

        Expects detail to contain '[ebp+0xNN]' or '[ebp+NN]' which encodes the
        callee's [ebp+offset] access. Computes func_arg_pos = (offset - 8) // 4.
        """
        func_arg_pos = self._parse_ebp_offset(sc.detail)
        if func_arg_pos is None:
            return CallerArgReport(func_va=sc.func_va, func_arg_pos=-1)
        return self.resolve(sc.func_va, func_arg_pos)

    def fmt_report(self, report: CallerArgReport) -> str:
        lines = [
            f'CallerArgResolver: func=0x{report.func_va:x}  '
            f'arg_pos={report.func_arg_pos}  '
            f'callers={len(report.results)}  '
            f'summary={report.verdict_summary}'
        ]
        for r in report.results:
            lines.append(r.fmt())
        return '\n'.join(lines)

    # ── classification ────────────────────────────────────────────────────────

    def _classify_call_site(self, call_va: int, arg_pos: int,
                             cfunc: Optional[int]) -> CallerSiteResult:
        """
        Walk backwards from call_va counting cdecl pushes to find arg at arg_pos.
        """
        if self._cs is None:
            return CallerSiteResult(
                caller_func_va=cfunc or 0,
                call_site_va=call_va,
                verdict=UNKNOWN,
                detail='capstone not available',
            )

        insns = self._get_insns_before(call_va)
        if not insns:
            return CallerSiteResult(
                caller_func_va=cfunc or 0,
                call_site_va=call_va,
                verdict=UNKNOWN,
                detail='could not disassemble before call site',
            )

        verdict, detail = self._find_push_at_pos(insns, arg_pos)
        return CallerSiteResult(
            caller_func_va=cfunc or 0,
            call_site_va=call_va,
            verdict=verdict,
            detail=detail,
        )

    def _find_push_at_pos(self, insns: list, target_pos: int) -> Tuple[str, str]:
        """
        Walk insns in reverse (from call site backwards) counting pushes.

        cdecl: last push before call = arg_pos 0. Adjust for intermediate
        'add esp, N' (stack cleanup for inner call) which resets N bytes = N//4 pushes.
        """
        push_count = 0   # counts pushes in the arg-setup sequence
        sub_esp_debt = 0  # bytes owed by sub esp,N that have not yet been matched
        skip_after_call = 0  # bytes to skip after we cross an 'add esp,N'

        for insn in reversed(insns):
            mn = insn.mnemonic
            ops = insn.operands

            # --- 'add esp, N' signals cleanup from an inner call N bytes above ---
            if mn == 'add' and ops and ops[0].type == X86_OP_REG:
                if self._cs and hasattr(ops[0], 'reg') and insn.op_str.startswith('esp,'):
                    try:
                        n_bytes = int(insn.op_str.split(',')[1].strip(), 16) if '0x' in insn.op_str else int(insn.op_str.split(',')[1].strip())
                    except Exception:
                        n_bytes = 0
                    if n_bytes > 0:
                        sub_esp_debt += n_bytes // 4
                continue

            # --- sub esp, N — these bytes are "logical pushes" for sub+mov patterns ---
            if mn == 'sub' and ops and insn.op_str.startswith('esp,'):
                try:
                    n_bytes = int(insn.op_str.split(',')[1].strip(), 16) if '0x' in insn.op_str else int(insn.op_str.split(',')[1].strip())
                except Exception:
                    n_bytes = 0
                # sub esp,N after cleanup = those N/4 slots are args for the outer call
                # (they would have been pushed first = highest arg positions)
                # Account: they count as sub_esp_debt//4 pushes at high positions
                # We skip this many as if they were pushes
                # But since we're going backwards, these come after (code-wise = before the cleanup)
                # If we haven't consumed the debt yet, these correspond to those slots
                if sub_esp_debt > 0:
                    n_slots = n_bytes // 4
                    if sub_esp_debt >= n_slots:
                        sub_esp_debt -= n_slots
                    else:
                        push_count += n_slots - sub_esp_debt
                        sub_esp_debt = 0
                continue

            # --- actual push instructions ---
            if mn == 'push':
                if sub_esp_debt > 0:
                    sub_esp_debt -= 1
                    continue
                if push_count == target_pos:
                    return self._classify_push(insn)
                push_count += 1
                continue

            # --- stop at function prologue ---
            if mn in ('ret', 'leave') or (mn == 'push' and insn.op_str == 'ebp'):
                break

        return UNKNOWN, f'arg_pos={target_pos} not found in {len(insns)}-insn window'

    def _classify_push(self, insn) -> Tuple[str, str]:
        """Classify the value being pushed by one push instruction."""
        ops = insn.operands
        if not ops:
            return UNKNOWN, 'push with no operands'

        op = ops[0]

        # push imm32
        if op.type == X86_OP_IMM:
            val = op.imm
            if val == 0:
                return CONST_NULL, 'push 0 → system(NULL)'
            if self._is_rodata(val):
                raw = self._read_cstr(val)
                snippet = repr(raw[:32]) if raw else hex(val)
                return RODATA_CONST, f'push {hex(val)} (rodata: {snippet})'
            return CONST_NONZERO, f'push {hex(val)}'

        # push [ebp ± N]
        if op.type == X86_OP_MEM:
            base = op.mem.base
            disp = op.mem.disp
            if _CS_OK and base == X86_REG_EBP:
                if disp > 0:
                    arg_idx = (disp - 8) // 4
                    return ARG_PROPAGATED, f'push [ebp+{hex(disp)}] = arg{arg_idx} of caller'
                elif disp < 0:
                    return STACK_LOCAL, f'push [ebp{hex(disp)}] = local variable'
            return UNKNOWN, f'push mem [{insn.op_str}]'

        # push reg — would need register-origin trace (out of scope for one-hop)
        if op.type == X86_OP_REG:
            reg_name = insn.op_str
            return UNKNOWN, f'push {reg_name} — register trace required'

        return UNKNOWN, insn.op_str

    # ── helpers ───────────────────────────────────────────────────────────────

    def _find_call_in_func(self, func_va: int, callee_va: int,
                            max_bytes: int = 65536) -> Optional[int]:
        """Scan func_va's body for a 'call callee_va' instruction; return its VA or None."""
        if self._cs is None:
            return None
        off_s = self._va_to_offset(func_va)
        if off_s < 0:
            return None
        chunk = self._data[off_s:off_s + max_bytes]
        for insn in self._cs.disasm(chunk, func_va):
            if insn.mnemonic == 'call' and insn.operands:
                op = insn.operands[0]
                if op.type == X86_OP_IMM and op.imm == callee_va:
                    return insn.address
        return None

    def _containing_func(self, call_va: int) -> Optional[int]:
        """Return the function start VA that contains call_va."""
        import bisect
        fs = self._ctx.func_starts
        if not fs:
            return None
        idx = bisect.bisect_right(fs, call_va) - 1
        return fs[idx] if idx >= 0 else None

    def _get_insns_before(self, call_va: int) -> list:
        """Disassemble up to _LOOKBACK instructions ending at call_va."""
        if self._cs is None:
            return []
        # Scan from (call_va - est_bytes) to cover enough instructions
        est_bytes = _LOOKBACK * 6
        start = max(call_va - est_bytes, 0)
        off_s = self._va_to_offset(start)
        off_e = self._va_to_offset(call_va)
        if off_s < 0 or off_e <= off_s:
            return []
        chunk = self._data[off_s:off_e]
        insns = list(self._cs.disasm(chunk, start))
        # Keep only the last _LOOKBACK instructions
        return insns[-_LOOKBACK:]

    def _va_to_offset(self, va: int) -> int:
        if self._bin is None:
            return va
        try:
            return int(self._bin.virtual_address_to_offset(va))
        except Exception:
            return -1

    def _is_rodata(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._rodata_ranges)

    def _read_cstr(self, va: int) -> Optional[str]:
        off = self._va_to_offset(va)
        if off < 0:
            return None
        raw = self._data[off:off + 128]
        for i, b in enumerate(raw):
            if b == 0:
                if i == 0:
                    return None
                try:
                    return raw[:i].decode('ascii')
                except Exception:
                    return None
            if b < 0x20 and b not in (0x09, 0x0a, 0x0d):
                return None
        return None

    @staticmethod
    def _parse_ebp_offset(detail: str) -> Optional[int]:
        """Parse '[ebp+0xNN]' from a detail string and return func_arg_pos."""
        m = re.search(r'\[ebp\+(0x[0-9a-fA-F]+|\d+)\]', detail)
        if not m:
            return None
        raw = m.group(1)
        offset = int(raw, 16) if raw.startswith('0x') else int(raw)
        if offset <= 4:
            return None
        return (offset - 8) // 4
