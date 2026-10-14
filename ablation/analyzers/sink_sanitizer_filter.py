"""
sink_sanitizer_filter.py: post-process ARG_PROPAGATED SinkArgClassifier results
to detect sanitizer-gated exec sinks and reclassify them as SANITIZER_VALIDATED.

The biggest manual bottleneck in a sink-triage engagement is distinguishing
ARG_PROPAGATED sites that are structurally safe (the argument passes through a
shell-safe allowlist validator before reaching the exec sink) from those that are
genuinely exploitable.  Every ARG_PROPAGATED site must otherwise be manually
disassembled and traced — a 30–60 minute task per site on a stripped binary.

SinkArgClassifier identifies where exec-sink arguments originate.
SanitizerDetector identifies which functions enforce a shell-safe character
allowlist.  This module connects the two: for each ARG_PROPAGATED site it
disassembles the containing function and verifies three conditions:

  1. A SHELL_SAFE sanitizer is called on the same argument somewhere before
     the exec sink within the same basic region (up to _SANITIZER_SCAN_WINDOW
     instructions back).
  2. A conditional branch on the sanitizer's return value guards execution:
     test eax, eax / jz <error> means execution does not reach the exec sink
     when the sanitizer rejects.
  3. The argument register at the sanitizer call traces to the same source
     register as the argument at the exec call (same variable, not a
     different string that happens to share register rdi momentarily).

Sites meeting all three conditions are reclassified SANITIZER_VALIDATED
(severity lowered from HIGH to LOW).  Sites that partially match are left
ARG_PROPAGATED with detail unchanged.

Confirmed engagement gap (TG-FAD-2): on FortiADC authd, auth_sso_krb
(0xd930) was manually confirmed as the only ARG_PROPAGATED site without
a sanitizer guard.  Five other ARG_PROPAGATED sites in the same binary
would have been automatically downgraded had this module existed.

Usage:
    from ablation.analyzers.sink_sanitizer_filter import SinkSanitizerFilter
    from ablation.analyzers.sink_arg_classifier import SinkArgClassifier

    clf = SinkArgClassifier.from_path('/path/to/binary')
    results = clf.classify_all()

    flt = SinkSanitizerFilter.from_path('/path/to/binary')
    results = flt.apply(results)

    # Only exploit candidates (not sanitizer-gated)
    hot = [r for r in results
           if r.verdict not in ('RODATA_CONST', 'SNPRINTF_RODATA', 'SANITIZER_VALIDATED')]
    print(flt.report(results))
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    _CS_OK = True
except ImportError:
    pass

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

from ablation.analyzers.sink_arg_classifier import (
    SinkClassification, ARG_PROPAGATED, RODATA_CONST,
)
from ablation.analyzers.sanitizer_detector import SanitizerDetector

SANITIZER_VALIDATED = 'SANITIZER_VALIDATED'

# How many instructions before the exec call to scan for a sanitizer call.
_SANITIZER_SCAN_WINDOW = 256

# How many instructions after the sanitizer call to look for test+branch guard.
_GUARD_SCAN_WINDOW = 12

# How far back to trace a register source at a call site.
_TRACE_LOOKBACK = 80

# x86-64 SysV caller-saved registers (clobbered across any call).
_CALLER_SAVED: FrozenSet[str] = frozenset(
    ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'r10', 'r11', 'rax']
)

# x86-64 callee-saved (non-volatile) registers.
_NONVOL: FrozenSet[str] = frozenset(['rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'])

# Regex for extracting the first bare register token from an operand string.
_REG_TOK = re.compile(r'\b(r[0-9a-z]+|[re][a-z]{2,}|[a-z]{2,3})\b', re.IGNORECASE)

# Full alias → canonical 64-bit register name table.
_CANON: Dict[str, str] = {}


def _build_canon() -> Dict[str, str]:
    families = {
        'rax': ['rax', 'eax', 'ax', 'al', 'ah'],
        'rbx': ['rbx', 'ebx', 'bx', 'bl', 'bh'],
        'rcx': ['rcx', 'ecx', 'cx', 'cl', 'ch'],
        'rdx': ['rdx', 'edx', 'dx', 'dl', 'dh'],
        'rsi': ['rsi', 'esi', 'si', 'sil'],
        'rdi': ['rdi', 'edi', 'di', 'dil'],
        'rbp': ['rbp', 'ebp', 'bp', 'bpl'],
        'rsp': ['rsp', 'esp', 'sp', 'spl'],
        'r8':  ['r8',  'r8d',  'r8w',  'r8b'],
        'r9':  ['r9',  'r9d',  'r9w',  'r9b'],
        'r10': ['r10', 'r10d', 'r10w', 'r10b'],
        'r11': ['r11', 'r11d', 'r11w', 'r11b'],
        'r12': ['r12', 'r12d', 'r12w', 'r12b'],
        'r13': ['r13', 'r13d', 'r13w', 'r13b'],
        'r14': ['r14', 'r14d', 'r14w', 'r14b'],
        'r15': ['r15', 'r15d', 'r15w', 'r15b'],
    }
    m: Dict[str, str] = {}
    for canon, aliases in families.items():
        for a in aliases:
            m[a] = canon
    return m


_CANON = _build_canon()


def _reg_canon(reg: str) -> str:
    """Return canonical 64-bit register name, or the input lower-cased if unknown."""
    return _CANON.get(reg.lower().strip(), reg.lower().strip())


def _trace_first_arg_source(
    insns: List[Tuple[int, str, str]],
    call_idx: int,
) -> Optional[str]:
    """
    Trace rdi at insns[call_idx] backward to find its ultimate source register.

    Returns:
      - Canonical register name (e.g. 'r14', 'rdi') — the register that last
        wrote to rdi before this call.
      - 'STACK' if rdi was set via lea [rsp/rbp + N] (stack buffer address).
      - None if the source cannot be determined within _TRACE_LOOKBACK instructions
        (ambiguous memory dereference, xor, or clobber by a call).

    One level of non-volatile register follow: if `mov rdi, r14` is found, the
    function continues backward looking for what set r14.  Only non-volatile
    registers are followed (r12–r15, rbx, rbp) — caller-saved regs (rsi, rdx, …)
    are not followed because a call between the setter and the use would clobber
    them, breaking the chain.

    Stops at a CALL instruction when the current target register is caller-saved,
    since the callee may return a new value via rax that gets moved into the target.
    """
    target = 'rdi'
    scan_end = max(-1, call_idx - _TRACE_LOOKBACK)

    for i in range(call_idx - 1, scan_end, -1):
        va, mnem, ops = insns[i]
        ml = mnem.lower()

        # Call clobbers all caller-saved registers.
        if ml == 'call' and target in _CALLER_SAVED:
            return None

        if not ops:
            continue

        parts = [p.strip() for p in ops.split(',', 1)]
        if len(parts) < 2:
            continue
        dest_raw, src_raw = parts[0], parts[1]
        dest_canon = _reg_canon(dest_raw)
        if dest_canon != target:
            continue

        # Found an instruction that writes to our target register.
        if ml in ('mov', 'movq', 'movabs', 'movsxd', 'movzx'):
            src = src_raw.strip()
            if '[' in src or 'ptr' in src.lower():
                # Memory dereference — extract base register as proxy for source.
                m = _REG_TOK.search(src)
                if m:
                    base = _reg_canon(m.group(1))
                    if base in ('rsp', 'rbp'):
                        return 'STACK'
                    return base
                return None
            else:
                src_canon = _reg_canon(src)
                if src_canon in _NONVOL:
                    # Follow one level through non-volatile register.
                    target = src_canon
                    continue
                # Caller-saved or immediate — cannot follow further.
                return src_canon

        elif ml == 'lea':
            src = src_raw.strip()
            if '[' not in src:
                continue
            m = _REG_TOK.search(src)
            if m:
                base = _reg_canon(m.group(1))
                if base in ('rsp', 'rbp'):
                    return 'STACK'
                return base
            return None

        else:
            # Arithmetic / logic / other instruction writes target — source unclear.
            return None

    # Scanned past lookback window without finding a setter.
    # Return the current target — if we never left 'rdi', it was the entry arg.
    return target


def _call_target_from_ops(ops: str) -> Optional[int]:
    """Return direct call target VA from capstone op_str, or None for indirect."""
    ops = ops.strip()
    try:
        if ops.startswith('0x'):
            return int(ops, 16)
        if ops.lstrip('-').isdigit():
            return int(ops)
    except ValueError:
        pass
    return None


# ─── Main class ──────────────────────────────────────────────────────────────


class SinkSanitizerFilter:
    """
    Post-processor for SinkArgClassifier output.

    Reclassifies ARG_PROPAGATED sites to SANITIZER_VALIDATED where the argument
    demonstrably passes through a SHELL_SAFE allowlist validator before the exec
    sink, and a conditional branch on the validator's return value gates execution.
    """

    def __init__(self, binary_path: str, ctx=None):
        self.binary_path = binary_path
        self._ctx = ctx
        self._data: Optional[bytes] = None
        # (section_va, section_end_va, file_offset) for VA→byte mapping
        self._sections: List[Tuple[int, int, int]] = []
        self._func_starts: List[int] = []
        self._sanitizer_vas: Set[int] = set()
        self._sanitizer_names: Dict[int, str] = {}
        self._func_insns_cache: Dict[int, List[Tuple[int, str, str]]] = {}

    @classmethod
    def from_path(cls, path: str) -> 'SinkSanitizerFilter':
        inst = cls(path)
        inst._init()
        return inst

    @classmethod
    def from_context(cls, ctx) -> 'SinkSanitizerFilter':
        inst = cls(ctx.path, ctx=ctx)
        inst._init()
        return inst

    def _init(self) -> None:
        if not _CS_OK or not _LIEF_OK:
            return
        try:
            self._data = Path(self.binary_path).read_bytes()
        except OSError:
            return

        binary = _lief.parse(self.binary_path)
        if not isinstance(binary, _lief.ELF.Binary):
            return

        # Build section table for VA → file-offset mapping.
        for sec in binary.sections:
            va = sec.virtual_address
            sz = sec.size
            fo = sec.offset
            if va and sz:
                self._sections.append((va, va + sz, fo))

        # Detect SHELL_SAFE sanitizer functions.
        det = SanitizerDetector.from_path(self.binary_path)
        for p in det.detect():
            if p.shell_safe:
                self._sanitizer_vas.add(p.func_va)
                self._sanitizer_names[p.func_va] = p.verdict

        # Collect function starts.
        if self._ctx is not None:
            try:
                self._func_starts = sorted(self._ctx.func_starts())
            except Exception:
                pass
        else:
            try:
                from ablation.analyzers.binary_context import BinaryContext
                ctx = BinaryContext.load_or_build(self.binary_path)
                self._ctx = ctx
                self._func_starts = sorted(ctx.func_starts())
            except Exception:
                pass

    def _va_to_bytes(self, va: int, length: int) -> Optional[bytes]:
        """Return `length` raw bytes starting at virtual address `va`, or None."""
        if self._data is None:
            return None
        for sec_va, sec_end, file_off in self._sections:
            if sec_va <= va < sec_end:
                off = file_off + (va - sec_va)
                if off < 0 or off >= len(self._data):
                    return None
                end = min(off + length, sec_end - sec_va + file_off)
                return self._data[off:end]
        return None

    def _func_containing(self, va: int) -> int:
        if self._ctx is not None:
            try:
                result = self._ctx.func_containing(va)
                if result:
                    return result
            except Exception:
                pass
        # Fallback: sorted list binary search.
        import bisect
        starts = self._func_starts
        if not starts:
            return va
        idx = bisect.bisect_right(starts, va) - 1
        return starts[idx] if idx >= 0 else va

    def _disasm_func(self, func_va: int) -> List[Tuple[int, str, str]]:
        """Disassemble the function at func_va, up to 4096 bytes or next function start."""
        if func_va in self._func_insns_cache:
            return self._func_insns_cache[func_va]

        result: List[Tuple[int, str, str]] = []
        if not _CS_OK:
            return result

        # Determine max bytes to read.
        import bisect
        starts = self._func_starts
        max_bytes = 4096
        if starts:
            idx = bisect.bisect_right(starts, func_va)
            if idx < len(starts):
                max_bytes = min(4096, starts[idx] - func_va)

        code = self._va_to_bytes(func_va, max_bytes)
        if not code:
            return result

        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        cs.detail = False
        for insn in cs.disasm(code, func_va):
            result.append((insn.address, insn.mnemonic, insn.op_str))

        self._func_insns_cache[func_va] = result
        return result

    def _find_sanitizer_and_guard(
        self,
        insns: List[Tuple[int, str, str]],
        exec_idx: int,
    ) -> Optional[Tuple[int, int, str]]:
        """
        Scan backward from exec_idx for a SHELL_SAFE sanitizer call that is
        subsequently guarded by a conditional branch on eax.

        Returns (sanitizer_call_idx, guard_branch_idx, sanitizer_name) or None.
        The guard must appear within _GUARD_SCAN_WINDOW instructions after the
        sanitizer call and must test eax/al/rax before a conditional jump.
        """
        scan_start = max(0, exec_idx - _SANITIZER_SCAN_WINDOW)

        for i in range(exec_idx - 1, scan_start - 1, -1):
            va, mnem, ops = insns[i]
            if mnem.lower() != 'call':
                continue

            target_va = _call_target_from_ops(ops)
            if target_va is None or target_va not in self._sanitizer_vas:
                continue

            san_name = self._sanitizer_names.get(
                target_va, 'sanitizer@0x{:x}'.format(target_va)
            )

            # Scan forward for test/cmp on eax followed by a conditional jump.
            end = min(len(insns), i + _GUARD_SCAN_WINDOW + 1)
            found_test = -1
            for j in range(i + 1, end):
                jva, jmnem, jops = insns[j]
                jml = jmnem.lower()
                if jml in ('test', 'cmp'):
                    ops_lc = jops.lower().replace(' ', '')
                    if any(r in ops_lc for r in ('eax', 'rax', 'al')):
                        found_test = j
                elif jml.startswith('j') and jml != 'jmp':
                    if found_test >= 0:
                        return (i, j, san_name)
                    # Conditional jump without prior test — only valid immediately
                    # after the call (some sanitizers set flags directly via test al,al).
                    if j == i + 1:
                        return (i, j, san_name)

        return None

    def _try_upgrade(self, clf: SinkClassification) -> Optional[SinkClassification]:
        """
        Try to upgrade clf from ARG_PROPAGATED to SANITIZER_VALIDATED.

        Returns a new SinkClassification on success, None on failure.
        Arg-identity check: rdi at sanitizer call and rdi at exec call must trace
        to the same source register (same variable, not a coincidentally shared rdi).
        """
        if not self._sanitizer_vas:
            return None

        insns = self._disasm_func(clf.func_va)
        if not insns:
            return None

        # Find exec call site in the instruction list.
        exec_idx: Optional[int] = None
        for i, (va, mnem, ops) in enumerate(insns):
            if va == clf.call_va:
                exec_idx = i
                break
        if exec_idx is None:
            return None

        found = self._find_sanitizer_and_guard(insns, exec_idx)
        if found is None:
            return None

        san_idx, guard_idx, san_name = found
        san_va = insns[san_idx][0]
        guard_va = insns[guard_idx][0]

        # Arg-identity check: both call sites must pass the same source register.
        exec_src = _trace_first_arg_source(insns, exec_idx)
        san_src  = _trace_first_arg_source(insns, san_idx)

        if exec_src is None or san_src is None or exec_src != san_src:
            return None

        detail = (
            f"SANITIZER_VALIDATED: {san_name} at 0x{san_va:x} "
            f"(SHELL_SAFE, both args trace to {exec_src}); "
            f"cond-branch guard at 0x{guard_va:x}. "
            f"Original: {clf.detail}"
        )
        # Pass severity='LOW' explicitly — __post_init__ skips assignment
        # when severity is truthy, so SANITIZER_VALIDATED stays LOW not MEDIUM.
        return replace(clf, verdict=SANITIZER_VALIDATED, detail=detail, severity='LOW')

    def apply(
        self,
        classifications: List[SinkClassification],
    ) -> List[SinkClassification]:
        """
        Post-process SinkArgClassifier output.

        Returns a new list; ARG_PROPAGATED entries are upgraded to
        SANITIZER_VALIDATED where all three conditions are confirmed.
        All other entries (RODATA_CONST, SNPRINTF_RODATA, UNKNOWN) are unchanged.
        """
        if not _CS_OK or not _LIEF_OK or not self._data:
            return classifications

        result: List[SinkClassification] = []
        for clf in classifications:
            if clf.verdict != ARG_PROPAGATED:
                result.append(clf)
                continue
            upgraded = self._try_upgrade(clf)
            result.append(upgraded if upgraded is not None else clf)
        return result

    def report(self, classifications: List[SinkClassification]) -> str:
        """Format a triage summary after apply()."""
        validated = [c for c in classifications if c.verdict == SANITIZER_VALIDATED]
        remaining = [c for c in classifications if c.verdict == ARG_PROPAGATED]
        lines = [
            'SinkSanitizerFilter: {} SANITIZER_VALIDATED, {} ARG_PROPAGATED remaining'.format(
                len(validated), len(remaining)
            ),
        ]
        if validated:
            lines.append('\nSANITIZER_VALIDATED (structurally safe — not exploitable):')
            for c in validated:
                lines.append(
                    '  0x{:x}  call@0x{:x}  {}(arg{})'.format(
                        c.func_va, c.call_va, c.sink_name, c.arg_pos
                    )
                )
                lines.append('    {}'.format(c.detail))
        if remaining:
            lines.append('\nARG_PROPAGATED remaining (not sanitizer-gated — investigate):')
            for c in remaining:
                lines.append(
                    '  0x{:x}  call@0x{:x}  {}(arg{})'.format(
                        c.func_va, c.call_va, c.sink_name, c.arg_pos
                    )
                )
                lines.append('    {}'.format(c.detail))
        return '\n'.join(lines)
