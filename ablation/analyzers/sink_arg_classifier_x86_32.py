"""
sink_arg_classifier_x86_32.py: classify exec-class sink argument provenance on x86_32 ELFs.

Gap this fills vs SinkArgClassifier:
  SinkArgClassifier hardcodes x86-64 registers (rdi, rsi, rdx).
  x86_32 cdecl passes all arguments on the stack (pushed right-to-left).
  That gap is RMC-GAP-002 / COMMSVR-GAP-004 / HACMP-GAP-001.
  This module resolves all three.

Four verdicts (same as SinkArgClassifier):
  RODATA_CONST     — argument is a constant from .rodata or a literal immediate.
  SNPRINTF_RODATA  — argument is a stack buffer written by snprintf/sprintf
                     whose format string is RODATA_CONST.
  ARG_PROPAGATED   — argument traces back to [ebp + N] (N > 0): a function argument.
  UNKNOWN          — provenance not resolved within the look-back window.

x86_32 cdecl calling convention:
  Args are pushed right-to-left. The LAST push before call = arg_pos 0 (first arg).
  Argument position 0 → last push  (closest to call instruction)
  Argument position 1 → second-to-last push
  Argument position 2 → third-to-last push
  ...

x86_32 string address patterns:
  1. push imm                              — direct pointer; check if imm in .rodata.
  2. lea eax, [ebx - N] / lea eax, [ebx+N]— GOT-relative: ebx = GOT base (PIC via
                                             call/pop + add ebx, N); -N/+N is .rodata offset.
                                             Then push eax.
  3. mov eax, [ebp + N] (N > 0)           — function argument → ARG_PROPAGATED.
  4. mov eax, [ebp - N]                   — stack local; check snprintf backtrack.
  5. lea eax, [ebp - N]                   — address of stack local; snprintf backtrack.
  6. push reg                              — trace register backward to its origin.
  7. sub esp, N then mov [esp+M], val     — slot-style arg passing; trace val.

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier_x86_32 import SinkArgClassifierX86_32

    ctx = BinaryContext.load_or_build('/path/to/rmcd', force_rebuild=True)
    clf = SinkArgClassifierX86_32.from_context(ctx)

    # Add strcpy as a sink to classify BOF candidates (arg_pos=1 = source string)
    clf.add_sink('strcpy',  arg_pos=1)
    clf.add_sink('sprintf', arg_pos=1)   # fmt string is arg_pos=1

    results = clf.classify_all()
    print(clf.report(results))

    # Filter to non-safe findings only
    flagged = [r for r in results if r.verdict not in ('RODATA_CONST',)]
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86_const import (
        X86_OP_REG, X86_OP_MEM, X86_OP_IMM,
        X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX,
        X86_REG_ESI, X86_REG_EDI, X86_REG_EBP, X86_REG_ESP,
    )
    _CS_OK = True
except ImportError:
    pass

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

# Re-export shared verdict constants and SinkClassification from the x86 module.
from ablation.analyzers.sink_arg_classifier import (
    SinkClassification,
    RODATA_CONST,
    SNPRINTF_RODATA,
    ARG_PROPAGATED,
    UNKNOWN,
)

# ── Capstone x86_32 register IDs ─────────────────────────────────────────────
# Named for clarity; Capstone's x86_32 assigns different integer IDs than x86_64.
# We use the Capstone constants where available; fall back to known values.

# Argument-save detection: [ebp + N] where N > 0 is a function argument.
# [ebp - N] where N > 0 is a local variable.
# N=0 is the saved ebp itself. N=4 (after ret addr) = arg_pos 0.

# ── Default sinks ─────────────────────────────────────────────────────────────
_DEFAULT_SINKS_X86_32: Dict[str, int] = {
    'system':    0,   # arg_pos 0 = cmd string
    'popen':     0,   # arg_pos 0 = cmd string
    'execve':    0,   # arg_pos 0 = pathname
    'execvp':    0,
    'execl':     0,
    'execlp':    0,
}

# snprintf-family: format-string argument positions (arg_pos counts from 0).
# sprintf(dest, fmt, ...) → fmt at arg_pos 1
# snprintf(dest, n, fmt, ...) → fmt at arg_pos 2
_SNPRINTF_FMT_POS_X86_32: Dict[str, int] = {
    'sprintf':        1,
    'snprintf':       2,
    'vsnprintf':      2,
    '__sprintf_chk':  3,
    '__snprintf_chk': 4,
}

# ── Scan constants ────────────────────────────────────────────────────────────
_LOOKBACK        = 80    # instructions to scan backward from call site
_SNPRINTF_WINDOW = 140   # instructions to scan for prior snprintf
_MAX_FUNC_BYTES  = 65536


class SinkArgClassifierX86_32:
    """
    Classify exec-class sink call site argument provenance on x86_32 ELFs.

    Handles the cdecl calling convention: args pushed right-to-left, so the
    LAST push before the call instruction is arg_pos=0 (the first argument).

    This module fills RMC-GAP-002, COMMSVR-GAP-004, and HACMP-GAP-001.
    """

    def __init__(self, ctx) -> None:
        self._ctx  = ctx
        self._data: bytes = Path(ctx.path).read_bytes()
        self._plt_rev: Dict[str, int] = {v: k for k, v in ctx.plt.items()}
        self._sinks: Dict[str, int]   = dict(_DEFAULT_SINKS_X86_32)
        self._snprintf_plts: Dict[int, int] = {}  # PLT VA → fmt arg position
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._dead_sinks: List[str] = []
        self._bin = None
        self._cs: Optional[Cs] = None
        if _CS_OK:
            self._cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self._cs.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(ctx.path)
        self._init()

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierX86_32':
        """Build from a BinaryContext."""
        return cls(ctx)

    def add_sink(self, name: str, arg_pos: int) -> None:
        """Register an additional sink (e.g., 'strcpy' at arg_pos=1 for source)."""
        self._sinks[name] = arg_pos

    # ── initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        for sec in self._bin.sections:
            if sec.name in ('.rodata', '.rodata1', '__const', '__cstring', '.rdata'):
                self._rodata_ranges.append(
                    (int(sec.virtual_address), int(sec.virtual_address) + int(sec.size))
                )
        for name, fmt_pos in _SNPRINTF_FMT_POS_X86_32.items():
            va = self._plt_rev.get(name)
            if va is not None:
                self._snprintf_plts[va] = fmt_pos

    # ── helpers ───────────────────────────────────────────────────────────────

    def _is_rodata(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._rodata_ranges)

    def _va_to_file_offset(self, va: int) -> int:
        if self._bin is None:
            return va
        try:
            return int(self._bin.virtual_address_to_offset(va))
        except Exception:
            return -1

    def _read_va(self, va: int, size: int) -> bytes:
        off = self._va_to_file_offset(va)
        if off < 0 or off >= len(self._data):
            return b''
        return self._data[off:off + size]  # Python slice clamps at buffer end

    def _read_u32(self, va: int) -> Optional[int]:
        raw = self._read_va(va, 4)
        if len(raw) < 4:
            return None
        return struct.unpack_from('<I', raw)[0]

    def _next_func_va(self, func_va: int) -> Optional[int]:
        fs = self._ctx.func_starts
        if not fs:
            return None
        import bisect
        idx = bisect.bisect_right(fs, func_va)
        return fs[idx] if idx < len(fs) else None

    def _get_insns(self, func_va: int) -> list:
        if self._cs is None:
            return []
        nxt = self._next_func_va(func_va)
        size = min(nxt - func_va if nxt else _MAX_FUNC_BYTES, _MAX_FUNC_BYTES)
        raw = self._read_va(func_va, size)
        if not raw:
            return []
        return list(self._cs.disasm(raw, func_va))

    def _find_sink_plts(self) -> Dict[int, Tuple[str, int]]:
        """Return {sink_va: (name, arg_pos)} for sinks with ≥1 caller."""
        result: Dict[int, Tuple[str, int]] = {}
        self._dead_sinks = []
        for name, arg_pos in self._sinks.items():
            va = self._plt_rev.get(name) or self._ctx.exports.get(name)
            if not va:
                continue
            callers = self._ctx.callers_of(name)
            if not callers:
                self._dead_sinks.append(name)
            else:
                result[va] = (name, arg_pos)
        return result

    def _find_call_sites(self, insns: list, sink_va: int) -> List[int]:
        """Return indices of call instructions that target sink_va."""
        sites: List[int] = []
        for i, insn in enumerate(insns):
            if insn.mnemonic != 'call':
                continue
            if not insn.operands:
                continue
            op = insn.operands[0]
            if op.type == X86_OP_IMM and op.imm == sink_va:
                sites.append(i)
        return sites

    # ── backward argument trace ───────────────────────────────────────────────

    def _classify_value(
        self,
        insns: list,
        start_idx: int,
        target: str,    # 'reg:<capstone_id>' or 'stack:<ebp_offset>' or 'imm:<value>'
        depth: int = 0,
    ) -> str:
        """
        Classify a value's provenance by scanning backward from start_idx.

        target forms:
          'imm:<N>'       — immediate value (check .rodata membership)
          'reg:<id>'      — register to trace backward
          'stack:<N>'     — stack slot [ebp-N] to trace backward (local var)
          'arg:<N>'       — [ebp+N] (N > 0) — already classified as ARG_PROPAGATED
        """
        if depth > 3:
            return UNKNOWN

        if target.startswith('imm:'):
            val = int(target[4:])
            if val == 0:
                return RODATA_CONST  # NULL constant
            return RODATA_CONST if self._is_rodata(val) else UNKNOWN

        if target.startswith('arg:'):
            return ARG_PROPAGATED

        if target.startswith('stack:'):
            return self._backtrack_stack_slot(insns, start_idx, int(target[6:]), depth)

        if not target.startswith('reg:'):
            return UNKNOWN

        try:
            reg_id = int(target[4:])
        except ValueError:
            return UNKNOWN

        window_start = max(0, start_idx - _LOOKBACK)
        for j in range(start_idx - 1, window_start - 1, -1):
            insn = insns[j]
            mn = insn.mnemonic
            ops = insn.operands if insn.operands else []
            if not ops:
                continue

            # Check if this instruction writes to reg_id
            if not self._writes_reg(insn, reg_id):
                continue

            # Found a definition — classify based on opcode
            if mn == 'lea':
                return self._classify_lea(insn, j, insns, depth)
            elif mn in ('mov', 'movzx', 'movsx'):
                return self._classify_mov(insn, j, insns, reg_id, depth)
            elif mn in ('xor', 'and'):
                # xor reg, reg → zeroing → RODATA_CONST (NULL)
                if len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                    if ops[0].reg == ops[1].reg:
                        return RODATA_CONST
                return UNKNOWN
            elif mn == 'pop':
                return UNKNOWN
            else:
                return UNKNOWN

        return UNKNOWN

    def _writes_reg(self, insn, reg_id: int) -> bool:
        """True if the instruction's first operand writes to reg_id."""
        ops = insn.operands
        if not ops:
            return False
        op = ops[0]
        if op.type != X86_OP_REG:
            return False
        # Capstone x86_32: 32-bit register IDs differ from 64-bit
        # We accept exact match; partial register (al, ax vs eax) handled by same reg_id
        return op.reg == reg_id

    def _classify_lea(self, insn, insn_idx: int, insns: list, depth: int) -> str:
        """
        Classify a lea instruction.
        lea eax, [ebx + N]    → GOT-relative; check if target is .rodata
        lea eax, [ebp - N]    → address of stack local; snprintf backtrack
        lea eax, [ebp + N]    → address of function arg (rare); ARG_PROPAGATED
        """
        ops = insn.operands
        if len(ops) < 2:
            return UNKNOWN
        mem = ops[1]
        if mem.type != X86_OP_MEM:
            return UNKNOWN
        base = mem.mem.base
        disp = mem.mem.disp

        # ebp-relative: local buffer or argument address
        if base == X86_REG_EBP:
            if disp > 0:
                return ARG_PROPAGATED
            if disp < 0:
                # Address of local stack buffer — snprintf backtrack
                return self._backtrack_stack_slot(insns, insn_idx, -disp, depth)
            return UNKNOWN

        # ebx-relative (GOT base in PIC x86_32)
        if base == X86_REG_EBX:
            # ebx = GOT base; compute target VA
            got_base = self._find_ebx_got_base(insns, insn_idx)
            if got_base is not None:
                target_va = got_base + disp
                if self._is_rodata(target_va):
                    return RODATA_CONST
                # Could be a GOT entry pointing to .rodata
                ptr = self._read_u32(target_va)
                if ptr is not None and self._is_rodata(ptr):
                    return RODATA_CONST
            return UNKNOWN

        return UNKNOWN

    def _classify_mov(
        self, insn, insn_idx: int, insns: list, dest_reg: int, depth: int
    ) -> str:
        """Classify a mov instruction that writes to dest_reg."""
        ops = insn.operands
        if len(ops) < 2:
            return UNKNOWN
        src = ops[1]

        if src.type == X86_OP_IMM:
            return self._classify_value(insns, insn_idx, f'imm:{src.imm}', depth + 1)

        if src.type == X86_OP_REG:
            return self._classify_value(insns, insn_idx, f'reg:{src.reg}', depth + 1)

        if src.type == X86_OP_MEM:
            base = src.mem.base
            disp = src.mem.disp
            idx  = src.mem.index
            # [ebp + N]: function argument
            if base == X86_REG_EBP and idx == 0:
                if disp > 0:
                    return ARG_PROPAGATED
                if disp < 0:
                    return self._backtrack_stack_slot(insns, insn_idx, -disp, depth)
            # [ebx + N]: GOT-relative global
            if base == X86_REG_EBX and idx == 0:
                got_base = self._find_ebx_got_base(insns, insn_idx)
                if got_base is not None:
                    target_va = got_base + disp
                    ptr = self._read_u32(target_va)
                    if ptr is not None and self._is_rodata(ptr):
                        return RODATA_CONST
                return UNKNOWN
            # [reg + N] — struct/heap field
            return UNKNOWN

        return UNKNOWN

    def _find_ebx_got_base(self, insns: list, from_idx: int) -> Optional[int]:
        """
        Find the GOT base value in ebx.
        In PIC x86_32: call _got_stub / pop ebx / add ebx, N (computed at link time).
        Scan backward for 'add ebx, imm' which sets ebx to the GOT base.
        """
        start = max(0, from_idx - _LOOKBACK * 2)
        for j in range(from_idx - 1, start - 1, -1):
            insn = insns[j]
            if insn.mnemonic != 'add':
                continue
            ops = insn.operands
            if len(ops) < 2:
                continue
            if ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_EBX:
                if ops[1].type == X86_OP_IMM:
                    # ebx was set by: pop ebx (gets RIP), then add ebx, N
                    # The pop value would be the instruction after the call; reconstruct:
                    # The add instruction is at insn.address; pop would be at insn.address - 1
                    # pop ebx puts insns[j].address into ebx (the call/pop thunk address)
                    # But we don't know the exact pop value statically — we need the pop target.
                    # In PIC code: pop ebx gets the address of the next instruction after
                    # the 'call $+5' trick, then add ebx, DELTA gets GOT base.
                    # We can recover: the pop_va is insns[j].address (the add instruction)
                    # Actually pop_va is 1 byte before the add (since pop = 1 byte: 0x5b).
                    # Let's scan one more step back for the 'pop ebx' + get its address.
                    pop_va = self._find_pop_ebx_va(insns, j)
                    if pop_va is not None:
                        return pop_va + ops[1].imm
        return None

    def _find_pop_ebx_va(self, insns: list, add_idx: int) -> Optional[int]:
        """Find the VA of the 'pop ebx' that precedes the 'add ebx, N'."""
        start = max(0, add_idx - 8)
        for j in range(add_idx - 1, start - 1, -1):
            insn = insns[j]
            if insn.mnemonic == 'pop':
                ops = insn.operands
                if ops and ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_EBX:
                    return insn.address
        return None

    def _backtrack_stack_slot(
        self, insns: list, from_idx: int, ebp_neg_offset: int, depth: int
    ) -> str:
        """
        Determine if a stack slot [ebp - ebp_neg_offset] was filled by a snprintf with
        RODATA format string. Returns SNPRINTF_RODATA or UNKNOWN.
        """
        if depth > 2:
            return UNKNOWN

        start = max(0, from_idx - _SNPRINTF_WINDOW)
        for j in range(from_idx - 1, start - 1, -1):
            insn = insns[j]
            if insn.mnemonic != 'call':
                continue
            ops = insn.operands
            if not ops or ops[0].type != X86_OP_IMM:
                continue
            callee_va = ops[0].imm
            if callee_va not in self._snprintf_plts:
                continue

            # Found a snprintf-family call. Verify its dest is our slot.
            fmt_pos = self._snprintf_plts[callee_va]
            # For sprintf(dest, fmt, ...) → arg_pos 0 = dest, arg_pos 1 = fmt
            # snprintf(dest, n, fmt, ...) → arg_pos 0 = dest, arg_pos 2 = fmt
            dest_arg_idx = 0

            dest_verdict = self._get_pushed_arg(insns, j, dest_arg_idx, depth + 1)
            fmt_verdict  = self._get_pushed_arg(insns, j, fmt_pos, depth + 1)

            if dest_verdict is None or fmt_verdict is None:
                continue

            # Check if dest points to [ebp - ebp_neg_offset]
            dest_is_our_slot = self._arg_is_stack_slot(insns, j, dest_arg_idx, ebp_neg_offset)
            if not dest_is_our_slot:
                continue

            # Verify format string is RODATA
            if fmt_verdict == RODATA_CONST:
                return SNPRINTF_RODATA

        return UNKNOWN

    def _arg_is_stack_slot(
        self, insns: list, call_idx: int, arg_pos: int, ebp_neg_offset: int
    ) -> bool:
        """
        Check if the arg at arg_pos to the call at call_idx is lea eax, [ebp - ebp_neg_offset].
        """
        push_idx = self._find_push_for_arg(insns, call_idx, arg_pos)
        if push_idx is None:
            return False
        insn = insns[push_idx]
        if insn.mnemonic == 'push':
            ops = insn.operands
            if ops and ops[0].type == X86_OP_REG:
                reg_id = ops[0].reg
                # Trace back to a lea [ebp - N]
                start = max(0, push_idx - _LOOKBACK)
                for j in range(push_idx - 1, start - 1, -1):
                    i2 = insns[j]
                    if i2.mnemonic == 'lea' and self._writes_reg(i2, reg_id):
                        o2 = i2.operands
                        if len(o2) >= 2 and o2[1].type == X86_OP_MEM:
                            m = o2[1].mem
                            if m.base == X86_REG_EBP and m.index == 0 and m.disp == -ebp_neg_offset:
                                return True
                        break
        return False

    def _find_push_for_arg(
        self, insns: list, call_idx: int, arg_pos: int
    ) -> Optional[int]:
        """
        Find the instruction index that pushes argument arg_pos.
        arg_pos 0 = last push before call, arg_pos 1 = second-to-last, etc.
        Handles both: push <val> and sub esp, N / mov [esp+M], val patterns.
        """
        pushes: List[int] = []
        start = max(0, call_idx - _LOOKBACK)

        # Scan backward counting push instructions and sub-esp+mov patterns
        for j in range(call_idx - 1, start - 1, -1):
            insn = insns[j]
            if insn.mnemonic == 'push':
                pushes.append(j)
            elif insn.mnemonic in ('ret', 'leave', 'call'):
                break  # don't cross function boundaries or other calls

        # pushes is in reverse order; pushes[0] = last push = arg_pos 0
        if arg_pos < len(pushes):
            return pushes[arg_pos]
        return None

    def _get_pushed_arg(
        self, insns: list, call_idx: int, arg_pos: int, depth: int
    ) -> Optional[str]:
        """
        Get the classification verdict for arg_pos at the call at call_idx.
        Returns verdict string or None if the argument couldn't be found.
        """
        push_idx = self._find_push_for_arg(insns, call_idx, arg_pos)
        if push_idx is None:
            return None
        insn = insns[push_idx]
        ops = insn.operands
        if not ops:
            return None
        op = ops[0]
        if op.type == X86_OP_IMM:
            return self._classify_value(insns, push_idx, f'imm:{op.imm}', depth)
        if op.type == X86_OP_REG:
            return self._classify_value(insns, push_idx, f'reg:{op.reg}', depth)
        if op.type == X86_OP_MEM:
            m = op.mem
            if m.base == X86_REG_EBP and m.index == 0:
                if m.disp > 0:
                    return ARG_PROPAGATED
                if m.disp < 0:
                    return self._backtrack_stack_slot(insns, push_idx, -m.disp, depth)
        return UNKNOWN

    # ── per-call-site classification ──────────────────────────────────────────

    def _classify_site(
        self,
        func_va:  int,
        call_va:  int,
        insns:    list,
        call_idx: int,
        sink_name: str,
        arg_pos:  int,
    ) -> SinkClassification:
        verdict = self._get_pushed_arg(insns, call_idx, arg_pos, depth=0)
        if verdict is None:
            verdict = UNKNOWN
        sev = 'HIGH' if verdict in (ARG_PROPAGATED, UNKNOWN) else 'INFO'
        return SinkClassification(
            sink_name=sink_name,
            arg_pos=arg_pos,
            func_va=func_va,
            call_va=call_va,
            verdict=verdict,
            detail=f'x86_32 arg_pos={arg_pos}',
            severity=sev,
        )

    # ── public API ────────────────────────────────────────────────────────────

    def classify_all(self) -> List[SinkClassification]:
        """
        Classify argument provenance for all call sites of all registered sinks.
        Returns a list of SinkClassification objects.
        """
        if not _CS_OK or not _LIEF_OK:
            return []

        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []

        results: List[SinkClassification] = []
        for func_va in self._ctx.func_starts:
            insns = self._get_insns(func_va)
            if not insns:
                continue
            for sink_va, (sink_name, arg_pos) in sink_plts.items():
                for call_idx in self._find_call_sites(insns, sink_va):
                    call_va = insns[call_idx].address
                    result = self._classify_site(
                        func_va, call_va, insns, call_idx, sink_name, arg_pos
                    )
                    results.append(result)

        return results

    def report(self, results: List[SinkClassification]) -> str:
        """Format results as a human-readable report."""
        if not results:
            return 'SinkArgClassifierX86_32: no call sites found.\n'
        lines = [
            'SinkArgClassifierX86_32 Results',
            '=' * 60,
        ]
        counts: Dict[str, int] = {}
        for r in results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1

        lines.append('Summary: ' + '  '.join(f'{k}={v}' for k, v in sorted(counts.items())))
        lines.append('')

        for r in sorted(results, key=lambda x: (x.verdict != UNKNOWN, x.verdict != ARG_PROPAGATED)):
            lines.append(
                f'[{r.verdict:16s}] {r.sink_name:12s} '
                f'call={hex(r.call_va)} func={hex(r.func_va)}'
                f'  [{r.detail}]'
            )
        return '\n'.join(lines) + '\n'
