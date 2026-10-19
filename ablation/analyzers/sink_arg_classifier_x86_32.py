"""
sink_arg_classifier_x86_32.py: classify exec-class sink argument provenance on x86_32 ELFs.

Gap this fills vs SinkArgClassifier:
  SinkArgClassifier hardcodes x86-64 registers (rdi, rsi, rdx).
  x86_32 cdecl passes all arguments on the stack (pushed right-to-left).
  That gap is RMC-GAP-002 / COMMSVR-GAP-004 / HACMP-GAP-001.
  This module resolves all three.

Session 20 improvements (2026-10-19):
  [A] [reg+disp] dereference → ARG_PROPAGATED when base register traces to ARG_PROPAGATED.
      Fixes execv(argv[0], argv) pattern where arg0 = [eax] and eax = [ebp+8].
      Prior: UNKNOWN. Now: ARG_PROPAGATED.
  [B] strcpy/strcat-family added to _backtrack_stack_slot.
      Fixes strcpy(buf, RODATA); system(buf) — buffer filled from static string.
      Prior: UNKNOWN. Now: SNPRINTF_RODATA.
  Gap IDs: SYNERGY-UNKNOWN-001 (execv argv deref), SYNERGY-UNKNOWN-002 (strcpy fill).

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
    from ablation.analyzers.sink_arg_classifier_x86_32 import SinkArgClassifierI386

    ctx = BinaryContext.load_or_build('/path/to/rmcd', force_rebuild=True)
    clf = SinkArgClassifierI386.from_context(ctx)

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
    'execv':     0,   # execv(path, argv[]) — no envp; path at arg_pos 0
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

# strcpy-family: dest=arg0, src=arg1.  If the src is RODATA_CONST and dest is our
# stack slot, the slot holds a RODATA-derived string → SNPRINTF_RODATA verdict.
# strcat fills dst at arg0 from src at arg1.
_STRCPY_DST_SRC_X86_32: Dict[str, Tuple[int, int]] = {
    'strcpy':    (0, 1),
    'strncpy':   (0, 1),
    'strlcpy':   (0, 1),
    'stpcpy':    (0, 1),
    'strcat':    (0, 1),
    'strncat':   (0, 1),
    'g_strlcpy': (0, 1),
    'g_strlcat': (0, 1),
    'g_stpcpy':  (0, 1),
}

# ── Scan constants ────────────────────────────────────────────────────────────
_LOOKBACK        = 80    # instructions to scan backward from call site
_SNPRINTF_WINDOW = 140   # instructions to scan for prior snprintf
_MAX_FUNC_BYTES  = 65536


class SinkArgClassifierI386:
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
        self._strcpy_plts: Dict[int, Tuple[int, int]] = {}  # PLT VA → (dst_pos, src_pos)
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._data_ranges:  List[Tuple[int, int]] = []
        self._bss_ranges:   List[Tuple[int, int]] = []
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
    def from_context(cls, ctx) -> 'SinkArgClassifierI386':
        """Build from a BinaryContext."""
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> 'SinkArgClassifierI386':
        """Build directly from an ELF path — constructs BinaryContext internally."""
        from ablation.analyzers.binary_context import BinaryContext
        ctx = BinaryContext.load_or_build(path)
        return cls(ctx)

    def add_sink(self, name: str, arg_pos: int) -> None:
        """Register an additional sink (e.g., 'strcpy' at arg_pos=1 for source)."""
        self._sinks[name] = arg_pos

    # ── initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        for sec in self._bin.sections:
            va_s = int(sec.virtual_address)
            va_e = va_s + int(sec.size)
            if sec.name in ('.rodata', '.rodata1', '__const', '__cstring', '.rdata'):
                self._rodata_ranges.append((va_s, va_e))
            elif sec.name in ('.data', '.data.rel.ro', '.data.rel', '.data1'):
                self._data_ranges.append((va_s, va_e))
            elif sec.name in ('.bss', '.tbss', '.sbss'):
                self._bss_ranges.append((va_s, va_e))
        for name, fmt_pos in _SNPRINTF_FMT_POS_X86_32.items():
            va = self._plt_rev.get(name)
            if va is not None:
                self._snprintf_plts[va] = fmt_pos
        for name, (dst_pos, src_pos) in _STRCPY_DST_SRC_X86_32.items():
            va = self._plt_rev.get(name)
            if va is not None:
                self._strcpy_plts[va] = (dst_pos, src_pos)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _is_rodata(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._rodata_ranges)

    def _is_in_bss(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._bss_ranges)

    def _read_cstr(self, va: int) -> Optional[str]:
        """Return null-terminated printable ASCII at va, or None if not a string."""
        raw = self._read_va(va, 256)
        for i, b in enumerate(raw):
            if b == 0:
                if i == 0:
                    return None  # empty string — likely BSS zero, not a constant
                try:
                    return raw[:i].decode('ascii')
                except Exception:
                    return None
            if b < 0x20 and b not in (0x09, 0x0a, 0x0d):
                return None
            if b > 0x7e:
                return None
        return None

    def _is_static_const(self, va: int) -> bool:
        """True if va holds a compile-time string constant (.rodata or .data init)."""
        if self._is_rodata(va):
            return True
        if self._is_in_bss(va):
            return False
        return self._read_cstr(va) is not None

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
            return RODATA_CONST if self._is_static_const(val) else UNKNOWN

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

            # Found a definition — classify based on opcode.
            # Pass start_idx so _classify_lea can use it as the snprintf
            # backtrack origin (handles the case where the snprintf filling
            # the buffer comes between the lea and the sink call).
            if mn == 'lea':
                return self._classify_lea(insn, j, insns, depth, call_idx=start_idx)
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

    # Instructions whose first operand is a *source*, not a destination.
    # `push reg` reads the register; `cmp`/`test` are comparison-only; `call`
    # uses the operand as a branch target.  None of these write to the register.
    _READ_ONLY_MNEMONICS = frozenset({'push', 'cmp', 'test', 'jmp', 'call'})

    def _writes_reg(self, insn, reg_id: int) -> bool:
        """True if the instruction's first operand is a register destination (writes reg_id).

        Excludes instructions where the first operand is a source: push, cmp, test,
        jmp, call.  Without this exclusion, 'push esi' would be mistaken for a write
        to ESI, causing _classify_value() to stop at the push rather than continuing
        backward to the lea that actually loads ESI.
        """
        if insn.mnemonic in self._READ_ONLY_MNEMONICS:
            return False
        ops = insn.operands
        if not ops:
            return False
        op = ops[0]
        if op.type != X86_OP_REG:
            return False
        # Capstone x86_32: 32-bit register IDs differ from 64-bit
        # We accept exact match; partial register (al, ax vs eax) handled by same reg_id
        return op.reg == reg_id

    def _classify_lea(self, insn, insn_idx: int, insns: list, depth: int,
                      call_idx: int = -1) -> str:
        """
        Classify a lea instruction.
        lea eax, [abs_addr]   → direct absolute address; check if in .rodata
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
        base  = mem.mem.base
        index = mem.mem.index
        disp  = mem.mem.disp

        # Direct absolute address: lea eax, [0xNNNN] — base=0, index=0
        # Capstone reports no-register as 0 (X86_REG_INVALID).
        if base == 0 and index == 0:
            if self._is_static_const(disp):
                return RODATA_CONST
            return UNKNOWN

        # ebp-relative: local buffer or argument address
        if base == X86_REG_EBP:
            if disp > 0:
                return ARG_PROPAGATED
            if disp < 0:
                # Address of local stack buffer — snprintf backtrack.
                # Use call_idx (the original sink call site) as the scan origin when
                # available: the snprintf that fills the buffer may be BETWEEN the lea
                # and the sink call, so scanning from insn_idx would miss it.
                backtrack_from = call_idx if call_idx > insn_idx else insn_idx
                return self._backtrack_stack_slot(insns, backtrack_from, -disp, depth)
            return UNKNOWN

        # ebx-relative (GOT base in PIC x86_32)
        if base == X86_REG_EBX:
            # ebx = GOT base; compute target VA
            got_base = self._find_ebx_got_base(insns, insn_idx)
            if got_base is not None:
                target_va = got_base + disp
                if self._is_static_const(target_va):
                    return RODATA_CONST
                # Could be a GOT entry pointing to .rodata or .data string
                ptr = self._read_u32(target_va)
                if ptr is not None and self._is_static_const(ptr):
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
                    if ptr is not None and self._is_static_const(ptr):
                        return RODATA_CONST
                return UNKNOWN
            # [disp] — absolute address (base=X86_REG_INVALID=0), no index
            if base == 0 and idx == 0 and disp != 0:
                if self._is_static_const(disp):
                    return RODATA_CONST
                ptr = self._read_u32(disp)
                if ptr is not None and self._is_static_const(ptr):
                    return RODATA_CONST
                return UNKNOWN
            # [reg + N] — pointer dereference (struct, heap, or argv-style array).
            # Trace the base register: if it came from an ARG_PROPAGATED source,
            # so does its dereference.  Applies to execv(argv[0], argv) where
            # arg0 = [eax] and eax = [ebp+8].
            if base != 0 and idx == 0 and depth < 2:
                base_verdict = self._classify_value(insns, insn_idx, f'reg:{base}', depth + 1)
                if base_verdict == ARG_PROPAGATED:
                    return ARG_PROPAGATED
            return UNKNOWN

        return UNKNOWN

    def _find_ebx_got_base(self, insns: list, from_idx: int) -> Optional[int]:
        """
        Find the GOT base value in ebx.

        Two PIC x86_32 patterns:
          1. call $+5 / pop ebx / add ebx, DELTA  — used in hand-written or old GCC code.
             pop_va = address of pop ebx; got_base = pop_va + DELTA.

          2. call __x86_get_pc_thunk_bx / add ebx, DELTA  — GCC PIC standard.
             Thunk body: mov ebx, [esp]; ret — so on return, ebx = return address
             = address of the instruction after the call = address of the add itself.
             got_base = add_insn.address + DELTA.
        """
        for j in range(from_idx - 1, -1, -1):
            insn = insns[j]
            if insn.mnemonic != 'add':
                continue
            ops = insn.operands
            if len(ops) < 2:
                continue
            if ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_EBX:
                if ops[1].type == X86_OP_IMM:
                    delta = ops[1].imm
                    # Pattern 1: call $+5 / pop ebx
                    pop_va = self._find_pop_ebx_va(insns, j)
                    if pop_va is not None:
                        return pop_va + delta
                    # Pattern 2: call __x86_get_pc_thunk_bx
                    # The thunk puts the add instruction's address into ebx.
                    if self._has_pc_thunk_call(insns, j):
                        return insn.address + delta
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

    def _has_pc_thunk_call(self, insns: list, add_idx: int) -> bool:
        """
        Return True if a call to __x86_get_pc_thunk_bx (or equivalent) immediately
        precedes the 'add ebx, N' at add_idx.

        Two identification strategies:
          - Named: call target matches a known PLT/export entry with 'get_pc_thunk'
            or 'i686.get_pc.thunk' in its name.
          - Structural: any call within 4 instructions before the add where the
            callee is a tiny (≤8 byte) function — GCC always emits the thunk as
            a tiny helper near the call site.
        """
        start = max(0, add_idx - 4)
        for j in range(add_idx - 1, start - 1, -1):
            insn = insns[j]
            if insn.mnemonic != 'call':
                continue
            ops = insn.operands
            if not ops or ops[0].type != X86_OP_IMM:
                continue
            target_va = ops[0].imm
            # Named check via context symbol table
            name = (self._ctx.name(target_va) or '').lower()
            if 'get_pc_thunk' in name or 'i686.get_pc.thunk' in name:
                return True
            # Structural check: callee is ≤8 bytes (thunk body is 3 bytes: mov+ret)
            import bisect
            fs = self._ctx.func_starts
            idx = bisect.bisect_right(fs, target_va)
            if idx < len(fs):
                callee_size = fs[idx] - target_va
                if 0 < callee_size <= 8:
                    return True
        return False

    def _backtrack_stack_slot(
        self, insns: list, from_idx: int, ebp_neg_offset: int, depth: int
    ) -> str:
        """
        Determine if a stack slot [ebp - ebp_neg_offset] was filled by a string-building
        call (snprintf/sprintf or strcpy/strcat) with a RODATA source.
        Returns SNPRINTF_RODATA or UNKNOWN.
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
            if callee_va not in self._snprintf_plts and callee_va not in self._strcpy_plts:
                continue

            # snprintf-family: check dest=slot and fmt=RODATA
            if callee_va in self._snprintf_plts:
                fmt_pos = self._snprintf_plts[callee_va]
                dest_arg_idx = 0
                dest_is_our_slot = self._arg_is_stack_slot(insns, j, dest_arg_idx, ebp_neg_offset)
                if not dest_is_our_slot:
                    continue
                fmt_verdict = self._get_pushed_arg(insns, j, fmt_pos, depth + 1)
                if fmt_verdict == RODATA_CONST:
                    return SNPRINTF_RODATA
                continue

            # strcpy-family: check dest=slot and src=RODATA.
            # strcpy(dest=[ebp-N], src=RODATA) → slot holds a RODATA-derived string.
            if callee_va in self._strcpy_plts:
                dst_pos, src_pos = self._strcpy_plts[callee_va]
                dest_is_our_slot = self._arg_is_stack_slot(insns, j, dst_pos, ebp_neg_offset)
                if not dest_is_our_slot:
                    continue
                src_verdict = self._get_pushed_arg(insns, j, src_pos, depth + 1)
                if src_verdict == RODATA_CONST:
                    return SNPRINTF_RODATA  # slot holds string copied from .rodata
                continue

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
        Find the instruction index that provides argument arg_pos.

        Handles two x86_32 cdecl calling convention styles:
          Push-based (O0): push <val> instructions right-to-left.
            arg_pos 0 = last push, arg_pos 1 = second-to-last, etc.
          Sub-esp+mov (O1+): frame pre-allocated by sub esp,N; args written
            as mov dword ptr [esp + N*4], val.
            arg_pos N → look for mov [esp + N*4], val.
        """
        pushes: List[int] = []
        start = max(0, call_idx - _LOOKBACK)

        for j in range(call_idx - 1, start - 1, -1):
            insn = insns[j]
            mn = insn.mnemonic
            if mn == 'push':
                pushes.append(j)
            elif mn in ('ret', 'leave'):
                break
            elif mn == 'call' and j < call_idx - 1:
                # Don't cross an earlier call's argument setup region.
                if pushes:
                    break

        if pushes:
            if arg_pos < len(pushes):
                return pushes[arg_pos]
            return None

        # No push instructions found — try sub-esp + mov [esp + N*4], val pattern.
        target_disp = arg_pos * 4
        for j in range(call_idx - 1, start - 1, -1):
            insn = insns[j]
            if insn.mnemonic != 'mov':
                continue
            ops = insn.operands
            if len(ops) < 2:
                continue
            dst = ops[0]
            if dst.type != X86_OP_MEM:
                continue
            if dst.mem.base != X86_REG_ESP or dst.mem.index != 0:
                continue
            if dst.mem.disp == target_disp:
                return j

        return None

    def _get_pushed_arg(
        self, insns: list, call_idx: int, arg_pos: int, depth: int
    ) -> Optional[str]:
        """
        Get the classification verdict for arg_pos at the call at call_idx.
        Returns verdict string or None if the argument couldn't be found.

        Handles both push-based and sub-esp+mov calling styles.
        For push: ops[0] is the value.
        For mov [esp+N], val: ops[0] is the destination, ops[1] is the value.
        """
        push_idx = self._find_push_for_arg(insns, call_idx, arg_pos)
        if push_idx is None:
            return None
        insn = insns[push_idx]
        ops = insn.operands
        if not ops:
            return None

        # Select the value operand based on instruction type.
        if insn.mnemonic == 'push':
            op = ops[0]
        elif insn.mnemonic == 'mov' and len(ops) >= 2:
            op = ops[1]  # mov [esp+N], <src> — source is ops[1]
        else:
            return UNKNOWN

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
            if m.base == X86_REG_EBX and m.index == 0:
                got_base = self._find_ebx_got_base(insns, push_idx)
                if got_base is not None:
                    target_va = got_base + m.disp
                    ptr = self._read_u32(target_va)
                    if ptr is not None and self._is_static_const(ptr):
                        return RODATA_CONST
                return UNKNOWN
            # [disp] absolute address
            if m.base == 0 and m.index == 0 and m.disp != 0:
                if self._is_static_const(m.disp):
                    return RODATA_CONST
                ptr = self._read_u32(m.disp)
                if ptr is not None and self._is_static_const(ptr):
                    return RODATA_CONST
                return UNKNOWN
            # [reg+N] — trace base register: execv(argv[0]) where argv[0]=[eax] and eax=[ebp+8]
            if m.base != 0 and m.index == 0 and depth < 2:
                base_verdict = self._classify_value(insns, push_idx, f'reg:{m.base}', depth + 1)
                if base_verdict == ARG_PROPAGATED:
                    return ARG_PROPAGATED
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
            return 'SinkArgClassifierI386: no call sites found.\n'
        lines = [
            'SinkArgClassifierI386 Results',
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


# Backward-compat alias: the class was previously named SinkArgClassifierX86_32.
# sac_for_path() and callers should use SinkArgClassifierI386 (the canonical name).
SinkArgClassifierX86_32 = SinkArgClassifierI386
