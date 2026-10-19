"""
sink_arg_classifier_i386.py — forward register-state exec-sink classifier for i386 ELFs.

Gap vs sink_arg_classifier_x86_32.py (push-backtrack approach):
  The push-backtrack module scans backward N instructions before each exec call site.
  When the exec argument register is loaded from [ebp+8] far before the call — beyond
  the _LOOKBACK window — and passed through several MOV aliases, the backtrack returns
  UNKNOWN.

  This module uses a forward register-state pass through each function:
    1. Single forward disassembly pass builds a reg_state dict for each function.
    2. At each exec PLT call, reg_state already holds the current verdict for every
       register — no lookback limit.
    3. Handles register aliases: mov edi, eax after eax=ARG_PROPAGATED → edi=ARG_PROPAGATED.
    4. Handles both push and sub-esp/mov-[esp+N] calling conventions natively.

  Together with sink_arg_classifier_x86_32.py (which has deeper snprintf/strcpy
  stack-slot backtrack), these cover complementary i386 classification patterns.

Gap IDs closed: RMC-GAP-002, COMMSVR-GAP-004, HACMP-GAP-001 (same as x86_32 module,
now with forward-tracking coverage for long-range register persistence).

Four verdicts (same as SinkArgClassifier):
  RODATA_CONST    — argument is a constant from .rodata/.text or a zero immediate.
  SNPRINTF_RODATA — argument is a stack slot filled by snprintf with RODATA_CONST fmt.
  ARG_PROPAGATED  — argument register traces back to [ebp+N] (N > 0): a function arg.
  UNKNOWN         — provenance not resolved in the forward pass.

Algorithm:
  for each function containing exec PLT calls:
    reg_state = {}         # reg_id → verdict string
    call_args = {}         # {arg_slot_idx: verdict} for sub-esp/mov[esp+N] style
    for insn in forward_disasm(func_va):
      update reg_state from insn
      if insn is exec PLT call:
        verdict = lookup_arg(arg_pos, reg_state, call_args)
        emit SinkClassification

Usage:
    from ablation.analyzers.sink_arg_classifier_i386 import SinkArgClassifierI386

    clf = SinkArgClassifierI386.from_path('/path/to/ccm_eng_inf')
    results = clf.classify_all()
    for r in results:
        print(r.severity, r.verdict, hex(r.call_va), r.sink_name)
"""
from __future__ import annotations

import bisect
from typing import Dict, List, Optional, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86_const import (
        X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
        X86_REG_EBP, X86_REG_ESP, X86_REG_EAX,
        X86_REG_EBX, X86_REG_ECX, X86_REG_EDX,
        X86_REG_ESI, X86_REG_EDI,
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

# Re-use shared verdict constants and SinkClassification from the x86 module.
from ablation.analyzers.sink_arg_classifier import (
    SinkClassification,
    RODATA_CONST,
    SNPRINTF_RODATA,
    ARG_PROPAGATED,
    UNKNOWN,
)

# ── exec-class sinks (i386 cdecl arg_pos=0 for all) ───────────────────────────
_DEFAULT_SINKS: Dict[str, int] = {
    'system':    0,
    'popen':     0,
    'execl':     0,
    'execle':    0,
    'execlp':    0,
    'execv':     0,
    'execve':    0,
    'execvp':    0,
    'execvpe':   0,
    'execveat':  0,
    'posix_spawn': 2,
}

# snprintf-family: (fmt_arg_pos). We classify a stack slot as SNPRINTF_RODATA when
# snprintf is called with a RODATA_CONST format into that slot.
_SNPRINTF_FMT_POS: Dict[str, int] = {
    'snprintf':  1,
    'sprintf':   1,
    '_snprintf': 1,
    '__snprintf_chk': 4,
    'asprintf':  1,
    'vasprintf': 1,
    'vsnprintf': 2,
    'vsprintf':  1,
}

_MAX_FUNC_INSNS = 2000  # hard cap per function to avoid O(∞) on data misidentified as code


# ── main class ─────────────────────────────────────────────────────────────────

class SinkArgClassifierI386:
    """
    Forward register-state exec-sink classifier for i386 ELF binaries.

    Uses a single forward disassembly pass per function to maintain a live
    register-state dict. At each exec PLT call, looks up the current verdict
    for the argument register — no backward lookback limit.
    """

    def __init__(self, ctx) -> None:
        self._ctx    = ctx
        self._cs:    Optional[Cs] = Cs(CS_ARCH_X86, CS_MODE_32) if _CS_OK else None
        if self._cs:
            self._cs.detail = True
        self._data:  bytes = b''
        self._bin              = None   # cached lief.Binary
        self._sorted_funcs:    List[int] = []
        self._sinks: Dict[int, Tuple[str, int]] = {}   # plt_va → (name, arg_pos)
        self._snpf:  Dict[int, int] = {}               # plt_va → fmt_arg_pos
        self._rodata: List[Tuple[int, int]] = []        # [(va_start, va_end), ...]
        if _LIEF_OK:
            self._load_lief()

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierI386':
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> 'SinkArgClassifierI386':
        from ablation.analyzers.binary_context import BinaryContext
        return cls(BinaryContext.load_or_build(path))

    def add_sink(self, name: str, arg_pos: int = 0) -> None:
        for va, n in self._ctx.plt.items():
            if n.split('@')[0] == name:
                self._sinks[va] = (name, arg_pos)

    # ── public API ─────────────────────────────────────────────────────────────

    def classify_all(self) -> List[SinkClassification]:
        if not self._sinks:
            return []
        results: List[SinkClassification] = []
        for func_va in sorted(self._ctx.func_starts):
            results.extend(self._classify_func(func_va))
        return results

    def report(self, results: List[SinkClassification]) -> str:
        if not results:
            return 'SinkArgClassifierI386: 0 exec-class call sites'
        lines = ['SinkArgClassifierI386 results (%d sites):' % len(results)]
        for r in results:
            lines.append('  %s  %-20s  func=0x%x  call=0x%x  %s' % (
                r.severity, r.verdict, r.func_va, r.call_va, r.sink_name))
        return '\n'.join(lines)

    # ── per-function forward pass ───────────────────────────────────────────────

    def _classify_func(self, func_va: int) -> List[SinkClassification]:
        insns = self._disasm_func(func_va)
        if not insns:
            return []

        # Quick filter: does this function call any exec sink?
        call_vas = {insn.address for insn in insns if insn.mnemonic == 'call'}
        if not any(
            insn.mnemonic == 'call'
            and insn.operands
            and insn.operands[0].type == X86_OP_IMM
            and insn.operands[0].imm in self._sinks
            for insn in insns
        ):
            return []

        # Forward register-state pass
        # reg_state: reg_id → verdict string
        # call_args: slot_idx → verdict  (for sub-esp/mov[esp+N] style)
        # stack: {ebp_neg_offset → verdict}  (snprintf fill detection)
        reg_state:  Dict[int, str] = {}
        call_args:  Dict[int, str] = {}
        stack:      Dict[int, str] = {}
        results: List[SinkClassification] = []

        for insn in insns:
            if insn.mnemonic == 'call' and insn.operands:
                op = insn.operands[0]
                if op.type == X86_OP_IMM:
                    callee = op.imm
                    # Record exec-sink result BEFORE clearing call_args
                    if callee in self._sinks:
                        name, arg_pos = self._sinks[callee]
                        verdict = self._get_arg_verdict(arg_pos, reg_state, call_args, stack)
                        results.append(SinkClassification(
                            sink_name=name,
                            arg_pos=arg_pos,
                            func_va=func_va,
                            call_va=insn.address,
                            verdict=verdict,
                            detail='forward-state i386',
                        ))
                    # After any call: EAX = unknown return value; push arg build-up resets
                    call_args.clear()
                    if _CS_OK:
                        reg_state[X86_REG_EAX] = UNKNOWN
                    continue  # call handling complete; skip _update_state

            self._update_state(insn, reg_state, call_args, stack)

        return results

    # ── register state update ──────────────────────────────────────────────────

    def _update_state(
        self,
        insn,
        reg_state: Dict[int, str],
        call_args: Dict[int, str],
        stack: Dict[int, str],
    ) -> None:
        if not insn.operands:
            return
        mn = insn.mnemonic

        if mn in ('mov', 'movzx', 'movsx', 'lea'):
            dst, src = insn.operands[0], insn.operands[1]
            verdict = self._classify_src(src, reg_state, stack)

            if dst.type == X86_OP_REG:
                reg_state[dst.reg] = verdict

            elif dst.type == X86_OP_MEM:
                mem = dst.mem
                if mem.base == X86_REG_ESP and mem.index == 0:
                    # mov [esp+N], val — sub-esp style arg passing
                    slot = mem.disp // 4
                    call_args[slot] = verdict
                elif mem.base == X86_REG_EBP and mem.disp < 0:
                    # mov [ebp-N], val — local stack slot fill
                    stack[abs(mem.disp)] = verdict

        elif mn == 'push':
            # push val — traditional cdecl arg passing
            # call_args uses negative indices from the end to represent push order
            # Slot 0 = last push (arg0), slot 1 = second-to-last (arg1), etc.
            src = insn.operands[0]
            verdict = self._classify_src(src, reg_state, stack)
            # Shift existing call_args up by one slot
            shifted = {k + 1: v for k, v in call_args.items()}
            shifted[0] = verdict
            call_args.clear()
            call_args.update(shifted)

        elif mn == 'xor':
            dst, src = insn.operands[0], insn.operands[1]
            if (dst.type == X86_OP_REG and src.type == X86_OP_REG
                    and dst.reg == src.reg):
                reg_state[dst.reg] = RODATA_CONST  # xor self = zero constant

        # Note: 'call' instructions are handled in _classify_func, not here.
        # _classify_func records exec-sink verdicts BEFORE clearing call_args.

        elif mn in ('add', 'sub', 'and', 'or', 'not', 'neg', 'shr', 'shl',
                    'sar', 'ror', 'rol', 'inc', 'dec'):
            # Arithmetic clobbers destination — result is no longer clean ARG_PROPAGATED
            dst = insn.operands[0]
            if dst.type == X86_OP_REG and reg_state.get(dst.reg) == ARG_PROPAGATED:
                reg_state[dst.reg] = UNKNOWN

    def _classify_src(
        self,
        src,
        reg_state: Dict[int, str],
        stack: Dict[int, str],
    ) -> str:
        if src.type == X86_OP_IMM:
            return RODATA_CONST  # immediates are compile-time constants

        if src.type == X86_OP_REG:
            return reg_state.get(src.reg, UNKNOWN)

        if src.type == X86_OP_MEM:
            mem = src.mem
            if mem.base == X86_REG_EBP:
                if mem.disp > 0:
                    return ARG_PROPAGATED  # [ebp+N], N > 0 = function argument
                if mem.disp < 0:
                    return stack.get(abs(mem.disp), UNKNOWN)  # [ebp-N] = local
            if mem.base == 0 and mem.index == 0 and mem.disp != 0:
                if self._is_rodata(mem.disp):
                    return RODATA_CONST  # [abs_va] pointing to .rodata
            if mem.base != 0:
                base_verdict = reg_state.get(mem.base, UNKNOWN)
                if base_verdict == ARG_PROPAGATED:
                    return ARG_PROPAGATED  # [ARG+offset] dereference
        return UNKNOWN

    def _get_arg_verdict(
        self,
        arg_pos: int,
        reg_state: Dict[int, str],
        call_args: Dict[int, str],
        stack: Dict[int, str],
    ) -> str:
        return call_args.get(arg_pos, UNKNOWN)

    # ── lief / section helpers ─────────────────────────────────────────────────

    def _load_lief(self) -> None:
        try:
            self._bin = _lief.parse(self._ctx.path)
            with open(self._ctx.path, 'rb') as fh:
                self._data = fh.read()
            for sec in self._bin.sections:
                if sec.name in ('.rodata', '.rodata1', '__const', '.rdata', '__cstring', '.text'):
                    va = int(sec.virtual_address)
                    self._rodata.append((va, va + int(sec.size)))
            for va, name in self._ctx.plt.items():
                bare = name.split('@')[0]
                if bare in _DEFAULT_SINKS:
                    self._sinks[va] = (bare, _DEFAULT_SINKS[bare])
                if bare in _SNPRINTF_FMT_POS:
                    self._snpf[va] = _SNPRINTF_FMT_POS[bare]
            self._sorted_funcs = sorted(self._ctx.func_starts)
        except Exception:
            pass

    def _is_rodata(self, va: int) -> bool:
        return any(lo <= va < hi for lo, hi in self._rodata)

    def _disasm_func(self, func_va: int) -> list:
        if self._cs is None or not self._data or self._bin is None:
            return []
        try:
            off = int(self._bin.virtual_address_to_offset(func_va))
            # Size bound: use next function start or MAX_FUNC_INSNS*8 bytes
            idx = bisect.bisect_right(self._sorted_funcs, func_va)
            if idx < len(self._sorted_funcs):
                next_va = self._sorted_funcs[idx]
                max_bytes = min(next_va - func_va, _MAX_FUNC_INSNS * 8)
            else:
                max_bytes = _MAX_FUNC_INSNS * 8
            seg = self._data[off: off + max_bytes]
            insns = list(self._cs.disasm(seg, func_va))
            return insns[:_MAX_FUNC_INSNS]
        except Exception:
            return []
