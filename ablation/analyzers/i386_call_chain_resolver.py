"""
i386_call_chain_resolver.py — multi-level call chain resolver for i386 binaries.

Gap this fills vs CallerArgResolver:
  CallerArgResolver resolves ONE level of callers and returns UNKNOWN when a caller
  passes "push mem [dword ptr [reg]]" — a struct field dereference where the struct
  pointer origin is not tracked.

  This module fills two gaps:
  (A) Multi-level traversal: automatically ascends the call graph up to max_depth
      levels following ARG_PROPAGATED links, instead of stopping after one level.
  (B) Struct pointer origin tracing: when a caller passes *reg (deref), this module
      traces `reg` backward in the caller to find its origin:
        - [ebp+N]             → ARG_PROPAGATED (continue ascending)
        - return value of F   → if F is a network source (recv/read/accept) → CONFIRMED
        - [global_va]         → GLOBAL_LOAD (static ceiling)
        - unknown             → UNKNOWN (static ceiling)

Gap IDs closed: SYNERGY-GAP-004 (ccm_eng_inf/ora struct-field-deref static ceiling).

Three chain verdicts:
  CONFIRMED       — taint reaches a network source function (recv/recvfrom/read/etc.)
  SAFE            — argument traces back to RODATA_CONST or CONST at all chain leaves
  STATIC_CEILING  — max_depth reached or struct pointer origin not resolvable

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.i386_call_chain_resolver import I386CallChainResolver

    ctx  = BinaryContext.load_or_build('/path/to/ccm_eng_inf')
    ccr  = I386CallChainResolver.from_context(ctx)

    # Trace the execvp dispatch function's arg_pos=0 up the call graph
    result = ccr.resolve_chain(func_va=0x80cf362, func_arg_pos=0)
    print(result.verdict, result.depth_reached, result.detail)
    for step in result.chain:
        print('  0x%x → %s' % (step.func_va, step.verdict))
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86_const import (
        X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
        X86_REG_EBP, X86_REG_ESP, X86_REG_EAX,
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

from ablation.analyzers.caller_arg_resolver import (
    CallerArgResolver, ARG_PROPAGATED, RODATA_CONST, UNKNOWN,
    CONST_NULL, CONST_NONZERO, STACK_LOCAL,
)

# ── constants ──────────────────────────────────────────────────────────────────

CONFIRMED      = 'CONFIRMED'
SAFE           = 'SAFE'
STATIC_CEILING = 'STATIC_CEILING'

# PLT names that indicate network/IPC input (any of these in call chain → CONFIRMED)
_NETWORK_SOURCES: FrozenSet[str] = frozenset([
    'recv', 'recvfrom', 'recvmsg', 'recvmmsg',
    'read', 'pread', 'pread64', 'fread',
    'accept', 'accept4',
    'gets', 'fgets', 'fgetc', 'getchar',
    'scanf', 'fscanf', 'sscanf', 'vscanf', 'vfscanf',
    '__isoc99_sscanf', '__isoc99_fscanf', '__isoc99_scanf',
    'getline', 'getdelim',
    # IPC / sockets
    'msgrcv', 'mq_receive', 'mq_timedreceive',
    # Synergy-specific IPC patterns (stripped names won't match, but explicit ones might)
    'ipc_receive', 'ccm_recv', 'ccm_ipc_recv',
])

_LOOKBACK = 80  # instructions to scan before a call site

# ── data classes ───────────────────────────────────────────────────────────────

@dataclass
class ChainStep:
    func_va: int
    caller_func_va: int
    call_site_va: int
    verdict: str
    detail: str


@dataclass
class ChainResult:
    root_func_va: int
    root_arg_pos: int
    verdict: str              # CONFIRMED / SAFE / STATIC_CEILING
    depth_reached: int
    network_source: Optional[str]   # PLT name if CONFIRMED
    network_source_va: Optional[int]
    chain: List[ChainStep] = field(default_factory=list)
    detail: str = ''

    def report(self) -> str:
        lines = [
            'I386CallChainResolver: 0x%x arg_pos=%d → %s (depth=%d)' % (
                self.root_func_va, self.root_arg_pos, self.verdict, self.depth_reached),
        ]
        if self.network_source:
            lines.append('  network source: %s @ 0x%x' % (
                self.network_source, self.network_source_va or 0))
        for step in self.chain:
            lines.append('  0x%x ← caller 0x%x (site=0x%x): %s — %s' % (
                step.func_va, step.caller_func_va, step.call_site_va,
                step.verdict, step.detail[:80]))
        if self.detail:
            lines.append('  ' + self.detail)
        return '\n'.join(lines)


# ── main class ─────────────────────────────────────────────────────────────────

class I386CallChainResolver:
    """
    Multi-level call chain resolver for i386 ELF binaries.

    Iteratively applies CallerArgResolver logic across multiple call-graph levels,
    extending it with struct pointer origin tracing to detect network input sources.
    """

    def __init__(self, ctx) -> None:
        self._ctx    = ctx
        self._car    = CallerArgResolver(ctx)
        self._cs     = Cs(CS_ARCH_X86, CS_MODE_32) if _CS_OK else None
        if self._cs:
            self._cs.detail = True
        self._data: bytes = b''
        self._text_va: int = 0
        self._plt:   Dict[int, str] = {}
        self._net_vas: Set[int] = set()
        if _LIEF_OK:
            self._load_lief()

    @classmethod
    def from_context(cls, ctx) -> 'I386CallChainResolver':
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> 'I386CallChainResolver':
        from ablation.analyzers.binary_context import BinaryContext
        return cls(BinaryContext.load_or_build(path))

    def _load_lief(self) -> None:
        try:
            bin_ = _lief.parse(self._ctx.path)
            for sec in bin_.sections:
                if sec.name == '.text':
                    self._text_va = int(sec.virtual_address)
                    off = int(bin_.virtual_address_to_offset(self._text_va))
                    with open(self._ctx.path, 'rb') as fh:
                        self._data = fh.read()
                    break
            self._plt = dict(self._ctx.plt)
            self._net_vas = {va for va, name in self._plt.items()
                             if name.split('@')[0] in _NETWORK_SOURCES}
        except Exception:
            pass

    # ── public API ─────────────────────────────────────────────────────────────

    def resolve_chain(
        self,
        func_va: int,
        func_arg_pos: int,
        max_depth: int = 8,
    ) -> ChainResult:
        """
        Ascend the call graph from func_va, tracing where func_arg_pos originates.

        Returns CONFIRMED if a network source is found within max_depth levels,
        STATIC_CEILING if the chain cannot be fully resolved, or SAFE if all
        leaves trace to RODATA_CONST / compile-time constants.
        """
        result = ChainResult(
            root_func_va=func_va,
            root_arg_pos=func_arg_pos,
            verdict=STATIC_CEILING,
            depth_reached=0,
            network_source=None,
            network_source_va=None,
        )

        # Worklist: (callee_va, arg_pos, depth)
        worklist: List[Tuple[int, int, int]] = [(func_va, func_arg_pos, 0)]
        visited: Set[Tuple[int, int]] = set()
        safe_leaves = 0
        total_leaves = 0

        while worklist:
            callee_va, arg_pos, depth = worklist.pop(0)
            key = (callee_va, arg_pos)
            if key in visited or depth >= max_depth:
                result.depth_reached = max(result.depth_reached, depth)
                continue
            visited.add(key)
            result.depth_reached = max(result.depth_reached, depth)

            report = self._car.resolve(func_va=callee_va, func_arg_pos=arg_pos)

            if not report.results:
                # No callers: function pointer dispatch — static ceiling leaf
                total_leaves += 1
                result.chain.append(ChainStep(
                    func_va=callee_va,
                    caller_func_va=0,
                    call_site_va=0,
                    verdict=STATIC_CEILING,
                    detail='NO_CALLERS — function pointer dispatch',
                ))
                continue

            for site in report.results:
                if site.verdict == ARG_PROPAGATED:
                    # Caller passes its own argument — recurse upward
                    worklist.append((site.caller_func_va, 0, depth + 1))
                    result.chain.append(ChainStep(
                        func_va=callee_va,
                        caller_func_va=site.caller_func_va,
                        call_site_va=site.call_site_va,
                        verdict=ARG_PROPAGATED,
                        detail=site.detail,
                    ))

                elif site.verdict == UNKNOWN:
                    # Try struct pointer origin tracing
                    reg_verdict, reg_detail, net_va, net_name = self._resolve_deref_origin(
                        site.call_site_va, site.caller_func_va, arg_pos)
                    result.chain.append(ChainStep(
                        func_va=callee_va,
                        caller_func_va=site.caller_func_va,
                        call_site_va=site.call_site_va,
                        verdict=reg_verdict,
                        detail=reg_detail,
                    ))
                    if reg_verdict == CONFIRMED:
                        result.verdict = CONFIRMED
                        result.network_source = net_name
                        result.network_source_va = net_va
                        return result
                    elif reg_verdict == ARG_PROPAGATED:
                        worklist.append((site.caller_func_va, 0, depth + 1))
                    else:
                        total_leaves += 1

                elif site.verdict in (RODATA_CONST, CONST_NULL, CONST_NONZERO):
                    safe_leaves += 1
                    total_leaves += 1
                    result.chain.append(ChainStep(
                        func_va=callee_va,
                        caller_func_va=site.caller_func_va,
                        call_site_va=site.call_site_va,
                        verdict=SAFE,
                        detail=site.detail,
                    ))
                else:
                    total_leaves += 1
                    result.chain.append(ChainStep(
                        func_va=callee_va,
                        caller_func_va=site.caller_func_va,
                        call_site_va=site.call_site_va,
                        verdict=site.verdict,
                        detail=site.detail,
                    ))

        if result.verdict != CONFIRMED:
            if total_leaves > 0 and safe_leaves == total_leaves:
                result.verdict = SAFE
            else:
                result.verdict = STATIC_CEILING
            result.detail = '%d/%d leaves resolved as safe' % (safe_leaves, total_leaves)

        return result

    # ── struct pointer origin tracing ──────────────────────────────────────────

    def _resolve_deref_origin(
        self,
        call_site_va: int,
        caller_func_va: int,
        arg_pos: int,
    ) -> Tuple[str, str, Optional[int], Optional[str]]:
        """
        When CallerArgResolver returns UNKNOWN for 'push mem [dword ptr [reg]]',
        trace what 'reg' is in the caller function.

        Returns (verdict, detail, network_va, network_name).
        """
        if self._cs is None or not self._data:
            return STATIC_CEILING, 'capstone not available', None, None

        insns = self._get_insns_before(call_site_va)
        if not insns:
            return STATIC_CEILING, 'disassembly failed', None, None

        # Find the push/mov that corresponds to arg_pos
        push_idx, reg_id = self._find_push_deref_reg(insns, arg_pos)
        if push_idx is None or reg_id is None:
            return STATIC_CEILING, 'push for arg_pos=%d not found' % arg_pos, None, None

        # Trace reg_id backward from push_idx
        return self._trace_reg_origin(insns, push_idx, reg_id, caller_func_va)

    def _find_push_deref_reg(
        self,
        insns: list,
        arg_pos: int,
    ) -> Tuple[Optional[int], Optional[int]]:
        """
        Find the push/mov that supplies arg_pos and return (insn_index, dereffed_reg_id).
        Handles both 'push [reg]' and 'mov [esp+N], [reg]' patterns.
        """
        if self._cs is None:
            return None, None
        push_count = 0
        for i in range(len(insns) - 1, -1, -1):
            insn = insns[i]
            if insn.mnemonic == 'push':
                if push_count == arg_pos:
                    # This push supplies arg_pos — check if it's a deref
                    if insn.operands and insn.operands[0].type == X86_OP_MEM:
                        op = insn.operands[0].mem
                        if op.base != 0 and op.base != X86_REG_EBP and op.base != X86_REG_ESP:
                            return i, op.base
                push_count += 1
            elif insn.mnemonic in ('mov', 'lea') and insn.operands:
                dst = insn.operands[0]
                if dst.type == X86_OP_MEM and dst.mem.base == X86_REG_ESP:
                    slot = dst.mem.disp // 4
                    if slot == arg_pos:
                        src = insn.operands[1]
                        if src.type == X86_OP_MEM:
                            op = src.mem
                            if op.base != 0 and op.base != X86_REG_EBP:
                                return i, op.base
        return None, None

    def _trace_reg_origin(
        self,
        insns: list,
        from_idx: int,
        reg_id: int,
        caller_func_va: int,
    ) -> Tuple[str, str, Optional[int], Optional[str]]:
        """
        Walk backward from from_idx to find where reg_id was last assigned.

        Handles:
          mov reg, [ebp+N]   → ARG_PROPAGATED
          call F (eax=ret)   → if F is network source → CONFIRMED; else UNKNOWN
          mov reg, [abs_va]  → GLOBAL_LOAD (static ceiling)
          xor reg, reg       → CONST_ZERO (safe)
        """
        if self._cs is None:
            return STATIC_CEILING, 'capstone not available', None, None

        for i in range(from_idx - 1, -1, -1):
            insn = insns[i]
            if not insn.operands:
                continue

            dst = insn.operands[0]
            # Check if this instruction writes to reg_id
            if dst.type == X86_OP_REG and dst.reg == reg_id:
                if insn.mnemonic in ('mov', 'lea', 'movzx', 'movsx', 'and', 'or', 'xor'):
                    if insn.mnemonic == 'xor' and len(insn.operands) == 2:
                        if insn.operands[1].type == X86_OP_REG and insn.operands[1].reg == reg_id:
                            return SAFE, 'xor self-zero → CONST_ZERO', None, None
                    src = insn.operands[1]
                    if src.type == X86_OP_MEM:
                        mem = src.mem
                        if mem.base == X86_REG_EBP and mem.disp > 0:
                            # [ebp+N] — function argument
                            arg_n = (mem.disp - 8) // 4
                            return ARG_PROPAGATED, (
                                'reg traced to [ebp+0x%x] = func_arg_%d → ARG_PROPAGATED'
                                % (mem.disp, arg_n)), None, None
                        if mem.base == 0 and mem.index == 0 and mem.disp != 0:
                            # [abs_addr] — global load
                            return STATIC_CEILING, (
                                'reg loaded from global [0x%x] — GLOBAL_LOAD; '
                                'struct origin requires dynamic analysis' % mem.disp), None, None
                    elif src.type == X86_OP_IMM:
                        return SAFE, 'reg = imm 0x%x → CONST' % src.imm, None, None

            # Check call instructions: if reg_id is EAX, the return value of a call
            if insn.mnemonic == 'call' and reg_id == X86_REG_EAX:
                callee_va = None
                if insn.operands and insn.operands[0].type == X86_OP_IMM:
                    callee_va = insn.operands[0].imm
                if callee_va and callee_va in self._plt:
                    name = self._plt[callee_va].split('@')[0]
                    if name in _NETWORK_SOURCES:
                        return CONFIRMED, (
                            'eax = return of %s @ 0x%x → CONFIRMED network source'
                            % (name, callee_va)), callee_va, name
                    return STATIC_CEILING, (
                        'eax = return of %s @ 0x%x (not a network source)'
                        % (name, callee_va)), None, None
                elif callee_va:
                    return STATIC_CEILING, (
                        'eax = return of internal func @ 0x%x — '
                        'internal call chain not traced' % callee_va), None, None

        return STATIC_CEILING, (
            'reg origin not found within lookback window — '
            'struct pointer origin unknown'), None, None

    # ── disassembly helpers ────────────────────────────────────────────────────

    def _get_insns_before(self, call_va: int) -> list:
        if self._cs is None or not self._data:
            return []
        try:
            bin_ = _lief.parse(self._ctx.path) if _LIEF_OK else None
            if bin_ is None:
                return []
            off = int(bin_.virtual_address_to_offset(call_va))
            start = max(0, off - _LOOKBACK * 7)
            seg = self._data[start:off + 6]
            base_va = call_va - (off - start)
            insns = list(self._cs.disasm(seg, base_va))
            # Keep only instructions up to and including the call
            result = []
            for insn in insns:
                result.append(insn)
                if insn.address >= call_va:
                    break
            return result
        except Exception:
            return []
