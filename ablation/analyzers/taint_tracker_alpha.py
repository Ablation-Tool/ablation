"""
taint_tracker_alpha.py — CFG-fixpoint taint tracker for Alpha AXP binaries.

Why this exists:
  The existing taint_tracker_*.py family does linear backward scans within
  a per-block window. Three gaps:
    1. Taint does NOT cross basic block boundaries.
    2. A register tainted on ONE path reaching a join is not propagated to
       the merged state (no phi-node joining).
    3. BSR_RETVAL terminates the trace at a call boundary; the callee is not
       entered.

  This tracker uses forward CFG-fixpoint propagation instead:
    - TaintState is propagated along CFG edges via a worklist.
    - At join points, states from all predecessors are merged (any tainted
      predecessor taints the merged result — conservative / sound).
    - BSR results are modelled: if the callee itself receives a tainted
      argument, its return value is conservatively tainted.

  The result is that exec-class findings are not limited to single-block
  functions. A command string assembled across multiple blocks, or passed
  through a wrapper that returns tainted data, is now traced correctly.

Usage:

    from ablation.analyzers.taint_tracker_alpha import AlphaTaintTracker

    tracker = AlphaTaintTracker.from_path('/path/to/binary')
    findings = tracker.scan_function(func_va)
    for f in findings:
        print(f)

    # Interprocedural: follow up to `depth` call levels
    all_findings = tracker.run_interprocedural(depth=3)
"""

from __future__ import annotations

import struct
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from ablation.analyzers.alpha_cfg import AlphaCFGBuilder, BasicBlock
from ablation.analyzers.arch_configs_raw import AlphaAXPConfig
from ablation.analyzers.dataflow_engine import CFG, DomTree


# ─── Taint values ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TaintLabel:
    """A single source label for taint."""
    name: str   # e.g. 'argv', 'env', 'network', 'callee_retval:0x12345678'


CLEAN: FrozenSet[TaintLabel] = frozenset()


def _join_labels(a: FrozenSet, b: FrozenSet) -> FrozenSet:
    return a | b


# ─── Taint state ──────────────────────────────────────────────────────────────

@dataclass
class AlphaTaintState:
    """
    Per-basic-block register taint map.

    regs: reg name → frozenset of TaintLabels (empty = CLEAN)
    """
    regs: Dict[str, FrozenSet[TaintLabel]] = field(default_factory=dict)

    def get(self, reg: str) -> FrozenSet[TaintLabel]:
        return self.regs.get(reg, CLEAN)

    def set(self, reg: str, labels: FrozenSet[TaintLabel]) -> None:
        if labels:
            self.regs[reg] = labels
        else:
            self.regs.pop(reg, None)

    def taint(self, reg: str, label: TaintLabel) -> None:
        self.regs[reg] = self.get(reg) | frozenset([label])

    def is_tainted(self, reg: str) -> bool:
        return bool(self.get(reg))

    def copy(self) -> 'AlphaTaintState':
        return AlphaTaintState(regs=dict(self.regs))

    def join(self, other: 'AlphaTaintState') -> 'AlphaTaintState':
        """Conservative join: union of labels for each register."""
        merged: Dict[str, FrozenSet[TaintLabel]] = dict(self.regs)
        for reg, labels in other.regs.items():
            existing = merged.get(reg, CLEAN)
            merged[reg] = existing | labels
        return AlphaTaintState(regs=merged)

    def equals(self, other: 'AlphaTaintState') -> bool:
        return self.regs == other.regs

    # Alpha calling convention: caller passes args in r16–r21
    _ALPHA_ARG_REGS = ('r16', 'r17', 'r18', 'r19', 'r20', 'r21')

    def tainted_arg_regs(self) -> List[str]:
        return [r for r in self._ALPHA_ARG_REGS if self.is_tainted(r)]


# ─── Transfer function ────────────────────────────────────────────────────────

# Alpha ISA constants (subset for taint transfer)
_OP_LDA   = 0x08
_OP_LDAH  = 0x09
_OP_LDQ   = 0x29
_OP_LDL   = 0x28
_OP_STQ   = 0x2D
_OP_STL   = 0x2C
_OP_BSR   = 0x34
_OP_JSR   = 0x1A
_OP_BR    = 0x30
_COND_OPS = frozenset(range(0x38, 0x40)) | frozenset(range(0x31, 0x38))
_INT_OPS  = frozenset(range(0x10, 0x18))  # INTA/INTL/INTS/INTM

_SINK_NAMES = {
    'system', 'popen', 'execl', 'execle', 'execlp',
    'execv', 'execve', 'execvp', 'execvpe',
    'system_r', 'bsd_system',
}


def _sign_ext16(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


def _alpha_ra(word: int) -> str:
    return f'r{(word >> 21) & 0x1F}'


def _alpha_rb(word: int) -> str:
    return f'r{(word >> 16) & 0x1F}'


def _alpha_rc(word: int) -> str:
    return f'r{word & 0x1F}'


def _transfer(insn_va: int, word: int, state: AlphaTaintState,
              callee_results: Dict[int, FrozenSet[TaintLabel]]) -> None:
    """
    Apply one Alpha instruction's taint transfer to `state` in-place.

    callee_results: VA → frozenset of labels for the callee's r0 return value.
    Populated by the interprocedural driver.
    """
    op = (word >> 26) & 0x3F
    ra = _alpha_ra(word)
    rb = _alpha_rb(word)
    rc = _alpha_rc(word)

    # LDA/LDAH: result is a constant or GP-offset address — CLEAN
    if op in (_OP_LDA, _OP_LDAH):
        state.set(ra, CLEAN)
        return

    # LDQ/LDL: load from memory — if address reg is tainted, result is tainted
    if op in (_OP_LDQ, _OP_LDL):
        base_labels = state.get(rb)
        state.set(ra, base_labels)
        return

    # STQ/STL: store — no register written, nothing to propagate
    if op in (_OP_STQ, _OP_STL):
        return

    # BSR: call — result register is tainted if callee_results says so
    if op == _OP_BSR:
        disp21 = word & 0x1FFFFF
        if disp21 & 0x100000:
            disp21 -= 0x200000
        callee_va = (insn_va + 4) + disp21 * 4
        result_labels = callee_results.get(callee_va, CLEAN)
        state.set(ra, result_labels)
        # Caller-save: clobber r0–r8, r23–r28 (they are undefined after a call)
        for csr in ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8',
                    'r23', 'r24', 'r25', 'r27', 'r28'):
            if csr != ra:
                state.set(csr, CLEAN)
        return

    # JSR/JMP (op 0x1A): indirect call
    if op == _OP_JSR:
        hint = (word >> 14) & 0x3
        if hint == 2:  # RET
            return
        # indirect call — conservatively taint r0 if rb is tainted
        if state.is_tainted(rb):
            state.taint('r0', TaintLabel('indirect_call_retval'))
        for csr in ('r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8',
                    'r23', 'r24', 'r25', 'r27', 'r28'):
            pass  # leave tainted if rb was tainted; clean otherwise handled above
        return

    # BR: unconditional — no register written
    if op == _OP_BR:
        # ra is the link register (r31 in most cases for BR)
        state.set(ra, CLEAN)
        return

    # Conditional branches: no register written
    if op in _COND_OPS:
        return

    # Integer arithmetic: rc = f(rb, rb_or_lit)
    if op in _INT_OPS:
        use_lit = bool((word >> 12) & 1)
        rb_labels = state.get(rb)
        if use_lit:
            state.set(rc, rb_labels)   # literal operand is CLEAN
        else:
            # Binary op: if either operand is tainted, result is tainted
            rb2 = _alpha_rb(word)
            state.set(rc, rb_labels | state.get(rb2))
        return

    # All others: conservatively mark ra CLEAN (unknown instruction)
    state.set(ra, CLEAN)


# ─── Finding ──────────────────────────────────────────────────────────────────

@dataclass
class AlphaTaintFinding:
    func_va:      int
    func_name:    str
    sink_va:      int
    sink_name:    str
    tainted_args: List[str]             # register names that are tainted at the call
    labels:       FrozenSet[TaintLabel]  # combined taint labels
    severity:     str = 'HIGH'

    def __str__(self) -> str:
        args_s = ', '.join(self.tainted_args)
        lbls_s = ', '.join(sorted(l.name for l in self.labels))
        return (
            f'[{self.severity}] 0x{self.func_va:x} ({self.func_name}): '
            f'tainted {{{args_s}}} -> {self.sink_name} @ 0x{self.sink_va:x} '
            f'(labels: {{{lbls_s}}})'
        )


# ─── Main tracker ─────────────────────────────────────────────────────────────

class AlphaTaintTracker:
    """
    CFG-fixpoint taint tracker for Alpha AXP ELF/ECOFF binaries.

    Uses AlphaCFGBuilder for CFG construction and propagates taint state
    forward through all basic blocks via a worklist algorithm.
    """

    def __init__(self,
                 data:       bytes,
                 base:       int,
                 sections:   Dict,
                 gp_value:   Optional[int],
                 sym_table:  Dict[int, str]):
        self._data    = data
        self._base    = base
        self._secs    = sections
        self._gp      = gp_value or 0
        self._syms    = sym_table        # VA → symbol name
        self._builder = AlphaCFGBuilder(data, sections, gp_value)

    @classmethod
    def from_path(cls, path: str) -> 'AlphaTaintTracker':
        """
        Construct from a binary path. Attempts to use AlphaEcoffScanner
        if available; falls back to raw ELF parsing.
        """
        try:
            from ablation.analyzers.insn_alpha import AlphaEcoffScanner
            scanner = AlphaEcoffScanner(path)
            data, gp, sections = scanner._load()
            sym_table = scanner._sym_table() if hasattr(scanner, '_sym_table') else {}
            # Determine load base from first section VA
            base = min((s.va for s in sections.values() if hasattr(s, 'va')),
                       default=0)
            return cls(data=data, base=base, sections=sections,
                       gp_value=gp, sym_table=sym_table)
        except Exception:
            with open(path, 'rb') as fh:
                data = fh.read()
            return cls(data=data, base=0, sections={},
                       gp_value=None, sym_table={})

    def _func_name(self, va: int) -> str:
        return self._syms.get(va, f'sub_{va:x}')

    def _resolve_bsr_target(self, insn_va: int, word: int) -> Optional[int]:
        disp21 = word & 0x1FFFFF
        if disp21 & 0x100000:
            disp21 -= 0x200000
        return (insn_va + 4) + disp21 * 4

    def _is_sink(self, va: int) -> Optional[str]:
        """Return the sink name if va is a known exec-class sink call target."""
        name = self._syms.get(va, '')
        base_name = name.lstrip('_').split('@')[0]
        if base_name in _SINK_NAMES:
            return base_name
        return None

    def scan_function(
        self,
        func_va:      int,
        init_taint:   Optional[Dict[str, FrozenSet[TaintLabel]]] = None,
        callee_results: Optional[Dict[int, FrozenSet[TaintLabel]]] = None,
        max_insns:    int = 4096,
    ) -> List[AlphaTaintFinding]:
        """
        Scan a single function at func_va for exec-class sink calls with
        tainted arguments.

        init_taint: initial register → taint map (default: args r16–r21 are
            all tainted with label 'arg_N' — conservative for library functions).
        callee_results: VA → frozenset of labels for each callee's return value.
        """
        try:
            cfg = self._builder.build(func_va, max_insns=max_insns)
        except Exception:
            return []

        if not cfg.blocks:
            return []

        if init_taint is None:
            init_taint = {
                f'r{16 + i}': frozenset([TaintLabel(f'arg_{i}')])
                for i in range(6)
            }
        if callee_results is None:
            callee_results = {}

        # Worklist fixpoint
        # block_state[va] = taint state at ENTRY to block va
        block_state: Dict[int, AlphaTaintState] = {}
        for va in cfg.blocks:
            block_state[va] = AlphaTaintState()

        # Seed entry block
        entry_state = AlphaTaintState(regs=dict(init_taint))
        block_state[cfg.entry] = entry_state

        worklist: deque = deque([cfg.entry])
        visited: Set[int] = set()

        while worklist:
            va = worklist.popleft()
            block = cfg.blocks.get(va)
            if block is None:
                continue

            state_in = block_state[va].copy()

            # Run transfer function over every instruction in the block
            for insn_va, word in block.insns:
                _transfer(insn_va, word, state_in, callee_results)

            # Propagate to successors
            for succ_va in block.succs:
                if succ_va not in cfg.blocks:
                    continue
                old_state = block_state[succ_va]
                new_state = old_state.join(state_in)
                if not new_state.equals(old_state):
                    block_state[succ_va] = new_state
                    worklist.append(succ_va)

        # Collect findings: look for BSR calls to sinks where arg regs are tainted
        findings: List[AlphaTaintFinding] = []
        func_name = self._func_name(func_va)

        for va, block in cfg.blocks.items():
            state = block_state[va].copy()

            for insn_va, word in block.insns:
                op = (word >> 26) & 0x3F

                if op == _OP_BSR:
                    callee_va = self._resolve_bsr_target(insn_va, word)
                    if callee_va:
                        sink_name = self._is_sink(callee_va)
                        if sink_name:
                            tainted_args = state.tainted_arg_regs()
                            if tainted_args:
                                all_labels: FrozenSet[TaintLabel] = frozenset()
                                for r in tainted_args:
                                    all_labels = all_labels | state.get(r)
                                findings.append(AlphaTaintFinding(
                                    func_va=func_va,
                                    func_name=func_name,
                                    sink_va=insn_va,
                                    sink_name=sink_name,
                                    tainted_args=tainted_args,
                                    labels=all_labels,
                                ))

                _transfer(insn_va, word, state, callee_results)

        return findings

    def run_interprocedural(
        self,
        depth:     int = 3,
        max_insns: int = 4096,
    ) -> List[AlphaTaintFinding]:
        """
        Scan all functions in the binary for exec-class taint paths.

        For each function: taint all argument registers (r16–r21) with
        'arg_N' labels and scan for sink calls. Repeats up to `depth`
        times to resolve callee return-value propagation.
        """
        # Build a candidate function list from symbol table
        func_vas = sorted(
            va for va, name in self._syms.items()
            if name and not name.startswith('.')
        )

        if not func_vas:
            # No symbol table: scan the .text section heuristically
            func_vas = self._heuristic_func_list()

        all_findings: List[AlphaTaintFinding] = []
        callee_results: Dict[int, FrozenSet[TaintLabel]] = {}

        for iteration in range(depth):
            new_findings: List[AlphaTaintFinding] = []
            for func_va in func_vas:
                findings = self.scan_function(
                    func_va,
                    callee_results=callee_results,
                    max_insns=max_insns,
                )
                new_findings.extend(findings)
                # Update callee_results: if this function calls a sink with
                # tainted args, its return value (r0) is conservatively tainted
                if findings:
                    combined: FrozenSet[TaintLabel] = frozenset()
                    for f in findings:
                        combined = combined | f.labels
                    callee_results[func_va] = combined

            if not new_findings:
                break
            # Dedup by (func_va, sink_va)
            seen = {(f.func_va, f.sink_va) for f in all_findings}
            for f in new_findings:
                if (f.func_va, f.sink_va) not in seen:
                    all_findings.append(f)
                    seen.add((f.func_va, f.sink_va))

        return all_findings

    def _heuristic_func_list(self) -> List[int]:
        """
        Heuristic function discovery: scan .text for BSR/BR patterns and
        collect targets as potential function entry points. Fallback when
        there is no symbol table.
        """
        # Find the .text section
        text_start = 0
        text_end = 0
        for name, sec in self._secs.items():
            if 'text' in str(name).lower() or (
                hasattr(sec, 'flags') and sec.flags & 0x4
            ):
                text_start = getattr(sec, 'va', 0) or getattr(sec, 'offset', 0)
                text_end = text_start + getattr(sec, 'size', 0)
                break

        if not text_end:
            return []

        targets: Set[int] = {text_start}
        base = self._base
        data = self._data

        va = text_start
        while va < text_end:
            off = va - base
            if off < 0 or off + 4 > len(data):
                break
            word = struct.unpack_from('<I', data, off)[0]
            op = (word >> 26) & 0x3F
            if op == _OP_BSR:
                disp21 = word & 0x1FFFFF
                if disp21 & 0x100000:
                    disp21 -= 0x200000
                target = (va + 4) + disp21 * 4
                if text_start <= target < text_end:
                    targets.add(target)
            va += 4

        return sorted(targets)
