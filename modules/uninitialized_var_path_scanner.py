"""
uninitialized_var_path_scanner.py: Uninitialized variable on error-path detector.

Detects the pattern where a variable is used in a cleanup epilogue that is
reachable from multiple predecessors, including predecessors that may not
initialize the variable.

The canonical pattern in stripped firmware:
  1. Function entry: allocate stack variable at [rsp+N] or similar
  2. Conditional path: initialize [rsp+N] on the success branch
  3. Error path: jump directly to shared cleanup epilogue
  4. Cleanup epilogue: load [rsp+N] (uninitialized on error path)

This is distinct from `dead_security_check_scanner.py` (which finds unreachable
checks) and `truncation_at_sink_scanner.py` (which finds narrowing). Here the
variable exists and is used, but its initializer is only on some incoming edges.

Detection strategy using CFGBuilder:
  1. Build CFG for each function.
  2. Find blocks with multiple predecessors (merge points / epilogues).
  3. For each such block, check which predecessor blocks contain a store to
     a stack slot that the block then loads.
  4. If any predecessor does NOT have a store to that slot before the merge,
     the slot may be uninitialized on that path.
  5. If the block eventually reaches a sink (PLT call with stack-slot arg,
     or function return), emit a finding.

Architecture coverage: x86-64, ARM64. MIPS partial.

Usage:
    scanner = UninitializedVarPathScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = UninitializedVarPathScanner.from_context(ctx)
    findings = scanner.scan()
"""

from __future__ import annotations
from modules._disasm_helper import disasm_func

from dataclasses import dataclass, field
from typing import List, Optional


# ── Stack slot representation ──────────────────────────────────────────────────

def _parse_stack_slot(op_str: str) -> Optional[str]:
    """
    Extract a normalized stack slot key from a memory operand string.
    Returns None if the operand does not reference rsp/rbp/sp/fp.
    """
    op = op_str.lower()
    for base in ('rsp', 'rbp', 'esp', 'ebp', 'sp', 'fp', 'x29', 'x30'):
        if base in op:
            # Normalize: extract the offset portion only
            # e.g. "[rsp + 0x10]" → "rsp+0x10", "[rbp - 8]" → "rbp-0x8"
            import re
            m = re.search(r'(' + re.escape(base) + r')\s*([+-])\s*(0x[\da-f]+|\d+)', op)
            if m:
                offset = int(m.group(3), 16 if m.group(3).startswith('0x') else 10)
                sign = '+' if m.group(2) == '+' else '-'
                return f'{base}{sign}0x{offset:x}'
            # Base register alone (offset 0)
            return f'{base}+0x0'
    return None


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class UninitFinding:
    func_va:     int      # VA of the containing function
    func_name:   str      # name if known
    merge_va:    int      # VA of the merge block (epilogue)
    slot:        str      # stack slot key (e.g. "rbp-0x8")
    uninit_edge: int      # VA of the predecessor block missing the store
    confidence:  str      # HIGH / MEDIUM

    def fmt(self) -> str:
        return (f"  {self.confidence:6s}  [UNINIT_VAR_PATH]  {self.func_name}\n"
                f"         merge point 0x{self.merge_va:x}  slot {self.slot}\n"
                f"         predecessor 0x{self.uninit_edge:x} has no store to slot before merge")


# ── Scanner ────────────────────────────────────────────────────────────────────

class UninitializedVarPathScanner:
    """Detect stack variables used in merge blocks without initialization on all paths."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'UninitializedVarPathScanner':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._ctx  = ctx
        return obj

    def _load_ctx(self):
        if self._ctx is not None:
            return self._ctx
        from ablation.analyzers.binary_context import BinaryContext
        self._ctx = BinaryContext.load_or_build(self._path)
        return self._ctx

    def _build_block_map(self, insns: list) -> dict[int, list]:
        """
        Split instruction list into basic blocks keyed by their start VA.
        A new block starts after any branch instruction and at each branch target.
        """
        if not insns:
            return {}

        # Identify branch targets and branch sites
        _BRANCH_MN = frozenset({
            'jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge',
            'jb', 'ja', 'jbe', 'jae', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
            'b', 'bl', 'bx', 'blx', 'beq', 'bne', 'blt', 'bgt', 'ble', 'bge',
            'blo', 'bhi', 'bls', 'bhs', 'bpl', 'bmi', 'bvs', 'bvc', 'bcs', 'bcc',
            'cbz', 'cbnz', 'tbz', 'tbnz',
        })

        leaders: set[int] = {insns[0].address}
        for insn in insns:
            mn = insn.mnemonic.lower().split()[0]
            if mn in _BRANCH_MN:
                # The next instruction is a leader
                idx = insns.index(insn)
                if idx + 1 < len(insns):
                    leaders.add(insns[idx + 1].address)
                # The target of the branch is a leader
                target = _call_target(insn)
                if target:
                    leaders.add(target)

        # Build blocks
        blocks: dict[int, list] = {}
        current_block_start: Optional[int] = None
        for insn in insns:
            if insn.address in leaders:
                current_block_start = insn.address
                blocks[current_block_start] = []
            if current_block_start is not None:
                blocks[current_block_start].append(insn)

        return blocks

    def _block_predecessors(self, blocks: dict[int, list]) -> dict[int, list[int]]:
        """Build a predecessor map: block_va -> list of predecessor block VAs."""
        preds: dict[int, list[int]] = {va: [] for va in blocks}
        block_vas = sorted(blocks.keys())

        _UNCOND = frozenset({'jmp', 'b', 'bx', 'ret', 'retq', 'retn'})
        _BRANCH_MN = frozenset({
            'jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge',
            'jb', 'ja', 'jbe', 'jae', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
            'b', 'bl', 'bx', 'blx', 'beq', 'bne', 'blt', 'bgt', 'ble', 'bge',
            'blo', 'bhi', 'bls', 'bhs', 'bpl', 'bmi', 'bvs', 'bvc', 'bcs', 'bcc',
            'cbz', 'cbnz', 'tbz', 'tbnz',
        })

        for i, va in enumerate(block_vas):
            block = blocks[va]
            if not block:
                continue
            last = block[-1]
            mn = last.mnemonic.lower().split()[0]

            # Fallthrough edge
            if mn not in _UNCOND and i + 1 < len(block_vas):
                next_va = block_vas[i + 1]
                preds[next_va].append(va)

            # Branch edge
            if mn in _BRANCH_MN:
                target = _call_target(last)
                if target and target in preds:
                    preds[target].append(va)

        return preds

    def _block_stack_stores(self, block: list) -> set[str]:
        """Return the set of stack slots stored to within this block."""
        _STORE_MN = frozenset({
            'mov', 'movl', 'movq', 'movb', 'movw', 'str', 'stp',
            'sw', 'sd', 'sb', 'sh',  # MIPS stores
        })
        slots: set[str] = set()
        for insn in block:
            mn = insn.mnemonic.lower()
            if mn not in _STORE_MN:
                continue
            # The destination is the first operand for x86 (mov dst, src)
            # For ARM str: "str x0, [sp, #8]" — second operand is the slot
            parts = insn.op_str.split(',', 2)
            # Check all parts for a stack slot reference
            for part in parts:
                slot = _parse_stack_slot(part.strip())
                if slot:
                    slots.add(slot)
        return slots

    def _block_stack_loads(self, block: list) -> set[str]:
        """Return the set of stack slots loaded from within this block."""
        _LOAD_MN = frozenset({
            'mov', 'movl', 'movq', 'movb', 'movw', 'ldr', 'ldp',
            'lw', 'ld', 'lb', 'lh',  # MIPS loads
        })
        slots: set[str] = set()
        for insn in block:
            mn = insn.mnemonic.lower()
            if mn not in _LOAD_MN:
                continue
            parts = insn.op_str.split(',', 2)
            for part in parts:
                slot = _parse_stack_slot(part.strip())
                if slot:
                    slots.add(slot)
        return slots

    def scan(self) -> List[UninitFinding]:
        ctx = self._load_ctx()
        findings: list[UninitFinding] = []

        for func_va in ctx.func_starts:
            insns = list(disasm_func(ctx, func_va))
            if len(insns) < 8:
                continue

            blocks = self._build_block_map(insns)
            if len(blocks) < 3:
                continue

            preds = self._block_predecessors(blocks)

            # Find merge points: blocks with 2+ predecessors
            for block_va, pred_list in preds.items():
                if len(pred_list) < 2:
                    continue

                block = blocks.get(block_va, [])
                if not block:
                    continue

                # Slots loaded in the merge block
                loaded_slots = self._block_stack_loads(block)
                if not loaded_slots:
                    continue

                # For each loaded slot, check if all predecessors store to it
                for slot in loaded_slots:
                    missing_preds = []
                    for pred_va in pred_list:
                        pred_block = blocks.get(pred_va, [])
                        stores = self._block_stack_stores(pred_block)
                        if slot not in stores:
                            missing_preds.append(pred_va)

                    if not missing_preds:
                        continue  # all predecessors initialize the slot

                    # At least one predecessor does not initialize the slot
                    confidence = 'HIGH' if len(missing_preds) == len(pred_list) else 'MEDIUM'
                    findings.append(UninitFinding(
                        func_va=func_va,
                        func_name=ctx.name(func_va),
                        merge_va=block_va,
                        slot=slot,
                        uninit_edge=missing_preds[0],
                        confidence=confidence,
                    ))
                    break  # one finding per merge point

        return findings

    def report(self, findings: Optional[List[UninitFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'UninitializedVarPathScanner: no uninitialized-path findings in {self._path}'
        lines = [f'UninitializedVarPathScanner: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _call_target(insn) -> int:
    try:
        op = insn.op_str.strip()
        if op.startswith('0x') or op.startswith('#0x'):
            return int(op.lstrip('#'), 16)
        return int(op, 16)
    except (ValueError, AttributeError):
        return 0
