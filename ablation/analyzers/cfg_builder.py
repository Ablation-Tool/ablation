"""
cfg_builder.py -- Per-function control flow graph for x86-64 ELF binaries.

Implements the iterative recursive disassembly approach from:
  Andriesse, "Practical Binary Analysis" (No Starch), ch. 8.2.4.

Algorithm:
  1. For each function: start queue with function entry VA.
  2. cs_disasm_iter from each queue entry; follow direct branches.
  3. Stop basic block at: ret, jmp (unconditional), hlt.
  4. Stop basic block at: conditional branch (push both fall-through + target).
  5. Stop basic block at: call (push fall-through; don't follow cross-function).
  6. Result: dict of basic_block_va -> BasicBlock.

BasicBlock:
  start: int  -- first instruction VA
  end:   int  -- last instruction VA (inclusive)
  succs: List[int]  -- successor VAs (branch targets + fall-through)
  insns: List[(va, mnemonic, op_str)]

CFG:
  func_va: int
  blocks:  Dict[int, BasicBlock]  -- keyed by block start VA
  entry:   int  -- == func_va

Usage:
    from ablation.analyzers.cfg_builder import CFGBuilder

    xg = XRefGraph.from_path(binary)
    xg.build()

    builder = CFGBuilder(binary, xref=xg)
    cfg = builder.build_function(func_va)
    for bb_va, bb in cfg.blocks.items():
        print(f"  BB {bb_va:#x}: {len(bb.insns)} insns -> {[hex(s) for s in bb.succs]}")
"""

from __future__ import annotations

import bisect
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone
from capstone.x86_const import (
    X86_INS_CALL, X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ, X86_INS_HLT,
    X86_INS_JMP, X86_INS_LJMP,
    X86_OP_IMM,
)
import lief

# ── Capstone group IDs ────────────────────────────────────────────────────────
_GRP_JUMP = 1    # CS_GRP_JUMP
_GRP_CALL = 2    # CS_GRP_CALL
_GRP_RET  = 3    # CS_GRP_RET
_GRP_IRET = 4    # CS_GRP_IRET

_UNCONDITIONAL_JUMPS = frozenset([X86_INS_JMP, X86_INS_LJMP])
_RET_INSNS = frozenset([X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ])

MAX_FUNC_BYTES = 8192   # hard cap per function


# ── data structures ───────────────────────────────────────────────────────────

@dataclass
class BasicBlock:
    start: int
    end: int = 0         # VA of last instruction (inclusive)
    succs: List[int] = field(default_factory=list)
    insns: List[Tuple[int, str, str]] = field(default_factory=list)  # (va, mnem, op_str)

    def __repr__(self) -> str:
        return (f"BB({self.start:#x}..{self.end:#x}, "
                f"insns={len(self.insns)}, succs={[hex(s) for s in self.succs]})")


@dataclass
class CFG:
    func_va: int
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)

    @property
    def entry(self) -> int:
        return self.func_va

    def dominator_tree(self) -> Dict[int, int]:
        """Simple dominators via Cooper et al. postorder (used for loop detection)."""
        # Topological sort via BFS from entry
        order: List[int] = []
        visited: Set[int] = set()
        q: deque = deque([self.func_va])
        while q:
            va = q.popleft()
            if va in visited or va not in self.blocks:
                continue
            visited.add(va)
            order.append(va)
            for succ in self.blocks[va].succs:
                q.append(succ)

        # Simple immediate dominator (single-pass approximation)
        doms: Dict[int, Optional[int]] = {va: None for va in order}
        doms[self.func_va] = self.func_va
        changed = True
        while changed:
            changed = False
            for va in order:
                if va == self.func_va:
                    continue
                preds = [b.start for b in self.blocks.values() if va in b.succs]
                if not preds:
                    continue
                # new_idom = first pred with idom set
                new_idom = None
                for p in preds:
                    if doms.get(p) is not None:
                        new_idom = p
                        break
                if new_idom is None:
                    continue
                for p in preds:
                    if p == new_idom or doms.get(p) is None:
                        continue
                    # Intersect: walk up dominator tree
                    b1, b2 = order.index(new_idom), order.index(p)
                    while b1 != b2:
                        while b1 > b2:
                            new_idom = doms[new_idom]
                            b1 = order.index(new_idom)
                        while b2 > b1:
                            p = doms[p]
                            b2 = order.index(p)
                    new_idom = order[b1]
                if doms.get(va) != new_idom:
                    doms[va] = new_idom
                    changed = True
        return {va: idom for va, idom in doms.items() if idom is not None}

    def reaching_defs(self) -> None:
        """Placeholder: flow-sensitive reaching definitions over CFG."""
        raise NotImplementedError("Use DataflowEngine for reaching definitions analysis")

    def stats(self) -> dict:
        n_edges = sum(len(b.succs) for b in self.blocks.values())
        n_insns = sum(len(b.insns) for b in self.blocks.values())
        return {"blocks": len(self.blocks), "edges": n_edges, "instructions": n_insns}


# ── builder ───────────────────────────────────────────────────────────────────

class CFGBuilder:
    """Build per-function CFGs for a stripped x86-64 ELF binary."""

    def __init__(self, binary_path: str, xref=None):
        self.path = binary_path
        self.data = Path(binary_path).read_bytes()
        self.xref = xref

        # LIEF for VA->offset mapping
        try:
            self._lief = lief.parse(binary_path)
        except Exception:
            self._lief = None

        self._sections: List[Tuple[int, int, int]] = []  # (vaddr, size, file_offset)
        if self._lief:
            try:
                for sect in self._lief.sections:
                    va = sect.virtual_address
                    sz = int(sect.size)
                    off = int(sect.offset)
                    if sz > 0 and va > 0:
                        self._sections.append((va, sz, off))
            except Exception:
                pass

        # Sort sections by VA for binary search
        self._sections.sort()
        self._sect_vas = [s[0] for s in self._sections]

        # Capstone with detail mode
        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._md.detail = True

        # PLT map from xref
        self._plt: Dict[int, str] = {}
        if xref is not None:
            self._plt = dict(xref._plt)

        # Function boundaries from xref (for limiting analysis scope)
        self._func_starts: List[int] = sorted(xref._func_starts) if xref else []

    def _va_to_offset(self, va: int) -> Optional[int]:
        """Map virtual address to file offset."""
        idx = bisect.bisect_right(self._sect_vas, va) - 1
        if idx < 0:
            return None
        svaddr, ssz, soff = self._sections[idx]
        rel = va - svaddr
        if 0 <= rel < ssz:
            return soff + rel
        return None

    def _read_at(self, va: int, size: int) -> Optional[bytes]:
        """Read up to `size` bytes from virtual address `va`."""
        off = self._va_to_offset(va)
        if off is None:
            return None
        return self.data[off: off + size]

    def _func_end_va(self, func_va: int) -> int:
        """Estimate function end VA from next function start."""
        if not self._func_starts:
            return func_va + MAX_FUNC_BYTES
        idx = bisect.bisect_right(self._func_starts, func_va)
        if idx < len(self._func_starts):
            return min(self._func_starts[idx], func_va + MAX_FUNC_BYTES)
        return func_va + MAX_FUNC_BYTES

    def build_function(self, func_va: int, end_va: int = 0) -> CFG:
        """
        Build CFG for one function using iterative recursive disassembly.

        func_va: function entry VA
        end_va:  optional explicit end (default: next function start or +8KB)
        """
        if not end_va:
            end_va = self._func_end_va(func_va)

        cfg = CFG(func_va=func_va)
        visited_starts: Set[int] = set()
        queue: deque = deque([func_va])

        while queue:
            bb_start = queue.popleft()

            if bb_start in visited_starts:
                continue
            if bb_start < func_va or bb_start >= end_va:
                continue  # outside function bounds

            visited_starts.add(bb_start)
            block = BasicBlock(start=bb_start)

            # Read bytes from this address
            size = min(end_va - bb_start, MAX_FUNC_BYTES)
            chunk = self._read_at(bb_start, size)
            if not chunk:
                continue

            prev_va = bb_start
            pc = chunk
            addr = bb_start
            n = len(chunk)

            # Disassemble iteratively via Python capstone
            # cs_disasm_iter equivalent in Python: iterate md.disasm
            # Python capstone doesn't expose cs_disasm_iter directly; use disasm with count limit
            for insn in self._md.disasm(chunk, bb_start):
                va = insn.address
                if va >= end_va:
                    break

                # Block splitting: if we reach a known block boundary that is not
                # our own start, link to it and stop -- avoids overlapping blocks
                # that cause empty-succs bugs in the MFP taint propagation.
                if va != bb_start and va in cfg.blocks:
                    block.succs.append(va)
                    break

                mnem = insn.mnemonic
                op_str = insn.op_str
                block.insns.append((va, mnem, op_str))
                block.end = va

                # Check if this is a control flow instruction
                is_cflow = any(g in (_GRP_JUMP, _GRP_CALL, _GRP_RET, _GRP_IRET)
                               for g in (insn.groups or []))
                next_va = va + insn.size

                if insn.id in _RET_INSNS or insn.id == X86_INS_HLT:
                    # End of basic block; no successors
                    break

                if insn.id == X86_INS_CALL:
                    # Call: fall-through is always a successor edge regardless of
                    # whether it was already visited; only queue if not yet built.
                    if next_va < end_va:
                        if next_va not in block.succs:
                            block.succs.append(next_va)
                        if next_va not in visited_starts:
                            queue.append(next_va)
                    # Also push target if in-function (unusual: local label / tail call)
                    target = _get_imm_target(insn)
                    if target and func_va <= target < end_va:
                        if target not in visited_starts:
                            queue.append(target)
                    break  # end of basic block after call (resume at fall-through)

                if is_cflow:
                    target = _get_imm_target(insn)
                    unconditional = insn.id in _UNCONDITIONAL_JUMPS

                    if target and func_va <= target < end_va:
                        block.succs.append(target)
                        if target not in visited_starts:
                            queue.append(target)

                    if not unconditional:
                        # Conditional: fall-through also reachable
                        if next_va < end_va:
                            block.succs.append(next_va)
                            if next_va not in visited_starts:
                                queue.append(next_va)
                    break  # end of basic block

            cfg.blocks[bb_start] = block

            # If block ended without explicit control flow (data? end of section?)
            # push fall-through anyway if block has instructions
            if block.insns and not block.succs:
                last_va, last_mnem, _ = block.insns[-1]
                last_insn_end = last_va  # we don't store size; approximate
                # No successors for terminal blocks

        return cfg

    def build_all(self) -> Dict[int, CFG]:
        """Build CFGs for all functions known via XRefGraph."""
        results: Dict[int, CFG] = {}
        for fva in self._func_starts:
            try:
                results[fva] = self.build_function(fva)
            except Exception:
                continue
        return results


def _get_imm_target(insn) -> Optional[int]:
    """Extract immediate control flow target from a capstone instruction."""
    for op in insn.operands:
        if op.type == X86_OP_IMM:
            return op.imm
    return None


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli():
    import argparse, sys
    ap = argparse.ArgumentParser(description="Build x86-64 per-function CFG")
    ap.add_argument("binary", help="Stripped ELF binary")
    ap.add_argument("--func", help="Build CFG for one function at VA (hex)")
    ap.add_argument("--dot", help="Write DOT format to file")
    ap.add_argument("--use-xref", action="store_true", help="Use XRefGraph for function detection")
    args = ap.parse_args()

    xref = None
    if args.use_xref:
        from ablation.analyzers.xref_graph import XRefGraph
        print(f"[*] Building XRefGraph ...")
        xref = XRefGraph.from_path(args.binary)
        xref.build()
        xs = xref.stats()
        print(f"[*] XRef: {xs['functions']} functions, {xs['plt_entries']} PLT")

    builder = CFGBuilder(args.binary, xref=xref)

    if args.func:
        va = int(args.func, 16)
        cfg = builder.build_function(va)
        s = cfg.stats()
        print(f"CFG for {va:#x}: {s['blocks']} blocks, {s['edges']} edges, {s['instructions']} instructions")
        for bb_va in sorted(cfg.blocks):
            bb = cfg.blocks[bb_va]
            print(f"  BB {bb_va:#x}: {len(bb.insns)} insns -> {[hex(s) for s in bb.succs]}")
        if args.dot:
            _write_dot(cfg, args.dot)
    else:
        all_cfgs = builder.build_all()
        total_blocks = sum(len(c.blocks) for c in all_cfgs.values())
        total_edges = sum(c.stats()["edges"] for c in all_cfgs.values())
        print(f"Built CFGs for {len(all_cfgs)} functions: {total_blocks} blocks, {total_edges} edges")


def _write_dot(cfg: CFG, path: str):
    with open(path, "w") as f:
        f.write(f'digraph cfg_{cfg.func_va:#x} {{\n')
        f.write('  node [shape=box fontname=monospace];\n')
        for va, bb in sorted(cfg.blocks.items()):
            label = f"{va:#x}\\n" + "\\n".join(
                f"{v:#x}: {m} {o}" for v, m, o in bb.insns[:8]
            )
            if len(bb.insns) > 8:
                label += f"\\n... +{len(bb.insns)-8} more"
            label = label.replace('"', '\\"')
            f.write(f'  "{va:#x}" [label="{label}"];\n')
        for va, bb in sorted(cfg.blocks.items()):
            for succ in bb.succs:
                f.write(f'  "{va:#x}" -> "{succ:#x}";\n')
        f.write("}\n")
    print(f"[*] DOT written to {path}")


if __name__ == "__main__":
    _cli()
