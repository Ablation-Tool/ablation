"""
ssa.py — Arch-agnostic SSA construction over dataflow_engine CFG + DomTree.

Implements Cytron, Ferrante, Rosen, Wegman, Zadeck 1991:
  "Efficiently Computing Static Single Assignment Form and the
   Control Dependence Graph" (ACM TOPLAS 13(4)).

Three phases:
  1. Dominance frontiers — from DomTree.dom_frontier() (already in dataflow_engine)
  2. Phi insertion      — insert phi nodes at every DF+(def site) per variable
  3. Renaming          — DFS over dominator tree; push/pop version stacks

Works with any CFG whose BasicBlock.insns elements are accepted by
ArchConfig.dest_reg(). Supports both Capstone CsInsn (ARM32/ARM64/x86-64)
and RawInsn (AlphaAXPConfig) instruction types.

Why this exists:
  trace_arg() and SinkArgClassifier do a linear backward scan within a window.
  They stop at BSR_RETVAL when the register was set by a prior call, and at
  basic block boundaries when the assignment is in a different block. SSA
  gives a correct answer in both cases: the reaching definition of a register
  at any use site, regardless of branching structure or call depth.

Usage:
    from ablation.analyzers.dataflow_engine import CFGBuilder, DomTree, make_arch
    from ablation.analyzers.ssa import SSABuilder

    arch = make_arch('alpha')
    cfg  = CFGBuilder(arch, data, base).build(func_va)
    ssa  = SSABuilder(cfg, arch).build()

    # What SSA name does r0 have at the RET instruction?
    name = ssa.reaching_def('r0', ret_va)
    print(name)         # e.g. SSAName(reg='r0', ver=3)

    # Where is r0_3 defined?
    defs = ssa.defs_of(name)   # [va_of_defining_insn, ...]

    # All uses of r0_3?
    uses = ssa.uses_of(name)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from ablation.analyzers.dataflow_engine import ArchConfig, BasicBlock, CFG, DomTree


# ─── Public data structures ───────────────────────────────────────────────────

@dataclass(frozen=True)
class SSAName:
    """An SSA variable name: a (register, version) pair."""
    reg: str
    ver: int

    def __str__(self) -> str:
        return f'{self.reg}_{self.ver}'


@dataclass
class PhiNode:
    """Phi function inserted at the entry of a basic block."""
    result: SSAName                      # the SSA name this phi defines
    args:   Dict[int, SSAName]           # predecessor block VA → incoming SSA name
    block_va: int


@dataclass
class SSAForm:
    """
    Complete SSA form for a single function.

    Attributes:
        cfg         Original CFG.
        dom         Dominator tree used for construction.
        phis        Phi nodes keyed by block VA (empty if no phi in that block).
        defs_map    Maps (block_va, insn_index) → SSAName defined at that point.
        use_map     Maps (block_va, insn_index) → dict of operand reg → SSAName.
        reaching    Maps (block_va, insn_index) → dict of reg → SSAName.
                    This is the full register state at ENTRY to each instruction.
    """
    cfg:      CFG
    dom:      DomTree
    phis:     Dict[int, List[PhiNode]]              # block_va → phi list
    defs_map: Dict[Tuple[int, int], SSAName]        # (block_va, insn_idx) → def
    use_map:  Dict[Tuple[int, int], Dict[str, SSAName]]  # (bva, idx) → {reg→name}
    reaching: Dict[Tuple[int, int], Dict[str, SSAName]]  # entry state per insn

    def reaching_def(self, reg: str, use_va: int) -> Optional[SSAName]:
        """
        Return the SSA name of `reg` at the point just before the instruction
        at `use_va`. Returns None if `use_va` is not in the CFG.
        """
        for block_va, block in self.cfg.blocks.items():
            for idx, insn in enumerate(block.insns):
                if insn.address == use_va:
                    state = self.reaching.get((block_va, idx), {})
                    return state.get(reg)
        return None

    def defs_of(self, name: SSAName) -> List[int]:
        """Return all instruction VAs that define `name`."""
        result: List[int] = []
        # Check phi nodes first
        for block_va, phi_list in self.phis.items():
            for phi in phi_list:
                if phi.result == name:
                    result.append(self.cfg.blocks[block_va].insns[0].address
                                  if self.cfg.blocks[block_va].insns else block_va)
        # Check ordinary definitions
        for (block_va, idx), defined in self.defs_map.items():
            if defined == name:
                block = self.cfg.blocks.get(block_va)
                if block and idx < len(block.insns):
                    result.append(block.insns[idx].address)
        return result

    def uses_of(self, name: SSAName) -> List[int]:
        """Return all instruction VAs that use `name`."""
        result: List[int] = []
        for (block_va, idx), uses in self.use_map.items():
            if name in uses.values():
                block = self.cfg.blocks.get(block_va)
                if block and idx < len(block.insns):
                    result.append(block.insns[idx].address)
        return result

    def report(self) -> str:
        """Human-readable SSA summary."""
        total_phis = sum(len(pl) for pl in self.phis.values())
        total_defs = len(self.defs_map)
        phi_blocks = [va for va, pl in self.phis.items() if pl]
        lines = [
            f'SSAForm: {len(self.cfg.blocks)} blocks, {total_defs} definitions, '
            f'{total_phis} phi nodes in {len(phi_blocks)} blocks',
        ]
        for bva in sorted(phi_blocks):
            for phi in self.phis[bva]:
                args_str = ', '.join(
                    f'0x{pred:x}:{name}' for pred, name in sorted(phi.args.items())
                )
                lines.append(f'  BB 0x{bva:x}: {phi.result} = phi({args_str})')
        return '\n'.join(lines)


# ─── SSA builder ──────────────────────────────────────────────────────────────

class SSABuilder:
    """
    Build SSA form for a single function CFG.

    Args:
        cfg:  dataflow_engine.CFG for the function.
        arch: ArchConfig providing dest_reg() and all_regs().
    """

    def __init__(self, cfg: CFG, arch: ArchConfig) -> None:
        self._cfg  = cfg
        self._arch = arch
        self._dom  = DomTree(cfg)

    def build(self) -> SSAForm:
        """Run all three SSA phases and return SSAForm."""
        all_regs = self._arch.all_regs()

        # Phase 1 — collect definition sites per register
        # defs_for[reg] = list of block VAs that contain a definition of reg
        defs_for: Dict[str, List[int]] = defaultdict(list)
        for block_va, block in self._cfg.blocks.items():
            regs_defined_in_block: Set[str] = set()
            for insn in block.insns:
                d = self._arch.dest_reg(insn)
                if d and d in all_regs and d not in regs_defined_in_block:
                    defs_for[d].append(block_va)
                    regs_defined_in_block.add(d)
                # Call instructions clobber caller-save registers
                if self._arch.is_call(insn):
                    for cr in self._arch.call_clobbers():
                        if cr in all_regs and cr not in regs_defined_in_block:
                            defs_for[cr].append(block_va)
                            regs_defined_in_block.add(cr)

        # Phase 2 — phi insertion via iterated dominance frontiers
        df = self._dom.dom_frontier()
        phis: Dict[int, List[PhiNode]] = {va: [] for va in self._cfg.blocks}
        phi_regs: Dict[int, Set[str]] = {va: set() for va in self._cfg.blocks}

        for reg in all_regs:
            worklist = list(defs_for.get(reg, []))
            has_phi: Set[int] = set()
            processed: Set[int] = set()

            while worklist:
                n = worklist.pop()
                if n in processed:
                    continue
                processed.add(n)
                for y in df.get(n, set()):
                    if reg not in phi_regs.get(y, set()):
                        # Insert a placeholder phi (args filled in phase 3)
                        phis[y].append(PhiNode(
                            result=SSAName(reg=reg, ver=0),  # version set in phase 3
                            args={},
                            block_va=y,
                        ))
                        phi_regs[y].add(reg)
                        if y not in has_phi:
                            has_phi.add(y)
                            worklist.append(y)

        # Phase 3 — variable renaming (DFS over dominator tree)
        # version counters
        counters:  Dict[str, int] = defaultdict(int)
        # stack of SSA names per register (version stack)
        stacks:    Dict[str, List[SSAName]] = defaultdict(list)

        defs_map:  Dict[Tuple[int, int], SSAName] = {}
        use_map:   Dict[Tuple[int, int], Dict[str, SSAName]] = {}
        reaching:  Dict[Tuple[int, int], Dict[str, SSAName]] = {}

        # Seed the stack with version-0 "undefined" names for all regs
        for r in all_regs:
            stacks[r].append(SSAName(r, 0))
            counters[r] = 1   # next fresh version is 1

        def _top(r: str) -> SSAName:
            return stacks[r][-1] if stacks[r] else SSAName(r, 0)

        def _fresh(r: str) -> SSAName:
            v = counters[r]
            counters[r] += 1
            name = SSAName(r, v)
            stacks[r].append(name)
            return name

        def _rename(block_va: int) -> None:
            block = self._cfg.blocks[block_va]
            pushed: List[Tuple[str, SSAName]] = []  # (reg, name) to pop on exit

            # Assign fresh names to phi results at this block's entry
            for phi in phis[block_va]:
                reg = phi.result.reg
                name = _fresh(reg)
                phi.result = name
                pushed.append((reg, name))

            # Rename instructions
            for idx, insn in enumerate(block.insns):
                # Record reaching state (entry state for this instruction)
                reaching[(block_va, idx)] = {r: _top(r) for r in all_regs}

                # Record uses (before the def so uses see the old version)
                uses_here: Dict[str, SSAName] = {}
                for r in all_regs:
                    uses_here[r] = _top(r)
                use_map[(block_va, idx)] = uses_here

                # Process definition
                if self._arch.is_call(insn):
                    # Clobber caller-save regs first (they lose their value)
                    for cr in self._arch.call_clobbers():
                        if cr in all_regs:
                            name = _fresh(cr)
                            defs_map[(block_va, idx)] = name
                            pushed.append((cr, name))

                d = self._arch.dest_reg(insn)
                if d and d in all_regs:
                    name = _fresh(d)
                    defs_map[(block_va, idx)] = name
                    pushed.append((d, name))

            # Fill phi args in successor blocks
            for succ_va in block.succs:
                if succ_va not in self._cfg.blocks:
                    continue
                for phi in phis[succ_va]:
                    reg = phi.result.reg
                    phi.args[block_va] = _top(reg)

            # Recurse into dominator tree children
            for child_va in self._dom.children(block_va):
                _rename(child_va)

            # Restore stacks (pop everything pushed in this block)
            for reg, _ in reversed(pushed):
                if stacks[reg]:
                    stacks[reg].pop()

        _rename(self._cfg.entry)

        return SSAForm(
            cfg=self._cfg,
            dom=self._dom,
            phis=phis,
            defs_map=defs_map,
            use_map=use_map,
            reaching=reaching,
        )
