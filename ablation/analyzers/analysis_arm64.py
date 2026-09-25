"""Path-insensitive, flow-sensitive dataflow analysis over an AArch64 CFG.

Usage:
    from ablation.analyzers.analysis_arm64 import analyze_cfg
    from ablation.analyzers.taint_tracker_arm64 import TaintState
    from ablation.analyzers.insn_arm64 import from_listing

    init = TaintState()
    init.taint_reg("x0", "user")
    result = analyze_cfg(list(from_listing(text)), initial=init)
    for f in result.findings:
        print(f)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .cfg_arm64 import CFG, build_cfg
from .insn_arm64 import Insn
from .taint_tracker_arm64 import Finding, TaintEngine, TaintState


@dataclass
class CFGResult:
    cfg: CFG
    findings: List[Finding]
    entry_states: Dict[int, TaintState]
    exit_states: Dict[int, TaintState]
    iterations: int
    unknown: Set[str] = field(default_factory=set)
    unreachable: List[int] = field(default_factory=list)


def _loop_heads(cfg: CFG) -> Set[int]:
    heads: Set[int] = set()
    color: Dict[int, int] = {}

    def dfs(start: int) -> None:
        stack: List[Tuple[int, int]] = [(start, 0)]
        color[start] = 1
        while stack:
            node, i = stack[-1]
            succs = cfg.blocks[node].succs
            if i < len(succs):
                stack[-1] = (node, i + 1)
                s = succs[i]
                c = color.get(s, 0)
                if c == 1:
                    heads.add(s)
                elif c == 0:
                    color[s] = 1
                    stack.append((s, 0))
            else:
                color[node] = 2
                stack.pop()

    dfs(cfg.entry)
    for b in cfg.blocks:
        if color.get(b, 0) == 0:
            dfs(b)
    return heads


def analyze_cfg(
    insns: Sequence[Insn],
    initial: Optional[TaintState] = None,
    entry: Optional[int] = None,
    max_iterations: int = 10_000,
) -> CFGResult:
    cfg = build_cfg(insns, entry=entry)
    heads = _loop_heads(cfg)

    entry_states: Dict[int, TaintState] = {cfg.entry: (initial or TaintState()).copy()}
    exit_states: Dict[int, TaintState] = {}
    visits: Dict[int, int] = {}
    seen_findings: Set[Tuple[int, str, frozenset]] = set()
    findings: List[Finding] = []
    unknown: Set[str] = set()

    worklist: List[int] = [cfg.entry]
    iterations = 0
    while worklist and iterations < max_iterations:
        iterations += 1
        b = worklist.pop(0)
        block = cfg.blocks[b]
        visits[b] = visits.get(b, 0) + 1

        t = TaintEngine()
        t.state = entry_states[b].copy()
        t.run(block.insns)
        unknown |= t.unknown
        for f in t.findings:
            key = (f.address, f.kind, f.labels)
            if key not in seen_findings:
                seen_findings.add(key)
                findings.append(f)

        exit_states[b] = t.state
        for s in block.succs:
            widen = s in heads and visits.get(s, 0) >= 2
            new = t.state.copy() if s not in entry_states else entry_states[s].join(t.state, widen=widen)
            if s not in entry_states or not new.same_as(entry_states[s]):
                entry_states[s] = new
                if s not in worklist:
                    worklist.append(s)

    findings.sort(key=lambda f: f.address)
    unreachable = sorted(b for b in cfg.blocks if b not in entry_states)
    return CFGResult(cfg, findings, entry_states, exit_states, iterations, unknown, unreachable)
