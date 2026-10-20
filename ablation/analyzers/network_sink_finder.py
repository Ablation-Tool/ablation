"""
NetworkSinkFinder: automates the "HACMP-003 pattern" for any high-SAC networked binary.

Pattern:
    find all PLT network sources (recv/recvfrom/read/fgets/gets/fread/accept)
    → build depth-N reachable function set (BinaryContext.reachable_from)
    → cross-reference with SinkArgClassifier ARG_PROPAGATED + UNKNOWN sinks
    → report {func_va: NetworkSinkResult} for every reachable dangerous sink

The result collapses ~50 lines of per-session manual assembly into 3 lines:

    nsf = NetworkSinkFinder.from_context(ctx)
    results = nsf.find(depth=3)
    for r in results.values(): print(r.fmt())

This was the exact analysis pattern used for HACMP-003 (CONFIRMED HIGH
NETWORK_ARG_PROPAGATED_STRCPY) and is reusable for every PPC32/x86-32/x86-64
binary with network exposure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# Default network source function names (PLT names without version suffixes).
# We match by containment ("recv" in name) to handle @@GLIBC_2.x suffixes.
_DEFAULT_NET_SOURCES = frozenset({
    'recv', 'recvfrom', 'recvmsg', 'read', 'fgets', 'gets',
    'fread', 'accept', 'accept4',
})


@dataclass
class NetworkSinkResult:
    """A single network-reachable dangerous sink finding."""
    func_va:     int    # VA of the function that contains the sink
    func_name:   str    # name (from ctx.name) of that function
    sink_name:   str    # PLT symbol of the sink (e.g. "strcpy", "system")
    verdict:     str    # ARG_PROPAGATED / UNKNOWN / SNPRINTF_RODATA / etc.
    depth:       int    # call depth from the nearest network source
    source_syms: List[str] = field(default_factory=list)  # which sources reach this func

    def fmt(self) -> str:
        srcs = ', '.join(self.source_syms) if self.source_syms else '?'
        return (
            f"{self.func_name} (0x{self.func_va:x}): "
            f"{self.sink_name} [{self.verdict}] "
            f"depth={self.depth} via {srcs}"
        )


class NetworkSinkFinder:
    """Cross-reference network-reachable functions with ARG_PROPAGATED SAC results.

    Designed for:
    - High-SAC binaries (100+ sinks) where manual reachability is impractical
    - Any arch — dispatches SAC via SinkArgClassifier.from_context (arch-aware)
    - Works with stripped binaries (no debug symbols needed)

    Args:
        ctx:        BinaryContext for the binary
        depth:      Maximum call depth from network source to sink function
        net_source_names:
                    Additional network source PLT names to include beyond defaults
        extra_sinks:
                    Additional sink names + arg positions beyond SAC defaults
    """

    def __init__(self, ctx, depth: int = 3,
                 net_source_names: Optional[Set[str]] = None,
                 extra_sinks: Optional[Dict[str, int]] = None):
        self._ctx = ctx
        self._depth = depth
        self._net_source_names = _DEFAULT_NET_SOURCES | (net_source_names or set())
        self._extra_sinks = extra_sinks or {}

    # ── constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_context(cls, ctx, depth: int = 3, **kwargs) -> 'NetworkSinkFinder':
        return cls(ctx, depth=depth, **kwargs)

    # ── main analysis ─────────────────────────────────────────────────────────

    def find(self, depth: Optional[int] = None) -> Dict[int, NetworkSinkResult]:
        """Run the full HACMP-03 pattern; return {func_va: NetworkSinkResult}.

        Results are keyed by *function VA* (not sink-call VA).  When multiple
        sinks exist in the same function, only the highest-priority verdict is
        kept (ARG_PROPAGATED > UNKNOWN > SNPRINTF_RODATA).
        """
        if depth is not None:
            self._depth = depth

        ctx = self._ctx

        # 1. Find network source PLT VAs
        net_source_vas: Dict[int, List[str]] = {}
        for plt_va, plt_name in ctx.plt.items():
            for src in self._net_source_names:
                if src in plt_name:
                    net_source_vas[plt_va] = net_source_vas.get(plt_va, []) + [plt_name]

        if not net_source_vas:
            return {}

        # 2. Find callers of each network source and seed BFS
        seed_vas: Set[int] = set()
        for src_va in net_source_vas:
            for caller_va, _ in ctx.callers_of(src_va):
                seed_vas.add(caller_va)

        if not seed_vas:
            return {}

        # 3. BFS reachability from seed callers up to depth
        # Track minimum depth for each reachable VA
        depth_map: Dict[int, int] = {va: 1 for va in seed_vas}
        frontier = set(seed_vas)
        for d in range(2, self._depth + 1):
            next_frontier: Set[int] = set()
            for va in frontier:
                for callee_va, _ in ctx.callees_of(va):
                    if callee_va not in depth_map:
                        depth_map[callee_va] = d
                        next_frontier.add(callee_va)
            frontier = next_frontier
            if not frontier:
                break

        reachable_vas = set(depth_map)

        # 4. Run SinkArgClassifier (arch-dispatched)
        from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
        clf = SinkArgClassifier.from_context(ctx)
        for sink_name, arg_pos in self._extra_sinks.items():
            clf.add_sink(sink_name, arg_pos)

        sac_results = clf.classify_all()

        # 5. Cross-reference: keep only results whose function is reachable
        _VERDICT_PRIORITY = {'ARG_PROPAGATED': 3, 'UNKNOWN': 2,
                             'SNPRINTF_RODATA': 1, 'RODATA_CONST': 0}
        findings: Dict[int, NetworkSinkResult] = {}

        for r in sac_results:
            if r.verdict == 'RODATA_CONST':
                continue
            func_va = getattr(r, 'func_va', None)
            if func_va is None or func_va not in reachable_vas:
                continue

            new_prio = _VERDICT_PRIORITY.get(r.verdict, 0)
            existing = findings.get(func_va)
            if existing and _VERDICT_PRIORITY.get(existing.verdict, 0) >= new_prio:
                continue

            # Determine which source symbols reach this function
            src_syms: List[str] = []
            for src_va, names in net_source_vas.items():
                callers = {cva for cva, _ in ctx.callers_of(src_va)}
                if callers & {func_va}:
                    src_syms.extend(names)

            findings[func_va] = NetworkSinkResult(
                func_va=func_va,
                func_name=ctx.name(func_va),
                sink_name=r.sink_name,
                verdict=r.verdict,
                depth=depth_map[func_va],
                source_syms=src_syms,
            )

        return findings

    # ── convenience ───────────────────────────────────────────────────────────

    def report(self, findings: Optional[Dict[int, NetworkSinkResult]] = None) -> str:
        """Run find() if *findings* is None, return formatted report string."""
        if findings is None:
            findings = self.find()
        if not findings:
            return "NetworkSinkFinder: no network-reachable dangerous sinks found."
        lines = [f"NetworkSinkFinder: {len(findings)} network-reachable dangerous sinks"]
        by_depth = sorted(findings.values(), key=lambda r: (r.depth, r.func_va))
        for r in by_depth:
            lines.append(f"  depth={r.depth}  {r.fmt()}")
        return "\n".join(lines)
