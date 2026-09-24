"""
cross_binary_taint.py -- Cross-binary interprocedural taint tracker.

Extends TaintTracker to follow tainted arguments across shared library
boundaries using LibGraph's import/export resolution.

Single-binary TaintTracker.run_interprocedural() stops when a tainted
arg is passed into a PLT entry -- it knows the name, not the address.
This module resolves that name to the exporting binary via LibGraph and
continues the BFS from the exported function's entry point.

Usage:
    from ablation.analyzers.cross_binary_taint import CrossBinaryTaintTracker
    from ablation.analyzers.lib_graph import LibGraph

    lg = LibGraph.from_dir('/path/to/firmware/lib/')
    tracker = CrossBinaryTaintTracker(
        entry_binary='/path/to/firmware/lib/libservice.so',
        lib_graph=lg,
        max_hops=6,
    )
    chains = tracker.run()
    print(tracker.report(chains))

Each TaintChain records the full cross-binary path:
  libservice.so:recv_wrapper -> libdata.so:parse_packet -> libcmd.so:exec_command -> system()
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# ── imports with graceful fallback ────────────────────────────────────────────

try:
    from ablation.analyzers.taint_tracker_x86 import TaintTracker
    _HAS_TAINT = True
except ImportError:
    _HAS_TAINT = False

try:
    from ablation.analyzers.lib_graph import LibGraph
    _HAS_LIBGRAPH = True
except ImportError:
    _HAS_LIBGRAPH = False


# ── data classes ──────────────────────────────────────────────────────────────

@dataclass
class TaintHop:
    """One function in a cross-binary taint chain."""
    binary_path: str
    func_va: int
    func_name: str
    tainted_arg_indices: List[int]   # which args arrived tainted
    calls_made: List[str] = field(default_factory=list)  # notable calls in this function

    @property
    def binary_name(self) -> str:
        return Path(self.binary_path).name

    def fmt(self) -> str:
        args_str = ", ".join(f"arg{i}" for i in self.tainted_arg_indices)
        prefix = f"  {self.binary_name}:{self.func_name}"
        if self.tainted_arg_indices:
            return f"{prefix}  [tainted: {args_str}]"
        return prefix


@dataclass
class TaintChain:
    """Full cross-binary taint path from source to sink."""
    hops: List[TaintHop]
    sink_binary: str
    sink_va: int
    sink_name: str
    tainted_args: List[int]
    source_name: str

    @property
    def depth(self) -> int:
        return len(self.hops)

    @property
    def sink_binary_name(self) -> str:
        return Path(self.sink_binary).name

    def fmt(self) -> str:
        chain_str = " -> ".join(
            f"{h.binary_name}:{h.func_name}" for h in self.hops
        )
        if chain_str:
            chain_str += f" -> {self.sink_binary_name}:{self.sink_name}"
        else:
            chain_str = f"{self.sink_binary_name}:{self.sink_name}"
        args_str = ", ".join(f"arg{i}" for i in self.tainted_args)
        return (
            f"[xb-taint] {chain_str}  sink_args=[{args_str}]"
            f"  src={self.source_name}"
        )


# ── queue entry ───────────────────────────────────────────────────────────────

@dataclass
class _QueueEntry:
    binary_path: str
    func_va: int
    seed_arg_indices: List[int]
    path_so_far: List[TaintHop]
    source_name: str
    depth: int


# ── main class ────────────────────────────────────────────────────────────────

class CrossBinaryTaintTracker:
    """
    Cross-binary interprocedural taint tracker.

    Follows tainted arguments from network receive functions across shared
    library boundaries until they reach dangerous sinks.

    Parameters:
        entry_binary    Path to the binary where analysis begins.
        lib_graph       LibGraph covering all relevant shared libraries.
                        If None, falls back to single-binary mode.
        max_hops        Maximum function hops before stopping BFS (default 6).
        custom_sinks    Extra sinks: {name: [arg_index, ...]}
        custom_sources  Extra sources (functions whose return value is tainted).
    """

    def __init__(
        self,
        entry_binary: str,
        lib_graph: Optional["LibGraph"] = None,
        max_hops: int = 6,
        custom_sinks: Optional[Dict[str, List[int]]] = None,
        custom_sources: Optional[Set[str]] = None,
    ):
        if not _HAS_TAINT:
            raise ImportError("TaintTracker not available -- install capstone")

        self.entry_binary = entry_binary
        self.lib_graph = lib_graph
        self.max_hops = max_hops
        self._custom_sinks = custom_sinks or {}
        self._custom_sources = custom_sources or set()

        # Cache of TaintTracker instances per binary path
        self._trackers: Dict[str, TaintTracker] = {}
        # Cache of function name -> binary path, from LibGraph
        self._export_cache: Dict[str, Optional[str]] = {}

    def _get_tracker(self, binary_path: str) -> Optional[TaintTracker]:
        if binary_path not in self._trackers:
            try:
                from ablation.analyzers.xref_graph import XRefGraph
                xg = XRefGraph.from_path(binary_path).build()
                tracker = TaintTracker(binary_path, xref=xg,
                                       custom_sinks=self._custom_sinks)
                self._trackers[binary_path] = tracker
            except Exception:
                self._trackers[binary_path] = None
        return self._trackers[binary_path]

    def _resolve_export(self, symbol_name: str) -> Optional[str]:
        """Return the binary path that exports symbol_name, or None."""
        if symbol_name in self._export_cache:
            return self._export_cache[symbol_name]

        result = None
        if self.lib_graph is not None:
            try:
                hits = self.lib_graph.defined_in(symbol_name)
                if hits:
                    result = hits[0][0]  # first match
            except Exception:
                pass

        self._export_cache[symbol_name] = result
        return result

    def _func_starts_for(self, binary_path: str) -> List[int]:
        tracker = self._get_tracker(binary_path)
        if tracker is None:
            return []
        return tracker._get_func_starts()

    def _find_seeds(self, binary_path: str) -> List[Tuple[int, str]]:
        """Find functions in binary_path that call a taint source."""
        tracker = self._get_tracker(binary_path)
        if tracker is None:
            return []

        import capstone
        from capstone.x86_const import X86_INS_CALL, X86_OP_IMM

        # Network source names
        SOURCES = getattr(TaintTracker, '_SOURCES', {
            "recv", "recvfrom", "recvmsg", "read", "pread",
            "fread", "fgets", "getline",
        }) | self._custom_sources

        seeds: List[Tuple[int, str]] = []
        func_starts = tracker._get_func_starts()
        func_end_map: Dict[int, int] = {}
        for i, fva in enumerate(func_starts):
            fend = func_starts[i+1] if i+1 < len(func_starts) else fva + 0x8000
            func_end_map[fva] = fend

        for fva in func_starts:
            fend = func_end_map[fva]
            func_bytes = tracker._va_to_slice(fva, min(fend - fva, 0x8000))
            if not func_bytes or len(func_bytes) < 8:
                continue
            try:
                for insn in tracker._md.disasm(func_bytes, fva):
                    if insn.id == X86_INS_CALL:
                        ops = insn.operands
                        if ops and ops[0].type == X86_OP_IMM:
                            name = tracker._plt.get(ops[0].imm, "")
                            if name in SOURCES or name in self._custom_sources:
                                seeds.append((fva, name))
                                break
            except Exception:
                continue

        return seeds

    def run(self) -> List[TaintChain]:
        """
        Run cross-binary BFS from network source functions to dangerous sinks.
        Returns all discovered TaintChain paths.
        """
        results: List[TaintChain] = []
        queue: deque = deque()
        visited: Set[Tuple[str, int, FrozenSet[int]]] = set()

        # Seed from the entry binary
        seeds = self._find_seeds(self.entry_binary)
        if not seeds:
            return results

        for seed_va, src_name in seeds:
            key = (self.entry_binary, seed_va, frozenset())
            if key not in visited:
                visited.add(key)
                queue.append(_QueueEntry(
                    binary_path=self.entry_binary,
                    func_va=seed_va,
                    seed_arg_indices=[],
                    path_so_far=[],
                    source_name=src_name,
                    depth=0,
                ))

        while queue:
            entry = queue.popleft()
            if entry.depth > self.max_hops:
                continue

            tracker = self._get_tracker(entry.binary_path)
            if tracker is None:
                continue

            # Run single-binary interprocedural from this function
            try:
                if entry.seed_arg_indices:
                    single_findings = tracker.run_on_function_seeded(
                        func_va=entry.func_va,
                        seed_arg_indices=entry.seed_arg_indices,
                        source_calls=[entry.source_name],
                    )
                else:
                    single_findings = tracker.run_on_function(
                        func_va=entry.func_va,
                    )
            except Exception:
                single_findings = []

            func_name = tracker._func_name(entry.func_va) if hasattr(tracker, '_func_name') else f"0x{entry.func_va:x}"
            current_hop = TaintHop(
                binary_path=entry.binary_path,
                func_va=entry.func_va,
                func_name=func_name,
                tainted_arg_indices=entry.seed_arg_indices,
            )

            # Record any sinks found
            for f in single_findings:
                results.append(TaintChain(
                    hops=entry.path_so_far + [current_hop],
                    sink_binary=entry.binary_path,
                    sink_va=f.sink_va,
                    sink_name=f.sink_name,
                    tainted_args=f.tainted_args,
                    source_name=entry.source_name,
                ))

            # Get callee propagation: find calls where tainted args flow into
            # PLT entries that we can resolve to other binaries
            callee_props = self._get_callee_propagations(tracker, entry)
            for callee_binary, callee_va, callee_args, callee_name in callee_props:
                key = (callee_binary, callee_va, frozenset(callee_args))
                if key not in visited:
                    visited.add(key)
                    queue.append(_QueueEntry(
                        binary_path=callee_binary,
                        func_va=callee_va,
                        seed_arg_indices=callee_args,
                        path_so_far=entry.path_so_far + [current_hop],
                        source_name=entry.source_name,
                        depth=entry.depth + 1,
                    ))

        return results

    def _get_callee_propagations(
        self, tracker, entry: _QueueEntry
    ) -> List[Tuple[str, int, List[int], str]]:
        """
        Returns [(callee_binary, callee_va, tainted_arg_indices, name)] for
        callees that receive tainted arguments and can be resolved to a binary.
        """
        result: List[Tuple[str, int, List[int], str]] = []

        if not hasattr(tracker, '_va_to_slice') or not hasattr(tracker, '_md'):
            return result

        from capstone.x86_const import X86_INS_CALL, X86_OP_IMM, X86_OP_MEM

        func_starts = tracker._get_func_starts()
        func_end_map: Dict[int, int] = {}
        for i, fva in enumerate(func_starts):
            fend = func_starts[i+1] if i+1 < len(func_starts) else fva + 0x8000
            func_end_map[fva] = fend

        fend = func_end_map.get(entry.func_va, entry.func_va + 0x8000)
        func_bytes = tracker._va_to_slice(entry.func_va, min(fend - entry.func_va, 0x8000))
        if not func_bytes:
            return result

        # Lightweight taint pass to find propagations to cross-binary callees
        # Use TaintTracker's existing run_interprocedural logic to get propagations
        try:
            from ablation.analyzers.taint_tracker_x86 import analyze_function_seeded
            _, propagations = analyze_function_seeded(
                data=func_bytes,
                func_va=entry.func_va,
                func_end_va=fend,
                plt=tracker._plt,
                md=tracker._md,
                seed_arg_indices=entry.seed_arg_indices,
                source_calls=[entry.source_name],
                extra_sinks=tracker._extra_sinks,
            )
        except Exception:
            return result

        func_start_set = set(func_starts)

        for callee_va, tainted_arg_indices in propagations:
            if not tainted_arg_indices:
                continue

            # Callee within same binary -- will be picked up by TaintTracker internally
            if callee_va in func_start_set:
                continue

            # Callee is a PLT entry -- try to resolve to exporting binary
            callee_name = tracker._plt.get(callee_va, "")
            if not callee_name:
                continue

            export_binary = self._resolve_export(callee_name)
            if export_binary is None:
                continue

            # Look up the exported function's VA in the target binary
            target_tracker = self._get_tracker(export_binary)
            if target_tracker is None:
                continue

            callee_export_va = None
            try:
                if hasattr(target_tracker, '_exports'):
                    callee_export_va = target_tracker._exports.get(callee_name)
            except Exception:
                pass

            if callee_export_va is None:
                # Try via BinaryContext
                try:
                    from ablation.analyzers.binary_context import BinaryContext
                    ctx = BinaryContext.load_or_build(export_binary)
                    callee_export_va = ctx.export_va(callee_name)
                except Exception:
                    pass

            if callee_export_va:
                result.append((export_binary, callee_export_va, list(tainted_arg_indices), callee_name))

        return result

    def report(self, chains: List[TaintChain]) -> str:
        if not chains:
            return f"[cross_binary_taint] No cross-binary taint paths found from {self.entry_binary}"

        lines = [
            f"[cross_binary_taint] {self.entry_binary}",
            f"  {len(chains)} taint chain(s) found",
            "",
        ]
        for c in chains:
            lines.append(c.fmt())
            for hop in c.hops:
                lines.append(hop.fmt())
            lines.append(
                f"    -> {Path(c.sink_binary).name}:{c.sink_name}"
                f"(args=[{','.join(str(a) for a in c.tainted_args)}])"
            )
            lines.append("")
        return "\n".join(lines)
