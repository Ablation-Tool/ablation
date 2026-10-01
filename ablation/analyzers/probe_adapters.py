"""
probe_adapters.py — Concrete probe execution adapters for the Hypothesis Engine.

Milestone 3 of the Active Architecture Tomography plan.

Each adapter takes a ProbeRecord and the current analysis context, runs the
appropriate Ablation analyzer, and returns a list of EvidenceRecord objects.
The HypothesisEngine calls execute_probe() — which picks the right adapter —
and feeds the resulting evidence back into the scoring loop.

Adapter catalog:
    disassembly  → Capstone: function size, insn count, call targets, strings
    cfg          → CFGBuilder: basic block count, loop detection, branch count
    xref         → XRefGraph: callers, callees, PLT imports
    lifter       → BinaryLifter: pseudo-C IR, declared variables, call args
    semantic     → SemanticSearcher: description similarity to known patterns
    version      → DTWMatcher: structural similarity to homolog functions
    taint        → ARM64TaintTracker / arch-appropriate: source→sink paths
    manual       → no execution; marks probe pending for analyst

Usage:

    from ablation.analyzers.probe_adapters import execute_probe, ProbeAdapter
    from ablation.analyzers.binary_context import BinaryContext

    ctx = BinaryContext.load_or_build('/path/to/binary')
    evidence_list = execute_probe(probe_record, ctx, session)
"""
from __future__ import annotations

import traceback
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .hypothesis_models import EvidenceRecord, EvidenceRelation, HypothesisSession

if TYPE_CHECKING:
    from .hypothesis_models import ProbeRecord
    from .binary_context import BinaryContext


# ── Base class ────────────────────────────────────────────────────────────────

class ProbeAdapter:
    """Base class for probe execution adapters."""

    kind: str = "base"

    def can_handle(self, probe_kind: str) -> bool:
        return probe_kind == self.kind

    def execute(
        self,
        probe: "ProbeRecord",
        ctx: "BinaryContext",
        session: HypothesisSession,
    ) -> List[EvidenceRecord]:
        """Execute the probe and return evidence records.

        Must not raise — catch exceptions internally and return empty list
        or a low-strength NEUTRAL evidence record describing the failure.
        """
        raise NotImplementedError

    def _target_vas(self, probe: "ProbeRecord", session: HypothesisSession) -> List[int]:
        """Extract target function VAs from probe parameters or hypothesis subjects."""
        # Probe parameters may specify them directly
        params = probe.parameters
        vas = []
        if "va" in params:
            try:
                vas.append(int(str(params["va"]), 0))
            except (ValueError, TypeError):
                pass
        if "vas" in params:
            for v in params.get("vas", []):
                try:
                    vas.append(int(str(v), 0))
                except (ValueError, TypeError):
                    pass
        if vas:
            return list(set(vas))
        # Fall back to hypothesis subjects
        for hid in probe.target_hypothesis_ids:
            h = session.get_hypothesis(hid)
            if h is None:
                continue
            subj = h.subject
            for key in ("va", "func_va", "call_site_va", "target_va"):
                if key in subj:
                    try:
                        vas.append(int(str(subj[key]), 0))
                    except (ValueError, TypeError):
                        pass
        return list(set(vas))

    def _evidence(
        self,
        probe: "ProbeRecord",
        family: str,
        observation: Dict[str, Any],
        relation: str = EvidenceRelation.NEUTRAL,
        strength: float = 0.5,
        reliability: float = 0.8,
        notes: str = "",
    ) -> EvidenceRecord:
        return EvidenceRecord.create(
            analyzer=self.__class__.__name__,
            family=family,
            subject=probe.parameters,
            observation=observation,
            relation=relation,
            hypothesis_ids=probe.target_hypothesis_ids,
            strength=strength,
            reliability=reliability,
            notes=notes,
        )


# ── Disassembly adapter ───────────────────────────────────────────────────────

class DisassemblyAdapter(ProbeAdapter):
    """Uses Capstone to extract function structure observations."""

    kind = "disassembly"

    def execute(self, probe, ctx, session):
        import capstone
        evidence = []
        for va in self._target_vas(probe, session):
            try:
                func_bytes = ctx.func_bytes(va) if hasattr(ctx, "func_bytes") else None
                if func_bytes is None or len(func_bytes) < 4:
                    continue
                arch = getattr(ctx, "arch", "arm64")
                if arch in ("arm64", "aarch64"):
                    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                elif arch in ("x86_64", "x86"):
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                else:
                    continue
                cs.detail = False
                insns = list(cs.disasm(func_bytes, va))
                if not insns:
                    continue

                # Count call instructions
                call_targets = []
                branch_count = 0
                for insn in insns:
                    mn = insn.mnemonic.lower()
                    if mn in ("bl", "blr", "call", "callq"):
                        call_targets.append(hex(insn.address))
                    elif mn.startswith("b") or mn in ("je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle"):
                        branch_count += 1

                obs = {
                    "va": hex(va),
                    "insn_count": len(insns),
                    "func_bytes": len(func_bytes),
                    "call_count": len(call_targets),
                    "branch_count": branch_count,
                    "call_targets": call_targets[:20],
                }
                # Size is structural evidence (neutral until interpreted)
                evidence.append(self._evidence(
                    probe, "structure", obs,
                    relation=EvidenceRelation.NEUTRAL,
                    strength=0.6,
                    notes=f"disasm: {len(insns)} insns, {len(call_targets)} calls",
                ))
            except Exception:
                pass
        return evidence


# ── CFG adapter ───────────────────────────────────────────────────────────────

class CFGAdapter(ProbeAdapter):
    """Builds CFG and reports basic block count, loop presence, branch targets."""

    kind = "cfg"

    def execute(self, probe, ctx, session):
        evidence = []
        for va in self._target_vas(probe, session):
            try:
                from .cfg_builder import CFGBuilder
                builder = CFGBuilder(ctx) if hasattr(ctx, "path") else None
                if builder is None:
                    continue
                cfg = builder.build(va)
                if cfg is None:
                    continue
                # Loop detection: any back-edge (target VA < source VA)
                has_loop = any(
                    edge.target < edge.source
                    for edge in getattr(cfg, "edges", [])
                )
                num_blocks = len(getattr(cfg, "blocks", []))
                obs = {
                    "va": hex(va),
                    "num_basic_blocks": num_blocks,
                    "has_loop": has_loop,
                    "num_edges": len(getattr(cfg, "edges", [])),
                }
                evidence.append(self._evidence(
                    probe, "structure", obs,
                    relation=EvidenceRelation.NEUTRAL,
                    strength=0.65,
                    notes=f"cfg: {num_blocks} blocks, loops={has_loop}",
                ))
            except Exception:
                pass
        return evidence


# ── XRef adapter ──────────────────────────────────────────────────────────────

class XRefAdapter(ProbeAdapter):
    """Reports callers, callees, PLT imports, and string references."""

    kind = "xref"

    def execute(self, probe, ctx, session):
        evidence = []
        for va in self._target_vas(probe, session):
            try:
                from .xref_graph import XRefGraph
                xg = XRefGraph.from_path(ctx.path) if hasattr(ctx, "path") else None
                if xg is None:
                    continue
                # XRefGraph may already be built; if not, build quietly
                if not getattr(xg, "_built", False):
                    xg.build()

                callers = list(xg.callers_of(va) or [])
                callees = list(xg.callees_of(va) or [])
                plt_name = xg.plt_name(va)
                strings = list(ctx.strings_in_func(va) if hasattr(ctx, "strings_in_func") else [])

                obs = {
                    "va": hex(va),
                    "callers": [hex(c) for c in callers[:20]],
                    "callees": [hex(c) for c in callees[:20]],
                    "plt_name": plt_name,
                    "string_refs": strings[:20],
                    "caller_count": len(callers),
                    "callee_count": len(callees),
                }
                # xref = cross_reference family
                evidence.append(self._evidence(
                    probe, "cross_reference", obs,
                    relation=EvidenceRelation.NEUTRAL,
                    strength=0.60,
                    notes=f"xref: {len(callers)} callers, {len(callees)} callees",
                ))
            except Exception:
                pass
        return evidence


# ── Lifter adapter ────────────────────────────────────────────────────────────

class LifterAdapter(ProbeAdapter):
    """Lifts function to pseudo-C IR and extracts data-flow observations."""

    kind = "lifter"

    def execute(self, probe, ctx, session):
        evidence = []
        for va in self._target_vas(probe, session):
            try:
                from .binary_lifter import BinaryLifter
                arch = getattr(ctx, "arch", "arm64")
                lifter = BinaryLifter.from_context(ctx) if hasattr(ctx, "path") else None
                if lifter is None:
                    lifter = BinaryLifter.from_path(ctx.path, arch=arch)
                ir = lifter.lift_function(va)
                if not ir or len(ir) < 10:
                    continue

                # Count tainted annotations and call sites
                taint_count = ir.count("/* TAINTED */")
                call_sites = ir.count("fn_")
                declared_vars = ir.count("uint") + ir.count("void*") + ir.count("int8_t")

                obs = {
                    "va": hex(va),
                    "ir_lines": len(ir.splitlines()),
                    "tainted_vars": taint_count,
                    "call_sites": call_sites,
                    "declared_vars": declared_vars,
                    "ir_excerpt": ir[:2048],
                }
                # IR is both structural (shape) and data_flow (taint annotations)
                family = "data_flow" if taint_count > 0 else "structure"
                strength = 0.70 + (0.10 if taint_count > 0 else 0)
                evidence.append(self._evidence(
                    probe, family, obs,
                    relation=EvidenceRelation.NEUTRAL,
                    strength=strength,
                    notes=f"lifter: {len(ir.splitlines())} IR lines, {taint_count} tainted",
                ))
            except Exception:
                pass
        return evidence


# ── Semantic adapter ──────────────────────────────────────────────────────────

class SemanticAdapter(ProbeAdapter):
    """Runs SemanticSearcher with a hypothesis-derived description query."""

    kind = "semantic"

    def execute(self, probe, ctx, session):
        evidence = []
        try:
            from .semantic_search import SemanticSearcher
            from .xref_graph import XRefGraph

            xg = XRefGraph.from_path(ctx.path)
            if not getattr(xg, "_built", False):
                xg.build()

            searcher = SemanticSearcher(ctx, xg=xg)
            if not getattr(searcher, "_corpus_built", False):
                searcher.build_corpus()

            # Use hypothesis claim descriptions as queries
            for hid in probe.target_hypothesis_ids:
                h = session.get_hypothesis(hid)
                if h is None:
                    continue
                query = probe.parameters.get("query") or str(h.claim.get("description", ""))
                if not query:
                    continue
                hits = searcher.query(query, top_k=5)
                if not hits:
                    continue
                obs = {
                    "query": query[:200],
                    "hypothesis_id": hid,
                    "hits": [
                        {"va": hex(getattr(hit, "va", 0)), "score": getattr(hit, "score", 0.0)}
                        for hit in hits
                    ],
                }
                evidence.append(self._evidence(
                    probe, "semantic", obs,
                    relation=EvidenceRelation.NEUTRAL,
                    strength=max((getattr(h, "score", 0.0) for h in hits), default=0.0) * 0.25,
                    notes=f"semantic: top score={getattr(hits[0], 'score', 0):.3f}",
                ))
        except Exception:
            pass
        return evidence


# ── Version adapter ───────────────────────────────────────────────────────────

class VersionAdapter(ProbeAdapter):
    """Compares function to a reference binary via DTWMatcher."""

    kind = "version"

    def execute(self, probe, ctx, session):
        evidence = []
        ref_path = probe.parameters.get("reference_binary")
        if not ref_path:
            return evidence
        try:
            from .dtw_matcher import DTWMatcher

            for va in self._target_vas(probe, session):
                try:
                    matcher = DTWMatcher(ctx.path, ref_path)
                    result = matcher.score_functions(va, va)
                    if result is None:
                        continue
                    sim = getattr(result, "similarity", 0.0)
                    obs = {
                        "va": hex(va),
                        "reference_binary": ref_path,
                        "similarity": sim,
                        "dtw_distance": getattr(result, "distance", None),
                    }
                    # High similarity to known reference = version evidence
                    strength = min(0.80, sim * 0.80)
                    evidence.append(self._evidence(
                        probe, "version", obs,
                        relation=EvidenceRelation.NEUTRAL,
                        strength=strength,
                        notes=f"dtw: similarity={sim:.3f} to {ref_path}",
                    ))
                except Exception:
                    pass
        except ImportError:
            pass
        return evidence


# ── Taint adapter ─────────────────────────────────────────────────────────────

class TaintAdapter(ProbeAdapter):
    """Runs the architecture-appropriate taint tracker and reports source→sink paths."""

    kind = "taint"

    def execute(self, probe, ctx, session):
        evidence = []
        for va in self._target_vas(probe, session):
            try:
                arch = getattr(ctx, "arch", "arm64")
                paths = self._run_taint(ctx, va, arch, probe.parameters)
                if not paths:
                    continue
                obs = {
                    "va": hex(va),
                    "path_count": len(paths),
                    "paths": [
                        {
                            "source": getattr(p, "source", ""),
                            "sink": getattr(p, "sink", ""),
                            "depth": getattr(p, "depth", 0),
                        }
                        for p in paths[:10]
                    ],
                }
                strength = min(0.90, 0.60 + 0.10 * len(paths))
                evidence.append(self._evidence(
                    probe, "data_flow", obs,
                    relation=EvidenceRelation.SUPPORTS,
                    strength=strength,
                    notes=f"taint: {len(paths)} source→sink path(s)",
                ))
            except Exception:
                pass
        return evidence

    def _run_taint(self, ctx, va, arch, params):
        custom_sinks = params.get("custom_sinks", {})
        path = ctx.path
        if arch in ("arm64", "aarch64"):
            from .taint_tracker_arm64 import ARM64TaintTracker
            tracker = ARM64TaintTracker.from_path(path, custom_sinks=custom_sinks)
        elif arch in ("arm32", "arm"):
            from .taint_tracker_arm32 import ARM32TaintTracker
            tracker = ARM32TaintTracker.from_path(path, custom_sinks=custom_sinks)
        elif arch in ("x86_64", "x86"):
            from .taint_tracker_x86 import TaintTracker
            tracker = TaintTracker(path, custom_sinks=custom_sinks)
        elif arch in ("la64", "loongarch64"):
            from .taint_tracker_loongarch64 import LoongArch64TaintTracker
            tracker = LoongArch64TaintTracker.from_path(path, custom_sinks=custom_sinks)
        else:
            return []
        results = tracker.run_interprocedural()
        return results if results else []


# ── Manual adapter ────────────────────────────────────────────────────────────

class ManualAdapter(ProbeAdapter):
    """Placeholder for probes that require analyst action — returns empty."""

    kind = "manual"

    def execute(self, probe, ctx, session):
        # Cannot auto-execute. Analyst must add evidence via add_evidence().
        return [self._evidence(
            probe, "manual",
            {"note": "manual probe — analyst must add evidence via add_evidence()"},
            relation=EvidenceRelation.NEUTRAL,
            strength=0.0,
            notes="manual probe pending",
        )]


# ── Adapter registry + dispatch ───────────────────────────────────────────────

def _make_dynamic_adapter():
    try:
        from .dynamic_sandbox import DynamicProbeAdapter
        return DynamicProbeAdapter()
    except Exception:
        return None


_dynamic = _make_dynamic_adapter()
_ADAPTERS: List[ProbeAdapter] = [
    DisassemblyAdapter(),
    CFGAdapter(),
    XRefAdapter(),
    LifterAdapter(),
    SemanticAdapter(),
    VersionAdapter(),
    TaintAdapter(),
    ManualAdapter(),
]
if _dynamic is not None:
    _ADAPTERS.append(_dynamic)

_ADAPTER_MAP: Dict[str, ProbeAdapter] = {a.kind: a for a in _ADAPTERS}


def execute_probe(
    probe: "ProbeRecord",
    ctx: "BinaryContext",
    session: HypothesisSession,
) -> List[EvidenceRecord]:
    """Execute a probe and return evidence records.

    Picks the right adapter by probe.kind. If no adapter exists, returns empty.
    Never raises — all exceptions are caught internally.
    """
    adapter = _ADAPTER_MAP.get(probe.kind)
    if adapter is None:
        return []
    try:
        return adapter.execute(probe, ctx, session)
    except Exception:
        return []


def available_kinds() -> List[str]:
    """Return list of probe kinds that have concrete adapters."""
    return list(_ADAPTER_MAP.keys())


__all__ = [
    "ProbeAdapter",
    "DisassemblyAdapter", "CFGAdapter", "XRefAdapter",
    "LifterAdapter", "SemanticAdapter", "VersionAdapter",
    "TaintAdapter", "ManualAdapter",
    "execute_probe", "available_kinds",
    # DynamicProbeAdapter re-exported if unicorn is installed
]
