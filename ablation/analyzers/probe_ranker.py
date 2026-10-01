"""
probe_ranker.py — Probe candidate generation and expected-value ranking.

Implements the probe selection formula from active-hypothesis-engine-plan.md:

    probe_value = predicted_disagreement
                * observability
                * analyzer_reliability
                / max(estimated_cost, epsilon)

Probes are generated for a set of surviving hypotheses.
Only probes that could change at least one hypothesis state are ranked.
Probes with identical predicted outcomes across all hypotheses are skipped.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .hypothesis_models import (
    ConfidenceState, EvidenceRecord, HypothesisRecord, ProbeRecord,
)


# ── Probe kind definitions ────────────────────────────────────────────────────
# cost=1.0 is the baseline; lower = cheaper.

_PROBE_CATALOG: Dict[str, Dict] = {
    "cfg": {
        "analyzer": "CFGBuilder",
        "estimated_cost": 1.0,
        "observability": 0.9,
        "reliability": 0.85,
        "description": "Rebuild CFG from candidate entry point",
    },
    "xref": {
        "analyzer": "XRefGraph",
        "estimated_cost": 0.8,
        "observability": 0.85,
        "reliability": 0.80,
        "description": "Resolve callers, callees, string and PLT references",
    },
    "disassembly": {
        "analyzer": "Capstone",
        "estimated_cost": 0.5,
        "observability": 0.95,
        "reliability": 0.90,
        "description": "Decode ambiguous region under candidate mode/boundary",
    },
    "taint": {
        "analyzer": "ARM64TaintTracker",
        "estimated_cost": 3.0,
        "observability": 0.80,
        "reliability": 0.75,
        "description": "Test whether a source can influence a claimed sink",
    },
    "semantic": {
        "analyzer": "SemanticSearcher",
        "estimated_cost": 2.0,
        "observability": 0.60,
        "reliability": 0.65,
        "description": "Retrieve similar functions for analyst prioritization",
    },
    "version": {
        "analyzer": "DTWMatcher",
        "estimated_cost": 2.5,
        "observability": 0.70,
        "reliability": 0.70,
        "description": "Compare candidate homologs across firmware versions",
    },
    "manual": {
        "analyzer": "analyst",
        "estimated_cost": 10.0,
        "observability": 1.0,
        "reliability": 0.95,
        "description": "Analyst-confirmed evidence (manual inspection)",
    },
    "lifter": {
        "analyzer": "BinaryLifter",
        "estimated_cost": 1.5,
        "observability": 0.80,
        "reliability": 0.80,
        "description": "Lift function to pseudo-C IR and inspect data flow",
    },
    "dynamic": {
        "analyzer": "DynamicSandbox",
        "estimated_cost": 2.0,
        "observability": 0.95,
        "reliability": 0.85,
        "description": "Execute leaf function in Unicorn sandbox; observe return value and memory writes",
    },
}


def probe_kinds() -> List[str]:
    return list(_PROBE_CATALOG.keys())


# ── Disagreement estimators ───────────────────────────────────────────────────

def _confidence_spread(hypotheses: List[HypothesisRecord]) -> float:
    """How spread out are the current confidence values?"""
    if len(hypotheses) < 2:
        return 0.0
    confs = [h.confidence for h in hypotheses]
    return max(confs) - min(confs)


def _hypothesis_disagreement(
    hypotheses: List[HypothesisRecord],
    probe_kind: str,
) -> float:
    """Estimated disagreement: how differently would the hypotheses predict probe outcome?

    For now this is heuristic-based. A real implementation would use
    symbolic prediction from hypothesis claim fields.
    """
    if not hypotheses:
        return 0.0

    # Hypotheses with different status are more likely to disagree
    statuses = {h.status for h in hypotheses}
    status_diversity = len(statuses) / max(len(ConfidenceState), 1)

    # Hypotheses about different VAs are more likely to disagree on structural probes
    va_diversity = 0.0
    if probe_kind in ("cfg", "disassembly", "taint", "lifter"):
        vas = {h.claim.get("target_va") or h.subject.get("va") for h in hypotheses}
        vas.discard(None)
        va_diversity = min(1.0, len(vas) / max(len(hypotheses), 1))

    spread = _confidence_spread(hypotheses)
    return max(spread, status_diversity * 0.3, va_diversity * 0.4)


# ── Probe ranker ──────────────────────────────────────────────────────────────

class ProbeRanker:
    """Generate and rank probe candidates for a set of surviving hypotheses."""

    def __init__(self, configuration: Optional[Dict] = None):
        self._catalog = dict(_PROBE_CATALOG)
        if configuration:
            overrides = configuration.get("probe_catalog_overrides", {})
            for kind, vals in overrides.items():
                if kind in self._catalog:
                    self._catalog[kind].update(vals)
                else:
                    self._catalog[kind] = vals

    def generate(
        self,
        hypotheses: List[HypothesisRecord],
        executed_kinds: Optional[List[str]] = None,
        max_candidates: int = 10,
    ) -> List[ProbeRecord]:
        """Generate ranked probe candidates for the given hypotheses.

        Args:
            hypotheses:     Surviving (non-rejected) hypotheses.
            executed_kinds: Probe kinds already executed this session (reduce repeats).
            max_candidates: Max number of candidates to return.

        Returns:
            Ranked list of ProbeRecord objects, highest expected info gain first.
            These are NOT executed — call HypothesisEngine.execute_probe() to run one.
        """
        if not hypotheses:
            return []

        executed_kinds = list(executed_kinds or [])
        h_ids = [h.id for h in hypotheses]
        candidates: List[ProbeRecord] = []

        for kind, meta in self._catalog.items():
            # De-prioritize already-executed kinds (but don't exclude entirely)
            recent_penalty = 0.3 if kind in executed_kinds else 1.0

            disagreement = _hypothesis_disagreement(hypotheses, kind)
            if disagreement < 0.05:
                # This probe can't meaningfully distinguish the hypotheses
                continue

            reliability = meta["reliability"]
            observability = meta["observability"] * recent_penalty
            cost = meta["estimated_cost"]

            eig = (disagreement * observability * reliability) / max(cost, 1e-6)

            probe = ProbeRecord.create(
                kind=kind,
                target_hypothesis_ids=h_ids,
                analyzer=meta["analyzer"],
                parameters={"description": meta["description"]},
                estimated_cost=cost,
                observability=observability,
                predicted_disagreement=disagreement,
                notes=meta["description"],
            )
            probe.expected_information_gain = eig
            candidates.append(probe)

        candidates.sort(key=lambda p: p.expected_information_gain, reverse=True)
        return candidates[:max_candidates]

    def top_probe(
        self,
        hypotheses: List[HypothesisRecord],
        executed_kinds: Optional[List[str]] = None,
    ) -> Optional[ProbeRecord]:
        """Return the single highest-value probe, or None if none useful."""
        ranked = self.generate(hypotheses, executed_kinds=executed_kinds, max_candidates=1)
        return ranked[0] if ranked else None

    def plan_report(
        self,
        hypotheses: List[HypothesisRecord],
        executed_kinds: Optional[List[str]] = None,
        top_n: int = 5,
    ) -> str:
        """Return a human-readable probe plan for analyst review."""
        candidates = self.generate(hypotheses, executed_kinds=executed_kinds, max_candidates=top_n)
        if not hypotheses:
            return "No surviving hypotheses — nothing to probe."
        lines = [
            f"Probe plan for {len(hypotheses)} surviving hypotheses "
            f"(showing top {min(top_n, len(candidates))}):"
        ]
        for i, p in enumerate(candidates, 1):
            lines.append(
                f"  {i}. [{p.kind}] {p.analyzer}  "
                f"eig={p.expected_information_gain:.3f}  "
                f"cost={p.estimated_cost:.1f}  "
                f"disagree={p.predicted_disagreement:.2f}"
            )
            lines.append(f"     {p.notes}")
        if not candidates:
            lines.append("  (no probes can distinguish the current hypothesis set)")
        return "\n".join(lines)


__all__ = ["ProbeRanker", "probe_kinds"]
