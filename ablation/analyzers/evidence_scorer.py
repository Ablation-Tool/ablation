"""
evidence_scorer.py — Evidence aggregation and confidence state transitions.

Implements the scoring model from active-hypothesis-engine-plan.md:

    support(H) = sum of independent family contributions (diminishing returns)
    contradiction(H) = sum of contradiction contributions
    uncertainty(H) = unresolved assumptions + missing evidence
    raw(H) = prior + support - contradiction - uncertainty
    confidence(H) = clamp(normalize(raw), 0.0, 1.0)

Key rule: CONFIRMED requires more than a threshold float.
It requires at least one structural or data_flow evidence item
plus no unresolved hard contradictions.
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple

from .hypothesis_models import (
    ConfidenceState, EVIDENCE_FAMILIES, EvidenceRecord, EvidenceRelation,
    HypothesisRecord,
)


# ── Hard-contradiction triggers ───────────────────────────────────────────────
# Evidence from these analyzers with CONTRADICTS relation rejects immediately
# when strength >= this threshold.

HARD_CONTRADICTION_THRESHOLD = 0.80

# Families that can trigger CONFIRMED (behavioral or data_flow required)
_STRONG_FAMILIES = frozenset({"behavioral", "data_flow", "structure"})

# Minimum confidence float to enter SUPPORTED state
_SUPPORTED_THRESHOLD = 0.55

# Minimum confidence float to enter CONFIRMED state (float necessary but not sufficient)
_CONFIRMED_THRESHOLD = 0.75


# ── Independence factor ───────────────────────────────────────────────────────

def _independence_factor(count: int) -> float:
    """Diminishing-returns factor for N items in the same evidence family.

    Returns: 1/(1 + ln(count)) so the first item counts fully, the second
    about 0.59, the third about 0.45, etc.
    """
    if count <= 0:
        return 0.0
    return 1.0 / (1.0 + math.log(count))


# ── Evidence scorer ───────────────────────────────────────────────────────────

class EvidenceScorer:
    """Computes confidence scores and state transitions for a hypothesis."""

    def __init__(self, configuration: Optional[Dict[str, float]] = None):
        self._family_weights: Dict[str, float] = dict(EVIDENCE_FAMILIES)
        if configuration:
            self._family_weights.update(configuration.get("family_weights", {}))

    def score(
        self,
        hypothesis: HypothesisRecord,
        evidence_items: List[EvidenceRecord],
    ) -> Tuple[float, str, List[str]]:
        """Score a hypothesis given its evidence list.

        Returns:
            (confidence, new_status, contradiction_notes)
        """
        support = 0.0
        contradiction = 0.0
        uncertainty = 0.0
        contradiction_notes: List[str] = []
        hard_rejected = False

        # Group by family for independence computation
        family_support_counts: Dict[str, int] = {}
        family_contradiction_counts: Dict[str, int] = {}

        for ev in evidence_items:
            if ev.relation == EvidenceRelation.NEUTRAL:
                continue
            fam_weight = self._family_weights.get(ev.family, 0.5)
            if ev.relation == EvidenceRelation.CONTRADICTS:
                family_contradiction_counts[ev.family] = family_contradiction_counts.get(ev.family, 0) + 1
                ind = _independence_factor(family_contradiction_counts[ev.family])
                contrib = ev.contribution(ind) * fam_weight
                contradiction += contrib
                if ev.strength >= HARD_CONTRADICTION_THRESHOLD:
                    hard_rejected = True
                    contradiction_notes.append(
                        f"Hard contradiction from {ev.analyzer} ({ev.family}): "
                        f"{ev.observation.get('summary', str(ev.observation)[:80])}"
                    )
            elif ev.relation == EvidenceRelation.SUPPORTS:
                family_support_counts[ev.family] = family_support_counts.get(ev.family, 0) + 1
                ind = _independence_factor(family_support_counts[ev.family])
                support += ev.contribution(ind) * fam_weight

        # Uncertainty from unresolved assumptions
        uncertainty += 0.1 * len(hypothesis.assumptions)

        raw = hypothesis.prior + support - contradiction - uncertainty
        confidence = max(0.0, min(1.0, raw))

        # State transition
        if hard_rejected:
            return confidence, ConfidenceState.REJECTED, contradiction_notes

        status = self._transition(
            hypothesis.status,
            confidence,
            evidence_items,
            contradiction,
        )
        return confidence, status, contradiction_notes

    def _transition(
        self,
        current: str,
        confidence: float,
        evidence_items: List[EvidenceRecord],
        contradiction: float,
    ) -> str:
        # Already rejected stays rejected
        if current == ConfidenceState.REJECTED:
            return ConfidenceState.REJECTED

        # No evidence at all
        if not evidence_items:
            return ConfidenceState.UNTESTED

        support_items = [e for e in evidence_items if e.relation == EvidenceRelation.SUPPORTS]
        if not support_items:
            return ConfidenceState.UNTESTED

        # CONFIRMED: high confidence + strong family evidence + no unresolved hard contradictions
        strong_support = [e for e in support_items if e.family in _STRONG_FAMILIES]
        families_represented = {e.family for e in support_items}
        if (
            confidence >= _CONFIRMED_THRESHOLD
            and len(strong_support) >= 1
            and len(families_represented) >= 2
            and contradiction < 0.2
        ):
            return ConfidenceState.CONFIRMED

        # SUPPORTED: multiple families agree
        if confidence >= _SUPPORTED_THRESHOLD and len(families_represented) >= 2:
            return ConfidenceState.SUPPORTED

        # PLAUSIBLE: something is there but not enough
        if confidence >= 0.3 or support_items:
            return ConfidenceState.PLAUSIBLE

        return ConfidenceState.UNTESTED

    def update_hypothesis(
        self,
        hypothesis: HypothesisRecord,
        evidence_items: List[EvidenceRecord],
    ) -> List[str]:
        """Compute and write scores back to the hypothesis. Returns contradiction notes."""
        confidence, status, notes = self.score(hypothesis, evidence_items)

        # Accumulate by family for display
        family_support: Dict[str, float] = {}
        family_contradiction: Dict[str, float] = {}
        family_counts: Dict[str, int] = {}
        for ev in evidence_items:
            if ev.relation == EvidenceRelation.NEUTRAL:
                continue
            fam_weight = self._family_weights.get(ev.family, 0.5)
            family_counts[ev.family] = family_counts.get(ev.family, 0) + 1
            ind = _independence_factor(family_counts[ev.family])
            contrib = ev.contribution(ind) * fam_weight
            if ev.relation == EvidenceRelation.SUPPORTS:
                family_support[ev.family] = family_support.get(ev.family, 0.0) + contrib
            elif ev.relation == EvidenceRelation.CONTRADICTS:
                family_contradiction[ev.family] = family_contradiction.get(ev.family, 0.0) + contrib

        hypothesis.support_score = sum(family_support.values())
        hypothesis.contradiction_score = sum(family_contradiction.values())
        hypothesis.uncertainty_score = 0.1 * len(hypothesis.assumptions)
        hypothesis.confidence = confidence
        hypothesis.status = status
        hypothesis.touch()
        return notes


def score_report(
    hypothesis: HypothesisRecord,
    evidence_items: List[EvidenceRecord],
    scorer: Optional[EvidenceScorer] = None,
) -> str:
    """Return a human-readable confidence breakdown for a hypothesis."""
    if scorer is None:
        scorer = EvidenceScorer()
    confidence, status, contradiction_notes = scorer.score(hypothesis, evidence_items)

    lines = [
        f"Hypothesis {hypothesis.id}",
        f"  kind:       {hypothesis.kind}",
        f"  claim:      {hypothesis.claim}",
        f"  status:     {status}  (prior={hypothesis.prior:.2f}  confidence={confidence:.3f})",
        f"  support:    {hypothesis.support_score:.3f}",
        f"  contradict: {hypothesis.contradiction_score:.3f}",
        f"  uncertain:  {hypothesis.uncertainty_score:.3f}",
    ]
    by_family: Dict[str, List[EvidenceRecord]] = {}
    for e in evidence_items:
        by_family.setdefault(e.family, []).append(e)
    for fam, items in sorted(by_family.items()):
        supports = sum(1 for e in items if e.relation == EvidenceRelation.SUPPORTS)
        contradicts = sum(1 for e in items if e.relation == EvidenceRelation.CONTRADICTS)
        lines.append(f"  [{fam}] {supports} supporting, {contradicts} contradicting ({len(items)} total)")
    if contradiction_notes:
        lines.append("  HARD CONTRADICTIONS:")
        for n in contradiction_notes:
            lines.append(f"    ! {n}")
    return "\n".join(lines)


__all__ = ["EvidenceScorer", "score_report", "HARD_CONTRADICTION_THRESHOLD"]
