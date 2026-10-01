"""
hypothesis_engine.py — Active Hypothesis Engine lifecycle and orchestration.

Coordinates HypothesisRecord, EvidenceRecord, ProbeRecord, EvidenceScorer,
and ProbeRanker into a coherent session that:

1. Accepts typed hypotheses about a binary.
2. Accepts evidence from existing Ablation analyzers.
3. Ranks probes by expected information gain.
4. Updates confidence after each piece of evidence.
5. Persists the full session to JSON for reproducibility.

Usage (Milestone 1/2 — report only, no auto execution):

    from ablation.analyzers.hypothesis_engine import HypothesisEngine

    engine = HypothesisEngine.from_binary('/path/to/binary')

    # Seed hypotheses
    h1, h2 = engine.seed(
        kind="indirect_call_target",
        subject={"call_site_va": "0x401920"},
        claims=[
            {"target_va": "0x4026c0"},
            {"target_va": "0x403110"},
        ],
    )

    # Add evidence from an existing analyzer result
    engine.add_evidence(
        analyzer="ARM64TaintTracker",
        family="data_flow",
        subject={"va": "0x4026c0"},
        observation={"source_to_sink": True, "path_length": 3},
        relation="supports",
        hypothesis_ids=[h1.id],
        strength=0.80,
    )

    # Plan next probes (dry run — no execution)
    print(engine.plan())

    # Run one approved probe manually
    result = engine.step(kind="cfg", approved=True)

    # Get full report
    print(engine.report())

    # Save
    engine.save()
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .hypothesis_models import (
    ConfidenceState, EvidenceRecord, EvidenceRelation,
    HypothesisRecord, HypothesisSession, ProbeRecord,
)
from .evidence_scorer import EvidenceScorer, score_report
from .probe_ranker import ProbeRanker


def _lazy_execute_probe(probe, ctx, session):
    """Import and call execute_probe without creating a top-level circular import."""
    from .probe_adapters import execute_probe
    return execute_probe(probe, ctx, session)


class HypothesisEngine:
    """Active hypothesis engine for a single binary analysis session."""

    def __init__(
        self,
        session: HypothesisSession,
        scorer: Optional[EvidenceScorer] = None,
        ranker: Optional[ProbeRanker] = None,
        max_probes: int = 50,
        ctx=None,
    ):
        self.session = session
        self._scorer = scorer or EvidenceScorer(session.configuration)
        self._ranker = ranker or ProbeRanker(session.configuration)
        self._max_probes = max_probes
        self._executed_kinds: List[str] = []
        self._ctx = ctx  # BinaryContext — supplied for Milestone 3 probe execution

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_binary(
        cls,
        binary_path: str,
        architecture: Optional[str] = None,
        configuration: Optional[Dict[str, Any]] = None,
        max_probes: int = 50,
        ctx=None,
    ) -> "HypothesisEngine":
        """Create a new engine session for the given binary.

        Pass ctx (BinaryContext) to enable Milestone 3 probe auto-execution.
        """
        session = HypothesisSession.create(
            binary_path=binary_path,
            architecture=architecture,
            configuration=configuration,
        )
        return cls(session, max_probes=max_probes, ctx=ctx)

    def with_context(self, ctx) -> "HypothesisEngine":
        """Attach a BinaryContext to an existing engine instance."""
        self._ctx = ctx
        return self

    @classmethod
    def load(cls, session_path: str, max_probes: int = 50) -> "HypothesisEngine":
        """Resume an existing session from JSON."""
        session = HypothesisSession.load(session_path)
        inst = cls(session, max_probes=max_probes)
        inst._executed_kinds = [p.kind for p in session.executed_probes()]
        return inst

    # ── Hypothesis seeding ────────────────────────────────────────────────────

    def seed(
        self,
        kind: str,
        subject: Dict[str, Any],
        claims: List[Dict[str, Any]],
        prior: float = 0.5,
        notes: str = "",
    ) -> List[HypothesisRecord]:
        """Seed a set of competing hypotheses about the same subject.

        Returns the list of created HypothesisRecord objects.
        """
        result = []
        for claim in claims:
            h = HypothesisRecord.create(
                kind=kind,
                subject=subject,
                claim=claim,
                prior=prior,
                notes=notes,
            )
            self.session.add_hypothesis(h)
            result.append(h)
        return result

    def seed_one(
        self,
        kind: str,
        subject: Dict[str, Any],
        claim: Dict[str, Any],
        prior: float = 0.5,
        notes: str = "",
    ) -> HypothesisRecord:
        """Seed a single hypothesis."""
        return self.seed(kind, subject, [claim], prior, notes)[0]

    # ── Evidence addition ─────────────────────────────────────────────────────

    def add_evidence(
        self,
        analyzer: str,
        family: str,
        subject: Dict[str, Any],
        observation: Dict[str, Any],
        relation: str,
        hypothesis_ids: List[str],
        strength: float = 0.5,
        reliability: Optional[float] = None,
        reproducible: bool = True,
        artifact_hashes: Optional[List[str]] = None,
        parameters: Optional[Dict[str, Any]] = None,
        source_location: Optional[Dict[str, Any]] = None,
        notes: str = "",
        probe_id: Optional[str] = None,
    ) -> EvidenceRecord:
        """Record an evidence observation and update affected hypotheses.

        Returns the created EvidenceRecord.
        """
        ev = EvidenceRecord.create(
            analyzer=analyzer,
            family=family,
            subject=subject,
            observation=observation,
            relation=relation,
            hypothesis_ids=hypothesis_ids,
            strength=strength,
            reliability=reliability,
            reproducible=reproducible,
            artifact_hashes=artifact_hashes or [],
            parameters=parameters or {},
            source_location=source_location,
            notes=notes,
        )
        self.session.add_evidence(ev)

        # If this evidence came from a probe, mark the probe result
        if probe_id:
            for p in self.session.probes:
                if p.id == probe_id:
                    if ev.id not in p.result_evidence_ids:
                        p.result_evidence_ids.append(ev.id)

        # Update confidence for all affected hypotheses
        for hid in hypothesis_ids:
            h = self.session.get_hypothesis(hid)
            if h:
                ev_for_h = self.session.evidence_for(hid)
                self._scorer.update_hypothesis(h, ev_for_h)

        return ev

    def add_hard_contradiction(
        self,
        analyzer: str,
        family: str,
        subject: Dict[str, Any],
        observation: Dict[str, Any],
        hypothesis_ids: List[str],
        explanation: str,
        source_location: Optional[Dict[str, Any]] = None,
    ) -> EvidenceRecord:
        """Record a hard contradiction that should reject the named hypotheses."""
        return self.add_evidence(
            analyzer=analyzer,
            family=family,
            subject=subject,
            observation={**observation, "summary": explanation},
            relation=EvidenceRelation.CONTRADICTS,
            hypothesis_ids=hypothesis_ids,
            strength=0.95,
            reliability=0.95,
            source_location=source_location,
            notes=f"HARD CONTRADICTION: {explanation}",
        )

    # ── Planning (dry-run, no execution) ─────────────────────────────────────

    def plan(self, top_n: int = 5) -> str:
        """Rank probes and return a human-readable plan without executing anything."""
        surviving = self.session.surviving_hypotheses()
        return self._ranker.plan_report(
            surviving,
            executed_kinds=self._executed_kinds,
            top_n=top_n,
        )

    def next_probe(self) -> Optional[ProbeRecord]:
        """Return the highest-value probe record without executing it."""
        surviving = self.session.surviving_hypotheses()
        return self._ranker.top_probe(surviving, executed_kinds=self._executed_kinds)

    # ── Stepping (Milestone 3 — approved execution) ───────────────────────────

    def step(
        self,
        kind: Optional[str] = None,
        approved: bool = False,
        max_probes: Optional[int] = None,
    ) -> Optional[ProbeRecord]:
        """Plan one probe step.

        In Milestone 3, this will execute the probe. For now (Milestones 1-2),
        it records the probe in the session and returns it for analyst review.
        The analyst adds evidence via add_evidence() after inspecting the result.

        Args:
            kind:       Force a specific probe kind instead of the top-ranked.
            approved:   Set True to mark the probe as analyst-approved for execution.
            max_probes: Override the session max probe budget.

        Returns:
            The ProbeRecord that was selected, or None if budget exhausted.
        """
        budget = max_probes or self._max_probes
        if len(self.session.executed_probes()) >= budget:
            return None

        surviving = self.session.surviving_hypotheses()
        if not surviving:
            return None

        if kind is not None:
            # Generate probes and find the requested kind
            candidates = self._ranker.generate(
                surviving,
                executed_kinds=self._executed_kinds,
                max_candidates=20,
            )
            probe = next((p for p in candidates if p.kind == kind), None)
            if probe is None:
                # Create a minimal probe for the requested kind
                from .probe_ranker import _PROBE_CATALOG
                meta = _PROBE_CATALOG.get(kind, {"analyzer": kind, "estimated_cost": 1.0})
                probe = ProbeRecord.create(
                    kind=kind,
                    target_hypothesis_ids=[h.id for h in surviving],
                    analyzer=meta.get("analyzer", kind),
                    parameters={"description": meta.get("description", "")},
                    estimated_cost=meta.get("estimated_cost", 1.0),
                )
        else:
            probe = self._ranker.top_probe(surviving, executed_kinds=self._executed_kinds)

        if probe is None:
            return None

        self.session.add_probe(probe)

        if approved and self._ctx is not None:
            # Milestone 3: execute via concrete adapter, feed evidence back into scoring
            evidence_list = _lazy_execute_probe(probe, self._ctx, self.session)
            for ev in evidence_list:
                self.session.add_evidence(ev)
                for hid in ev.hypothesis_ids:
                    h = self.session.get_hypothesis(hid)
                    if h:
                        self._scorer.update_hypothesis(h, self.session.evidence_for(hid))
            probe.mark_executed([ev.id for ev in evidence_list])
            self._executed_kinds.append(probe.kind)
        elif approved:
            # ctx not attached — mark for planning only, analyst adds evidence manually
            self._executed_kinds.append(probe.kind)

        return probe

    def run_until_stable(self, max_steps: int = 8) -> int:
        """Run planning steps until all hypotheses reach a terminal state or budget exhausted.

        Returns the number of steps taken.
        """
        steps = 0
        for _ in range(max_steps):
            surviving = self.session.surviving_hypotheses()
            unresolved = [
                h for h in surviving
                if h.status not in (ConfidenceState.CONFIRMED, ConfidenceState.REJECTED)
            ]
            if not unresolved:
                break
            probe = self.step()
            if probe is None:
                break
            steps += 1
        return steps

    # ── Reporting ──────────────────────────────────────────────────────────────

    def report(self) -> str:
        """Full human-readable session report."""
        lines = [
            "=" * 72,
            "HYPOTHESIS ENGINE REPORT",
            "=" * 72,
            self.session.summary(),
            "",
        ]

        # Group hypotheses by status
        by_status: Dict[str, List[HypothesisRecord]] = {}
        for h in self.session.hypotheses:
            by_status.setdefault(h.status, []).append(h)

        for status in (
            ConfidenceState.CONFIRMED, ConfidenceState.SUPPORTED,
            ConfidenceState.PLAUSIBLE, ConfidenceState.UNRESOLVED,
            ConfidenceState.UNTESTED, ConfidenceState.REJECTED,
        ):
            hs = by_status.get(status, [])
            if not hs:
                continue
            lines.append(f"── {status} ({len(hs)}) " + "─" * (50 - len(status)))
            for h in hs:
                ev = self.session.evidence_for(h.id)
                lines.append(score_report(h, ev, self._scorer))
                lines.append("")

        # Contradiction summary
        all_notes: List[str] = []
        for h in self.session.hypotheses:
            ev = self.session.evidence_for(h.id)
            _, _, notes = self._scorer.score(h, ev)
            all_notes.extend(notes)
        if all_notes:
            lines.append("── HARD CONTRADICTIONS " + "─" * 50)
            for n in all_notes:
                lines.append(f"  ! {n}")
            lines.append("")

        # Probe history
        if self.session.probes:
            lines.append("── PROBE HISTORY " + "─" * 56)
            for p in self.session.probes:
                status_mark = "✓" if p.executed else "○"
                lines.append(
                    f"  {status_mark} [{p.kind}] {p.analyzer}  "
                    f"eig={p.expected_information_gain:.3f}  "
                    f"{'executed' if p.executed else 'pending'}"
                )
            lines.append("")

        lines.append("=" * 72)
        return "\n".join(lines)

    def export_report(self, path: str) -> None:
        """Write the session JSON to path."""
        out = self.session.save(path)
        print(f"Session saved to {out}")

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: Optional[str] = None) -> Path:
        return self.session.save(path)


__all__ = ["HypothesisEngine"]
