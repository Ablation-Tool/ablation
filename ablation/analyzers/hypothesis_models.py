"""
hypothesis_models.py — Data model for the Active Hypothesis Engine.

Implements Milestone 1 of the Active Architecture Tomography plan:
HypothesisRecord, EvidenceRecord, ProbeRecord, and HypothesisSession
with JSON serialization and deterministic IDs.

Design rules from active-hypothesis-engine-plan.md:
- Hypotheses are structured data, not free-form text.
- Evidence items carry analyzer provenance and an evidence family.
- Evidence from the same family does not double-count.
- CONFIRMED requires a decisive test — not just a high confidence float.
- Every session is reproducible from binary hashes + probe parameters.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Confidence states ─────────────────────────────────────────────────────────

class ConfidenceState(str, Enum):
    UNTESTED      = "UNTESTED"      # no meaningful evidence
    PLAUSIBLE     = "PLAUSIBLE"     # weak or single-family support
    SUPPORTED     = "SUPPORTED"     # multiple independent families agree
    CONFIRMED     = "CONFIRMED"     # decisive test or trusted ground truth
    UNRESOLVED    = "UNRESOLVED"    # two or more hypotheses observationally equivalent
    REJECTED      = "REJECTED"      # hard contradiction


# ── Evidence relation ──────────────────────────────────────────────────────────

class EvidenceRelation(str, Enum):
    SUPPORTS     = "supports"
    CONTRADICTS  = "contradicts"
    NEUTRAL      = "neutral"


# ── Evidence families ─────────────────────────────────────────────────────────
# Evidence from the same family must not be counted as independent.

EVIDENCE_FAMILIES = {
    "structure":      0.75,  # CFG, instruction boundaries, branch targets
    "cross_reference": 0.65, # strings, PLT, imports, callers, callees
    "data_flow":      0.90,  # taint, use-def chains, source-to-sink paths
    "semantic":       0.25,  # embeddings, function similarity, labels
    "version":        0.60,  # Jaccard, DTW, structural homologs
    "behavioral":     1.00,  # runtime traces, emulator output, test vectors
    "manual":         0.50,  # analyst observation with provenance
}


# ── Hypothesis kinds ──────────────────────────────────────────────────────────

HYPOTHESIS_KINDS = frozenset({
    "code_region",
    "data_region",
    "function_entry",
    "function_boundary",
    "indirect_call_target",
    "memory_region",
    "input_source",
    "security_sink",
    "source_to_sink_path",
    "version_homolog",
    "architecture_mode",
})


# ── ID generation ──────────────────────────────────────────────────────────────

def _make_id(prefix: str, content: Any) -> str:
    """Deterministic short ID from content hash."""
    digest = hashlib.sha256(json.dumps(content, sort_keys=True, default=str).encode()).hexdigest()
    return f"{prefix}-{digest[:12]}"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ── HypothesisRecord ──────────────────────────────────────────────────────────

@dataclass
class HypothesisRecord:
    """A typed, testable claim about an artifact."""

    id: str
    kind: str                   # one of HYPOTHESIS_KINDS
    subject: Dict[str, Any]     # what the hypothesis is about (e.g. {"va": "0x401920"})
    claim: Dict[str, Any]       # the specific claim (machine-readable)
    assumptions: List[Dict[str, Any]] = field(default_factory=list)
    status: str = ConfidenceState.UNTESTED
    prior: float = 0.5
    support_score: float = 0.0
    contradiction_score: float = 0.0
    uncertainty_score: float = 0.0
    confidence: float = 0.0
    evidence_ids: List[str] = field(default_factory=list)
    parent_id: Optional[str] = None
    notes: str = ""
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    @classmethod
    def create(
        cls,
        kind: str,
        subject: Dict[str, Any],
        claim: Dict[str, Any],
        prior: float = 0.5,
        notes: str = "",
        parent_id: Optional[str] = None,
    ) -> "HypothesisRecord":
        if kind not in HYPOTHESIS_KINDS:
            raise ValueError(f"Unknown hypothesis kind: {kind!r}. Valid: {sorted(HYPOTHESIS_KINDS)}")
        hid = _make_id("H", {"kind": kind, "subject": subject, "claim": claim})
        now = _now()
        return cls(
            id=hid,
            kind=kind,
            subject=subject,
            claim=claim,
            prior=prior,
            confidence=prior,
            notes=notes,
            parent_id=parent_id,
            created_at=now,
            updated_at=now,
        )

    def touch(self) -> None:
        self.updated_at = _now()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HypothesisRecord":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── EvidenceRecord ────────────────────────────────────────────────────────────

@dataclass
class EvidenceRecord:
    """An observation produced by a named analyzer or manually recorded."""

    id: str
    analyzer: str               # module name that produced this (e.g. "ARM64TaintTracker")
    family: str                 # one of EVIDENCE_FAMILIES
    subject: Dict[str, Any]     # what was analyzed
    observation: Dict[str, Any] # the concrete observation
    relation: str               # EvidenceRelation value
    hypothesis_ids: List[str] = field(default_factory=list)
    strength: float = 0.5       # analyzer-local, [0, 1]
    reliability: float = 0.75   # analyzer calibration, [0, 1]
    reproducible: bool = True
    artifact_hashes: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    source_location: Optional[Dict[str, Any]] = None
    notes: str = ""
    created_at: str = field(default_factory=_now)

    @classmethod
    def create(
        cls,
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
    ) -> "EvidenceRecord":
        if family not in EVIDENCE_FAMILIES:
            raise ValueError(f"Unknown evidence family: {family!r}. Valid: {sorted(EVIDENCE_FAMILIES)}")
        if relation not in (e.value for e in EvidenceRelation):
            raise ValueError(f"Unknown evidence relation: {relation!r}")
        eid = _make_id("E", {"analyzer": analyzer, "family": family, "subject": subject, "observation": observation})
        return cls(
            id=eid,
            analyzer=analyzer,
            family=family,
            subject=subject,
            observation=observation,
            relation=relation,
            hypothesis_ids=list(hypothesis_ids),
            strength=max(0.0, min(1.0, strength)),
            reliability=reliability if reliability is not None else EVIDENCE_FAMILIES.get(family, 0.5),
            reproducible=reproducible,
            artifact_hashes=list(artifact_hashes or []),
            parameters=dict(parameters or {}),
            source_location=source_location,
            notes=notes,
            created_at=_now(),
        )

    def contribution(self, independence_factor: float = 1.0) -> float:
        """Evidence contribution toward a hypothesis score."""
        return self.strength * self.reliability * independence_factor

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceRecord":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── ProbeRecord ───────────────────────────────────────────────────────────────

@dataclass
class ProbeRecord:
    """An analysis action selected to discriminate between surviving hypotheses."""

    id: str
    kind: str                           # "cfg", "xref", "taint", "semantic", "version", "manual"
    target_hypothesis_ids: List[str]    # which hypotheses this probe targets
    analyzer: str                       # which analyzer will run the probe
    parameters: Dict[str, Any] = field(default_factory=dict)
    estimated_cost: float = 1.0         # relative cost (lower = cheaper)
    observability: float = 0.8          # how clear/machine-checkable the result will be
    predicted_disagreement: float = 0.5 # how differently the hypotheses predict the result
    expected_information_gain: float = 0.0  # computed by probe ranker
    executed: bool = False
    result_evidence_ids: List[str] = field(default_factory=list)
    notes: str = ""
    created_at: str = field(default_factory=_now)
    executed_at: Optional[str] = None

    @classmethod
    def create(
        cls,
        kind: str,
        target_hypothesis_ids: List[str],
        analyzer: str,
        parameters: Optional[Dict[str, Any]] = None,
        estimated_cost: float = 1.0,
        observability: float = 0.8,
        predicted_disagreement: float = 0.5,
        notes: str = "",
    ) -> "ProbeRecord":
        pid = _make_id("P", {"kind": kind, "analyzer": analyzer, "parameters": parameters or {}})
        eig = (predicted_disagreement * observability) / max(estimated_cost, 1e-6)
        return cls(
            id=pid,
            kind=kind,
            target_hypothesis_ids=list(target_hypothesis_ids),
            analyzer=analyzer,
            parameters=dict(parameters or {}),
            estimated_cost=estimated_cost,
            observability=observability,
            predicted_disagreement=predicted_disagreement,
            expected_information_gain=eig,
            notes=notes,
            created_at=_now(),
        )

    def mark_executed(self, evidence_ids: List[str]) -> None:
        self.executed = True
        self.executed_at = _now()
        self.result_evidence_ids = list(evidence_ids)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ProbeRecord":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── HypothesisSession ─────────────────────────────────────────────────────────

@dataclass
class HypothesisSession:
    """A complete hypothesis-driven analysis session for one binary."""

    session_id: str
    binary_sha256: str
    binary_path: str
    architecture: Optional[str] = None
    hypotheses: List[HypothesisRecord] = field(default_factory=list)
    evidence: List[EvidenceRecord] = field(default_factory=list)
    probes: List[ProbeRecord] = field(default_factory=list)
    configuration: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    @classmethod
    def create(
        cls,
        binary_path: str,
        architecture: Optional[str] = None,
        configuration: Optional[Dict[str, Any]] = None,
    ) -> "HypothesisSession":
        path = Path(binary_path)
        if path.exists():
            sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            sha256 = "unknown"
        sid = _make_id("S", {"binary_path": str(path), "sha256": sha256, "ts": _now()})
        now = _now()
        return cls(
            session_id=sid,
            binary_sha256=sha256,
            binary_path=str(path),
            architecture=architecture,
            configuration=dict(configuration or {}),
            created_at=now,
            updated_at=now,
        )

    # ── Hypothesis management ─────────────────────────────────────────────────

    def add_hypothesis(self, h: HypothesisRecord) -> None:
        self.hypotheses.append(h)
        self.updated_at = _now()

    def get_hypothesis(self, hid: str) -> Optional[HypothesisRecord]:
        for h in self.hypotheses:
            if h.id == hid:
                return h
        return None

    def surviving_hypotheses(self) -> List[HypothesisRecord]:
        """Hypotheses not yet REJECTED."""
        return [h for h in self.hypotheses if h.status != ConfidenceState.REJECTED]

    def confirmed_hypotheses(self) -> List[HypothesisRecord]:
        return [h for h in self.hypotheses if h.status == ConfidenceState.CONFIRMED]

    # ── Evidence management ───────────────────────────────────────────────────

    def add_evidence(self, e: EvidenceRecord) -> None:
        self.evidence.append(e)
        self.updated_at = _now()

    def evidence_for(self, hypothesis_id: str) -> List[EvidenceRecord]:
        return [e for e in self.evidence if hypothesis_id in e.hypothesis_ids]

    def evidence_by_family(self, hypothesis_id: str) -> Dict[str, List[EvidenceRecord]]:
        """Group evidence for a hypothesis by family."""
        families: Dict[str, List[EvidenceRecord]] = {}
        for e in self.evidence_for(hypothesis_id):
            families.setdefault(e.family, []).append(e)
        return families

    # ── Probe management ──────────────────────────────────────────────────────

    def add_probe(self, p: ProbeRecord) -> None:
        self.probes.append(p)
        self.updated_at = _now()

    def pending_probes(self) -> List[ProbeRecord]:
        return [p for p in self.probes if not p.executed]

    def executed_probes(self) -> List[ProbeRecord]:
        return [p for p in self.probes if p.executed]

    # ── Persistence ───────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id":   self.session_id,
            "binary_sha256": self.binary_sha256,
            "binary_path":  self.binary_path,
            "architecture": self.architecture,
            "hypotheses":   [h.to_dict() for h in self.hypotheses],
            "evidence":     [e.to_dict() for e in self.evidence],
            "probes":       [p.to_dict() for p in self.probes],
            "configuration": self.configuration,
            "created_at":   self.created_at,
            "updated_at":   self.updated_at,
        }

    def save(self, path: Optional[str] = None) -> Path:
        """Persist session to JSON. Default path: ~/.ablation/sessions/<session_id>.json"""
        if path is None:
            sessions_dir = Path.home() / ".ablation" / "sessions"
            sessions_dir.mkdir(parents=True, exist_ok=True)
            out = sessions_dir / f"{self.session_id}.json"
        else:
            out = Path(path)
        self.updated_at = _now()
        out.write_text(json.dumps(self.to_dict(), indent=2))
        return out

    @classmethod
    def load(cls, path: str) -> "HypothesisSession":
        d = json.loads(Path(path).read_text())
        return cls.from_dict(d)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HypothesisSession":
        sess = cls(
            session_id=d["session_id"],
            binary_sha256=d["binary_sha256"],
            binary_path=d["binary_path"],
            architecture=d.get("architecture"),
            configuration=d.get("configuration", {}),
            created_at=d.get("created_at", _now()),
            updated_at=d.get("updated_at", _now()),
        )
        sess.hypotheses = [HypothesisRecord.from_dict(h) for h in d.get("hypotheses", [])]
        sess.evidence   = [EvidenceRecord.from_dict(e) for e in d.get("evidence", [])]
        sess.probes     = [ProbeRecord.from_dict(p) for p in d.get("probes", [])]
        return sess

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> str:
        counts: Dict[str, int] = {}
        for h in self.hypotheses:
            counts[h.status] = counts.get(h.status, 0) + 1
        status_str = "  ".join(f"{s}:{n}" for s, n in sorted(counts.items()))
        return (
            f"Session {self.session_id[:16]}  binary={Path(self.binary_path).name}\n"
            f"  hypotheses={len(self.hypotheses)} [{status_str}]\n"
            f"  evidence={len(self.evidence)}  probes={len(self.probes)} "
            f"(pending={len(self.pending_probes())})"
        )


__all__ = [
    "ConfidenceState", "EvidenceRelation", "EVIDENCE_FAMILIES", "HYPOTHESIS_KINDS",
    "HypothesisRecord", "EvidenceRecord", "ProbeRecord", "HypothesisSession",
]
