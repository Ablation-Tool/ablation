"""WorkflowDocument — schema-validated stage output with deterministic routing.

Three gaps this closes:

1. SESSION.md is human-maintained flat markdown with no schema validation on stage
   outputs.  A finding_confirmation missing ``byte_proof`` is not caught until FORGE.

2. Stage routing is implicit in prose.  There is no machine-checkable transition rule
   between triage, sweep, profile, taint, confirmation, and registration.

3. Stage outputs are untyped and context-embedded.  State cannot be observed as a
   structured document or diffed across sessions.

Usage::

    doc = WorkflowDocument.for_re_session("cisco", "fmc_server")

    # validate before writing
    errors = doc.validate("triage", {...})
    if errors:
        raise ValueError(errors)

    # advance: validates, commits, returns next stage names
    next_stages = doc.advance({
        "binary_hash": "abc123", "arch": "arm64", "bits": 64,
        "section_count": 8, "string_count": 1200, "plt_count": 340,
    }, producer_id="session-42")
    # returns ["semantic_sweep"]

    # serialise to disk between sessions
    Path("session.json").write_text(doc.to_json())
    doc2 = WorkflowDocument.from_json(Path("session.json").read_text())

    # detect post-commit mutation
    doc.current().instance["arch"] = "x86_64"  # tampering
    assert doc.dirty_since_commit()
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

_TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "str": str,
    "int": int,
    "float": (int, float),
    "bool": bool,
    "list": list,
    "dict": dict,
}


def _validate_instance(schema: dict[str, Any], instance: dict[str, Any]) -> list[str]:
    """Return validation errors; empty list means the instance is valid.

    Checks ``schema["required"]`` keys for presence and ``schema["properties"]``
    entries for their declared Python type.  No external dependency required.
    """
    errors: list[str] = []
    for key in schema.get("required", []):
        if key not in instance:
            errors.append(f"missing required field: {key!r}")
    for key, spec in schema.get("properties", {}).items():
        if key not in instance:
            continue
        type_name = spec.get("type")
        if type_name and type_name in _TYPE_MAP:
            expected = _TYPE_MAP[type_name]
            if not isinstance(instance[key], expected):
                actual = type(instance[key]).__name__
                errors.append(f"{key!r}: expected {type_name}, got {actual}")
    return errors


@dataclass
class Stage:
    """One stage in a WorkflowDocument pipeline."""

    name: str
    schema: dict[str, Any]
    instance: dict[str, Any] = field(default_factory=dict)
    routing: list[str] = field(default_factory=list)
    committed: bool = False


@dataclass
class StageTransition:
    """Recorded when advance() moves from one stage to the next."""

    from_stage: str
    to_stage: str
    timestamp: str
    producer_id: str


class WorkflowDocument:
    """Schema-validated stage pipeline with deterministic routing.

    State lives in ``stages[i].instance`` — outside LLM context tokens —
    and is observable as a JSON document.  ``advance()`` validates, commits,
    and returns the next stage names.  ``dirty_since_commit()`` detects any
    mutation of committed instances.
    """

    def __init__(self, stages: list[Stage], doc_id: str = "") -> None:
        if not stages:
            raise ValueError("stages list must not be empty")
        self.stages = stages
        self.doc_id = doc_id
        self._current_index: int = 0
        self.log: list[StageTransition] = []
        self._committed_snapshots: dict[str, str] = {}
        self._by_name: dict[str, int] = {s.name: i for i, s in enumerate(stages)}

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def current(self) -> Stage:
        """Return the active (not yet committed) stage."""
        return self.stages[self._current_index]

    def validate(self, stage_name: str, instance: dict[str, Any]) -> list[str]:
        """Validate *instance* against *stage_name*'s schema without advancing.

        Returns a list of error strings.  An empty list means the instance is
        valid and can be passed to ``advance()``.
        """
        if stage_name not in self._by_name:
            return [f"unknown stage: {stage_name!r}"]
        stage = self.stages[self._by_name[stage_name]]
        return _validate_instance(stage.schema, instance)

    def advance(
        self, instance: dict[str, Any], producer_id: str = ""
    ) -> list[str]:
        """Validate *instance*, commit the current stage, and return next stage names.

        Raises ``ValueError`` if the instance does not satisfy the current
        stage's schema.  Returns an empty list when the workflow is complete
        (terminal stage reached).
        """
        stage = self.current()
        errors = _validate_instance(stage.schema, instance)
        if errors:
            raise ValueError(
                f"stage {stage.name!r} validation failed: {errors}"
            )
        stage.instance = instance
        stage.committed = True
        self._committed_snapshots[stage.name] = json.dumps(
            instance, sort_keys=True
        )
        ts = datetime.now(timezone.utc).isoformat()
        for nxt in stage.routing:
            self.log.append(
                StageTransition(
                    from_stage=stage.name,
                    to_stage=nxt,
                    timestamp=ts,
                    producer_id=producer_id,
                )
            )
        if stage.routing and stage.routing[0] in self._by_name:
            self._current_index = self._by_name[stage.routing[0]]
        return list(stage.routing)

    def dirty_since_commit(self) -> bool:
        """Return True if any committed instance has been mutated since commit."""
        for name, snapshot in self._committed_snapshots.items():
            stage = self.stages[self._by_name[name]]
            if json.dumps(stage.instance, sort_keys=True) != snapshot:
                return True
        return False

    def report(self) -> str:
        """Human-readable status table of all stages."""
        lines = [f"WorkflowDocument id={self.doc_id!r}"]
        for s in self.stages:
            if s.committed:
                status = "COMMITTED"
            elif s is self.stages[self._current_index]:
                status = "CURRENT"
            else:
                status = "pending"
            lines.append(
                f"  {s.name:<24} {status:<10}  fields={len(s.instance)}"
            )
        lines.append(f"  transitions logged: {len(self.log)}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """Serialise the full document to a JSON string."""
        return json.dumps(
            {
                "doc_id": self.doc_id,
                "current_index": self._current_index,
                "stages": [asdict(s) for s in self.stages],
                "log": [asdict(t) for t in self.log],
                "committed_snapshots": self._committed_snapshots,
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, s: str) -> "WorkflowDocument":
        """Deserialise a document produced by ``to_json()``."""
        d = json.loads(s)
        stages = [Stage(**st) for st in d["stages"]]
        doc = cls(stages, doc_id=d.get("doc_id", ""))
        doc._current_index = d.get("current_index", 0)
        doc.log = [StageTransition(**t) for t in d.get("log", [])]
        doc._committed_snapshots = d.get("committed_snapshots", {})
        return doc

    # ------------------------------------------------------------------
    # Pre-built factory
    # ------------------------------------------------------------------

    @classmethod
    def for_re_session(cls, vendor: str, target: str) -> "WorkflowDocument":
        """Return the standard six-stage ablation RE pipeline.

        Stages follow the documented tool ordering from CLAUDE.md::

            triage → semantic_sweep → candidate_profile
                   → taint_trace → finding_confirmation → registration
        """
        if not vendor or not target:
            raise ValueError("vendor and target must be non-empty strings")
        stages = [
            Stage(
                name="triage",
                schema={
                    "required": [
                        "binary_hash", "arch", "bits",
                        "section_count", "string_count", "plt_count",
                    ],
                    "properties": {
                        "binary_hash": {"type": "str"},
                        "arch": {"type": "str"},
                        "bits": {"type": "int"},
                        "section_count": {"type": "int"},
                        "string_count": {"type": "int"},
                        "plt_count": {"type": "int"},
                    },
                },
                routing=["semantic_sweep"],
            ),
            Stage(
                name="semantic_sweep",
                schema={
                    "required": ["query", "candidates"],
                    "properties": {
                        "query": {"type": "str"},
                        "candidates": {"type": "list"},
                    },
                },
                routing=["candidate_profile"],
            ),
            Stage(
                name="candidate_profile",
                schema={
                    "required": [
                        "va", "name", "complexity", "call_count", "caller_count",
                    ],
                    "properties": {
                        "va": {"type": "int"},
                        "name": {"type": "str"},
                        "complexity": {"type": "int"},
                        "call_count": {"type": "int"},
                        "caller_count": {"type": "int"},
                    },
                },
                routing=["taint_trace"],
            ),
            Stage(
                name="taint_trace",
                schema={
                    "required": [
                        "source_va", "sink_va", "path_length", "taint_regs",
                    ],
                    "properties": {
                        "source_va": {"type": "int"},
                        "sink_va": {"type": "int"},
                        "path_length": {"type": "int"},
                        "taint_regs": {"type": "list"},
                    },
                },
                routing=["finding_confirmation"],
            ),
            Stage(
                name="finding_confirmation",
                schema={
                    "required": [
                        "va", "cwe", "severity", "title",
                        "description", "byte_proof",
                    ],
                    "properties": {
                        "va": {"type": "int"},
                        "cwe": {"type": "str"},
                        "severity": {"type": "str"},
                        "title": {"type": "str"},
                        "description": {"type": "str"},
                        "byte_proof": {"type": "str"},
                    },
                },
                routing=["registration"],
            ),
            Stage(
                name="registration",
                schema={
                    "required": ["finding_id", "forge_gate_passed"],
                    "properties": {
                        "finding_id": {"type": "int"},
                        "forge_gate_passed": {"type": "bool"},
                    },
                },
                routing=[],
            ),
        ]
        return cls(stages, doc_id=f"{vendor}/{target}")
