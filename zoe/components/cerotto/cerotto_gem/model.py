"""Read-only case and defense-event model for the CEROTTO GEM workbench."""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import json
import math
from pathlib import Path
import sqlite3
from typing import Any


MAX_CASE_EVENTS = 10_000


class CaseModelError(RuntimeError):
    pass


@dataclass(frozen=True)
class EvidenceSource:
    source_id: int
    kind: str
    origin_path: str
    sha256: str
    status: str


@dataclass(frozen=True)
class CaseEvent:
    event_id: str
    observed_at: str
    host_id: str
    source_tool: str
    event_type: str
    conversation_id: str
    prompt_id: str
    tool_call_id: str
    path: str
    source_id: int | None
    details: dict[str, Any]

    @property
    def label(self) -> str:
        if self.source_tool == "cerotto.vault":
            detail = self.details.get("source_detail", {})
            name = self.path.rsplit("/", 1)[-1] or self.path or "(no path)"
            if self.event_type.startswith("file."):
                return f"{self.event_type[5:]}: {name}"
            if self.event_type.startswith("sensor."):
                return f"Sensor: {detail.get('reason', self.event_type[7:])}"
            if self.event_type.startswith("release."):
                return f"Release: {detail.get('cleanup_result', self.event_type[8:])}"
            if self.event_type.startswith("response."):
                return f"Response: {detail.get('action', self.event_type[9:])}"
            return f"Vault: {self.event_type.replace('_', ' ')}"
        if self.event_type == "model_forecast":
            return "Accessible-volume forecast"
        if self.event_type == "action_proposal":
            return f"Proposal: {self.details.get('action', self.details.get('request', 'action'))}"
        if self.event_type == "policy_decision":
            return f"Policy: {self.details.get('reason', self.details.get('decision', 'decision'))}"
        if self.event_type == "execution_receipt":
            return f"Execution: {self.details.get('status', 'recorded')}"
        if self.event_type == "gem_investigation_event":
            event = self.details.get("gem_event", {})
            return str(event.get("label", event.get("id", self.event_id)))
        return self.event_type.replace("_", " ")

    @property
    def status(self) -> str:
        if self.source_tool == "cerotto.vault":
            if self.event_type in {"file.open", "file.read"}:
                return "contact"
            if self.event_type.startswith("file."):
                return "modified"
            if self.event_type in {"sensor.queue_overflow", "sensor.degraded", "sensor.clock_change"}:
                return "degraded"
            if self.event_type == "release.denied":
                return "denied"
            if self.event_type == "release.approved":
                return "released"
            if self.event_type.startswith("release.cleanup"):
                return "cleanup"
            if self.event_type == "response.suspended":
                return "suspended"
            if self.event_type == "response.resumed":
                return "resumed"
            return "recorded"
        if self.event_type == "model_forecast":
            return "measured"
        if self.event_type == "action_proposal":
            return "proposed"
        if self.event_type == "policy_decision":
            return str(self.details.get("decision", "recorded"))
        if self.event_type == "execution_receipt":
            return str(self.details.get("status", "recorded"))
        if self.event_type == "gem_investigation_event":
            return str(self.details.get("gem_event", {}).get("status", "recorded"))
        return "recorded"

    @property
    def accessible_volume(self) -> list[tuple[float, int, float]]:
        measurement = self.details.get("measurement", self.details)
        sweep = measurement.get("threshold_sweep", []) if isinstance(measurement, dict) else []
        if not isinstance(sweep, list):
            raise CaseModelError(f"invalid threshold sweep in {self.event_id}")
        series = []
        for entry in sweep:
            if not isinstance(entry, dict):
                raise CaseModelError(f"invalid threshold entry in {self.event_id}")
            tau = entry.get("tau")
            count = entry.get("accessible_volume")
            normalized = entry.get("normalized_accessible_volume")
            if any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in (tau, count, normalized)):
                raise CaseModelError(f"invalid threshold values in {self.event_id}")
            if not all(math.isfinite(float(value)) for value in (tau, count, normalized)):
                raise CaseModelError(f"non-finite threshold values in {self.event_id}")
            if not 0 < tau < 1 or count < 0 or int(count) != count or normalized < 0:
                raise CaseModelError(f"out-of-range threshold values in {self.event_id}")
            series.append((float(tau), int(count), float(normalized)))
        if any(left[0] >= right[0] for left, right in zip(series, series[1:])):
            raise CaseModelError(f"non-increasing thresholds in {self.event_id}")
        return series

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "observed_at": self.observed_at,
            "host_id": self.host_id,
            "source_tool": self.source_tool,
            "event_type": self.event_type,
            "conversation_id": self.conversation_id,
            "prompt_id": self.prompt_id,
            "tool_call_id": self.tool_call_id,
            "source_id": self.source_id,
            "path": self.path,
            "details": self.details,
        }


@dataclass(frozen=True)
class CaseSnapshot:
    case_id: str
    conversation_id: str
    events: tuple[CaseEvent, ...]
    sources: tuple[EvidenceSource, ...]


class CaseModel:
    def __init__(self, database: str | Path, case_id: str, conversation_id: str, limit: int = MAX_CASE_EVENTS):
        self.database = Path(database).expanduser().resolve()
        self.case_id = case_id
        self.conversation_id = conversation_id
        if not case_id or not conversation_id:
            raise ValueError("case and conversation identifiers are required")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_CASE_EVENTS:
            raise ValueError("case event limit must be between 1 and 10000")
        self.limit = limit

    def _connect(self) -> sqlite3.Connection:
        if not self.database.is_file():
            raise CaseModelError(f"case database not found: {self.database}")
        uri = self.database.as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return connection

    def load(self) -> CaseSnapshot:
        with closing(self._connect()) as connection:
            if not connection.execute("SELECT 1 FROM cases WHERE id=?", (self.case_id,)).fetchone():
                raise CaseModelError(f"case not found: {self.case_id}")
            event_rows = connection.execute(
                "SELECT id,source_id,observed_at,host_id,source_tool,event_type,conversation_id,"
                "prompt_id,tool_call_id,path,details_json FROM events "
                "WHERE case_id=?1 AND (conversation_id=?2 OR host_id IN "
                "(SELECT DISTINCT host_id FROM events WHERE case_id=?1 AND conversation_id=?2)) "
                "ORDER BY observed_at,id LIMIT ?",
                (self.case_id, self.conversation_id, self.limit),
            ).fetchall()
            source_rows = connection.execute(
                "SELECT id,kind,origin_path,sha256,status FROM evidence_sources WHERE case_id=? ORDER BY id",
                (self.case_id,),
            ).fetchall()
        events = []
        for row in event_rows:
            try:
                details = json.loads(row["details_json"])
            except json.JSONDecodeError as exc:
                raise CaseModelError(f"invalid stored details for {row['id']}") from exc
            if not isinstance(details, dict):
                raise CaseModelError(f"stored details are not an object for {row['id']}")
            events.append(CaseEvent(
                event_id=row["id"], observed_at=row["observed_at"], host_id=row["host_id"],
                source_tool=row["source_tool"], event_type=row["event_type"],
                conversation_id=row["conversation_id"], prompt_id=row["prompt_id"],
                tool_call_id=row["tool_call_id"], path=row["path"], source_id=row["source_id"],
                details=details,
            ))
        sources = tuple(EvidenceSource(
            source_id=row["id"], kind=row["kind"], origin_path=row["origin_path"],
            sha256=row["sha256"], status=row["status"],
        ) for row in source_rows)
        return CaseSnapshot(self.case_id, self.conversation_id, tuple(events), sources)
