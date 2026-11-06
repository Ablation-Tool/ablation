"""Deterministic policy enforcement around GEM's structured command broker."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .forecast import document_sha256, gem_forecast_context


POLICY_VERSION = "gem-command-v1"
SOURCE_TOOL = "cerotto-guard-v1"
_FIELDS = {
    "snapshot": {"command"},
    "resolve": {"command", "reference"},
    "select": {"command", "id", "expected_revision"},
    "begin_selected_work": {"command", "expected_id", "expected_revision", "note"},
    "export": {"command", "expected_revision"},
}
_ALLOWED_COMMANDS = {"snapshot", "resolve", "begin_selected_work", "export"}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("the guard clock must return an aware datetime")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _valid_revision(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 1


def _forecast_reason(forecast: Any) -> str:
    if not isinstance(forecast, dict):
        return "forecast_missing"
    if forecast.get("schema_version") != 1:
        return "forecast_schema_invalid"
    if forecast.get("instrument") != "next-token-accessible-volume":
        return "forecast_instrument_invalid"
    if not isinstance(forecast.get("context_sha256"), str) or not _DIGEST.fullmatch(forecast["context_sha256"]):
        return "forecast_context_digest_invalid"
    if not isinstance(forecast.get("context_tokens"), int) or isinstance(forecast.get("context_tokens"), bool) or forecast["context_tokens"] < 1:
        return "forecast_context_size_invalid"
    if not isinstance(forecast.get("input_ids_sha256"), str) or not _DIGEST.fullmatch(forecast["input_ids_sha256"]):
        return "forecast_input_digest_invalid"
    model = forecast.get("model")
    if not isinstance(model, dict) or not isinstance(model.get("id"), str) or not model["id"]:
        return "forecast_model_invalid"
    measurement = forecast.get("measurement")
    if not isinstance(measurement, dict) or measurement.get("schema_version") != 1:
        return "forecast_measurement_invalid"
    if measurement.get("measurement_point") != "pre_execution":
        return "forecast_measurement_point_invalid"
    if not isinstance(measurement.get("threshold_sweep"), list) or not measurement["threshold_sweep"]:
        return "forecast_sweep_missing"
    if not isinstance(measurement.get("probability_values_sha256"), str) or not _DIGEST.fullmatch(measurement["probability_values_sha256"]):
        return "forecast_probability_digest_invalid"
    return ""


def _proposal_reason(proposal: Any, snapshot: dict[str, Any]) -> str:
    if not isinstance(proposal, dict) or not isinstance(proposal.get("command"), str):
        return "proposal_schema_invalid"
    command = proposal["command"]
    if command not in _FIELDS:
        return "command_not_supported"
    if set(proposal) - _FIELDS[command]:
        return "command_fields_not_supported"
    if command not in _ALLOWED_COMMANDS:
        return "command_requires_external_authorization"
    authoritative = snapshot["authoritative"]
    if command == "resolve":
        reference = proposal.get("reference")
        objects = snapshot.get("derived", {}).get("objects", [])
        valid_references = {
            item.get("reference") for item in objects if isinstance(item, dict)
        }
        if not isinstance(reference, str) or reference not in valid_references:
            return "reference_outside_current_snapshot"
    if command in {"begin_selected_work", "export"}:
        if not _valid_revision(proposal.get("expected_revision")):
            return "expected_revision_required"
        if proposal["expected_revision"] != snapshot["revision"]:
            return "stale_selection_revision"
    if command == "begin_selected_work":
        if proposal.get("expected_id") != authoritative["selected_id"]:
            return "selected_event_changed"
        note = proposal.get("note")
        if note is not None and (not isinstance(note, str) or len(note) > 4000):
            return "note_invalid"
    return ""


def _result_summary(result: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {"result_type": type(result).__name__}
    if isinstance(result, dict):
        summary["keys"] = sorted(str(key) for key in result)
        if _valid_revision(result.get("revision")):
            summary["revision"] = result["revision"]
        if isinstance(result.get("selected_id"), str):
            summary["selected_id"] = result["selected_id"]
        if isinstance(result.get("last_operation"), dict):
            summary["last_operation"] = result["last_operation"]
    evidence = getattr(result, "evidence", None)
    if isinstance(evidence, dict):
        summary["evidence"] = evidence
    passed = getattr(result, "passed", None)
    if isinstance(passed, bool):
        summary["passed"] = passed
    run = getattr(result, "run", None)
    path = getattr(run, "path", None)
    if path is not None:
        summary["run_path"] = str(path)
    return summary


@dataclass(frozen=True)
class GuardResult:
    decision: str
    reason: str
    executed: bool
    succeeded: bool
    events: list[dict[str, Any]]
    response: Any = None


class GuardedGemBroker:
    def __init__(
        self,
        broker: Any,
        host_id: str,
        conversation_id: str,
        clock: Callable[[], datetime] = utc_now,
    ):
        self.broker = broker
        self.host_id = _identifier(host_id, "host_id")
        self.conversation_id = _identifier(conversation_id, "conversation_id")
        self.clock = clock

    def _event(
        self,
        action_id: str,
        sequence: int,
        event_type: str,
        details: dict[str, Any],
        prompt_id: str,
        path: str = "",
    ) -> dict[str, Any]:
        return {
            "id": f"guard:{action_id}:{sequence:02d}:{event_type}",
            "observed_at": _timestamp(self.clock()),
            "host_id": self.host_id,
            "source_tool": SOURCE_TOOL,
            "event_type": event_type,
            "conversation_id": self.conversation_id,
            "prompt_id": prompt_id,
            "tool_call_id": action_id,
            "path": path,
            "details": details,
        }

    def execute(self, action_id: str, proposal: dict[str, Any], forecast: dict[str, Any]) -> GuardResult:
        action_id = _identifier(action_id, "action_id")
        forecast_reason = _forecast_reason(forecast)
        claimed_context = forecast.get("context_sha256", "") if isinstance(forecast, dict) else ""
        artifact = forecast.get("artifact", {}) if isinstance(forecast, dict) else {}
        artifact_path = artifact.get("path", "") if isinstance(artifact, dict) else ""
        if not isinstance(artifact_path, str) or len(artifact_path) > 4096:
            raise ValueError("forecast artifact path is invalid")
        forecast_details = forecast if isinstance(forecast, dict) else {"invalid_forecast_type": type(forecast).__name__}
        events = [self._event(action_id, 1, "model_forecast", forecast_details, claimed_context, artifact_path)]
        proposal_details = {"request": proposal} if isinstance(proposal, dict) else {"invalid_request_type": type(proposal).__name__}
        events.append(self._event(action_id, 2, "action_proposal", proposal_details, claimed_context))
        snapshot = self.broker.execute({"command": "snapshot"})
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("authoritative"), dict):
            raise ValueError("GEM broker returned an invalid snapshot")
        reason = forecast_reason or _proposal_reason(proposal, snapshot)
        if not reason:
            expected_context = gem_forecast_context(snapshot, proposal)
            if claimed_context != document_sha256(expected_context):
                reason = "forecast_context_mismatch"
        decision = "deny" if reason else "allow"
        events.append(self._event(action_id, 3, "policy_decision", {
            "policy_version": POLICY_VERSION,
            "decision": decision,
            "reason": reason or "authorized",
            "forecast_verification": "context_bound" if not forecast_reason else "invalid",
            "snapshot_revision": snapshot["revision"],
        }, claimed_context))
        if reason:
            return GuardResult(decision, reason, False, False, events)
        try:
            response = self.broker.execute(proposal)
        except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
            events.append(self._event(action_id, 4, "execution_receipt", {
                "status": "failed",
                "error": str(exc)[:1000],
            }, claimed_context))
            return GuardResult(decision, "broker_execution_failed", True, False, events)
        events.append(self._event(action_id, 4, "execution_receipt", {
            "status": "succeeded",
            "result": _result_summary(response),
        }, claimed_context))
        return GuardResult(decision, "authorized", True, True, events, response)
