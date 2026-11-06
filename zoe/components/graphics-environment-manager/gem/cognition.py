from dataclasses import dataclass
from datetime import datetime, timezone
import re

from .measurement import document_sha256, gem_forecast_context


POLICY_VERSION = "gem-cognitive-v1"
_ALLOWED_COMMANDS = {"snapshot", "resolve", "begin_selected_work", "export"}
_FIELDS = {
    "snapshot": {"command"},
    "resolve": {"command", "reference"},
    "select": {"command", "id", "expected_revision"},
    "begin_selected_work": {"command", "expected_id", "expected_revision", "note"},
    "export": {"command", "expected_revision"},
}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _identifier(value, name):
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("proposal contains duplicate fields")
        result[key] = value
    return result


def _valid_revision(value):
    return not isinstance(value, bool) and isinstance(value, int) and value >= 1


def bind_forecast(report, snapshot, proposal, artifact_path=""):
    context = gem_forecast_context(snapshot, proposal)
    gem_context = report.get("gem_context", {})
    measurement = {
        "schema_version": 1,
        "instrument": "next-token-accessible-volume",
        "measurement_point": "pre_execution",
        "threshold_sweep": report["threshold_sweep"],
        "probability_values_sha256": report["probability_values_sha256"],
    }
    return {
        "schema_version": 1,
        "instrument": "next-token-accessible-volume",
        "context_sha256": document_sha256(context),
        "context_tokens": gem_context.get("context_tokens", 1),
        "input_ids_sha256": report["input_ids_sha256"],
        "model": report["model"],
        "measurement": measurement,
        "artifact": {"path": str(artifact_path)},
    }


def _forecast_reason(forecast):
    if not isinstance(forecast, dict):
        return "forecast_missing"
    if forecast.get("schema_version") != 1:
        return "forecast_schema_invalid"
    if forecast.get("instrument") != "next-token-accessible-volume":
        return "forecast_instrument_invalid"
    if not isinstance(forecast.get("context_sha256"), str) or not _DIGEST.fullmatch(forecast["context_sha256"]):
        return "forecast_context_digest_invalid"
    if not isinstance(forecast.get("context_tokens"), int) or isinstance(forecast["context_tokens"], bool) or forecast["context_tokens"] < 1:
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


def _proposal_reason(proposal, snapshot):
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
        valid_references = {item.get("reference") for item in objects if isinstance(item, dict)}
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


def response_summary(response):
    summary = {"result_type": type(response).__name__}
    if isinstance(response, dict):
        summary["keys"] = sorted(str(key) for key in response)
        if _valid_revision(response.get("revision")):
            summary["revision"] = response["revision"]
        if isinstance(response.get("selected_id"), str):
            summary["selected_id"] = response["selected_id"]
        if isinstance(response.get("last_operation"), dict):
            summary["last_operation"] = response["last_operation"]
    evidence = getattr(response, "evidence", None)
    if isinstance(evidence, dict):
        summary["evidence"] = evidence
    passed = getattr(response, "passed", None)
    if isinstance(passed, bool):
        summary["passed"] = passed
    run = getattr(response, "run", None)
    path = getattr(run, "path", None)
    if path is not None:
        summary["run_path"] = str(path)
    return summary


@dataclass(frozen=True)
class CognitiveResult:
    decision: str
    reason: str
    executed: bool
    succeeded: bool
    events: list
    response: object = None


class CognitiveGuard:
    def __init__(self, broker, approve=False):
        self.broker = broker
        self.approve = bool(approve)
        self.action_ids = set()

    @staticmethod
    def _event(action_id, sequence, event_type, details):
        return {
            "id": f"guard:{action_id}:{sequence:02d}:{event_type}",
            "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "action_id": action_id,
            "sequence": sequence,
            "event_type": event_type,
            "details": details,
        }

    def execute(self, action_id, proposal, forecast):
        action_id = _identifier(action_id, "action_id")
        if action_id in self.action_ids:
            return CognitiveResult("deny", "duplicate_action_id", False, False, [])
        self.action_ids.add(action_id)
        events = [
            self._event(action_id, 1, "model_forecast", forecast),
            self._event(action_id, 2, "action_proposal", {"request": proposal}),
        ]
        snapshot = self.broker.execute({"command": "snapshot"})
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("authoritative"), dict):
            raise ValueError("GEM broker returned an invalid snapshot")
        reason = _forecast_reason(forecast) or _proposal_reason(proposal, snapshot)
        if not reason:
            expected = gem_forecast_context(snapshot, proposal)
            if forecast.get("context_sha256") != document_sha256(expected):
                reason = "forecast_context_mismatch"
        if reason:
            events.append(self._event(action_id, 3, "policy_decision", {
                "policy_version": POLICY_VERSION, "decision": "deny", "reason": reason,
                "snapshot_revision": snapshot["revision"],
            }))
            return CognitiveResult("deny", reason, False, False, events)
        if not self.approve:
            events.append(self._event(action_id, 3, "policy_decision", {
                "policy_version": POLICY_VERSION, "decision": "review", "reason": "approval_required",
                "snapshot_revision": snapshot["revision"],
            }))
            return CognitiveResult("review", "approval_required", False, False, events)
        events.append(self._event(action_id, 3, "policy_decision", {
            "policy_version": POLICY_VERSION, "decision": "allow", "reason": "approved",
            "snapshot_revision": snapshot["revision"],
        }))
        try:
            response = self.broker.execute(proposal)
        except (OSError, RuntimeError, ValueError, TypeError, KeyError) as error:
            events.append(self._event(action_id, 4, "execution_receipt", {
                "status": "failed", "error": str(error)[:1000],
            }))
            return CognitiveResult("allow", "broker_execution_failed", True, False, events)
        events.append(self._event(action_id, 4, "execution_receipt", {
            "status": "succeeded", "result": response_summary(response),
        }))
        return CognitiveResult("allow", "approved", True, True, events, response)
