#!/usr/bin/env python3
import copy
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from investigation.forecast import (
    document_sha256,
    gem_forecast_context,
    input_ids_sha256,
    measure_accessible_volume,
    probabilities_from_logits,
)
from investigation.gem_events import export_gem_events, write_jsonl_new
from investigation.guard import GuardedGemBroker


BINARY = Path(os.environ.get("CEROTTO_BIN", ROOT / "build" / "cerotto")).resolve()
PROBABILITIES = [0.40, 0.20, 0.12, 0.06, 0.04] + [0.02] * 9


def snapshot():
    return {
        "schema_version": 1,
        "environment": "gem",
        "revision": 3,
        "authoritative": {
            "target": "/bin/true",
            "selected_id": "artifact:abc",
            "events": [{"id": "artifact:abc", "type": "artifact"}],
        },
        "derived": {
            "objects": [
                {"reference": "investigation:artifact:abc", "id": "artifact:abc"},
                {"reference": "spatial:scene:object", "id": "object"},
            ],
        },
    }


def forecast(context):
    return {
        "schema_version": 1,
        "instrument": "next-token-accessible-volume",
        "context_sha256": document_sha256(context),
        "context_tokens": 3,
        "input_ids_sha256": input_ids_sha256([1, 2, 3]),
        "model": {"id": "test-model"},
        "measurement": measure_accessible_volume(PROBABILITIES),
    }


class FakeBroker:
    def __init__(self):
        self.state = snapshot()
        self.calls = []
        self.fail_command = ""

    def execute(self, request):
        self.calls.append(copy.deepcopy(request))
        command = request["command"]
        if command == self.fail_command:
            raise RuntimeError("injected broker failure")
        if command == "snapshot":
            return copy.deepcopy(self.state)
        if command == "resolve":
            return {"kind": "investigation", "object": {"id": request["reference"]}}
        if command == "begin_selected_work":
            return {
                "revision": self.state["revision"] + 1,
                "selected_id": self.state["authoritative"]["selected_id"],
                "last_operation": {"type": "begin_selected_work"},
            }
        if command == "export":
            return {"passed": True, "revision": self.state["revision"]}
        raise ValueError("unexpected command")


class Clock:
    def __init__(self):
        self.value = datetime(2026, 11, 3, 13, 0, tzinfo=timezone.utc)

    def __call__(self):
        result = self.value
        self.value += timedelta(microseconds=1)
        return result


class ForecastTests(unittest.TestCase):
    def test_reference_distribution_and_strict_threshold(self):
        result = measure_accessible_volume(PROBABILITIES)
        self.assertEqual([item["accessible_volume"] for item in result["threshold_sweep"]], [5, 4, 3, 2, 1, 0])
        self.assertEqual(result["vocabulary_size"], 14)
        self.assertEqual(result["max_probability"], 0.40)
        self.assertTrue(math.isclose(result["probability_sum"], 1.0))
        self.assertTrue(all(
            left["accessible_volume"] >= right["accessible_volume"]
            for left, right in zip(result["threshold_sweep"], result["threshold_sweep"][1:])
        ))

    def test_logits_and_distribution_validation(self):
        probabilities = probabilities_from_logits([0.0, 0.0, 0.0])
        self.assertTrue(math.isclose(math.fsum(probabilities), 1.0))
        self.assertEqual(probabilities, [1 / 3] * 3)
        for invalid in ([0.5, -0.1, 0.6], [0.5, 0.4], [math.nan, 1.0], [True, False]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                measure_accessible_volume(invalid)
        with self.assertRaisesRegex(ValueError, "strictly increasing"):
            measure_accessible_volume([0.5, 0.5], [0.1, 0.1])

    def test_context_binds_target_revision_and_proposal(self):
        base = gem_forecast_context(snapshot(), {"command": "snapshot"})
        changed = gem_forecast_context(snapshot(), {"command": "export", "expected_revision": 3})
        self.assertNotEqual(document_sha256(base), document_sha256(changed))
        revised = snapshot()
        revised["revision"] += 1
        self.assertNotEqual(
            document_sha256(base),
            document_sha256(gem_forecast_context(revised, {"command": "snapshot"})),
        )


class GuardTests(unittest.TestCase):
    def guard(self, broker):
        return GuardedGemBroker(broker, "agent-vm-1", "conv-7", Clock())

    def execute(self, broker, proposal, state=None, action_id="action-1"):
        context = gem_forecast_context(state or broker.state, proposal)
        return self.guard(broker).execute(action_id, proposal, forecast(context))

    def test_allowed_action_has_complete_evidence_chain(self):
        broker = FakeBroker()
        result = self.execute(broker, {"command": "snapshot"})
        self.assertTrue(result.succeeded)
        self.assertEqual([event["event_type"] for event in result.events], [
            "model_forecast", "action_proposal", "policy_decision", "execution_receipt",
        ])
        self.assertEqual(len(broker.calls), 2)
        self.assertEqual(result.events[2]["details"]["forecast_verification"], "context_bound")
        self.assertEqual(len({event["prompt_id"] for event in result.events}), 1)
        self.assertEqual(len({event["tool_call_id"] for event in result.events}), 1)

    def test_revision_checked_begin_and_export_execute(self):
        for proposal in (
            {"command": "begin_selected_work", "expected_id": "artifact:abc", "expected_revision": 3},
            {"command": "export", "expected_revision": 3},
        ):
            with self.subTest(proposal=proposal):
                broker = FakeBroker()
                result = self.execute(broker, proposal)
                self.assertTrue(result.succeeded, result.reason)
                self.assertEqual(broker.calls[-1], proposal)

    def test_unknown_and_uncontrolled_selection_commands_do_not_execute(self):
        for proposal in ({"command": "shell"}, {"command": "select", "id": "artifact:abc", "expected_revision": 3}):
            with self.subTest(proposal=proposal):
                broker = FakeBroker()
                result = self.execute(broker, proposal)
                self.assertEqual(result.decision, "deny")
                self.assertFalse(result.executed)
                self.assertEqual(len(broker.calls), 1)
                self.assertEqual(len(result.events), 3)

    def test_stale_revision_and_changed_selection_are_denied(self):
        proposals = [
            {"command": "begin_selected_work", "expected_id": "artifact:abc", "expected_revision": 2},
            {"command": "begin_selected_work", "expected_id": "artifact:other", "expected_revision": 3},
            {"command": "export"},
        ]
        for proposal in proposals:
            with self.subTest(proposal=proposal):
                broker = FakeBroker()
                result = self.execute(broker, proposal)
                self.assertEqual(result.decision, "deny")
                self.assertFalse(result.executed)

    def test_forecast_substitution_and_invalid_forecast_are_denied(self):
        broker = FakeBroker()
        proposal = {"command": "snapshot"}
        other = gem_forecast_context(snapshot(), {"command": "export", "expected_revision": 3})
        result = self.guard(broker).execute("action-1", proposal, forecast(other))
        self.assertEqual(result.reason, "forecast_context_mismatch")
        self.assertFalse(result.executed)
        broker = FakeBroker()
        invalid = forecast(gem_forecast_context(broker.state, proposal))
        invalid["measurement"]["threshold_sweep"] = []
        result = self.guard(broker).execute("action-1", proposal, invalid)
        self.assertEqual(result.reason, "forecast_sweep_missing")
        self.assertFalse(result.executed)
        result = self.guard(broker).execute("action-1", proposal, [])
        self.assertEqual(result.reason, "forecast_missing")
        self.assertEqual(result.events[0]["details"], {"invalid_forecast_type": "list"})

    def test_out_of_scope_reference_is_denied(self):
        broker = FakeBroker()
        result = self.execute(broker, {"command": "resolve", "reference": "investigation:invented"})
        self.assertEqual(result.reason, "reference_outside_current_snapshot")
        self.assertFalse(result.executed)

    def test_broker_failure_is_not_a_success_receipt(self):
        broker = FakeBroker()
        broker.fail_command = "begin_selected_work"
        result = self.execute(broker, {
            "command": "begin_selected_work", "expected_id": "artifact:abc", "expected_revision": 3,
        })
        self.assertTrue(result.executed)
        self.assertFalse(result.succeeded)
        self.assertEqual(result.events[-1]["details"]["status"], "failed")


class CerottoIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cerotto-defense-test-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.db = self.root / "case.db"
        self.assertTrue(BINARY.is_file())
        self.cli("init", "--db", self.db)

    def cli(self, *args, expected=0):
        result = subprocess.run(
            [str(BINARY), *map(str, args)], capture_output=True, text=True,
            timeout=30, cwd=self.root,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def timeline(self):
        result = self.cli(
            "timeline", "--db", self.db, "--case", "incident-7",
            "--conversation", "conv-7", "--include-details", "--limit", "100",
        )
        return json.loads(result.stdout)

    def test_guard_events_ingest_and_correlate_in_timeline(self):
        broker = FakeBroker()
        proposal = {"command": "begin_selected_work", "expected_id": "artifact:abc", "expected_revision": 3}
        result = GuardedGemBroker(broker, "agent-vm-1", "conv-7", Clock()).execute(
            "action-1", proposal, forecast(gem_forecast_context(broker.state, proposal)),
        )
        output = write_jsonl_new(result.events, self.root / "guard.jsonl")
        self.cli("ingest", "--db", self.db, "--case", "incident-7", "--input", output)
        timeline = self.timeline()
        self.assertEqual(len(timeline["events"]), 4)
        self.assertEqual({event["tool_call_id"] for event in timeline["events"]}, {"action-1"})
        forecast_event = next(event for event in timeline["events"] if event["event_type"] == "model_forecast")
        self.assertEqual(
            [entry["accessible_volume"] for entry in forecast_event["details"]["measurement"]["threshold_sweep"]],
            [5, 4, 3, 2, 1, 0],
        )
        with self.assertRaises(FileExistsError):
            write_jsonl_new(result.events, output)

    def test_invalid_jsonl_leaves_no_partial_output(self):
        output = self.root / "invalid.jsonl"
        with self.assertRaises(ValueError):
            write_jsonl_new([{"id": "valid"}, {"id": "invalid", "value": math.nan}], output)
        self.assertFalse(output.exists())

    def gem_session(self):
        session = self.root / "session"
        session.mkdir()
        events = [
            {
                "schema_version": 1, "timestamp_utc": "2026-11-03T13:00:00Z",
                "id": "artifact:abc", "parent_id": None, "type": "artifact", "label": "true",
                "status": "not_started", "source": "system", "evidence": "/bin/true",
                "note": "Initial artifact", "scope": None,
            },
            {
                "schema_version": 1, "timestamp_utc": "2026-11-03T13:00:01Z",
                "id": "artifact:abc", "parent_id": None, "type": "artifact", "label": "true",
                "status": "in_progress", "source": "agent", "evidence": "/bin/true",
                "note": "Guarded work", "scope": None,
            },
        ]
        (session / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
        return session

    def test_gem_history_export_is_bounded_and_ingestible(self):
        session = self.gem_session()
        events, next_line = export_gem_events(
            session / "events.jsonl", "agent-vm-1", "conv-7", "session-test", 2,
        )
        self.assertEqual(next_line, 3)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["details"]["gem_event"]["status"], "in_progress")
        output = write_jsonl_new(events, self.root / "gem.jsonl")
        self.cli("ingest", "--db", self.db, "--case", "incident-7", "--input", output)
        timeline = self.timeline()
        self.assertEqual(timeline["events"][0]["event_type"], "gem_investigation_event")
        self.assertEqual(timeline["events"][0]["details"]["source_line"], 2)

    def test_export_cli_ingests_real_gem_jsonl(self):
        session = self.gem_session()
        output = self.root / "cli-gem.jsonl"
        result = subprocess.run([
            sys.executable, str(ROOT / "integration" / "ablation_gem_defense.py"), "export-gem",
            "--session", str(session), "--output", str(output), "--host", "agent-vm-1",
            "--conversation", "conv-7", "--db", str(self.db), "--case", "incident-7",
            "--cerotto-binary", str(BINARY), "--session-id", "session-test",
        ], capture_output=True, text=True, timeout=30, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["events"], 2)
        self.assertEqual(summary["next_line"], 3)
        self.assertTrue(summary["ingested"])
        self.assertEqual(len(self.timeline()["events"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
