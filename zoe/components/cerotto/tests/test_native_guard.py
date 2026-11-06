#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import tempfile
import unittest

from test_cerotto import agent_events


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("CEROTTO_BIN", ROOT / "build" / "cerotto")).resolve()
PROBABILITIES = [0.40, 0.20, 0.12, 0.06, 0.04] + [0.02] * 9


class NativeGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cerotto-native-guard-test-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.db = self.root / "case.db"
        self.counter = 0
        self.assertTrue(BINARY.is_file())
        self.cli("init", "--db", self.db)
        source = self.root / "events.jsonl"
        source.write_text("".join(json.dumps(event) + "\n" for event in agent_events()))
        self.cli("ingest", "--db", self.db, "--case", "incident-7", "--input", source)

    def cli(self, *args, expected=0):
        result = subprocess.run(
            [str(BINARY), *map(str, args)], capture_output=True, text=True,
            timeout=30, cwd=self.root,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def event_count(self):
        with sqlite3.connect(self.db) as connection:
            return connection.execute("select count(*) from events").fetchone()[0]

    def guard_records(self, action_id):
        with sqlite3.connect(self.db) as connection:
            return connection.execute(
                "select event_type,details_json,source_id,prompt_id from events where tool_call_id=? order by id",
                (action_id,),
            ).fetchall()

    def proposal(self, action="query_timeline", arguments=None, expected_count=None,
                 action_id=None, context_hash=None, probabilities=None):
        self.counter += 1
        action_id = action_id or f"native-action-{self.counter}"
        arguments = {"limit": 2} if arguments is None else arguments
        expected_count = self.event_count() if expected_count is None else expected_count
        context = {
            "case_id": "incident-7",
            "conversation_id": "conv-7",
            "expected_event_count": expected_count,
            "action": action,
            "arguments": arguments,
        }
        encoded = json.dumps(context, separators=(",", ":"))
        document = {
            "schema_version": 1,
            "action_id": action_id,
            "host_id": "agent-vm-1",
            "conversation_id": "conv-7",
            "expected_event_count": expected_count,
            "action": action,
            "arguments": arguments,
            "forecast": {
                "model": "reference-test",
                "context_sha256": context_hash or hashlib.sha256(encoded.encode()).hexdigest(),
                "probabilities": PROBABILITIES if probabilities is None else probabilities,
            },
        }
        path = self.root / f"proposal-{self.counter}.json"
        path.write_text(json.dumps(document, separators=(",", ":")))
        return action_id, path

    def guard(self, path, expected=0, output=True):
        action_id = json.loads(path.read_text())["action_id"]
        destination = self.root / f"result-{path.stem}.json" if output else None
        args = ["guard", "--db", self.db, "--case", "incident-7", "--input", path]
        if destination:
            args.extend(["--output", destination])
        result = self.cli(*args, expected=expected)
        if destination and destination.exists():
            document = json.loads(destination.read_text())
        elif result.stdout.strip():
            document = json.loads(result.stdout)
        else:
            document = None
        return action_id, document, destination

    def test_native_query_timeline_and_reference_measurement(self):
        action_id, path = self.proposal()
        _, result, _ = self.guard(path)
        self.assertEqual(result["decision"], "allow")
        self.assertTrue(result["succeeded"])
        self.assertEqual(len(result["result"]["events"]), 2)
        records = self.guard_records(action_id)
        self.assertEqual([row[0] for row in records], [
            "model_forecast", "action_proposal", "policy_decision", "execution_receipt",
        ])
        self.assertEqual(len({row[2] for row in records}), 1)
        self.assertEqual(len({row[3] for row in records}), 1)
        measurement = json.loads(records[0][1])["measurement"]
        self.assertEqual([entry["accessible_volume"] for entry in measurement["threshold_sweep"]], [5, 4, 3, 2, 1, 0])
        packed = b"".join(struct.pack("<d", value) for value in PROBABILITIES)
        self.assertEqual(measurement["probability_values_sha256"], hashlib.sha256(packed).hexdigest())
        with sqlite3.connect(self.db) as connection:
            source = connection.execute(
                "select kind,origin_path,sha256 from evidence_sources where id=?", (records[0][2],),
            ).fetchone()
        self.assertEqual(source[0], "guard_proposal")
        self.assertEqual(source[1], str(path))
        self.assertEqual(source[2], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_all_bounded_evidence_actions_execute(self):
        action_id, path = self.proposal(action="get_event", arguments={"event_id": "evt-tool"})
        _, result, _ = self.guard(path)
        self.assertEqual(result["result"]["event_id"], "evt-tool")
        self.assertEqual(json.loads(self.guard_records(action_id)[-1][1])["status"], "succeeded")
        action_id, path = self.proposal(action="get_manifest", arguments={})
        _, result, _ = self.guard(path)
        self.assertEqual(result["result"]["case_id"], "incident-7")
        self.assertIn("guard_proposal", {source["kind"] for source in result["result"]["sources"]})
        action_id, path = self.proposal(action="verify_case", arguments={})
        _, result, _ = self.guard(path)
        self.assertTrue(result["result"]["verified"])
        self.assertTrue(json.loads(self.guard_records(action_id)[-1][1])["result"]["verified"])

    def test_unknown_action_is_denied_without_execution(self):
        action_id, path = self.proposal(action="shell", arguments={"command": "id"})
        _, result, _ = self.guard(path, expected=3)
        self.assertEqual(result["reason"], "command_not_supported")
        self.assertFalse(result["executed"])
        records = self.guard_records(action_id)
        self.assertEqual([row[0] for row in records], ["model_forecast", "action_proposal", "policy_decision"])
        self.assertNotIn("execution_receipt", {row[0] for row in records})

    def test_stale_case_state_and_forecast_substitution_are_denied(self):
        action_id, path = self.proposal(expected_count=self.event_count() - 1)
        _, result, _ = self.guard(path, expected=3)
        self.assertEqual(result["reason"], "stale_case_event_count")
        self.assertFalse(result["executed"])
        action_id, path = self.proposal(context_hash="0" * 64)
        _, result, _ = self.guard(path, expected=3)
        self.assertEqual(result["reason"], "forecast_context_mismatch")
        self.assertEqual(len(self.guard_records(action_id)), 3)

    def test_missing_scoped_event_has_failed_receipt(self):
        action_id, path = self.proposal(action="get_event", arguments={"event_id": "invented"})
        _, result, _ = self.guard(path, expected=1)
        self.assertEqual(result["decision"], "allow")
        self.assertTrue(result["executed"])
        self.assertFalse(result["succeeded"])
        self.assertEqual(json.loads(self.guard_records(action_id)[-1][1])["status"], "failed")

    def test_invalid_distribution_and_existing_output_do_not_execute(self):
        before = self.event_count()
        _, path = self.proposal(probabilities=[0.5, 0.4])
        self.guard(path, expected=1)
        self.assertEqual(self.event_count(), before)
        action_id, path = self.proposal()
        output = self.root / f"result-{path.stem}.json"
        output.write_text("preserve")
        self.cli("guard", "--db", self.db, "--case", "incident-7", "--input", path,
                 "--output", output, expected=1)
        self.assertEqual(output.read_text(), "preserve")
        self.assertEqual(self.guard_records(action_id), [])
        self.assertEqual(self.event_count(), before)

    def test_duplicate_action_id_rolls_back_new_chain(self):
        _, first = self.proposal(action_id="duplicate-action")
        self.guard(first)
        before = self.event_count()
        action_id, second = self.proposal(action_id="duplicate-action")
        self.guard(second, expected=1)
        self.assertEqual(action_id, "duplicate-action")
        self.assertEqual(self.event_count(), before)
        self.assertEqual(len(self.guard_records(action_id)), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
