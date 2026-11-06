#!/usr/bin/env python3
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from test_cerotto import agent_events

from cerotto_gem.commands import CommandRunner
from cerotto_gem.model import CaseModel
from cerotto_gem.vault import vault_summary


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("CEROTTO_BIN", ROOT / "build" / "cerotto")).resolve()
PROBABILITIES = [0.40, 0.20, 0.12, 0.06, 0.04] + [0.02] * 9


def create_case(root: Path):
    database = root / "case.db"
    subprocess.run([str(BINARY), "init", "--db", str(database)], check=True, capture_output=True, text=True)
    source = root / "events.jsonl"
    source.write_text("".join(json.dumps(event) + "\n" for event in agent_events()))
    subprocess.run([
        str(BINARY), "ingest", "--db", str(database), "--case", "incident-7", "--input", str(source),
    ], check=True, capture_output=True, text=True)
    context = {
        "case_id": "incident-7", "conversation_id": "conv-7", "expected_event_count": 5,
        "action": "get_manifest", "arguments": {},
    }
    proposal = root / "proposal.json"
    document = {
        "schema_version": 1, "action_id": "gui-action-1", "host_id": "agent-vm-1",
        "conversation_id": "conv-7", "expected_event_count": 5,
        "action": "get_manifest", "arguments": {},
        "forecast": {
            "model": "reference-test",
            "context_sha256": hashlib.sha256(json.dumps(context, separators=(",", ":")).encode()).hexdigest(),
            "probabilities": PROBABILITIES,
        },
    }
    proposal.write_text(json.dumps(document, separators=(",", ":")))
    subprocess.run([
        str(BINARY), "guard", "--db", str(database), "--case", "incident-7",
        "--input", str(proposal), "--output", str(root / "guard-result.json"),
    ], check=True, capture_output=True, text=True)
    return database


class WorkbenchModelTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cerotto-gem-model-test-")
        self.root = Path(self.temporary.name) / "case with spaces"
        self.root.mkdir()
        self.addCleanup(self.temporary.cleanup)
        self.database = create_case(self.root)

    def test_read_only_model_loads_guard_chain_and_forecast(self):
        snapshot = CaseModel(self.database, "incident-7", "conv-7").load()
        self.assertEqual(len(snapshot.events), 8)
        self.assertEqual(len(snapshot.sources), 2)
        forecast = next(event for event in snapshot.events if event.event_type == "model_forecast")
        self.assertEqual([count for _tau, count, _normalized in forecast.accessible_volume], [5, 4, 3, 2, 1, 0])
        self.assertEqual(forecast.status, "measured")
        decision = next(event for event in snapshot.events if event.event_type == "policy_decision")
        self.assertEqual(decision.status, "allow")
        self.assertTrue(all(event.tool_call_id == "gui-action-1" for event in snapshot.events if event.event_type.startswith("model_") or event.event_type.endswith("receipt") or event.event_type == "policy_decision" or event.event_type == "action_proposal"))

    def test_native_runner_verifies_and_exports_report(self):
        runner = CommandRunner(BINARY)
        verification = runner.verify(self.database, "incident-7")
        self.assertTrue(verification.document["verified"])
        report = self.root / "report.json"
        runner.report(self.database, "incident-7", "conv-7", report)
        document = json.loads(report.read_text())
        self.assertEqual(document["case_id"], "incident-7")
        self.assertEqual(document["timeline"]["conversation_id"], "conv-7")

    def test_vault_summary_filters_native_vault_events(self):
        snapshot = CaseModel(self.database, "incident-7", "conv-7").load()
        contact = replace(snapshot.events[0], source_tool="cerotto.vault", event_type="file.open")
        denied = replace(snapshot.events[1], source_tool="cerotto.vault", event_type="release.denied")
        unrelated = snapshot.events[2]
        summary = vault_summary([contact, denied, unrelated])
        self.assertEqual(summary["events"], 2)
        self.assertEqual(summary["contacts"], 1)
        self.assertEqual(summary["denied_releases"], 1)
        self.assertEqual(summary["modifications"], 0)


@unittest.skipUnless(shutil.which("Xephyr") and shutil.which("xwininfo"), "Xephyr tools unavailable")
class NativeWorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cerotto-gem-native-test-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.database = create_case(self.root)

    def test_real_gtk_chart_agent_lifecycle_and_screenshot(self):
        screenshot = self.root / "workbench.png"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT)
        result = subprocess.run([
            str(ROOT / "integration" / "nested_x11.sh"), sys.executable, "-m", "cerotto_gem",
            "--db", str(self.database), "--case", "incident-7", "--conversation", "conv-7",
            "--binary", str(BINARY), "--agent-command", "/bin/sh",
            "--self-test", "--screenshot", str(screenshot),
        ], capture_output=True, text=True, timeout=40, cwd=ROOT, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        summary = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(summary["self_test"], "passed")
        self.assertEqual(summary["forecast_points"], 6)
        self.assertIsInstance(summary["agent_pid"], int)
        self.assertTrue(screenshot.is_file())
        self.assertGreater(screenshot.stat().st_size, 10_000)
        self.assertEqual(screenshot.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            stat = Path(f"/proc/{summary['agent_pid']}/stat")
            if not stat.exists() or stat.read_text().split()[2] == "Z":
                break
            time.sleep(0.05)
        else:
            self.fail(f"agent process {summary['agent_pid']} survived workbench shutdown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
