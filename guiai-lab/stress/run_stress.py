#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import io
import json
import multiprocessing as mp
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from guiai.cli import build_parser, command_tree
from guiai.events import Session


DEEP_NODES = int(os.environ.get("GUIAI_STRESS_DEEP", "1500"))
LARGE_NODES = int(os.environ.get("GUIAI_STRESS_LARGE", "5000"))


def initialize_worker(root):
    Session(root, "/bin/true")


def initialize_directory_worker(root, target):
    Session(root, target)


def specification(node_id, parent_id, label, status="not_started"):
    return {
        "id": node_id, "parent_id": parent_id, "type": "function",
        "label": label, "status": status, "source": "agent",
        "evidence": "", "note": "", "scope": None,
    }


def emit_worker(root, start, count):
    session = Session(root)
    parent = f"artifact:{session.metadata['sha256']}"
    session.emit_many([
        specification(f"function:{index}", parent, f"fn {index}")
        for index in range(start, start + count)
    ])


class SessionCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guiai-stress-")
        self.root = Path(self.temporary.name)
        self.session = Session(self.root, "/bin/true")
        self.artifact = f"artifact:{self.session.metadata['sha256']}"

    def tearDown(self):
        self.temporary.cleanup()

    def test_validation_boundaries(self):
        self.session.emit("x" * 128, self.artifact, "function", "x" * 500, note="n" * 4000)
        for node_id in ("", "x" * 129, "bad id", "bad\nid"):
            with self.subTest(node_id=node_id):
                with self.assertRaises(ValueError):
                    self.session.emit(node_id, self.artifact, "note", "invalid")
        with self.assertRaises(ValueError):
            self.session.emit("long-label", self.artifact, "note", "x" * 501)
        with self.assertRaises(ValueError):
            self.session.emit("long-note", self.artifact, "note", "long", note="x" * 4001)
        with self.assertRaises(ValueError):
            self.session.emit("bad-parent", "missing", "note", "orphan")
        with self.assertRaises(ValueError):
            self.session.emit("bad-type", self.artifact, "invalid", "bad")
        with self.assertRaises(ValueError):
            self.session.emit("bad-status", self.artifact, "note", "bad", status="finished")
        with self.assertRaises(ValueError):
            self.session.emit("bad-source", self.artifact, "note", "bad", source="robot")
        with self.assertRaises(ValueError):
            self.session.emit("no-scope", self.artifact, "finding", "bad", status="complete_scoped")

    def test_identical_upsert_is_a_noop(self):
        first = self.session.emit("function:noop", self.artifact, "function", "noop", "partial", "agent", "evidence.json", "note")
        second = self.session.emit("function:noop", self.artifact, "function", "noop", "partial", "agent", "evidence.json", "note")
        self.assertEqual(first, second)
        self.assertEqual(len((self.root / "events.jsonl").read_text().splitlines()), 2)

    def test_emit_many_uses_one_sync_and_no_duplicate_replay(self):
        specifications = [specification(f"function:{index}", self.artifact, f"fn {index}") for index in range(500)]
        syncs = []
        original = os.fsync
        os.fsync = lambda descriptor: syncs.append(descriptor)
        try:
            self.session.emit_many(specifications)
            self.session.emit_many(specifications)
        finally:
            os.fsync = original
        self.assertEqual(len(syncs), 1)
        self.assertEqual(len((self.root / "events.jsonl").read_text().splitlines()), 501)

    def test_invalid_batch_does_not_append_partial_results(self):
        self.session.emit("node:a", self.artifact, "function", "a")
        before = (self.root / "events.jsonl").read_text()
        specifications = [
            specification("node:b", "node:a", "b"),
            specification("node:a", "node:b", "a"),
        ]
        with self.assertRaises(ValueError):
            self.session.emit_many(specifications)
        self.assertEqual((self.root / "events.jsonl").read_text(), before)

    def test_cycles_are_rejected(self):
        self.session.emit("node:a", self.artifact, "function", "a")
        self.session.emit("node:b", "node:a", "function", "b")
        with self.assertRaises(ValueError):
            self.session.emit("node:a", "node:b", "function", "a")
        with self.assertRaises(ValueError):
            self.session.emit("node:a", "node:a", "function", "self")

    def test_malformed_event_is_explicit(self):
        (self.root / "events.jsonl").write_text('{"id":"broken"}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "line 1"):
            self.session.events_by_id()

    def test_invalid_json_is_explicit(self):
        (self.root / "events.jsonl").write_text('{"id":\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "line 1"):
            self.session.events_by_id()

    def test_missing_selected_node_falls_back_to_artifact(self):
        (self.root / "state.json").write_text(json.dumps({"selected_id": "missing"}), encoding="utf-8")
        self.assertEqual(self.session.current_state()["selected_id"], self.artifact)

    def test_concurrent_initialization_has_one_artifact_event(self):
        root = Path(self.temporary.name) / "concurrent-init"
        context = mp.get_context("fork")
        with context.Pool(6) as pool:
            pool.map(initialize_worker, [str(root)] * 12)
        self.assertEqual(len((root / "events.jsonl").read_text().splitlines()), 1)

    def test_concurrent_writers_and_readers(self):
        errors = []
        stop = threading.Event()

        def read_continually():
            while not stop.is_set():
                try:
                    self.session.events_by_id()
                except Exception as error:
                    errors.append(error)
                    return

        readers = [threading.Thread(target=read_continually) for _ in range(4)]
        for reader in readers:
            reader.start()
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda start: emit_worker(str(self.root), start, 100), range(0, 800, 100)))
        stop.set()
        for reader in readers:
            reader.join(timeout=3)
        self.assertEqual(errors, [])
        self.assertEqual(len(self.session.events()), 801)
        for line in (self.root / "events.jsonl").read_text().splitlines():
            json.loads(line)

    def test_concurrent_selection_is_always_valid_json(self):
        errors = []
        def select(index):
            node_id = f"function:{index}"
            self.session.emit(node_id, self.artifact, "function", f"fn {index}")
            self.session.select(node_id)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(select, range(100)))
        state = json.loads((self.root / "state.json").read_text())
        self.assertIn(state["selected_id"], {f"function:{index}" for index in range(100)})
        self.assertEqual(errors, [])

    def test_starring_persists_across_selection_and_reopen(self):
        self.assertEqual(self.session.current_state()["starred_ids"], [])
        self.session.emit("function:starred", self.artifact, "function", "starred")
        state = self.session.set_starred("function:starred", True)
        self.assertEqual(state["starred_ids"], ["function:starred"])
        self.session.select(self.artifact)
        self.assertEqual(self.session.current_state()["starred_ids"], ["function:starred"])
        self.assertEqual(Session(self.root).current_state()["starred_ids"], ["function:starred"])
        self.assertEqual(self.session.set_starred("function:starred", False)["starred_ids"], [])
        with self.assertRaisesRegex(ValueError, "does not exist"):
            self.session.set_starred("function:missing", True)

    def test_deep_cli_tree_does_not_recurse(self):
        parent = self.artifact
        specifications = []
        for index in range(DEEP_NODES):
            node_id = f"node:{index}"
            specifications.append(specification(node_id, parent, f"node {index}"))
            parent = node_id
        self.session.emit_many(specifications)
        output = io.StringIO()
        with redirect_stdout(output):
            command_tree(type("Args", (), {"session": str(self.root), "json": False})())
        self.assertIn(f"node {DEEP_NODES - 1}", output.getvalue())

    def test_large_event_log(self):
        self.session.emit_many([
            specification(f"function:{index}", self.artifact, f"fn {index}")
            for index in range(LARGE_NODES)
        ])
        events = self.session.events()
        self.assertEqual(len(events), LARGE_NODES + 1)
        self.assertEqual(self.session.counts()["not_started"], LARGE_NODES + 1)

    def test_unicode_and_empty_log_lines(self):
        self.session.emit("function:café-雪", self.artifact, "function", "関数 🧪")
        with (self.root / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write("\n\n")
        event = self.session.events_by_id()["function:café-雪"]
        self.assertEqual(event["label"], "関数 🧪")

    def test_invalid_event_version_and_timestamps(self):
        original = self.session.events()[0]
        for field, value in (
            ("schema_version", 2), ("timestamp_utc", None),
            ("timestamp_utc", "not-a-time"), ("timestamp_utc", "2026-01-01T00:00:00"),
        ):
            with self.subTest(field=field, value=value):
                event = dict(original)
                event[field] = value
                self.session.events_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "line 1"):
                    self.session.events()

    def test_invalid_event_specifications_are_explicit_and_atomic(self):
        before = self.session.events_path.read_text(encoding="utf-8")
        for invalid in (None, {}, {"id": "missing-fields"}):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "required fields"):
                    self.session.emit_many([invalid])
                self.assertEqual(self.session.events_path.read_text(encoding="utf-8"), before)

    def test_corrupt_session_metadata_is_explicit(self):
        root = Path(self.temporary.name) / "metadata-session"
        session = Session(root, "/bin/true")
        original = dict(session.metadata)
        for invalid in (
            None, [], {**original, "sha256": "bad"}, {**original, "target_kind": "directory"},
            {**original, "workspace": "relative/path"}, {**original, "workspace": 123},
        ):
            with self.subTest(invalid=invalid):
                session.metadata_path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "session metadata"):
                    Session(root)

    def test_failed_atomic_state_write_preserves_previous_selection(self):
        original = self.session.current_state()
        self.session.emit("function:state", self.artifact, "function", "state")
        with mock.patch("guiai.events.os.fsync", side_effect=OSError("injected sync failure")):
            with self.assertRaisesRegex(OSError, "injected sync failure"):
                self.session.select("function:state")
        self.assertEqual(self.session.current_state()["selected_id"], original["selected_id"])
        self.assertEqual(list(self.root.glob(".state.json.*")), [])

    def test_legacy_file_session_remains_readable(self):
        root = Path(self.temporary.name) / "legacy-session"
        session = Session(root, "/bin/true")
        metadata = dict(session.metadata)
        metadata.pop("target")
        metadata.pop("target_kind")
        session.metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        loaded = Session(root)
        self.assertEqual(loaded.target_kind, "file")
        self.assertEqual(loaded.target, metadata["binary"])
        self.assertEqual(loaded.root_id, session.root_id)
        self.assertEqual(loaded.current_state()["target"], metadata["binary"])


class DirectorySessionCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guiai-directory-stress-")
        self.target = Path(self.temporary.name) / "corpus"
        self.target.mkdir()
        (self.target / "z-last").mkdir()
        (self.target / "a-first").mkdir()
        (self.target / "a-first" / "nested.bin").write_bytes(b"nested")
        (self.target / "firmware.bin").write_bytes(b"firmware")
        (self.target / "placeholder").touch()
        self.root = Path(self.temporary.name) / "session"
        self.session = Session(self.root, self.target)

    def tearDown(self):
        self.temporary.cleanup()

    def test_real_top_level_inventory_without_content_digest(self):
        self.assertEqual(self.session.target_kind, "directory")
        self.assertIsNone(self.session.metadata["sha256"])
        self.assertIsNone(self.session.metadata["binary"])
        self.assertEqual(self.session.metadata["target"], str(self.target))
        self.assertTrue(self.session.root_id.startswith("artifact:directory:"))
        events = self.session.events()
        self.assertEqual([event["label"] for event in events], [
            "corpus/", "a-first/", "z-last/", "firmware.bin", "placeholder",
        ])
        self.assertEqual(events[1]["evidence"], str(self.target / "a-first"))
        self.assertNotIn("nested.bin", {event["label"] for event in events})
        self.assertTrue(all(event["status"] == "not_started" for event in events))
        self.assertEqual(len(self.root.joinpath("events.jsonl").read_text().splitlines()), 5)

    def test_selection_exposes_directory_not_fake_binary(self):
        state = self.session.current_state()
        self.assertEqual(state["selected_id"], self.session.root_id)
        self.assertEqual(state["target"], str(self.target))
        self.assertEqual(state["target_kind"], "directory")
        self.assertIsNone(state["binary"])
        self.assertIsNone(state["sha256"])
        child = next(event for event in self.session.events() if event["label"] == "firmware.bin")
        self.assertEqual(self.session.select(child["id"])["selected"]["evidence"], str(self.target / "firmware.bin"))

    def test_agent_shell_cli_wrapper_works_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix="guiai cli path ") as directory:
            session = Session(Path(directory) / "session with spaces", self.target)
            environment = os.environ.copy()
            environment.update({"GUIAI_CLI": str(session.cli_path), "GUIAI_SESSION": str(session.root)})
            result = subprocess.run(
                ["/bin/sh", "-c", '"$GUIAI_CLI" state --session "$GUIAI_SESSION"'],
                capture_output=True, text=True, env=environment, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            state = json.loads(result.stdout)
            self.assertEqual(state["target"], str(self.target))
            self.assertEqual(state["target_kind"], "directory")
            self.assertTrue(os.access(session.cli_path, os.X_OK))

    def test_reopen_is_idempotent_and_new_entries_are_added(self):
        reopened = Session(self.root, self.target)
        self.assertEqual(len(reopened.events()), 5)
        (self.target / "new.pkg").write_bytes(b"new")
        reopened = Session(self.root, self.target)
        self.assertEqual(len(reopened.events()), 6)
        self.assertIn("new.pkg", {event["label"] for event in reopened.events()})

    def test_file_and_directory_sessions_cannot_be_confused(self):
        with self.assertRaisesRegex(ValueError, "different target"):
            Session(self.root, "/bin/true")
        other = Path(self.temporary.name) / "other"
        other.mkdir()
        with self.assertRaisesRegex(ValueError, "different target"):
            Session(self.root, other)
        file_session = Session(Path(self.temporary.name) / "file-session", "/bin/true")
        with self.assertRaisesRegex(ValueError, "different target"):
            Session(file_session.root, self.target)

    def test_session_cannot_be_created_inside_target(self):
        nested = self.target / ".guiai-session"
        with self.assertRaisesRegex(ValueError, "outside the target"):
            Session(nested, self.target)
        self.assertFalse(nested.exists())
        with self.assertRaisesRegex(ValueError, "outside the target"):
            Session(self.target, self.target)

    def test_concurrent_directory_initialization_is_idempotent(self):
        root = Path(self.temporary.name) / "concurrent-directory"
        context = mp.get_context("fork")
        with context.Pool(6) as pool:
            pool.starmap(initialize_directory_worker, [(str(root), str(self.target))] * 12)
        session = Session(root)
        self.assertEqual(session.target, str(self.target))
        self.assertEqual(session.target_kind, "directory")
        self.assertEqual(len(session.events()), 5)
        self.assertEqual(session.current_state()["selected_id"], session.root_id)
        self.assertEqual(len(root.joinpath("events.jsonl").read_text().splitlines()), 5)

    def test_large_real_directory_inventory(self):
        count = int(os.environ.get("GUIAI_STRESS_DIRECTORY", "1000"))
        for index in range(count):
            (self.target / f"package-{index:05}.bin").touch()
        session = Session(Path(self.temporary.name) / "large-directory-session", self.target)
        self.assertEqual(len(session.events()), count + 5)
        self.assertEqual(session.counts()["not_started"], count + 5)


class AgentCommandCase(unittest.TestCase):
    def test_agent_option_accepts_any_interactive_cli(self):
        from metrix.agent import parse_agent_command

        parser = build_parser()
        for executable in ("kimi", "claude", "codex", "custom-agent"):
            with self.subTest(executable=executable):
                args = parser.parse_args(["desktop", "/bin/true", "--agent", executable])
                self.assertEqual(args.agent, executable)
                self.assertIsNone(args.agent_command)
                self.assertEqual(parse_agent_command(args.agent), [executable])
        args = parser.parse_args([
            "desktop", "/bin/true", "--agent-command", "custom-agent --flag 'two words'",
        ])
        self.assertEqual(
            parse_agent_command(args.agent_command), ["custom-agent", "--flag", "two words"],
        )


class LauncherCase(unittest.TestCase):
    def test_launch_uses_target_workspace_and_stable_session(self):
        from guiai import cli

        with tempfile.TemporaryDirectory(prefix="guiai-launch-test-") as temporary:
            root = Path(temporary)
            file_target = root / "firmware.bin"
            file_target.touch()
            directory_target = root / "material"
            directory_target.mkdir()
            for target in (file_target, directory_target):
                with self.subTest(target=target):
                    args = build_parser().parse_args(["launch", "--toolkit", "tk", "--agent", "kimi"])
                    with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(root / "data")}):
                        with mock.patch.object(cli, "choose_target", return_value=target), mock.patch.object(
                            cli, "command_desktop", return_value=23,
                        ) as desktop:
                            self.assertEqual(args.function(args), 23)
                    desktop.assert_called_once_with(args)
                    self.assertEqual(args.target, str(target.resolve()))
                    self.assertEqual(args.workspace, str((target if target.is_dir() else target.parent).resolve()))
                    self.assertEqual(Path(args.session).parent.parent, root / "data" / "Ablation" / "GUIAI")
                    self.assertEqual(args.toolkit, "tk")
                    self.assertEqual(args.agent, "kimi")

    def test_launch_cancel_is_clean(self):
        from guiai import cli

        args = build_parser().parse_args(["launch"])
        with mock.patch.object(cli, "choose_target", return_value=None), mock.patch.object(cli, "command_desktop") as desktop:
            self.assertEqual(args.function(args), 0)
        desktop.assert_not_called()

    def test_launch_failure_is_visible(self):
        from guiai import cli

        args = build_parser().parse_args(["launch"])
        with mock.patch.object(cli, "choose_target", side_effect=OSError("display unavailable")), mock.patch.object(
            cli, "show_launch_error",
        ) as show_error:
            self.assertEqual(args.function(args), 1)
        show_error.assert_called_once_with("display unavailable")

    def test_launch_rejects_session_inside_directory_target(self):
        from guiai.launcher import session_for_target

        with tempfile.TemporaryDirectory(prefix="guiai-launch-test-") as temporary:
            target = Path(temporary)
            with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(target / "data")}):
                with self.assertRaisesRegex(ValueError, "contains GUIAI's session data"):
                    session_for_target(target)


class DropPayloadCase(unittest.TestCase):
    def test_posix_payload_is_quoted_without_enter(self):
        import shlex
        from metrix.drop import dropped_payload

        with tempfile.TemporaryDirectory(prefix="guiai-drop test-") as temporary:
            directory = Path(temporary) / "folder with spaces"
            directory.mkdir()
            artifact = directory / "firmware's image.bin"
            artifact.touch()
            payload = dropped_payload([directory, artifact], windows=False)
            self.assertEqual(payload, (shlex.join([str(directory), str(artifact)]) + " ").encode())
            self.assertNotIn(b"\r", payload)
            self.assertNotIn(b"\n", payload)

    def test_windows_payload_quotes_metacharacters(self):
        from metrix.drop import dropped_payload, quote_dropped_path

        self.assertEqual(quote_dropped_path(r"C:\Users\A & B\firmware.bin", windows=True), '"C:\\Users\\A & B\\firmware.bin"')
        with tempfile.TemporaryDirectory(prefix="guiai-drop-test-") as temporary:
            artifact = Path(temporary) / "a&b.bin"
            artifact.touch()
            self.assertEqual(dropped_payload([artifact], windows=True), f'"{artifact}" '.encode())

    def test_missing_empty_and_control_paths_are_rejected(self):
        from metrix.drop import dropped_payload

        with tempfile.TemporaryDirectory(prefix="guiai-drop-test-") as temporary:
            with self.assertRaisesRegex(ValueError, "does not exist"):
                dropped_payload([Path(temporary) / "missing"])
            with self.assertRaisesRegex(ValueError, "control characters"):
                dropped_payload([Path(temporary) / "bad\nname"])
        with self.assertRaisesRegex(ValueError, "no local files"):
            dropped_payload([])

    def test_oversized_payload_is_rejected(self):
        from metrix import drop

        with tempfile.TemporaryDirectory(prefix="guiai-drop-test-") as temporary:
            artifact = Path(temporary) / "firmware.bin"
            artifact.touch()
            with mock.patch.object(drop, "MAX_DROP_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "8 MiB"):
                    drop.dropped_payload([artifact])


class SafetyCase(unittest.TestCase):
    def test_audit_is_read_only_and_reports_platform_requirements(self):
        from guiai.safety import evaluate_safety

        with mock.patch("subprocess.run", side_effect=AssertionError("audit executed an external command")):
            report = evaluate_safety([os.sys.executable])
        self.assertTrue(report["ready"], report["details"])
        self.assertGreaterEqual(len(report["checks"]), 7)
        self.assertTrue(report["summary"])
        self.assertFalse(any("REVIEW" in line and "Native Linux GTK/VTE" not in line for line in report["details"].splitlines()), report["details"])

    def test_permission_prompt_is_single_line_and_bounded(self):
        from guiai.safety import agent_request

        report = {
            "summary": "one fix",
            "details": "first line\nsecond line",
            "remediations": [{"action": "Run the shown command", "command": "echo approved"}],
            "checks": [],
            "ready": False,
        }
        request = agent_request(report)
        self.assertNotIn("\r", request)
        self.assertNotIn("\n", request)
        payload = json.loads(request.split("user. ", 1)[1])
        self.assertIn("at most once", payload["instruction"])
        self.assertEqual(payload["audit"], report)
        from guiai import safety
        with mock.patch.object(safety.os, "name", "nt"):
            command = safety.command_text([r"C:\Python 311\python.exe", "-m", "pip", "install", "pyte>=0.8.1,<1"])
        self.assertEqual(command, r'"C:\Python 311\python.exe" -m pip install "pyte>=0.8.1,<1"')

    def test_empty_remediation_prompt_is_read_only(self):
        from guiai.safety import agent_request

        report = {"summary": "ready", "details": "pass", "remediations": [], "checks": [], "ready": True}
        request = agent_request(report)
        payload = json.loads(request.split("user. ", 1)[1])
        self.assertIn("read-only AI review", payload["instruction"])
        self.assertIn("Do not install", payload["instruction"])


class AccessibilityCase(unittest.TestCase):
    def test_preferences_round_trip_and_validation(self):
        from guiai.accessibility import DEFAULT_PALETTE, load_accessibility, save_accessibility

        with tempfile.TemporaryDirectory(prefix="guiai-a11y-test-") as temporary:
            root = Path(temporary)
            self.assertEqual(load_accessibility(root), (DEFAULT_PALETTE, None))
            save_accessibility(root, "colorblind")
            self.assertEqual(load_accessibility(root), ("colorblind", None))
            (root / "accessibility.json").write_text('{"palette":"invalid"}')
            palette, error = load_accessibility(root)
            self.assertEqual(palette, DEFAULT_PALETTE)
            self.assertIn("Unknown accessibility palette", error)
            with self.assertRaises(ValueError):
                save_accessibility(root, "invalid")

    def test_palette_text_meets_normal_text_contrast(self):
        from guiai.accessibility import PALETTE_MODES, contrast_ratio
        from guiai.safety import safety_colors

        self.assertAlmostEqual(contrast_ratio("#000000", "#ffffff"), 21.0)
        for palette in PALETTE_MODES:
            for light, background in ((True, "#ffffff"), (False, "#0d1117")):
                colors = safety_colors(light, palette)
                for name in ("pass", "review", "accent"):
                    with self.subTest(palette=palette, light=light, name=name):
                        self.assertGreaterEqual(contrast_ratio(colors[name], background), 4.5)
        self.assertEqual(safety_colors(True, "system", "#123456")["accent"], "#123456")
        self.assertNotEqual(safety_colors(True, "colorblind", "#123456")["accent"], "#123456")

    def test_audit_reports_missing_features_and_remediation(self):
        from guiai.accessibility import evaluate_accessibility

        report = evaluate_accessibility("colorblind", False, "#0d1117", {"Keyboard navigation": False})
        self.assertFalse(report["ready"])
        self.assertFalse(report["remediations"][0]["command"])
        self.assertIn("Keyboard navigation", report["remediations"][0]["action"])
        passing = evaluate_accessibility("colorblind", False, "#0d1117", {"Keyboard navigation": True})
        self.assertTrue(passing["ready"])
        self.assertIn("Manual assistive-technology validation", passing["details"])

    def test_a11y_agent_request_is_single_line_and_scoped(self):
        from guiai.safety import agent_request

        report = {"summary": "a11y", "details": "line one\nline two", "remediations": [], "checks": [], "ready": True}
        request = agent_request(report, "a11y Optimization/Debugging")
        self.assertTrue(request.startswith("a11y Optimization/Debugging requested by the user. "))
        self.assertNotIn("\r", request)
        self.assertNotIn("\n", request)
        payload = json.loads(request.split("user. ", 1)[1])
        self.assertIn("read-only AI review", payload["instruction"])


def main():
    parser = argparse.ArgumentParser(description="Run GUIAI core stress tests")
    parser.add_argument("--failfast", action="store_true")
    args = parser.parse_args()
    suite = unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(SessionCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(DirectorySessionCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(AgentCommandCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(LauncherCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(DropPayloadCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(SafetyCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(AccessibilityCase),
    ])
    result = unittest.TextTestRunner(verbosity=2, failfast=args.failfast).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
