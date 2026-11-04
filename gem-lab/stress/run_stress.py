#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import io
import json
import multiprocessing as mp
import numpy as np
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from gem.lab_cli import build_parser, command_tree
from gem.events import Session


DEEP_NODES = int(os.environ.get("GEM_STRESS_DEEP", "1500"))
LARGE_NODES = int(os.environ.get("GEM_STRESS_LARGE", "5000"))


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
        self.temporary = tempfile.TemporaryDirectory(prefix="gem-stress-")
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

    def test_begin_selected_work_requires_current_revision(self):
        self.session.emit(
            "function:begin", self.artifact, "function", "begin",
            evidence="analysis/before.json", note="preserve this note",
        )
        selected = self.session.select("function:begin")
        before = self.session.events_path.read_text(encoding="utf-8")

        state = self.session.begin_selected_work(selected["selected_id"], selected["revision"])

        self.assertEqual(state["revision"], selected["revision"] + 1)
        self.assertEqual(state["selected"]["status"], "in_progress")
        self.assertEqual(state["selected"]["note"], "preserve this note")
        self.assertEqual(state["selected"]["evidence"], "analysis/before.json")
        with self.assertRaisesRegex(ValueError, "stale selection revision"):
            self.session.begin_selected_work(selected["selected_id"], selected["revision"])
        appended = self.session.events_path.read_text(encoding="utf-8").removeprefix(before)
        self.assertEqual(len(appended.splitlines()), 1)

    def test_selection_change_invalidates_begin(self):
        self.session.emit("function:first", self.artifact, "function", "first")
        self.session.emit("function:second", self.artifact, "function", "second")
        selected = self.session.select("function:first")
        self.session.select("function:second")
        with self.assertRaisesRegex(ValueError, "selected node changed"):
            self.session.begin_selected_work(selected["selected_id"], selected["revision"])
        self.assertEqual(self.session.events_by_id()["function:first"]["status"], "not_started")

    def test_concurrent_begin_has_exactly_one_winner(self):
        self.session.emit("function:contended", self.artifact, "function", "contended")
        selected = self.session.select("function:contended")
        before = self.session.events_path.read_text(encoding="utf-8")

        def begin(_index):
            try:
                self.session.begin_selected_work(selected["selected_id"], selected["revision"])
                return True
            except ValueError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(begin, range(16)))

        self.assertEqual(outcomes.count(True), 1)
        state = self.session.current_state()
        self.assertEqual(state["revision"], selected["revision"] + 1)
        self.assertEqual(state["selected"]["status"], "in_progress")
        appended = self.session.events_path.read_text(encoding="utf-8").removeprefix(before)
        self.assertEqual(len(appended.splitlines()), 1)

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
        with mock.patch("gem.events.os.fsync", side_effect=OSError("injected sync failure")):
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
        self.temporary = tempfile.TemporaryDirectory(prefix="gem-directory-stress-")
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
        with tempfile.TemporaryDirectory(prefix="gem cli path ") as directory:
            session = Session(Path(directory) / "session with spaces", self.target)
            environment = os.environ.copy()
            environment.update({"GEM_CLI": str(session.cli_path), "GEM_SESSION": str(session.root)})
            result = subprocess.run(
                ["/bin/sh", "-c", '"$GEM_CLI" state --session "$GEM_SESSION"'],
                capture_output=True, text=True, env=environment, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            state = json.loads(result.stdout)
            self.assertEqual(state["target"], str(self.target))
            self.assertEqual(state["target_kind"], "directory")
            self.assertTrue(os.access(session.cli_path, os.X_OK))
            began = subprocess.run(
                [
                    str(session.cli_path), "begin", "--session", str(session.root),
                    "--expected-id", state["selected_id"],
                    "--expected-revision", str(state["revision"]),
                ],
                capture_output=True, text=True, env=environment, timeout=10,
            )
            self.assertEqual(began.returncode, 0, began.stderr)
            self.assertEqual(json.loads(began.stdout)["selected"]["status"], "in_progress")

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
        nested = self.target / ".gem-session"
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
        count = int(os.environ.get("GEM_STRESS_DIRECTORY", "1000"))
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
    def test_launch_uses_lab_workspace_and_stable_session(self):
        from gem import lab_cli as cli, launcher

        with tempfile.TemporaryDirectory(prefix="gem-launch-test-") as temporary:
            root = Path(temporary)
            file_target = root / "firmware.bin"
            file_target.touch()
            directory_target = root / "material"
            directory_target.mkdir()
            for target in (file_target, directory_target):
                with self.subTest(target=target):
                    args = build_parser().parse_args(["launch", "--toolkit", "tk", "--agent", "kimi"])
                    with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(root / "data")}):
                        with mock.patch.object(cli, "command_desktop", side_effect=[target, 23]) as desktop:
                            self.assertEqual(args.function(args), 23)
                    self.assertEqual(desktop.call_args_list, [mock.call(args), mock.call(args)])
                    self.assertEqual(args.target, str(target.resolve()))
                    self.assertEqual(args.workspace, str(Path(launcher.__file__).resolve().parent.parent))
                    self.assertEqual(Path(args.session).parent.parent, root / "data" / "Ablation" / "GEM")
                    self.assertEqual(args.toolkit, "tk")
                    self.assertEqual(args.agent, "kimi")

    def test_installed_launch_uses_home_lab_workspace(self):
        from gem import lab_cli as cli, launcher

        with tempfile.TemporaryDirectory(prefix="gem-launch-test-") as temporary:
            root = Path(temporary)
            target = root / "firmware.bin"
            target.touch()
            package = root / "site-packages" / "gem"
            package.mkdir(parents=True)
            with mock.patch.object(launcher, "__file__", str(package / "launcher.py")), mock.patch.object(
                launcher.Path, "home", return_value=root / "home",
            ):
                first = launcher.default_workspace()
                second = launcher.default_workspace()
            self.assertEqual(first, root / "home" / "gem-lab")
            self.assertEqual(second, first)
            self.assertTrue(first.is_dir())
            args = build_parser().parse_args([
                "desktop", str(target), "--session", str(root / "session"), "--toolkit", "tk",
            ])
            with mock.patch.object(cli, "default_workspace", return_value=first), mock.patch(
                "gem.app.run_desktop", return_value=0,
            ) as desktop:
                self.assertEqual(args.function(args), 0)
            self.assertEqual(desktop.call_args.args[3], first)

    def test_launch_auto_detects_an_installed_agent(self):
        from gem import lab_cli as cli

        with tempfile.TemporaryDirectory(prefix="gem-launch-test-") as temporary:
            root = Path(temporary)
            for detected in ("kimi", ""):
                with self.subTest(detected=detected or "none"):
                    args = build_parser().parse_args(["launch"])
                    with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(root / "data")}), mock.patch.object(
                        cli, "default_agent", return_value=detected,
                    ), mock.patch.object(cli, "command_desktop", return_value=0):
                        self.assertEqual(args.function(args), 0)
                    self.assertEqual(args.agent, detected or None)

    def test_launch_preserves_agent_choices_and_opt_out(self):
        from gem import lab_cli as cli

        for arguments in (
            ["launch", "--no-agent"],
            ["launch", "--agent", "codex"],
            ["launch", "--agent-command", "custom-agent --flag"],
        ):
            with self.subTest(arguments=arguments):
                args = build_parser().parse_args(arguments)
                with mock.patch.object(cli, "default_agent") as detect, mock.patch.object(
                    cli, "command_desktop", return_value=0,
                ):
                    self.assertEqual(args.function(args), 0)
                detect.assert_not_called()

    def test_agent_discovery_prepares_graphical_path(self):
        from gem import launcher

        with tempfile.TemporaryDirectory(prefix="gem-launch-test-") as temporary:
            local_bin = Path(temporary) / ".local" / "bin"
            local_bin.mkdir(parents=True)
            with mock.patch.object(launcher.Path, "home", return_value=Path(temporary)), mock.patch.dict(
                os.environ, {"PATH": ""},
            ):
                launcher.prepare_agent_path()
                launcher.prepare_agent_path()
                entries = os.environ["PATH"].split(os.pathsep)
                self.assertNotIn("", entries)
                self.assertEqual(entries.count(str(local_bin)), 1)
            with mock.patch.object(launcher, "prepare_agent_path"), mock.patch.object(
                launcher.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}" if name == "claude" else None,
            ):
                self.assertEqual(launcher.default_agent(), "claude")

    def test_launch_opens_home_without_creating_a_session(self):
        from gem import lab_cli as cli

        args = build_parser().parse_args(["launch", "--toolkit", "tk"])
        with mock.patch.object(cli, "default_agent", return_value=None), mock.patch(
            "gem.app.run_desktop", return_value=0,
        ) as home:
            self.assertEqual(args.function(args), 0)
        home.assert_called_once()
        self.assertIsNone(home.call_args.args[0])
        self.assertIsNone(home.call_args.args[1])
        self.assertFalse(hasattr(args, "target"))
        self.assertFalse(hasattr(args, "session"))

    def test_launch_cancel_is_clean(self):
        from gem import lab_cli as cli

        args = build_parser().parse_args(["launch"])
        with mock.patch.object(cli, "command_desktop", return_value=0) as desktop:
            self.assertEqual(args.function(args), 0)
        desktop.assert_called_once_with(args)
        self.assertFalse(hasattr(args, "target"))
        self.assertFalse(hasattr(args, "session"))

    def test_launch_failure_is_visible(self):
        from gem import lab_cli as cli

        args = build_parser().parse_args(["launch"])
        with mock.patch.object(cli, "command_desktop", side_effect=OSError("display unavailable")), mock.patch.object(
            cli, "show_launch_error",
        ) as show_error:
            self.assertEqual(args.function(args), 1)
        show_error.assert_called_once_with("display unavailable")

    def test_launch_rejects_session_inside_directory_target(self):
        from gem.launcher import session_for_target

        with tempfile.TemporaryDirectory(prefix="gem-launch-test-") as temporary:
            target = Path(temporary)
            with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(target / "data")}):
                with self.assertRaisesRegex(ValueError, "contains GEM's session data"):
                    session_for_target(target)


class AgentBridgeCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gem bridge ")
        self.session = Session(Path(self.temporary.name) / "session with spaces", "/bin/true")
        self.addCleanup(self.temporary.cleanup)

    def test_kimi_receives_session_profile(self):
        from gem.agent_bridge import prepare_agent_command

        command, bootstrap = prepare_agent_command(["kimi"], self.session)
        self.assertEqual(command[:1], ["kimi"])
        self.assertEqual(command[-2], "--agent-file")
        profile = Path(command[-1])
        self.assertEqual(profile.parent, self.session.root)
        text = profile.read_text(encoding="utf-8")
        self.assertIn("${base_prompt}", text)
        self.assertIn("selected item", text)
        self.assertIn("emit command", text)
        self.assertIn(str(self.session.root), text)
        self.assertEqual(bootstrap, "")

    def test_claude_receives_appended_protocol_without_losing_arguments(self):
        from gem.agent_bridge import bridge_prompt, prepare_agent_command

        command, bootstrap = prepare_agent_command(["claude", "--model", "opus"], self.session)
        self.assertEqual(command[:3], ["claude", "--model", "opus"])
        self.assertEqual(command[-2:], ["--append-system-prompt", bridge_prompt(self.session)])
        self.assertEqual(bootstrap, "")

    def test_custom_agent_receives_initial_protocol(self):
        from gem.agent_bridge import prepare_agent_command

        original = ["custom-agent", "--flag"]
        command, bootstrap = prepare_agent_command(original, self.session)
        self.assertEqual(command, original)
        self.assertIn("selected item", bootstrap)
        self.assertIn(str(self.session.cli_path), bootstrap)

    def test_agent_profile_conflicts_fall_back_without_overriding_user_intent(self):
        from gem.agent_bridge import prepare_agent_command

        for original in (["kimi", "--continue"], ["claude", "--system-prompt", "custom"]):
            with self.subTest(command=original):
                command, bootstrap = prepare_agent_command(original, self.session)
                self.assertEqual(command, original)
                self.assertIn("GEM", bootstrap)
        self.assertFalse((self.session.root / "gem-kimi-agent.md").exists())


class DropPayloadCase(unittest.TestCase):
    def test_posix_payload_is_quoted_without_enter(self):
        import shlex
        from metrix.drop import dropped_payload

        with tempfile.TemporaryDirectory(prefix="gem-drop test-") as temporary:
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
        with tempfile.TemporaryDirectory(prefix="gem-drop-test-") as temporary:
            artifact = Path(temporary) / "a&b.bin"
            artifact.touch()
            self.assertEqual(dropped_payload([artifact], windows=True), f'"{artifact}" '.encode())

    def test_missing_empty_and_control_paths_are_rejected(self):
        from metrix.drop import dropped_payload

        with tempfile.TemporaryDirectory(prefix="gem-drop-test-") as temporary:
            with self.assertRaisesRegex(ValueError, "does not exist"):
                dropped_payload([Path(temporary) / "missing"])
            with self.assertRaisesRegex(ValueError, "control characters"):
                dropped_payload([Path(temporary) / "bad\nname"])
        with self.assertRaisesRegex(ValueError, "no local files"):
            dropped_payload([])

    def test_oversized_payload_is_rejected(self):
        from metrix import drop

        with tempfile.TemporaryDirectory(prefix="gem-drop-test-") as temporary:
            artifact = Path(temporary) / "firmware.bin"
            artifact.touch()
            with mock.patch.object(drop, "MAX_DROP_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "8 MiB"):
                    drop.dropped_payload([artifact])


class SafetyCase(unittest.TestCase):
    def test_audit_is_read_only_and_reports_platform_requirements(self):
        from gem.safety import evaluate_safety

        with mock.patch("subprocess.run", side_effect=AssertionError("audit executed an external command")):
            report = evaluate_safety([os.sys.executable])
        self.assertTrue(report["ready"], report["details"])
        self.assertGreaterEqual(len(report["checks"]), 7)
        self.assertTrue(report["summary"])
        self.assertFalse(any("REVIEW" in line and "Native Linux GTK/VTE" not in line for line in report["details"].splitlines()), report["details"])

    def test_permission_prompt_is_single_line_and_bounded(self):
        from gem.safety import agent_request

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
        from gem import safety
        with mock.patch.object(safety.os, "name", "nt"):
            command = safety.command_text([r"C:\Python 311\python.exe", "-m", "pip", "install", "pyte>=0.8.1,<1"])
        self.assertEqual(command, r'"C:\Python 311\python.exe" -m pip install "pyte>=0.8.1,<1"')

    def test_empty_remediation_prompt_is_read_only(self):
        from gem.safety import agent_request

        report = {"summary": "ready", "details": "pass", "remediations": [], "checks": [], "ready": True}
        request = agent_request(report)
        payload = json.loads(request.split("user. ", 1)[1])
        self.assertIn("read-only AI review", payload["instruction"])
        self.assertIn("Do not install", payload["instruction"])


class AccessibilityCase(unittest.TestCase):
    def test_preferences_round_trip_and_validation(self):
        from gem.accessibility import DEFAULT_PALETTE, load_accessibility, save_accessibility

        with tempfile.TemporaryDirectory(prefix="gem-a11y-test-") as temporary:
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
        from gem.accessibility import PALETTE_MODES, contrast_ratio
        from gem.safety import safety_colors

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
        from gem.accessibility import evaluate_accessibility

        report = evaluate_accessibility("colorblind", False, "#0d1117", {"Keyboard navigation": False})
        self.assertFalse(report["ready"])
        self.assertFalse(report["remediations"][0]["command"])
        self.assertIn("Keyboard navigation", report["remediations"][0]["action"])
        passing = evaluate_accessibility("colorblind", False, "#0d1117", {"Keyboard navigation": True})
        self.assertTrue(passing["ready"])
        self.assertIn("Manual assistive-technology validation", passing["details"])

    def test_a11y_agent_request_is_single_line_and_scoped(self):
        from gem.safety import agent_request

        report = {"summary": "a11y", "details": "line one\nline two", "remediations": [], "checks": [], "ready": True}
        request = agent_request(report, "a11y Optimization/Debugging")
        self.assertTrue(request.startswith("a11y Optimization/Debugging requested by the user. "))
        self.assertNotIn("\r", request)
        self.assertNotIn("\n", request)
        payload = json.loads(request.split("user. ", 1)[1])
        self.assertIn("read-only AI review", payload["instruction"])


class StubProvider:
    def __init__(self):
        self.np = np
        self.context = None
        self.contexts = []
        self.probabilities = None

    def forward(self, context):
        self.context = context
        self.contexts.append(context)
        ids = np.array([1, 2, 3], dtype=np.int64)
        if self.probabilities is not None:
            probabilities = self.probabilities
        elif "concentrated" in context:
            probabilities = np.array([0.90, 0.04, 0.04, 0.02], dtype=np.float64)
        else:
            probabilities = np.array([0.70, 0.20, 0.08, 0.02], dtype=np.float64)
        return ids, probabilities, {"model": {"id": "stub-model"}, "top_tokens": []}


class AccessibleVolumeCase(unittest.TestCase):
    def test_strict_threshold_excludes_equal_values(self):
        from gem.accessible_volume import accessible_volume, complementary_volume

        counts = accessible_volume([0.70, 0.20, 0.05, 0.05])
        self.assertEqual(counts, {
            "0.02": 4, "0.05": 2, "0.10": 2,
            "0.15": 2, "0.30": 1, "0.50": 1,
        })
        self.assertEqual(complementary_volume([0.70, 0.20, 0.05, 0.05]), {
            "0.02": 0, "0.05": 2, "0.10": 2,
            "0.15": 2, "0.30": 3, "0.50": 3,
        })

    def test_distribution_and_threshold_validation(self):
        from gem.accessible_volume import accessible_volume

        for probabilities, thresholds in (
            ([], [0.05]),
            ([0.5, 0.6], [0.05]),
            ([0.5, -0.1, 0.6], [0.05]),
            ([0.5, 0.5], []),
            ([0.5, 0.5], [1.1]),
        ):
            with self.subTest(probabilities=probabilities, thresholds=thresholds):
                with self.assertRaises(ValueError):
                    accessible_volume(probabilities, thresholds)

    def test_measure_session_records_separate_evidence(self):
        from gem.accessible_volume import measure_session

        with tempfile.TemporaryDirectory(prefix="gem-accessible-volume-test-") as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            provider = StubProvider()
            report, event = measure_session(session, provider=provider)
            self.assertEqual(report["counts"]["0.05"], 3)
            self.assertEqual(report["vocabulary_size"], 4)
            self.assertEqual(event["source"], "tool")
            self.assertEqual(event["type"], "evidence")
            self.assertEqual(event["parent_id"], session.root_id)
            self.assertEqual(event["id"], report["evidence_event_id"])
            self.assertIn("does not measure the interactive agent", report["scope"])
            probability_path = Path(report["probability_artifact"])
            self.assertTrue(probability_path.is_file())
            with np.load(probability_path) as artifact:
                self.assertEqual(artifact["input_ids"].tolist(), [1, 2, 3])
                self.assertTrue(np.allclose(artifact["probabilities"], [0.70, 0.20, 0.08, 0.02]))
            report_path = probability_path.with_suffix(".json")
            saved = json.loads(report_path.read_text())
            self.assertEqual(saved["counts"], report["counts"])
            self.assertEqual(saved["evidence_event_id"], event["id"])
            self.assertIn("recent_evidence", provider.context)

    def test_measure_context_is_bounded(self):
        from gem.accessible_volume import build_context

        with tempfile.TemporaryDirectory(prefix="gem-accessible-volume-test-") as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            for index in range(40):
                session.emit(
                    f"observation:{index}", session.root_id, "observation", f"Evidence {index}",
                    "partial", "agent", "x" * 500,
                )
            context, state = build_context(session)
            self.assertLessEqual(len(context), 6000)
            self.assertIn("Evidence 39", context)
            self.assertNotIn("Evidence 0", context)
            self.assertEqual(state["selected_id"], session.root_id)

    def test_cli_measure_records_report(self):
        from gem.cli import main

        with tempfile.TemporaryDirectory(prefix="gem-accessible-volume-test-") as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            output = io.StringIO()
            with mock.patch("gem.accessible_volume.DistilGpt2Provider", return_value=StubProvider()):
                with redirect_stdout(output):
                    result = main(["measure", "--session", str(session.root), "--json"])
            self.assertEqual(result, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["counts"]["0.05"], 3)
            self.assertTrue(any(event["id"] == report["evidence_event_id"] for event in session.events()))

    def test_candidate_previews_are_advisory_not_execution(self):
        from gem.accessible_volume import measure_session
        from gem.cli import main

        with tempfile.TemporaryDirectory(prefix="gem-accessible-volume-test-") as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            provider = StubProvider()
            candidates = ["inspect broadly", "concentrated review"]
            report, _ = measure_session(session, provider=provider, candidates=candidates)
            self.assertEqual(report["counts"]["0.05"], 3)
            self.assertEqual(report["candidates"][0]["counts"]["0.05"], 3)
            self.assertEqual(report["candidates"][1]["counts"]["0.05"], 1)
            self.assertEqual(report["candidates"][1]["delta"]["0.05"], -2)
            self.assertEqual(report["most_concentrated_candidate"]["action"], "concentrated review")
            self.assertIn("no action is authorized or executed", report["scope"])
            self.assertEqual(len(provider.contexts), 3)
            with np.load(report["probability_artifact"]) as artifact:
                self.assertIn("candidate_0_probabilities", artifact)
                self.assertIn("candidate_1_probabilities", artifact)
            output = io.StringIO()
            with mock.patch("gem.accessible_volume.DistilGpt2Provider", return_value=StubProvider()):
                with redirect_stdout(output):
                    result = main([
                        "measure", "--session", str(session.root), "--candidate", "concentrated review",
                    ])
            self.assertEqual(result, 0)
            self.assertIn("Most concentrated candidate: concentrated review", output.getvalue())
            before_invalid = len(provider.contexts)
            with self.assertRaises(ValueError):
                measure_session(session, provider=provider, candidates=[""])
            with self.assertRaises(ValueError):
                measure_session(session, provider=provider, candidates=[f"candidate-{index}" for index in range(17)])
            self.assertEqual(len(provider.contexts), before_invalid)

    def test_complement_and_momentum_history(self):
        from gem.accessible_volume import measure_session, momentum_guidance

        with tempfile.TemporaryDirectory(prefix="gem-accessible-volume-test-") as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            provider = StubProvider()
            first, _ = measure_session(session, provider=provider)
            self.assertEqual(first["complement_counts"]["0.05"], 1)
            provider.probabilities = np.array([0.90, 0.04, 0.04, 0.02], dtype=np.float64)
            second, _ = measure_session(session, provider=provider)
            self.assertEqual(second["complement_counts"]["0.05"], 3)
            self.assertEqual(second["momentum"]["0.05"], -2)
            self.assertEqual(second["guidance"]["trend"], "narrowing")
            self.assertEqual(second["guidance"]["suggestion"], "Narrow context")
            self.assertEqual(second["previous_report"], first["probability_artifact"].replace(".npz", ".json"))
            self.assertFalse(second["guidance"]["executed"])
            third, _ = measure_session(session, provider=provider)
            self.assertEqual(third["momentum"]["0.05"], 0)
            self.assertEqual(third["guidance"]["suggestion"], "Proceed within a target band")
            self.assertEqual(momentum_guidance({"0.05": 2}, "0.05", 1)["suggestion"], "Broaden context")
            self.assertEqual(momentum_guidance({"0.05": -1}, "0.05", 1)["suggestion"], "Let the current trend continue")
            with self.assertRaises(ValueError):
                measure_session(session, provider=provider, momentum_band=-1)


class VolumeBridgeCase(unittest.TestCase):
    def write_distribution(self, path, probabilities):
        np.savez(path, input_ids=np.arange(len(probabilities), dtype=np.int64), probabilities=np.asarray(probabilities, dtype=np.float64))

    def test_forward_backward_feedback_and_no_overwrite(self):
        from gem.volume_bridge import VolumeBridge

        with tempfile.TemporaryDirectory(prefix="gem-volume-bridge-test-") as directory:
            root = Path(directory)
            previous = root / "previous.npz"
            current = root / "current.npz"
            self.write_distribution(previous, [0.70, 0.20, 0.08, 0.02])
            self.write_distribution(current, [0.90, 0.04, 0.04, 0.02])
            session = Session(root / "session", "/bin/true")
            bridge = VolumeBridge(session)
            observation = bridge.observe(current, previous=previous)
            self.assertEqual(observation["counts"]["0.05"], 1)
            self.assertEqual(observation["complement_counts"]["0.05"], 3)
            self.assertEqual(observation["momentum"]["0.05"], -2)
            self.assertEqual(observation["guidance"]["suggestion"], "Narrow context")
            self.assertFalse(observation["guidance"]["executed"])
            self.assertGreaterEqual(observation["elapsed_ns"], 0)
            self.assertTrue(observation["created_utc"].endswith("Z"))
            self.assertEqual(len(observation["input_ids_sha256"]), 64)
            self.assertEqual(len(observation["probability_values_sha256"]), 64)
            first_report = observation["feedback"]["report"]
            self.assertTrue(Path(first_report).is_file())
            self.assertTrue(Path(observation["feedback"]["probabilities"]).is_file())
            second = bridge.observe(current, previous=previous)
            self.assertNotEqual(second["feedback"]["report"], first_report)
            self.assertTrue(Path(second["feedback"]["report"]).is_file())
            self.assertTrue(any(event["type"] == "evidence" for event in session.events()))

    def test_custom_keys_and_target_volume_band(self):
        from gem.volume_bridge import VolumeBridge

        with tempfile.TemporaryDirectory(prefix="gem-volume-bridge-test-") as directory:
            root = Path(directory)
            previous = root / "previous.npz"
            current = root / "current.npz"
            np.savez(previous, earlier=np.asarray([1.0, 0.0, 0.0, 0.0]))
            np.savez(current, current=np.asarray([0.70, 0.20, 0.08, 0.02]))
            observation = VolumeBridge().observe(
                current, previous=previous, thresholds=[0.05],
                key="current", previous_key="earlier", minimum=4, maximum=6,
            )
            self.assertEqual(observation["counts"]["0.05"], 3)
            self.assertEqual(observation["momentum"]["0.05"], 2)
            self.assertEqual(observation["guidance"]["suggestion"], "let_breadth_grow")
            self.assertEqual(observation["guidance"]["target_volume_band"], [4, 6])
            self.assertFalse(observation["guidance"]["executed"])

            from gem.cli import main

            output = root / "session.json"
            session = root / "cli-session"
            Session(session, "/bin/true")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([
                    "volume", str(current), "--session", str(session),
                    "--previous", str(previous), "--key", "current", "--previous-key", "earlier",
                    "--tau", "0.05", "--min-volume", "4", "--max-volume", "6",
                    "--output", str(output),
                ]), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["counts"]["0.05"], 3)
            self.assertEqual(report["momentum"]["0.05"], 2)
            self.assertEqual(report["guidance"]["suggestion"], "let_breadth_grow")
            self.assertFalse(report["guidance"]["executed"])

    def test_artifact_volume_cli_keys_bands_and_required_output(self):
        from gem.cli import main

        with tempfile.TemporaryDirectory(prefix="gem-volume-bridge-test-") as directory:
            root = Path(directory)
            previous = root / "previous.npz"
            current = root / "current.npz"
            output = root / "artifact.json"
            np.savez(previous, earlier=np.asarray([1.0, 0.0, 0.0, 0.0]))
            np.savez(current, current=np.asarray([0.70, 0.20, 0.08, 0.02]))
            arguments = [
                "volume", "--probabilities", str(current), "--key", "current",
                "--previous", str(previous), "--previous-key", "earlier",
                "--tau", "0.05", "--min-volume", "4", "--max-volume", "6",
            ]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 2)
                self.assertEqual(main([*arguments, "--session", str(root / "session")]), 2)
                self.assertEqual(main([*arguments, "--output", str(output)]), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            entry = report["threshold_sweep"][0]
            self.assertEqual(entry["accessible_volume"], 3)
            self.assertEqual(entry["complement_volume"], 1)
            self.assertEqual(entry["accessible_momentum"], 2)
            self.assertEqual(entry["suggested_action"], "let_breadth_grow")
            self.assertEqual(report["source"]["key"], "current")
            self.assertEqual(report["previous_source"]["key"], "earlier")

    def test_volume_cli_never_overwrites_output(self):
        from gem.cli import main

        with tempfile.TemporaryDirectory(prefix="gem-volume-bridge-test-") as directory:
            root = Path(directory)
            previous = root / "previous.npz"
            current = root / "current.npz"
            self.write_distribution(previous, [0.70, 0.20, 0.08, 0.02])
            self.write_distribution(current, [0.90, 0.04, 0.04, 0.02])
            output = root / "momentum.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["volume", str(current), "--previous", str(previous), "--output", str(output)]), 0)
            original = output.read_text()
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["volume", str(current), "--previous", str(previous), "--output", str(output)]), 2)
            self.assertEqual(output.read_text(), original)


class BrandingCase(unittest.TestCase):
    def test_packaged_assets_match_the_master_set(self):
        root = Path(__file__).resolve().parents[2]
        master = root / "assets" / "branding" / "woven-diamond"
        packaged = root / "gem-lab" / "gem" / "icons"
        pairs = {
            "png/gem-woven-diamond-512x512.png": "gem-woven-diamond.png",
            "png/gem-woven-diamond-32x32.png": "gem-woven-diamond-32.png",
            "windows/gem-woven-diamond.ico": "gem-woven-diamond.ico",
            "macos/gem-woven-diamond.icns": "gem-woven-diamond.icns",
            "source/gem-woven-diamond.svg": "gem-woven-diamond.svg",
        }
        for source, destination in pairs.items():
            with self.subTest(destination=destination):
                self.assertEqual(
                    (master / source).read_bytes(),
                    (packaged / destination).read_bytes(),
                )

    def test_icon_containers_and_desktop_entry(self):
        root = Path(__file__).resolve().parents[2]
        packaged = root / "gem-lab" / "gem" / "icons"
        self.assertEqual(int.from_bytes((packaged / "gem-woven-diamond.ico").read_bytes()[4:6], "little"), 7)
        self.assertTrue((packaged / "gem-woven-diamond.icns").read_bytes().startswith(b"icns"))
        self.assertIn("GEM Woven Diamond", (packaged / "gem-woven-diamond.svg").read_text())
        desktop = root / "gem-lab" / "packaging" / "re.gem.workbench.desktop.in"
        self.assertIn("Icon=gem-woven-diamond", desktop.read_text())
        linux_installer = (root / "gem-lab" / "packaging" / "install_linux.sh").read_text()
        self.assertIn('install -m 0644 "$SOURCE/gem-woven-diamond.png"', linux_installer)
        self.assertNotIn("gem-woven-diamond-logo.png", linux_installer)
        for obsolete in ("ablation-gem-logo.png", "ablation-gem-logo-32.png", "ablation-gem.ico", "ablation-gem.icns"):
            self.assertFalse((packaged / obsolete).exists(), obsolete)


def main():
    parser = argparse.ArgumentParser(description="Run GEM core stress tests")
    parser.add_argument("--failfast", action="store_true")
    args = parser.parse_args()
    suite = unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(SessionCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(DirectorySessionCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(AgentCommandCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(LauncherCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(AgentBridgeCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(DropPayloadCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(SafetyCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(AccessibilityCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(AccessibleVolumeCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(VolumeBridgeCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(BrandingCase),
    ])
    result = unittest.TextTestRunner(verbosity=2, failfast=args.failfast).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
