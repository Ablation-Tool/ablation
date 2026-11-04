import contextlib
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from gem.agent import AgentError, extract_scene, invoke_agent, solve
from gem.cli import main as gem_main
from gem.events import Session
from gem.geometry import verify
from gem.host import GemCommandBroker, GemLabHost
from gem.model import MAX_POINTS, Scene, demo_scene, scene_from_events
from gem.render import scene_to_svg, write_png
from gem.runner import export_run, replay, verify_vdi
from gem.volume import VolumeBridge, accessible_momentum, accessible_volume, steering_action
from gem.vdi import (
    opcode_inventory,
    parse_metafile,
    scene_from_metafile,
    scene_to_metafile,
)


HAS_GTK = False
if os.environ.get("DISPLAY"):
    try:
        import cairo
        import gi
        gi.require_version("Gdk", "3.0")
        gi.require_version("Gtk", "3.0")
        gi.require_foreign("cairo")
        from gi.repository import GLib, Gtk
        from gem.view import GemView
        HAS_GTK = True
    except (ImportError, ValueError):
        pass


class GeometryCase(unittest.TestCase):
    def test_demo_source_and_vdi_constraints(self):
        scene = demo_scene()
        source = verify(scene)
        self.assertTrue(source.passed, source.text())
        self.assertEqual(source.to_dict()["constraints_passed"], 4)
        data = scene_to_metafile(scene)
        recovered = scene_from_metafile(data, scene.constraints)
        self.assertEqual([item["id"] for item in recovered.objects], [item["id"] for item in scene.objects])
        self.assertEqual(recovered.object("caption")["size"], 260)
        self.assertTrue(verify(recovered).passed)
        inventory = opcode_inventory(data)
        self.assertEqual(inventory["v_bar"], 4)
        self.assertEqual(inventory["v_fillarea"], 1)
        self.assertEqual(inventory["v_ellipse"], 1)
        self.assertEqual(inventory["v_write_meta"], 8)
        self.assertEqual(inventory["vst_height"], 2)

    def test_small_device_quantization_preserves_connector_invariants(self):
        events = [
            {"id": "root", "parent_id": None, "label": "root", "status": "in_progress"},
            {"id": "child", "parent_id": "root", "label": "child", "status": "not_started"},
            {"id": "observation", "parent_id": "root", "label": "observation", "status": "complete_scoped"},
        ]
        scene = scene_from_events(events, "root")
        for dimensions in ((320, 200), (640, 480)):
            with self.subTest(dimensions=dimensions):
                scaled = scene.rescaled(*dimensions, scene_id=f"scene-{dimensions[0]}")
                report = verify_vdi(scaled)
                self.assertTrue(report.passed, report.text())

    def test_failure_diagnostics_and_pair_symmetry(self):
        document = demo_scene().to_dict()
        document["objects"][1]["points"][0][1] -= 300
        document["objects"][1]["points"][2][1] -= 300
        document["objects"][2]["bounds"][3] += 500
        document["objects"][4]["bounds"] = [5900, 3200, 6600, 4600]
        scene = Scene.from_dict(document)
        report = verify(scene)
        self.assertFalse(report.passed)
        self.assertEqual(report.to_dict()["constraints_passed"], 1)
        self.assertIn("roof", report.failed_ids)
        self.assertIn("door", report.failed_ids)
        self.assertIn("right_window", report.failed_ids)
        detail = report.results[2]["detail"]
        self.assertIn("centers 3750, 6250", detail)
        document = demo_scene().to_dict()
        document["objects"][3]["bounds"] = [4650, 3200, 5350, 3900]
        document["objects"][4]["bounds"] = [4650, 3200, 5350, 3900]
        self.assertTrue(verify(Scene.from_dict(document)).results[2]["passed"])

    def test_all_constraint_types(self):
        document = demo_scene().to_dict()
        document["objects"].append({
            "id": "connector", "type": "line", "points": [[5000, 5500], [5000, 5700]],
            "stroke": "black", "fill": "none",
        })
        document["constraints"] = [
            {"type": "touches", "a": "roof", "b": "body"},
            {"type": "contains", "outer": "body", "inner": "door"},
            {"type": "symmetric", "a": "left_window", "b": "right_window", "axis": "x", "value": 5000},
            {"type": "aligned", "a": "left_window", "b": "right_window", "axis": "top"},
            {"type": "inside_canvas", "object": "*"},
            {"type": "nonoverlap", "objects": ["left_window", "right_window"]},
            {"type": "connected", "a": "connector", "b": "body", "anchor": "bottom", "endpoint": 0},
        ]
        self.assertTrue(verify(Scene.from_dict(document)).passed)
        document["constraints"][-1]["anchor"] = "top"
        self.assertFalse(verify(Scene.from_dict(document)).results[-1]["passed"])

    def test_schema_rejects_malformed_and_unbounded_scenes(self):
        document = demo_scene().to_dict()
        document["objects"][0]["bounds"][0] = float("nan")
        with self.assertRaisesRegex(ValueError, "finite"):
            Scene.from_dict(document)
        document = demo_scene().to_dict()
        document["objects"][1]["id"] = "body"
        with self.assertRaisesRegex(ValueError, "unique"):
            Scene.from_dict(document)
        document = demo_scene().to_dict()
        document["constraints"][0]["a"] = "missing"
        with self.assertRaisesRegex(ValueError, "unknown object"):
            Scene.from_dict(document)
        document = demo_scene().to_dict()
        document["objects"][0]["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            Scene.from_dict(document)
        document = demo_scene().to_dict()
        document["objects"][1]["points"] = [[0, 0], [1, 1], [2, 2]] * (MAX_POINTS // 3 + 1)
        with self.assertRaisesRegex(ValueError, "too many points"):
            Scene.from_dict(document)

    def test_event_layout_long_ids_and_selection(self):
        root = "r" * 128
        child = "c" * 128
        events = [
            {"id": root, "parent_id": None, "label": "x" * 500, "status": "not_started"},
            {"id": child, "parent_id": root, "label": "child", "status": "partial"},
        ]
        scene = scene_from_events(events, root, child)
        self.assertTrue(verify(scene).passed, verify(scene).text())
        connector = next(item for item in scene.objects if item["role"] == "connector")
        self.assertLessEqual(len(connector["id"]), 128)
        self.assertEqual(connector["from"], root)
        self.assertEqual(connector["to"], child)
        self.assertLessEqual(len(scene.object(child)["label"]), 500)
        recovered = scene_from_metafile(scene_to_metafile(scene), scene.constraints)
        self.assertTrue(recovered.object(child)["selected"])
        self.assertTrue(verify(recovered).passed)


class ArtifactCase(unittest.TestCase):
    def test_vdi_rejects_truncation_trailing_and_bad_metadata(self):
        data = scene_to_metafile(demo_scene())
        for malformed in (data[:-2], data + b"\0", data + struct.pack("<h", -1), b"not a metafile"):
            with self.subTest(length=len(malformed)), self.assertRaises(ValueError):
                parse_metafile(malformed)
        document = bytearray(data)
        document[58] = ord("X")
        with self.assertRaises(ValueError):
            scene_from_metafile(bytes(document))

    def test_run_replay_and_hash_tamper_detection(self):
        scene = demo_scene()
        incomplete = scene.to_dict()
        incomplete["objects"] = [item for item in incomplete["objects"] if item["id"] != "caption"]
        with mock.patch("gem.runner.scene_from_metafile", return_value=Scene.from_dict(incomplete)):
            report = verify_vdi(scene, b"fixture")
        self.assertEqual(report.to_dict()["constraints_passed"], 4)
        self.assertFalse(report.invariants["object_ids_preserved"])
        self.assertFalse(report.invariants["object_count_preserved"])
        self.assertFalse(report.passed)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run"
            result = export_run(demo_scene(), path, trajectory=[{"sequence": 1, "kind": "test"}])
            self.assertTrue(result.passed)
            self.assertTrue(all(item["passed"] for item in result.devices.values()))
            expected = {
                "scene.json", "scene.gem", "scene-cga.gem", "scene-vga.gem", "scene-ndc.gem",
                "preview.svg", "source-report.json", "vdi-report.json", "device-report.json",
                "trajectory.jsonl", "run.json",
            }
            self.assertEqual({item.name for item in path.iterdir()}, expected)
            replayed = replay(path)
            self.assertTrue(replayed.passed)
            self.assertTrue(replayed.matches_recorded)
            with self.assertRaises(FileExistsError):
                export_run(demo_scene(), path)
            (path / "source-report.json").write_text('{"passed":true}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                replay(path)

    def test_concurrent_export_has_one_writer_and_a_replayable_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run"

            def export(_index):
                try:
                    export_run(demo_scene(), path)
                    return "written"
                except FileExistsError:
                    return "rejected"

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(export, range(2)))

            self.assertEqual(outcomes.count("written"), 1)
            self.assertEqual(outcomes.count("rejected"), 1)
            self.assertFalse((path / ".export.lock").exists())
            self.assertTrue(replay(path).matches_recorded)

    def test_export_failure_releases_writer_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run"
            with mock.patch("gem.runner._atomic_write", side_effect=OSError("injected disk failure")):
                with self.assertRaisesRegex(OSError, "injected disk failure"):
                    export_run(demo_scene(), path)
            self.assertFalse((path / ".export.lock").exists())

    @unittest.skipIf(os.name == "nt", "requires symbolic-link support")
    def test_export_rejects_symlinked_run_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside").mkdir()
            (root / "run").symlink_to(root / "outside", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                export_run(demo_scene(), root / "run")

    @unittest.skipIf(os.name == "nt", "requires symbolic-link support")
    def test_export_rejects_symlinked_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "run"
            path.mkdir()
            original = root / "original.json"
            original.write_text("preserve", encoding="utf-8")
            (path / "scene.json").symlink_to(original)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                export_run(demo_scene(), path, overwrite=True)
            self.assertEqual(original.read_text(encoding="utf-8"), "preserve")

    def test_stale_export_lock_is_explicit_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run"
            path.mkdir()
            (path / ".export.lock").write_text("stale", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                export_run(demo_scene(), path)
            self.assertFalse((path / "scene.json").exists())
            self.assertTrue((path / ".export.lock").is_file())

    def test_render_and_replay_resource_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scene.png"
            with self.assertRaisesRegex(ValueError, "dimensions"):
                write_png(demo_scene(), path, width=16384)
            document = demo_scene().to_dict()
            document["canvas"] = {"width": 1, "height": 32767}
            with self.assertRaisesRegex(ValueError, "dimensions"):
                write_png(Scene.from_dict(document), path)
            run = export_run(demo_scene(), Path(directory) / "run").path
            with mock.patch("gem.runner.MAX_RUN_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "too large"):
                    replay(run)
            self.assertFalse(path.exists())

    def test_metafile_size_limit_is_enforced(self):
        with mock.patch("gem.vdi.MAX_METAFILE_BYTES", 4):
            with self.assertRaisesRegex(ValueError, "too large"):
                parse_metafile(b"12345")

    def test_svg_and_optional_real_cairo_rendering(self):
        document = demo_scene().to_dict()
        document["objects"][0]["label"] = "body <&>"
        scene = Scene.from_dict(document)
        svg = scene_to_svg(scene)
        self.assertIn("body &lt;&amp;&gt;", svg)
        self.assertIn('data-object-id="roof"', svg)
        self.assertNotIn("<script", svg)
        if importlib.util.find_spec("cairo") is None:
            with self.assertRaises(RuntimeError):
                write_png(scene, Path(tempfile.gettempdir()) / "unused-gem-test.png")
            return
        import cairo
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scene.png"
            write_png(scene, path, 800)
            surface = cairo.ImageSurface.create_from_png(str(path))
            self.assertEqual((surface.get_width(), surface.get_height()), (800, 480))
            self.assertGreater(len(set(surface.get_data())), 20)


class EnvironmentCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gem-gem-host-")
        self.session = Session(Path(self.temporary.name) / "session", "/bin/true")
        self.host = GemLabHost(self.session)
        self.broker = GemCommandBroker(self.host)
        self.session.emit("artifact:child", self.session.root_id, "artifact", "firmware.bin")

    def tearDown(self):
        self.temporary.cleanup()

    def test_unified_objects_and_derived_state_is_not_authoritative(self):
        snapshot = self.broker.execute({"command": "snapshot"})
        self.assertEqual(snapshot["environment"], "gem")
        self.assertEqual(snapshot["application"], "gem-lab")
        references = {item["reference"] for item in snapshot["derived"]["objects"]}
        self.assertIn("investigation:artifact:child", references)
        spatial = next(item for item in snapshot["derived"]["objects"] if item["kind"] == "spatial")
        resolved = self.broker.execute({"command": "resolve", "reference": spatial["reference"]})
        self.assertEqual(resolved["kind"], "spatial")
        before = self.session.events_path.read_bytes()
        snapshot["derived"]["scene"]["objects"][0]["label"] = "changed only in the view"
        self.assertEqual(self.session.events_path.read_bytes(), before)
        with self.assertRaisesRegex(ValueError, "unsupported GEM command fields"):
            self.broker.execute({"command": "snapshot", "unexpected": True})

    def test_broker_selection_and_begin_are_revision_checked(self):
        revision = self.session.current_state()["revision"]
        selected = self.broker.execute({
            "command": "select", "id": "artifact:child", "expected_revision": revision,
        })
        self.assertEqual(selected["selected_id"], "artifact:child")
        began = self.broker.execute({
            "command": "begin_selected_work",
            "expected_id": "artifact:child",
            "expected_revision": selected["revision"],
        })
        self.assertEqual(began["selected"]["status"], "in_progress")
        with self.assertRaisesRegex(ValueError, "stale selection revision"):
            self.broker.execute({
                "command": "select", "id": self.session.root_id, "expected_revision": revision,
            })

    def test_host_export_and_lab_state_share_replayed_evidence(self):
        self.session.select("artifact:child")
        outcome = self.broker.execute({"command": "export"})
        self.assertTrue(outcome.passed)
        self.assertTrue(outcome.replay.matches_recorded)
        self.assertEqual(outcome.evidence["status"], "complete_scoped")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(gem_main(["lab-state", "--session", str(self.session.root)]), 0)
        snapshot = json.loads(output.getvalue())
        self.assertEqual(snapshot["environment"], "gem")
        self.assertIn(outcome.evidence["id"], {
            item["id"] for item in snapshot["authoritative"]["events"]
        })

    def test_export_rejects_stale_revision(self):
        revision = self.session.current_state()["revision"]
        self.session.select("artifact:child")
        with self.assertRaisesRegex(ValueError, "stale selection revision"):
            self.broker.execute({"command": "export", "expected_revision": revision})
        self.assertFalse((self.session.root / "gem-runs").exists())

    def test_real_ablation_analysis_becomes_scoped_replayable_evidence(self):
        state = self.session.current_state()
        began = self.session.begin_selected_work(state["selected_id"], state["revision"])
        target = Path(self.session.target)
        environment = os.environ.copy()
        source_root = str(Path(__file__).resolve().parents[2])
        environment["PYTHONPATH"] = source_root + os.pathsep + environment.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, "-m", "ablation.cli", "analyze", str(target), "--entropy"],
            capture_output=True, text=True, timeout=30, env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip())
        evidence_path = self.session.root / "analysis" / "system-true.txt"
        evidence_path.parent.mkdir(exist_ok=True)
        evidence_path.write_text(result.stdout, encoding="utf-8")
        scope = "Static metadata and entropy inspection only; no target execution"
        observation = self.session.emit(
            "observation:system-true-analysis",
            self.session.root_id,
            "observation",
            "System binary metadata and entropy",
            "complete_scoped",
            "tool",
            evidence_path.relative_to(self.session.root).as_posix(),
            "Ablation analyze completed on the selected system binary; target not executed",
            scope,
        )
        self.assertEqual(observation["scope"], scope)
        outcome = self.broker.execute({
            "command": "export", "expected_revision": began["revision"],
        })
        self.assertTrue(
            outcome.passed,
            f"run={outcome.run.passed}; replay={outcome.replay.passed}; "
            f"matches={outcome.replay.matches_recorded}; evidence={outcome.evidence}",
        )
        self.assertTrue(outcome.replay.matches_recorded)
        self.assertTrue(evidence_path.is_file())

    def test_snapshot_selection_and_scene_are_coherent(self):
        self.session.select("artifact:child")
        state, _parent_id, scene, events = self.host.current_scene()
        self.assertEqual(state["selected"]["id"], "artifact:child")
        self.assertIn("artifact:child", {event["id"] for event in events})
        selected = [item for item in scene.objects if item.get("selected")]
        self.assertEqual([item["event_id"] for item in selected], ["artifact:child"])
        snapshot = self.host.snapshot()
        self.assertEqual(snapshot["revision"], state["revision"])
        self.assertEqual(snapshot["authoritative"]["selected_id"], state["selected_id"])

    def test_lab_command_delegates_to_the_native_application(self):
        with mock.patch("gem.lab_cli.main", return_value=0) as launch:
            result = gem_main([
                "lab", "/bin/true", "--session", str(self.session.root), "--no-agent",
            ])
        self.assertEqual(result, 0)
        launch.assert_called_once_with([
            "desktop", "/bin/true", "--session", str(self.session.root),
            "--toolkit", "auto", "--no-agent",
        ])


class AgentCase(unittest.TestCase):
    def fake_agent(self, directory):
        path = Path(directory) / "fake_agent.py"
        path.write_text(textwrap.dedent("""
            import json
            import sys
            from gem.model import demo_scene
            prompt = sys.stdin.read()
            scene = demo_scene().to_dict()
            if "previous response failed" not in prompt:
                scene["objects"][4]["bounds"] = [6400, 3200, 7100, 3900]
            print(json.dumps(scene))
        """), encoding="utf-8")
        return [sys.executable, str(path)]

    def test_generate_verify_repair_and_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            result = solve("Draw the verified house", self.fake_agent(directory), max_attempts=3, timeout=10)
            self.assertTrue(result.passed, result.error)
            self.assertEqual(result.attempts, 2)
            self.assertEqual([item["outcome"] for item in result.trajectory], ["constraints_failed", "passed"])
            self.assertIn("symmetric", result.trajectory[1]["prompt"])
            run = export_run(result.scene, Path(directory) / "run", result.trajectory)
            self.assertTrue(run.passed)
            self.assertTrue(replay(run.path).matches_recorded)

    def test_prompt_delivery_extraction_and_invalid_response(self):
        result = invoke_agent(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", "{prompt}"], "prompt-marker", timeout=5,
        )
        self.assertEqual(result["stdout"].strip(), "prompt-marker")
        result = invoke_agent([sys.executable, "-c", "import sys; print(sys.stdin.read())"], "stdin-marker", timeout=5)
        self.assertEqual(result["stdout"].strip(), "stdin-marker")
        response = "Result:\n```json\n" + demo_scene().json() + "\n```"
        self.assertTrue(verify(extract_scene(response)).passed)
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, "-c", "print('not a scene')"]
            result = solve("invalid fixture", command, max_attempts=2, timeout=5, cwd=directory)
            self.assertIsNone(result.scene)
            self.assertEqual([item["outcome"] for item in result.trajectory], ["invalid_scene"] * 2)

    def test_timeout_kills_the_entire_process_group(self):
        with self.assertRaises(AgentError) as caught:
            invoke_agent(["/bin/sh", "-c", "sleep 30 & echo $!; wait"], "prompt", timeout=0.1)
        child_id = int(str(caught.exception).split("output='", 1)[1].split("\\n'", 1)[0])
        deadline = time.monotonic() + 2
        stat = Path(f"/proc/{child_id}/stat")
        while stat.exists() and time.monotonic() < deadline:
            if stat.read_text().split()[2] == "Z":
                break
            time.sleep(0.01)
        self.assertTrue(not stat.exists() or stat.read_text().split()[2] == "Z")

    def test_windows_timeout_uses_bounded_tree_termination(self):
        from gem._process import terminate_process_tree

        process = mock.Mock(pid=2468)
        with mock.patch("gem._process.os.name", "nt"), mock.patch(
            "gem._process.subprocess.run",
        ) as terminate, mock.patch.object(process, "kill") as kill:
            terminate_process_tree(process)
        terminate.assert_called_once_with(
            ["taskkill", "/PID", "2468", "/T", "/F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=5,
        )
        kill.assert_called_once_with()

    def test_metrix_timeout_uses_shared_process_cleanup(self):
        from metrix.agent import AgentBridge, AgentError as MetrixAgentError

        with tempfile.TemporaryDirectory() as directory:
            bridge = AgentBridge(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                directory, directory, timeout=0.05,
            )
            with self.assertRaisesRegex(MetrixAgentError, "timed out"):
                bridge.ask("Inspect the selected corpus", [], {}, [])
            bridge = AgentBridge([
                sys.executable, "-c",
                "import os,sys; prompt=sys.stdin.read(); assert 'Inspect' in prompt; "
                "assert os.environ['METRIX_READ_ONLY_REQUEST']=='1'; "
                "print('METRIX_JSON={\"message\":\"Observed\",\"action\":null}')",
            ], directory, directory, timeout=5)
            response = bridge.ask("Inspect the selected corpus", [], {}, [])
            self.assertEqual(response["message"], "Observed")
            self.assertEqual(response["exit_code"], 0)

    def test_agent_output_is_bounded(self):
        command = [sys.executable, "-c", "import sys; sys.stdout.write('x' * (8 * 1024 * 1024 + 1))"]
        with self.assertRaisesRegex(AgentError, "exceeds"):
            invoke_agent(command, "prompt", timeout=5)

    def test_timeout_is_bounded(self):
        started = time.monotonic()
        with self.assertRaisesRegex(AgentError, "timed out"):
            invoke_agent([sys.executable, "-c", "import time; time.sleep(30)"], "prompt", timeout=0.05)
        self.assertLess(time.monotonic() - started, 3)


class CliCase(unittest.TestCase):
    def test_demo_verify_render_and_replay_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(gem_main(["demo", "--output", str(run)]), 0)
                self.assertEqual(gem_main(["verify", str(run / "scene.json"), "--vdi", "--json"]), 0)
                self.assertEqual(gem_main(["render", str(run / "scene.json"), "--output", str(Path(directory) / "scene.svg")]), 0)
                self.assertEqual(gem_main(["replay", str(run), "--json"]), 0)
            self.assertIn('"matches_recorded": true', output.getvalue())
            self.assertTrue((Path(directory) / "scene.svg").is_file())
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["replay", str(run), "--json"]), 0)
                self.assertEqual(gem_main(["render", str(run / "scene.json"), "--output", str(Path(directory) / "bad.unknown")]), 2)
            self.assertIn("output format", errors.getvalue())


@unittest.skipUnless(HAS_GTK, "native GEM tests require GTK, Cairo, and an X11 DISPLAY")
class NativeGemCase(unittest.TestCase):
    def test_native_render_hit_testing_and_selection(self):
        events = [
            {"id": "root", "parent_id": None, "label": "Root", "status": "not_started"},
            {"id": "child", "parent_id": "root", "label": "Child", "status": "partial"},
        ]
        selected = []
        widget = GemView(selected.append)
        widget.set_model(scene_from_events(events, "root", "child"), "root", "child")
        window = Gtk.Window()
        window.set_default_size(640, 480)
        window.add(widget)
        window.show_all()
        context = GLib.MainContext.default()
        deadline = time.monotonic() + 0.2
        while time.monotonic() < deadline:
            context.iteration(False)
            time.sleep(0.005)
        try:
            child = widget.scene.object("child")
            left, top, right, bottom = child["bounds"]
            layout = widget.update_layout()
            x = layout.offset_x + (left + right) / 2 * layout.scale
            y = layout.offset_y + (top + bottom) / 2 * layout.scale
            self.assertEqual(widget.item_at(x, y)["event_id"], "child")
            widget.on_motion(widget, mock.Mock(x=x, y=y))
            self.assertIn("Child", widget.get_tooltip_text())
            self.assertTrue(widget.on_button(widget, mock.Mock(button=1, x=x, y=y)))
            self.assertEqual(selected, ["child"])
            surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, 640, 480)
            widget.draw(cairo.Context(surface))
            self.assertGreater(len(set(surface.get_data())), 20)
            self.assertIn("not human confirmation", widget.get_accessible().get_description())
        finally:
            window.destroy()
            deadline = time.monotonic() + 0.05
            while time.monotonic() < deadline:
                context.iteration(False)
                time.sleep(0.005)


class VolumeCase(unittest.TestCase):
    def test_volume_complement_and_momentum_invariants(self):
        probabilities = [0.70, 0.20, 0.08, 0.02]
        self.assertEqual(accessible_volume(probabilities, 0.05), 3)
        self.assertEqual(accessible_volume([0.05] * 20, 0.05), 0)
        bridge = VolumeBridge(minimum=4, maximum=6)
        first = bridge.observe([1.0, 0.0, 0.0, 0.0], thresholds=[0.05])
        second = bridge.observe(probabilities, thresholds=[0.05])
        entry = second["threshold_sweep"][0]
        self.assertNotIn("accessible_momentum", first["threshold_sweep"][0])
        self.assertEqual(entry["accessible_momentum"], 2)
        self.assertEqual(entry["suggested_action"], "let_breadth_grow")
        self.assertEqual(entry["accessible_volume"] + entry["complement_volume"], 4)
        self.assertEqual(entry["accessible_momentum"] + (-entry["accessible_momentum"]), 0)

    def test_steering_directions(self):
        self.assertEqual(steering_action(2, -1, 3, 5), "broaden_context")
        self.assertEqual(steering_action(2, 1, 3, 5), "let_breadth_grow")
        self.assertEqual(steering_action(6, 1, 3, 5), "narrow_context")
        self.assertEqual(steering_action(6, -1, 3, 5), "let_breadth_settle")
        self.assertEqual(steering_action(4, 0, 3, 5), "continue")

    def test_volume_command_and_validation(self):
        import numpy as np
        with tempfile.TemporaryDirectory() as directory:
            current = Path(directory) / "current.npz"
            previous = Path(directory) / "previous.npz"
            output = Path(directory) / "evidence.json"
            np.savez(current, probabilities=np.array([0.70, 0.20, 0.08, 0.02]))
            np.savez(previous, probabilities=np.array([1.0, 0.0, 0.0, 0.0]))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main([
                    "volume", str(current), "--previous", str(previous),
                    "--tau", "0.05", "--min-volume", "4", "--max-volume", "6",
                    "--output", str(output),
                ]), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            entry = report["threshold_sweep"][0]
            self.assertEqual(entry["accessible_volume"], 3)
            self.assertEqual(entry["complement_volume"], 1)
            self.assertEqual(entry["accessible_momentum"], 2)
            self.assertEqual(entry["suggested_action"], "let_breadth_grow")
            self.assertGreaterEqual(report["time"]["elapsed_ms"], 0)
            self.assertTrue(report["time"]["observed_at_utc"].endswith("Z"))
            self.assertEqual(report["steering"]["status"], "experimental_recommendation_only")
            self.assertEqual(gem_main(["volume", str(current), "--output", str(output)]), 2)
            with self.assertRaises(ValueError):
                accessible_volume([0.5, 0.2], 0.05)


if __name__ == "__main__":
    unittest.main(verbosity=2)
