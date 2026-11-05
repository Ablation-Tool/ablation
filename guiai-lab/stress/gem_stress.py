import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from guiai.gem.agent import AgentError, extract_scene, invoke_agent, solve
from guiai.gem.atlas import (
    ATLAS_MODULES, default_document, graph_invariants, procrustes,
)
from guiai.gem.cli import main as gem_main
from guiai.gem.geometry import verify
from guiai.gem.model import MAX_POINTS, Scene, demo_scene, scene_from_events
from guiai.gem.onset import experiment_summary, retrograde_intervals, run_synthetic_experiment, temper
from guiai.gem.render import scene_to_svg, write_png
from guiai.gem.runner import export_run, replay, verify_vdi
from guiai.gem.volume import VolumeBridge, accessible_momentum, accessible_volume, steering_action
from guiai.gem.vdi import (
    opcode_inventory,
    parse_metafile,
    scene_from_metafile,
    scene_to_metafile,
)


HAS_ONSET = importlib.util.find_spec("numpy") is not None and importlib.util.find_spec("sklearn") is not None
HAS_GTK = False
if os.environ.get("DISPLAY"):
    try:
        import cairo
        import gi
        gi.require_version("Gdk", "3.0")
        gi.require_version("Gtk", "3.0")
        gi.require_foreign("cairo")
        from gi.repository import GLib, Gtk
        from guiai.gem.atlas_view import AtlasWindow
        from guiai.gem.view import GemView
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
        with mock.patch("guiai.gem.runner.scene_from_metafile", return_value=Scene.from_dict(incomplete)):
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


class AgentCase(unittest.TestCase):
    def fake_agent(self, directory):
        path = Path(directory) / "fake_agent.py"
        path.write_text(textwrap.dedent("""
            import json
            import sys
            from guiai.gem.model import demo_scene
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

    def test_timeout_is_bounded(self):
        started = time.monotonic()
        with self.assertRaisesRegex(AgentError, "timed out"):
            invoke_agent([sys.executable, "-c", "import time; time.sleep(30)"], "prompt", timeout=0.05)
        self.assertLess(time.monotonic() - started, 3)


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


class AtlasCase(unittest.TestCase):
    def test_exact_similarity_rigid_residual_and_affine(self):
        result = procrustes([[101, 114], [285, 159]], [[345, 35], [500, 205]])
        self.assertAlmostEqual(result["scale"], 1.2145018039)
        self.assertAlmostEqual(result["rotation_degrees"], 33.8997475549)
        self.assertLess(result["squared_error"], 1e-12)
        rigid = procrustes([[101, 114], [285, 159]], [[345, 35], [500, 205]], "rigid")
        self.assertAlmostEqual(rigid["squared_error"], 825.4607739262)
        affine = procrustes([[0, 0], [1, 0], [0, 1]], [[2, 3], [4, 3], [2, 5]], "affine")
        self.assertLess(affine["squared_error"], 1e-12)
        with self.assertRaisesRegex(ValueError, "at least three"):
            procrustes([[0, 0], [1, 0]], [[2, 3], [4, 3]], "affine")

    def test_atlas_scene_vdi_roundtrips_and_cli(self):
        for name in ATLAS_MODULES:
            if name == "onset" and not HAS_ONSET:
                continue
            with self.subTest(module=name):
                scene, _ = default_document(name)
                self.assertTrue(verify(scene).passed, verify(scene).text())
                self.assertTrue(verify_vdi(scene).passed)
        self.assertEqual(graph_invariants()["cycle_rank"], 16 - 13 + 3)
        self.assertEqual(graph_invariants(True)["cycle_rank"], 28 - 19 + 1)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "atlas.svg"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["atlas", "--module", "procrustes", "--output", str(output)]), 0)
            self.assertIn('data-object-id="source-segment"', output.read_text(encoding="utf-8"))


@unittest.skipUnless(HAS_ONSET, "onset tests require NumPy and scikit-learn")
class OnsetCase(unittest.TestCase):
    def test_seeded_experiment_metrics_and_probability_invariants(self):
        import numpy as np
        experiment = run_synthetic_experiment()
        self.assertEqual(experiment.forward["observations"], 1920)
        self.assertEqual(experiment.retrograde["observations"], 1920)
        self.assertAlmostEqual(experiment.forward["top1"], .84375)
        self.assertAlmostEqual(experiment.retrograde["top1"], .5895833333333333)
        self.assertAlmostEqual(experiment.forward["log_loss"], .33885633598124937)
        self.assertAlmostEqual(experiment.retrograde["log_loss"], 2.898662373434196)
        self.assertAlmostEqual(experiment.deterministic_forward, .3701923076923077)
        self.assertAlmostEqual(experiment.deterministic_retrograde, .3283653846153846)
        self.assertTrue(np.all(np.diff(experiment.forward_curve) <= 1e-12))
        self.assertTrue(np.all(np.diff(experiment.retrograde_curve) <= 1e-12))
        transformed = temper(experiment.forward_probabilities, 1.7)
        self.assertTrue(np.allclose(transformed.sum(axis=1), 1))
        self.assertTrue(np.array_equal(retrograde_intervals([1, 2, 4]), np.array([4, 2, 1])))
        summary = experiment_summary(experiment)
        self.assertIsNone(summary["deterministic_linear_extrapolation"]["accessible_volume"])
        self.assertIn("measured negative baseline", summary["hop_negative_baseline"]["scope"])


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

    def test_native_atlas_drag_modules_bridge_and_export(self):
        window = AtlasWindow(experiment_factory=lambda: run_synthetic_experiment(train_count=2, test_count=1))
        context = GLib.MainContext.default()
        window.show_all()
        deadline = time.monotonic() + .2
        while time.monotonic() < deadline:
            context.iteration(False)
            time.sleep(.005)
        try:
            self.assertLess(window.report["squared_error"], 1e-12)
            point = window.source[0]
            layout = window.canvas.update_layout()
            x = layout.offset_x + point[0] * layout.scale
            y = layout.offset_y + point[1] * layout.scale
            self.assertTrue(window.canvas.on_button(window.canvas, mock.Mock(button=1, x=x, y=y)))
            window.canvas.on_motion(window.canvas, mock.Mock(x=x + 20, y=y + 10))
            self.assertIsNotNone(window.canvas.dragging)
            window.canvas.on_release(window.canvas, mock.Mock())
            self.assertNotEqual(window.source[0], point)
            self.assertGreater(window.report["squared_error"], 0)
            window.reset_landmarks()
            window.add_landmark_pair()
            window.controls["mode"].set_active_id("affine")
            self.assertNotIn("error", window.report)
            self.assertEqual(window.report["landmark_count"], 3)
            for name in ATLAS_MODULES:
                if name == "onset" and not HAS_ONSET:
                    continue
                window.module_selector.set_active_id(name)
                deadline = time.monotonic() + .03
                while time.monotonic() < deadline:
                    context.iteration(False)
                    time.sleep(.005)
                self.assertEqual(window.module, name)
                self.assertIsNotNone(window.scene)
            window.module_selector.set_active_id("volume")
            window.observe_volume()
            self.assertIsNotNone(window.volume_previous)
            with tempfile.TemporaryDirectory() as directory:
                svg = window.export_current(Path(directory) / "atlas.svg")
                png = window.export_current(Path(directory) / "atlas.png")
                self.assertTrue(svg.is_file())
                surface = cairo.ImageSurface.create_from_png(str(png))
                self.assertGreater(len(set(surface.get_data())), 20)
        finally:
            window.destroy()
            deadline = time.monotonic() + .05
            while time.monotonic() < deadline:
                context.iteration(False)
                time.sleep(.005)


if __name__ == "__main__":
    unittest.main(verbosity=2)
