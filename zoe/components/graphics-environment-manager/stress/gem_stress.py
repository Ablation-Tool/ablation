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
from gem.vdi import (
    opcode_inventory,
    parse_metafile,
    scene_from_metafile,
    scene_to_metafile,
)

if importlib.util.find_spec("numpy"):
    import numpy as np


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


class HourglassCase(unittest.TestCase):
    def test_scene_math_constraints_and_native_vdi_primitives(self):
        from gem.hourglass import _inside_triangle, accessible_q_toy, hourglass_scene

        toy = accessible_q_toy()
        self.assertEqual([row["delta_accessible_q_volume"] for row in toy["arrows"]], [-1, 3])
        self.assertAlmostEqual(toy["arrows"][0]["ei_bits"], 0.4150374992788437)
        scene, report = hourglass_scene()
        self.assertTrue(verify(scene).passed, verify(scene).text())
        self.assertTrue(verify_vdi(scene).passed)
        self.assertEqual(report["past_accessible_q_volume"], 3)
        self.assertEqual(report["future_accessible_volume"], 3)
        self.assertGreater(report["contour_segments"], 0)
        self.assertTrue(any(item["id"].startswith("past-hatch-") for item in scene.objects))
        self.assertTrue(any(item["id"].startswith("future-hatch-") for item in scene.objects))
        for prefix, triangle in (
            ("past", [[250, 190], [950, 190], [600, 480]]),
            ("future", [[250, 770], [950, 770], [600, 480]]),
        ):
            for item in scene.objects:
                if item["id"].startswith(f"{prefix}-hatch-"):
                    self.assertTrue(all(_inside_triangle(point, triangle) for point in item["points"]), item["id"])
        self.assertFalse(report["phi_computed"])
        self.assertFalse(report["consciousness_measured"])
        self.assertFalse(report["executed"])
        inventory = opcode_inventory(scene_to_metafile(scene))
        self.assertGreaterEqual(inventory["v_fillarea"], 2)
        self.assertGreater(inventory["v_pline"], 0)
        self.assertGreater(inventory["v_gtext"], 0)

    def test_hourglass_cli_exports_spatial_ir_svg(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "hourglass.svg"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = gem_main(["hourglass", "--output", str(output)])
            self.assertEqual(result, 0)
            self.assertIn('data-object-id="past-hourglass"', output.read_text(encoding="utf-8"))
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["measurement"]["module"], "hourglass")
            self.assertFalse(report["measurement"]["executed"])

    def test_cairo_resets_path_for_every_scene_object(self):
        from gem.hourglass import hourglass_scene
        from gem.render import draw_cairo

        scene, _ = hourglass_scene()
        context = mock.Mock()
        with mock.patch.dict(sys.modules, {"cairo": mock.Mock()}):
            draw_cairo(context, scene, 1200, 1040)
        self.assertEqual(context.new_path.call_count, len(scene.objects))


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


@unittest.skipUnless(importlib.util.find_spec("numpy"), "prediction tests require NumPy")
class PredictionCase(unittest.TestCase):
    def test_reference_distribution_and_strict_threshold(self):
        from gem.prediction import check_reference_distribution, measure_probabilities

        self.assertTrue(check_reference_distribution())
        report = measure_probabilities([0.05, 0.95], thresholds=(0.05,))
        self.assertEqual(report["threshold_sweep"][0]["accessible_volume"], 1)
        self.assertEqual(report["threshold_sweep"][0]["normalized_accessible_volume"], 0.5)

    def test_measurement_records_evidence_and_replays_artifacts(self):
        import numpy as np
        from gem.prediction import ModelPrediction

        probabilities = np.array([0.40, 0.20, 0.12, 0.06, 0.04] + [0.02] * 9)

        class Predictor:
            model = {"id": "fixture-model", "runtime": "fixture"}
            context_truncated = False

            def predict(self, prompt):
                self.prompt = prompt
                return ModelPrediction(np.array([1, 2, 3]), probabilities, self.model, False)

            def decode(self, token_id):
                return f"token:{token_id}"

        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            predictor = Predictor()
            result = GemLabHost(session).measure_prediction(predictor=predictor)
            self.assertIn(session.root_id, predictor.prompt)
            self.assertEqual(
                [item["accessible_volume"] for item in result.report["threshold_sweep"]],
                [5, 4, 3, 2, 1, 0],
            )
            self.assertEqual(result.evidence["type"], "evidence")
            self.assertEqual(result.evidence["status"], "complete_scoped")
            self.assertEqual(result.evidence["parent_id"], session.root_id)
            self.assertEqual(result.report["measurement_event_id"], result.evidence["id"])
            self.assertEqual(result.report["top_tokens"][0]["token"], "token:0")
            with np.load(result.path / "probabilities.npz") as artifact:
                self.assertTrue(np.array_equal(artifact["probabilities"], probabilities))
            self.assertTrue((result.path / "context.txt").is_file())
            self.assertTrue((result.path / "accessible-volume.json").is_file())

    def test_selection_change_during_measurement_does_not_attach_to_stale_node(self):
        import numpy as np
        from gem.prediction import ModelPrediction

        probabilities = np.array([0.40, 0.20, 0.12, 0.06, 0.04] + [0.02] * 9)

        class Predictor:
            model = {"id": "fixture-model", "runtime": "fixture"}
            context_truncated = False

            def __init__(self, session):
                self.session = session

            def predict(self, _prompt):
                self.session.select("artifact:child")
                return ModelPrediction(np.array([1, 2, 3]), probabilities, self.model, False)

        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            session.emit("artifact:child", session.root_id, "artifact", "child")
            predictor = Predictor(session)
            with self.assertRaisesRegex(ValueError, "selection changed"):
                GemLabHost(session).measure_prediction(predictor=predictor)
            self.assertFalse(any(
                event["id"].startswith("evidence:accessible-volume:")
                for event in session.events()
            ))
            runs = list((session.root / "prediction-runs").iterdir())
            self.assertEqual(len(runs), 1)
            self.assertTrue((runs[0] / "accessible-volume.json").is_file())

    def test_advisory_modes_and_trend_escalation(self):
        from gem.steering import evaluate_advisory

        def report(a002, a005, entropy):
            return {
                "model": {"id": "fixture-model"},
                "gem_context": {"selected_id": "artifact:root", "revision": 1},
                "threshold_sweep": [
                    {"tau": 0.02, "accessible_volume": a002},
                    {"tau": 0.05, "accessible_volume": a005},
                ],
                "entropy_bits": entropy,
                "max_probability": 0.8,
                "top_10_probability_mass": 0.95,
            }

        self.assertEqual(evaluate_advisory(report(1, 1, 4.0))["mode"], "propose_with_verification")
        self.assertEqual(evaluate_advisory(report(2, 2, 5.0))["mode"], "review_with_human")
        self.assertEqual(evaluate_advisory(report(8, 1, 4.0))["mode"], "gather_evidence")
        previous = evaluate_advisory(report(5, 5, 4.0))
        changed = evaluate_advisory(report(1, 1, 4.0), previous)
        self.assertEqual(changed["mode"], "review_with_human")
        self.assertTrue(changed["trend"]["escalated"])
        self.assertEqual(changed["trend"]["accessible_volume_005_delta"], -4)
        self.assertIn("autonomous execution", changed["prohibited_actions"])

    def test_advice_session_records_recommendation_and_history(self):
        import numpy as np
        from gem.prediction import ModelPrediction
        from gem.steering import latest_advisory

        class Predictor:
            model = {"id": "fixture-model", "runtime": "fixture"}
            context_truncated = False

            def predict(self, _prompt):
                return ModelPrediction(
                    np.array([1, 2, 3]), np.array([0.97, 0.01, 0.01, 0.01]),
                    self.model, False,
                )

        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            predictor = Predictor()
            first = GemLabHost(session).advise_next_action(predictor=predictor)
            advisory = first.report["advisory"]
            self.assertEqual(advisory["mode"], "propose_with_verification")
            self.assertEqual(advisory["trend"]["status"], "no previous measurement")
            self.assertEqual(first.evidence["parent_id"], advisory["measurement_event_id"])
            self.assertTrue((first.path / "advisory.json").is_file())
            self.assertEqual(latest_advisory(session)["advisory_event_id"], first.evidence["id"])
            second = GemLabHost(session).advise_next_action(predictor=predictor)
            self.assertEqual(second.report["advisory"]["trend"]["status"], "compared with previous measurement")
            self.assertEqual(second.report["advisory"]["trend"]["accessible_volume_005_delta"], 0)

    def test_adaptive_equation_uses_max_relative_and_absolute_cutoff(self):
        from gem.tournament import adaptive_accessible_volume

        probabilities = [0.60, 0.20, 0.10, 0.05, 0.05]
        self.assertEqual(adaptive_accessible_volume(probabilities, 0.5, 0.02)["accessible_volume"], 1)
        self.assertEqual(adaptive_accessible_volume(probabilities, 0.01, 0.02)["accessible_volume"], 5)
        self.assertEqual(adaptive_accessible_volume(probabilities, 0.5, 0.5)["accessible_volume"], 1)

    def test_tournament_attacks_equations_and_context(self):
        import numpy as np
        from gem.prediction import ModelPrediction
        from gem.steering import latest_advisory

        probabilities = np.array([0.40, 0.20, 0.12, 0.06, 0.04] + [0.02] * 9)

        class Predictor:
            model = {"id": "fixture-model", "runtime": "fixture"}
            context_truncated = False

            def __init__(self):
                self.prompts = []

            def predict(self, prompt):
                self.prompts.append(prompt)
                return ModelPrediction(np.array([1, 2, 3]), probabilities, self.model, False)

        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            predictor = Predictor()
            result = GemLabHost(session).run_equation_tournament(predictor=predictor)
            tournament = result.report["tournament"]
            self.assertEqual(
                [variant["name"] for variant in tournament["variants"]],
                ["baseline", "evidence_removed", "repeated_evidence", "irrelevant_context"],
            )
            self.assertEqual(len(predictor.prompts), 4)
            self.assertIn("removed for equation tournament", predictor.prompts[1])
            self.assertIn("repeated three times for equation tournament", predictor.prompts[2])
            self.assertIn("irrelevant context prepended", predictor.prompts[3])
            self.assertGreater(tournament["advisory_flip_count"], 0)
            self.assertTrue(all(len(variant["adaptive_candidates"]) == 12 for variant in tournament["variants"]))
            self.assertTrue((result.path / "tournament.json").is_file())
            for attack in ("evidence_removed", "repeated_evidence", "irrelevant_context"):
                self.assertTrue((result.path / f"probabilities-{attack}.npz").is_file())
            self.assertEqual(tournament["tournament_event_id"], result.evidence["id"])
            self.assertIsNone(latest_advisory(session))


@unittest.skipUnless(importlib.util.find_spec("numpy"), "measurement tests require NumPy")
class MeasurementKernelCase(unittest.TestCase):
    def test_complement_momentum_and_outcome(self):
        from gem.measurement import measure_distribution

        report = measure_distribution(
            [0.70, 0.20, 0.08, 0.02], thresholds=[0.05],
            previous=[1.0, 0.0, 0.0, 0.0], minimum=4, maximum=6,
            actual_token_id=1,
        )
        entry = report["threshold_sweep"][0]
        self.assertEqual(entry["accessible_volume"], 3)
        self.assertEqual(entry["complement_volume"], 1)
        self.assertEqual(entry["accessible_momentum"], 2)
        self.assertEqual(entry["suggested_action"], "let_breadth_grow")
        self.assertFalse(report["steering"]["executed"])
        self.assertFalse(report["outcome"]["correct"])
        self.assertAlmostEqual(report["outcome"]["actual_probability"], 0.20)
        self.assertGreater(report["outcome"]["log_loss"], 1.0)

    def test_logits_and_validation(self):
        from gem.measurement import measure_distribution, probabilities_from_logits

        self.assertTrue(np.allclose(probabilities_from_logits([0.0, 0.0]), [0.5, 0.5]))
        report = measure_distribution([0.05, 0.95], thresholds=[0.05])
        self.assertEqual(report["threshold_sweep"][0]["accessible_volume"], 1)
        self.assertEqual(report["threshold_sweep"][0]["complement_volume"], 1)
        with self.assertRaises(ValueError):
            measure_distribution([0.5, 0.2])
        with self.assertRaises(ValueError):
            measure_distribution([0.5, 0.5], thresholds=[1.1])
        with self.assertRaises(ValueError):
            measure_distribution([0.5, 0.5], actual_token_id=2)


@unittest.skipUnless(importlib.util.find_spec("numpy"), "NPZ feedback tests require NumPy")
class VolumeBridgeCase(unittest.TestCase):
    def test_custom_keys_feedback_and_no_overwrite(self):
        from gem.volume import VolumeBridge, write_report

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "previous.npz"
            current = root / "current.npz"
            np.savez(previous, earlier=np.asarray([1.0, 0.0, 0.0, 0.0]))
            np.savez(current, input_ids=np.asarray([11, 12]), current=np.asarray([0.70, 0.20, 0.08, 0.02]))
            session = Session(root / "session", "/bin/true")
            bridge = VolumeBridge(session)
            result = bridge.observe(
                current, previous=previous, key="current", previous_key="earlier",
                minimum=4, maximum=6, actual_token_id=0,
            )
            entry = result.report["threshold_sweep"][1]
            self.assertEqual(entry["accessible_volume"], 3)
            self.assertEqual(entry["accessible_momentum"], 2)
            self.assertEqual(entry["suggested_action"], "let_breadth_grow")
            self.assertTrue(result.report["outcome"]["correct"])
            self.assertEqual(result.report["source"]["key"], "current")
            self.assertEqual(result.report["previous_source"]["key"], "earlier")
            self.assertFalse(result.report["executed"])
            self.assertEqual(result.evidence["type"], "evidence")
            with np.load(result.path / "probabilities.npz") as artifact:
                self.assertEqual(len(artifact["input_ids"]), 2)
                self.assertEqual(len(artifact["probabilities"]), 4)
            second = bridge.observe(current, key="current")
            self.assertEqual(second.report["previous_source"]["path"], str(result.path / "probabilities.npz"))
            self.assertEqual(second.report["threshold_sweep"][1]["accessible_momentum"], 0)
            output = root / "report.json"
            write_report(result.report, output)
            original = output.read_text(encoding="utf-8")
            with self.assertRaises(FileExistsError):
                write_report(result.report, output)
            self.assertEqual(output.read_text(encoding="utf-8"), original)

    def test_volume_cli_and_live_outcome(self):
        from gem.prediction import ModelPrediction

        class Predictor:
            model = {"id": "fixture-model"}
            context_truncated = False

            def predict(self, _prompt):
                return ModelPrediction(
                    np.asarray([1, 2]), np.asarray([0.70, 0.20, 0.08, 0.02]), self.model, False,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "previous.npz"
            current = root / "current.npz"
            output = root / "volume.json"
            np.savez(previous, earlier=np.asarray([1.0, 0.0, 0.0, 0.0]))
            np.savez(current, current=np.asarray([0.70, 0.20, 0.08, 0.02]))
            session = Session(root / "session", "/bin/true")
            with contextlib.redirect_stdout(io.StringIO()):
                result = gem_main([
                    "volume", str(current), "--session", str(session.root),
                    "--previous", str(previous), "--key", "current", "--previous-key", "earlier",
                    "--thresholds", "0.05", "--min-volume", "4", "--max-volume", "6",
                    "--actual-token-id", "0", "--output", str(output),
                ])
            self.assertEqual(result, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["threshold_sweep"][0]["accessible_momentum"], 2)
            self.assertTrue(report["outcome"]["correct"])
            original = output.read_text(encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                duplicate = gem_main([
                    "volume", str(current), "--session", str(session.root),
                    "--key", "current", "--output", str(output),
                ])
            self.assertEqual(duplicate, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), original)
            live = GemLabHost(session).measure_prediction(predictor=Predictor(), actual_token_id=0)
            self.assertTrue(live.report["outcome"]["correct"])


@unittest.skipUnless(importlib.util.find_spec("numpy"), "cognitive guard tests require NumPy")
class CognitiveGuardCase(unittest.TestCase):
    def measurement(self, session, path):
        from gem.volume import VolumeBridge

        np.savez(path, input_ids=np.asarray([1, 2]), probabilities=np.asarray([0.70, 0.20, 0.08, 0.02]))
        return VolumeBridge(session).observe(path).report

    def test_review_approval_and_duplicate_action(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            measurement = self.measurement(session, Path(directory) / "forecast.npz")
            host = GemLabHost(session)
            proposal = {"command": "snapshot"}
            review = host.review_proposal(proposal, measurement, "review-action")
            self.assertEqual(review.report["decision"], "review")
            self.assertFalse(review.report["executed"])
            self.assertEqual(len(review.report["events"]), 3)
            approved = host.review_proposal(proposal, measurement, "approved-action", approve=True)
            self.assertTrue(approved.report["succeeded"])
            self.assertTrue(approved.report["executed"])
            self.assertEqual(approved.report["response"]["result_type"], "dict")
            duplicate = host.review_proposal(proposal, measurement, "approved-action", approve=True)
            self.assertEqual(duplicate.report["decision"], "deny")
            self.assertEqual(duplicate.report["reason"], "duplicate_action_id")
            self.assertFalse(duplicate.report["executed"])

    def test_stale_selection_and_context_mismatch_are_denied(self):
        from gem.cognition import CognitiveGuard, bind_forecast

        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            measurement = self.measurement(session, Path(directory) / "forecast.npz")
            host = GemLabHost(session)
            snapshot = host.snapshot()
            proposal = {
                "command": "begin_selected_work",
                "expected_id": session.root_id,
                "expected_revision": snapshot["revision"] + 1,
            }
            stale = host.review_proposal(proposal, measurement, "stale-action", approve=True)
            self.assertEqual(stale.report["decision"], "deny")
            self.assertEqual(stale.report["reason"], "stale_selection_revision")
            self.assertFalse(stale.report["executed"])
            proposal = {"command": "snapshot"}
            forecast = bind_forecast(measurement, host.snapshot(), proposal)
            forecast["context_sha256"] = "0" * 64
            mismatch = CognitiveGuard(GemCommandBroker(host), approve=True).execute(
                "mismatch-action", proposal, forecast,
            )
            self.assertEqual(mismatch.decision, "deny")
            self.assertEqual(mismatch.reason, "forecast_context_mismatch")
            self.assertFalse(mismatch.executed)

    def test_exact_revision_approval_and_broker_failure(self):
        from gem.cognition import CognitiveGuard, bind_forecast

        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            measurement = self.measurement(session, Path(directory) / "forecast.npz")
            host = GemLabHost(session)
            proposal = {
                "command": "begin_selected_work",
                "expected_id": session.root_id,
                "expected_revision": host.snapshot()["revision"],
                "note": "bounded test work",
            }
            result = host.review_proposal(proposal, measurement, "begin-action", approve=True)
            self.assertTrue(result.report["succeeded"])
            self.assertEqual(session.current_state()["last_operation"]["type"], "begin_selected_work")

            snapshot = host.snapshot()
            proposal = {
                "command": "begin_selected_work",
                "expected_id": session.root_id,
                "expected_revision": snapshot["revision"],
                "note": "exercise the broker failure path",
            }
            forecast = bind_forecast(measurement, snapshot, proposal)

            class FailingBroker:
                def execute(self, request):
                    if request["command"] == "snapshot":
                        return snapshot
                    raise RuntimeError("fixture broker failure")

            failed = CognitiveGuard(FailingBroker(), approve=True).execute(
                "failed-action", proposal, forecast,
            )
            self.assertTrue(failed.executed)
            self.assertFalse(failed.succeeded)
            self.assertEqual(failed.reason, "broker_execution_failed")
            self.assertEqual(failed.events[-1]["details"]["status"], "failed")

    def test_guard_cli_review_and_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = Session(root / "session", "/bin/true")
            measurement_path = root / "forecast.npz"
            self.measurement(session, measurement_path)
            proposal = root / "proposal.json"
            proposal.write_text('{"command":"snapshot"}', encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = gem_main([
                    "guard", str(proposal), "--action-id", "cli-review",
                    "--session", str(session.root), "--distribution", str(measurement_path), "--json",
                ])
            self.assertEqual(result, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["decision"], "review")
            self.assertFalse(report["executed"])
            with contextlib.redirect_stdout(io.StringIO()):
                duplicate = gem_main([
                    "guard", str(proposal), "--action-id", "cli-review",
                    "--session", str(session.root), "--distribution", str(measurement_path), "--json",
                ])
            self.assertEqual(duplicate, 2)
            invalid = root / "duplicate-field.json"
            invalid.write_text('{"command":"snapshot","command":"begin_selected_work"}', encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                rejected = gem_main([
                    "guard", str(invalid), "--action-id", "duplicate-field",
                    "--session", str(session.root), "--distribution", str(measurement_path),
                ])
            self.assertEqual(rejected, 2)


@unittest.skipUnless(importlib.util.find_spec("numpy"), "research measurement tests require NumPy")
class ResearchMeasurementCase(unittest.TestCase):
    def test_joint_horizon_counts_and_model_identity(self):
        from gem.volume import VolumeBridge

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current = root / "joint.npz"
            previous = root / "previous.npz"
            np.savez(previous, joint_probabilities=np.asarray([1.0, 0.0, 0.0, 0.0]))
            np.savez(
                current,
                input_ids=np.asarray([1, 2]),
                joint_probabilities=np.asarray([[0.40, 0.30], [0.20, 0.10]]),
                model_id=np.asarray("research-model"),
            )
            session = Session(root / "session", "/bin/true")
            result = VolumeBridge(session).observe(
                current, previous=previous, key="joint_probabilities", horizon=2,
            )
            self.assertEqual(result.report["model"]["id"], "research-model")
            self.assertEqual(result.report["horizon"], 2)
            self.assertEqual(result.report["vocabulary_size"], 2)
            self.assertEqual(result.report["joint_outcome_space"], 4)
            self.assertFalse(result.report["approximate"])
            entry = result.report["threshold_sweep"][1]
            self.assertEqual(entry["accessible_volume"], 4)
            self.assertEqual(entry["complement_volume"], 0)
            self.assertEqual(entry["accessible_momentum"], 3)
            with self.assertRaisesRegex(ValueError, "horizon=1"):
                VolumeBridge(session).observe(
                    current, key="joint_probabilities", horizon=2, actual_token_id=0,
                )
            single = root / "single.npz"
            np.savez(single, probabilities=np.asarray([0.70, 0.20, 0.08, 0.02]))
            bridge = VolumeBridge(session)
            one_step = bridge.observe(single)
            self.assertIsNone(one_step.report["previous_source"])
            repeated_joint = bridge.observe(current, key="joint_probabilities", horizon=2)
            self.assertEqual(repeated_joint.report["previous_source"]["path"], str(result.path / "probabilities.npz"))
            self.assertEqual(repeated_joint.report["threshold_sweep"][1]["accessible_momentum"], 0)

    def test_joint_shape_validation(self):
        from gem.measurement import measure_joint_distribution

        with self.assertRaises(ValueError):
            measure_joint_distribution([0.5, 0.5], 2)
        with self.assertRaises(ValueError):
            measure_joint_distribution([0.5, 0.5], True)
        with self.assertRaises(ValueError):
            measure_joint_distribution([[0.5, 0.5], [0.0, 0.0]], 3)

    def test_calibration_metrics_and_cli(self):
        from gem.evaluation import calibration_metrics

        records = [
            {"max_probability": 0.9, "outcome": {"correct": True, "log_loss": 0.1, "brier_score": 0.1}},
            {"max_probability": 0.8, "outcome": {"correct": True, "log_loss": 0.2, "brier_score": 0.2}},
            {"max_probability": 0.2, "outcome": {"correct": False, "log_loss": 0.3, "brier_score": 0.3}},
            {"max_probability": 0.1, "outcome": {"correct": False, "log_loss": 0.4, "brier_score": 0.4}},
        ]
        report = calibration_metrics(records, bins=2)
        self.assertEqual(report["cases"], 4)
        self.assertEqual(report["auroc_correctness"], 1.0)
        self.assertEqual(report["auprc_correctness"], 1.0)
        self.assertAlmostEqual(report["expected_calibration_error"], 0.15)
        self.assertAlmostEqual(report["log_loss"], 0.25)
        self.assertAlmostEqual(report["brier_score"], 0.25)
        single = calibration_metrics(records[:1])
        self.assertIsNone(single["auroc_correctness"])
        self.assertEqual(single["auprc_correctness"], 1.0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for index, record in enumerate(records):
                path = root / f"measurement-{index}.json"
                path.write_text(json.dumps(record), encoding="utf-8")
                paths.append(path)
            output = root / "calibration.json"
            with contextlib.redirect_stdout(io.StringIO()):
                result = gem_main([
                    "calibrate", *(str(path) for path in paths),
                    "--bins", "2", "--output", str(output),
                ])
            self.assertEqual(result, 0)
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved["auroc_correctness"], 1.0)
            original = output.read_text(encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                duplicate = gem_main([
                    "calibrate", str(paths[0]), "--output", str(output),
                ])
            self.assertEqual(duplicate, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), original)

    def test_linear_and_nonlinear_estimation(self):
        from gem.estimation import ExtendedKalmanFilter, linear_filter

        results = linear_filter(
            [[1.0], [2.0], [3.0]],
            [[1.0, 1.0], [0.0, 1.0]], [[0.001, 0.0], [0.0, 0.001]],
            [[1.0, 0.0]], [[0.01]], [0.0, 1.0], np.eye(2),
        )
        self.assertEqual(len(results), 3)
        self.assertAlmostEqual(results[-1]["state"][0], 3.0, places=2)
        self.assertAlmostEqual(results[-1]["state"][1], 1.0, places=2)
        self.assertTrue(np.all(np.linalg.eigvalsh(results[-1]["covariance"]) > 0))

        estimator = ExtendedKalmanFilter([2.0], [[0.01]], measurement_model=lambda state: (
            np.asarray([state[0] ** 2]), np.asarray([[2 * state[0]]]),
        ))
        estimator.predict([[1.0]], [[0.001]])
        update = estimator.update([4.0], observation_covariance=[[0.01]])
        self.assertAlmostEqual(update["state"][0], 2.0, places=1)
        self.assertGreaterEqual(update["innovation"][0], 0.0)
        with self.assertRaises(ValueError):
            ExtendedKalmanFilter([1.0], [[1.0, 0.0]])

    def test_estimate_cli_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root / "model.json"
            output = root / "estimate.json"
            model.write_text(json.dumps({
                "observations": [[1.0], [2.0], [3.0]],
                "process_matrix": [[1.0, 1.0], [0.0, 1.0]],
                "process_covariance": [[0.001, 0.0], [0.0, 0.001]],
                "observation_matrix": [[1.0, 0.0]],
                "observation_covariance": [[0.01]],
                "initial_state": [0.0, 1.0],
                "initial_covariance": [[1.0, 0.0], [0.0, 1.0]],
            }), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                result = gem_main(["estimate", str(model), "--output", str(output)])
            self.assertEqual(result, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["observation_count"], 3)
            self.assertAlmostEqual(report["final_state"][0], 3.0, places=2)
            original = output.read_text(encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                duplicate = gem_main(["estimate", str(model), "--output", str(output)])
            self.assertEqual(duplicate, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), original)


@unittest.skipUnless(importlib.util.find_spec("numpy"), "generative tests require NumPy")
class GenerativeCase(unittest.TestCase):
    def measurement(self, session, path):
        from gem.volume import VolumeBridge

        np.savez(path, input_ids=np.asarray([1, 2]), probabilities=np.asarray([0.70, 0.20, 0.08, 0.02]))
        return VolumeBridge(session).observe(path).report

    def test_baseline_generation_is_review_only_and_repeatable(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            measurement = self.measurement(session, Path(directory) / "forecast.npz")
            host = GemLabHost(session)
            result = host.generate_proposals(measurement, count=4)
            self.assertEqual(result.report["reviewable"], 4)
            self.assertEqual(result.report["denied"], 0)
            self.assertFalse(result.report["executed"])
            self.assertEqual(result.evidence["type"], "hypothesis")
            self.assertTrue(all(candidate["score"] is None for candidate in result.report["candidates"]))
            self.assertTrue(all(not candidate["guard_report"]["executed"] for candidate in result.report["candidates"]))
            self.assertTrue((result.path / "generation.json").is_file())
            self.assertIsNone(session.current_state().get("last_operation"))
            first_action = result.report["candidates"][0]["action_id"]
            repeated = host.generate_proposals(measurement, count=1)
            self.assertEqual(repeated.report["reviewable"], 1)
            self.assertNotEqual(repeated.report["candidates"][0]["action_id"], first_action)

    def test_external_generator_deduplicates_and_denies_stale_work(self):
        from gem.generation import AgentProposalGenerator

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "generator.py"
            script.write_text(textwrap.dedent('''
                import json
                print(json.dumps({"hypotheses": [
                    {"statement": "Read state", "proposal": {"command": "snapshot"}, "rationale": "baseline"},
                    {"statement": "Read state again", "proposal": {"command": "snapshot"}, "rationale": "duplicate"},
                    {"statement": "Stale work", "proposal": {"command": "begin_selected_work", "expected_id": "wrong", "expected_revision": 999}, "rationale": "must deny"}
                ]}))
            '''), encoding="utf-8")
            session = Session(root / "session", "/bin/true")
            measurement = self.measurement(session, root / "forecast.npz")
            generator = AgentProposalGenerator([sys.executable, str(script)])
            result = GemLabHost(session).generate_proposals(measurement, count=3, generator=generator)
            self.assertEqual(result.report["generator"]["mode"], "external-agent")
            self.assertEqual(result.report["reviewable"], 1)
            self.assertEqual(result.report["denied"], 1)
            self.assertEqual(result.report["duplicates"], 1)
            self.assertTrue(all(not candidate.get("guard_report", {}).get("executed", False) for candidate in result.report["candidates"] if candidate["guard_report"] is not None))
            prompt = (result.path / "generation-prompt.txt").read_text(encoding="utf-8")
            self.assertIn("untrusted data", prompt)
            self.assertIn("RIGHT-SIDE GENERATION INSTRUCTIONS", prompt)
            from hashlib import sha256
            self.assertEqual(result.report["generator"]["prompt_sha256"], sha256(prompt.encode("utf-8")).hexdigest())

    def test_external_generator_rejects_invalid_output_and_self_scores(self):
        from gem.generation import AgentProposalGenerator

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = Session(root / "session", "/bin/true")
            measurement = self.measurement(session, root / "forecast.npz")
            for content in (
                "not json",
                '{"hypotheses":[{"statement":"self scored","proposal":{"command":"snapshot"},"score":1.0}]}',
            ):
                script = root / "generator.py"
                script.write_text(f"print({content!r})\n", encoding="utf-8")
                generator = AgentProposalGenerator([sys.executable, str(script)])
                with self.subTest(content=content), self.assertRaises(ValueError):
                    GemLabHost(session).generate_proposals(measurement, count=1, generator=generator)

    def test_generate_cli_uses_baseline_without_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            session = Session(root / "session", "/bin/true")
            measurement_path = root / "forecast.npz"
            self.measurement(session, measurement_path)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = gem_main([
                    "generate", "--session", str(session.root),
                    "--distribution", str(measurement_path), "--count", "2", "--json",
                ])
            self.assertEqual(result, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["generator"]["mode"], "deterministic-baseline")
            self.assertEqual(report["reviewable"], 2)
            self.assertFalse(report["executed"])


@unittest.skipUnless(importlib.util.find_spec("numpy"), "landmark tests require NumPy")
class LandmarkCase(unittest.TestCase):
    def setUp(self):
        self.source = [[83, 467], [270, 513]]
        self.target = [[328, 389], [485, 560]]

    def test_two_pair_similarity_procrustes(self):
        from gem.landmarks import similarity_procrustes

        result = similarity_procrustes(self.source, self.target)
        self.assertAlmostEqual(result.scale, 1.2054659568464863)
        self.assertAlmostEqual(result.determinant, 1.0)
        self.assertAlmostEqual(result.angle_degrees, 33.62430635369026)
        self.assertTrue(np.allclose(result.predicted, self.target))
        self.assertLess(result.rms, 1e-10)
        self.assertTrue(np.allclose(result.translation, [556.4187677, -135.1671835]))

    def test_two_pair_reflection_allowed_procrustes(self):
        from gem.landmarks import similarity_procrustes

        result = similarity_procrustes(self.source, self.target, allow_reflection=True)
        self.assertAlmostEqual(result.determinant, -1.0)
        self.assertTrue(np.allclose(result.predicted, self.target))
        self.assertLess(result.rms, 1e-10)
        self.assertTrue(np.allclose(result.translation, [-213.72447081, 571.92339221]))

    def test_two_pair_affine_is_explicitly_underdetermined(self):
        from gem.landmarks import affine_design, affine_procrustes

        design, _ = affine_design(self.source, self.target)
        self.assertEqual(np.linalg.matrix_rank(design), 4)
        with self.assertRaisesRegex(ValueError, "three non-collinear"):
            affine_procrustes(self.source, self.target)

    def test_three_pair_affine_recovers_transform(self):
        from gem.landmarks import affine_procrustes

        source = np.array([[0.0, 0.0], [1.0, 0.0], [0.0, 1.0]])
        matrix = np.array([[2.0, 0.5], [-1.0, 1.5]])
        translation = np.array([3.0, -2.0])
        target = (matrix @ source.T).T + translation
        result = affine_procrustes(source, target)
        self.assertTrue(result.unique)
        self.assertEqual(result.rank, 6)
        self.assertTrue(np.allclose(result.matrix, matrix))
        self.assertTrue(np.allclose(result.translation, translation))
        self.assertLess(result.rms, 1e-12)

    def test_landmark_host_exports_replayable_procrustes_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            result = GemLabHost(session).align_landmarks(self.source, self.target)
            self.assertTrue(result.export.passed)
            self.assertTrue(result.export.replay.matches_recorded)
            self.assertEqual(result.report["affine_design_rank"], 4)
            self.assertFalse(result.report["affine_unique"])
            self.assertEqual(result.report["landmark_evidence_event_id"], result.evidence["id"])
            self.assertEqual(result.evidence["status"], "complete_scoped")
            self.assertEqual(result.evidence["parent_id"], result.export.evidence["id"])
            self.assertTrue((result.path / "landmark-report.json").is_file())
            self.assertTrue(replay(result.path).matches_recorded)

    def test_landmark_cli_exports_json_evidence(self):
        example = Path(__file__).resolve().parents[1] / "examples" / "landmark-alignment" / "landmarks.json"
        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = gem_main([
                    "landmarks", str(example), "--session", str(session.root), "--json",
                ])
            self.assertEqual(result, 0)
            report = json.loads(output.getvalue())
            self.assertTrue(report["geometry"]["source_vdi_passed"])
            self.assertTrue(report["geometry"]["replay_matches_recorded"])
            self.assertEqual(report["affine_design_rank"], 4)
            self.assertEqual(len(report["source"]), 2)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
