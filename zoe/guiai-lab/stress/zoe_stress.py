from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from guiai.gem.atlas import default_document
from guiai.gem.brain import BrainKernel, toy_horizon
from guiai.gem.cli import main as gem_main
from guiai.gem.field import FieldNotebook, bayes_binary, volume_joint
from guiai.gem.geometry import verify
from guiai.gem.qualia import (
    LENSES, accessible_q_toy, accessible_set, accessible_sweep, causal_repertoire,
    qualia_scene, reconstruct_filtration, relative_entropy, silent_and_example,
)
from guiai.gem.research import ResearchPack
from guiai.gem.runner import verify_vdi

RESEARCH_ROOT = Path(os.environ.get("MASTER_GEM_RESEARCH_ROOT", "/home/cowboy/_projects/next-token-predictability"))

try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_foreign("cairo")
    from gi.repository import Gtk
    from guiai.gem.atlas_view import AtlasWindow
    HAS_GTK = bool(os.environ.get("DISPLAY"))
except (ImportError, ValueError):
    HAS_GTK = False


class ZoeBrainCase(unittest.TestCase):
    def test_helen_observation_sequence_and_export_state(self):
        kernel = BrainKernel()
        first = kernel.observe_onset(index=0)
        self.assertEqual(first["observation_count"], 1)
        self.assertEqual(first["current"]["source"], "helen.seed7")
        self.assertEqual(first["current"]["index"], 0)
        self.assertIsNotNone(first["current"]["top1"])
        self.assertIsNone(first["current"]["momentum"])
        self.assertEqual(first["current"]["accessible_volume"] + first["current"]["complement_volume"], 8)
        second = kernel.observe_onset()
        self.assertEqual(second["current"]["index"], 1)
        self.assertIsNotNone(second["current"]["momentum"])
        self.assertEqual(second["onset_positions"]["forward"], 2)
        self.assertEqual(len(second["history"]), 2)
        self.assertFalse(second["executed"])
        exported = kernel.mark_exported()
        self.assertEqual(exported["evidence_exports"], 1)
        self.assertFalse(exported["executed"])

    def test_exact_multi_horizon_counts(self):
        for horizon, tau, accessible, complement in ((1, .5, 1, 1), (2, .2, 2, 2), (3, .1, 5, 3)):
            with self.subTest(horizon=horizon, tau=tau):
                result = toy_horizon(horizon, tau)
                self.assertEqual(result["accessible_volume"], accessible)
                self.assertEqual(result["complement_volume"], complement)
                self.assertEqual(result["universe_size"], 2**horizon)
                self.assertAlmostEqual(sum(item["probability"] for item in result["continuations"]), 1.0)
                self.assertTrue(result["exact"])
        with self.assertRaises(ValueError):
            toy_horizon(0)


class ZoeFieldNotebookCase(unittest.TestCase):
    def test_binary_updates_preserve_belief_diffs_and_dependence(self):
        self.assertAlmostEqual(bayes_binary(.5, .8, .2)["posterior"], .8)
        notebook = FieldNotebook()
        question = notebook.add_question("Is the resource tree the main menu?")
        claim = notebook.add_claim(question["id"], "DEMOMENU is tree zero.", prior=.5, falsifier="A contradictory primary definition.")
        notebook.add_evidence(claim["id"], "The header defines tree zero.", .8, .2, family="header")
        self.assertAlmostEqual(notebook.claim(claim["id"])["posterior"], .8)
        notebook.add_evidence(claim["id"], "Appearance alone is inconclusive.", .1, .4, family="appearance", direction="challenges")
        self.assertAlmostEqual(notebook.claim(claim["id"])["posterior"], .5)
        self.assertEqual(len(notebook.claim(claim["id"])["updates"]), 2)
        with self.assertRaisesRegex(ValueError, "evidence family"):
            notebook.add_evidence(claim["id"], "A derivative copy of the header.", .9, .1, family="header")
        notebook.add_evidence(claim["id"], "An explicitly dependent header copy.", 1, 1, family="header", dependence_acknowledged=True)
        self.assertAlmostEqual(notebook.claim(claim["id"])["posterior"], .5)

    def test_deterministic_and_stochastic_chambers_do_not_update_belief(self):
        notebook = FieldNotebook()
        question = notebook.add_question("How broad is the forecast?")
        claim = notebook.add_claim(question["id"], "The forecast is broad.", prior=.4)
        deterministic = notebook.add_chamber("Strict", "deterministic", "volume/strict@v1", disposition="active")
        measurement = notebook.run_chamber(deterministic["id"], probabilities=[.70, .20, .08, .02], tau=.05)
        self.assertEqual(measurement["result"]["accessible_volume"], 3)
        self.assertEqual(measurement["result"]["normalized_accessible_volume"], .75)
        self.assertFalse(measurement["belief_updated"])
        self.assertEqual(notebook.claim(claim["id"])["posterior"], .4)
        stochastic = notebook.add_chamber("Sample", "stochastic", "sample/categorical@v1")
        first = notebook.run_chamber(stochastic["id"], probabilities=[.70, .20, .08, .02], seed=7)
        second = notebook.run_chamber(stochastic["id"], probabilities=[.70, .20, .08, .02], seed=7)
        self.assertEqual(first["result"]["selected_index"], second["result"]["selected_index"])
        self.assertNotEqual(first["id"], second["id"])
        quarantined = notebook.add_chamber("Quarantined", "deterministic", "volume/strict@v1", disposition="quarantined")
        with self.assertRaisesRegex(ValueError, "quarantined"):
            notebook.run_chamber(quarantined["id"], probabilities=[1], tau=0)

    def test_exact_and_restricted_joint_counts(self):
        probabilities = [.42, .18, .28, .12]
        exact = volume_joint(probabilities, 2, 2, .2)
        self.assertEqual(exact["accessible_volume"], 2)
        self.assertEqual(exact["complement_volume"], 2)
        self.assertTrue(exact["exact"])
        restricted = volume_joint(probabilities[:3], 2, 2, .2, complete=False)
        self.assertEqual(restricted["accessible_volume"], 2)
        self.assertIsNone(restricted["complement_volume"])
        self.assertTrue(restricted["lower_bound_only"])
        self.assertAlmostEqual(restricted["excluded_probability_mass"], .12)

    def test_memory_roundtrip_large_input_digest_and_tamper_detection(self):
        notebook = FieldNotebook.demo()
        chamber = notebook.chambers[0]
        probabilities = [.7] + [.3 / 99] * 99
        measurement = notebook.run_chamber(chamber["id"], probabilities=probabilities, tau=.05)
        self.assertEqual(measurement["input_storage"], "probability-digest-only; full vector not embedded")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory.json"
            notebook.save(path)
            restored = FieldNotebook.load(path)
            self.assertEqual(restored.document(), notebook.document())
            document = notebook.document()
            document["events"][1]["payload"]["claim"]["statement"] = "tampered"
            tampered = Path(directory) / "tampered.json"
            tampered.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash-chain mismatch"):
                FieldNotebook.load(tampered)
            with self.assertRaises(FileExistsError):
                notebook.save(path)

    def test_brain_observation_is_memory_not_automatic_belief(self):
        notebook = FieldNotebook()
        question = notebook.add_question("What does the forecast mean?")
        claim = notebook.add_claim(question["id"], "A narrow forecast is correct.", prior=.5)
        kernel = BrainKernel()
        current = kernel.observe_onset(index=0)["current"]
        observation = notebook.record_brain_observation(current, question["id"])
        self.assertFalse(observation["belief_updated"])
        self.assertEqual(notebook.claim(claim["id"])["posterior"], .5)
        self.assertEqual(notebook.observations[0]["source"]["source"], "helen.seed7")


@unittest.skipUnless(RESEARCH_ROOT.is_dir(), "research pack checkout is unavailable")
class ZoeResearchCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pack = ResearchPack.load(RESEARCH_ROOT)

    def test_all_conformance_vectors(self):
        checks = self.pack.verify_conformance()
        self.assertEqual(len(checks), 17)
        self.assertTrue(all(check["passed"] for check in checks), checks)

    def test_real_groove_observation(self):
        probabilities, target = self.pack.observe("groove:forward", 0)
        self.assertEqual(len(probabilities), 192)
        self.assertAlmostEqual(sum(probabilities), 1.0, places=6)
        kernel = BrainKernel()
        state = kernel.observe(probabilities, target=target, source="groove:forward", index=0)
        self.assertEqual(state["current"]["source"], "groove:forward")
        self.assertEqual(state["current"]["target"], target)
        self.assertEqual(state["current"]["accessible_volume"] + state["current"]["complement_volume"], 192)

    def test_nightingale_is_explicitly_aggregate_only(self):
        with self.assertRaisesRegex(ValueError, "aggregate-only"):
            self.pack.observe("nightingale:jazz:forward", 0)


class ZoeQualiaCase(unittest.TestCase):
    def test_accessible_q_volume_toy_and_cli_evidence(self):
        toy = accessible_q_toy()
        low, high = toy["arrows"]
        self.assertEqual(low["delta_accessible_q_volume"], -1)
        self.assertEqual(low["exited"], ["11"])
        self.assertEqual(high["delta_accessible_q_volume"], 3)
        self.assertEqual(high["entered"], ["00", "01", "10"])
        self.assertAlmostEqual(low["ei_bits"], 0.4150374992788437)
        self.assertAlmostEqual(high["ei_bits"], low["ei_bits"])
        self.assertEqual(accessible_set(toy["before"], 0.25), [])
        self.assertEqual(accessible_set(toy["after"], 1 / 3), [])
        self.assertEqual(reconstruct_filtration(toy["after_sweep"]), {"00": 0.3, "01": 0.3, "10": 0.3})
        fine_thresholds = [index / 10000 for index in range(3334)] + [1 / 3]
        recovered = reconstruct_filtration(accessible_sweep(toy["after"], fine_thresholds))
        for state in ("00", "01", "10"):
            self.assertLess(abs(recovered[state] - 1 / 3), 0.0001)
        self.assertNotIn("11", recovered)
        self.assertEqual(toy["two_way"]["past"]["accessible_q_volume"], 3)
        self.assertEqual(toy["two_way"]["future"]["accessible_volume"], 3)
        with self.assertRaisesRegex(ValueError, "zero probability"):
            causal_repertoire({"00": 0.0, "11": 0.0})
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "accessible-q-volume.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["qualia", "--output", str(output)]), 0)
            report = json.loads(output.read_text())
            self.assertEqual(report["checks"]["arithmetic"], "passed")
            self.assertTrue(report["finite_sweep_is_approximate"])
            self.assertFalse(report["phi_computed"])
            custom = Path(directory) / "custom-thresholds.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["qualia", "--tau", "0.25", "--tau", "0.30", "--output", str(custom)]), 0)
            custom_report = json.loads(custom.read_text())
            self.assertEqual([row["delta_accessible_q_volume"] for row in custom_report["toy"]["arrows"]], [3, 3])
            self.assertEqual(gem_main(["qualia", "--output", str(output)]), 2)


class ZoeSceneCase(unittest.TestCase):
    def test_brain_horizon_and_qualia_scenes_and_cli_exports(self):
        for module in ("brain", "horizon", "qualia"):
            with self.subTest(module=module):
                scene, _ = default_document(module)
                self.assertTrue(verify(scene).passed, verify(scene).text())
                self.assertTrue(verify_vdi(scene).passed)
        example = silent_and_example()
        self.assertAlmostEqual(example["whole_vs_product_bits"], 0.2516291673878228)
        self.assertAlmostEqual(relative_entropy([0.25] * 4, [0.25] * 4), 0.0)
        with self.assertRaisesRegex(ValueError, "zero probability"):
            relative_entropy([1.0, 0.0], [0.0, 1.0])
        for lens in LENSES:
            scene, report = qualia_scene(lens)
            self.assertEqual(report["lens"], lens)
            positions = [tuple(item["center"]) for item in scene.objects if item["id"].startswith("lattice-node")]
            self.assertEqual(len(set(positions)), 16)
            self.assertEqual((report["repertoires"], report["subset_links"], report["ordered_q_edges"]), (16, 32, 24))
            self.assertFalse(report["phi_computed"])
            self.assertFalse(report["consciousness_measured"])
            self.assertTrue(verify(scene).passed, verify(scene).text())
        with self.assertRaisesRegex(ValueError, "qualia lens"):
            qualia_scene("consciousness-detector")
        with tempfile.TemporaryDirectory() as directory:
            for module in ("brain", "horizon", "qualia"):
                output = Path(directory) / f"{module}.svg"
                with contextlib.redirect_stdout(io.StringIO()):
                    result = gem_main(["zoe", "--module", module, "--output", str(output)])
                self.assertEqual(result, 0)
                self.assertIn("<svg", output.read_text())

    def test_field_scene_memory_and_render_cli(self):
        scene, report = default_document("field")
        self.assertTrue(verify(scene).passed, verify(scene).text())
        self.assertTrue(verify_vdi(scene).passed)
        self.assertIn("DEMOMENU", report["summary"])
        with tempfile.TemporaryDirectory() as directory:
            memory = Path(directory) / "memory.json"
            rendered = Path(directory) / "memory.svg"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["notebook", "--output", str(memory)]), 0)
                self.assertEqual(gem_main(["notebook", str(memory), "--output", str(rendered)]), 0)
            self.assertEqual(FieldNotebook.load(memory).document(), FieldNotebook.demo().document())
            self.assertIn("BAYESIAN FIELD NOTEBOOK", rendered.read_text())

    @unittest.skipUnless(RESEARCH_ROOT.is_dir(), "research pack checkout is unavailable")
    def test_research_scene_and_cli_export(self):
        scene, _ = default_document("research", research_root=RESEARCH_ROOT)
        self.assertTrue(verify(scene).passed, verify(scene).text())
        self.assertTrue(verify_vdi(scene).passed)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "research.svg"
            with contextlib.redirect_stdout(io.StringIO()):
                result = gem_main(["zoe", "--module", "research", "--research-root", str(RESEARCH_ROOT), "--output", str(output)])
            self.assertEqual(result, 0)
            self.assertIn("Groove · Forward", output.read_text())


@unittest.skipUnless(HAS_GTK, "native Zoe tests require GTK, Cairo, and an X11 DISPLAY")
class ZoeNativeCase(unittest.TestCase):
    def test_observe_navigate_horizon_and_export(self):
        window = AtlasWindow("brain")
        try:
            window.observe_brain()
            self.assertEqual(window.brain.observation_count, 1)
            self.assertEqual(len(window.field.observations), 1)
            window.observe_brain_next()
            self.assertEqual(window.brain.observation_count, 2)
            self.assertEqual(len(window.field.observations), 2)
            window.open_recommended()
            self.assertIn(window.module, {"volume", "research", "horizon"})
            window.module_selector.set_active_id("horizon")
            self.assertEqual(window.report["accessible_volume"], 5)
            window.module_selector.set_active_id("qualia")
            self.assertEqual(window.report["lens"], "overview")
            window.controls["qualia_lens"].set_active_id("tomography")
            self.assertEqual(window.report["lens"], "tomography")
            self.assertEqual([row["delta_accessible_q_volume"] for row in window.report["accessible_q_volume"]["arrows"]], [-1, 3])
            self.assertFalse(window.report["consciousness_measured"])
            self.assertEqual(len(window.field.observations), 2)
            with tempfile.TemporaryDirectory() as directory:
                output = window.export_current(Path(directory) / "zoe.svg")
                self.assertTrue(output.is_file())
                window.module_selector.set_active_id("brain")
                window.export_current(Path(directory) / "brain.svg")
                self.assertEqual(window.brain.evidence_exports, 1)
        finally:
            window.destroy()

    def test_native_field_notebook_workflow(self):
        window = AtlasWindow("field")
        try:
            window.load_field_demo()
            self.assertEqual(len(window.field.questions), 1)
            window.controls["new_question"].set_text("Can a deterministic measurement update belief silently?")
            window.add_field_question()
            self.assertEqual(len(window.field.questions), 2)
            window.controls["new_claim"].set_text("A measurement is automatically true evidence.")
            window.controls["falsifier"].set_text("Inspect the measurement event boundary.")
            window.add_field_claim()
            claim = window.field.claims[-1]
            window.controls["evidence"].set_text("The chamber records belief_updated=False.")
            window.controls["source"].set_text("native conformance observation")
            window.add_field_evidence()
            self.assertEqual(len(window.field.claim(claim["id"])["updates"]), 1)
            window.measure_field()
            window.sample_field()
            self.assertGreaterEqual(len(window.field.measurements), 3)
            self.assertTrue(all(not measurement["belief_updated"] for measurement in window.field.measurements))
            with tempfile.TemporaryDirectory() as directory:
                output = window.export_current(Path(directory) / "memory.json")
                self.assertEqual(FieldNotebook.load(output).document(), window.field.document())
        finally:
            window.destroy()

    @unittest.skipUnless(RESEARCH_ROOT.is_dir(), "research pack checkout is unavailable")
    def test_native_real_groove_observation(self):
        window = AtlasWindow("research", research_root=RESEARCH_ROOT)
        try:
            window.observe_research()
            self.assertEqual(window.module, "brain")
            self.assertEqual(window.brain.current["source"], "groove:forward")
            self.assertEqual(window.brain.current["index"], 0)
            self.assertEqual(window.brain.current["accessible_volume"] + window.brain.current["complement_volume"], 192)
        finally:
            window.destroy()

    def test_guiai_host_launches_zoe(self):
        from guiai.events import Session
        from guiai.gtk_app import GuiAIGtkApplication, InvestigationWorkspace, configure_native_fonts
        from guiai.preferences import WorkbenchPreferences

        with tempfile.TemporaryDirectory() as directory:
            session = Session(Path(directory) / "session", "/bin/true")
            app = GuiAIGtkApplication(session, None, session.root, "re.guiai.zoe.test.window", export_actions=False)
            host = None
            atlas = None
            try:
                preferences = WorkbenchPreferences(session.root, configure_native_fonts().to_string())
                workspace = InvestigationWorkspace(session, None, session.root, preferences)
                host = Gtk.Window()
                host.add(workspace)
                host.show_all()
                atlas = workspace.open_geometry_atlas()
                self.assertEqual(atlas.module, "brain")
                self.assertIn("Zoe", atlas.get_title())
            finally:
                if atlas is not None:
                    atlas.destroy()
                if host is not None:
                    host.destroy()
                app.quit()


from guiai.gem.model import Scene
from guiai.gem.dorothy import default_dorothy_document, dorothy_scene
from guiai.gem.dorothy_data import default_root, load_structures, parse_nrrd_counts, subtree_volumes
from guiai.gem.dorothy_jenga import BLOCK_HEIGHT, default_jenga_document, jenga_blocks, jenga_scene
from guiai.gem.dorothy_rings import build_tree, ring_sectors, rings_scene
from guiai.gem.dorothy_stack import default_stack_document, stack_meshes
from guiai.gem.spatial3d import Mesh
from guiai.gem.render import draw_cairo, scene_to_svg
from guiai.gem.spatial3d import Camera, _clip_near, parse_ply
from guiai.gem.vdi import opcode_inventory, scene_from_metafile, scene_to_metafile

CUBE_VERTICES = [
    (0, 0, 0), (1, 0, 0), (1, 1, 0), (0, 1, 0),
    (0, 0, 1), (1, 0, 1), (1, 1, 1), (0, 1, 1),
]
CUBE_QUADS = [(0, 1, 2, 3), (4, 5, 6, 7), (0, 1, 5, 4), (2, 3, 7, 6), (0, 3, 7, 4), (1, 2, 6, 5)]


def _cube_ply(format_name):
    header = (
        f"ply\nformat {format_name} 1.0\n"
        "element vertex 8\nproperty float x\nproperty float y\nproperty float z\n"
        "element face 6\nproperty list uchar int vertex_indices\nend_header\n"
    ).encode("ascii")
    if format_name == "ascii":
        body = "\n".join([" ".join(f"{float(axis):g}" for axis in vertex) for vertex in CUBE_VERTICES])
        faces = "\n".join("4 " + " ".join(str(index) for index in quad) for quad in CUBE_QUADS)
        return header + f"{body}\n{faces}\n".encode("ascii")
    import struct
    body = b"".join(struct.pack("<3f", *map(float, vertex)) for vertex in CUBE_VERTICES)
    body += b"".join(struct.pack("<B4i", 4, *quad) for quad in CUBE_QUADS)
    return header + body


class ZoeDorothyCase(unittest.TestCase):
    def test_ply_ascii_binary_and_quad_triangulation(self):
        ascii_mesh = parse_ply(_cube_ply("ascii"))
        binary_mesh = parse_ply(_cube_ply("binary_little_endian"))
        self.assertEqual(len(ascii_mesh.vertices), 8)
        self.assertEqual(len(ascii_mesh.faces), 12)
        self.assertEqual(ascii_mesh.faces, binary_mesh.faces)
        self.assertEqual(ascii_mesh.vertices, binary_mesh.vertices)
        with self.assertRaises(ValueError):
            parse_ply(_cube_ply("binary_little_endian")[:-9])
        with self.assertRaises(ValueError):
            parse_ply(b"not a ply file")

    def test_camera_projection_and_near_clipping(self):
        camera = Camera.fit(CUBE_VERTICES)
        self.assertGreater(camera.distance, 0)
        mesh = parse_ply(_cube_ply("ascii"))
        from guiai.gem.spatial3d import render_triangles
        rendered = render_triangles([(1, mesh, "#ff0000")], camera, 200, 200)
        self.assertEqual(rendered["total"], 12)
        self.assertEqual(len(rendered["points"]), 36)
        for x, y in rendered["points"]:
            self.assertTrue(0 <= x <= 200 and 0 <= y <= 200)
        clipped = _clip_near([(0, 0, 0.5), (1, 0, 1.5), (0, 1, 1.5)], 1.0)
        self.assertEqual(len(clipped), 4)
        self.assertEqual(sum(point[2] == 1.0 for point in clipped), 2)
        with self.assertRaises(ValueError):
            Camera((0, 0, 0), 1.0, pitch=90.0)

    def test_mesh_scene_validation_and_verification(self):
        document = {
            "schema_version": 1, "id": "mesh-test",
            "canvas": {"width": 100, "height": 100},
            "objects": [{
                "id": "m", "type": "mesh", "fill": "none", "stroke": "none", "width": 0,
                "points": [[0, 0], [10, 0], [0, 10], [20, 20], [30, 20], [20, 30]],
                "fills": ["#ff0000", "#00ff00"],
            }],
            "constraints": [{"type": "inside_canvas", "object": "*"}],
        }
        scene = Scene.from_dict(document)
        self.assertTrue(verify(scene).passed)
        document["objects"][0]["fills"] = ["#ff0000"]
        with self.assertRaises(ValueError):
            Scene.from_dict(document)
        document["objects"][0]["fills"] = ["#ff0000", "#00ff00"]
        document["objects"][0]["points"] = document["objects"][0]["points"][:-1]
        with self.assertRaises(ValueError):
            Scene.from_dict(document)

    def test_svg_cairo_and_vdi_preserve_painter_order(self):
        scene = Scene.from_dict({
            "schema_version": 1, "id": "painter-test",
            "canvas": {"width": 100, "height": 100},
            "objects": [{
                "id": "m", "type": "mesh", "fill": "none", "stroke": "none", "width": 0,
                "points": [[0, 0], [10, 0], [0, 10], [20, 20], [30, 20], [20, 30], [40, 40], [50, 40], [40, 50]],
                "fills": ["#ff0000", "#00ff00", "#ff0000"],
            }],
            "constraints": [],
        })
        svg = scene_to_svg(scene)
        self.assertLess(svg.index("#ff0000"), svg.index("#00ff00"))
        self.assertEqual(svg.count("<path"), 3)

        import types
        import sys
        recorder = type("Recorder", (), {})()
        recorder.fills = []
        recorder.rgb = None
        for name in ("save", "restore", "translate", "scale", "paint", "set_line_join", "move_to", "line_to", "close_path", "new_path"):
            setattr(recorder, name, lambda *args: None)
        recorder.set_source_rgb = lambda *rgb: setattr(recorder, "rgb", rgb)
        recorder.fill = lambda: recorder.fills.append(recorder.rgb)
        original = sys.modules.get("cairo")
        sys.modules["cairo"] = types.SimpleNamespace(LineJoin=types.SimpleNamespace(ROUND=0))
        try:
            draw_cairo(recorder, scene, 100, 100)
        finally:
            if original is None:
                del sys.modules["cairo"]
            else:
                sys.modules["cairo"] = original
        self.assertEqual(recorder.fills, [(1.0, 0.0, 0.0), (0.0, 1.0, 0.0), (1.0, 0.0, 0.0)])

        data = scene_to_metafile(scene)
        inventory = opcode_inventory(data)
        self.assertEqual(inventory["v_fillarea"], 3)
        self.assertGreaterEqual(inventory["vs_color"], 2)
        replayed = scene_from_metafile(data)
        mesh = replayed.object("m")
        self.assertEqual(mesh["fills"], ["#ff0000", "#00ff00", "#ff0000"])
        self.assertEqual(len(mesh["points"]), 9)

    def test_vendored_manifest_hash_verification(self):
        import hashlib
        data = _cube_ply("binary_little_endian")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "meshes").mkdir()
            (root / "meshes" / "1.ply").write_bytes(data)
            manifest = {
                "schema_version": 1,
                "structures": [{
                    "id": 1, "name": "Cube", "acronym": "C", "color": "#ff0000",
                    "mesh": "meshes/1.ply", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                }],
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            records = load_structures(root)
            self.assertEqual(records[0]["data"], data)
            scene, report = dorothy_scene(records)
            self.assertEqual(report["triangles"], 12)
            self.assertEqual(scene.digest(), dorothy_scene(records)[0].digest())
            (root / "meshes" / "1.ply").write_bytes(data[:20] + bytes([data[20] ^ 0xFF]) + data[21:])
            with self.assertRaises(ValueError):
                load_structures(root)

    @unittest.skipUnless((default_root() / "manifest.json").is_file(), "vendored CCF data is not fetched")
    def test_bookmark_determinism_and_vdi_evidence(self):
        first_scene, first_report = default_dorothy_document()
        second_scene, second_report = default_dorothy_document()
        self.assertEqual(first_scene.digest(), second_scene.digest())
        self.assertEqual(scene_to_svg(first_scene), scene_to_svg(second_scene))
        self.assertEqual(len(first_report["structures"]), 12)
        self.assertEqual(sum(record["triangles"] for record in first_report["structures"]), first_report["triangles"])
        self.assertEqual(first_report["scene_sha256"], second_report["scene_sha256"])
        self.assertTrue(verify(first_scene).passed)
        inventory = opcode_inventory(scene_to_metafile(first_scene))
        self.assertEqual(inventory["v_fillarea"], first_report["triangles"])

    @unittest.skipUnless((default_root() / "manifest.json").is_file(), "vendored CCF data is not fetched")
    def test_thalamus_hypothalamus_vdi_roundtrip_and_cli(self):
        records = load_structures(ids="549,1097")
        scene, report = dorothy_scene(records)
        replayed = scene_from_metafile(scene_to_metafile(scene))
        mesh = replayed.object("ccf-mesh")
        original = scene.object("ccf-mesh")
        self.assertEqual(mesh["fills"], original["fills"])
        expected = [[float(int(round(x))), float(int(round(y)))] for x, y in original["points"]]
        self.assertEqual(mesh["points"], expected)
        swatch = replayed.object("swatch-549")
        self.assertEqual(swatch["fill"], "#ff7080")
        with tempfile.TemporaryDirectory() as directory:
            svg = Path(directory) / "pair.svg"
            gem = Path(directory) / "pair.gem"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["dorothy", "--structures", "549,1097", "--output", str(svg)]), 0)
                self.assertEqual(gem_main(["dorothy", "--structures", "549,1097", "--output", str(gem)]), 0)
                self.assertEqual(gem_main(["zoe", "--module", "dorothy", "--output", str(Path(directory) / "atlas.svg")]), 0)
            self.assertTrue(svg.is_file() and gem.is_file())
            self.assertIn("Thalamus", svg.read_text())


class ZoeDorothyViewsCase(unittest.TestCase):
    def _graph(self):
        return [
            {"id": 1, "name": "Root", "acronym": "R", "color": "#808080", "parent_structure_id": None},
            {"id": 2, "name": "Alpha", "acronym": "A", "color": "#ff0000", "parent_structure_id": 1},
            {"id": 3, "name": "Beta", "acronym": "B", "color": "#00ff00", "parent_structure_id": 1},
            {"id": 4, "name": "Gamma", "acronym": "G", "color": "#0000ff", "parent_structure_id": 3},
        ]

    def test_subtree_volumes_sum_leaves(self):
        volumes = subtree_volumes(self._graph(), {2: 10, 3: 5, 4: 2})
        self.assertEqual(volumes, {1: 17, 2: 10, 3: 7, 4: 2})

    def test_parse_nrrd_counts_synthetic_volume(self):
        import gzip
        import struct
        header = (
            "NRRD0004\ntype: unsigned int\ndimension: 3\nsizes: 2 2 2\n"
            "endian: little\nencoding: gzip\n\n"
        ).encode("ascii")
        labels = [0, 1, 1, 2, 2, 2, 0, 2]
        data = header + gzip.compress(struct.pack("<8I", *labels))
        self.assertEqual(parse_nrrd_counts(data), {0: 2, 1: 2, 2: 4})
        with self.assertRaises(ValueError):
            parse_nrrd_counts(b"not nrrd")

    def test_rings_angles_follow_volume(self):
        by_id, children = build_tree(self._graph())
        volumes = subtree_volumes(self._graph(), {2: 10, 3: 5, 4: 2})
        sectors, omitted, thickness = ring_sectors(by_id, children, volumes, 1, max_depth=2)
        self.assertEqual(omitted, 0)
        first = {sector["id"]: sector for sector in sectors if sector["depth"] == 1}
        self.assertAlmostEqual(first[2]["angle"], TAU_FOR_TEST * 10 / 17)
        self.assertAlmostEqual(first[3]["angle"], TAU_FOR_TEST * 7 / 17)
        self.assertAlmostEqual(first[2]["angle"] + first[3]["angle"], TAU_FOR_TEST)
        gamma = next(sector for sector in sectors if sector["id"] == 4)
        self.assertAlmostEqual(gamma["angle"], first[3]["angle"] * 2 / 7)
        scene, report = rings_scene(self._graph(), volumes, center=1, max_depth=2)
        self.assertEqual(report["subtree_mm3"], round(17 * 25 ** 3 / 1e9, 6))
        self.assertEqual(scene.digest(), rings_scene(self._graph(), volumes, center=1, max_depth=2)[0].digest())
        self.assertTrue(verify(scene).passed)

    def _structures(self):
        return [
            {"id": 2, "acronym": "A", "name": "Alpha", "color": "#ff0000"},
            {"id": 3, "acronym": "B", "name": "Beta", "color": "#00ff00"},
            {"id": 4, "acronym": "G", "name": "Gamma", "color": "#0000ff"},
        ]

    def test_jenga_layouts_and_pull(self):
        volumes = {2: 10, 3: 30, 4: 20}
        items, layers, selected = jenga_blocks(self._structures(), volumes, layout="tower")
        self.assertEqual(len(items), 9)
        self.assertEqual([layer["record"]["id"] for layer in layers], [3, 4, 2])
        self.assertAlmostEqual(layers[0]["scale"], 1.0)
        self.assertAlmostEqual(layers[1]["scale"], (20 / 30) ** (1 / 3))
        for lower, upper in zip(layers, layers[1:]):
            top_of_lower = lower["y"] - BLOCK_HEIGHT * lower["scale"] / 2
            bottom_of_upper = upper["y"] + BLOCK_HEIGHT * upper["scale"] / 2
            self.assertGreaterEqual(top_of_lower - bottom_of_upper, 0)
        tower_span = max(vertex[1] for _id, mesh, _c in items for vertex in mesh.vertices) - min(vertex[1] for _id, mesh, _c in items for vertex in mesh.vertices)
        exploded, _, _ = jenga_blocks(self._structures(), volumes, layout="exploded")
        exploded_span = max(vertex[1] for _id, mesh, _c in exploded for vertex in mesh.vertices) - min(vertex[1] for _id, mesh, _c in exploded for vertex in mesh.vertices)
        self.assertGreater(exploded_span, tower_span)
        pulled, layers, selected = jenga_blocks(self._structures(), volumes, layout="pull", selected=4)
        self.assertEqual(selected, 4)
        gamma = next(layer for layer in layers if layer["record"]["id"] == 4)
        self.assertEqual(sum(block["pulled"] for block in gamma["blocks"]), 1)
        scene, report = jenga_scene(self._structures(), volumes, layout="pull", selected=4)
        self.assertEqual(report["triangles"], 108)
        self.assertEqual(scene.digest(), jenga_scene(self._structures(), volumes, layout="pull", selected=4)[0].digest())
        self.assertTrue(verify(scene).passed)

    def test_stack_slab_assignment_and_determinism(self):
        cube = parse_ply(_cube_ply("ascii"))
        shifted = Mesh([(x + 100, y, z) for x, y, z in cube.vertices], list(cube.faces))
        exploded, slabs, axis, gap = stack_meshes([(1, cube, "#ff0000"), (2, shifted, "#00ff00")], slices=2)
        self.assertEqual(axis, 0)
        self.assertEqual(sum(slab["triangles"] for slab in slabs), 24)
        self.assertEqual(slabs[1]["triangles"], 12)
        self.assertGreater(gap, 0)
        again, _, _, _ = stack_meshes([(1, cube, "#ff0000"), (2, shifted, "#00ff00")], slices=2)
        self.assertEqual([mesh.vertices for _id, mesh, _c in exploded], [mesh.vertices for _id, mesh, _c in again])

    @unittest.skipUnless((default_root() / "volumes.json").is_file(), "vendored CCF data is not fetched")
    def test_view_cli_and_document_determinism(self):
        first, _ = default_jenga_document()
        second, _ = default_jenga_document()
        self.assertEqual(first.digest(), second.digest())
        stack_first, _ = default_stack_document(slices=4)
        stack_second, _ = default_stack_document(slices=4)
        self.assertEqual(stack_first.digest(), stack_second.digest())
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["dorothy", "--view", "jenga", "--layout", "pull", "--structure", "549", "--output", str(Path(directory) / "pull.svg")]), 0)
                self.assertEqual(gem_main(["dorothy", "--view", "rings", "--structure", "315", "--output", str(Path(directory) / "rings.svg")]), 0)
                self.assertEqual(gem_main(["dorothy", "--view", "stack", "--slices", "6", "--output", str(Path(directory) / "stack.svg")]), 0)
                self.assertEqual(gem_main(["zoe", "--module", "dorothy-jenga", "--output", str(Path(directory) / "jenga.svg")]), 0)
            self.assertIn("Isocortex", (Path(directory) / "rings.svg").read_text())


TAU_FOR_TEST = 2 * 3.141592653589793


if __name__ == "__main__":
    unittest.main(verbosity=2)
