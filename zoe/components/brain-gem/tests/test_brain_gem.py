from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from brain_gem.atlas import default_document
from brain_gem.brain import BrainKernel, toy_horizon
from brain_gem.cli import main as gem_main
from brain_gem.field import FieldNotebook, bayes_binary, volume_joint
from brain_gem.geometry import verify
from brain_gem.research import ResearchPack
from brain_gem.runner import verify_vdi

RESEARCH_ROOT = Path(os.environ.get("MASTER_GEM_RESEARCH_ROOT", "/home/cowboy/_projects/next-token-predictability"))

try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_foreign("cairo")
    from gi.repository import Gtk
    from brain_gem.atlas_view import AtlasWindow
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


class ZoeSceneCase(unittest.TestCase):
    def test_brain_and_horizon_scenes_and_cli_exports(self):
        for module in ("brain", "horizon"):
            with self.subTest(module=module):
                scene, _ = default_document(module)
                self.assertTrue(verify(scene).passed, verify(scene).text())
                self.assertTrue(verify_vdi(scene).passed)
        with tempfile.TemporaryDirectory() as directory:
            for module in ("brain", "horizon"):
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

if __name__ == "__main__":
    unittest.main(verbosity=2)
