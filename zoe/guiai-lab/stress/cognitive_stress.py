from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from guiai.gem.atlas import ATLAS_MODULES, default_document
from guiai.gem.cli import main as gem_main
from guiai.gem.cognitive import CognitiveField, cognitive_scene, export_cognitive
from guiai.gem.geometry import verify
from guiai.gem.runner import verify_vdi
from guiai.gem.vdi import scene_from_metafile, scene_to_metafile


try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_foreign("cairo")
    from gi.repository import Gtk
    from guiai.gem.atlas_view import AtlasWindow
    HAS_GTK = bool(os.environ.get("DISPLAY"))
except (ImportError, ValueError):
    HAS_GTK = False


class CognitiveFieldCase(unittest.TestCase):
    def test_encoding_is_sourced_bounded_and_explicitly_evicted(self):
        field = CognitiveField(working_capacity=2)
        first = field.encode("first", "test source", "one")
        field.encode("second", "test source", ["two"])
        third = field.encode("third", "test source", "three")
        self.assertEqual(first["source"], "test source")
        self.assertEqual(third["event_sequence"], 3)
        self.assertEqual([item["id"] for item in field.working], ["r-2", "r-3"])
        self.assertEqual(len(field.evicted), 1)
        self.assertEqual(field.evicted[0]["id"], "r-1")
        self.assertEqual(field.evicted[0]["eviction_event_sequence"], 3)
        self.assertEqual(field.sensory[0]["status"], "evicted")
        with self.assertRaisesRegex(ValueError, "not active"):
            field.store_active("r-1")
        for invalid in (0, 17, True, 1.5):
            with self.assertRaises(ValueError):
                CognitiveField(working_capacity=invalid)

    def test_declarative_provenance_and_revision_mismatch(self):
        field = CognitiveField()
        field.encode("retained observation", "experiment 1", "memory")
        stored = field.store_active("r-1", expected_revision=0)
        self.assertEqual(stored["revision"], 1)
        self.assertEqual(stored["source"], "experiment 1")
        matched = field.retrieve(stored["id"], 1)
        self.assertEqual(matched["record"]["text"], "retained observation")
        self.assertEqual(matched["source_representation_id"], "r-1")
        self.assertEqual(matched["source_event_sequence"], 1)
        mismatch = field.retrieve(stored["id"], 0)
        self.assertEqual(mismatch["status"], "revision_mismatch")
        self.assertNotIn("record", mismatch)
        self.assertTrue(mismatch["event_sequence"] > matched["event_sequence"])
        self.assertFalse(mismatch["belief_updated"])
        with self.assertRaises(ValueError):
            field.store_active("r-1", expected_revision=1)
        with self.assertRaises(ValueError):
            field.retrieve("unknown", 1)

    def test_procedural_matching_never_executes_and_negative_results_remain(self):
        field = CognitiveField()
        field.encode("inspect", "native test", ["inspect", "review"])
        field.add_rule("Review", ["inspect", "review"], "Prepare a review record.")
        field.add_rule("Absent", ["absent"], "Do not run this rule.")
        match = field.match_rules()
        self.assertEqual(match["matched_rule_ids"], ["p-1"])
        self.assertFalse(match["executed"])
        proposal = field.propose_performance(match["id"], "human review requested")
        self.assertTrue(proposal["review_required"])
        self.assertFalse(proposal["executed"])
        self.assertFalse(proposal["belief_updated"])
        no_match = field.match_rules("p-2")
        self.assertEqual(no_match["status"], "no_match")
        with self.assertRaisesRegex(ValueError, "no-match"):
            field.propose_performance(no_match["id"], "must not be proposed")
        with self.assertRaisesRegex(ValueError, "not part"):
            field.propose_performance(match["id"], "wrong rule", rule_id="p-2")
        self.assertEqual(len(field.performance), 1)

    def test_measurements_and_seeded_samples_preserve_belief_boundary(self):
        field = CognitiveField()
        question = field.add_question("Does a measurement change a posterior?")
        claim = field.add_claim(question["id"], "It changes automatically.", prior=.4)
        measurement = field.measure([.70, .20, .08, .02], .05)
        self.assertEqual(measurement["result"]["accessible_volume"], 3)
        first = field.measure([.70, .20, .08, .02], .05, seed=7)
        second = field.measure([.70, .20, .08, .02], .05, seed=7)
        self.assertEqual(first["result"]["selected_index"], second["result"]["selected_index"])
        self.assertEqual(field.claim(claim["id"])["posterior"], .4)
        self.assertFalse(field.evidence)
        self.assertTrue(all(not row["belief_updated"] and not row["executed"] for row in field.measurements))
        probabilities = [.7] + [.3 / 99] * 99
        large = field.measure(probabilities, .05)
        self.assertEqual(large["inputs"]["probabilities"]["length"], 100)
        self.assertNotIsInstance(large["inputs"]["probabilities"], list)

    def test_hash_chain_roundtrip_tamper_detection_and_no_overwrite(self):
        field = CognitiveField.demo()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cognitive.json"
            field.save(path)
            restored = CognitiveField.load(path)
            self.assertEqual(restored.document(), field.document())
            self.assertEqual(restored.cognitive_state(), field.cognitive_state())
            self.assertEqual(restored.working_capacity, 4)
            with self.assertRaises(FileExistsError):
                field.save(path)
            document = field.document()
            document["events"][2]["payload"]["record"]["representation"]["text"] = "tampered"
            tampered = Path(directory) / "tampered.json"
            tampered.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash-chain mismatch"):
                CognitiveField.load(tampered)
            reordered = field.document()
            reordered["events"][2], reordered["events"][3] = reordered["events"][3], reordered["events"][2]
            reordered_path = Path(directory) / "reordered.json"
            reordered_path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash-chain mismatch"):
                CognitiveField.load(reordered_path)

    def test_deterministic_scene_vdi_and_no_overwrite_exports(self):
        field = CognitiveField.demo()
        first, report = cognitive_scene(field)
        second, _ = cognitive_scene(CognitiveField.demo())
        self.assertEqual(first.digest(), second.digest())
        self.assertTrue(verify(first).passed, verify(first).text())
        self.assertTrue(verify_vdi(first).passed, verify_vdi(first).text())
        recovered = scene_from_metafile(scene_to_metafile(first))
        self.assertEqual(recovered.object("working-panel")["fill"], first.object("working-panel")["fill"])
        self.assertEqual(first.object("title")["text"], "Z.O.E. · COGNITIVE FIELD / GSP")
        self.assertIn("GENERAL SYMBOL PROCESSOR", first.object("architecture")["text"])
        self.assertEqual(len([item for item in first.objects if item.get("role") == "active_memory_layer"]), 15)
        self.assertEqual(len(report["memory"]["events"]), 16)
        self.assertFalse(report["consciousness_measured"])
        self.assertFalse(report["act_r_implementation"])
        with tempfile.TemporaryDirectory() as directory:
            for suffix in ("json", "svg", "png", "gem"):
                path = Path(directory) / f"cognitive.{suffix}"
                output, exported = export_cognitive(field, path, width=1400)
                self.assertEqual(output, path)
                self.assertGreater(path.stat().st_size, 0)
                if suffix != "json":
                    self.assertTrue(exported["verification"]["scene"]["passed"])
                    self.assertTrue(exported["verification"]["vdi"]["passed"])
                with self.assertRaises(FileExistsError):
                    export_cognitive(field, path)

    def test_cli_and_atlas_worked_example(self):
        self.assertIn("cognitive", ATLAS_MODULES)
        scene, report = default_document("cognitive")
        self.assertEqual(report["eviction_count"], 1)
        self.assertTrue(verify(scene).passed)
        with tempfile.TemporaryDirectory() as directory:
            memory = Path(directory) / "memory.json"
            rendered = Path(directory) / "field.svg"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["cognitive", "--output", str(memory)]), 0)
                self.assertEqual(gem_main(["cognitive", str(memory), "--output", str(rendered)]), 0)
                self.assertEqual(gem_main(["cognitive", "--output", str(memory)]), 2)
            self.assertIn("COGNITIVE FIELD", rendered.read_text(encoding="utf-8"))
            self.assertEqual(CognitiveField.load(memory).document(), CognitiveField.demo().document())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["zoe", "--module", "cognitive", "--output", str(Path(directory) / "atlas.svg")]), 0)


@unittest.skipUnless(HAS_GTK, "native Cognitive Field tests require GTK, Cairo, and an X11 DISPLAY")
class CognitiveNativeCase(unittest.TestCase):
    def test_native_memory_workflow_and_exports(self):
        window = AtlasWindow("cognitive")
        try:
            self.assertEqual(window.cognitive.events, [])
            window.controls["capacity"].set_value(2)
            window.new_cognitive()
            window.controls["sensory_text"].set_text("first observation")
            window.encode_cognitive()
            window.store_cognitive()
            window.controls["expected_revision"].set_value(1)
            window.retrieve_cognitive()
            self.assertEqual(window.cognitive.retrievals[-1]["status"], "matched")
            window.add_cognitive_rule()
            window.match_cognitive()
            window.propose_cognitive()
            proposal = window.cognitive.performance[-1]
            self.assertTrue(proposal["review_required"])
            self.assertFalse(proposal["executed"])
            window.controls["sensory_text"].set_text("second observation")
            window.encode_cognitive()
            window.controls["sensory_text"].set_text("third observation")
            window.encode_cognitive()
            self.assertEqual(len(window.cognitive.working), 2)
            self.assertEqual(len(window.cognitive.evicted), 1)
            window.measure_cognitive()
            window.sample_cognitive()
            self.assertEqual(window.cognitive.measurements[-1]["result"]["seed"], 7)
            self.assertFalse(window.cognitive.evidence)
            with tempfile.TemporaryDirectory() as directory:
                for suffix in ("json", "svg", "png", "gem"):
                    path = window.export_current(Path(directory) / f"cognitive.{suffix}")
                    self.assertTrue(path.is_file())
                    with self.assertRaises(FileExistsError):
                        window.export_current(path)
                restored = CognitiveField.load(Path(directory) / "cognitive.json")
                self.assertEqual(restored.document(), window.cognitive.document())
            window.load_cognitive_demo()
            self.assertEqual(window.cognitive.document(), CognitiveField.demo().document())
        finally:
            window.destroy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
