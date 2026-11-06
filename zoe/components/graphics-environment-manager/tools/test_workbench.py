from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from gem.cli import main as gem_main
from gem.field import FieldNotebook
from gem.geometry import verify
from gem.mirror import MirroredBrain, mirror_scene
from gem.onset import load_experiment
from gem.runner import verify_vdi
from gem.workbench import Workbench


class UnifiedWorkbenchCase(unittest.TestCase):
    def test_all_operations_and_mirrored_pairs(self):
        report = Workbench().verify()
        self.assertEqual(report["algorithm_count"], 17)
        self.assertEqual(report["passed"], 17)
        self.assertEqual(report["failed"], 0, [row for row in report["results"] if not row["passed"]])

        experiment = load_experiment()
        brain = MirroredBrain()
        for index in range(1920):
            state = brain.observe(index, include_history=False)
            current = state["current"]
            self.assertEqual(current["index"], index)
            for condition in ("forward", "retrograde"):
                observation = current[condition]
                probabilities = experiment.probabilities(condition)[index]
                self.assertEqual(observation["accessible_volume"], sum(value > current["tau"] for value in probabilities))
                self.assertEqual(current["accessible_volume"][condition] + current["complement_volume"][condition], len(probabilities))
                self.assertEqual(observation["predicted_target"], max(range(len(probabilities)), key=probabilities.__getitem__))
                self.assertEqual(observation["target"], experiment.targets(condition)[index])
                self.assertFalse(observation["executed"])
            self.assertEqual(current["volume_delta"], current["accessible_volume"]["forward"] - current["accessible_volume"]["retrograde"])
            self.assertEqual(current["argmax_agreement"], current["forward"]["predicted_target"] == current["retrograde"]["predicted_target"])
            self.assertFalse(current["executed"])
            self.assertFalse(state["history_included"])
        state = brain.state()
        self.assertEqual(state["observation_count"], 1920)
        self.assertEqual(len(state["history"]), 128)
        self.assertEqual([row["index"] for row in state["history"]], list(range(1792, 1920)))
        self.assertEqual(brain.forward.history, [])
        self.assertEqual(brain.retrograde.history, [])
        self.assertEqual(brain.observe()["current"]["index"], 0)
        scene, _ = mirror_scene(brain)
        self.assertTrue(verify(scene).passed, verify(scene).text())
        self.assertTrue(verify_vdi(scene).passed)

    def test_operation_cli_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "inputs.json"
            inputs.write_text(json.dumps({"probabilities": [0.70, 0.20, 0.08, 0.02], "tau": 0.05}))
            output = root / "volume.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["workbench", "run", "volume/strict@v1", "--input", str(inputs), "--output", str(output)]), 0)
            report = json.loads(output.read_text())
            self.assertEqual(report["result"]["accessible_volume"], 3)
            self.assertFalse(report["executed"])
            self.assertEqual(gem_main(["workbench", "run", "volume/strict@v1", "--input", str(inputs), "--output", str(output)]), 2)


try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_foreign("cairo")
    HAS_GTK = bool(os.environ.get("DISPLAY"))
except (ImportError, ValueError):
    HAS_GTK = False


@unittest.skipUnless(HAS_GTK, "native mirrored-brain tests require GTK, Cairo, and an X11 display")
class NativeMirroredBrainCase(unittest.TestCase):
    def test_observation_export_and_explicit_field_update(self):
        from gem.mirror_view import MirrorWindow

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            window = MirrorWindow("mirror")
            try:
                window.observe_mirror()
                window.observe_mirror_next()
                self.assertEqual(window.mirror.observation_count, 2)
                self.assertEqual(window.mirror.current["index"], 1)
                self.assertEqual(len(window.field.observations), 2)
                self.assertEqual(window.field.claims, [])
                output = window.export_current(root / "mirror.svg")
                self.assertIn("MIRRORED BRAIN", output.read_text())
                self.assertEqual(window.mirror.evidence_exports, 1)
                self.assertFalse(window.mirror.current["executed"])
            finally:
                window.destroy()

            window = MirrorWindow("field")
            try:
                window.load_field_demo()
                measurement_count = len(window.field.measurements)
                before = window.field.claims[0]["posterior"]
                window.controls["evidence"].set_text("Independent test evidence")
                window.controls["family"].set_text("native-verification")
                window.add_field_evidence()
                self.assertNotEqual(window.field.claims[0]["posterior"], before)
                window.measure_field()
                window.sample_field()
                self.assertEqual(len(window.field.measurements), measurement_count + 2)
                output = window.export_current(root / "field.json")
                restored = FieldNotebook.load(output)
                self.assertEqual(restored.document(), window.field.document())
                self.assertEqual(len(restored.measurements), measurement_count + 2)
            finally:
                window.destroy()


if __name__ == "__main__":
    unittest.main()
