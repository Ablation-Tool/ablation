from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from gem.cli import main as gem_main
from gem.eye import EyeModel, eye_scene, stereo_observations
from gem.geometry import verify
from gem.runner import verify_vdi


class SecondEyeCase(unittest.TestCase):
    def test_stereo_depth_and_defocus_math(self):
        model = EyeModel()
        disparity = model.disparity(2.0)
        self.assertAlmostEqual(disparity, model.focal_pixels * model.baseline / 2.0)
        self.assertAlmostEqual(model.depth_from_disparity(disparity), 2.0)
        self.assertEqual(model.circle_of_confusion(model.focus), 0)
        near = model.circle_of_confusion(.73)
        self.assertGreater(near, model.circle_of_confusion(2.45))
        narrower = EyeModel(fstop=16)
        self.assertLess(narrower.circle_of_confusion(.73), near)
        depth_of_field = model.depth_of_field()
        self.assertLess(depth_of_field["near_m"], model.focus)
        self.assertGreater(depth_of_field["far_m"], model.focus)
        extreme = EyeModel(focus=10, fstop=64).depth_of_field()
        self.assertIsNone(extreme["far_m"])
        self.assertTrue(extreme["far_unbounded"])
        with self.assertRaises(ValueError):
            EyeModel(baseline=.001)
        with self.assertRaises(ValueError):
            EyeModel(focus=.1)
        with self.assertRaises(ValueError):
            model.depth_from_disparity(0)

    def test_synthetic_depth_scene_and_cli_exports(self):
        model = EyeModel()
        scene, report = eye_scene(model)
        self.assertTrue(verify(scene).passed, verify(scene).text())
        self.assertTrue(verify_vdi(scene).passed)
        self.assertFalse(report["actual_camera_used"])
        self.assertFalse(report["subjective_sight"])
        self.assertFalse(report["executed"])
        self.assertGreater(len(report["observations"]), 40)
        for observation in report["observations"]:
            tolerance = model.depth_sensitivity(observation["depth"]) + .001
            self.assertLessEqual(abs(observation["depth_error_m"]), tolerance, observation["name"])
            self.assertGreaterEqual(observation["disparity_sensitivity_m"], 0)
            self.assertGreaterEqual(observation["circle_of_confusion_m"], 0)
        far = next(item for item in report["observations"] if item["name"] == "dew")
        near = next(item for item in report["observations"] if item["name"] == "stem")
        self.assertGreater(far["disparity_sensitivity_m"], near["disparity_sensitivity_m"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for suffix in ("json", "svg", "gem"):
                output = root / f"eye.{suffix}"
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gem_main(["eye", "--output", str(output)]), 0)
                self.assertTrue(output.is_file())
            report = json.loads((root / "eye.json").read_text())
            self.assertFalse(report["actual_camera_used"])
            self.assertIn("Parallax, not a second opinion.", (root / "eye.svg").read_text())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(gem_main(["eye", "--output", str(root / "eye.json")]), 2)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["eye", "--focus", "10", "--aperture", "64", "--output", str(root / "extreme.json")]), 0)
            self.assertIsNone(json.loads((root / "extreme.json").read_text())["depth_of_field"]["far_m"])


try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_foreign("cairo")
    HAS_GTK = bool(os.environ.get("DISPLAY"))
except (ImportError, ValueError):
    HAS_GTK = False


@unittest.skipUnless(HAS_GTK, "native second-eye tests require GTK, Cairo, and an X11 display")
class NativeSecondEyeCase(unittest.TestCase):
    def test_focus_aperture_baseline_and_export(self):
        from gem.eye_view import EyeWindow

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            window = EyeWindow()
            try:
                window.controls["focus"].set_value(2.0)
                self.assertAlmostEqual(window.model.focus, 2.0)
                window.aperture.set_active_id("16.0")
                self.assertAlmostEqual(window.model.fstop, 16.0)
                window.controls["baseline"].set_value(.1)
                self.assertAlmostEqual(window.model.baseline, .1)
                core = next(item for item in window.report["observations"] if item["name"] == "core")
                self.assertAlmostEqual(core["recovered_depth_m"], 2.0, delta=.05)
                self.assertLess(core["circle_of_confusion_m"], .02)
                output = window.export_current(root / "eye.json")
                self.assertEqual(json.loads(output.read_text())["baseline_m"], .1)
                self.assertIn("SECOND EYE", window.export_current(root / "eye.svg").read_text())
                self.assertTrue(window.export_current(root / "eye.gem").stat().st_size > 1000)
            finally:
                window.destroy()
            custom = EyeWindow(EyeModel(fstop=3.2, focus=5.0, baseline=.22))
            try:
                self.assertAlmostEqual(custom.model.fstop, 3.2)
                self.assertAlmostEqual(custom.model.focus, 5.0)
                self.assertAlmostEqual(custom.model.baseline, .22)
            finally:
                custom.destroy()


if __name__ == "__main__":
    unittest.main()
