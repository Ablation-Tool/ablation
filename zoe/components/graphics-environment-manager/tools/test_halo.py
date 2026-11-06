from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import numpy as np

from gem.cli import main as gem_main
from gem.geometry import verify
from gem.halo import (
    Pose,
    _evaluate,
    experiment,
    halo_scene,
    is_bent,
    nonlinearity,
    pixel_distance,
    pool,
    project,
    rotation,
    rotation_error,
    synthetic_points,
    walsh_distance,
    walsh_spectrum,
    walsh_template,
)
from gem.runner import verify_vdi


class HaloFieldCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = experiment("both")

    def test_rotation_and_projection(self):
        self.assertEqual(rotation(Pose()).shape, (3, 3))
        np.testing.assert_allclose(rotation(Pose()), np.eye(3))
        np.testing.assert_allclose(rotation(Pose(rx=90)) @ [0, 1, 0], [0, 0, 1], atol=1e-12)
        arbitrary = rotation(Pose(17, -21, 27))
        np.testing.assert_allclose(arbitrary.T @ arbitrary, np.eye(3), atol=1e-12)
        self.assertAlmostEqual(np.linalg.det(arbitrary), 1)
        self.assertAlmostEqual(rotation_error(Pose(), Pose(rz=180)), 180)
        points = synthetic_points()
        self.assertEqual(points.shape, (450, 3))
        image = project(points, Pose())
        self.assertEqual(image.shape, (48, 48))
        self.assertAlmostEqual(float(image.sum()), 1)
        self.assertTrue(np.all(image >= 0))
        np.testing.assert_array_equal(image, project(points, Pose()))
        truth = Pose(17, -21, 27, .10, -.08, .09)
        target = (project(points, truth), project(points, truth, 65))
        for metric in ("l2", "walsh"):
            self.assertEqual(_evaluate(points, truth, target, 65, metric), 0)
            self.assertGreater(_evaluate(points, Pose(), target, 65, metric), 0)

    def test_signed_walsh_and_classic_bent_function(self):
        bits = np.asarray([
            ((index & 1) * ((index >> 1) & 1)) ^ (((index >> 2) & 1) * ((index >> 3) & 1))
            for index in range(16)
        ])
        coefficients = walsh_spectrum(bits)
        self.assertEqual(set(np.abs(coefficients)), {4})
        self.assertEqual(nonlinearity(bits), 6)
        self.assertTrue(is_bent(bits))
        self.assertFalse(is_bent(np.asarray([index.bit_count() % 2 for index in range(16)])))
        with self.assertRaises(ValueError):
            walsh_spectrum([0, 1, 0])
        with self.assertRaises(ValueError):
            walsh_spectrum([0, 2, 1, 0])

    def test_pooling_and_metric_identity(self):
        image = np.arange(16, dtype=float).reshape(4, 4)
        np.testing.assert_allclose(pool(image, 2), [[2.5, 4.5], [10.5, 12.5]])
        self.assertEqual(pool(project(synthetic_points(), Pose()), 24).shape, (24, 24))
        self.assertEqual(pixel_distance(image, image), 0)
        self.assertEqual(walsh_distance(image, image), 0)
        template = walsh_template(project(synthetic_points(), Pose()))
        self.assertEqual(template.shape, (16,))
        self.assertAlmostEqual(float(np.linalg.norm(template)), 1)
        np.testing.assert_array_equal(template, np.sort(template))

    def test_default_results_preserve_disagreement_and_failure(self):
        report = self.report
        self.assertNotIn("best", report)
        self.assertTrue(report["disagreement"])
        self.assertFalse(report["medical_data"])
        self.assertFalse(report["anatomical_model"])
        self.assertFalse(report["physical_xray_simulation"])
        self.assertFalse(report["encryption"])
        self.assertFalse(report["autonomous_action"])
        l2 = report["metrics"]["l2"]
        self.assertLess(l2["best"]["translation_error"], .02)
        self.assertLess(l2["best"]["rotation_error_degrees"], 10)
        walsh = report["metrics"]["walsh"]
        self.assertTrue(walsh["tied_with_next"])
        self.assertEqual(walsh["score_gap"], 0)
        self.assertLess(walsh["truth_score"], walsh["best"]["score"])
        self.assertGreater(report["metric_rotation_difference_degrees"], 1)
        for result in report["metrics"].values():
            self.assertEqual(len(result["alternatives"]), 2)
            self.assertGreaterEqual(result["score_gap"], 0)

    def test_deterministic_report_and_single_metric_boundary(self):
        self.assertEqual(self.report, experiment("both"))
        report = experiment("l2", view_angle=55, noise=.005, seed=11)
        self.assertEqual(set(report["metrics"]), {"l2"})
        self.assertIsNone(report["disagreement"])
        self.assertIsNone(report["metric_rotation_difference_degrees"])
        self.assertEqual(report["seed"], 11)
        self.assertEqual(report["view_angle_degrees"], 55)
        self.assertEqual(report["noise"], .005)
        for arguments in ({"view_angle": 0}, {"noise": .1}, {"seed": -1}, {"metric": "combined"}):
            with self.assertRaises(ValueError):
                experiment(**arguments)

    def test_scene_and_vdi(self):
        scene, report = halo_scene(self.report)
        self.assertIs(report, self.report)
        self.assertTrue(verify(scene).passed, verify(scene).text())
        self.assertTrue(verify_vdi(scene).passed)
        identifiers = {item["id"] for item in scene.objects}
        self.assertIn("zoe-circle", identifiers)
        self.assertIn("halo-negative-space", identifiers)
        self.assertTrue(any(item["id"].startswith("halo-upper-") for item in scene.objects))

    def test_cli_exports_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for suffix in ("json", "svg", "png", "gem"):
                output = root / f"halo.{suffix}"
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gem_main(["halo", "--metric", "l2", "--output", str(output)]), 0)
                self.assertGreater(output.stat().st_size, 100)
            report = json.loads((root / "halo.json").read_text())
            self.assertEqual(set(report["metrics"]), {"l2"})
            self.assertIn("HALO FIELD", (root / "halo.svg").read_text())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(gem_main(["halo", "--output", str(root / "halo.json")]), 2)
                self.assertEqual(gem_main(["halo", "--noise", ".2", "--output", str(root / "invalid.json")]), 2)


try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_foreign("cairo")
    HAS_GTK = bool(os.environ.get("DISPLAY"))
except (ImportError, ValueError):
    HAS_GTK = False


@unittest.skipUnless(HAS_GTK, "native Halo tests require GTK, Cairo, and an X11 display")
class NativeHaloFieldCase(unittest.TestCase):
    def test_controls_and_exports(self):
        from gem.halo_view import HaloWindow

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            window = HaloWindow(metric="l2")
            try:
                window.controls["view_angle"].set_value(55)
                self.assertEqual(window.report["view_angle_degrees"], 55)
                window.controls["noise"].set_value(.005)
                self.assertAlmostEqual(window.report["noise"], .005)
                window.controls["seed"].set_value(12)
                self.assertEqual(window.report["seed"], 12)
                window.metric.set_active_id("both")
                self.assertEqual(set(window.report["metrics"]), {"l2", "walsh"})
                output = window.export_current(root / "halo.json")
                self.assertEqual(json.loads(output.read_text())["seed"], 12)
                self.assertIn("HALO FIELD", window.export_current(root / "halo.svg").read_text())
                self.assertGreater(window.export_current(root / "halo.png").stat().st_size, 1000)
                self.assertGreater(window.export_current(root / "halo.gem").stat().st_size, 1000)
            finally:
                window.destroy()
            custom = HaloWindow(metric="walsh", view_angle=40, noise=.002, seed=9)
            try:
                self.assertEqual(set(custom.report["metrics"]), {"walsh"})
                self.assertEqual(custom.report["view_angle_degrees"], 40)
                self.assertEqual(custom.report["noise"], .002)
                self.assertEqual(custom.report["seed"], 9)
            finally:
                custom.destroy()


if __name__ == "__main__":
    unittest.main()
