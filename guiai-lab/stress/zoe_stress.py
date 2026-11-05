from __future__ import annotations

import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest

from guiai.gem.atlas import default_document
from guiai.gem.brain import BrainKernel, toy_horizon
from guiai.gem.cli import main as gem_main
from guiai.gem.geometry import verify
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


@unittest.skipUnless(RESEARCH_ROOT.is_dir(), "research pack checkout is unavailable")
class ZoeResearchCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pack = ResearchPack.load(RESEARCH_ROOT)

    def test_all_conformance_vectors(self):
        checks = self.pack.verify_conformance()
        self.assertEqual(len(checks), 15)
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
            window.observe_brain_next()
            self.assertEqual(window.brain.observation_count, 2)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
