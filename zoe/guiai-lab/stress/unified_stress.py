from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from guiai.gem.atlas import default_document
from guiai.gem.cli import main as gem_main
from guiai.gem.geometry import verify
from guiai.gem.knowledge import KnowledgeField
from guiai.gem.runner import verify_vdi
from guiai.gem.unified import COMPONENTS, IDENTITY, ComponentRegistry, unified_scene
from guiai.gem.unified_cli import main as zoe_main


ROOT = Path(__file__).resolve().parents[1].parent
REGISTRY = ComponentRegistry(ROOT)


try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_foreign("cairo")
    from gi.repository import Gtk
    from guiai.gem.atlas_view import AtlasWindow
    HAS_GTK = bool(os.environ.get("DISPLAY"))
except (ImportError, ValueError):
    HAS_GTK = False


class UnifiedSourceCase(unittest.TestCase):
    def test_all_ten_repositories_and_full_ablation_are_present(self):
        lock = json.loads((ROOT / "components.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["identity"], IDENTITY)
        self.assertEqual(len(lock["components"]), 9)
        self.assertEqual(len(COMPONENTS), 11)
        manifest = REGISTRY.manifest()
        self.assertEqual(manifest["repository_count"], 10)
        self.assertEqual(manifest["upstream_repository_count"], 9)
        self.assertEqual(manifest["entrypoint_count"], 11)
        self.assertTrue(all(row["source"]["source_present"] for row in manifest["components"]))
        self.assertTrue(all(row["source"]["mode"] in {"bundled", "zoe", "host"} for row in manifest["components"]))
        self.assertEqual(REGISTRY.source("ablation")["path"], ROOT.parent)
        self.assertEqual(REGISTRY.source("gem-lab")["path"], ROOT.parent)
        self.assertEqual(REGISTRY.source("ablation")["mode"], "host")
        self.assertEqual(REGISTRY.source("gem-lab")["mode"], "host")
        for component in COMPONENTS:
            if component.revision is not None:
                self.assertEqual(component.revision, lock["components"][component.checkout]["revision"])
        for relative in (
            "../ablation/analyzers/entropy_mapper.py",
            "../gem-lab/gem/gtk_app.py",
            "../tests",
            "components/kevlar/policy.py",
            "components/pdf-signature-toolkit/pdf_signature_toolkit/verify.py",
            "components/Chalkboard/templates/README.template.md",
        ):
            self.assertTrue((ROOT / relative).exists(), relative)
        self.assertTrue((ROOT / "assets/branding/orbital-emblem.png").is_file())
        self.assertEqual(REGISTRY.knowledge.knowledge_state()["observation_count"], 11)
        self.assertEqual(REGISTRY.knowledge.knowledge_state()["link_count"], 10)
        self.assertEqual(len(REGISTRY.knowledge.events), 21)

    def test_knowledge_observations_and_declared_links_preserve_boundaries(self):
        registry = ComponentRegistry(ROOT)
        observation = registry.observe(
            "kevlar", {"mode": "audit", "tool_count": 2},
            scope="synthetic unit-test observation", source="unified test fixture",
        )
        self.assertEqual(observation["trust_context"]["repository"], "https://github.com/Ablation-Tool/kevlar")
        self.assertEqual(observation["trust_context"]["source"], "unified test fixture")
        self.assertFalse(observation["stability_context"]["runtime_verified"])
        self.assertFalse(observation["belief_updated"])
        self.assertFalse(observation["executed"])
        link = registry.knowledge.connect(observation["id"], "zoe", "inspectable test link")
        self.assertFalse(link["evidence_transfer"])
        self.assertFalse(link["permission_transfer"])
        self.assertEqual(registry.knowledge.claims, [])
        with self.assertRaisesRegex(ValueError, "unknown knowledge observation"):
            registry.knowledge.connect("missing", "zoe", "must fail")
        with self.assertRaisesRegex(ValueError, "canonical JSON bytes"):
            registry.observe("zoe", {"large": "x" * 70000}, scope="bound test", source="test")

    def test_knowledge_roundtrip_tamper_detection_and_no_overwrite(self):
        field = ComponentRegistry(ROOT).knowledge
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "knowledge.json"
            field.save(path)
            restored = KnowledgeField.load(path)
            self.assertEqual(restored.document(), field.document())
            self.assertEqual(restored.knowledge_state(), field.knowledge_state())
            with self.assertRaises(FileExistsError):
                field.save(path)
            document = field.document()
            document["events"][0]["payload"]["observation"]["observation"]["summary"] = "tampered"
            tampered = Path(directory) / "tampered.json"
            tampered.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash-chain mismatch"):
                KnowledgeField.load(tampered)
            reordered = field.document()
            reordered["events"][0], reordered["events"][1] = reordered["events"][1], reordered["events"][0]
            reordered_path = Path(directory) / "reordered.json"
            reordered_path.write_text(json.dumps(reordered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash-chain mismatch"):
                KnowledgeField.load(reordered_path)

    def test_command_source_isolation_research_runtime_and_content_library(self):
        with mock.patch.dict(os.environ, {"PYTHONPATH": "/invalid/host", "ZOE_PYTHON_DEPENDENCIES": "/tmp/dependencies"}, clear=False):
            command, cwd = REGISTRY.command("gem-lab")
            environment = REGISTRY.environment("gem-lab")
            self.assertEqual(command[-2:], ["launch", "--no-agent"])
            self.assertEqual(cwd, ROOT.parent / "gem-lab")
            self.assertIn("gem-lab", environment["PYTHONPATH"])
            self.assertIn("/tmp/dependencies", environment["PYTHONPATH"])
            self.assertNotIn("/invalid/host", environment["PYTHONPATH"])
            command, cwd = REGISTRY.command("research")
            self.assertEqual(command[-2:], ["gem", "os"])
            self.assertEqual(cwd, ROOT / "components/graphics-environment-manager")
            self.assertEqual(environment["MASTER_GEM_RESEARCH_ROOT"], str(ROOT / "components/next-token-predictability"))
        with self.assertRaisesRegex(ValueError, "content library"):
            REGISTRY.command("chalkboard")
        with self.assertRaisesRegex(ValueError, "--db"):
            REGISTRY.command("cerotto")

    def test_cli_manifest_knowledge_show_and_default_native(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            knowledge = Path(directory) / "knowledge.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(zoe_main(["list"]), 0)
                self.assertEqual(zoe_main(["manifest", "--output", str(manifest)]), 0)
                self.assertEqual(zoe_main(["knowledge", "--output", str(knowledge)]), 0)
                self.assertEqual(zoe_main(["manifest", "--output", str(manifest)]), 2)
                self.assertEqual(zoe_main(["show", "chalkboard"]), 0)
            self.assertIn("chalkboard", stdout.getvalue())
            self.assertEqual(json.loads(manifest.read_text())["entrypoint_count"], 11)
            self.assertEqual(KnowledgeField.load(knowledge).document(), REGISTRY.knowledge.document())
            with mock.patch("guiai.gem.atlas_view.launch_atlas") as launch:
                self.assertEqual(zoe_main([]), 0)
                launch.assert_called_once_with("unified")

    def test_orbital_scene_vdi_and_headless_export(self):
        first, report = default_document("unified")
        second, _ = unified_scene(ComponentRegistry(ROOT))
        self.assertEqual(first.digest(), second.digest())
        self.assertEqual(first.document["id"], "zoe-allgems")
        self.assertTrue(verify(first).passed, verify(first).text())
        self.assertTrue(verify_vdi(first).passed, verify_vdi(first).text())
        self.assertEqual(report["knowledge"]["observation_count"], 11)
        self.assertEqual(report["knowledge"]["link_count"], 10)
        self.assertEqual(len(report["memory"]["events"]), 21)
        self.assertTrue(report["scene_only"])
        self.assertFalse(report["executed"])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unified.svg"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["zoe", "--module", "unified", "--output", str(output)]), 0)
            text = output.read_text(encoding="utf-8")
            self.assertIn("ZOE · ALLGEMS", text)
            self.assertIn("Kevlar", text)
            self.assertIn("Chalkboard", text)


@unittest.skipUnless(os.environ.get("GEM_COMPONENT_TESTS") == "1", "set GEM_COMPONENT_TESTS=1 for real component commands")
class UnifiedCommandCase(unittest.TestCase):
    def test_real_component_commands(self):
        registry = ComponentRegistry(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = [
                ("ablation", ["--help"], None),
                ("gem-lab", ["demo", "--output", str(root / "lab-run")], "lab-run"),
                ("gem", ["workbench", "check", "--output", str(root / "canonical.json")], "canonical.json"),
                ("helen", ["--module", "onset", "--output", str(root / "helen.json")], "helen.json"),
                ("brain", ["notebook", "--output", str(root / "brain.json")], "brain.json"),
                ("kevlar", ["--help"], None),
                ("pdf", ["--help"], None),
                ("research", ["workbench", "list"], None),
            ]
            for identifier, arguments, artifact in cases:
                with self.subTest(component=identifier):
                    result = registry.launch(identifier, arguments, detach=False)
                    self.assertEqual(result.returncode, 0, (identifier, result.stdout, result.stderr))
                    if artifact:
                        self.assertTrue((root / artifact).exists())


@unittest.skipUnless(HAS_GTK, "native unified tests require GTK, Cairo, and an X11 DISPLAY")
class UnifiedNativeCase(unittest.TestCase):
    def test_native_hub_inspect_link_launch_and_memory(self):
        window = AtlasWindow("unified")
        try:
            self.assertEqual(window.unified_registry.knowledge.knowledge_state()["observation_count"], 11)
            window.show_unified("chalkboard")
            self.assertIn("Chalkboard", window.summary.get_text())
            self.assertIn("Content inspection only", window.summary.get_text())
            window.record_unified_source("kevlar")
            self.assertEqual(window.unified_registry.knowledge.knowledge_state()["observation_count"], 12)
            self.assertEqual(window.unified_registry.knowledge.knowledge_state()["link_count"], 11)
            with mock.patch.object(window.unified_registry, "launch", return_value=types.SimpleNamespace(pid=12345)) as launch:
                window.launch_unified("kevlar", ["--help"])
                launch.assert_called_once_with("kevlar", ["--help"], detach=True)
            self.assertIn("12345", window.summary.get_text())
            self.assertIn("does not verify readiness", window.summary.get_text())
            with tempfile.TemporaryDirectory() as directory:
                path = window.export_current(Path(directory) / "knowledge.json")
                self.assertEqual(KnowledgeField.load(path).document(), window.unified_registry.knowledge.document())
                with self.assertRaises(FileExistsError):
                    window.export_current(path)
            window.open_cognitive()
            self.assertEqual(window.module, "cognitive")
        finally:
            window.destroy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
