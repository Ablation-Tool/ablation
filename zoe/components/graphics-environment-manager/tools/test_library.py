from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from gem.mirror import os_document as default_document
from gem.cli import main as gem_main
from gem.geometry import verify
from gem.library import ManualLibrary, library_scene
from gem.runner import verify_vdi


class ManualLibraryCase(unittest.TestCase):
    def test_real_index_search_scene_and_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manual.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" width="600" height="120"><text x="20" y="65" font-family="sans-serif" font-size="26">VDI driver and AES resource construction</text></svg>')
            subprocess.run(["/usr/bin/rsvg-convert", "-f", "pdf", "-o", str(root / "manual.pdf"), str(root / "manual.svg")], check=True)
            (root / "notes.txt").write_text("AES resource construction set and Graphics Device Interface")
            (root / "reference.html").write_text("<html><body><h1>GEM VDI</h1><p>Read the driver contract.</p></body></html>")
            (root / "ignored.bin").write_bytes(b"not a document")
            self.assertFalse(ManualLibrary(root / "index.sqlite").available)
            library = ManualLibrary.index([root], root / "index.sqlite")
            summary = library.summary()
            self.assertTrue(summary["available"])
            self.assertEqual(summary["documents"], 3)
            self.assertEqual(summary["unsupported_files"], 2)
            self.assertEqual(summary["groups"], [root.name])
            self.assertGreaterEqual(summary["pages_total"], 3)
            with library._connection() as connection:
                hashes = connection.execute("SELECT sha256,bytes FROM documents").fetchall()
            self.assertTrue(all(len(digest) == 64 and size > 0 for digest, size in hashes))
            results = library.search("VDI")
            self.assertTrue(results)
            self.assertTrue(any(item["title"] == "manual" for item in results))
            self.assertTrue(all(item["page"] >= 1 for item in results))
            self.assertTrue(all("<html>" not in item["snippet"] and "<h1>" not in item["snippet"] for item in results))
            self.assertEqual(library.search("not-in-the-manual"), [])
            with self.assertRaises(ValueError):
                library.search("")
            with self.assertRaises(FileExistsError):
                ManualLibrary.index([root], root / "index.sqlite")
            scene, report = library_scene(library, "VDI", results)
            self.assertTrue(verify(scene).passed, verify(scene).text())
            self.assertTrue(verify_vdi(scene).passed)
            self.assertIn("3 documents indexed", report["summary"])
            second = root / "second.sqlite"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gem_main(["library", "index", "--root", str(root / "manual.pdf"), "--database", str(second)]), 0)
            with patch.dict(os.environ, {"GEM_LIBRARY": str(second)}):
                scene, _ = default_document("library")
                self.assertTrue(verify(scene).passed, verify(scene).text())
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(gem_main(["library", "search", "--database", str(second), "--query", "driver", "--limit", "3"]), 0)
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["results"])
            self.assertFalse(result["executed"])


try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_foreign("cairo")
    HAS_GTK = bool(os.environ.get("DISPLAY"))
except (ImportError, ValueError):
    HAS_GTK = False


@unittest.skipUnless(HAS_GTK, "native library tests require GTK, Cairo, and an X11 display")
class NativeManualLibraryCase(unittest.TestCase):
    def test_native_search_and_export_preserves_read_only_boundary(self):
        from gem.mirror_view import MirrorWindow as AtlasWindow

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manual.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" width="600" height="120"><text x="20" y="65" font-family="sans-serif" font-size="26">VDI driver and AES resource construction</text></svg>')
            subprocess.run(["/usr/bin/rsvg-convert", "-f", "pdf", "-o", str(root / "manual.pdf"), str(root / "manual.svg")], check=True)
            library_path = ManualLibrary.index([root / "manual.pdf"], root / "library.sqlite").path
            with patch.dict(os.environ, {"GEM_LIBRARY": str(library_path)}):
                window = AtlasWindow("library")
                try:
                    window.controls["library_query"].set_text("VDI")
                    window.search_library()
                    self.assertTrue(window.library_results)
                    self.assertTrue(window.report["library"]["read_only"])
                    self.assertEqual(window.field.observations, [])
                    output = window.export_current(root / "library.svg")
                    self.assertIn("MANUAL LIBRARY", output.read_text())
                finally:
                    window.destroy()


if __name__ == "__main__":
    unittest.main()
