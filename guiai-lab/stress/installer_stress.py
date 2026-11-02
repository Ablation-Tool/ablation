#!/usr/bin/env python3
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
from zipfile import ZipFile


SOURCE = Path(__file__).resolve().parents[1] / "packaging" / "forall.py"
SPEC = importlib.util.spec_from_file_location("guiai_forall", SOURCE)
forall = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(forall)


class UniversalInstallerCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guiai-installer-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def package(self, name="GUIAI-Linux.zip", installer="install_linux.sh", content="offline package"):
        archive = self.root / name
        with ZipFile(archive, "w") as bundle:
            bundle.writestr(installer, content)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.root / "SHA256SUMS.txt").write_text(f"{digest}  {name}\n", encoding="utf-8")
        return archive

    def test_selects_native_packages(self):
        self.assertEqual(forall.platform_package("darwin")[0], "GUIAI-macOS.zip")
        self.assertEqual(forall.platform_package("win32", "AMD64")[0], "GUIAI-Windows-Native.zip")
        self.assertEqual(forall.platform_package("linux")[0], "GUIAI-Linux.zip")

    def test_rejects_unsupported_platforms(self):
        with self.assertRaises(RuntimeError):
            forall.platform_package("win32", "ARM64")
        with self.assertRaises(RuntimeError):
            forall.platform_package("sunos")

    def test_checksum_parser_rejects_malformed_and_duplicate_entries(self):
        for content in ("one-field\n", "invalid  package.zip\n", "0" * 64 + "  package.zip\n" + "1" * 64 + "  package.zip\n"):
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                forall.release_checksums(content)

    def test_checksum_verification_rejects_changed_package(self):
        archive = self.package()
        (self.root / "SHA256SUMS.txt").write_text("0" * 64 + "  GUIAI-Linux.zip\n", encoding="utf-8")
        checksums = forall.release_checksums((self.root / "SHA256SUMS.txt").read_text())
        with self.assertRaisesRegex(RuntimeError, "Checksum"):
            forall.verify_archive(archive, checksums)

    def test_archive_rejects_parent_paths_absolute_paths_and_symlinks(self):
        for name, attributes in (("../outside", 0), ("/absolute", 0), ("..\\outside", 0), ("linked", stat.S_IFLNK << 16)):
            archive = self.root / "unsafe.zip"
            with ZipFile(archive, "w") as bundle:
                bundle.writestr(name, "bad")
                bundle.getinfo(name).external_attr = attributes
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "Unsafe"):
                forall.extract_archive(archive, self.root / "extract")
        self.assertFalse((self.root / "outside").exists())

    def test_existing_installation_is_not_changed(self):
        destination = self.root / "existing"
        destination.mkdir()
        marker = destination / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        with mock.patch.object(forall, "download") as download:
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                forall.main(["--directory", str(destination)])
        download.assert_not_called()
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_complete_verified_offline_install(self):
        self.package()
        destination = self.root / "completed install"
        def install(source, installer, skip_tests):
            self.assertEqual(installer, "install_linux.sh")
            self.assertFalse(skip_tests)
            self.assertEqual((source / installer).read_text(), "offline package")
            executable = source / ".venv" / "bin" / "guiai"
            executable.parent.mkdir(parents=True)
            executable.write_text("installed", encoding="utf-8")
        with (
            mock.patch.object(forall, "install_package", side_effect=install),
            mock.patch.object(forall, "verify_installed_cli"),
        ):
            forall.main(["--directory", str(destination), "--gui-only", "--base-url", self.root.as_uri()])
        self.assertEqual((destination / ".venv" / "bin" / "guiai").read_text(), "installed")
        metadata = json.loads((destination / ".guiai-install.json").read_text())
        self.assertEqual(metadata["package"], "GUIAI-Linux.zip")
        self.assertEqual(metadata["sha256"], hashlib.sha256((self.root / "GUIAI-Linux.zip").read_bytes()).hexdigest())

    def test_full_install_includes_ablation_and_gui(self):
        self.package()
        wheel = self.root / "ablation_tool-2.93.1-py3-none-any.whl"
        wheel.write_bytes(b"standard Ablation wheel")
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        with (self.root / "SHA256SUMS.txt").open("a", encoding="utf-8") as stream:
            stream.write(f"{digest}  {wheel.name}\n")
        destination = self.root / "full install"
        with (
            mock.patch.object(forall, "install_ablation") as install_ablation,
            mock.patch.object(forall, "install_package") as install_package,
            mock.patch.object(forall, "verify_installed_cli") as verify,
        ):
            forall.main(["--directory", str(destination), "--base-url", self.root.as_uri()])
        self.assertEqual(install_ablation.call_args.args[1].name, wheel.name)
        install_package.assert_called_once()
        self.assertTrue(verify.call_args.args[1])
        metadata = json.loads((destination / ".guiai-install.json").read_text())
        self.assertEqual(metadata["ablation_package"], wheel.name)
        self.assertEqual(metadata["ablation_sha256"], digest)

    def test_ablation_wheel_is_required_by_default(self):
        self.package()
        destination = self.root / "missing ablation"
        with mock.patch.object(forall, "install_package") as install:
            with self.assertRaisesRegex(RuntimeError, "exactly one"):
                forall.main(["--directory", str(destination), "--base-url", self.root.as_uri()])
        install.assert_not_called()
        self.assertFalse(destination.exists())

    def test_failed_verification_does_not_run_installer(self):
        archive = self.package()
        (self.root / "SHA256SUMS.txt").write_text("0" * 64 + "  GUIAI-Linux.zip\n", encoding="utf-8")
        destination = self.root / "rejected"
        with mock.patch.object(forall, "install_package") as install:
            with self.assertRaisesRegex(RuntimeError, "Checksum"):
                forall.main(["--directory", str(destination), "--gui-only", "--base-url", self.root.as_uri()])
        install.assert_not_called()
        self.assertFalse(destination.exists())
        self.assertTrue(archive.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
