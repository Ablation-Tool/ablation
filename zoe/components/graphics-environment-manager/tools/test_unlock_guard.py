from __future__ import annotations

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from gem.authorization import explicit_command
from tools.unlock_guard import capture


class AuthorizationCase(unittest.TestCase):
    def test_only_explicit_owner_commands_are_accepted(self):
        with self.assertRaises(PermissionError):
            explicit_command(["/bin/true"])
        with self.assertRaises(PermissionError):
            explicit_command(["/bin/true"], approved=True, principal="someone-else")
        self.assertEqual(explicit_command(["/bin/true"], approved=True), ["/bin/true"])
        with self.assertRaises(ValueError):
            explicit_command([], approved=True)
        with patch("os.geteuid", return_value=0), self.assertRaises(PermissionError):
            explicit_command(["/bin/true"], approved=True)


class UnlockGuardCase(unittest.TestCase):
    def test_fake_camera_event_preserves_boundaries(self):
        calls = []

        def fake_runner(arguments, **options):
            calls.append((arguments, options))
            return SimpleNamespace(returncode=0, stdout=b"\xff\xd8" + b"image" * 300 + b"\xff\xd9", stderr=b"")

        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"PAM_AUTHTOK": "dummy-value-that-is-not-a-password"}):
                image, record = capture(directory, event="failed-unlock", service="gdm-password", user="cowboy", runner=fake_runner)
            self.assertTrue(Path(image).is_file())
            self.assertEqual(record["service"], "gdm-password")
            self.assertFalse(record["network"])
            self.assertFalse(record["face_recognition"])
            self.assertNotIn("PAM_AUTHTOK", calls[0][1]["env"])
            self.assertNotIn("dummy-value-that-is-not-a-password", (Path(directory) / "events.jsonl").read_text())
            with self.assertRaises(ValueError):
                capture(directory, event="other", service="gdm-password", user="cowboy", runner=fake_runner)


if __name__ == "__main__":
    unittest.main()
