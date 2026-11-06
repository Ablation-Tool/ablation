#!/usr/bin/env python3
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
import tkinter as tk
import unittest
from unittest import mock

from guiai.app import InvestigationApp
from guiai.environment import configure_environment
from guiai.events import Session
from guiai.layout import LAYOUTS
from guiai.macos_launcher import LauncherDialog, prepare_agent_path
from metrix.desktop import TerminalPanel


FIXTURE = r'''
import os
import subprocess
import sys

print("READY", flush=True)
for line in sys.stdin:
    command = line.strip()
    if command == "check":
        result = subprocess.run(
            [os.environ["GUIAI_CLI"], "state", "--session", os.environ["GUIAI_SESSION"]],
            capture_output=True, text=True,
        )
        print("STATE_RC=" + str(result.returncode), flush=True)
    elif command == "exit":
        print("BYE", flush=True)
        break
'''


@unittest.skipUnless(sys.platform == "darwin", "native macOS only")
class MacOSNativeCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guiai-macos-")
        self.root_path = Path(self.temporary.name)
        self.session = Session(self.root_path / "session with spaces", sys.executable)
        configure_environment(self.session)
        self.root = tk.Tk()
        self.root.withdraw()
        self.panels = []

    def tearDown(self):
        for panel in self.panels:
            panel.stop()
        try:
            self.root.destroy()
        except tk.TclError:
            pass
        self.temporary.cleanup()

    def make_panel(self, command):
        panel = TerminalPanel(
            self.root, self.root_path, self.root_path, command,
            lambda message: print(f"MACOS_STATUS {message}", flush=True),
        )
        self.panels.append(panel)
        return panel

    def wait_for(self, predicate, message, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            self.root.update_idletasks()
            self.root.tk.dooneevent(tk._tkinter.DONT_WAIT)
            time.sleep(0.02)
        output = self.panels[-1].text.get("1.0", "end") if self.panels else ""
        self.fail(f"{message}: {output!r}")

    def assert_reaped(self, panel):
        self.assertTrue(panel.reaped)
        with self.assertRaises(ProcessLookupError):
            os.kill(panel.process, 0)

    def test_shell_wrapper_and_workspace(self):
        self.assertFalse(self.session.cli_path.suffix)
        self.session.set_workspace(self.root_path)
        result = subprocess.run(
            [str(self.session.cli_path), "state", "--session", str(self.session.root)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["target"], self.session.target)
        self.assertEqual(self.session.workspace, self.root_path.resolve())

    def test_posix_interactive_terminal(self):
        panel = self.make_panel([sys.executable, "-u", "-c", FIXTURE])
        self.wait_for(lambda: "READY" in panel.text.get("1.0", "end"), "PTY fixture did not start")
        panel.write(b"check\r")
        self.wait_for(lambda: "STATE_RC=0" in panel.text.get("1.0", "end"), "session wrapper failed through PTY")
        panel.write(b"exit\r")
        self.wait_for(lambda: "BYE" in panel.text.get("1.0", "end"), "PTY input did not reach the fixture")
        self.wait_for(lambda: panel.reaped, "PTY child was not reaped")
        panel.stop()
        self.assert_reaped(panel)

    def test_posix_forced_cleanup(self):
        panel = self.make_panel([
            sys.executable, "-u", "-c", "print('READY', flush=True); import time; time.sleep(60)",
        ])
        self.wait_for(lambda: "READY" in panel.text.get("1.0", "end"), "stubborn child did not start")
        panel.stop()
        self.assert_reaped(panel)

    def test_workspace_branding_layout_and_save(self):
        application = InvestigationApp(self.root, self.session)
        try:
            self.assertEqual(application.brand_header_image.width(), 32)
            self.assertTrue(application.brand_header_image.transparency_get(0, 0))
            application.show_preferences()
            for layout in LAYOUTS:
                self.assertTrue(application.select_layout(layout))
                expected = "horizontal" if layout in {"lab-left", "lab-right"} else "vertical"
                self.assertEqual(str(application.panes.cget("orient")), expected)
            manifest = application.save_project()
            self.assertEqual(manifest["active_lab"], 1)
            application.close_preferences()
        finally:
            application.close()

    def test_first_run_launcher(self):
        launched = []
        dialog = LauncherDialog(self.root, launched.append)
        self.root.deiconify()
        self.root.update_idletasks()
        self.assertTrue(self.root.winfo_ismapped())
        dialog.target.set(sys.executable)
        dialog.session.set(str(self.session.root))
        dialog.agent.set("")
        self.assertNotIn("--agent", dialog.arguments())
        dialog.agent.set(sys.executable)
        expected = dialog.arguments()
        self.assertEqual(expected[:2], ["desktop", str(Path(sys.executable).resolve())])
        self.assertEqual(expected[-2:], ["--agent", sys.executable])
        dialog.agent.set("guiai-agent-that-does-not-exist")
        with self.assertRaises(ValueError):
            dialog.arguments()
        dialog.agent.set(sys.executable)
        dialog.launch()
        self.assertEqual(launched, [expected])

    def test_launcher_path_has_no_empty_entries(self):
        with mock.patch.dict(os.environ, {"PATH": ""}):
            prepare_agent_path()
            self.assertNotIn("", os.environ["PATH"].split(os.pathsep))

    def test_application_bundle_and_relocation(self):
        bundle = Path(__file__).resolve().parent / "Ablation.app"
        executable = bundle / "Contents" / "MacOS" / "Ablation"
        with (bundle / "Contents" / "Info.plist").open("rb") as stream:
            metadata = plistlib.load(stream)
        self.assertEqual(metadata["CFBundleIdentifier"], "re.ablation.guiai")
        self.assertEqual(metadata["CFBundleExecutable"], "Ablation")
        self.assertTrue((bundle / "Contents" / "Resources" / "Ablation.icns").is_file())
        result = subprocess.run(
            [str(executable), "--self-test"], capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "GUIAI_MACOS_APP_OK")
        moved = self.root_path / "moved with spaces" / "Ablation.app"
        moved.parent.mkdir()
        shutil.copytree(bundle, moved)
        launcher = moved / "Contents" / "Resources" / ".venv" / "bin" / "guiai"
        self.assertEqual(launcher.read_text().splitlines()[0], "#!/bin/sh")
        result = subprocess.run(
            [str(launcher), "--help"], capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(
            [str(moved / "Contents" / "MacOS" / "Ablation"), "--self-test"],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        opened = subprocess.run(
            ["open", "-n", str(bundle), "--args", "--self-test"],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(opened.returncode, 0, opened.stderr)


if __name__ == "__main__":
    import faulthandler
    faulthandler.dump_traceback_later(20, repeat=True)
    unittest.main(verbosity=2)
