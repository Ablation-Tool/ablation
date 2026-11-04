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

from gem.app import InvestigationApp
from gem.environment import configure_environment
from gem.events import Session
from gem.layout import LAYOUTS
from gem.macos_launcher import prepare_agent_path
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
            [os.environ["GEM_CLI"], "state", "--session", os.environ["GEM_SESSION"]],
            capture_output=True, text=True,
        )
        print("STATE_RC=" + str(result.returncode), flush=True)
    elif command == "exit":
        print("BYE", flush=True)
        break
    elif command:
        print("RECEIVED:" + command, flush=True)
'''


@unittest.skipUnless(sys.platform == "darwin", "native macOS only")
class MacOSNativeCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gem-macos-")
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
        if self.panels:
            panel = self.panels[-1]
            diagnostics = (
                f"pending={bytes(panel.write_queue)!r}, reaped={panel.reaped}, "
                f"exited={panel.exited}, reader_eof={panel.reader_eof}"
            )
        else:
            diagnostics = "no terminal panel"
        self.fail(f"{message}: {output!r}; {diagnostics}")

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
        fixture = FIXTURE.replace(
            "    command = line.strip()\n",
            "    command = line.strip()\n    print('INPUT=' + ascii(command), flush=True)\n",
        )
        panel = self.make_panel([sys.executable, "-u", "-c", fixture])
        self.wait_for(lambda: "READY" in panel.text.get("1.0", "end"), "PTY fixture did not start")
        panel.write(b"check\r")
        self.wait_for(lambda: "STATE_RC=0" in panel.text.get("1.0", "end"), "session wrapper failed through PTY")
        panel.write("café\r".encode("utf-8"))
        self.wait_for(lambda: "RECEIVED:café" in panel.text.get("1.0", "end"), "Unicode input was not preserved")
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

    def test_native_drop_target_inserts_path_without_enter(self):
        from unittest import mock
        from metrix.drop import dropped_payload

        panel = self.make_panel([sys.executable, "-u", "-c", FIXTURE])
        self.assertTrue(panel.drop_enabled, "native macOS tkdnd bridge did not initialize")
        panel.fd = 123456
        messages = []
        panel.status_callback = messages.append
        directory = self.root_path / "dropped folder with spaces"
        directory.mkdir()
        with mock.patch.object(panel, "write") as write:
            action = panel.on_drop(mock.Mock(data="{" + str(directory) + "}"))
        self.assertEqual(action, "copy")
        write.assert_called_once_with(dropped_payload([directory]))
        payload = write.call_args.args[0]
        self.assertTrue(payload.endswith(b" "))
        self.assertNotIn(b"\r", payload)
        self.assertNotIn(b"\n", payload)
        self.assertIn("review before running", messages[-1])

    def test_workspace_branding_layout_and_save(self):
        application = InvestigationApp(self.root, self.session)
        try:
            self.assertEqual(os.environ["GEM_WORKSPACE"], str(application.workspace))
            self.assertEqual(application.brand_header_image.width(), 32)
            self.assertTrue(application.brand_header_image.transparency_get(0, 0))
            application.toggle_settings()
            self.assertEqual(application.settings_bar.winfo_manager(), "pack")
            application.run_safety_check()
            self.assertEqual(application.safety_panel.winfo_manager(), "pack")
            self.assertIn("disabled", application.allow_safety_button.state())
            application.clear_safety()
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
        from gem import macos_launcher

        with mock.patch("gem.cli.main", return_value=0) as launch:
            self.assertEqual(macos_launcher.main([]), 0)
        launch.assert_called_once_with(["launch"])

    def test_launcher_path_has_no_empty_entries(self):
        with mock.patch.dict(os.environ, {"PATH": ""}):
            prepare_agent_path()
            self.assertNotIn("", os.environ["PATH"].split(os.pathsep))

    def test_application_bundle_and_relocation(self):
        bundle = Path(__file__).resolve().parent / "GEM.app"
        executable = bundle / "Contents" / "MacOS" / "GEM"
        with (bundle / "Contents" / "Info.plist").open("rb") as stream:
            metadata = plistlib.load(stream)
        self.assertEqual(metadata["CFBundleIdentifier"], "re.ablation.gem")
        self.assertEqual(metadata["CFBundleExecutable"], "GEM")
        self.assertTrue((bundle / "Contents" / "Resources" / "GEM.icns").is_file())
        result = subprocess.run(
            [str(executable), "--self-test"], capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "GEM_MACOS_APP_OK")
        moved = self.root_path / "moved with spaces" / "GEM.app"
        moved.parent.mkdir()
        shutil.copytree(bundle, moved)
        launcher = moved / "Contents" / "Resources" / ".venv" / "bin" / "gem"
        self.assertEqual(launcher.read_text().splitlines()[0], "#!/bin/sh")
        result = subprocess.run(
            [str(launcher), "--help"], capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(
            [str(moved / "Contents" / "MacOS" / "GEM"), "--self-test"],
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
