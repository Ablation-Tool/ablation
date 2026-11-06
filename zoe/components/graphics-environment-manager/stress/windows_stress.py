#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tkinter as tk
import unittest

from gem.agent import AgentError, invoke_agent
from gem.app import InvestigationApp
from gem.environment import configure_environment
from gem.events import Session
from gem.layout import LAYOUTS
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


@unittest.skipUnless(os.name == "nt", "native Windows only")
class WindowsNativeCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gem-windows-")
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
        messages = []
        panel = TerminalPanel(self.root, self.root_path, self.root_path, command, messages.append)
        self.panels.append(panel)
        return panel

    def wait_for(self, predicate, message, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            self.root.update()
            time.sleep(0.02)
        output = self.panels[-1].text.get("1.0", "end") if self.panels else ""
        self.fail(f"{message}: {output!r}")

    def test_cmd_wrapper_and_workspace(self):
        self.assertEqual(self.session.cli_path.suffix, ".cmd")
        self.session.set_workspace(self.root_path)
        result = subprocess.run(
            [str(self.session.cli_path), "state", "--session", str(self.session.root)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["target"], self.session.target)
        self.assertEqual(self.session.workspace, self.root_path.resolve())

    def test_conpty_interactive_terminal(self):
        panel = self.make_panel([sys.executable, "-u", "-c", FIXTURE])
        self.wait_for(lambda: "READY" in panel.text.get("1.0", "end"), "ConPTY fixture did not start")
        panel.write(b"check\r")
        self.wait_for(lambda: "STATE_RC=0" in panel.text.get("1.0", "end"), "session wrapper failed through ConPTY")
        panel.write("café\r".encode("utf-8"))
        self.wait_for(lambda: "RECEIVED:café" in panel.text.get("1.0", "end"), "Unicode input was not preserved")
        panel.write(b"exit\r")
        self.wait_for(lambda: "BYE" in panel.text.get("1.0", "end"), "ConPTY input did not reach the fixture")
        self.wait_for(lambda: panel.reaped, "ConPTY child was not reaped")
        panel.stop()
        self.assertFalse(panel.process.isalive())

    def test_agent_timeout_kills_process_tree(self):
        marker = self.root_path / "agent-child.pid"
        fixture = (
            "import pathlib,subprocess,sys,time;"
            "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
            "pathlib.Path(sys.argv[1]).write_text(str(child.pid));"
            "print(child.pid,flush=True);time.sleep(60)"
        )
        with self.assertRaisesRegex(AgentError, "timed out"):
            invoke_agent([sys.executable, "-c", fixture, str(marker)], "prompt", timeout=2)
        child_id = int(marker.read_text())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {child_id}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            if f',"{child_id}",' not in result.stdout:
                break
            time.sleep(0.05)
        self.assertNotIn(f',"{child_id}",', result.stdout)

    def test_conpty_forced_cleanup(self):
        panel = self.make_panel([
            sys.executable, "-u", "-c", "print('READY', flush=True); import time; time.sleep(60)",
        ])
        self.wait_for(lambda: "READY" in panel.text.get("1.0", "end"), "stubborn child did not start")
        panel.stop()
        self.assertTrue(panel.reaped)
        self.assertFalse(panel.process.isalive())

    def test_native_drop_target_inserts_path_without_enter(self):
        from unittest import mock
        from metrix.drop import dropped_payload

        panel = self.make_panel([sys.executable, "-u", "-c", FIXTURE])
        self.assertTrue(panel.drop_enabled, "native Windows tkdnd bridge did not initialize")
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
        bitmap_calls = []
        original_iconbitmap = self.root.iconbitmap
        def record_iconbitmap(*args, **kwargs):
            bitmap_calls.extend(args)
            return original_iconbitmap(*args, **kwargs)
        self.root.iconbitmap = record_iconbitmap
        application = InvestigationApp(self.root, self.session)
        try:
            self.assertEqual(os.environ["GEM_WORKSPACE"], str(application.workspace))
            self.assertEqual(application.brand_header_image.width(), 32)
            self.assertTrue(application.brand_header_image.transparency_get(0, 0))
            self.assertTrue(any(str(path).endswith("gem2red.ico") for path in bitmap_calls), bitmap_calls)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
