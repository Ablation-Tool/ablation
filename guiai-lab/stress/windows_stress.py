#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tkinter as tk
import unittest

from guiai.environment import configure_environment
from guiai.events import Session
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


@unittest.skipUnless(os.name == "nt", "native Windows only")
class WindowsNativeCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guiai-windows-")
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
        self.fail(message)

    def test_cmd_wrapper_and_workspace(self):
        self.assertEqual(self.session.cli_path.suffix, ".cmd")
        self.session.set_workspace(self.root_path)
        result = subprocess.run(
            [str(self.session.cli_path), "state", "--session", str(self.session.root)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.session.target, result.stdout)
        self.assertEqual(self.session.workspace, self.root_path)

    def test_conpty_interactive_terminal(self):
        panel = self.make_panel([sys.executable, "-u", "-c", FIXTURE])
        self.wait_for(lambda: "READY" in panel.text.get("1.0", "end"), "ConPTY fixture did not start")
        panel.write(b"check\r")
        self.wait_for(lambda: "STATE_RC=0" in panel.text.get("1.0", "end"), "session wrapper failed through ConPTY")
        panel.write(b"exit\r")
        self.wait_for(lambda: "BYE" in panel.text.get("1.0", "end"), "ConPTY input did not reach the fixture")
        self.wait_for(lambda: panel.reaped, "ConPTY child was not reaped")
        panel.stop()
        self.assertFalse(panel.process.isalive())

    def test_conpty_forced_cleanup(self):
        panel = self.make_panel([
            sys.executable, "-u", "-c", "print('READY', flush=True); import time; time.sleep(60)",
        ])
        self.wait_for(lambda: "READY" in panel.text.get("1.0", "end"), "stubborn child did not start")
        panel.stop()
        self.assertTrue(panel.reaped)
        self.assertFalse(panel.process.isalive())


if __name__ == "__main__":
    unittest.main(verbosity=2)
