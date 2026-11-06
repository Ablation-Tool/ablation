#!/usr/bin/env python3
import os
from pathlib import Path
import tempfile
import time
import tkinter as tk
import unittest
from types import SimpleNamespace

from gem.app import InvestigationApp
from gem.events import Session


FIXTURE = r'''
import json
import os
import shlex
import shutil
import subprocess
import sys

print("FIXTURE READY", flush=True)
for line in sys.stdin:
    command = line.strip()
    if command == "check":
        print("GEM_COMMAND=" + str(shutil.which("gem")), flush=True)
        result = subprocess.run(
            shlex.split(os.environ["GEM_CLI"]) + ["state", "--session", os.environ["GEM_SESSION"]],
            capture_output=True, text=True,
        )
        print("STATE_RC=" + str(result.returncode), flush=True)
        print("TARGET=" + os.environ.get("GEM_TARGET", ""), flush=True)
        print("TARGET_KIND=" + os.environ.get("GEM_TARGET_KIND", ""), flush=True)
        print("WORKSPACE=" + os.environ.get("GEM_WORKSPACE", ""), flush=True)
        print("SESSION=" + os.environ.get("GEM_SESSION", ""), flush=True)
        print("ABLATION_BINARY=" + os.environ.get("ABLATION_BINARY", "<unset>"), flush=True)
    elif command == "begin":
        cli = shlex.split(os.environ["GEM_CLI"])
        state_result = subprocess.run(
            cli + ["state", "--session", os.environ["GEM_SESSION"]],
            capture_output=True, text=True,
        )
        selected = json.loads(state_result.stdout)["selected"]
        arguments = cli + [
            "emit", "--session", os.environ["GEM_SESSION"],
            "--id", selected["id"], "--type", selected["type"],
            "--label", selected["label"], "--status", "in_progress",
            "--evidence", selected.get("evidence") or "", "--note", selected.get("note") or "",
        ]
        if selected.get("parent_id"):
            arguments += ["--parent", selected["parent_id"]]
        result = subprocess.run(arguments, capture_output=True, text=True)
        print("BEGIN_RC=" + str(result.returncode), flush=True)
        print("BEGIN_ID=" + selected["id"], flush=True)
    elif command == "exit":
        print("BYE", flush=True)
        break
    elif command:
        print("RECEIVED:" + command, flush=True)
'''


class TkInput:
    KEY_NAMES = {
        "-": "minus", "_": "underscore", ".": "period", ",": "comma",
        "/": "slash", "\\": "backslash", " ": "space", "'": "apostrophe",
        '"': "quotedbl", ";": "semicolon", ":": "colon", "=": "equal",
        "+": "plus", "$": "dollar", "[": "bracketleft", "]": "bracketright",
        "(": "parenleft", ")": "parenright", "<": "less", ">": "greater",
        "?": "question", "!": "exclam", "@": "at", "#": "numbersign",
        "%": "percent", "^": "asciicircum", "&": "ampersand", "*": "asterisk",
        "~": "asciitilde", "`": "quoteleft", "{": "braceleft", "}": "braceright",
        "|": "bar",
    }

    def __init__(self, root):
        self.root = root
        self.window = None

    def close(self):
        self.window = None

    def key(self, name, control=False, shift=False):
        if self.window is None:
            raise RuntimeError("no target widget has been selected")
        keysym = self.KEY_NAMES.get(name, name)
        if shift and len(keysym) == 1 and keysym.isalpha():
            keysym = keysym.upper()
        state = (4 if control else 0) | (1 if shift else 0)
        sequence = "<KeyPress>"
        if control or shift:
            sequence = "<" + ("Control-" if control else "") + ("Shift-" if shift else "") + keysym + ">"
        self.window.event_generate(sequence, keysym=keysym, state=state)
        self.window.event_generate("<KeyRelease>", keysym=keysym, state=state)

    def type(self, text):
        for character in text:
            self.key(character, shift=character.isupper() or character in '~!@#$%^&*()_+{}|:"<>?')

    def click(self, widget, x, y, root_x, root_y):
        self.window = widget
        widget.event_generate("<ButtonPress-1>", x=x, y=y, rootx=root_x, rooty=root_y)
        widget.event_generate("<ButtonRelease-1>", x=x, y=y, rootx=root_x, rooty=root_y)


class DesktopInputCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gem-input-stress-")
        self.target = Path(self.temporary.name) / "corpus"
        self.target.mkdir()
        (self.target / "firmware.bin").write_bytes(b"firmware")
        (self.target / "nested").mkdir()
        self.session = Session(Path(self.temporary.name) / "session", self.target)
        self.root = tk.Tk()
        self.root.geometry("1200x760+20+20")
        self.callback_errors = []
        self.root.report_callback_exception = self.record_callback_exception
        self.addCleanup(self.assert_no_callback_errors)
        self.saved_clipboard = None
        try:
            self.saved_clipboard = self.root.clipboard_get()
        except tk.TclError:
            pass
        self.app = InvestigationApp(
            self.root, self.session,
            [os.sys.executable, "-u", "-c", FIXTURE],
        )
        self.input = TkInput(self.root)
        self.clicks = []
        self.all_clicks = []
        self.app.terminal.text.bind("<Button-1>", lambda event: self.clicks.append((event.x, event.y)), add="+")
        self.root.bind_all("<Button-1>", lambda event: self.all_clicks.append(str(event.widget)), add="+")
        self.root.attributes("-topmost", True)
        self.root.lift()
        self.root.focus_force()
        self.pump(0.3)

    def tearDown(self):
        if hasattr(self, "app"):
            self.app.close()
        self.restore_clipboard()
        if hasattr(self, "root"):
            try:
                self.root.destroy()
            except tk.TclError:
                pass
        if hasattr(self, "input"):
            self.input.close()
        self.temporary.cleanup()

    def record_callback_exception(self, exception_type, exception, _traceback):
        self.callback_errors.append(f"{exception_type.__name__}: {exception}")

    def assert_no_callback_errors(self):
        self.assertEqual(self.callback_errors, [])

    def restore_clipboard(self):
        if not hasattr(self, "root"):
            return
        try:
            self.root.clipboard_clear()
            if self.saved_clipboard is not None:
                self.root.clipboard_append(self.saved_clipboard)
            self.root.update()
        except tk.TclError:
            pass

    def pump(self, seconds=0.15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        self.root.update()

    def wait_for(self, predicate, message):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self.pump(0.05)
            if predicate():
                return
        self.fail(f"{message}: {self.terminal_text()!r}")

    def terminal_text(self):
        return self.app.terminal.text.get("1.0", "end")

    def assert_terminal_focus(self):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self.root.focus_get() is self.app.terminal.text:
                return
            self.pump(0.02)
        actual = self.root.focus_get()
        coordinates = self.root.winfo_pointerxy()
        pointer = self.root.winfo_containing(*coordinates)
        terminal = self.app.terminal.text
        self.fail(
            f"terminal focus failed: actual={actual}, pointer_widget={pointer}, "
            f"pointer={coordinates}, root={self.root.winfo_geometry()}, "
            f"terminal={terminal} at {terminal.winfo_rootx()},{terminal.winfo_rooty()} "
            f"size={terminal.winfo_width()}x{terminal.winfo_height()}, "
            f"master={terminal.master}, mapped={terminal.winfo_ismapped()}, "
            f"terminal_clicks={self.clicks}, all_clicks={self.all_clicks}"
        )

    def type(self, text):
        for character in text:
            self.input.key(character, shift=character.isupper() or character in '~!@#$%^&*()_+{}|:"<>?')
            self.pump(0.01)

    def send(self, text):
        self.assert_terminal_focus()
        self.type(text)
        self.input.key("Return")
        self.pump()

    def test_real_desktop_input_and_agent_bridge(self):
        self.wait_for(lambda: "FIXTURE READY" in self.terminal_text(), "fixture did not start")
        self.app.tree.focus_set()
        self.pump()
        terminal = self.app.terminal.text
        self.input.click(
            terminal,
            terminal.winfo_width() // 2, terminal.winfo_height() // 2,
            terminal.winfo_rootx() + terminal.winfo_width() // 2,
            terminal.winfo_rooty() + terminal.winfo_height() // 2,
        )
        self.assertTrue(self.clicks)
        terminal.focus_force()
        self.pump()
        self.assert_terminal_focus()

        self.send("echo-test")
        self.wait_for(lambda: "RECEIVED:echo-test" in self.terminal_text(), "ordinary keyboard input failed")
        self.send("Case-Test_42")
        self.wait_for(lambda: "RECEIVED:Case-Test_42" in self.terminal_text(), "shifted keyboard input failed")
        self.type("caf")
        self.pump()
        self.app.terminal.on_key(SimpleNamespace(keysym="eacute", char="é", state=0))
        self.input.key("Return")
        self.wait_for(lambda: "RECEIVED:café" in self.terminal_text(), "Unicode PTY input failed")
        self.assert_terminal_focus()
        self.type("abx")
        self.input.key("BackSpace")
        self.type("c")
        self.input.key("Return")
        self.wait_for(lambda: "RECEIVED:abc" in self.terminal_text(), "BackSpace failed")

        self.type("discard")
        self.input.key("u", control=True)
        self.type("sync")
        self.input.key("Return")
        self.wait_for(lambda: "RECEIVED:sync" in self.terminal_text(), "Ctrl+U did not complete before the next command")
        self.type("accepted")
        self.input.key("Return")
        self.wait_for(lambda: "RECEIVED:accepted" in self.terminal_text(), "Ctrl+U or subsequent input failed")
        self.assertNotIn("RECEIVED:discard", self.terminal_text())

        self.root.clipboard_clear()
        self.root.clipboard_append("clip-check")
        self.pump()
        self.input.key("v", control=True, shift=True)
        self.input.key("Return")
        self.wait_for(lambda: "RECEIVED:clip-check" in self.terminal_text(), "clipboard paste failed")

        fixture_index = terminal.search("FIXTURE READY", "1.0")
        self.assertTrue(fixture_index)
        terminal.tag_add("sel", fixture_index, fixture_index + "+5c")
        self.input.key("c", control=True, shift=True)
        self.pump()
        self.assertEqual(self.root.clipboard_get(), "FIXTU")
        terminal.tag_remove("sel", "1.0", "end")

        self.send("check")
        self.wait_for(lambda: "ABLATION_BINARY=" in self.terminal_text(), "agent bridge checks did not finish")
        output = self.terminal_text()
        unwrapped_output = "".join(line.rstrip() for line in output.splitlines())
        self.assertIn("GEM_COMMAND=" + str(self.session.cli_path), unwrapped_output)
        self.assertIn("STATE_RC=0", unwrapped_output)
        self.assertIn("TARGET=" + str(self.target), unwrapped_output)
        self.assertIn("TARGET_KIND=directory", unwrapped_output)
        self.assertIn("WORKSPACE=" + str(self.app.workspace), unwrapped_output)
        self.assertIn("SESSION=" + str(self.session.root), unwrapped_output)
        self.assertIn("ABLATION_BINARY=<unset>", unwrapped_output)
        self.assertEqual(self.app.details_frame.winfo_manager(), "")
        self.app.details_button.invoke()
        self.pump()
        self.assertTrue(self.app.details_frame.winfo_ismapped())
        self.app.details_button.invoke()
        self.pump()
        self.assertEqual(self.app.details_frame.winfo_manager(), "")

        package = next(event for event in self.session.events() if event["label"] == "firmware.bin")
        self.app.tree.selection_set(package["id"])
        self.app.on_select()
        self.assertEqual(self.session.current_state()["selected_id"], package["id"])
        self.assertIn("Evidence / path:", self.app.details.get("1.0", "end"))
        self.assertIn(str(self.target / "firmware.bin"), self.app.details.get("1.0", "end"))
        self.assertEqual(tuple(self.app.tree.item(package["id"], "values")), ("artifact", "not_started"))
        self.send("begin")
        self.wait_for(
            lambda: "BEGIN_ID=" + package["id"] in self.terminal_text()
            and tuple(self.app.tree.item(package["id"], "values")) == ("artifact", "in_progress"),
            "agent did not read the human selection and update the visible Lab",
        )
        self.assertIn("BEGIN_RC=0", self.terminal_text())
        self.app.copy_follow_up()
        self.assertIn(package["id"], self.root.clipboard_get())
        self.assertIn(str(self.target / "firmware.bin"), self.root.clipboard_get())

        (self.target / "new-package.bin").write_bytes(b"new")
        self.app.rescan_directory()
        self.assertIn("new-package.bin", {event["label"] for event in self.app.events})
        self.app.focus_agent()
        self.assert_terminal_focus()
        self.send("exit")
        self.wait_for(lambda: "BYE" in self.terminal_text(), "fixture did not exit")
        self.restore_clipboard()
        process = self.app.terminal.process
        self.app.close()
        with self.assertRaises(ProcessLookupError):
            os.kill(process, 0)


if __name__ == "__main__":
    if not os.environ.get("DISPLAY"):
        raise SystemExit("desktop input stress testing requires an X11 DISPLAY")
    unittest.main(verbosity=2)
