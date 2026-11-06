#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import queue
import tempfile
import time
import tkinter as tk
from tkinter import ttk
import unittest
from unittest import mock

from guiai.app import InvestigationApp
from guiai.events import Session
from guiai.layout import LAYOUTS
from metrix.desktop import TerminalPanel, TerminalScreen
import pyte


DEEP_NODES = int(os.environ.get("GUIAI_STRESS_DEEP", "1500"))
LARGE_NODES = int(os.environ.get("GUIAI_STRESS_LARGE", "5000"))


class NativeCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guiai-native-stress-")
        self.session = Session(Path(self.temporary.name), "/bin/true")
        self.artifact = f"artifact:{self.session.metadata['sha256']}"
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = InvestigationApp(self.root, self.session)

    def tearDown(self):
        try:
            self.app.close()
        except Exception:
            self.root.destroy()
        self.temporary.cleanup()

    def emit(self, node_id, parent, label=None, status="not_started"):
        return self.session.emit(node_id, parent, "function", label or node_id, status)

    def detail_lines(self):
        lines = self.app.details.count("1.0", "end", "displaylines")
        return lines[0] if isinstance(lines, tuple) else lines

    def test_empty_filter_has_guidance_and_reset(self):
        self.app.filter_variable.set("complete_scoped")
        self.app.render_tree()
        self.assertIn("No nodes match", self.app.empty_label.cget("text"))
        self.app.reset_filters()
        self.assertTrue(self.app.tree.exists(self.artifact))

    def test_details_are_collapsed_without_changing_selection(self):
        self.assertEqual(self.app.details_frame.winfo_manager(), "")
        self.assertEqual(self.app.details_label.winfo_manager(), "")
        self.assertEqual(self.app.details_button.cget("text"), "▸ Node details")
        self.root.deiconify()
        self.app.toggle_details()
        self.root.update()
        self.assertEqual(self.app.details_frame.winfo_manager(), "pack")
        self.assertEqual(self.app.details_label.winfo_manager(), "pack")
        self.assertEqual(self.app.details_button.cget("text"), "▾ Node details")
        self.assertEqual(self.app.details.cget("height"), self.detail_lines())
        self.assertEqual(self.app.details.yview(), (0.0, 1.0))
        self.assertFalse(any(isinstance(child, ttk.Scrollbar) for child in self.app.details_frame.children.values()))
        self.assertIn(self.artifact, self.app.details.get("1.0", "end"))
        self.assertEqual(self.session.current_state()["selected_id"], self.artifact)
        self.app.toggle_details()
        self.assertEqual(self.app.details_frame.winfo_manager(), "")
        self.assertEqual(self.app.details_label.winfo_manager(), "")
        self.assertEqual(len(self.session.events_path.read_text().splitlines()), 1)

    def test_long_details_fit_without_a_scrollbar(self):
        self.session.emit(
            "observation:long", self.artifact, "observation", "Long note", "blocked",
            "agent", "analysis/long.txt", "First line\n" + "wrapped evidence " * 60 + "\nFinal marker",
        )
        self.app.reload()
        self.app.tree.selection_set("observation:long")
        self.app.on_select()
        self.root.deiconify()
        self.app.toggle_details()
        self.root.update()
        lines = self.detail_lines()
        self.assertGreater(lines, 8)
        self.assertEqual(self.app.details.cget("height"), lines)
        self.assertEqual(self.app.details.yview(), (0.0, 1.0))
        self.assertTrue(self.app.details.get("1.0", "end").rstrip().endswith("Final marker"))
        self.assertFalse(any(isinstance(child, ttk.Scrollbar) for child in self.app.details_frame.children.values()))

    def test_show_in_files_uses_safe_nautilus_action(self):
        with mock.patch("guiai.app.shutil.which", return_value="/usr/bin/nautilus"), mock.patch("guiai.app.subprocess.Popen") as process:
            self.app.show_in_files()
        command = process.call_args.args[0]
        self.assertEqual(command[:2], ["nautilus", "--select"])
        self.assertEqual(command[2], self.session.target)
        self.assertFalse(process.call_args.kwargs.get("shell", False))
        self.assertTrue(process.call_args.kwargs["start_new_session"])

    def test_repeated_needs_work_is_idempotent(self):
        self.app.mark_selected("partial")
        self.app.mark_selected("partial")
        event = self.session.events_by_id()[self.artifact]
        self.assertEqual(event["note"].count("Human requested more work"), 1)
        self.assertEqual(len((self.session.events_path).read_text().splitlines()), 2)

    def test_expansion_is_preserved_at_every_depth(self):
        self.emit("node:a", self.artifact)
        self.emit("node:b", "node:a")
        self.emit("node:c", "node:b")
        self.app.reload()
        self.app.tree.item("node:a", open=True)
        self.app.tree.item("node:b", open=True)
        self.app.reload()
        self.assertTrue(self.app.tree.item("node:a", "open"))
        self.assertTrue(self.app.tree.item("node:b", "open"))

    def test_corrupt_event_log_shows_error_without_callback_failure(self):
        self.session.events_path.write_text('{"id":"broken"}\n', encoding="utf-8")
        self.app.reload()
        self.assertIn("error", self.app.counts_variable.get().casefold())
        self.app.reset_filters()
        self.app.after_refresh()

    def test_vanished_selection_does_not_break_actions(self):
        self.session.events_path.write_text("", encoding="utf-8")
        self.app.mark_selected("partial")
        self.assertIn("error", self.app.counts_variable.get().casefold())
        self.app.on_select()

    def test_corrupt_selection_shows_error_without_callback_failure(self):
        self.session.state_path.write_text("{bad json", encoding="utf-8")
        self.app.reload()
        self.assertIn("error", self.app.counts_variable.get().casefold())

    def test_deep_native_tree_does_not_recurse(self):
        parent = self.artifact
        specifications = []
        for index in range(DEEP_NODES):
            node_id = f"node:{index}"
            specifications.append({
                "id": node_id, "parent_id": parent, "type": "function",
                "label": node_id, "status": "not_started", "source": "agent",
                "evidence": "", "note": "", "scope": None,
            })
            parent = node_id
        self.session.emit_many(specifications)
        self.app.reload()
        self.assertTrue(self.app.tree.exists(f"node:{DEEP_NODES - 1}"))

    def test_large_native_sibling_set(self):
        self.session.emit_many([
            {
                "id": f"function:{index}", "parent_id": self.artifact,
                "type": "function", "label": f"fn {index}", "status": "not_started",
                "source": "agent", "evidence": "", "note": "", "scope": None,
            }
            for index in range(LARGE_NODES)
        ])
        started = time.monotonic()
        self.app.reload()
        self.assertLess(time.monotonic() - started, 15.0)
        self.assertEqual(len(self.app.tree.get_children(self.artifact)), LARGE_NODES)

    def test_unicode_tree_node(self):
        self.session.emit("function:café-雪", self.artifact, "function", "関数 🧪")
        self.app.reload()
        self.assertTrue(self.app.tree.exists("function:café-雪"))

    def test_visual_layouts_and_project_restoration(self):
        self.root.deiconify()
        self.assertEqual(self.app.brand_image.width(), 512)
        self.assertEqual(self.app.brand_header_image.width(), 32)
        self.assertTrue(self.app.brand_header_image.transparency_get(0, 0))
        self.app.show_preferences()
        self.assertEqual(set(self.app.layout_buttons), set(LAYOUTS))
        terminal = self.app.terminal
        tree = self.app.tree
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                self.assertTrue(self.app.select_layout(layout))
                self.assertEqual(self.app.layout, layout)
                expected_orientation = "horizontal" if layout in {"lab-left", "lab-right"} else "vertical"
                self.assertEqual(str(self.app.panes.cget("orient")), expected_orientation)
                expected_first = self.app.left if layout in {"lab-left", "lab-top"} else terminal
                self.assertEqual(self.app.panes.panes()[0], str(expected_first))
                self.assertIs(self.app.terminal, terminal)
                self.assertIs(self.app.tree, tree)
                self.assertIsInstance(self.app.layout_buttons[layout].winfo_children()[0], tk.Canvas)
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    self.root.update_idletasks()
                    self.root.tk.dooneevent(tk._tkinter.DONT_WAIT)
                    if self.app.layout_after_id is None and self.app.left.winfo_ismapped() and terminal.winfo_ismapped():
                        if self.app.left.winfo_width() > 0 and self.app.left.winfo_height() > 0 and terminal.winfo_width() > 0 and terminal.winfo_height() > 0:
                            break
                    time.sleep(0.01)
                geometry = (
                    f"{layout}: left={self.app.left.winfo_width()}x{self.app.left.winfo_height()} "
                    f"terminal={terminal.winfo_width()}x{terminal.winfo_height()} "
                    f"mapped={self.app.left.winfo_ismapped()}/{terminal.winfo_ismapped()} "
                    f"sash={self.app.panes.sashpos(0)}"
                )
                self.assertTrue(self.app.left.winfo_ismapped(), geometry)
                self.assertTrue(terminal.winfo_ismapped(), geometry)
                self.assertGreater(self.app.left.winfo_width(), 0, geometry)
                self.assertGreater(self.app.left.winfo_height(), 0, geometry)
                self.assertGreater(terminal.winfo_width(), 0, geometry)
                self.assertGreater(terminal.winfo_height(), 0, geometry)
        manifest = self.app.save_project()
        self.assertEqual(manifest["active_lab"], 1)
        self.assertEqual(manifest["labs"][0]["selected_id"], self.artifact)
        self.assertEqual(self.app.session.project_active_lab(), 1)
        self.app.close_preferences()
        root = tk.Tk()
        root.withdraw()
        restored = InvestigationApp(root, Session(self.session.root, self.session.target))
        self.addCleanup(restored.close)
        self.assertEqual(restored.layout, "lab-bottom")
        self.assertEqual(str(restored.panes.cget("orient")), "vertical")
        self.assertEqual(restored.panes.panes()[0], str(restored.terminal))
        self.assertIsNone(restored.layout_error)

    def test_private_device_status_sequence(self):
        screen = TerminalScreen(80, 24)
        pyte.ByteStream(screen).feed(b"\x1b[?6n")


class TerminalLifecycleCase(unittest.TestCase):
    def make_panel(self, command=None):
        root = tk.Tk()
        root.withdraw()
        self.addCleanup(self.destroy_root, root)
        temporary = tempfile.TemporaryDirectory(prefix="guiai-lifecycle-")
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name)
        panel = TerminalPanel(root, output, output, command, lambda message: None)
        self.addCleanup(panel.stop)
        return panel

    @staticmethod
    def destroy_root(root):
        try:
            root.destroy()
        except tk.TclError:
            pass

    def stubborn_panel(self):
        command = [
            os.environ.get("PYTHON", os.sys.executable), "-c",
            "import signal,time; signal.signal(signal.SIGHUP,signal.SIG_IGN); print('READY',flush=True); time.sleep(60)",
        ]
        panel = self.make_panel(command)
        deadline = time.monotonic() + 8
        while "READY" not in panel.text.get("1.0", "end") and time.monotonic() < deadline:
            panel.update()
            time.sleep(0.02)
        self.assertIn("READY", panel.text.get("1.0", "end"))
        return panel

    def assert_child_reaped(self, panel):
        self.assertTrue(panel.reaped)
        with self.assertRaises(ProcessLookupError):
            os.kill(panel.process, 0)

    def test_stubborn_child_is_killed_on_close(self):
        panel = self.stubborn_panel()
        started = time.monotonic()
        panel.stop()
        self.assertLess(time.monotonic() - started, 3.0)
        self.assert_child_reaped(panel)
        panel.stop()

    def test_io_error_does_not_leave_live_child_or_block_close(self):
        panel = self.stubborn_panel()
        panel.finish("Injected I/O failure")
        self.assertTrue(panel.exited)
        self.assertFalse(panel.reaped)
        original_waitpid = os.waitpid
        def nonblocking_wait(pid, options):
            self.assertEqual(options, os.WNOHANG)
            return original_waitpid(pid, options)
        started = time.monotonic()
        with mock.patch("metrix.desktop.os.waitpid", side_effect=nonblocking_wait):
            panel.stop()
        self.assertLess(time.monotonic() - started, 3.0)
        self.assert_child_reaped(panel)

    def test_stop_before_delayed_start_does_not_spawn(self):
        panel = self.make_panel([os.sys.executable, "-c", "import time; time.sleep(60)"])
        panel.stop()
        panel.update()
        self.assertIsNone(panel.process)

    def test_windows_exit_waits_for_queued_output_and_reader_eof(self):
        panel = self.make_panel()
        with mock.patch("metrix.desktop.os.name", "nt"):
            panel.process = mock.Mock()
            panel.process.isalive.return_value = False
            panel.fd = True
            panel.read_queue = queue.Queue()
            panel.poll()
            self.assertTrue(panel.reaped)
            self.assertFalse(panel.exited)
            panel.read_queue.put(b"BYE\r\n")
            panel.read_queue.put(None)
            panel.poll()
            self.assertTrue(panel.reader_eof)
            self.assertTrue(panel.exited)
            self.assertIn("BYE", panel.screen.display[0])

    def test_partial_and_blocked_writes_preserve_order(self):
        panel = self.make_panel()
        panel.after_cancel(panel.poll_after_id)
        panel.fd = 123
        attempts = []
        def partial_write(_fd, data):
            attempts.append(bytes(data))
            if len(attempts) in {1, 3, 5}:
                raise BlockingIOError()
            return 2 if len(attempts) == 2 else 1
        with mock.patch("metrix.desktop.os.write", side_effect=partial_write):
            panel.write(b"abcd")
            self.assertEqual(panel.write_queue, b"abcd")
            panel.flush_writes()
            self.assertEqual(panel.write_queue, b"cd", attempts)
            panel.flush_writes()
            self.assertEqual(panel.write_queue, b"d")
        self.assertEqual(attempts, [b"abcd", b"abcd", b"cd", b"cd", b"d"])
        panel.stop()
        self.assertEqual(panel.write_queue, b"")

    def test_oversized_paste_is_rejected_without_writing(self):
        panel = self.make_panel()
        messages = []
        panel.status_callback = messages.append
        panel.clipboard_get = mock.Mock(return_value="x" * (8 * 1024 * 1024 + 1))
        panel.paste()
        self.assertEqual(panel.write_queue, b"")
        self.assertIn("8 MiB", messages[-1])

    def test_application_close_is_idempotent(self):
        root = tk.Tk()
        root.withdraw()
        self.addCleanup(self.destroy_root, root)
        with tempfile.TemporaryDirectory(prefix="guiai-close-stress-") as directory:
            session = Session(Path(directory), "/bin/true")
            app = InvestigationApp(root, session)
            app.close()
            app.close()


def main():
    parser = argparse.ArgumentParser(description="Run GUIAI native stress tests")
    parser.add_argument("--failfast", action="store_true")
    args = parser.parse_args()
    suite = unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(NativeCase),
        unittest.defaultTestLoader.loadTestsFromTestCase(TerminalLifecycleCase),
    ])
    result = unittest.TextTestRunner(verbosity=2, failfast=args.failfast).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
