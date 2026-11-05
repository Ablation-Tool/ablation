#!/usr/bin/env python3
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from guiai.gtk_app import (
    AblationWindow, GuiAIGtkApplication, InvestigationWorkspace, PreferencesDialog,
    ORIGINAL_COLOR_ICONS, STATUS_LABELS, TYPE_LABELS,
    action_button, choose_workspace, configure_native_fonts, themed_pixbuf, wait_for_agents,
)
from guiai.environment import configure_environment
from guiai.events import Session
from guiai.gem.runner import replay
from guiai.chart_colors import baobab_hex, readable_text_color
from guiai.map_view import InvestigationMap, PAGE_SIZE, descendant_counts, treemap_layout
from guiai.rings_view import (
    InvestigationRings, MAX_DEPTH, MIN_ANGLE, TAU, ring_layout, sector_at, sector_color,
)
from guiai.preferences import SCHEMES, WorkbenchPreferences, parse_color
from gi.repository import Gdk, Gio, GLib, Gtk, Pango, Vte

from desktop_input_stress import FIXTURE


TEST_ID = itertools.count(1)
GTK_FIXTURE = FIXTURE.replace(
    '    elif command == "exit":',
    '''    elif command == "emit":
        result = subprocess.run(shlex.split(os.environ["GUIAI_CLI"]) + [
            "emit", "--session", os.environ["GUIAI_SESSION"],
            "--id", "observation:gtk-test", "--parent", os.environ["GUIAI_ROOT_ID"],
            "--type", "observation", "--label", "GTK discovery",
            "--status", "partial", "--evidence", "analysis/gtk-test.txt",
            "--note", "VTE integration evidence",
        ], capture_output=True, text=True)
        print("EMIT_RC=" + str(result.returncode), flush=True)
    elif command == "exit":''',
)


class GtkCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guiai-gtk-stress-")
        self.corpus = Path(self.temporary.name) / "corpus"
        self.corpus.mkdir()
        (self.corpus / "firmware.bin").write_bytes(b"firmware")
        (self.corpus / "nested").mkdir()
        self.app = None
        self.window = None
        self.host = None
        self.app_index = 0
        self.context = GLib.MainContext.default()
        self.addCleanup(self.cleanup)
        self.make_app()

    def cleanup(self):
        self.close_current()
        self.temporary.cleanup()

    def close_current(self):
        if self.app is None:
            return
        if self.window is not None:
            self.window.close()
        self.app.quit()
        if self.host is not None:
            self.host.destroy()
        self.pump(0.05)
        self.window = None
        self.host = None
        self.app = None

    def make_app(self, target=None, command=None):
        if self.app is None:
            self.app_index += 1
            session = Session(Path(self.temporary.name) / f"session-{self.app_index}", target or "/bin/true")
            self.app = GuiAIGtkApplication(session, command, session.root, f"re.guiai.test.p{os.getpid()}.n{next(TEST_ID)}", export_actions=False)
            preferences = WorkbenchPreferences(session.root, configure_native_fonts().to_string())
            self.window = InvestigationWorkspace(session, command, session.root, preferences)
            self.host = Gtk.Window()
            self.host.set_default_size(1500, 900)
            self.host.add(self.window)
            self.host.show_all()
            self.window.details_toggle.set_active(False)
        else:
            self.app_index += 1
            self.window.session = Session(Path(self.temporary.name) / f"session-{self.app_index}", target or "/bin/true")
            self.window.preferences = WorkbenchPreferences(self.window.session.root, configure_native_fonts().to_string())
            self.window.apply_preferences()
            configure_environment(self.window.session)
            self.window.expanded_ids.add(self.window.session.root_id)
            if self.window.session.target_kind == "directory" and self.window.rescan_button is None:
                self.window.rescan_button = action_button("Rescan directory", "system-search-symbolic", self.window.start_rescan, compact=True)
                self.window.search.get_parent().pack_start(self.window.rescan_button, False, False, 0)
            self.window.reload()
        self.window.show_all()
        self.pump(0.1)
        return self.app

    def pump(self, seconds=0.05):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.context.iteration(False)
            time.sleep(0.005)

    def wait_for(self, predicate, message, timeout=8):
        if predicate():
            return
        deadline = time.monotonic() + timeout
        loop = GLib.MainLoop()
        errors = []

        def check():
            try:
                if predicate() or time.monotonic() >= deadline:
                    loop.quit()
                    return False
            except Exception as error:
                errors.append(error)
                loop.quit()
                return False
            return True

        GLib.timeout_add(20, check)
        loop.run()
        if errors:
            raise errors[0]
        if not predicate():
            self.fail(message)

    def terminal_text(self):
        return self.window.terminal.get_text_format(Vte.Format.TEXT)

    def test_application_run_exports_actions_and_closes(self):
        import subprocess

        self.close_current()
        environment = os.environ.copy()
        environment["GUIAI_TEST_FIXTURE"] = FIXTURE
        probe = r'''
import os
from pathlib import Path
import sys
import tempfile
import time
from gi.repository import GLib
from guiai.events import Session
import guiai.gtk_app as gtk_app
from guiai.gtk_app import GuiAIGtkApplication

with tempfile.TemporaryDirectory(prefix="guiai-application-run-") as temporary:
    session = Session(Path(temporary) / "session", "/bin/true")
    command = [sys.executable, "-u", "-c", os.environ.pop("GUIAI_TEST_FIXTURE")]
    app = GuiAIGtkApplication(session, command, session.root, "re.guiai.test.application.run")
    chosen_workspace = Path(temporary) / "chosen terminal directory"
    chosen_workspace.mkdir()
    directory_choices = []

    def choose_test_directory(_parent, initial):
        assert Path(initial) == session.root, "chooser did not start in the active terminal directory"
        directory_choices.append(Path(initial))
        return chosen_workspace

    gtk_app.choose_workspace = choose_test_directory
    failures = []
    second_workspace = []
    check_sent = []
    child_process_ids = []
    deadline = time.monotonic() + 8

    def verify():
        try:
            window = app.window
            assert window is not None and window.get_visible(), "application window was not activated"
            assert window.get_title().startswith("Ablation"), "visible application name is not Ablation"
            assert window.header_bar.get_custom_title() is not None, "centered title text should be removed"
            assert isinstance(window.brand_mark, Gtk.Image), "header must use the supplied transparent icon"
            assert window.brand_mark.get_pixbuf().get_has_alpha(), "header icon must preserve transparency"
            assert window.brand_mark.get_pixbuf().get_width() == 32
            assert window.brand_mark.get_pixbuf().get_height() == 32
            assert window.brand_mark.get_parent() is window.header_bar
            assert window.header_bar.child_get_property(window.brand_mark, "pack-type") == Gtk.PackType.START, "brand mark must stay at the far left"
            workspace = window.current_workspace()
            if not second_workspace:
                assert workspace is not None and window.notebook.get_n_pages() == 1
                if "FIXTURE READY" not in workspace.terminal.get_text_format(Vte.Format.TEXT):
                    if time.monotonic() < deadline:
                        return True
                    raise AssertionError("CLI did not start through Application.run()")
                assert isinstance(workspace.agent_pid, int), "VTE did not return a child PID"
                assert Path(f"/proc/{workspace.agent_pid}/cwd").resolve() == session.root
                assert not workspace.progress.get_visible(), "parent show_all revealed idle progress"
                assert not workspace.cancel_button.get_visible(), "parent show_all revealed idle Cancel"
                assert workspace.tree.get_rules_hint(), "native alternating row colors are disabled"
                assert window.new_button.get_visible() and window.menu_button.get_visible()
                actions = window.get_action_group("workbench")
                assert actions is not None, "native action group was not exported"
                assert "new-investigation" in actions.list_actions()
                assert "preferences" in actions.list_actions()
                assert "focus-cli" in actions.list_actions()
                menu_items = window.menu_button.get_popup().get_children()
                preferences_item = next(item for item in menu_items if item.get_label() == "Preferences")
                preferences_item.emit("activate")
                assert window.preferences_dialog is not None, "menu did not open native preferences"
                window.preferences_dialog.destroy()
                assert window.preferences_dialog is None
                window.new_button.emit("clicked")
                second = window.current_workspace()
                assert second is not workspace, "+ did not create a paired investigation"
                assert second.workspace == chosen_workspace
                assert second.session.workspace == chosen_workspace
                assert second.session.target == workspace.session.target, "directory choice changed the RE target"
                assert directory_choices == [session.root]
                second_workspace.append(second)
                return True
            first = window.workspaces[0]
            second = second_workspace[0]
            if not check_sent:
                if not isinstance(second.agent_pid, int):
                    if time.monotonic() < deadline:
                        return True
                    raise AssertionError(
                        f"second investigation CLI did not start; status={second.agent_status}; "
                        f"pid={second.agent_pid}; mapped={second.terminal.get_mapped()}; "
                        f"realized={second.terminal.get_realized()}; visible={second.terminal.get_visible()}; "
                        f"text={second.terminal.get_text_format(Vte.Format.TEXT)!r}"
                    )
                assert Path(f"/proc/{second.agent_pid}/cwd").resolve() == chosen_workspace
                def send_check():
                    second.terminal.grab_focus()
                    second.terminal.feed_child(b"check\n")
                    check_sent.append(True)
                    return False

                GLib.timeout_add(250, send_check)
                return True
            if "STATE_RC=0" not in second.terminal.get_text_format(Vte.Format.TEXT):
                if time.monotonic() < deadline:
                    return True
                raise AssertionError("second investigation CLI did not answer through its own wrapper")
            assert window.notebook.get_n_pages() == 2
            assert window.current_workspace() is second
            assert isinstance(first.agent_pid, int) and isinstance(second.agent_pid, int)
            assert first.agent_pid != second.agent_pid
            assert first.session.events_path != second.session.events_path
            second.session.emit(
                "observation:second", second.session.root_id, "observation", "Second investigation",
                "partial", "agent",
            )
            second.reload()
            assert "observation:second" in second.node_iters
            assert all(event["id"] != "observation:second" for event in first.session.events())
            process_ids = (first.agent_pid, second.agent_pid)
            child_process_ids.extend(process_ids)
            window.preferences.update(
                scheme=window.preferences.scheme, font_name=window.preferences.font_name,
                **window.preferences.custom,
            )
            window.apply_preferences()
            assert all(workspace.layout == "horizontal" for workspace in window.workspaces)
            assert (first.agent_pid, second.agent_pid) == process_ids, "preference application restarted a CLI"
            assert all(workspace.terminal.get_parent() is not None for workspace in window.workspaces)
            assert all(workspace.map_stack.get_parent() is workspace.investigation_panes for workspace in window.workspaces)
            window.close_workspace(second)
            assert second.closed and not first.closed
            assert window.current_workspace() is first
            assert second.session.events_path.exists(), "closing a terminal discarded investigation history"
        except Exception:
            import traceback
            failures.append(traceback.format_exc())
        app.quit()
        return False

    from gi.repository import Gtk, Vte
    GLib.timeout_add(250, verify)
    status = app.run([sys.executable])
    assert app.window.closed, "application shutdown did not close the investigation window"
    for pid in child_process_ids:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        failures.append(f"CLI process survived application shutdown: {pid}")
        os.killpg(pid, 9)
    if status or failures:
        raise SystemExit(f"status={status}, failures={failures}")
    print("APPLICATION_RUN_OK")
'''
        completed = subprocess.run(
            [os.sys.executable, "-c", probe], env=environment,
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("APPLICATION_RUN_OK", completed.stdout)
        self.assertNotIn("CRITICAL", completed.stderr)

    def test_single_process_tab_churn(self):
        import subprocess

        self.close_current()
        environment = os.environ.copy()
        environment["GUIAI_TEST_FIXTURE"] = FIXTURE
        probe = r'''
import gc
import os
from pathlib import Path
import sys
import tempfile
import time
from gi.repository import GLib
from guiai.events import Session
from guiai.gtk_app import GuiAIGtkApplication, InvestigationWorkspace, Vte


def resident_mib():
    pages = int(Path("/proc/self/statm").read_text().split()[1])
    return pages * os.sysconf("SC_PAGE_SIZE") // (1024 * 1024)


def live_counts():
    objects = gc.get_objects()
    return (
        sum(isinstance(item, InvestigationWorkspace) for item in objects),
        sum(isinstance(item, Vte.Terminal) for item in objects),
        len(objects),
    )


def wait_ready(workspace):
    deadline = time.monotonic() + 4
    while "FIXTURE READY" not in workspace.terminal.get_text_format(Vte.Format.TEXT):
        if time.monotonic() >= deadline:
            raise TimeoutError("new investigation CLI did not start")
        GLib.MainContext.default().iteration(False)
        time.sleep(0.002)


with tempfile.TemporaryDirectory(prefix="guiai-tab-churn-") as temporary:
    session = Session(Path(temporary) / "session", "/bin/true")
    command = [sys.executable, "-u", "-c", os.environ.pop("GUIAI_TEST_FIXTURE")]
    app = GuiAIGtkApplication(session, command, session.root, "re.guiai.test.tab.churn")
    import guiai.gtk_app as gtk_app
    gtk_app.choose_workspace = lambda _parent, initial: Path(initial)
    iterations = max(1, int(os.environ.get("GUIAI_TAB_CHURN", "40")))
    state = {"iteration": 0}
    failures = []
    owned_pids = []
    memory_samples = []

    def churn():
        try:
            window = app.window
            first = window.workspaces[0]
            first_pid = first.agent_pid
            if state["iteration"] >= iterations:
                app.quit()
                return False
            index = state["iteration"]
            window.new_button.emit("clicked")
            second = window.current_workspace()
            assert second is not first
            wait_ready(second)
            assert isinstance(first.agent_pid, int) and isinstance(second.agent_pid, int)
            assert first.agent_pid == first_pid
            owned_pids.append(second.agent_pid)
            window.preferences.update(
                scheme=window.preferences.scheme, font_name=window.preferences.font_name,
                save=False, **window.preferences.custom,
            )
            window.apply_preferences()
            assert all(workspace.layout == "horizontal" for workspace in window.workspaces)
            assert (first.agent_pid, second.agent_pid) == (first_pid, owned_pids[-1])
            second.session.emit(
                "observation:churn", second.session.root_id, "observation", f"Churn {index}",
                "partial", "agent",
            )
            second.reload()
            assert "observation:churn" in second.node_iters
            assert all(event["id"] != "observation:churn" for event in first.session.events())
            history = second.session.events_path
            second_pid = second.agent_pid
            window.close_workspace(second)
            assert window.notebook.get_n_pages() == 1
            assert window.current_workspace() is first
            assert first.agent_pid == first_pid
            assert history.exists()
            reaping_deadline = time.monotonic() + 2
            while True:
                try:
                    os.kill(second_pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= reaping_deadline:
                    process_state = Path(f"/proc/{second_pid}/stat").read_text().split()[2]
                    raise AssertionError(
                        f"terminal survived tab close: {second_pid}; state={process_state}; iteration={index}; "
                        f"agent_pid={second.agent_pid}; exited={second.agent_exited}; closed={second.closed}"
                    )
                GLib.MainContext.default().iteration(False)
                time.sleep(0.002)
            state["iteration"] += 1
            if state["iteration"] % 10 == 0:
                gc.collect()
                memory_samples.append((state["iteration"], resident_mib(), *live_counts()))
            return True
        except Exception:
            import traceback
            failures.append(traceback.format_exc())
            app.quit()
            return False

    def begin():
        try:
            first = app.window.current_workspace()
            wait_ready(first)
            owned_pids.append(first.agent_pid)
            memory_samples.append((0, resident_mib()))
            GLib.timeout_add(10, churn)
        except Exception:
            import traceback
            failures.append(traceback.format_exc())
            app.quit()
        return False

    GLib.timeout_add(100, begin)
    status = app.run([sys.executable])
    gc.collect()
    final_memory = resident_mib()
    final_counts = live_counts()
    baseline = memory_samples[0][1] if memory_samples else 0
    growth = final_memory - baseline
    if growth > 64:
        failures.append(f"resident memory grew by {growth} MiB; samples={memory_samples}, final={final_memory}")
    if final_counts[:2] != (1, 1):
        current = app.window.current_workspace()
        retained = next(item for item in gc.get_objects() if isinstance(item, InvestigationWorkspace) and item is not current)
        references = [
            (type(reference).__name__, repr(getattr(reference, "cell_contents", reference))[:400])
            for reference in gc.get_referrers(retained)
        ]
        callback_owners = {
            reference.__name__: [(type(owner).__name__, repr(owner)[:240]) for owner in gc.get_referrers(reference)]
            for reference in gc.get_referrers(retained) if type(reference).__name__ == "method"
        }
        failures.append(f"closed workspaces or terminals were retained: {final_counts}; referrers={references}; owners={callback_owners}")
    for pid in owned_pids:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        failures.append(f"CLI process survived churn shutdown: {pid}")
        os.killpg(pid, 9)
    if status or failures:
        raise SystemExit(f"status={status}; failures={failures}; memory={memory_samples}; final={final_memory}")
    print(f"TAB_CHURN_OK iterations={iterations}; baseline={baseline} MiB; final={final_memory} MiB; samples={memory_samples}")
'''
        completed = subprocess.run(
            [os.sys.executable, "-c", probe], env=environment,
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("TAB_CHURN_OK", completed.stdout)
        self.assertNotIn("CRITICAL", completed.stderr)
        self.assertNotIn("TypeError", completed.stderr)
        print(completed.stdout.strip())

    def test_ubuntu_fonts_and_theme_text(self):
        schema_source = Gio.SettingsSchemaSource.get_default()
        if schema_source is not None and schema_source.lookup("org.gnome.desktop.interface", True):
            settings = Gio.Settings.new("org.gnome.desktop.interface")
            interface_font = settings.get_string("font-name")
            monospace_font = settings.get_string("monospace-font-name")
        else:
            interface_font = Gtk.Settings.get_default().get_property("gtk-font-name")
            monospace_font = "Monospace 11"
        self.window.show_all()
        self.pump(0.1)
        self.assertEqual(Gtk.Settings.get_default().get_property("gtk-font-name"), interface_font)
        actual = self.window.terminal.get_font()
        expected = Pango.FontDescription.from_string(monospace_font)
        self.assertEqual(actual.to_string(), expected.to_string())
        for index in range(1):
            for renderer in self.window.tree.get_column(index).get_cells():
                if isinstance(renderer, Gtk.CellRendererText):
                    self.assertFalse(renderer.get_property("foreground-set"))

    def test_sync_start_is_not_duplicated(self):
        self.window.command = [os.sys.executable, "-u", "-c", "print('fixture')"]
        with mock.patch.object(self.window.terminal, "spawn_sync", return_value=(True, 424242)) as spawn:
            self.window.ensure_agent()
            self.window.ensure_agent()
            spawn.assert_called_once()
            self.assertEqual(spawn.call_args.args[1], str(self.window.workspace))
            environment = dict(entry.split("=", 1) for entry in spawn.call_args.args[3])
            self.assertEqual(environment["GUIAI_WORKSPACE"], str(self.window.workspace))
            self.assertEqual(self.window.agent_pid, 424242)
            self.assertFalse(self.window.agent_starting)
            self.assertFalse(self.window.agent_exited)
            self.assertTrue(self.window.terminal.get_input_enabled())
            self.window.on_agent_exit(self.window.terminal)
            self.assertIsNone(self.window.agent_pid)
            self.assertTrue(self.window.agent_exited)

    def test_sync_start_failure_is_visible(self):
        self.window.command = [os.sys.executable, "-u", "-c", "print('fixture')"]
        with mock.patch.object(self.window.terminal, "spawn_sync", return_value=(False, -1)) as spawn:
            self.window.start_agent()
            spawn.assert_called_once()
            self.assertTrue(self.window.agent_exited)
            self.assertFalse(self.window.agent_starting)
            self.assertIsNone(self.window.agent_pid)
            self.assertIn("Unable to start CLI", self.window.agent_status)

    def test_exited_agent_reaping_fallback(self):
        import subprocess

        process = subprocess.Popen([os.sys.executable, "-c", "pass"])
        self.addCleanup(process.wait)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{process.pid}/stat").read_text().split()[2]
            except FileNotFoundError:
                self.fail("test child was reaped before the fallback fixture ran")
            if state == "Z":
                break
            time.sleep(0.005)
        else:
            self.fail("test child did not reach the zombie state")
        holder = mock.Mock()
        holder.agent_starting = False
        holder.agent_exited = True
        holder.agent_pid = process.pid
        self.assertTrue(wait_for_agents([holder], timeout=0))
        self.assertIsNone(holder.agent_pid)
        with self.assertRaises(ProcessLookupError):
            os.kill(process.pid, 0)

    def test_icons_use_theme_foreground(self):
        def rgba_values(color):
            return tuple(round(getattr(color, channel) * 255) for channel in ("red", "green", "blue"))

        def opaque_colors(pixbuf):
            pixels = pixbuf.get_pixels()
            channels = pixbuf.get_n_channels()
            return {
                tuple(pixels[offset:offset + 3])
                for offset in range(0, len(pixels), channels)
                if channels == 3 or pixels[offset + 3] > 0
            }

        self.window.show_all()
        self.pump(0.1)
        style = self.window.tree.get_style_context()
        normal = rgba_values(style.get_color(Gtk.StateFlags.NORMAL))
        selected = rgba_values(style.get_color(Gtk.StateFlags.SELECTED))
        names = (
            "p-icon--close", "p-icon--code", "p-icon--copy", "p-icon--file",
            "p-icon--folder", "p-icon--history", "p-icon--open-terminal-inverse",
            "p-icon--restart", "p-icon--show", "p-icon--success",
        )
        for name in names:
            colors = opaque_colors(themed_pixbuf(name, self.window.tree))
            self.assertTrue(colors, f"{name} rendered no visible pixels")
            if name not in ORIGINAL_COLOR_ICONS:
                self.assertIn(normal, colors, f"{name} does not use the theme foreground")
        selected_colors = opaque_colors(themed_pixbuf("p-icon--file", self.window.tree, state=Gtk.StateFlags.SELECTED))
        self.assertIn(selected, selected_colors)
        button = action_button("Test", "p-icon--restart", lambda: None)
        button.show_all()
        image = button.get_children()[0].get_children()[0]
        self.assertIsInstance(image, Gtk.Image)
        self.assertIsNotNone(image.get_pixbuf())
        button_foreground = rgba_values(button.get_style_context().get_color(Gtk.StateFlags.NORMAL))
        self.assertIn(button_foreground, opaque_colors(image.get_pixbuf()))
        button.destroy()

    def test_tree_expander_icons_and_vte_discovery(self):
        self.assertFalse(self.window.details_toggle.get_active())
        self.window.toggle_details()
        self.assertTrue(self.window.details_toggle.get_active())
        self.assertIn("gnutrue", self.window.detail_labels["label"].get_text())
        self.assertFalse(any(isinstance(child, Gtk.ScrolledWindow) for child in self.window.details_box.get_children()))
        self.window.toggle_details()
        self.assertFalse(self.window.details_toggle.get_active())
        self.assertIsNotNone(Gtk.IconTheme.get_default().load_icon("p-icon--copy", 16, Gtk.IconLookupFlags.GENERIC_FALLBACK))
        self.assertIsNotNone(Gtk.IconTheme.get_default().load_icon("p-icon--folder", 16, Gtk.IconLookupFlags.GENERIC_FALLBACK))

        self.window.command = [os.sys.executable, "-u", "-c", GTK_FIXTURE]
        self.window.start_agent()
        self.window.show_all()
        self.wait_for(lambda: isinstance(self.window.agent_pid, int), "VTE did not return a child PID")
        self.assertIsInstance(self.window.agent_pid, int)
        try:
            self.wait_for(lambda: "FIXTURE READY" in self.terminal_text(), "VTE fixture did not start")
        except AssertionError as error:
            raise AssertionError(
                f"{error}; status={self.window.agent_status}; pid={self.window.agent_pid}; "
                f"exited={self.window.agent_exited}; text={self.terminal_text()!r}"
            )
        self.window.terminal.feed_child(b"check\n")
        self.wait_for(lambda: "STATE_RC=0" in self.terminal_text(), "VTE session CLI failed")
        self.window.terminal.feed_child(b"emit\n")
        self.wait_for(lambda: "EMIT_RC=0" in self.terminal_text(), "agent discovery failed")
        self.window.poll_events()
        self.assertIn("observation:gtk-test", self.window.node_iters)
        event = self.window.store[self.window.node_iters["observation:gtk-test"]]
        self.assertEqual(event[0], "GTK discovery")
        self.assertEqual(event[1], "Observation")
        self.assertEqual(event[2], "Partial")
        self.assertFalse(self.window.reset_button.get_visible())
        self.assertEqual(self.window.status.get_active_text(), "All statuses")
        self.window.search.set_text("GTK discovery")
        self.window.on_filter_changed()
        self.assertTrue(self.window.reset_button.get_visible())
        self.assertIn("observation:gtk-test", self.window.matching)
        self.assertIn(self.window.session.root_id, self.window.matching)
        self.window.reset_filters()
        self.assertFalse(self.window.reset_button.get_visible())
        self.window.status.set_active_id("blocked")
        self.assertTrue(self.window.reset_button.get_visible())
        self.assertIn("No nodes match", self.window.empty_label.get_text())
        self.window.reset_filters()
        self.assertFalse(self.window.reset_button.get_visible())
        self.assertEqual(self.window.status.get_active_id(), "all")

    def test_readable_review_actions_summary_and_undo(self):
        workspace = self.window
        root = workspace.session.root_id
        root_iter = workspace.node_iters[root]
        self.assertFalse(workspace.type_column.get_visible())
        self.assertEqual(workspace.store[root_iter][1], "Artifact")
        self.assertEqual(workspace.store[root_iter][2], "Not started")
        self.assertEqual(workspace.tree.get_tooltip_column(), 6)
        self.assertIn(workspace.session.target, workspace.store[root_iter][6])
        lab_renderer = next(
            cell for cell in workspace.tree.get_column(0).get_cells()
            if isinstance(cell, Gtk.CellRendererText)
        )
        self.assertEqual(lab_renderer.get_property("ellipsize"), Pango.EllipsizeMode.MIDDLE)
        self.assertNotEqual(STATUS_LABELS["partial"], STATUS_LABELS["in_progress"])
        for value, label in STATUS_LABELS.items():
            with self.subTest(status=value):
                workspace.status.set_active_id(value)
                self.assertEqual(workspace.status.get_active_text(), label)
        workspace.reset_filters()

        long_name = "FD8369A-" + "very-long-firmware-name-" * 4 + ".pkg"
        workspace.session.emit(
            "artifact:long", root, "artifact", long_name, "partial", "agent",
            f"/tmp/{long_name}", "original note",
        )
        workspace.session.emit(
            "function:child", "artifact:long", "function", "main", "in_progress", "agent",
        )
        workspace.reload()
        self.assertTrue(workspace.type_column.get_visible())
        self.assertEqual(workspace.store[workspace.node_iters["artifact:long"]][1], TYPE_LABELS["artifact"])
        self.assertEqual(workspace.store[workspace.node_iters["artifact:long"]][2], "Partial")
        self.assertEqual(workspace.store[workspace.node_iters["function:child"]][1], "Function")
        self.assertEqual(workspace.store[workspace.node_iters["function:child"]][2], "In progress")
        workspace.select_node("artifact:long")
        self.assertEqual(workspace.detail_labels["status"].get_text(), "Status: Partial")
        self.assertEqual(workspace.detail_labels["status"].get_tooltip_text(), "Stored value: partial")
        self.assertEqual(workspace.detail_labels["type"].get_text(), "Type: Artifact")

        workspace.search.set_text("Partial")
        workspace.on_filter_changed()
        self.assertIn("artifact:long", workspace.matching)
        self.assertIn(root, workspace.matching)
        self.assertNotIn("function:child", workspace.matching)
        self.assertFalse(workspace.type_column.get_visible())
        workspace.reset_filters()
        self.assertTrue(workspace.type_column.get_visible())

        summary_buttons = {
            button.get_label(): button for button in workspace.status_counts.get_children()
        }
        self.assertEqual(
            list(summary_buttons), ["1 Not started", "1 In progress", "1 Partial"],
        )
        summary_buttons["1 In progress"].emit("clicked")
        self.assertEqual(workspace.status.get_active_id(), "in_progress")
        self.assertIn("function:child", workspace.matching)
        self.assertTrue(workspace.type_column.get_visible())
        summary_buttons["1 Partial"].emit("clicked")
        self.assertEqual(workspace.status.get_active_id(), "partial")
        self.assertIn("artifact:long", workspace.matching)
        self.assertNotIn("function:child", workspace.matching)
        self.assertFalse(workspace.type_column.get_visible())
        workspace.reset_filters()

        self.assertEqual(workspace.flag_button.get_child().get_children()[1].get_text(), "Flag for follow-up")
        self.assertEqual(workspace.review_button.get_child().get_children()[1].get_text(), "Mark as reviewed")
        self.assertEqual(workspace.open_cli_button.get_child().get_children()[1].get_text(), "Open in CLI")
        self.assertFalse(workspace.review_button.get_style_context().has_class("suggested-action"))
        self.assertTrue(workspace.open_cli_button.get_style_context().has_class("suggested-action"))
        self.assertEqual(
            [item.get_label() for item in workspace.node_overflow.get_popup().get_children()],
            ["Copy follow-up note", "Show in file manager"],
        )
        self.assertEqual(workspace.star_button.get_accessible().get_name(), "Star selected node")

        workspace.select_node("artifact:long")
        before = workspace.session.events_path.read_text(encoding="utf-8").splitlines()
        workspace.review_button.emit("clicked")
        reviewed = workspace.session.events_by_id()["artifact:long"]
        self.assertEqual(reviewed["status"], "reviewed")
        self.assertEqual(reviewed["source"], "human")
        self.assertTrue(workspace.undo_button.get_visible())
        self.assertIn("marked as reviewed", workspace.counts.get_text())
        self.assertEqual(workspace.session.events_by_id()[root]["status"], "not_started")
        workspace.undo_button.emit("clicked")
        restored = workspace.session.events_by_id()["artifact:long"]
        self.assertEqual(restored["status"], "partial")
        self.assertEqual(restored["source"], "agent")
        self.assertEqual(restored["note"], "original note")
        self.assertFalse(workspace.undo_button.get_visible())
        self.assertIn("Restored", workspace.counts.get_text())
        after = workspace.session.events_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(after), len(before) + 2)
        self.assertEqual(after[:len(before)], before)
        self.assertEqual(workspace.session.events_by_id()[root]["status"], "not_started")

        workspace.show_error("no selection")
        self.assertFalse(workspace.star_button.get_sensitive())
        self.assertTrue(all(not button.get_sensitive() for button in workspace.selection_actions))
        workspace.reload()

    def test_tree_layout_stays_bounded(self):
        self.window.show_all()
        self.window.details_toggle.set_active(False)
        self.pump(0.2)
        self.assertFalse(self.window.progress.get_visible())
        self.assertFalse(self.window.cancel_button.get_visible())
        self.assertTrue(self.window.tree.get_headers_visible())
        self.assertEqual(len(self.window.tree.get_columns()), 4)
        star_column = self.window.tree.get_column(1)
        column = self.window.tree.get_column(0)
        type_column = self.window.tree.get_column(2)
        status_column = self.window.tree.get_column(3)
        self.assertEqual(column.get_title(), "Lab")
        self.assertFalse(column.get_resizable())
        self.assertEqual(column.get_sizing(), Gtk.TreeViewColumnSizing.FIXED)
        self.assertEqual(column.get_fixed_width(), 360)
        self.assertEqual(star_column.get_fixed_width(), 34)
        self.assertEqual(type_column.get_title(), "Type")
        self.assertEqual(type_column.get_fixed_width(), 100)
        self.assertEqual(status_column.get_title(), "Status")
        self.assertFalse(status_column.get_resizable())
        self.assertFalse(status_column.get_expand())
        self.assertEqual(status_column.get_fixed_width(), 128)
        self.assertEqual([cell.get_property("xalign") for cell in status_column.get_cells()], [0.0])
        self.assertTrue(self.window.panes.child_get_property(self.window.panes.get_children()[0], "shrink"))

        self.window.session.emit(
            "note:long-layout-label", self.window.session.root_id, "note", "layout " * 60,
            "partial", "agent",
        )
        self.window.reload()
        self.window.panes.set_position(600)
        self.pump(0.2)
        narrow = column.get_width()
        self.window.panes.set_position(850)
        self.pump(0.2)
        wide = column.get_width()
        self.assertGreater(self.window.panes.get_position(), 600)
        self.assertLess(narrow, wide)
        for width in (narrow, wide):
            fixed_width = star_column.get_width() + type_column.get_width() + status_column.get_width()
            self.assertLessEqual(width + fixed_width, self.window.tree.get_allocation().width)

    def test_starred_nodes_and_eye_disclosure(self):
        self.assertFalse(self.window.details_toggle.get_active())
        self.assertEqual(self.window.details_toggle.get_tooltip_text(), "Show node details")
        with mock.patch.object(self.window, "update_map", wraps=self.window.update_map) as update_map:
            self.window.details_toggle.emit("clicked")
            update_map.assert_not_called()
        self.pump(0.1)
        self.assertTrue(self.window.details_toggle.get_active())
        self.assertTrue(self.window.details_box.get_visible())
        self.assertTrue(self.window.details_box.get_mapped())
        self.assertGreater(self.window.details_box.get_allocated_height(), 0)
        self.assertTrue(self.window.detail_labels["label"].get_mapped())
        self.assertTrue(self.window.details_scroller.get_propagate_natural_height())
        self.assertEqual(self.window.details_scroller.get_max_content_height(), 220)
        self.assertLessEqual(self.window.details_scroller.get_allocated_height(), 222)
        self.assertEqual(self.window.details_scroller.get_policy()[0], Gtk.PolicyType.NEVER)
        self.assertTrue(self.window.node_actions.get_mapped())
        self.assertTrue(self.window.counts.get_mapped())
        self.assertEqual(self.window.details_toggle.get_tooltip_text(), "Hide node details")
        self.assertIn("p-icon--hide", {key[0] for key in self.window.icon_cache})
        self.window.details_toggle.emit("clicked")
        self.pump(0.1)
        self.assertFalse(self.window.details_toggle.get_active())
        self.assertFalse(self.window.details_box.get_visible())
        self.assertIn("p-icon--show", {key[0] for key in self.window.icon_cache})

        root = self.window.session.root_id
        self.window.select_node(root)
        self.pump()
        path = self.window.filter_model.convert_child_path_to_path(
            self.window.store.get_path(self.window.node_iters[root])
        )
        area = self.window.tree.get_background_area(path, self.window.star_column)
        event = mock.Mock(button=1, x=area.x + 2, y=area.y + 2)
        self.assertTrue(self.window.on_tree_button(self.window.tree, event))
        self.assertIn(root, self.window.session.current_state()["starred_ids"])
        self.assertIn(root, self.window.starred_ids)
        self.assertEqual(self.window.star_button.get_tooltip_text(), "Remove star from selected node")
        self.window.reload()
        self.assertIn(root, self.window.starred_ids)
        self.window.toggle_selected_star()
        self.assertNotIn(root, self.window.session.current_state()["starred_ids"])
        self.assertEqual(self.window.star_button.get_tooltip_text(), "Star selected node")

    def test_pane_position_is_user_adjustable(self):
        self.host.show_all()
        self.pump(0.2)
        self.assertIs(self.window.node_actions.get_parent(), self.window.left)
        self.assertTrue(self.window.node_actions.get_visible())
        self.assertFalse(self.window.details_toggle.get_active())
        self.assertIs(self.window.counts.get_parent().get_parent(), self.window.left)
        self.assertEqual(self.window.counts.get_text(), "1 node")
        self.assertIn("1 Not started", self.window.counts.get_tooltip_text())
        self.assertEqual(self.window.refresh_button.get_tooltip_text(), "Refresh lab")
        self.window.panes.set_position(600)
        self.pump(0.1)
        self.assertAlmostEqual(self.window.panes.get_position(), 600, delta=2)
        self.window.reload()
        self.assertAlmostEqual(self.window.panes.get_position(), 600, delta=2)
        self.assertEqual(self.window.layout, "horizontal")
        self.assertIs(self.window.left.get_parent(), self.window.panes)
        self.assertIs(self.window.terminal.get_parent(), self.window.panes)
        self.assertIs(self.window.map_stack.get_parent(), self.window.investigation_panes)

        self.assertIsInstance(self.window.node_actions, Gtk.Grid)
        self.assertNotIsInstance(self.window.node_actions, Gtk.FlowBox)
        self.assertIs(self.window.node_overflow.get_parent(), self.window.node_actions)
        self.window.panes.set_position(850)
        self.pump(0.2)
        self.assertFalse(self.window.actions_compact)
        self.assertTrue(all(label.get_visible() for label in self.window.action_labels))
        self.assertGreater(
            self.window.review_button.get_allocated_width(),
            self.window.star_button.get_allocated_width(),
        )
        action_buttons = (
            self.window.star_button, self.window.flag_button, self.window.review_button,
            self.window.open_cli_button, self.window.node_overflow,
        )
        self.assertEqual(len({button.get_allocation().y for button in action_buttons}), 1)

        self.window.panes.set_position(420)
        self.pump(0.25)
        self.assertTrue(self.window.actions_compact)
        self.assertTrue(all(not label.get_visible() for label in self.window.action_labels))
        self.assertTrue(self.window.node_overflow.get_visible())
        self.assertEqual(len({button.get_allocation().y for button in action_buttons}), 1)
        row_start = self.window.node_actions.get_allocation().x
        row_width = self.window.node_actions.get_allocated_width()
        row_right = row_start + row_width
        container = (
            tuple(getattr(self.window.node_actions.get_allocation(), field) for field in ("x", "y", "width", "height")),
            tuple(getattr(self.window.left.get_allocation(), field) for field in ("x", "y", "width", "height")),
            self.window.node_actions.get_margin_start(), self.window.node_actions.get_margin_end(),
            self.window.node_actions.get_border_width(), self.window.node_actions.get_preferred_width(),
        )
        geometry = lambda: (container, row_width, self.window.full_action_width, [
            (
                button.get_tooltip_text(),
                tuple(getattr(button.get_allocation(), field) for field in ("x", "y", "width", "height")),
                button.get_margin_start(), button.get_margin_end(), button.get_hexpand(),
                button.get_preferred_width(),
            )
            for button in action_buttons
        ])
        for button in action_buttons:
            allocation = button.get_allocation()
            self.assertGreaterEqual(allocation.x, row_start, geometry())
            self.assertLessEqual(allocation.x + allocation.width, row_right, geometry())
        overflow = self.window.node_overflow.get_allocation()
        self.assertAlmostEqual(overflow.x + overflow.width, row_right, delta=2)

        self.window.panes.set_position(850)
        self.pump(0.25)
        self.assertFalse(self.window.actions_compact)
        self.assertTrue(all(label.get_visible() for label in self.window.action_labels))
        self.window.apply_preferences()
        self.pump(0.1)
        self.assertFalse(self.window.actions_compact)
        self.assertTrue(all(label.get_visible() for label in self.window.action_labels))

    def test_breadcrumb_navigation(self):
        root = self.window.session.root_id
        self.window.session.emit(
            "artifact:firmware", root, "artifact", "firmware.bin", "partial", "agent",
        )
        self.window.session.emit(
            "function:main", "artifact:firmware", "function", "main @ 0x50c8", "in_progress", "agent",
        )
        self.window.reload()
        self.window.select_node("function:main")
        labels = [child.get_label() for child in self.window.breadcrumb_box.get_children() if isinstance(child, Gtk.Button)]
        self.assertEqual(labels, ["gnutrue", "firmware.bin", "main @ 0x50c8"])
        self.assertTrue(self.window.up_button.get_sensitive())
        self.window.go_parent()
        self.assertEqual(self.window.selected_event["id"], "artifact:firmware")
        self.window.go_home()
        self.assertEqual(self.window.selected_event["id"], root)
        self.assertFalse(self.window.up_button.get_sensitive())
        self.window.select_node("function:main")
        parent_button = next(
            child for child in self.window.breadcrumb_box.get_children()
            if isinstance(child, Gtk.Button) and child.get_label() == "firmware.bin"
        )
        parent_button.emit("clicked")
        self.assertEqual(self.window.selected_event["id"], "artifact:firmware")
        self.assertEqual(self.window.session.current_state()["selected_id"], "artifact:firmware")

    def test_safe_nautilus_action(self):
        with mock.patch("guiai.gtk_app.shutil.which", return_value="/usr/bin/nautilus"), mock.patch("guiai.gtk_app.subprocess.Popen") as process:
            self.window.show_in_files()
        command = process.call_args.args[0]
        self.assertEqual(command[:2], ["nautilus", "--select"])
        self.assertEqual(command[2], self.window.session.target)
        self.assertFalse(process.call_args.kwargs.get("shell", False))
        self.assertTrue(process.call_args.kwargs["start_new_session"])

    def test_async_rescan_success(self):
        self.make_app(target=self.corpus)
        (self.corpus / "new-package.bin").write_bytes(b"new")
        worker_ids = set()
        main_id = threading.get_ident()

        class TrackedSession(Session):
            def _initialize_directory(self, directory, cancelled=None):
                worker_ids.add(threading.get_ident())
                return super()._initialize_directory(directory, cancelled)

        with mock.patch("guiai.gtk_app.Session", TrackedSession):
            self.window.start_rescan()
            self.assertTrue(self.window.progress.get_visible())
            self.assertTrue(self.window.cancel_button.get_visible())
            future = self.window.rescan_future
            self.assertIsNotNone(future)
            future.result(timeout=5)
            self.wait_for(lambda: self.window.rescan_future is None, "rescan did not finish")
        self.assertNotIn(main_id, worker_ids)
        self.assertIn("new-package.bin", {event["label"] for event in self.window.events})
        self.assertTrue(self.window.rescan_button.get_sensitive())
        self.assertEqual(self.window.rescan_button.get_tooltip_text(), "Rescan directory")
        self.assertFalse(self.window.progress.get_visible())
        self.assertFalse(self.window.cancel_button.get_visible())

    def test_async_rescan_cancellation_and_close(self):
        self.make_app(target=self.corpus)
        started = threading.Event()
        cancelled = threading.Event()

        def blocking_session(_root, _target, is_cancelled):
            started.set()
            while not is_cancelled():
                time.sleep(0.005)
            cancelled.set()
            raise ValueError("directory rescan cancelled")

        with mock.patch("guiai.gtk_app.Session", side_effect=blocking_session):
            self.window.start_rescan()
            self.assertTrue(started.wait(2))
            self.window.cancel_rescan()
            with self.assertRaises(ValueError):
                self.window.rescan_future.result(timeout=3)
            self.wait_for(lambda: self.window.rescan_future is None, "cancel did not complete")
            self.assertIn("cancelled", self.window.counts.get_text())
            self.assertFalse(self.window.cancel_button.get_visible())
            self.assertTrue(self.window.rescan_button.get_sensitive())
            started.clear()
            self.window.start_rescan()
            self.assertTrue(started.wait(2))
            self.window.close()
            self.assertTrue(cancelled.wait(2))

    def test_terminal_directory_choice_and_restoration(self):
        self.close_current()
        root = Path(self.temporary.name) / "directory-session"
        alternate = Path(self.temporary.name) / "alternate terminal directory"
        alternate.mkdir()
        override = Path(self.temporary.name) / "override terminal directory"
        override.mkdir()
        resources = []

        def make_window(workspace=None):
            session = Session(root, "/bin/true")
            cli_workspace = workspace or session.root
            app = GuiAIGtkApplication(
                session, None, cli_workspace, f"re.guiai.test.directory.n{next(TEST_ID)}", export_actions=False,
            )
            window = AblationWindow(app, session, None, cli_workspace, export_actions=False)
            resources.append((app, window))
            return window

        try:
            first_window = make_window()
            initial = first_window.current_workspace().workspace
            with mock.patch("guiai.gtk_app.choose_workspace", return_value=alternate) as chooser:
                second = first_window.new_investigation()
            self.assertIsNotNone(second)
            chooser.assert_called_once_with(first_window, initial)
            self.assertEqual(first_window.notebook.get_n_pages(), 2)
            self.assertEqual(second.workspace, alternate)
            self.assertEqual(second.session.workspace, alternate)
            self.assertEqual(second.session.target, first_window.session.target)
            metadata = json.loads(second.session.metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["workspace"], str(alternate))
            self.assertEqual(metadata["target"], second.session.target)
            self.assertNotIn("workspace", first_window.session.metadata)
            self.assertIn("GUIAI_WORKSPACE", (second.session.root / "AGENTS.md").read_text(encoding="utf-8"))

            invalid_file = Path(self.temporary.name) / "not-a-directory"
            invalid_file.write_text("file", encoding="utf-8")
            missing = Path(self.temporary.name) / "missing-directory"
            next_number = first_window.next_number
            for selected in (None, invalid_file, missing):
                with self.subTest(selected=selected):
                    with mock.patch("guiai.gtk_app.choose_workspace", return_value=selected):
                        self.assertIsNone(first_window.new_investigation())
                    self.assertEqual(first_window.notebook.get_n_pages(), 2)
                    self.assertEqual(first_window.next_number, next_number)
            self.assertEqual(
                [path.name for path in (root / "investigations").iterdir()], ["0002"],
            )

            dialog = mock.Mock()
            dialog.run.return_value = Gtk.ResponseType.ACCEPT
            dialog.get_filename.return_value = str(initial)
            with mock.patch("guiai.gtk_app.Gtk.FileChooserDialog", return_value=dialog) as dialog_type:
                self.assertEqual(choose_workspace(first_window, initial), initial)
            self.assertEqual(dialog_type.call_args.kwargs["transient_for"], first_window)
            self.assertEqual(
                dialog_type.call_args.kwargs["action"], Gtk.FileChooserAction.SELECT_FOLDER,
            )
            dialog.set_current_folder.assert_called_once_with(str(initial))
            dialog.destroy.assert_called_once()
            dialog.reset_mock()
            dialog.run.return_value = Gtk.ResponseType.CANCEL
            with mock.patch("guiai.gtk_app.Gtk.FileChooserDialog", return_value=dialog):
                self.assertIsNone(choose_workspace(first_window, initial))
            dialog.destroy.assert_called_once()

            second.session.emit(
                "observation:directory-preserved", second.session.root_id, "observation",
                "Directory choice preserved", "partial", "agent",
            )
            restored = make_window()
            self.assertEqual(restored.notebook.get_n_pages(), 2)
            self.assertEqual(restored.workspaces[1].workspace, alternate)
            self.assertEqual(restored.workspaces[1].session.workspace, alternate)
            self.assertEqual(restored.workspaces[1].session.target, second.session.target)
            self.assertIn("observation:directory-preserved", restored.workspaces[1].node_iters)

            overridden = make_window(override)
            self.assertTrue(all(workspace.workspace == override for workspace in overridden.workspaces))

            alternate.rmdir()
            fallback = make_window()
            self.assertEqual(fallback.notebook.get_n_pages(), 2)
            self.assertEqual(fallback.workspaces[1].workspace, fallback.workspaces[1].session.root)
            self.assertIn("saved terminal directory is unavailable", fallback.preferences_error.get_text())
            self.assertEqual(fallback.workspaces[1].session.target, second.session.target)
            self.assertEqual(
                json.loads(fallback.workspaces[1].session.metadata_path.read_text(encoding="utf-8"))["workspace"],
                str(alternate),
            )
        finally:
            for app, window in reversed(resources):
                window.close()
                app.quit()
                window.destroy()
            self.pump(0.1)

    def test_investigations_and_preferences_restore(self):
        self.close_current()
        root = Path(self.temporary.name) / "restore-session"
        resources = []

        def make_window():
            session = Session(root, "/bin/true")
            app = GuiAIGtkApplication(session, None, session.root, f"re.guiai.test.restore.n{next(TEST_ID)}", export_actions=False)
            window = AblationWindow(app, session, None, session.root, export_actions=False)
            resources.append((app, window))
            return window

        try:
            first_window = make_window()
            with mock.patch("guiai.gtk_app.choose_workspace", return_value=root):
                second = first_window.new_investigation()
            second.session.emit(
                "observation:restored", second.session.root_id, "observation", "Restored observation",
                "partial", "agent",
            )
            first_window.preferences.update(
                scheme="tango", font_name="Ubuntu Sans Mono 11",
                **first_window.preferences.custom,
            )
            corrupt = root / "investigations" / "0009"
            corrupt.mkdir(parents=True)
            (corrupt / "session.json").write_text("{broken", encoding="utf-8")

            restored = make_window()
            self.assertEqual(restored.notebook.get_n_pages(), 2)
            self.assertEqual(restored.preferences.scheme, "tango")
            self.assertEqual(restored.preferences.layout, "horizontal")
            self.assertIn("could not be restored", restored.preferences_error.get_text())
            labels = [
                restored.notebook.get_tab_label(workspace).get_children()[0].get_text()
                for workspace in restored.workspaces
            ]
            self.assertEqual(labels, ["Lab #1", "Lab #2"])
            self.assertTrue(all(workspace.layout == "horizontal" for workspace in restored.workspaces))
            self.assertIn("observation:restored", restored.workspaces[1].node_iters)
            self.assertNotIn("observation:restored", restored.workspaces[0].node_iters)
            self.assertTrue((corrupt / "session.json").exists())
        finally:
            for app, window in reversed(resources):
                window.close()
                app.quit()
                window.destroy()
            self.pump(0.1)

    def test_terminal_preferences_dialog(self):
        preferences = WorkbenchPreferences(Path(self.temporary.name) / "preferences-session", "Ubuntu Sans Mono 11")
        applied = []
        dialog = PreferencesDialog(self.host, preferences, lambda: applied.append(True), session=self.window.session)
        self.addCleanup(dialog.destroy)
        dialog.show_all()
        self.pump(0.05)
        self.assertEqual(set(dialog.section_expanders), {"lab", "terminal", "palette"})
        for name, expander in dialog.section_expanders.items():
            child = expander.get_child()
            self.assertFalse(expander.get_expanded(), name)
            self.assertFalse(child.get_mapped(), name)
            expander.set_expanded(True)
            dialog.show_all()
            self.pump(0.03)
            self.assertTrue(child.get_mapped(), name)
            expander.set_expanded(False)
            self.pump(0.03)
            self.assertFalse(child.get_mapped(), name)
        labels = [
            child.get_text() for child in dialog.section_expanders["lab"].get_child().get_children()
            if isinstance(child, Gtk.Label)
        ]
        self.assertIn(f"Target: {self.window.session.target}", labels)
        self.assertIn(f"Session: {self.window.session.root}", labels)
        self.assertFalse(hasattr(dialog, "layout_buttons"))
        dialog.scheme_combo.set_active_id("solarized-dark")
        dialog.apply()
        self.assertEqual(applied, [True])
        self.assertEqual(preferences.scheme, "solarized-dark")
        self.assertEqual(preferences.layout, "horizontal")
        self.assertTrue(preferences.path.exists())
        self.assertNotIn("layout", json.loads(preferences.path.read_text(encoding="utf-8")))

        loaded = WorkbenchPreferences(preferences.path.parent, "fallback")
        self.assertIsNone(loaded.error)
        self.assertEqual(loaded.scheme, "solarized-dark")
        self.assertEqual(loaded.layout, "horizontal")
        self.window.preferences = loaded
        self.window.apply_preferences()
        self.assertEqual(self.window.panes.get_orientation(), Gtk.Orientation.HORIZONTAL)
        self.assertEqual(self.window.layout, "horizontal")
        self.assertIs(self.window.panes.get_children()[0], self.window.left)
        self.assertIs(self.window.map_stack.get_parent(), self.window.investigation_panes)
        self.assertIsNotNone(self.window.terminal.get_parent())

        dialog.foreground_button.set_rgba(parse_color("#123456"))
        dialog.foreground_button.emit("color-set")
        self.assertEqual(dialog.scheme_combo.get_active_id(), "custom")
        dialog.palette_buttons[0].set_rgba(parse_color("#010203"))
        dialog.palette_buttons[0].emit("color-set")
        dialog.apply()
        self.assertEqual(preferences.scheme, "custom")
        self.assertEqual(preferences.custom["foreground"], "#123456")
        self.assertEqual(preferences.custom["palette"][0], "#010203")
        loaded = WorkbenchPreferences(preferences.path.parent, "fallback")
        self.assertEqual(loaded.custom, preferences.custom)
        loaded.apply_terminal(self.window.terminal)
        self.assertEqual(self.window.terminal.get_font().to_string(), "Ubuntu Sans Mono 11")
        dialog.destroy()
        self.pump(0.05)

    def test_preferences_validation_and_corruption(self):
        root = Path(self.temporary.name) / "invalid-preferences"
        preferences = WorkbenchPreferences(root, "Ubuntu Sans Mono 11")
        with self.assertRaises(ValueError):
            preferences.update(
                scheme="unknown", font_name="Ubuntu Sans Mono 11",
                **preferences.custom,
            )
        with self.assertRaises(ValueError):
            preferences.update(
                scheme="custom", font_name="Ubuntu Sans Mono 11",
                foreground=preferences.custom["foreground"], background=preferences.custom["background"],
                palette=preferences.custom["palette"][:15],
            )
        self.assertFalse(preferences.path.exists())
        root.mkdir(parents=True)
        preferences.path.write_text(json.dumps({
            "version": 1, "scheme": "system", "font_name": "Ubuntu Sans Mono 11",
            "layout": "vertical", "custom": preferences.custom,
        }), encoding="utf-8")
        legacy = WorkbenchPreferences(root, "fallback")
        self.assertIsNone(legacy.error)
        self.assertEqual(legacy.layout, "horizontal")
        legacy.update(scheme="system", font_name="Ubuntu Sans Mono 11", **legacy.custom)
        self.assertNotIn("layout", json.loads(preferences.path.read_text(encoding="utf-8")))
        preferences.path.write_text("{broken", encoding="utf-8")
        corrupt = WorkbenchPreferences(root, "Ubuntu Sans Mono 11")
        self.assertIsNotNone(corrupt.error)
        self.assertEqual(corrupt.scheme, "system")
        self.assertEqual(preferences.path.read_text(encoding="utf-8"), "{broken")

    def test_map_toggle_and_shared_selection(self):
        root = self.window.session.root_id
        self.window.session.emit("artifact:child", root, "artifact", "firmware.bin", "partial", "agent")
        self.window.session.emit("function:child", "artifact:child", "function", "main", "in_progress", "agent")
        self.window.reload()
        self.window.map_toggle.set_active(True)
        self.window.chart_selector.set_active_id("map")
        self.pump(0.2)
        self.assertEqual(self.window.map_stack.get_visible_child_name(), "map")
        self.assertEqual(self.window.map_toggle.get_label(), "Chart")
        self.assertTrue(self.window.map_stack.get_visible())
        tree_scroll = self.window.investigation_panes.get_children()[0]
        self.assertIs(tree_scroll.get_child(), self.window.tree)
        self.assertTrue(self.window.tree.get_mapped())
        self.assertEqual(
            [self.window.tree.get_column(index).get_fixed_width() for index in (0, 2, 3)],
            [144, 80, 104],
        )
        investigation_map = self.window.investigation_map
        self.assertEqual(
            investigation_map.last_size,
            (investigation_map.get_allocated_width(), investigation_map.get_allocated_height()),
        )
        for tile, button in self.window.investigation_map.tile_buttons:
            allocation = button.get_allocation()
            self.assertEqual(
                (allocation.x, allocation.y, allocation.width, allocation.height),
                (int(tile.x), int(tile.y), int(tile.width), int(tile.height)),
            )
            self.assertGreater(allocation.width, 100)
        tile = next(tile for tile in self.window.investigation_map.tiles if tile.event and tile.event["id"] == "artifact:child")
        self.window.investigation_map.activate_tile(tile)
        self.assertEqual(self.window.selected_event["id"], "artifact:child")
        self.assertEqual(self.window.session.current_state()["selected_id"], "artifact:child")
        self.assertEqual(self.window.investigation_map.parent_id, "artifact:child")
        self.window.details_toggle.emit("clicked")
        self.pump(0.1)
        self.assertTrue(self.window.details_box.get_mapped())
        self.assertTrue(self.window.detail_labels["label"].get_mapped())
        self.assertIn("firmware.bin", self.window.detail_labels["label"].get_text())
        self.window.details_toggle.emit("clicked")
        self.window.map_toggle.set_active(False)
        self.assertFalse(self.window.map_stack.get_visible())
        self.assertEqual(
            [self.window.tree.get_column(index).get_fixed_width() for index in (0, 2, 3)],
            [360, 100, 128],
        )
        self.assertTrue(self.window.tree.get_mapped())

    def test_rings_shared_selection_and_navigation(self):
        root = self.window.session.root_id
        self.window.session.emit("artifact:child", root, "artifact", "firmware.bin", "partial", "agent")
        self.window.session.emit("function:child", "artifact:child", "function", "main", "in_progress", "agent")
        self.window.reload()
        self.assertFalse(self.window.chart_selector.get_visible())
        self.window.map_toggle.set_active(True)
        self.assertEqual(self.window.chart_selector.get_active_id(), "rings")
        self.assertTrue(self.window.chart_selector.get_visible())
        self.assertEqual(self.window.map_stack.get_visible_child_name(), "rings")
        self.assertTrue(self.window.map_stack.get_visible())
        self.assertTrue(self.window.tree.get_mapped())
        rings = self.window.investigation_rings
        self.assertEqual(rings.root_id, root)
        self.assertEqual(rings.layout.root.weight, 3)
        child = next(sector for sector in rings.sectors if sector.event["id"] == "artifact:child")
        rings.activate_sector(child)
        self.assertEqual(self.window.selected_event["id"], "artifact:child")
        self.assertEqual(self.window.session.current_state()["selected_id"], "artifact:child")
        self.assertEqual(rings.root_id, "artifact:child")
        self.assertEqual(self.window.investigation_map.parent_id, "artifact:child")
        self.window.select_node("function:child")
        self.assertEqual(rings.root_id, "artifact:child")
        rings.activate_sector(rings.layout.root)
        self.assertEqual(self.window.session.current_state()["selected_id"], root)
        rings.on_key(rings, mock.Mock(keyval=Gdk.keyval_from_name("Right")))
        self.assertEqual(self.window.session.current_state()["selected_id"], "artifact:child")
        self.window.chart_selector.set_active_id("map")
        self.assertEqual(self.window.map_stack.get_visible_child_name(), "map")
        self.window.map_toggle.set_active(False)
        self.assertFalse(self.window.chart_selector.get_visible())
        self.assertFalse(self.window.map_stack.get_visible())
        self.assertTrue(self.window.tree.get_mapped())

    def test_gem_shared_selection_export_and_evidence(self):
        root = self.window.session.root_id
        self.window.session.emit("artifact:child", root, "artifact", "firmware.bin", "partial", "agent")
        self.window.session.emit("function:child", "artifact:child", "function", "main", "in_progress", "agent")
        self.window.reload()
        self.window.map_toggle.set_active(True)
        self.window.chart_selector.set_active_id("gem")
        self.assertEqual(self.window.map_stack.get_visible_child_name(), "gem")
        gem = self.window.investigation_gem
        self.assertTrue(gem.report.passed, gem.report.text())
        gem.activate_item(gem.scene.object("artifact:child"))
        self.assertEqual(self.window.selected_event["id"], "artifact:child")
        self.window.select_node("function:child")
        self.assertEqual(gem.parent_id, "artifact:child")
        self.assertEqual(gem.selected_id, "function:child")
        scene = gem.scene
        result = self.window.export_gem()
        self.assertIsNotNone(result)
        self.assertTrue(result.passed)
        replayed = replay(result.path)
        self.assertTrue(replayed.passed)
        self.assertTrue(replayed.matches_recorded)
        evidence_id = "evidence:gem:" + scene.digest()[:24]
        evidence = self.window.session.events_by_id()[evidence_id]
        self.assertEqual(evidence["parent_id"], "artifact:child")
        self.assertEqual(evidence["type"], "evidence")
        self.assertEqual(evidence["source"], "tool")
        self.assertEqual(evidence["status"], "complete_scoped")
        self.assertIn("source+VDI verified", evidence["scope"])
        self.assertIn("not human confirmation", evidence["note"])
        self.assertEqual(self.window.session.root / evidence["evidence"], result.path)
        self.assertTrue((result.path / "trajectory.jsonl").is_file())
        self.window.chart_selector.set_active_id("rings")
        self.assertEqual(self.window.map_stack.get_visible_child_name(), "rings")


class MapCase(unittest.TestCase):
    def test_layout_and_descendant_counts(self):
        events = [
            {"id": "root", "parent_id": None, "label": "root", "type": "artifact", "status": "not_started"},
            {"id": "a", "parent_id": "root", "label": "a", "type": "artifact", "status": "partial"},
            {"id": "a1", "parent_id": "a", "label": "a1", "type": "function", "status": "in_progress"},
            {"id": "a2", "parent_id": "a", "label": "a2", "type": "function", "status": "blocked"},
            {"id": "b", "parent_id": "root", "label": "b", "type": "artifact", "status": "reviewed"},
        ]
        self.assertEqual(descendant_counts(events), {"root": 4, "a": 2, "a1": 0, "a2": 0, "b": 0})
        tiles = treemap_layout([(3, "a"), (1, "b")], 0, 0, 400, 200)
        self.assertEqual(len(tiles), 2)
        self.assertAlmostEqual(sum(tile[4] * tile[5] for tile in tiles), 80000, delta=0.001)
        self.assertTrue(all(tile[4] > 0 and tile[5] > 0 for tile in tiles))

    def test_baobab_palette_is_positional_not_status_based(self):
        events = [
            {"id": "root", "parent_id": None, "label": "root", "type": "artifact", "status": "not_started"},
            {"id": "a", "parent_id": "root", "label": "a", "type": "artifact", "status": "partial"},
            {"id": "b", "parent_id": "root", "label": "b", "type": "artifact", "status": "reviewed"},
        ]
        widget = InvestigationMap(lambda _node_id: None)
        widget.set_model(events, "root", "a")
        colors = {tile.label: tile.color for tile in widget.tiles}
        self.assertEqual(colors, {"a": baobab_hex(0), "b": baobab_hex(100)})
        self.assertEqual(colors["a"], "#e01b24")
        self.assertEqual(colors["b"], "#33d17a")
        self.assertIn("Color = position/depth", widget.tile_tooltip(widget.tiles[0]))
        for tile, button in widget.tile_buttons:
            background = button.get_style_context().get_background_color(Gtk.StateFlags.NORMAL)
            actual = tuple(round(getattr(background, channel) * 255) for channel in ("red", "green", "blue"))
            expected = tuple(int(tile.color[index:index + 2], 16) for index in (1, 3, 5))
            self.assertEqual(actual, expected)
        events[1]["status"] = "not_started"
        events[2]["status"] = "blocked"
        widget.set_model(events, "root", "a")
        self.assertEqual({tile.label: tile.color for tile in widget.tiles}, colors)
        self.assertEqual(readable_text_color("#f6d32d"), "#202020")
        self.assertEqual(readable_text_color("#e01b24"), "#ffffff")

    def test_resize_reuses_tile_buttons(self):
        events = [
            {"id": "root", "parent_id": None, "label": "root", "type": "artifact", "status": "not_started"},
            {"id": "a", "parent_id": "root", "label": "a", "type": "artifact", "status": "partial"},
            {"id": "b", "parent_id": "root", "label": "b", "type": "artifact", "status": "reviewed"},
        ]
        widget = InvestigationMap(lambda _node_id: None)
        widget.set_model(events, "root", "a")
        buttons = {tile.event["id"]: button for tile, button in widget.tile_buttons}
        widget.last_size = None
        widget.rebuild()
        self.assertFalse(hasattr(widget, "resize_id"))
        self.assertEqual(widget.selected_id, "a")
        for tile, button in widget.tile_buttons:
            self.assertIs(button, buttons[tile.event["id"]])
        widget.destroy()

    def test_map_selection_and_pagination(self):
        selected = []
        widget = InvestigationMap(selected.append)
        events = [{"id": "root", "parent_id": None, "label": "root", "type": "artifact", "status": "not_started"}]
        events.extend(
            {"id": f"artifact:{index}", "parent_id": "root", "label": f"artifact:{index}", "type": "artifact", "status": "not_started"}
            for index in range(25)
        )
        widget.set_model(events, "root", "artifact:0")
        self.assertEqual(len(widget.tiles), PAGE_SIZE + 1)
        self.assertTrue(widget.tiles[-1].other)
        self.assertEqual(widget.tiles[-1].color, "#6a737d")
        widget.activate_tile(widget.tiles[-1])
        self.assertEqual(widget.offset, PAGE_SIZE)
        self.assertEqual(len(widget.tiles), 5)
        widget.activate_tile(widget.tiles[0])
        self.assertEqual(selected, ["artifact:5"])

    def test_map_resize_rebuilds_realized_tiles(self):
        widget = InvestigationMap(lambda _node_id: None)
        events = [
            {"id": "root", "parent_id": None, "label": "root", "type": "artifact", "status": "not_started"},
            {"id": "a", "parent_id": "root", "label": "a", "type": "artifact", "status": "partial"},
            {"id": "b", "parent_id": "root", "label": "b", "type": "artifact", "status": "reviewed"},
        ]
        widget.set_model(events, "root", "a")
        window = Gtk.Window()
        window.set_default_size(640, 480)
        window.add(widget)
        window.show_all()
        for width, height in ((640, 480), (480, 360)):
            window.resize(width, height)
            def rendered():
                return widget.last_size == (width, height) and all(
                    (
                        button.get_allocation().x, button.get_allocation().y,
                        button.get_allocation().width, button.get_allocation().height,
                    ) == (int(tile.x), int(tile.y), int(tile.width), int(tile.height))
                    for tile, button in widget.tile_buttons
                )

            deadline = time.monotonic() + 2
            while not rendered():
                if time.monotonic() >= deadline:
                    self.fail(
                        f"tiles were not allocated at {width}x{height}; last_size={widget.last_size}; "
                        f"allocation={widget.get_allocated_width()}x{widget.get_allocated_height()}; "
                        f"tiles={[(tile.label, tile.x, tile.y, tile.width, tile.height) for tile in widget.tiles]}; "
                        f"buttons={[(button.get_allocation().x, button.get_allocation().y, button.get_allocation().width, button.get_allocation().height) for _tile, button in widget.tile_buttons]}"
                    )
                GLib.MainContext.default().iteration(False)
                time.sleep(0.005)
            self.assertEqual([tile.label for tile in widget.tiles], ["a", "b"])
            self.assertEqual(widget.selected_id, "a")
            self.assertEqual([tile.weight for tile in widget.tiles], [1, 1])
            for tile, button in widget.tile_buttons:
                allocation = button.get_allocation()
                self.assertEqual(
                    (allocation.x, allocation.y, allocation.width, allocation.height),
                    (int(tile.x), int(tile.y), int(tile.width), int(tile.height)),
                )
                self.assertGreater(allocation.width, 100)
        window.destroy()

    def test_deep_map_model_does_not_recurse(self):
        events = [{"id": "root", "parent_id": None, "label": "root", "type": "artifact", "status": "not_started"}]
        for index in range(1, 1500):
            events.append({
                "id": f"node:{index}", "parent_id": "root" if index == 1 else f"node:{index - 1}",
                "label": f"node:{index}", "type": "function", "status": "in_progress",
            })
        widget = InvestigationMap(lambda _node_id: None)
        widget.set_model(events, "root", "node:1499")
        self.assertEqual(widget.counts["root"], 1499)
        self.assertEqual(widget.counts["node:1"], 1498)


class RingCase(unittest.TestCase):
    @staticmethod
    def events():
        return [
            {"id": "root", "parent_id": None, "label": "root", "type": "artifact", "status": "not_started"},
            {"id": "a", "parent_id": "root", "label": "a", "type": "artifact", "status": "partial"},
            {"id": "a1", "parent_id": "a", "label": "a1", "type": "function", "status": "in_progress"},
            {"id": "a2", "parent_id": "a", "label": "a2", "type": "function", "status": "blocked"},
            {"id": "b", "parent_id": "root", "label": "b", "type": "artifact", "status": "reviewed"},
        ]

    def test_baobab_geometry_weights_limits_and_deep_models(self):
        layout = ring_layout(self.events(), "root", 800, 600)
        self.assertEqual(layout.root.weight, 5)
        by_id = {sector.event["id"]: sector for sector in layout.sectors}
        self.assertAlmostEqual(by_id["a"].angle, TAU * 3 / 5)
        self.assertAlmostEqual(by_id["b"].angle, TAU / 5)
        self.assertEqual(by_id["a1"].depth, 2)
        self.assertEqual(layout.omitted, 0)
        self.assertEqual(sector_at(layout, layout.center_x, layout.center_y).event["id"], "root")
        self.assertIsNone(sector_at(layout, 0, 0))
        point = (
            layout.center_x + layout.root.outer_radius * 1.5 * 0.8,
            layout.center_y + layout.root.outer_radius * 1.5 * 0.6,
        )
        self.assertEqual(sector_at(layout, *point).event["id"], "a")
        shallow = ring_layout(self.events(), "root", 800, 600, max_depth=1)
        self.assertEqual(shallow.omitted, 2)
        self.assertTrue(next(sector for sector in shallow.sectors if sector.event["id"] == "a").continued)
        many = [{"id": "root", "parent_id": None, "label": "root", "type": "artifact", "status": "not_started"}]
        many.extend(
            {"id": f"node:{index}", "parent_id": "root", "label": f"node:{index}", "type": "artifact", "status": "not_started"}
            for index in range(250)
        )
        crowded = ring_layout(many, "root", 800, 600)
        self.assertEqual(len(crowded.sectors), 1)
        self.assertEqual(crowded.omitted, 250)
        self.assertLess(TAU / 251, MIN_ANGLE)
        self.assertIsNone(ring_layout([], "missing", 800, 600).root)
        self.assertIsNone(ring_layout(self.events(), "root", 0, 0).root)
        self.assertEqual(len(sector_color(0, 1)), 3)
        deep = [{"id": "root", "parent_id": None, "label": "root", "type": "artifact", "status": "not_started"}]
        deep.extend(
            {"id": f"node:{index}", "parent_id": "root" if index == 1 else f"node:{index - 1}", "label": f"node:{index}", "type": "function", "status": "in_progress"}
            for index in range(1, 1500)
        )
        deep_layout = ring_layout(deep, "root", 800, 600)
        self.assertEqual(max(sector.depth for sector in deep_layout.sectors), MAX_DEPTH)
        self.assertTrue(deep_layout.sectors[-1].continued)
        self.assertEqual(deep_layout.omitted, 1494)

    def test_real_cairo_render_hit_testing_keyboard_and_resize(self):
        import cairo
        import math

        selected = []
        summaries = []
        widget = InvestigationRings(selected.append, summaries.append)
        events = self.events()
        widget.set_model(events, "root", "root")
        window = Gtk.Window()
        window.set_default_size(640, 480)
        window.add(widget)
        window.show_all()
        context = GLib.MainContext.default()
        deadline = time.monotonic() + 0.2
        while time.monotonic() < deadline:
            context.iteration(False)
            time.sleep(0.005)
        try:
            self.assertEqual(len(widget.sectors), 5)
            self.assertTrue(widget.get_hexpand())
            self.assertTrue(widget.get_vexpand())
            self.assertGreater(widget.get_allocated_height(), 400)
            self.assertEqual(summaries[-1], 0)
            self.assertIn("not bytes", widget.get_accessible().get_description())
            layout = widget.update_layout()
            radius = layout.root.outer_radius * 1.5
            point = (layout.center_x + radius * 0.8, layout.center_y + radius * 0.6)
            widget.on_motion(widget, mock.Mock(x=point[0], y=point[1]))
            self.assertEqual(widget.hovered_id, "a")
            self.assertIn("Subtree: 3 nodes", widget.get_tooltip_text())
            widget.on_leave(widget)
            self.assertIsNone(widget.hovered_id)
            widget.on_button(widget, mock.Mock(button=1, x=point[0], y=point[1]))
            self.assertEqual(selected, ["a"])
            widget.set_model(events, "a", "a")
            widget.on_key(widget, mock.Mock(keyval=Gdk.keyval_from_name("Return")))
            self.assertEqual(selected, ["a", "root"])
            widget.set_model(events, "root", "root")
            widget.set_depth(1)
            self.assertEqual(widget.omitted, 2)
            self.assertEqual(summaries[-1], 2)
            widget.on_scroll(widget, mock.Mock(delta_y=-1))
            self.assertEqual(widget.max_depth, 2)
            self.assertEqual(widget.omitted, 0)
            self.assertEqual(summaries[-1], 0)
            widget.set_depth(MAX_DEPTH)
            surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, widget.get_allocated_width(), widget.get_allocated_height())
            widget.draw(cairo.Context(surface))
            self.assertGreater(len(set(surface.get_data())), 3)
            window.resize(480, 360)
            deadline = time.monotonic() + 1
            while widget.get_allocated_width() != 480 and time.monotonic() < deadline:
                context.iteration(False)
                time.sleep(0.005)
            resized = widget.update_layout()
            self.assertAlmostEqual(resized.center_x, widget.get_allocated_width() / 2)
            self.assertAlmostEqual(resized.center_y, widget.get_allocated_height() / 2)
            self.assertEqual(len(widget.sectors), 5)
        finally:
            window.destroy()
            deadline = time.monotonic() + 0.05
            while time.monotonic() < deadline:
                context.iteration(False)
                time.sleep(0.005)


if __name__ == "__main__":
    if not os.environ.get("DISPLAY"):
        raise SystemExit("GTK stress tests require an X11 DISPLAY")
    unittest.main(verbosity=2)
