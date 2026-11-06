"""Native GTK workbench for CEROTTO cases and guarded defense evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import threading

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, Gio, GLib, Gtk

from .agent import AgentTerminal
from .chart import ForecastChart
from .commands import CommandError, CommandRunner
from .model import CaseEvent, CaseModel
from .vault_view import VaultView


class CerottoGemWindow(Gtk.ApplicationWindow):
    def __init__(self, application, model: CaseModel, commands: CommandRunner,
                 agent_command: list[str] | None = None, workspace: Path | None = None):
        super().__init__(application=application)
        self.model = model
        self.commands = commands
        self.agent_command = agent_command
        self.workspace = workspace or model.database.parent
        self.snapshot = None
        self.events = {}
        self.closed = False
        self.busy = False
        self.agent = None
        self.set_title("CEROTTO GEM")
        self.set_default_size(1500, 900)
        self.set_position(Gtk.WindowPosition.CENTER)
        self._build()
        self.connect("delete-event", self._delete)
        self.reload()

    def _button(self, label: str, callback) -> Gtk.Button:
        button = Gtk.Button(label=label)
        button.connect("clicked", callback)
        return button

    def _build(self) -> None:
        header = Gtk.HeaderBar(show_close_button=True)
        header.set_title("CEROTTO GEM")
        header.set_subtitle(f"{self.model.case_id} / {self.model.conversation_id}")
        self.set_titlebar(header)
        self.refresh_button = self._button("Refresh", lambda _button: self.reload())
        self.guard_button = self._button("Run Guard", self.run_guard)
        self.verify_button = self._button("Verify Case", self.verify_case)
        self.report_button = self._button("Export Report", self.export_report)
        header.pack_start(self.refresh_button)
        header.pack_start(self.guard_button)
        header.pack_start(self.verify_button)
        header.pack_end(self.report_button)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.add(outer)
        self.panes = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.panes.set_position(560)
        outer.pack_start(self.panes, True, True, 0)
        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        left.set_size_request(480, -1)
        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Filter events, actions, hosts, or evidence")
        self.search.connect("changed", lambda _entry: self.populate_tree())
        left.pack_start(self.search, False, False, 5)
        self.store = Gtk.TreeStore(str, str, str, str, str, str)
        self.tree = Gtk.TreeView(model=self.store)
        self.tree.set_headers_visible(True)
        self.tree.get_selection().connect("changed", self.select_event)
        for title, column, expand in (
            ("Lab", 0, True), ("Status", 2, False), ("Observed", 4, False),
        ):
            renderer = Gtk.CellRendererText()
            renderer.set_property("ellipsize", 3)
            view_column = Gtk.TreeViewColumn(title, renderer, text=column)
            view_column.set_expand(expand)
            view_column.set_resizable(True)
            if column == 2:
                view_column.set_min_width(90)
            elif column == 4:
                view_column.set_min_width(110)
            self.tree.append_column(view_column)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.add(self.tree)
        left.pack_start(scroller, True, True, 0)
        self.panes.pack1(left)
        self.notebook = Gtk.Notebook()
        self.panes.pack2(self.notebook)
        self.details = Gtk.TextView()
        self.details.set_editable(False)
        self.details.set_cursor_visible(False)
        self.details.set_monospace(True)
        self.details.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        details_scroller = Gtk.ScrolledWindow()
        details_scroller.add(self.details)
        self.notebook.append_page(details_scroller, Gtk.Label(label="Details"))
        self.chart = ForecastChart()
        self.notebook.append_page(self.chart, Gtk.Label(label="Accessible Volume"))
        self.vault_view = VaultView()
        self.notebook.append_page(self.vault_view, Gtk.Label(label="Vault"))
        if self.agent_command:
            environment = os.environ.copy()
            environment.update({
                "CEROTTO_DB": str(self.model.database),
                "CEROTTO_CASE": self.model.case_id,
                "CEROTTO_CONVERSATION": self.model.conversation_id,
                "CEROTTO_BINARY": str(self.commands.binary),
                "CEROTTO_GEM": "1",
            })
            self.agent = AgentTerminal(self.agent_command, self.workspace, environment)
            self.notebook.append_page(self.agent, Gtk.Label(label="AI Agent"))
        self.status = Gtk.Label(xalign=0)
        self.status.set_margin_start(8)
        self.status.set_margin_end(8)
        self.status.set_margin_top(5)
        self.status.set_margin_bottom(5)
        outer.pack_end(self.status, False, False, 0)

    def reload(self) -> None:
        if self.closed:
            return
        try:
            selected = self.selected_event_id()
            self.snapshot = self.model.load()
            self.events = {event.event_id: event for event in self.snapshot.events}
            self.vault_view.set_events(self.snapshot.events)
            self.populate_tree(selected)
            counts = {}
            for event in self.snapshot.events:
                counts[event.status] = counts.get(event.status, 0) + 1
            summary = ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
            self.status.set_text(
                f"{len(self.snapshot.events)} events | {len(self.snapshot.sources)} sources | {summary or 'no events'}"
            )
        except (OSError, RuntimeError, ValueError) as exc:
            self.show_error("Unable to load case", exc)

    @staticmethod
    def _chain_status(events: list[CaseEvent]) -> str:
        statuses = {event.status for event in events}
        if "failed" in statuses:
            return "failed"
        if "deny" in statuses:
            return "deny"
        if "succeeded" in statuses:
            return "succeeded"
        return "proposed"

    def populate_tree(self, selected: str | None = None) -> None:
        if self.snapshot is None:
            return
        self.store.clear()
        query = self.search.get_text().strip().casefold()
        root = self.store.append(None, [
            f"{self.snapshot.case_id} / {self.snapshot.conversation_id}",
            "case", "active", "", "", "",
        ])
        chains = {}
        ungrouped = []
        for event in self.snapshot.events:
            if event.tool_call_id:
                chains.setdefault(event.tool_call_id, []).append(event)
            else:
                ungrouped.append(event)
        for action_id, events in sorted(chains.items(), key=lambda item: min(event.observed_at for event in item[1])):
            matching = [event for event in events if self.matches(event, query)]
            if query and not matching and query not in action_id.casefold():
                continue
            first = min(event.observed_at for event in events)
            group = self.store.append(root, [
                f"Action {action_id}", "guard_chain", self._chain_status(events),
                events[0].host_id, first[5:16].replace("T", " "), "",
            ])
            for event in events:
                if query and not self.matches(event, query) and query not in action_id.casefold():
                    continue
                self.store.append(group, self.row(event))
        for event in ungrouped:
            if self.matches(event, query):
                self.store.append(root, self.row(event))
        self.tree.expand_all()
        if not self.restore_selection(selected):
            self.select_first_forecast()
        self.update_status_filter(query)

    @staticmethod
    def row(event: CaseEvent) -> list[str]:
        return [
            event.label, event.event_type, event.status, event.host_id,
            event.observed_at[5:16].replace("T", " "), event.event_id,
        ]

    @staticmethod
    def matches(event: CaseEvent, query: str) -> bool:
        if not query:
            return True
        text = " ".join((event.event_id, event.label, event.event_type, event.host_id,
                         event.tool_call_id, json.dumps(event.details, ensure_ascii=False))).casefold()
        return query in text

    def update_status_filter(self, query: str) -> None:
        if query and self.snapshot is not None:
            self.status.set_text(f"Filter: {query} | {len(self.snapshot.events)} events in case")

    def restore_selection(self, event_id: str | None) -> bool:
        if not event_id or event_id not in self.events:
            return False
        return self.select_by_id(event_id)

    def select_by_id(self, event_id: str) -> bool:
        selected = []
        def visit(_model, _path, iterator):
            if self.store.get_value(iterator, 5) == event_id:
                selected.append(iterator)
                return True
            return False
        self.store.foreach(visit)
        if not selected:
            return False
        iterator = selected[0]
        self.tree.get_selection().select_iter(iterator)
        path = self.store.get_path(iterator)
        self.tree.expand_to_path(path)
        self.tree.scroll_to_cell(path, None, False, 0, 0)
        return True

    def select_first_forecast(self) -> bool:
        for event in self.events.values():
            if event.event_type == "model_forecast":
                return self.select_by_id(event.event_id)
        if self.events:
            return self.select_by_id(next(iter(self.events)))
        return False

    def selected_event_id(self) -> str | None:
        _model, iterator = self.tree.get_selection().get_selected()
        return self.store.get_value(iterator, 5) if iterator else None

    def select_event(self, _selection) -> None:
        event = self.events.get(self.selected_event_id())
        if event is None:
            self.details.get_buffer().set_text("Select an event to inspect its evidence.")
            self.chart.set_event(None)
            return
        self.details.get_buffer().set_text(json.dumps(event.as_dict(), indent=2, ensure_ascii=False))
        self.chart.set_event(event)
        self.notebook.set_current_page(1 if event.event_type == "model_forecast" else 0)

    def set_busy(self, busy: bool) -> None:
        self.busy = busy
        for button in (self.refresh_button, self.guard_button, self.verify_button, self.report_button):
            button.set_sensitive(not busy)

    def run_async(self, operation, completion) -> None:
        if self.busy or self.closed:
            return
        self.set_busy(True)
        def worker():
            result = None
            error = None
            try:
                result = operation()
            except (CommandError, OSError, RuntimeError, ValueError) as exc:
                error = exc
            GLib.idle_add(finish, result, error)
        def finish(result, error):
            if not self.closed:
                self.set_busy(False)
                if error is not None:
                    self.show_error("Native command failed", error)
                else:
                    completion(result)
            return False
        threading.Thread(target=worker, daemon=True).start()

    def run_guard(self, _button) -> None:
        chooser = Gtk.FileChooserDialog(
            title="Select a native guard proposal", transient_for=self,
            action=Gtk.FileChooserAction.OPEN,
        )
        chooser.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Run Guard", Gtk.ResponseType.ACCEPT)
        chooser.add_filter(self.json_filter())
        response = chooser.run()
        filename = chooser.get_filename()
        chooser.destroy()
        if response != Gtk.ResponseType.ACCEPT or not filename:
            return
        proposal = Path(filename).resolve()
        output = proposal.with_name(proposal.stem + "-guard-result.json")
        self.run_async(
            lambda: self.commands.guard(self.model.database, self.model.case_id, proposal, output),
            self.guard_completed,
        )

    def guard_completed(self, result) -> None:
        document = result.document
        self.show_information(
            "Guard decision",
            f"Decision: {document.get('decision', 'unknown')}\nReason: {document.get('reason', 'unknown')}\n"
            f"Executed: {document.get('executed', False)}\nSucceeded: {document.get('succeeded', False)}",
        )
        self.reload()

    def verify_case(self, _button) -> None:
        self.run_async(
            lambda: self.commands.verify(self.model.database, self.model.case_id),
            self.verify_completed,
        )

    def verify_completed(self, result) -> None:
        self.show_information("Case verification", json.dumps(result.document, indent=2))

    @staticmethod
    def json_filter():
        filter_ = Gtk.FileFilter()
        filter_.set_name("JSON documents")
        filter_.add_pattern("*.json")
        return filter_

    def export_report(self, _button) -> None:
        chooser = Gtk.FileChooserDialog(
            title="Export JSON investigation report", transient_for=self,
            action=Gtk.FileChooserAction.SAVE,
        )
        chooser.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Export", Gtk.ResponseType.ACCEPT)
        chooser.set_do_overwrite_confirmation(True)
        chooser.set_current_name("cerotto-report.json")
        chooser.add_filter(self.json_filter())
        response = chooser.run()
        filename = chooser.get_filename()
        chooser.destroy()
        if response != Gtk.ResponseType.ACCEPT or not filename:
            return
        output = Path(filename).resolve()
        self.run_async(
            lambda: self.commands.report(self.model.database, self.model.case_id, self.model.conversation_id, output),
            lambda _result: self.show_information("Report exported", str(output)),
        )

    def show_error(self, title: str, error: Exception) -> None:
        if self.closed:
            return
        dialog = Gtk.MessageDialog(
            transient_for=self, modal=True, message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK, text=title,
        )
        dialog.format_secondary_text(str(error)[:4000])
        dialog.run()
        dialog.destroy()

    def show_information(self, title: str, text: str) -> None:
        if self.closed:
            return
        dialog = Gtk.MessageDialog(
            transient_for=self, modal=True, message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK, text=title,
        )
        dialog.format_secondary_text(text[:6000])
        dialog.run()
        dialog.destroy()

    def _delete(self, *_args):
        self.close()
        return False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.commands.cancel_all()
        if self.agent is not None:
            self.agent.stop()

    def self_test(self, screenshot: Path | None = None) -> bool:
        try:
            if self.snapshot is None or not self.events:
                raise RuntimeError("self-test requires case events")
            if not self.select_first_forecast():
                raise RuntimeError("self-test could not select a forecast")
            if not self.chart.series:
                raise RuntimeError("self-test requires an accessible-volume sweep")
            if self.notebook.get_n_pages() < 3 or "vault events" not in self.vault_view.summary.get_text():
                raise RuntimeError("self-test vault view did not initialize")
            self.notebook.set_current_page(1)
            if self.agent_command and self.agent and self.agent.agent_pid is None:
                raise RuntimeError("self-test agent did not start")
            self.show_all()
            GLib.timeout_add(250, self.finish_self_test, screenshot)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"CEROTTO_GEM_SELF_TEST_FAIL: {exc}", file=sys.stderr, flush=True)
            self.get_application().exit(1)
        return False

    def finish_self_test(self, screenshot: Path | None) -> bool:
        try:
            if screenshot is not None:
                window = self.get_window()
                width, height = window.get_width(), window.get_height()
                pixbuf = Gdk.pixbuf_get_from_window(window, 0, 0, width, height)
                if pixbuf is None:
                    raise RuntimeError("could not capture the workbench window")
                pixbuf.savev(str(screenshot), "png", [], [])
            summary = {
                "self_test": "passed",
                "events": len(self.events),
                "forecast_points": len(self.chart.series),
                "agent_pid": self.agent.agent_pid if self.agent else None,
                "screenshot": str(screenshot) if screenshot else None,
            }
            print(json.dumps(summary, sort_keys=True), flush=True)
            self.close()
            self.get_application().quit()
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"CEROTTO_GEM_SELF_TEST_FAIL: {exc}", file=sys.stderr, flush=True)
            self.get_application().exit(1)
        return False


class CerottoGemApplication(Gtk.Application):
    def __init__(self, model: CaseModel, commands: CommandRunner,
                 agent_command: list[str] | None = None, workspace: Path | None = None):
        super().__init__(application_id="org.cerotto.Gem", flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.model = model
        self.commands = commands
        self.agent_command = agent_command
        self.workspace = workspace
        self.window = None
        self.agent_started = False

    def do_activate(self):
        if self.window is None:
            self.window = CerottoGemWindow(self, self.model, self.commands, self.agent_command, self.workspace)
        self.window.show_all()
        self.window.present()
        if self.window.agent is not None and not self.agent_started:
            self.agent_started = True
            self.window.agent.start()
        Gtk.Application.do_activate(self)

    def do_shutdown(self):
        if self.window is not None:
            self.window.close()
        Gtk.Application.do_shutdown(self)
