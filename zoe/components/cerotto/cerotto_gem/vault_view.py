"""Native GTK Vault-event timeline widget."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from .vault import vault_events, vault_summary


class VaultView(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.summary = Gtk.Label(xalign=0)
        self.summary.set_margin_start(8)
        self.summary.set_margin_top(8)
        self.pack_start(self.summary, False, False, 0)
        self.store = Gtk.ListStore(str, str, str, str, str)
        tree = Gtk.TreeView(model=self.store)
        for index, title in enumerate(("Observed", "Event", "Path", "Attribution", "Consent")):
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(title, renderer, text=index)
            column.set_resizable(True)
            column.set_expand(index in {1, 2})
            tree.append_column(column)
        tree.get_accessible().set_name("Vault event timeline")
        tree.get_accessible().set_description(
            "Native vault access, health, release, correlation, and response events."
        )
        scroller = Gtk.ScrolledWindow()
        scroller.add(tree)
        self.pack_start(scroller, True, True, 0)

    def set_events(self, events) -> None:
        selected = vault_events(events)
        summary = vault_summary(selected)
        self.summary.set_text(
            f"{summary['events']} vault events | {summary['contacts']} contacts | "
            f"{summary['modifications']} modifications | {summary['denied_releases']} denied releases | "
            f"{summary['health_alerts']} health alerts | {summary['responses']} responses"
        )
        self.store.clear()
        for event in selected:
            self.store.append([
                event.observed_at, event.event_type, event.path or "(no path)",
                str(event.details.get("attribution", "unresolved")),
                str(event.details.get("consent", "unknown")),
            ])
