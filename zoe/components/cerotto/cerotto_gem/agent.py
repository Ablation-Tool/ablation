"""Optional VTE agent terminal with bounded shutdown."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import time

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

try:
    gi.require_version("Vte", "2.91")
    from gi.repository import Vte
except (ImportError, ValueError):
    Vte = None


class AgentTerminal(Gtk.Box):
    def __init__(self, command: list[str], workspace: Path, environment: dict[str, str]):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.command = command
        self.workspace = workspace
        self.environment = environment
        self.agent_pid = None
        self.closed = False
        self.status = Gtk.Label(xalign=0)
        self.status.set_line_wrap(True)
        self.status.set_text("Unguarded agent terminal. Native guard policy applies only to cerotto guard actions.")
        self.pack_start(self.status, False, False, 4)
        self.terminal = None
        if Vte is None:
            self.status.set_text("VTE is unavailable. Install the VTE 2.91 GI bindings to embed an agent.")
            return
        self.terminal = Vte.Terminal()
        self.terminal.set_scrollback_lines(2000)
        self.terminal.set_scroll_on_keystroke(True)
        self.terminal.set_scroll_on_output(False)
        self.terminal.set_hexpand(True)
        self.terminal.set_vexpand(True)
        self.terminal.get_accessible().set_name("Embedded AI agent terminal")
        self.terminal.get_accessible().set_description(
            "Interactive unguarded agent CLI. Use the native guard command for policy-enforced evidence actions."
        )
        self.terminal.connect("child-exited", self._child_exited)
        self.pack_start(self.terminal, True, True, 0)

    def start(self) -> None:
        if self.closed or self.terminal is None or self.agent_pid is not None:
            return
        environment = [f"{name}={value}" for name, value in self.environment.items()]
        try:
            success, self.agent_pid = self.terminal.spawn_sync(
                Vte.PtyFlags.DEFAULT, str(self.workspace), self.command, environment,
                GLib.SpawnFlags.SEARCH_PATH, None, None, None,
            )
            if not success:
                raise RuntimeError("VTE could not start the configured agent")
            self.status.set_text(
                f"Unguarded agent: {Path(self.command[0]).name}. Native guard policy applies only to cerotto guard actions."
            )
        except (GLib.Error, OSError, RuntimeError) as exc:
            self.agent_pid = None
            self.status.set_text(f"Unable to start agent: {exc}")

    def _child_exited(self, _terminal, _status) -> None:
        self.agent_pid = None
        if not self.closed:
            self.status.set_text("Agent exited. Close and reopen the workbench to start it again.")

    def stop(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.agent_pid is not None:
            try:
                os.killpg(self.agent_pid, signal.SIGHUP)
            except ProcessLookupError:
                self.agent_pid = None
        deadline = time.monotonic() + 2.0
        killed = False
        context = GLib.MainContext.default()
        while self.agent_pid is not None and time.monotonic() < deadline:
            if not killed and time.monotonic() > deadline - 1.75:
                try:
                    os.killpg(self.agent_pid, signal.SIGKILL)
                except ProcessLookupError:
                    self.agent_pid = None
                    break
                killed = True
            while context.pending():
                context.iteration(False)
            time.sleep(0.01)
