import copy
import csv
import errno
import json
import os
from pathlib import Path
import shlex
import signal
import struct
import subprocess
import sys
import time
import queue
import threading
import tkinter as tk

if os.name == "nt":
    pty = None
    termios = None
else:
    import pty
    import termios
from tkinter import filedialog, font as tkfont, ttk

from .agent import parse_agent_command
from .inventory import load_records
from .render import load_summary


try:
    import pyte
except ImportError:
    pyte = None


if pyte is not None:
    class TerminalScreen(pyte.HistoryScreen):
        def report_device_status(self, mode, private=False):
            super().report_device_status(mode)


FG_COLORS = {
    "default": "#e6edf3", "black": "#0c1118", "red": "#ff7b72",
    "green": "#7ee787", "yellow": "#f2cc60", "blue": "#71b7ff",
    "magenta": "#d2a8ff", "cyan": "#76d7ea", "white": "#f0f6fc",
    "brightblack": "#7d8590", "brightred": "#ffa198",
    "brightgreen": "#aff5b4", "brightyellow": "#ffe38f",
    "brightblue": "#a5d6ff", "brightmagenta": "#e2c5ff",
    "brightcyan": "#a5f3fc", "brightwhite": "#ffffff",
}
BG_COLORS = {**FG_COLORS, "default": "#0c1118", "black": "#0c1118"}
KEY_SEQUENCES = {
    "BackSpace": b"\x7f", "Delete": b"\x1b[3~", "Return": b"\r",
    "KP_Enter": b"\r", "Tab": b"\t", "Up": b"\x1b[A", "Down": b"\x1b[B",
    "Right": b"\x1b[C", "Left": b"\x1b[D", "Home": b"\x1b[H",
    "End": b"\x1b[F", "Prior": b"\x1b[5~", "Next": b"\x1b[6~",
    "Insert": b"\x1b[2~", "Escape": b"\x1b",
}
for index in range(1, 13):
    KEY_SEQUENCES[f"F{index}"] = f"\x1bO{chr(ord('P') + index - 1)}".encode()


def human_size(value):
    if value is None:
        return "—"
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    index = 0
    while amount >= 1024 and index < len(units) - 1:
        amount /= 1024
        index += 1
    return f"{amount:.1f} {units[index]}" if index else f"{int(amount)} {units[index]}"


class TerminalPanel(ttk.Frame):
    def __init__(self, parent, output, workspace, command, status_callback):
        super().__init__(parent)
        if pyte is None:
            raise ValueError("The embedded terminal requires pyte. Install with: python3 -m pip install -e '.[desktop]'")
        self.output = output
        self.workspace = workspace
        self.command = command
        self.status_callback = status_callback
        self.process = None
        self.fd = None
        self.read_queue = None
        self.reader_thread = None
        self.reader_eof = False
        self.exited = False
        self.reaped = False
        self.write_queue = bytearray()
        self.write_after_id = None
        self.parser_warning = None
        self.screen = TerminalScreen(80, 24, history=1000)
        self.stream = pyte.ByteStream(self.screen)
        self.columns = 80
        self.lines = 24
        self.tag_cache = set()
        self.font_family = tkfont.nametofont("TkFixedFont").cget("family")
        self.font_size = 10
        self.text = tk.Text(
            self, bg=BG_COLORS["default"], fg=FG_COLORS["default"],
            insertwidth=0, wrap="none", undo=False, takefocus=True,
            font=(self.font_family, self.font_size), borderwidth=0,
        )
        self.text.pack(fill="both", expand=True)
        self.text.bind("<Key>", self.on_key)
        self.text.bind("<Configure>", self.on_resize)
        self.text.bind("<Button-4>", lambda event: self.scroll_history(-1))
        self.text.bind("<Button-5>", lambda event: self.scroll_history(1))
        self.text.bind("<MouseWheel>", self.on_mousewheel)
        self.text.bind("<Control-Shift-C>", lambda event: self.text.event_generate("<<Copy>>") or "break")
        self.text.bind("<Control-Shift-V>", lambda event: self.paste())
        self.text.bind("<<Paste>>", lambda event: self.paste())
        self.text.bind("<<Cut>>", lambda event: "break")
        self.text.bind("<<Clear>>", lambda event: "break")
        self.text.bind("<Button-2>", lambda event: "break")
        self.text.bind("<Button-1>", lambda event: self.text.focus_set())
        self.closed = False
        self.poll_after_id = None
        self.render_after_id = None
        if command:
            self.after_idle(self.start)
        else:
            self.text.insert("1.0", "No external CLI configured.\nRestart with --agent kimi or --agent-command.")
            self.text.configure(state="disabled")
        self.poll_after_id = self.after(30, self.poll)
        self.render_after_id = self.after(60, self.render)

    def start(self):
        if self.closed or self.process is not None:
            return
        environment = os.environ.copy()
        package_root = str(Path(__file__).resolve().parent.parent)
        environment.update({
            "TERM": "xterm-256color", "COLORTERM": "truecolor",
            "METRIX_OUTPUT": str(self.output), "METRIX_WORKSPACE": str(self.workspace),
            "METRIX_CLI": subprocess.list2cmdline([sys.executable, "-m", "metrix"]) if os.name == "nt" else shlex.join([sys.executable, "-m", "metrix"]),
            "PYTHONPATH": package_root + (os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""),
        })
        if os.name == "nt":
            try:
                from winpty import PtyProcess
                self.process = PtyProcess.spawn(
                    self.command, cwd=str(self.workspace), env=environment,
                    dimensions=(self.lines, self.columns),
                )
            except (ImportError, OSError, RuntimeError) as error:
                self.status_callback(f"Unable to start CLI: {error}")
                return
            self.fd = True
            self.read_queue = queue.Queue()
            self.reader_thread = threading.Thread(target=self._read_windows, daemon=True)
            self.reader_thread.start()
        else:
            try:
                pid, descriptor = pty.fork()
            except OSError as error:
                self.status_callback(f"Unable to start CLI: {error}")
                return
            if pid == 0:
                try:
                    os.chdir(self.workspace)
                    os.execvpe(self.command[0], self.command, environment)
                except BaseException as error:
                    os.write(2, f"Unable to start CLI: {error}\r\n".encode())
                    os._exit(127)
            self.process = pid
            self.fd = descriptor
            os.set_blocking(self.fd, False)
        terminal_kind = "ConPTY" if os.name == "nt" else "PTY"
        self.status_callback(f"Embedded CLI: {Path(self.command[0]).name} (interactive {terminal_kind})")
        self.text.focus_set()
        self.resize_terminal()

    def _read_windows(self):
        try:
            while True:
                data = self.process.read(65536)
                if not data:
                    break
                self.read_queue.put(data.encode("utf-8"))
        except (EOFError, OSError):
            pass
        finally:
            self.read_queue.put(None)

    def poll(self):
        if self.fd is not None:
            if os.name == "nt":
                while True:
                    try:
                        data = self.read_queue.get_nowait()
                    except queue.Empty:
                        break
                    if data is None:
                        self.reader_eof = True
                        break
                    self._feed(data)
            else:
                while True:
                    try:
                        data = os.read(self.fd, 65536)
                    except BlockingIOError:
                        break
                    except OSError as error:
                        if error.errno == errno.EIO:
                            self.finish("CLI session closed")
                            break
                        self.finish(f"CLI read error: {error}")
                        break
                    if not data:
                        self.finish("CLI session closed")
                        break
                    self._feed(data)
        if self.process is not None and not self.reaped:
            if os.name == "nt":
                if not self.process.isalive():
                    self.reaped = True
            else:
                try:
                    pid, status = os.waitpid(self.process, os.WNOHANG)
                except ChildProcessError:
                    pid, status = self.process, 0
                if pid:
                    self.reaped = True
                    code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else status
                    self.finish(f"CLI exited ({code})")
        if self.process is not None and os.name == "nt" and self.reaped and self.reader_eof:
            self.finish("CLI session closed")
        if not self.closed:
            self.poll_after_id = self.after(30, self.poll)

    def _feed(self, data):
        try:
            self.stream.feed(data)
        except Exception as error:
            warning = f"Terminal display warning: {error}"
            if warning != self.parser_warning:
                self.parser_warning = warning
                self.status_callback(warning)

    def finish(self, message):
        if self.exited:
            return
        self.exited = True
        if self.write_after_id is not None:
            try:
                self.after_cancel(self.write_after_id)
            except tk.TclError:
                pass
            self.write_after_id = None
        self.write_queue.clear()
        if self.fd is not None:
            if os.name != "nt":
                try:
                    os.close(self.fd)
                except OSError:
                    pass
            self.fd = None
        if not self.closed:
            self.status_callback(message)

    def signal_process(self, signal_number):
        if self.reaped:
            return
        if os.name == "nt":
            self.process.terminate(force=True)
            return
        try:
            os.killpg(self.process, signal_number)
        except ProcessLookupError:
            try:
                os.kill(self.process, signal_number)
            except ProcessLookupError:
                pass

    def wait_for_child(self, timeout):
        deadline = time.monotonic() + timeout
        if os.name == "nt":
            while self.process.isalive() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.reaped = not self.process.isalive()
            return self.reaped
        while True:
            try:
                pid, _ = os.waitpid(self.process, os.WNOHANG)
            except ChildProcessError:
                self.reaped = True
            if pid:
                self.reaped = True
            if self.reaped or time.monotonic() >= deadline:
                return self.reaped
            time.sleep(0.02)

    def stop(self):
        if self.closed:
            return
        self.closed = True
        for attribute in ("poll_after_id", "render_after_id", "write_after_id"):
            identifier = getattr(self, attribute)
            if identifier is not None:
                try:
                    self.after_cancel(identifier)
                except tk.TclError:
                    pass
                setattr(self, attribute, None)
        self.write_queue.clear()
        if self.process is not None and not self.reaped:
            self.signal_process(getattr(signal, "SIGHUP", signal.SIGINT))
            if not self.wait_for_child(1.0):
                self.signal_process(signal.SIGKILL)
                if not self.wait_for_child(1.0):
                    try:
                        self.status_callback(f"CLI process {self.process} could not be reaped; check the process table")
                    except tk.TclError:
                        pass
        if self.fd is not None:
            if os.name != "nt":
                try:
                    os.close(self.fd)
                except OSError:
                    pass
            self.fd = None
        if self.reader_thread is not None:
            self.reader_thread.join(timeout=1)
            self.reader_thread = None
        if os.name == "nt" and self.process is not None:
            self.process.close()
        self.exited = True

    def write(self, data):
        if self.fd is None or self.exited or self.closed:
            return
        self.write_queue.extend(data)
        self.flush_writes()

    def flush_writes(self):
        if self.write_after_id is not None:
            try:
                self.after_cancel(self.write_after_id)
            except tk.TclError:
                pass
            self.write_after_id = None
        if self.fd is None or self.exited or self.closed:
            return
        while self.write_queue:
            try:
                written = self.process.write(bytes(self.write_queue).decode("utf-8")) if os.name == "nt" else os.write(self.fd, self.write_queue)
            except BlockingIOError:
                break
            except OSError as error:
                self.finish(f"CLI write error: {error}")
                return
            if written <= 0:
                break
            del self.write_queue[:written]
        if self.write_queue and not self.closed:
            self.write_after_id = self.after(10, self.flush_writes)

    def on_key(self, event):
        if not self.command:
            return "break"
        self.text.focus_set()
        if event.state & 0x4 and len(event.keysym) == 1 and event.keysym.isascii() and event.keysym.isalpha():
            data = bytes([ord(event.keysym.casefold()) & 0x1F])
        elif event.keysym in KEY_SEQUENCES:
            data = KEY_SEQUENCES[event.keysym]
        elif event.char and event.char >= " " and event.keysym not in {"Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R"}:
            data = event.char.encode("utf-8")
        else:
            return "break"
        if event.state & 0x8:
            data = b"\x1b" + data
        self.write(data)
        return "break"

    def paste(self):
        try:
            value = self.clipboard_get()
        except tk.TclError:
            return "break"
        data = value.encode("utf-8")
        if len(data) > 8 * 1024 * 1024:
            self.status_callback("Paste rejected: 8 MiB maximum; use the CLI's file-input workflow")
            return "break"
        self.write(data)
        return "break"

    def scroll_history(self, direction):
        if direction < 0:
            self.screen.prev_page()
        else:
            self.screen.next_page()
        self.render(force=True)
        return "break"

    def on_mousewheel(self, event):
        return self.scroll_history(-1 if event.delta > 0 else 1)

    def on_resize(self, _event=None):
        self.resize_terminal()

    def resize_terminal(self):
        metrics = tkfont.Font(family=self.font_family, size=self.font_size)
        columns = max(20, self.text.winfo_width() // max(1, metrics.measure("M")))
        lines = max(4, self.text.winfo_height() // max(1, metrics.metrics("linespace")))
        if (columns, lines) == (self.columns, self.lines):
            return
        previous_lines = self.screen.lines
        previous_columns = self.screen.columns
        previous_cursor = copy.copy(self.screen.cursor)
        previous_buffer = copy.deepcopy(self.screen.buffer)
        previous_content = sum(bool(line.strip()) for line in self.screen.display)
        self.columns, self.lines = columns, lines
        self.screen.resize(lines, columns)
        if previous_content and lines < previous_lines:
            start = max(0, min(previous_cursor.y - lines + 1, previous_lines - lines))
            for line in range(lines):
                if start + line >= previous_lines:
                    break
                self.screen.buffer[line] = previous_buffer[start + line]
                for column in range(columns, previous_columns):
                    self.screen.buffer[line].pop(column, None)
            self.screen.cursor = previous_cursor
            self.screen.cursor.y = max(0, min(previous_cursor.y - start, lines - 1))
            self.screen.dirty.update(range(lines))
        if self.fd is not None:
            if os.name == "nt":
                self.process.setwinsize(lines, columns)
            else:
                import fcntl
                fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", lines, columns, 0, 0))
        self.render(force=True)

    def style_tag(self, character):
        foreground = FG_COLORS.get(character.fg, FG_COLORS["default"])
        background = BG_COLORS.get(character.bg, BG_COLORS["default"])
        if character.reverse:
            foreground, background = background, foreground
        key = (foreground, background, character.bold, character.italics, character.underscore, character.strikethrough)
        name = "style-" + "-".join(str(value) for value in key)
        if name not in self.tag_cache:
            font = tkfont.Font(family=self.font_family, size=self.font_size, weight="bold" if character.bold else "normal", slant="italic" if character.italics else "roman")
            self.text.tag_configure(name, foreground=foreground, background=background, font=font, underline=character.underscore, overstrike=character.strikethrough)
            self.tag_cache.add(name)
        return name

    def schedule_render(self):
        if self.closed or not self.command:
            return
        if self.render_after_id is not None:
            try:
                self.after_cancel(self.render_after_id)
            except tk.TclError:
                pass
        self.render_after_id = self.after(60, self.render)

    def render(self, force=False):
        if self.render_after_id is not None:
            try:
                self.after_cancel(self.render_after_id)
            except tk.TclError:
                pass
            self.render_after_id = None
        if self.closed or not self.command:
            return
        if not self.screen.dirty and not force:
            self.schedule_render()
            return
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.yview_moveto(0.0)
        for line in range(self.lines):
            for column in range(self.columns):
                character = self.screen.buffer[line].get(column)
                if character is None:
                    self.text.insert("end", " ")
                else:
                    self.text.insert("end", character.data, (self.style_tag(character),))
            if line + 1 < self.lines:
                self.text.insert("end", "\n")
        if self.screen.history.position == self.screen.history.size and not getattr(self.screen.cursor, "hidden", False):
            start = f"{self.screen.cursor.y + 1}.{self.screen.cursor.x}"
            self.text.tag_add("terminal-cursor", start, f"{start} +1c")
            self.text.tag_configure("terminal-cursor", background=FG_COLORS["default"], foreground=BG_COLORS["default"])
        self.screen.dirty.clear()
        self.schedule_render()


class MetrixDesktop:
    FILTER_FIELDS = (
        ("format", "Format"), ("architecture", "Architecture"),
        ("artifact_class", "Class"), ("status", "Status"),
        ("analysis_status", "Analysis"),
    )
    COLUMNS = ("path", "format", "architecture", "artifact_class", "size_bytes", "sha256", "status")

    def __init__(self, root, output, command=None, workspace=None):
        self.root = root
        self.output = Path(output).expanduser().resolve()
        self.workspace = Path(workspace).expanduser().resolve() if workspace else self.output
        self.command = command
        self.records = []
        self.summary = {}
        self.visible = []
        self.sort_key = "path"
        self.sort_ascending = True
        self.filter_variables = {}
        self.filter_boxes = {}
        self.search_variable = tk.StringVar()
        self.status_variable = tk.StringVar(value="Loading corpus…")
        self.agent_variable = tk.StringVar(value="No embedded CLI")
        self.summary_signature = None
        self.root.title("METRIX Workbench")
        self.root.geometry("1500x900")
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="METRIX Workbench", font=("TkDefaultFont", 16, "bold")).pack(side="left")
        ttk.Label(top, textvariable=self.agent_variable).pack(side="right")
        panes = ttk.Panedwindow(self.root, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=8, pady=8)
        dashboard = ttk.Frame(panes)
        panes.add(dashboard, weight=3)
        self.build_dashboard(dashboard)
        self.terminal = TerminalPanel(panes, self.output, self.workspace, self.command, self.agent_variable.set)
        panes.add(self.terminal, weight=2)
        bottom = ttk.Frame(self.root, padding=(8, 0, 8, 8))
        bottom.pack(fill="x")
        ttk.Label(bottom, textvariable=self.status_variable).pack(side="left")
        ttk.Button(bottom, text="Refresh", command=self.reload).pack(side="right")
        self.reload()
        self.after_refresh()

    def build_dashboard(self, parent):
        filters = ttk.Frame(parent)
        filters.pack(fill="x", pady=(0, 8))
        ttk.Label(filters, text="Search").grid(row=0, column=0, sticky="w")
        search = ttk.Entry(filters, textvariable=self.search_variable)
        search.grid(row=0, column=1, columnspan=5, sticky="ew", padx=(6, 0))
        search.bind("<KeyRelease>", lambda event: self.render_records())
        filters.columnconfigure(1, weight=1)
        for index, (field, label) in enumerate(self.FILTER_FIELDS):
            variable = tk.StringVar(value="All")
            box = ttk.Combobox(filters, textvariable=variable, state="readonly", values=("All",), width=16)
            box.grid(row=1, column=index, sticky="ew", pady=(8, 0), padx=(0 if index == 0 else 5, 0))
            box.bind("<<ComboboxSelected>>", lambda event: self.render_records())
            self.filter_variables[field] = variable
            self.filter_boxes[field] = box
        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="Reset filters", command=self.reset_filters).pack(side="left")
        ttk.Button(actions, text="Export visible CSV", command=self.export_csv).pack(side="left", padx=6)
        self.tree = ttk.Treeview(parent, columns=self.COLUMNS, show="headings", selectmode="browse")
        headings = {"path": "Artifact", "format": "Format", "architecture": "Architecture", "artifact_class": "Class", "size_bytes": "Size", "sha256": "SHA256", "status": "Status"}
        for column in self.COLUMNS:
            self.tree.heading(column, text=headings[column], command=lambda value=column: self.sort_records(value))
            self.tree.column(column, width=350 if column == "path" else 140, stretch=column == "path")
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self.show_details)

    def reload(self):
        try:
            self.summary = load_summary(self.output)
            self.records = list(load_records(self.output))
            self.summary_signature = (self.output / "summary.json").stat().st_mtime_ns
        except (OSError, ValueError, json.JSONDecodeError) as error:
            self.status_variable.set(f"Unable to load output: {error}")
            return
        values = {field: ["All"] + sorted({str(record.get(field) or "—") for record in self.records}) for field, _ in self.FILTER_FIELDS}
        for field, box in self.filter_boxes.items():
            current = self.filter_variables[field].get()
            box.configure(values=values[field])
            if current not in values[field]:
                self.filter_variables[field].set("All")
        self.render_records()
        self.status_variable.set(f"{len(self.records)} artifacts · {self.summary.get('root', '')} · refreshed")

    def after_refresh(self):
        try:
            signature = (self.output / "summary.json").stat().st_mtime_ns
            if signature != self.summary_signature:
                self.reload()
        except OSError:
            pass
        self.root.after(2000, self.after_refresh)

    def reset_filters(self):
        self.search_variable.set("")
        for variable in self.filter_variables.values():
            variable.set("All")
        self.render_records()

    def sort_records(self, key):
        if self.sort_key == key:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_key, self.sort_ascending = key, True
        self.render_records()

    def render_records(self):
        terms = self.search_variable.get().casefold().split()
        self.visible = []
        for record in self.records:
            haystack = json.dumps(record, ensure_ascii=False).casefold()
            if any(term not in haystack for term in terms):
                continue
            if any(self.filter_variables[field].get() != "All" and str(record.get(field) or "—") != self.filter_variables[field].get() for field, _ in self.FILTER_FIELDS):
                continue
            self.visible.append(record)
        def sort_value(record):
            value = record.get(self.sort_key)
            if self.sort_key == "size_bytes":
                return (value is None, value if value is not None else 0)
            return str(value or "").casefold()
        self.visible.sort(key=sort_value, reverse=not self.sort_ascending)
        self.tree.delete(*self.tree.get_children())
        for record in self.visible:
            values = [record.get(column) for column in self.COLUMNS]
            values[4] = human_size(record.get("size_bytes"))
            values[5] = f"{record['sha256'][:16]}…" if record.get("sha256") else "—"
            self.tree.insert("", "end", iid=record["id"], values=values)
        self.status_variable.set(f"{len(self.visible)} of {len(self.records)} artifacts · {self.summary.get('root', '')}")

    def show_details(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        record = next((record for record in self.records if record["id"] == selection[0]), None)
        if record is None:
            return
        window = tk.Toplevel(self.root)
        window.title(record["path"])
        window.geometry("850x650")
        text = tk.Text(window, wrap="word", font=("TkFixedFont", 10))
        text.pack(fill="both", expand=True)
        text.insert("1.0", json.dumps(record, indent=2, ensure_ascii=False))
        text.configure(state="disabled")

    def export_csv(self):
        destination = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=(("CSV", "*.csv"),), initialfile="metrix-visible.csv")
        if not destination:
            return
        fields = ("id", "path", "format", "architecture", "artifact_class", "size_bytes", "sha256", "status", "analysis_status")
        with open(destination, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.visible)
        self.status_variable.set(f"Exported {len(self.visible)} records to {destination}")

    def close(self):
        if getattr(self, "closed", False):
            return
        self.closed = True
        self.terminal.stop()
        try:
            self.root.destroy()
        except tk.TclError:
            pass


def run_desktop(output, command=None, workspace=None):
    if pyte is None:
        raise ValueError("Desktop support requires pyte. Install with: python3 -m pip install -e '.[desktop]'")
    output = Path(output).expanduser().resolve()
    if not (output / "artifacts.jsonl").is_file():
        raise ValueError(f"METRIX output is missing artifacts.jsonl: {output}")
    if workspace is not None and not Path(workspace).expanduser().is_dir():
        raise ValueError(f"CLI workspace is not a directory: {workspace}")
    root = tk.Tk()
    app = MetrixDesktop(root, output, command, workspace)
    try:
        root.mainloop()
    finally:
        app.close()
    return 0
