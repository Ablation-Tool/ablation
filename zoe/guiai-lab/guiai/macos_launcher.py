from datetime import datetime
import os
from pathlib import Path
import re
import shutil
import sys
import tkinter as tk
from tkinter import filedialog, ttk


AGENT_NAMES = ("kimi", "claude", "codex")


def prepare_agent_path():
    candidates = [Path.home() / ".local" / "bin", Path("/opt/homebrew/bin"), Path("/usr/local/bin")]
    entries = [entry for entry in os.environ.get("PATH", "").split(os.pathsep) if entry]
    if not entries:
        entries = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    for candidate in candidates:
        if candidate.is_dir() and str(candidate) not in entries:
            entries.append(str(candidate))
    os.environ["PATH"] = os.pathsep.join(entries)


def default_agent():
    return next((name for name in AGENT_NAMES if shutil.which(name)), "")


def default_session(target):
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", target.stem if target.is_file() else target.name).strip("-.")
    name = (name or "investigation")[:64]
    root = Path.home() / "Ablation" / "Projects"
    candidate = root / name
    if candidate.exists():
        candidate = root / f"{name}-{datetime.now():%Y%m%d-%H%M%S}"
    index = 2
    while candidate.exists():
        candidate = root / f"{name}-{datetime.now():%Y%m%d-%H%M%S}-{index}"
        index += 1
    return candidate


class LauncherDialog:
    def __init__(self, root, on_launch):
        self.root = root
        self.on_launch = on_launch
        self.session_custom = False
        self.target = tk.StringVar(master=root)
        self.session = tk.StringVar(master=root)
        self.agent = tk.StringVar(master=root, value=default_agent())
        self.error = tk.StringVar(master=root)
        root.title("Ablation")
        root.geometry("660x360")
        root.minsize(600, 340)
        root.protocol("WM_DELETE_WINDOW", root.destroy)
        icons = Path(__file__).resolve().parent / "icons"
        self.icon = tk.PhotoImage(master=root, file=str(icons / "ablation-guiai-logo.png"))
        self.header_icon = tk.PhotoImage(master=root, file=str(icons / "ablation-guiai-logo-32.png"))
        root.iconphoto(True, self.icon)
        content = ttk.Frame(root, padding=20)
        content.pack(fill="both", expand=True)
        header = ttk.Frame(content)
        header.pack(fill="x", pady=(0, 18))
        ttk.Label(header, image=self.header_icon).pack(side="left")
        ttk.Label(header, text="Open a reverse-engineering Lab", font=("TkDefaultFont", 15, "bold")).pack(side="left", padx=10)
        self.add_field(content, "RE target", self.target, self.choose_target)
        self.session_entry = self.add_field(content, "Project directory", self.session, self.choose_session)
        self.session_entry.bind("<Key>", self.mark_session_custom)
        self.add_field(content, "AI Agent (optional)", self.agent, self.choose_agent)
        ttk.Label(
            content, text="Use your installed agent, such as kimi, claude, or codex. No model or credentials are installed.",
            wraplength=580, justify="left",
        ).pack(anchor="w", pady=(0, 12))
        ttk.Label(content, textvariable=self.error, foreground="#c01c28", wraplength=580).pack(fill="x", pady=(0, 8))
        actions = ttk.Frame(content)
        actions.pack(fill="x", side="bottom")
        ttk.Button(actions, text="Cancel", command=root.destroy).pack(side="right")
        ttk.Button(actions, text="Open Lab", command=self.launch).pack(side="right", padx=(0, 8))
        root.bind("<Return>", lambda _event: self.launch())
        root.bind("<Escape>", lambda _event: root.destroy())

    def add_field(self, parent, label, variable, choose):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=5)
        ttk.Label(row, text=label, width=20).pack(side="left")
        entry = ttk.Entry(row, textvariable=variable)
        entry.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Choose…", command=choose).pack(side="left", padx=(6, 0))
        return entry

    def mark_session_custom(self, _event):
        self.session_custom = True

    def choose_target(self):
        directory = filedialog.askdirectory(parent=self.root, title="Choose a material directory")
        if directory:
            selected = directory
        else:
            selected = filedialog.askopenfilename(parent=self.root, title="Or choose a binary")
        if selected:
            self.target.set(selected)
            if not self.session_custom:
                self.session.set(str(default_session(Path(selected))))

    def choose_session(self):
        selected = filedialog.askdirectory(parent=self.root, title="Choose a project directory")
        if selected:
            self.session_custom = True
            self.session.set(selected)

    def choose_agent(self):
        selected = filedialog.askopenfilename(parent=self.root, title="Choose your installed AI Agent")
        if selected:
            self.agent.set(selected)

    def arguments(self):
        if not self.target.get().strip():
            raise ValueError("Choose a binary or material directory to investigate.")
        target = Path(self.target.get()).expanduser().resolve(strict=True)
        if not target.is_file() and not target.is_dir():
            raise ValueError("The RE target must be a regular file or directory.")
        session = Path(self.session.get()).expanduser() if self.session.get().strip() else default_session(target)
        session = session.resolve()
        if target.is_dir() and (session == target or target in session.parents):
            raise ValueError("The project directory must be outside the RE target directory.")
        agent = self.agent.get().strip()
        if agent and shutil.which(agent) is None:
            raise ValueError("AI Agent executable was not found. Enter an installed executable or leave it blank.")
        arguments = ["desktop", str(target), "--session", str(session), "--toolkit", "tk"]
        if agent:
            arguments.extend(["--agent", agent])
        return arguments

    def launch(self):
        try:
            arguments = self.arguments()
        except (OSError, ValueError, RuntimeError) as error:
            self.error.set(str(error))
            return
        self.root.destroy()
        self.on_launch(arguments)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--self-test"]:
        import pyte
        assert pyte is not None
        print("GUIAI_MACOS_APP_OK", flush=True)
        return 0
    from .cli import main as cli_main
    if arguments:
        return cli_main(arguments)
    prepare_agent_path()
    selected = []
    root = tk.Tk()
    LauncherDialog(root, selected.extend)
    root.mainloop()
    return cli_main(selected) if selected else 0


if __name__ == "__main__":
    raise SystemExit(main())
