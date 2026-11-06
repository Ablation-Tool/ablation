import hashlib
import os
from pathlib import Path
import shutil
import sys


AGENT_NAMES = ("kimi", "claude", "codex")


def prepare_agent_path():
    candidates = [Path.home() / ".local" / "bin"]
    if sys.platform == "darwin":
        candidates.append(Path("/opt/homebrew/bin"))
    if os.name != "nt":
        candidates.append(Path("/usr/local/bin"))
    entries = [entry for entry in os.environ.get("PATH", "").split(os.pathsep) if entry]
    if not entries and os.name != "nt":
        entries = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    for candidate in candidates:
        if candidate.is_dir() and str(candidate) not in entries:
            entries.append(str(candidate))
    os.environ["PATH"] = os.pathsep.join(entries)


def default_agent():
    prepare_agent_path()
    return next((name for name in AGENT_NAMES if shutil.which(name)), "")


def default_workspace():
    source = Path(__file__).resolve().parent.parent
    if (source / "pyproject.toml").is_file() and (source / "gem" / "__init__.py").is_file():
        return source
    workspace = Path.home() / "gem-lab"
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def user_data_root():
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "Ablation" / "GEM"


def session_for_target(target):
    target = Path(target).expanduser().resolve()
    session = user_data_root() / "sessions" / hashlib.sha256(os.fsencode(str(target))).hexdigest()[:16]
    if session == target or target in session.parents:
        raise ValueError(
            "The selected folder contains GEM's session data. Choose a subfolder, or use "
            "gem lab with --session outside the target directory.",
        )
    return session


def show_launch_error(message):
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        try:
            messagebox.showerror("Ablation could not start", message, parent=root)
        finally:
            root.destroy()
    except Exception:
        print(f"Ablation could not start: {message}", file=sys.stderr)
