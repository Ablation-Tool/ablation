import hashlib
import os
from pathlib import Path
import sys


def user_data_root():
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "Ablation" / "GUIAI"


def session_for_target(target):
    target = Path(target).expanduser().resolve()
    session = user_data_root() / "sessions" / hashlib.sha256(os.fsencode(str(target))).hexdigest()[:16]
    if session == target or target in session.parents:
        raise ValueError(
            "The selected folder contains GUIAI's session data. Choose a subfolder, or use "
            "guiai desktop with --session outside the target directory.",
        )
    return session


def choose_target():
    import tkinter as tk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    root.withdraw()
    try:
        try:
            root.attributes("-topmost", True)
        except tk.TclError:
            pass
        directory = messagebox.askyesnocancel(
            "Ablation",
            "Investigate a directory?\n\nChoose Yes for a material directory or No for a single binary.",
            parent=root,
        )
        if directory is None:
            return None
        if directory:
            selected = filedialog.askdirectory(title="Choose an investigation directory", parent=root)
        else:
            selected = filedialog.askopenfilename(title="Choose a binary to investigate", parent=root)
        return Path(selected).resolve() if selected else None
    finally:
        root.destroy()


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
