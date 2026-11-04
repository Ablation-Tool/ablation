import json
from pathlib import Path

from .events import atomic_write


LAYOUTS = ("lab-left", "lab-right", "lab-top", "lab-bottom")


def layout_name(value):
    if not isinstance(value, str):
        raise ValueError("workspace layout must be a string")
    value = {"horizontal": "lab-left", "vertical": "lab-top"}.get(value, value)
    if value not in LAYOUTS:
        raise ValueError(f"unknown workspace layout: {value}")
    return value


def load_layout(session_root):
    path = Path(session_root) / "preferences.json"
    if not path.exists():
        return "lab-left"
    if path.stat().st_size > 65536:
        raise ValueError("preferences.json exceeds 64 KiB")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("preferences must be a JSON object")
    return layout_name(data.get("layout", "lab-left"))


def save_layout(session_root, layout):
    path = Path(session_root) / "preferences.json"
    data = {"version": 1}
    if path.exists():
        if path.stat().st_size > 65536:
            raise ValueError("preferences.json exceeds 64 KiB")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("preferences must be a JSON object")
    data["layout"] = layout_name(layout)
    atomic_write(path, json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
