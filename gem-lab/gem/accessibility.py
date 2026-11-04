import json
import os
from pathlib import Path
import subprocess
import sys

from .events import atomic_write


PALETTE_MODES = {
    "system": "System colors",
    "colorblind": "Colorblind-safe colors",
    "high-contrast": "High-contrast colors",
}
DEFAULT_PALETTE = "system"
GNOME_ACCENTS = {
    "blue": "#3584e4", "teal": "#2190a4", "green": "#3a944a", "yellow": "#c88800",
    "orange": "#ed5b00", "red": "#e62d42", "pink": "#d56199", "purple": "#9141ac",
    "slate": "#6f8596", "bark": "#986a44",
}
MAC_ACCENTS = {
    -1: "#8e8e93", 0: "#e62d42", 1: "#ed5b00", 2: "#c88800",
    3: "#3a944a", 4: "#3584e4", 5: "#9141ac", 6: "#d56199",
}


def system_accent_color():
    try:
        if os.name == "nt":
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\DWM") as key:
                value, _ = winreg.QueryValueEx(key, "AccentColor")
            red, green, blue = value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff
            return f"#{red:02x}{green:02x}{blue:02x}"
        if sys.platform == "darwin":
            result = subprocess.run(
                ["/usr/bin/defaults", "read", "-g", "AppleAccentColor"],
                capture_output=True, text=True, timeout=2, check=False,
            )
            return MAC_ACCENTS.get(int(result.stdout.strip())) if result.returncode == 0 else None
        import gi
        from gi.repository import Gio
        source = Gio.SettingsSchemaSource.get_default()
        if source is None or not source.lookup("org.gnome.desktop.interface", True):
            return None
        settings = Gio.Settings.new("org.gnome.desktop.interface")
        return GNOME_ACCENTS.get(settings.get_string("accent-color"))
    except (ImportError, OSError, ValueError, subprocess.SubprocessError):
        return None


def load_accessibility(session_root):
    path = Path(session_root) / "accessibility.json"
    if not path.exists():
        return DEFAULT_PALETTE, None
    try:
        if path.stat().st_size > 16 * 1024:
            raise ValueError("accessibility.json exceeds 16 KiB")
        record = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(record, dict) or set(record) != {"palette"}:
            raise ValueError("accessibility.json must contain only the palette setting")
        palette = record["palette"]
        if palette not in PALETTE_MODES:
            raise ValueError(f"Unknown accessibility palette: {palette}")
        return palette, None
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return DEFAULT_PALETTE, str(error)


def save_accessibility(session_root, palette):
    if palette not in PALETTE_MODES:
        raise ValueError(f"Unknown accessibility palette: {palette}")
    atomic_write(
        Path(session_root) / "accessibility.json",
        json.dumps({"palette": palette}, indent=2) + "\n",
    )


def contrast_ratio(foreground, background):
    def channel(value):
        value = value / 255
        return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4

    def luminance(color):
        color = color.lstrip("#")
        red, green, blue = (int(color[index:index + 2], 16) for index in (0, 2, 4))
        return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)

    first = luminance(foreground)
    second = luminance(background)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


def evaluate_accessibility(palette, light_background, background, features):
    from .safety import safety_colors

    checks = []
    remediations = []
    for name, passed in features.items():
        checks.append({"name": name, "ok": bool(passed), "required": True, "detail": "Available" if passed else "Missing or incomplete"})
        if not passed:
            remediations.append({
                "action": f"Review and repair {name} within GEM; do not broaden the change to investigation artifacts",
                "command": None,
            })
    colors = safety_colors(light_background, palette)
    for name in ("pass", "review", "accent"):
        ratio = contrast_ratio(colors[name], background)
        passed = ratio >= 4.5
        checks.append({
            "name": f"{name.title()} text contrast",
            "ok": passed,
            "required": True,
            "detail": f"{ratio:.2f}:1 against {background}; WCAG normal-text target is 4.5:1",
        })
        if not passed:
            remediations.append({"action": f"Increase {name} text contrast to at least 4.5:1", "command": None})
    checks.append({
        "name": "Manual assistive-technology validation",
        "ok": True,
        "required": False,
        "detail": "Automated checks do not replace testing with NVDA, Narrator, VoiceOver, or the user's assistive setup",
    })
    blocking = [check for check in checks if check["required"] and not check["ok"]]
    summary = (
        f"{len(blocking)} accessibility item{'s' if len(blocking) != 1 else ''} need attention"
        if blocking else "Accessibility checks passed; manual screen-reader validation is still required"
    )
    details = "\n".join(
        f"[{'PASS' if check['ok'] else 'REVIEW'}] {check['name']}: {check['detail']}" for check in checks
    )
    if remediations:
        details += "\n\nProposed actions (no action has been taken):\n" + "\n".join(
            f"- {item['action']}" for item in remediations
        )
    return {
        "checks": checks,
        "details": details,
        "remediations": remediations,
        "summary": summary,
        "ready": not blocking,
    }
