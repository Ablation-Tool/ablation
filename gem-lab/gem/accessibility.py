import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

from .events import atomic_write


PALETTE_MODES = {
    "system": "System colors",
    "colorblind": "Colorblind-safe colors",
    "high-contrast": "High-contrast colors",
}
DEFAULT_PALETTE = "system"
FONT_SCALE_MIN = 0.85
FONT_SCALE_MAX = 2.0
FONT_SCALE_PRESETS = (0.85, 1.0, 1.15, 1.3, 1.5, 1.75, 2.0)
LINE_SPACING_MIN = 1.0
LINE_SPACING_MAX = 2.0
LINE_SPACING_PRESETS = (1.0, 1.2, 1.4, 1.6, 1.8, 2.0)
DEFAULT_SETTINGS = {
    "palette": DEFAULT_PALETTE,
    "font_scale": 1.0,
    "line_spacing": 1.2,
    "reduced_motion": False,
    "focus_ring": True,
    "dyslexia_spacing": False,
}
ALLOWED_SETTING_KEYS = frozenset(DEFAULT_SETTINGS)
WCAG_AA_CONTRAST = 4.5
WCAG_AAA_CONTRAST = 7.0
MAX_SETTINGS_BYTES = 16 * 1024
HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
GNOME_ACCENTS = {
    "blue": "#3584e4", "teal": "#2190a4", "green": "#3a944a", "yellow": "#c88800",
    "orange": "#ed5b00", "red": "#e62d42", "pink": "#d56199", "purple": "#9141ac",
    "slate": "#6f8596", "bark": "#986a44",
}
MAC_ACCENTS = {
    -1: "#8e8e93", 0: "#e62d42", 1: "#ed5b00", 2: "#c88800",
    3: "#3a944a", 4: "#3584e4", 5: "#9141ac", 6: "#d56199",
}


def _clamp_scale(value, minimum, maximum):
    return round(max(minimum, min(maximum, float(value))), 2)


def _validate_numeric_setting(name, value, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number between {minimum} and {maximum}")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return round(number, 2)


def _validate_bool_setting(name, value):
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def validate_accessibility_settings(record, require_palette=True):
    if not isinstance(record, dict):
        raise ValueError("accessibility.json must contain a JSON object")
    unknown = sorted(set(record) - ALLOWED_SETTING_KEYS)
    if unknown:
        raise ValueError(f"Unexpected accessibility keys: {', '.join(unknown)}")
    if require_palette and "palette" not in record:
        raise ValueError("accessibility.json must include the palette setting")
    merged = dict(DEFAULT_SETTINGS)
    merged.update(record)
    palette = merged["palette"]
    if palette not in PALETTE_MODES:
        raise ValueError(f"Unknown accessibility palette: {palette}")
    return {
        "palette": palette,
        "font_scale": _validate_numeric_setting("font_scale", merged["font_scale"], FONT_SCALE_MIN, FONT_SCALE_MAX),
        "line_spacing": _validate_numeric_setting("line_spacing", merged["line_spacing"], LINE_SPACING_MIN, LINE_SPACING_MAX),
        "reduced_motion": _validate_bool_setting("reduced_motion", merged["reduced_motion"]),
        "focus_ring": _validate_bool_setting("focus_ring", merged["focus_ring"]),
        "dyslexia_spacing": _validate_bool_setting("dyslexia_spacing", merged["dyslexia_spacing"]),
    }


def _gnome_settings(schema_id):
    from gi.repository import Gio
    source = Gio.SettingsSchemaSource.get_default()
    if source is None or not source.lookup(schema_id, True):
        return None
    return Gio.Settings.new(schema_id)


def _detect_gnome_accessibility():
    profile = {"accent_color": None, "high_contrast": False, "reduced_motion": False, "font_scale": 1.0}
    interface = _gnome_settings("org.gnome.desktop.interface")
    if interface is not None:
        keys = set(interface.list_keys())
        if "accent-color" in keys:
            profile["accent_color"] = GNOME_ACCENTS.get(interface.get_string("accent-color"))
        if "enable-animations" in keys:
            profile["reduced_motion"] = not bool(interface.get_boolean("enable-animations"))
        if "text-scaling-factor" in keys:
            profile["font_scale"] = _clamp_scale(interface.get_double("text-scaling-factor"), FONT_SCALE_MIN, FONT_SCALE_MAX)
        if "gtk-theme" in keys and "highcontrast" in interface.get_string("gtk-theme").casefold():
            profile["high_contrast"] = True
    a11y = _gnome_settings("org.gnome.desktop.a11y.interface")
    if a11y is not None and "high-contrast" in set(a11y.list_keys()):
        if bool(a11y.get_boolean("high-contrast")):
            profile["high_contrast"] = True
    return profile


def _read_macos_default(domain, key):
    result = subprocess.run(
        ["/usr/bin/defaults", "read", domain, key],
        capture_output=True, text=True, timeout=2, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _detect_macos_accessibility():
    accent_raw = _read_macos_default("-g", "AppleAccentColor")
    accent = MAC_ACCENTS.get(int(accent_raw)) if accent_raw is not None else None
    high_contrast = _read_macos_default("com.apple.universalaccess", "increaseContrast") == "1"
    reduced_motion = _read_macos_default("com.apple.universalaccess", "reduceMotion") == "1"
    return {
        "accent_color": accent,
        "high_contrast": high_contrast,
        "reduced_motion": reduced_motion,
        "font_scale": 1.0,
    }


def _detect_windows_accessibility():
    import winreg
    profile = {"accent_color": None, "high_contrast": False, "reduced_motion": False, "font_scale": 1.0}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\DWM") as key:
            value, _ = winreg.QueryValueEx(key, "AccentColor")
        red, green, blue = value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff
        profile["accent_color"] = f"#{red:02x}{green:02x}{blue:02x}"
    except (OSError, ValueError):
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Accessibility\HighContrast") as key:
            flags, _ = winreg.QueryValueEx(key, "Flags")
        profile["high_contrast"] = bool(int(flags) & 1)
    except (OSError, ValueError):
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Accessibility") as key:
            percent, _ = winreg.QueryValueEx(key, "TextScaleFactor")
        profile["font_scale"] = _clamp_scale(float(percent) / 100.0, FONT_SCALE_MIN, FONT_SCALE_MAX)
    except (OSError, ValueError):
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop\WindowMetrics") as key:
            animate, _ = winreg.QueryValueEx(key, "MinAnimate")
        profile["reduced_motion"] = str(animate).strip() == "0"
    except (OSError, ValueError):
        pass
    return profile


def detect_system_accessibility():
    profile = {
        "platform": sys.platform,
        "accent_color": None,
        "high_contrast": False,
        "reduced_motion": False,
        "font_scale": 1.0,
    }
    try:
        if os.name == "nt":
            detected = _detect_windows_accessibility()
        elif sys.platform == "darwin":
            detected = _detect_macos_accessibility()
        else:
            detected = _detect_gnome_accessibility()
        profile.update(detected)
    except (ImportError, OSError, ValueError, TypeError, subprocess.SubprocessError):
        pass
    return profile


def recommended_settings_from_system(detected=None):
    info = detect_system_accessibility() if detected is None else detected
    recommended = dict(DEFAULT_SETTINGS)
    if bool(info.get("high_contrast")):
        recommended["palette"] = "high-contrast"
    raw_scale = info.get("font_scale", 1.0)
    if not isinstance(raw_scale, bool) and isinstance(raw_scale, (int, float)) and math.isfinite(float(raw_scale)):
        recommended["font_scale"] = _clamp_scale(raw_scale, FONT_SCALE_MIN, FONT_SCALE_MAX)
    recommended["reduced_motion"] = bool(info.get("reduced_motion", False))
    return validate_accessibility_settings(recommended, require_palette=True)


def system_accent_color():
    try:
        if os.name == "nt":
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\DWM") as key:
                value, _ = winreg.QueryValueEx(key, "AccentColor")
            red, green, blue = value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff
            return f"#{red:02x}{green:02x}{blue:02x}"
        if sys.platform == "darwin":
            raw = _read_macos_default("-g", "AppleAccentColor")
            return MAC_ACCENTS.get(int(raw)) if raw is not None else None
        interface = _gnome_settings("org.gnome.desktop.interface")
        if interface is None:
            return None
        return GNOME_ACCENTS.get(interface.get_string("accent-color"))
    except (ImportError, OSError, ValueError, subprocess.SubprocessError):
        return None


def load_accessibility_settings(session_root):
    path = Path(session_root) / "accessibility.json"
    if not path.exists():
        return dict(DEFAULT_SETTINGS), None
    try:
        if path.stat().st_size > MAX_SETTINGS_BYTES:
            raise ValueError("accessibility.json exceeds 16 KiB")
        record = json.loads(path.read_text(encoding="utf-8"))
        return validate_accessibility_settings(record, require_palette=True), None
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        return dict(DEFAULT_SETTINGS), str(error)


def save_accessibility_settings(session_root, settings):
    validated = validate_accessibility_settings(settings, require_palette=True)
    atomic_write(
        Path(session_root) / "accessibility.json",
        json.dumps(validated, indent=2, sort_keys=True) + "\n",
    )
    return validated


def load_accessibility(session_root):
    settings, error = load_accessibility_settings(session_root)
    return settings["palette"], error


def save_accessibility(session_root, palette, **overrides):
    if palette not in PALETTE_MODES:
        raise ValueError(f"Unknown accessibility palette: {palette}")
    current, error = load_accessibility_settings(session_root)
    updated = dict(DEFAULT_SETTINGS if error else current)
    updated["palette"] = palette
    updated.update(overrides)
    return save_accessibility_settings(session_root, updated)


def wcag_contrast_target(palette):
    return WCAG_AAA_CONTRAST if palette == "high-contrast" else WCAG_AA_CONTRAST


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


def best_text_color(background):
    return "#ffffff" if contrast_ratio("#ffffff", background) >= contrast_ratio("#000000", background) else "#000000"


def step_font_scale(current, direction):
    if direction == 0:
        return 1.0
    value = _clamp_scale(current, FONT_SCALE_MIN, FONT_SCALE_MAX)
    if direction > 0:
        for preset in FONT_SCALE_PRESETS:
            if preset > value + 1e-6:
                return preset
        return FONT_SCALE_MAX
    for preset in reversed(FONT_SCALE_PRESETS):
        if preset < value - 1e-6:
            return preset
    return FONT_SCALE_MIN


def line_spacing_pixels(line_spacing, base_font_pt=10.5):
    spacing = _validate_numeric_setting("line_spacing", line_spacing, LINE_SPACING_MIN, LINE_SPACING_MAX)
    extra = max(0, round((spacing - 1.0) * float(base_font_pt)))
    above = extra // 2
    below = extra - above
    return above, below, extra


def scaled_font_points(base_pt, font_scale):
    scale = _validate_numeric_setting("font_scale", font_scale, FONT_SCALE_MIN, FONT_SCALE_MAX)
    return round(max(6.0, float(base_pt) * scale), 2)


def build_gtk_accessibility_css(settings, accent="#1867c0", base_font_pt=10.5):
    validated = validate_accessibility_settings(settings, require_palette=False)
    safe_accent = accent if isinstance(accent, str) and HEX_COLOR_RE.match(accent) else "#1867c0"
    font_pt = scaled_font_points(base_font_pt, validated["font_scale"])
    rules = [
        f"window, label, button, entry, textview, treeview, combobox {{ font-size: {font_pt:g}pt; }}",
    ]
    if validated["dyslexia_spacing"]:
        rules.append("label, entry, textview, treeview { letter-spacing: 1px; }")
    if validated["focus_ring"]:
        rules.append(
            f"*:focus {{ outline-style: solid; outline-width: 2px; outline-offset: 2px; outline-color: {safe_accent}; }}"
        )
    if validated["reduced_motion"]:
        rules.append("* { transition-duration: 0ms; animation-duration: 0ms; }")
    return "\n".join(rules) + "\n"


def apply_atk_metadata(widget, name=None, description=None, role=None):
    accessible = widget.get_accessible() if hasattr(widget, "get_accessible") else None
    if accessible is None:
        return False
    if name is not None:
        accessible.set_name(name)
    if description is not None:
        accessible.set_description(description)
    if role is not None:
        accessible.set_role(role)
    return True


def _append_settings_checks(checks, remediations, settings):
    validated = validate_accessibility_settings(settings, require_palette=False)
    scale_pct = int(round(validated["font_scale"] * 100))
    spacing = validated["line_spacing"]
    dyslexia_label = "enabled" if validated["dyslexia_spacing"] else "standard"
    checks.append({
        "name": "Typography and spacing",
        "ok": True,
        "required": True,
        "detail": f"{scale_pct}% text scale (WCAG 1.4.4 up to 200%), {spacing:.1f}x line spacing, extra letter spacing {dyslexia_label}",
    })
    focus_ok = validated["focus_ring"]
    checks.append({
        "name": "High-visibility focus ring",
        "ok": focus_ok,
        "required": True,
        "detail": "2px high-visibility keyboard focus ring active (WCAG 2.4.7)" if focus_ok else "Focus ring is disabled; enable for clear keyboard tracking",
    })
    if not focus_ok:
        remediations.append({
            "action": "Enable High-visibility focus ring in a11y Optimization for clear keyboard focus tracking",
            "command": None,
        })
    motion_state = "Reduced motion enabled (animations disabled)" if validated["reduced_motion"] else "Standard motion (reduced motion available)"
    checks.append({
        "name": "Motion preference",
        "ok": True,
        "required": False,
        "detail": f"{motion_state}; WCAG 2.3.3 supported",
    })


def evaluate_accessibility(palette, light_background, background, features, settings=None):
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
    target = wcag_contrast_target(palette)
    wcag_label = "WCAG AAA enhanced-text target is 7.0:1" if target >= WCAG_AAA_CONTRAST else "WCAG normal-text target is 4.5:1"
    for name in ("pass", "review", "accent"):
        ratio = contrast_ratio(colors[name], background)
        passed = ratio >= target
        checks.append({
            "name": f"{name.title()} text contrast",
            "ok": passed,
            "required": True,
            "detail": f"{ratio:.2f}:1 against {background}; {wcag_label}",
        })
        if not passed:
            remediations.append({"action": f"Increase {name} text contrast to at least {target:.1f}:1", "command": None})
    if settings is not None:
        _append_settings_checks(checks, remediations, settings)
    checks.append({
        "name": "Manual assistive-technology validation",
        "ok": True,
        "required": False,
        "detail": "Automated checks do not replace testing with Orca, NVDA, Narrator, VoiceOver, or the user's assistive setup",
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
        "contrast_target": target,
    }
