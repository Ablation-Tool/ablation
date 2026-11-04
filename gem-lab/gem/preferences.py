import json
import os
from pathlib import Path
import tempfile

import gi
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, Pango

from .layout import LAYOUTS, layout_name


TANGO_PALETTE = (
    "#2e3436", "#cc0000", "#4e9a06", "#c4a000", "#3465a4", "#75507b", "#06989a", "#d3d7cf",
    "#555753", "#ef2929", "#8ae234", "#fce94f", "#729fcf", "#ad7fa8", "#34e2e2", "#eeeeec",
)
LINUX_PALETTE = (
    "#000000", "#aa0000", "#00aa00", "#aa5500", "#0000aa", "#aa00aa", "#00aaaa", "#aaaaaa",
    "#555555", "#ff5555", "#55ff55", "#ffff55", "#5555ff", "#ff55ff", "#55ffff", "#ffffff",
)
XTERM_PALETTE = (
    "#000000", "#cd0000", "#00cd00", "#cdcd00", "#0000ee", "#cd00cd", "#00cdcd", "#e5e5e5",
    "#7f7f7f", "#ff0000", "#00ff00", "#ffff00", "#5c5cff", "#ff00ff", "#00ffff", "#ffffff",
)
SOLARIZED_PALETTE = (
    "#073642", "#dc322f", "#859900", "#b58900", "#268bd2", "#d33682", "#2aa198", "#eee8d5",
    "#002b36", "#cb4b16", "#586e75", "#657b83", "#839496", "#6c71c4", "#93a1a1", "#fdf6e3",
)
CONTRAST_PALETTE = (
    "#000000", "#ff5555", "#50fa7b", "#f1fa8c", "#8be9fd", "#ff79c6", "#8be9fd", "#f8f8f2",
    "#6272a4", "#ff6e6e", "#69ff94", "#ffffa5", "#d6acff", "#ff92df", "#a4ffff", "#ffffff",
)
SCHEMES = {
    "system": None,
    "tango": {"foreground": "#d3d7cf", "background": "#2e3436", "palette": TANGO_PALETTE},
    "linux": {"foreground": "#aaaaaa", "background": "#000000", "palette": LINUX_PALETTE},
    "xterm": {"foreground": "#e5e5e5", "background": "#000000", "palette": XTERM_PALETTE},
    "solarized-dark": {"foreground": "#839496", "background": "#002b36", "palette": SOLARIZED_PALETTE},
    "solarized-light": {"foreground": "#657b83", "background": "#fdf6e3", "palette": SOLARIZED_PALETTE},
    "high-contrast": {"foreground": "#ffffff", "background": "#000000", "palette": CONTRAST_PALETTE},
    "custom": None,
}
SCHEME_LABELS = {
    "system": "Ubuntu / system", "tango": "Tango", "linux": "Linux console",
    "xterm": "XTerm", "solarized-dark": "Solarized dark",
    "solarized-light": "Solarized light", "high-contrast": "High contrast",
    "custom": "Custom",
}


def parse_color(value):
    if not isinstance(value, str):
        raise ValueError("color must be a string")
    color = Gdk.RGBA()
    if not color.parse(value):
        raise ValueError(f"invalid terminal color: {value}")
    return color


def color_hex(color):
    return "#" + "".join(f"{round(getattr(color, channel) * 255):02x}" for channel in ("red", "green", "blue"))


def normalized_color(value):
    return color_hex(parse_color(value))


class WorkbenchPreferences:
    def __init__(self, session_root, default_font):
        self.path = Path(session_root) / "preferences.json"
        self.scheme = "system"
        self.font_name = default_font
        self.layout = "lab-left"
        self.custom = {
            "foreground": "#d3d7cf", "background": "#2e3436", "palette": list(TANGO_PALETTE),
        }
        self.error = None
        if self.path.exists():
            try:
                self.load()
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                self.error = str(error)

    def load(self):
        if self.path.stat().st_size > 65536:
            raise ValueError("preferences.json exceeds 64 KiB")
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("preferences must be a JSON object")
        custom = data.get("custom", self.custom)
        if not isinstance(custom, dict):
            raise ValueError("custom terminal colors must be an object")
        palette = custom.get("palette", self.custom["palette"])
        if not isinstance(palette, list) or len(palette) != 16:
            raise ValueError("terminal palette must contain exactly 16 colors")
        layout = data.get("layout", self.layout)
        layout = {"horizontal": "lab-left", "vertical": "lab-top"}.get(layout, layout)
        self.update(
            scheme=data.get("scheme", self.scheme),
            font_name=data.get("font_name", self.font_name),
            foreground=custom.get("foreground", self.custom["foreground"]),
            background=custom.get("background", self.custom["background"]),
            palette=palette,
            layout=layout,
            save=False,
        )

    def update(self, scheme, font_name, foreground, background, palette, layout=None, save=True):
        if scheme not in SCHEMES:
            raise ValueError(f"unknown terminal color scheme: {scheme}")
        if not isinstance(font_name, str) or not 1 <= len(font_name) <= 200:
            raise ValueError("terminal font must contain 1–200 characters")
        if any(ord(character) < 32 for character in font_name):
            raise ValueError("terminal font contains control characters")
        Pango.FontDescription.from_string(font_name)
        if not isinstance(palette, (list, tuple)) or len(palette) != 16:
            raise ValueError("terminal palette must contain exactly 16 colors")
        layout = layout_name(self.layout if layout is None else layout)
        custom = {
            "foreground": normalized_color(foreground),
            "background": normalized_color(background),
            "palette": [normalized_color(color) for color in palette],
        }
        if save:
            self.save(scheme, font_name, custom, layout)
        self.scheme = scheme
        self.font_name = font_name
        self.layout = layout
        self.custom = custom
        self.error = None

    def save(self, scheme, font_name, custom, layout=None):
        data = {
            "version": 1, "scheme": scheme, "font_name": font_name,
            "layout": layout or self.layout, "custom": custom,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.path.parent, prefix=".preferences-", delete=False,
            ) as stream:
                temporary = Path(stream.name)
                json.dump(data, stream, indent=2, sort_keys=True, ensure_ascii=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    def editing_colors(self, scheme):
        return SCHEMES.get(scheme) or self.custom

    def apply_terminal(self, terminal):
        terminal.set_font(Pango.FontDescription.from_string(self.font_name))
        colors = self.editing_colors(self.scheme) if self.scheme != "system" else None
        if colors is None:
            terminal.set_colors(None, None, [])
            return
        terminal.set_colors(
            parse_color(colors["foreground"]), parse_color(colors["background"]),
            [parse_color(color) for color in colors["palette"]],
        )
