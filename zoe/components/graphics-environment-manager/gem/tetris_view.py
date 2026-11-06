from __future__ import annotations

import json
from pathlib import Path

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_foreign("cairo")
from gi.repository import Gdk, GLib, Gtk

from .render import write_png, write_svg
from .tetris import TetrisGame, tetris_report, tetris_scene
from .vdi import write_metafile
from .view import GemView


class TetrisWindow(Gtk.Window):
    def __init__(self, game=None, seed=7, randomizer="bag"):
        super().__init__(title="Zoe · Bounded Tetris")
        self.set_default_size(1200, 900)
        self.game = game or TetrisGame(seed=seed, randomizer=randomizer)
        self.paused = False
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=10)
        self.add(outer)
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        for label, suffix in (("Export SVG", "svg"), ("Export PNG", "png"), ("Export GEM VDI", "gem"), ("Export JSON", "json")):
            button = Gtk.Button(label=label)
            button.connect("clicked", self.choose_export, suffix)
            toolbar.pack_start(button, False, False, 0)
        outer.pack_start(toolbar, False, False, 0)
        self.canvas = GemView(lambda *_args: False)
        outer.pack_start(self.canvas, True, True, 0)
        self.summary = Gtk.Label(xalign=0)
        self.summary.set_line_wrap(True)
        self.summary.set_selectable(True)
        outer.pack_start(self.summary, False, False, 0)
        self.connect("key-press-event", self.on_key)
        self.connect("destroy", self.on_destroy)
        self.timer_id = GLib.timeout_add(33, self.tick)
        self.refresh()

    def on_destroy(self, *_args):
        if self.timer_id is not None:
            GLib.source_remove(self.timer_id)
            self.timer_id = None
        if Gtk.main_level() > 0:
            Gtk.main_quit()

    def tick(self):
        if not self.paused:
            self.game.tick()
            self.refresh()
        return True

    def move(self, direction):
        offsets = {"Left": -1, "Right": 1, "Down": 0}
        if direction == "Down":
            result = self.game.soft_drop()
        else:
            result = self.game.move(offsets[direction])
        self.refresh()
        return result

    def rotate(self, direction=1):
        result = self.game.rotate(direction)
        self.refresh()
        return result

    def hard_drop(self):
        result = self.game.hard_drop()
        self.refresh()
        return result

    def on_key(self, _widget, event):
        actions = {
            Gdk.KEY_Left: lambda: self.move("Left"),
            Gdk.KEY_Right: lambda: self.move("Right"),
            Gdk.KEY_Down: lambda: self.move("Down"),
            Gdk.KEY_Up: lambda: self.rotate(),
            Gdk.KEY_z: lambda: self.rotate(-1),
            Gdk.KEY_Z: lambda: self.rotate(-1),
            Gdk.KEY_space: self.hard_drop,
        }
        action = actions.get(event.keyval)
        if action:
            return action()
        if event.keyval in (Gdk.KEY_p, Gdk.KEY_P):
            self.paused = not self.paused
        elif event.keyval in (Gdk.KEY_s, Gdk.KEY_S):
            self.game.soft_drop()
        elif event.keyval in (Gdk.KEY_r, Gdk.KEY_R):
            self.game = TetrisGame(seed=self.game.seed, randomizer=self.game.randomizer)
        elif event.keyval in (Gdk.KEY_b, Gdk.KEY_B):
            self.game.randomizer = "bag"
            self.game.remaining = []
        elif event.keyval in (Gdk.KEY_u, Gdk.KEY_U):
            self.game.randomizer = "uniform"
        else:
            return False
        self.refresh()
        return True

    def refresh(self):
        self.report = tetris_report(self.game)
        self.scene, _ = tetris_scene(self.report)
        self.canvas.set_model(self.scene, None, None)
        status = "paused" if self.paused else "running"
        self.summary.set_text(
            self.report["summary"] + f" · {status} · arrows move/rotate · space drops · P pauses · S steps · R resets · B bag · U uniform"
        )

    def export_current(self, path):
        path = Path(path)
        suffix = path.suffix.lower()
        if suffix == ".json":
            with path.open("x", encoding="utf-8") as stream:
                json.dump(self.report, stream, indent=2, sort_keys=True, allow_nan=False)
                stream.write("\n")
        elif suffix == ".svg":
            write_svg(self.scene, path, 1920)
        elif suffix == ".png":
            write_png(self.scene, path, 1920)
        elif suffix == ".gem":
            write_metafile(self.scene, path)
        else:
            raise ValueError("export must use .svg, .png, .gem, or .json")
        return path

    def choose_export(self, _widget, suffix):
        dialog = Gtk.FileChooserDialog(title=f"Export {suffix.upper()}", transient_for=self, action=Gtk.FileChooserAction.SAVE)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Export", Gtk.ResponseType.OK)
        dialog.set_current_name(f"bounded-tetris.{suffix}")
        dialog.set_do_overwrite_confirmation(True)
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.export_current(dialog.get_filename())
        except (OSError, ValueError, RuntimeError) as error:
            self.summary.set_text(f"Export failed: {error}")
        finally:
            dialog.destroy()


def launch_tetris(game=None):
    Gtk.init([])
    window = TetrisWindow(game=game)
    window.show_all()
    Gtk.main()
