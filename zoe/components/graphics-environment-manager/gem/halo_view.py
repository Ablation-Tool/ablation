from __future__ import annotations

import json
from pathlib import Path

import gi
gi.require_version("Gtk", "3.0")
gi.require_foreign("cairo")
from gi.repository import Gtk

from .halo import experiment, halo_scene
from .render import write_png, write_svg
from .vdi import write_metafile
from .view import GemView


class HaloWindow(Gtk.Window):
    def __init__(self, metric="both", view_angle=65, noise=0.0, seed=7):
        super().__init__(title="Zoe · Halo Field")
        self.set_default_size(1500, 920)
        self.settings = {"metric": metric, "view_angle": view_angle, "noise": noise, "seed": seed}
        self.controls = {}
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=10)
        self.add(outer)
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        for label, suffix in (("Export SVG", "svg"), ("Export PNG", "png"), ("Export GEM VDI", "gem"), ("Export JSON", "json")):
            button = Gtk.Button(label=label)
            button.connect("clicked", self.choose_export, suffix)
            toolbar.pack_start(button, False, False, 0)
        outer.pack_start(toolbar, False, False, 0)
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        outer.pack_start(paned, True, True, 0)
        self.canvas = GemView(lambda *_args: False)
        paned.pack1(self.canvas, True)
        controls = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=10)
        paned.pack2(controls, False)
        paned.set_position(1130)
        self.control_box = controls
        self.add_text("Independent similarity metric")
        self.metric = Gtk.ComboBoxText()
        for value, label in (("both", "L2 and Walsh"), ("l2", "L2 pixels"), ("walsh", "Coarse Walsh template")):
            self.metric.append(value, label)
        self.metric.set_active_id(metric)
        self.metric.connect("changed", self.update_model)
        controls.pack_start(self.metric, False, False, 0)
        self.add_scale("view_angle", "Parallax angle (degrees)", 1, 89, 1, view_angle, 0)
        self.add_scale("noise", "Observation noise", 0, .05, .001, noise, 3)
        self.add_text("Deterministic seed")
        seed_control = Gtk.SpinButton.new_with_range(0, 999999, 1)
        seed_control.set_value(seed)
        seed_control.connect("value-changed", self.update_model)
        controls.pack_start(seed_control, False, False, 0)
        self.controls["seed"] = seed_control
        self.add_text("Two synthetic orthographic views are compared with fixed target observations. Truth is used for evaluation, not as an optimizer start.")
        self.add_text("L2 and Walsh searches remain separate. Score gaps and ties indicate ambiguity, not posterior probabilities.")
        self.add_text("The coarse Walsh baseline can stall on plateaus. A poor result is retained rather than repaired with a hidden average.")
        self.summary = Gtk.Label(xalign=0)
        self.summary.set_line_wrap(True)
        self.summary.set_selectable(True)
        outer.pack_start(self.summary, False, False, 0)
        self.connect("destroy", self.on_destroy)
        self.refresh()

    def on_destroy(self, *_args):
        if Gtk.main_level() > 0:
            Gtk.main_quit()

    def add_text(self, value):
        label = Gtk.Label(label=value, xalign=0)
        label.set_line_wrap(True)
        self.control_box.pack_start(label, False, False, 0)

    def add_scale(self, name, label, minimum, maximum, step, initial, digits):
        self.add_text(label)
        scale = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, minimum, maximum, step)
        scale.set_value(initial)
        scale.set_digits(digits)
        scale.set_draw_value(True)
        scale.connect("value-changed", self.update_model)
        self.control_box.pack_start(scale, False, False, 0)
        self.controls[name] = scale

    def current_settings(self):
        return {
            "metric": self.metric.get_active_id(),
            "view_angle": self.controls["view_angle"].get_value(),
            "noise": self.controls["noise"].get_value(),
            "seed": self.controls["seed"].get_value_as_int(),
        }

    def update_model(self, *_args):
        try:
            self.refresh()
        except (OSError, RuntimeError, ValueError) as error:
            self.summary.set_text(f"Halo Field update failed: {error}")

    def refresh(self):
        self.settings = self.current_settings()
        self.report = experiment(**self.settings)
        self.scene, _ = halo_scene(self.report)
        self.canvas.set_model(self.scene, None, None)
        self.summary.set_text(self.report["summary"] + " · synthetic geometry only")

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
        dialog.set_current_name(f"halo-field.{suffix}")
        dialog.set_do_overwrite_confirmation(True)
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.export_current(dialog.get_filename())
        except (OSError, ValueError, RuntimeError) as error:
            self.summary.set_text(f"Export failed: {error}")
        finally:
            dialog.destroy()


def launch_halo(metric="both", view_angle=65, noise=0.0, seed=7):
    Gtk.init([])
    window = HaloWindow(metric=metric, view_angle=view_angle, noise=noise, seed=seed)
    window.show_all()
    Gtk.main()
