from __future__ import annotations

import json
from pathlib import Path

import gi
gi.require_version("Gtk", "3.0")
gi.require_foreign("cairo")
from gi.repository import Gtk

from .eye import APERTURES, EyeModel, eye_scene
from .render import write_png, write_svg
from .vdi import write_metafile
from .view import GemView


class EyeWindow(Gtk.Window):
    def __init__(self, model=EyeModel()):
        super().__init__(title="Zoe · Second eye")
        self.set_default_size(1500, 920)
        self.model = model
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
        self.add_scale("focus", "Focus distance (m)", .5, 10, .05, model.focus, 2)
        self.add_scale("baseline", "Stereo baseline (m)", .02, .25, .005, model.baseline, 3)
        self.add_text("Aperture (f-number)")
        aperture = Gtk.ComboBoxText()
        for value in APERTURES:
            aperture.append(str(value), f"f/{value:g}")
        if model.fstop not in APERTURES:
            aperture.append(str(float(model.fstop)), f"f/{model.fstop:g}")
        aperture.set_active_id(str(float(model.fstop)))
        aperture.connect("changed", self.update_model)
        controls.pack_start(aperture, False, False, 0)
        self.aperture = aperture
        self.add_text("Two synthetic views estimate depth from disparity. Focus controls defocus separately. No camera is accessed.")
        self.add_text("The ± range is first-order sensitivity to 0.25-pixel quantization, not a probability or confidence interval.")
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

    def current_model(self):
        return EyeModel(
            focus=self.controls["focus"].get_value(),
            baseline=self.controls["baseline"].get_value(),
            fstop=float(self.aperture.get_active_id()),
        )

    def update_model(self, *_args):
        try:
            self.refresh()
        except (OSError, RuntimeError, ValueError) as error:
            self.summary.set_text(f"Second-eye update failed: {error}")

    def refresh(self):
        self.model = self.current_model()
        self.scene, self.report = eye_scene(self.model)
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
        dialog.set_current_name(f"zoe-second-eye.{suffix}")
        dialog.set_do_overwrite_confirmation(True)
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.export_current(dialog.get_filename())
        except (OSError, ValueError, RuntimeError) as error:
            self.summary.set_text(f"Export failed: {error}")
        finally:
            dialog.destroy()


def launch_eye(model=EyeModel()):
    Gtk.init([])
    window = EyeWindow(model)
    window.show_all()
    Gtk.main()
