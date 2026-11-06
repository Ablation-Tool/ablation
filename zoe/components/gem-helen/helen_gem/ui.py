from __future__ import annotations

from copy import deepcopy
import math
import os
from pathlib import Path

import gi
gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
gi.require_foreign("cairo")
from gi.repository import Gdk, Gtk, Pango

from .core import (
    MODULES, DEFAULT_SOURCE, DEFAULT_TARGET, VolumeBridge,
    circle_scene, clock_scene, ellipses_scene, graph_scene, landmark_scene,
    onset_scene, parabola_scene, procrustes, volume_scene,
)
from .onset import load_experiment
from .render import draw_cairo, scene_layout, write_png, write_scene_json, write_svg

PRESETS = {
    "baseline": [.70, .20, .08, .02],
    "metadata": [.55, .35, .08, .02],
    "concentrated": [1.0, 0.0, 0.0, 0.0],
    "broad": [.25, .25, .25, .25],
}


class HelenCanvas(Gtk.DrawingArea):
    def __init__(self, on_landmark):
        super().__init__()
        self.on_landmark = on_landmark
        self.scene = None
        self.source = None
        self.target = None
        self.layout = None
        self.layout_size = None
        self.dragging = None
        self.selected = None
        self.set_size_request(560, 420)
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_can_focus(True)
        self.add_events(Gdk.EventMask.BUTTON_PRESS_MASK | Gdk.EventMask.BUTTON_RELEASE_MASK | Gdk.EventMask.POINTER_MOTION_MASK)
        self.get_accessible().set_description("GEM HELEN interactive canvas. Drag Procrustes landmarks or use arrow keys after selecting one.")
        self.connect("button-press-event", self.on_button)
        self.connect("button-release-event", self.on_release)
        self.connect("motion-notify-event", self.on_motion)
        self.connect("key-press-event", self.on_key)
        self.connect("focus-in-event", lambda *_args: self.queue_draw())
        self.connect("focus-out-event", lambda *_args: self.queue_draw())

    def set_model(self, scene, source=None, target=None):
        self.scene, self.source, self.target = scene, source, target
        self.layout_size = None
        if source is None or target is None:
            self.dragging = None
            self.selected = None
        self.queue_draw()

    def update_layout(self):
        size = max(1, self.get_allocated_width()), max(1, self.get_allocated_height())
        if self.scene is not None and size != self.layout_size:
            scale, offset_x, offset_y = scene_layout(self.scene, *size)
            self.layout = scale, offset_x, offset_y
            self.layout_size = size
        return self.layout

    def landmark_at(self, x, y):
        if self.source is None:
            return None
        scale, offset_x, offset_y = self.update_layout()
        for prefix, points in (("p", self.source), ("q", self.target)):
            for index, point in enumerate(points):
                if math.hypot(x-offset_x-point[0]*scale, y-offset_y-point[1]*scale) <= 14:
                    return prefix, index
        return None

    def on_button(self, _widget, event):
        if event.button != 1:
            return False
        self.grab_focus()
        self.selected = self.landmark_at(event.x, event.y)
        self.dragging = self.selected
        self.queue_draw()
        return self.selected is not None

    def on_release(self, *_args):
        self.dragging = None
        return False

    def on_motion(self, _widget, event):
        if self.dragging is None:
            return False
        scale, offset_x, offset_y = self.update_layout()
        point = [
            min(self.scene.width, max(0, (event.x-offset_x)/scale)),
            min(self.scene.height, max(0, (event.y-offset_y)/scale)),
        ]
        self.on_landmark(self.dragging[0], self.dragging[1], point)
        return True

    def on_key(self, _widget, event):
        if self.selected is None:
            return False
        key = Gdk.keyval_name(event.keyval)
        movements = {"Left": (-1, 0), "Right": (1, 0), "Up": (0, -1), "Down": (0, 1)}
        if key == "Escape":
            self.selected = None
            self.queue_draw()
            return True
        if key not in movements:
            return False
        prefix, index = self.selected
        points = self.source if prefix == "p" else self.target
        dx, dy = movements[key]
        step = 10 if event.state & Gdk.ModifierType.SHIFT_MASK else 1
        point = [
            min(self.scene.width, max(0, points[index][0]+step*dx)),
            min(self.scene.height, max(0, points[index][1]+step*dy)),
        ]
        self.on_landmark(prefix, index, point)
        return True

    def do_draw(self, context):
        if self.scene is None:
            return False
        scale, offset_x, offset_y = self.update_layout()
        draw_cairo(context, self.scene, self.get_allocated_width(), self.get_allocated_height())
        if self.selected is not None:
            prefix, index = self.selected
            points = self.source if prefix == "p" else self.target
            x, y = offset_x+points[index][0]*scale, offset_y+points[index][1]*scale
            context.set_source_rgb(.95, .35, .05)
            context.set_line_width(2)
            context.arc(x, y, 11, 0, math.tau)
            context.stroke()
        return False


class HelenWindow(Gtk.Window):
    def __init__(self, module="procrustes"):
        super().__init__(title="GEM HELEN")
        self.set_default_size(1200, 780)
        self.module = module if module in MODULES else "procrustes"
        self.controls = {}
        self.updating = False
        self.scene = None
        self.report = {}
        self.source = deepcopy(DEFAULT_SOURCE)
        self.target = deepcopy(DEFAULT_TARGET)
        self.onset_data = None
        self.volume_bridge = VolumeBridge()
        self.volume_current = PRESETS["baseline"]
        self.volume_previous = None
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=10)
        self.add(outer)
        brand = Gtk.Label(xalign=0)
        brand.set_markup("<b>GEM HELEN</b> · right-brain geometry laboratory")
        outer.pack_start(brand, False, False, 0)
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        outer.pack_start(toolbar, False, False, 0)
        self.module_selector = Gtk.ComboBoxText()
        for identifier, title in MODULES.items():
            self.module_selector.append(identifier, title)
        self.module_selector.set_active_id(self.module)
        self.module_selector.connect("changed", self.on_module_changed)
        toolbar.pack_start(self.module_selector, False, False, 0)
        for label, suffix, callback in (("Export SVG", "svg", self.on_export_svg), ("Export PNG", "png", self.on_export_png), ("Export scene", "json", self.on_export_json)):
            button = Gtk.Button(label=label)
            button.connect("clicked", callback)
            toolbar.pack_start(button, False, False, 0)
        toolbar.pack_start(Gtk.Label(label="native · local · optimized", xalign=1), True, True, 0)
        self.panes = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, wide_handle=True)
        outer.pack_start(self.panes, True, True, 0)
        self.canvas = HelenCanvas(self.move_landmark)
        self.panes.pack1(self.canvas, True, True)
        scroller = Gtk.ScrolledWindow()
        scroller.set_size_request(350, -1)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.control_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, border_width=8)
        scroller.add(self.control_box)
        self.panes.pack2(scroller, False, True)
        self.summary = Gtk.Label(xalign=0, selectable=True)
        self.summary.set_line_wrap(True)
        self.summary.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
        outer.pack_end(self.summary, False, False, 0)
        self.build_controls()

    def add_text(self, value):
        label = Gtk.Label(label=value, xalign=0)
        label.set_line_wrap(True)
        label.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
        self.control_box.pack_start(label, False, False, 0)
        return label

    def add_spin(self, key, label, minimum, maximum, step, initial):
        self.add_text(label)
        adjustment = Gtk.Adjustment(value=initial, lower=minimum, upper=maximum, step_increment=step, page_increment=step*10)
        widget = Gtk.SpinButton(adjustment=adjustment, numeric=True)
        widget.set_digits(0 if step >= 1 else 3)
        widget.connect("value-changed", self.on_control_changed)
        self.control_box.pack_start(widget, False, False, 0)
        self.controls[key] = widget

    def add_scale(self, key, label, minimum, maximum, step, initial):
        self.add_text(label)
        adjustment = Gtk.Adjustment(value=initial, lower=minimum, upper=maximum, step_increment=step, page_increment=step*10)
        widget = Gtk.Scale(orientation=Gtk.Orientation.HORIZONTAL, adjustment=adjustment)
        widget.set_digits(3)
        widget.set_value_pos(Gtk.PositionType.RIGHT)
        widget.connect("value-changed", self.on_control_changed)
        self.control_box.pack_start(widget, False, False, 0)
        self.controls[key] = widget

    def add_combo(self, key, label, choices, initial):
        self.add_text(label)
        widget = Gtk.ComboBoxText()
        for identifier, title in choices:
            widget.append(identifier, title)
        widget.set_active_id(initial)
        widget.connect("changed", self.on_control_changed)
        self.control_box.pack_start(widget, False, False, 0)
        self.controls[key] = widget

    def add_action(self, label, callback):
        button = Gtk.Button(label=label)
        button.connect("clicked", callback)
        self.control_box.pack_start(button, False, False, 0)

    def build_controls(self):
        self.updating = True
        for child in self.control_box.get_children():
            self.control_box.remove(child)
        self.controls = {}
        self.add_text(MODULES[self.module])
        if self.module == "procrustes":
            self.add_text("Drag red source and blue target landmarks. Two pairs determine similarity; affine needs three noncollinear pairs.")
            self.add_combo("mode", "Alignment model", (("similarity", "Similarity"), ("rigid", "Rigid"), ("affine", "Affine")), "similarity")
            self.add_action("Add landmark pair", self.add_pair)
            self.add_action("Remove landmark pair", self.remove_pair)
            self.add_action("Reset landmarks", self.reset_landmarks)
        elif self.module == "ellipses":
            self.add_spin("count", "Ellipse count", 2, 64, 1, 16)
            self.add_spin("selected", "Highlighted index", 0, 63, 1, 15)
            for key, label, initial in (("a0", "Horizontal radius at t=0", 99.5), ("a1", "Horizontal radius at t=1", 286.5), ("b0", "Vertical radius at t=0", 198), ("b1", "Vertical radius at t=1", 73)):
                self.add_scale(key, label, 1, 320, .5, initial)
        elif self.module == "parabola":
            self.add_spin("segments", "Ruled segments", 2, 256, 1, 32)
            self.add_scale("t", "Envelope parameter t", 0, 1, .001, .5)
        elif self.module == "circle":
            self.add_scale("radius", "Radius", 10, 207, .1, 207)
            self.add_scale("angle", "Central angle in degrees", 1, 360, .1, 100.1)
        elif self.module == "clock":
            self.add_spin("modulus", "Modulus", 2, 48, 1, 12)
            self.add_spin("value", "Integer value", 0, 999, 1, 15)
        elif self.module == "graph":
            self.add_combo("crossings", "Interpret six line crossings", (("no", "Not vertices"), ("yes", "Vertices")), "no")
            self.add_text("The graph is intentionally ambiguous. Both cycle-rank interpretations remain visible.")
        elif self.module == "volume":
            self.add_combo("preset", "Next categorical observation", tuple((key, key) for key in PRESETS), "baseline")
            self.add_scale("tau", "Probability threshold τ", 0, .5, .001, .05)
            self.add_spin("minimum", "Target band minimum", 0, 8, 1, 1)
            self.add_spin("maximum", "Target band maximum", 0, 8, 1, 4)
            self.add_action("Observe distribution", self.observe_volume)
            self.add_action("Reset bridge", self.reset_volume)
            self.add_text("Observation updates the previous distribution. No automatic action is executed.")
        elif self.module == "onset":
            self.add_scale("tau", "Probability threshold τ", .005, .5, .001, .05)
            self.add_scale("temperature", "Experimental distribution temperature", .25, 4, .01, 1)
            self.add_action("Reset Onset parameters", self.reload_onset)
            self.add_text("Precomputed seed-7 experiment: no model download, NumPy, scikit-learn, or clustering at startup. Temperature transforms probabilities only.")
            self.add_text("HOP negative baseline: 11.3% top-1, versus 41.3% linear velocity and 46.6% model. It supplies no categorical accessible volume.")
        self.updating = False
        self.refresh()
        self.control_box.show_all()

    def on_module_changed(self, widget):
        if not self.updating:
            self.module = widget.get_active_id()
            self.build_controls()

    def on_control_changed(self, *_args):
        if not self.updating:
            self.refresh()

    def value(self, key):
        return self.controls[key].get_value()

    def integer(self, key):
        return self.controls[key].get_value_as_int()

    def choice(self, key):
        return self.controls[key].get_active_id()

    def refresh(self):
        if self.module == "procrustes":
            self.refresh_procrustes()
        elif self.module == "ellipses":
            self.scene, self.report = ellipses_scene(self.integer("count"), self.integer("selected"), *(self.value(key) for key in ("a0", "a1", "b0", "b1")))
        elif self.module == "parabola":
            self.scene, self.report = parabola_scene(self.integer("segments"), self.value("t"))
        elif self.module == "circle":
            self.scene, self.report = circle_scene(self.value("radius"), self.value("angle"))
        elif self.module == "clock":
            self.scene, self.report = clock_scene(self.integer("modulus"), self.integer("value"))
        elif self.module == "graph":
            self.scene, self.report = graph_scene(self.choice("crossings") == "yes")
        elif self.module == "volume":
            self.scene, self.report = volume_scene(self.volume_current, self.volume_previous, self.value("tau"), self.integer("minimum"), self.integer("maximum"))
        elif self.module == "onset":
            try:
                if self.onset_data is None:
                    self.onset_data = load_experiment()
                self.scene, self.report = onset_scene(self.onset_data, self.value("tau"), self.value("temperature"))
            except (OSError, ValueError) as error:
                self.scene, self.report = None, {"error": str(error)}
        if self.scene is not None and self.module != "procrustes":
            self.canvas.set_model(self.scene)
        elif self.scene is None:
            self.canvas.set_model(None)
        self.update_summary()
        return self.scene

    def refresh_procrustes(self):
        try:
            self.report = procrustes(self.source, self.target, self.choice("mode"))
            self.scene = landmark_scene(self.source, self.target, self.report)
        except ValueError as error:
            self.report = {"error": str(error)}
            self.scene = landmark_scene(self.source, self.target)
        self.canvas.set_model(self.scene, self.source, self.target)

    def move_landmark(self, prefix, index, point):
        points = self.source if prefix == "p" else self.target
        points[index] = point
        self.refresh_procrustes()
        self.canvas.selected = (prefix, index)
        self.update_summary()

    def add_pair(self, *_args):
        if len(self.source) < 8:
            index = len(self.source)
            self.source.append([180+25*index, 230+10*index])
            self.target.append([440+20*index, 250+12*index])
            self.refresh()

    def remove_pair(self, *_args):
        if len(self.source) > 2:
            self.source.pop()
            self.target.pop()
            self.refresh()

    def reset_landmarks(self, *_args):
        self.source, self.target = deepcopy(DEFAULT_SOURCE), deepcopy(DEFAULT_TARGET)
        self.refresh()

    def observe_volume(self, *_args):
        minimum, maximum = self.integer("minimum"), self.integer("maximum")
        if maximum < minimum:
            self.report = {"error": "Target maximum must be at least the minimum"}
            self.update_summary()
            return
        self.volume_bridge.minimum, self.volume_bridge.maximum = minimum, maximum
        current = PRESETS[self.choice("preset")]
        self.volume_bridge.observe(current, self.value("tau"))
        self.volume_previous, self.volume_current = self.volume_current, current
        self.refresh()

    def reset_volume(self, *_args):
        self.volume_bridge = VolumeBridge(self.integer("minimum"), self.integer("maximum"))
        self.volume_previous = None
        self.refresh()

    def reload_onset(self, *_args):
        self.onset_data = load_experiment()
        self.controls["tau"].set_value(.05)
        self.controls["temperature"].set_value(1.0)
        self.refresh()

    def update_summary(self):
        if not self.report:
            return
        if "error" in self.report:
            value = self.report["error"]
        elif self.module == "procrustes":
            matrix = self.report["matrix"]
            value = (
                f"A = [[{matrix[0][0]:.6f}, {matrix[0][1]:.6f}], [{matrix[1][0]:.6f}, {matrix[1][1]:.6f}]]\n"
                f"t = ({self.report['translation'][0]:.6f}, {self.report['translation'][1]:.6f}) · "
                f"scale={self.report['scale']:.6f} angle={self.report['rotation_degrees']:.4f}° RMS={self.report['rmse_per_landmark']:.6f}"
            )
        elif self.module == "volume":
            value = self.report["summary"]
        elif self.module == "onset":
            value = (
                f"Forward: top-1 {self.report['forward']['top1']:.1%}, log-loss {self.report['forward']['log_loss']:.3f}, A(τ)={self.report['forward_at_tau']:.2f}. "
                f"Retrograde: top-1 {self.report['retrograde']['top1']:.1%}, log-loss {self.report['retrograde']['log_loss']:.3f}, A(τ)={self.report['retrograde_at_tau']:.2f}.\n"
                f"Temperature={self.report['temperature']:.2f}; precomputed synthetic evidence only. HOP and linear extrapolation are separate deterministic baselines."
            )
        else:
            value = " · ".join(f"{key}={item}" for key, item in self.report.items() if not isinstance(item, (dict, list)))
        self.summary.set_text(value)
        self.summary.set_tooltip_text(value)

    def export_current(self, path):
        if self.scene is None:
            self.refresh()
        if self.scene is None:
            raise ValueError("there is no HELEN scene to export")
        path = Path(path)
        suffix = path.suffix.lower()
        if suffix == ".svg":
            return write_svg(self.scene, path)
        if suffix == ".png":
            return write_png(self.scene, path)
        if suffix == ".json":
            return write_scene_json(self.scene, path, exclusive=False)
        raise ValueError("HELEN export must use .svg, .png, or .json")

    def choose_export(self, suffix):
        dialog = Gtk.FileChooserDialog(title=f"Export {suffix.upper()}", transient_for=self, action=Gtk.FileChooserAction.SAVE)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Export", Gtk.ResponseType.OK)
        dialog.set_do_overwrite_confirmation(True)
        dialog.set_current_name(f"helen-{self.module}.{suffix}")
        try:
            if dialog.run() == Gtk.ResponseType.OK:
                self.export_current(dialog.get_filename())
        finally:
            dialog.destroy()

    def on_export_svg(self, *_args):
        self.choose_export("svg")

    def on_export_png(self, *_args):
        self.choose_export("png")

    def on_export_json(self, *_args):
        self.choose_export("json")


def show_helen(module="procrustes"):
    window = HelenWindow(module)
    window.show_all()
    return window


def launch_helen(module="procrustes"):
    if not os.environ.get("DISPLAY"):
        raise RuntimeError("GEM HELEN needs a GTK display; use --output for headless export")
    window = show_helen(module)
    window.connect("destroy", Gtk.main_quit)
    Gtk.main()
    return window
