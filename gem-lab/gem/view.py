from __future__ import annotations

from dataclasses import dataclass

import gi
gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
gi.require_foreign("cairo")
from gi.repository import Gdk, Gtk

from ._callbacks import weak_callback
from .geometry import Bounds, object_bounds, verify
from .render import draw_cairo


@dataclass(frozen=True)
class GemLayout:
    scale: float
    offset_x: float
    offset_y: float
    width: float
    height: float

    def to_scene(self, x, y):
        return (x - self.offset_x) / self.scale, (y - self.offset_y) / self.scale


def scene_layout(scene, width, height):
    scale = min(width / scene.canvas["width"], height / scene.canvas["height"])
    return GemLayout(
        scale,
        (width - scene.canvas["width"] * scale) / 2,
        (height - scene.canvas["height"] * scale) / 2,
        scene.canvas["width"] * scale,
        scene.canvas["height"] * scale,
    )


class GemView(Gtk.DrawingArea):
    def __init__(self, on_select):
        super().__init__()
        self.on_select = on_select
        self.scene = None
        self.report = None
        self.parent_id = None
        self.selected_id = None
        self.layout = None
        self.layout_size = None
        self.set_size_request(320, 280)
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_can_focus(True)
        self.add_events(Gdk.EventMask.BUTTON_PRESS_MASK | Gdk.EventMask.POINTER_MOTION_MASK | Gdk.EventMask.LEAVE_NOTIFY_MASK)
        self.set_has_tooltip(True)
        self.get_accessible().set_description(
            "GEM investigation geometry. Rectangles are Lab nodes and lines connect their parents. "
            "Constraint checks are deterministic bounding-box and endpoint checks, not human confirmation."
        )
        for signal, callback in (
            ("button-press-event", self.on_button),
            ("motion-notify-event", self.on_motion),
            ("leave-notify-event", self.on_leave),
            ("key-press-event", self.on_key),
        ):
            self.connect(signal, weak_callback(callback))
        self.connect("focus-in-event", lambda *_args: self.queue_draw())
        self.connect("focus-out-event", lambda *_args: self.queue_draw())

    def do_get_preferred_width(self):
        return (320, 320)

    def do_get_preferred_height(self):
        return (280, 280)

    def set_model(self, scene, parent_id, selected_id):
        self.scene = scene
        self.report = verify(scene)
        self.parent_id = parent_id
        self.selected_id = selected_id
        self.layout_size = None
        self.update_layout()
        self.update_tooltip()
        self.queue_draw()

    def update_layout(self):
        size = (max(1, self.get_allocated_width()), max(1, self.get_allocated_height()))
        if self.scene is not None and size != self.layout_size:
            self.layout = scene_layout(self.scene, *size)
            self.layout_size = size
        return self.layout

    def item_at(self, x, y):
        layout = self.update_layout()
        if self.scene is None or layout is None:
            return None
        scene_x, scene_y = layout.to_scene(x, y)
        point = Bounds(scene_x, scene_y, scene_x, scene_y)
        for item in reversed(self.scene.objects):
            if item.get("event_id") and object_bounds(item).contains(point):
                return item
        return None

    def update_tooltip(self, item=None):
        if self.scene is None or not self.scene.objects:
            self.set_tooltip_text("No investigation nodes")
            self.get_accessible().set_name("GEM investigation geometry; no investigation nodes")
            return
        if item is None:
            item = next((entry for entry in self.scene.objects if entry.get("event_id") == self.selected_id), None)
        if item is None:
            self.set_tooltip_text("GEM executable investigation geometry")
            return
        lines = [item.get("label", item["id"]), f"Object: {item['id']}"]
        failures = [
            result for result in self.report.results
            if not result["passed"] and item["id"] in result["objects"]
        ]
        lines.extend(f"FAIL {result['type']}: {result['detail']}" for result in failures)
        lines.append("Click to select the Lab node · Geometry checks are not human review")
        self.set_tooltip_text("\n".join(lines))
        self.get_accessible().set_name(f"GEM Lab node: {item.get('label', item['id'])}")

    def do_draw(self, context):
        if self.scene is None or not self.scene.objects:
            style = self.get_style_context()
            Gtk.render_layout(style, context, 20, 20, self.create_pango_layout("No investigation nodes"))
            return False
        self.update_layout()
        draw_cairo(
            context, self.scene, self.get_allocated_width(), self.get_allocated_height(),
            highlight_ids=self.report.failed_ids,
        )
        if self.has_focus():
            foreground = self.get_style_context().get_color(Gtk.StateFlags.NORMAL)
            context.set_source_rgba(foreground.red, foreground.green, foreground.blue, foreground.alpha)
            context.set_line_width(1)
            context.rectangle(0.5, 0.5, self.get_allocated_width() - 1, self.get_allocated_height() - 1)
            context.stroke()
        return False

    def activate_item(self, item):
        if item is not None and item.get("event_id"):
            self.on_select(item["event_id"])
            return True
        return False

    def on_button(self, _widget, event):
        if event.button != 1:
            return False
        self.grab_focus()
        return self.activate_item(self.item_at(event.x, event.y))

    def on_motion(self, _widget, event):
        self.update_tooltip(self.item_at(event.x, event.y))
        return False

    def on_leave(self, *_args):
        self.update_tooltip()
        return False

    def on_key(self, _widget, event):
        key = Gdk.keyval_name(event.keyval)
        if key in ("Return", "KP_Enter") and self.scene is not None:
            item = next((entry for entry in self.scene.objects if entry.get("event_id") == self.selected_id), None)
            return self.activate_item(item)
        if key == "Home" and self.parent_id:
            self.on_select(self.parent_id)
            return True
        return False
