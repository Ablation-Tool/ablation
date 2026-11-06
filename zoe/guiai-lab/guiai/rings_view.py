# Ring geometry and palette adapted from GNOME Baobab 49.1.
# Copyright (C) 2008 Igalia; 2013 Stefano Facchini.
# This file is distributed under GPL-2.0-or-later; see licenses/GPL-2.0.txt.
from collections import defaultdict
from dataclasses import dataclass, replace
import math

import gi
gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
gi.require_foreign("cairo")
import cairo  # noqa: F401
from gi.repository import Gdk, Gtk, Pango

from ._callbacks import weak_callback
from .chart_colors import CHART_COLORS, baobab_color
from .map_view import descendant_counts


TAU = 2 * math.pi
MAX_DEPTH = 5
MIN_DEPTH = 1
MIN_ANGLE = 0.03
EDGE_ANGLE = 0.004


@dataclass(frozen=True)
class RingSector:
    event: dict
    weight: int
    depth: int
    inner_radius: float
    outer_radius: float
    start_angle: float
    angle: float
    continued: bool = False


@dataclass(frozen=True)
class RingLayout:
    sectors: tuple
    root: RingSector | None
    omitted: int
    center_x: float
    center_y: float


def sector_color(start_angle, depth, highlighted=False):
    return baobab_color(start_angle / math.pi * 99, depth, highlighted)


def ring_layout(events, root_id, width, height, max_depth=MAX_DEPTH):
    center_x, center_y = width / 2, height / 2
    by_id = {event["id"]: event for event in events}
    root_event = by_id.get(root_id)
    if root_event is None or width <= 0 or height <= 0:
        return RingLayout((), None, 0, center_x, center_y)
    max_depth = max(MIN_DEPTH, min(MAX_DEPTH, max_depth))
    counts = descendant_counts(events)
    children = defaultdict(list)
    for event in events:
        children[event["parent_id"]].append(event)
    ordered = {
        node_id: sorted(items, key=lambda event: (-counts[event["id"]] - 1, event["label"].casefold(), event["id"]))
        for node_id, items in children.items()
    }
    radius = max(0, min(width, height) / 2 - 6)
    thickness = radius / (max_depth + 1)
    root = RingSector(root_event, counts[root_id] + 1, 0, 0, thickness, 0, TAU)
    sectors = [root]
    pending = [root]
    omitted = 0
    while pending:
        parent = pending.pop()
        descendants = ordered.get(parent.event["id"], [])
        if parent.depth >= max_depth:
            if descendants:
                sectors[sectors.index(parent)] = replace(parent, continued=True)
                omitted += parent.weight - 1
            continue
        start = parent.start_angle
        for event in descendants:
            weight = counts[event["id"]] + 1
            angle = parent.angle * weight / parent.weight
            if angle < MIN_ANGLE:
                omitted += weight
                continue
            depth = parent.depth + 1
            sector = RingSector(
                event, weight, depth, depth * thickness, (depth + 1) * thickness,
                start, angle,
            )
            sectors.append(sector)
            pending.append(sector)
            start += angle
    return RingLayout(tuple(sectors), root, omitted, center_x, center_y)


def sector_at(layout, x, y):
    dx, dy = x - layout.center_x, y - layout.center_y
    radius = math.hypot(dx, dy)
    angle = math.atan2(dy, dx)
    if angle <= 0:
        angle += TAU
    for sector in reversed(layout.sectors):
        if (
            sector.inner_radius <= radius <= sector.outer_radius
            and sector.start_angle <= angle <= sector.start_angle + sector.angle
        ):
            return sector
    return None


def sector_tooltip(sector):
    event = sector.event
    lines = [
        event["label"],
        f"Type: {event['type']} · Status: {event['status']}",
        f"Subtree: {sector.weight} nodes, including this node",
    ]
    if event.get("evidence"):
        lines.append(f"Evidence: {event['evidence']}")
    if event.get("scope"):
        lines.append(f"Scope: {event['scope']}")
    if event.get("note"):
        lines.append(event["note"][:500])
    lines.append("Angle = subtree node count · Color = ring position/depth")
    return "\n".join(lines)


class InvestigationRings(Gtk.DrawingArea):
    def __init__(self, on_select, summary_changed=None):
        super().__init__()
        self.on_select = on_select
        self.summary_changed = summary_changed
        self.events = []
        self.by_id = {}
        self.root_id = None
        self.selected_id = None
        self.hovered_id = None
        self.max_depth = MAX_DEPTH
        self.layout = RingLayout((), None, 0, 0, 0)
        self.layout_size = None
        self.set_size_request(320, 280)
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_can_focus(True)
        self.add_events(
            Gdk.EventMask.BUTTON_PRESS_MASK | Gdk.EventMask.POINTER_MOTION_MASK
            | Gdk.EventMask.LEAVE_NOTIFY_MASK | Gdk.EventMask.SCROLL_MASK
        )
        self.set_has_tooltip(True)
        self.get_accessible().set_description(
            "Lab rings. Angular area represents subtree node count, not bytes or analysis coverage."
        )
        for signal, callback in (
            ("motion-notify-event", self.on_motion),
            ("leave-notify-event", self.on_leave),
            ("button-press-event", self.on_button),
            ("key-press-event", self.on_key),
            ("scroll-event", self.on_scroll),
        ):
            self.connect(signal, weak_callback(callback))
        self.connect("focus-in-event", lambda *_args: self.queue_draw())
        self.connect("focus-out-event", lambda *_args: self.queue_draw())

    def do_get_preferred_width(self):
        return (320, 320)

    def do_get_preferred_height(self):
        return (280, 280)

    def set_model(self, events, parent_id, selected_id):
        self.events = list(events)
        self.by_id = {event["id"]: event for event in self.events}
        self.root_id = parent_id
        self.selected_id = selected_id
        self.hovered_id = None
        self.layout_size = None
        self.update_layout()
        self.update_tooltip()
        self.queue_draw()

    def update_layout(self):
        size = (max(1, self.get_allocated_width()), max(1, self.get_allocated_height()))
        if size != self.layout_size:
            self.layout = ring_layout(self.events, self.root_id, *size, self.max_depth)
            self.layout_size = size
            if self.summary_changed is not None:
                self.summary_changed(self.layout.omitted)
        return self.layout

    @property
    def sectors(self):
        return self.layout.sectors

    @property
    def omitted(self):
        return self.layout.omitted

    def update_tooltip(self, sector=None):
        if sector is None:
            sector = next((item for item in self.sectors if item.event["id"] == self.selected_id), self.layout.root)
        self.set_tooltip_text(sector_tooltip(sector) if sector is not None else "No investigation nodes")
        name = sector.event["label"] if sector is not None else "No investigation nodes"
        self.get_accessible().set_name(f"{name}; {sector.weight} nodes" if sector is not None else name)

    def do_draw(self, context):
        self.update_layout()
        style = self.get_style_context()
        foreground = style.get_color(Gtk.StateFlags.NORMAL)
        found, background = style.lookup_color("theme_bg_color")
        if not found:
            background = style.get_background_color(Gtk.StateFlags.NORMAL)
        if self.layout.root is None:
            label = self.create_pango_layout("No investigation nodes")
            Gtk.render_layout(style, context, 20, 20, label)
            return False
        for sector in self.layout.sectors:
            selected = sector.event["id"] == self.selected_id
            if sector.depth == 0:
                context.set_line_width(2.5 if selected else 1)
                self.set_source(context, "#e95420" if selected else foreground.to_string())
                context.arc(self.layout.center_x, self.layout.center_y, sector.outer_radius + 1, 0, TAU)
                context.stroke()
                continue
            end = sector.start_angle + sector.angle
            context.arc(self.layout.center_x, self.layout.center_y, sector.inner_radius, sector.start_angle, end)
            context.arc_negative(self.layout.center_x, self.layout.center_y, sector.outer_radius, end, sector.start_angle)
            context.close_path()
            context.set_source_rgb(*sector_color(sector.start_angle, sector.depth, sector.event["id"] == self.hovered_id))
            context.fill_preserve()
            self.set_source(context, "#e95420" if selected else background.to_string())
            context.set_line_width(2.5 if selected else 1)
            context.stroke()
            if sector.continued:
                self.set_source(context, foreground.to_string())
                context.set_line_width(3)
                context.arc(
                    self.layout.center_x, self.layout.center_y, sector.outer_radius + 4,
                    sector.start_angle + EDGE_ANGLE, end - EDGE_ANGLE,
                )
                context.stroke()
        root = self.layout.root
        label = self.create_pango_layout(f"{root.weight} nodes")
        label.set_alignment(Pango.Alignment.CENTER)
        width, height = label.get_pixel_size()
        if width < 2 * max(0, root.outer_radius - 8):
            Gtk.render_layout(
                style, context, self.layout.center_x - width / 2,
                self.layout.center_y - height / 2, label,
            )
        if self.layout.omitted:
            label = self.create_pango_layout(f"{self.layout.omitted} nodes below display depth/angular resolution")
            font = label.get_context().get_font_description()
            if font is not None:
                font.set_size(9 * Pango.SCALE)
                label.get_context().set_font_description(font)
            width, height = label.get_pixel_size()
            if width <= self.get_allocated_width() - 16:
                Gtk.render_layout(style, context, 8, self.get_allocated_height() - height - 6, label)
        return False

    @staticmethod
    def set_source(context, color):
        rgba = Gdk.RGBA()
        rgba.parse(color)
        context.set_source_rgba(rgba.red, rgba.green, rgba.blue, rgba.alpha)

    def activate_sector(self, sector):
        if sector is None:
            return
        event = sector.event
        if sector.depth == 0 and event.get("parent_id"):
            self.on_select(event["parent_id"])
        else:
            self.on_select(event["id"])

    def on_motion(self, _widget, event):
        sector = sector_at(self.update_layout(), event.x, event.y)
        node_id = sector.event["id"] if sector is not None else None
        if node_id != self.hovered_id:
            self.hovered_id = node_id
            self.update_tooltip(sector)
            self.queue_draw()
        return False

    def on_leave(self, *_args):
        self.hovered_id = None
        self.update_tooltip()
        self.queue_draw()
        return False

    def on_button(self, _widget, event):
        if event.button not in (1, 2):
            return False
        self.grab_focus()
        if event.button == 2:
            self.activate_sector(self.layout.root)
        else:
            self.activate_sector(sector_at(self.update_layout(), event.x, event.y))
        return True

    def on_scroll(self, _widget, event):
        if event.delta_y < 0:
            self.set_depth(self.max_depth + 1)
        elif event.delta_y > 0:
            self.set_depth(self.max_depth - 1)
        return True

    def set_depth(self, depth):
        depth = max(MIN_DEPTH, min(MAX_DEPTH, depth))
        if depth != self.max_depth:
            self.max_depth = depth
            self.layout_size = None
            self.update_layout()
            self.queue_draw()

    def on_key(self, _widget, event):
        key = Gdk.keyval_name(event.keyval)
        if key in ("plus", "equal", "KP_Add"):
            self.set_depth(self.max_depth + 1)
            return True
        if key in ("minus", "KP_Subtract"):
            self.set_depth(self.max_depth - 1)
            return True
        selected = self.by_id.get(self.selected_id) or self.by_id.get(self.root_id)
        if selected is None:
            return False
        if key in ("Return", "KP_Enter"):
            sector = next((item for item in self.sectors if item.event["id"] == selected["id"]), self.layout.root)
            self.activate_sector(sector)
        elif key in ("Up", "Left"):
            if selected.get("parent_id"):
                self.on_select(selected["parent_id"])
        elif key in ("Down", "Right"):
            sector = next(
                (item for item in self.sectors if item.event["parent_id"] == selected["id"]), None,
            )
            if sector is not None:
                self.on_select(sector.event["id"])
        elif key == "Home":
            root = next((event for event in self.events if event["parent_id"] is None), selected)
            self.on_select(root["id"])
        else:
            return False
        return True
