"""Native Cairo chart for accessible-volume threshold sweeps."""

from __future__ import annotations

import cairo
import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from .model import CaseEvent


class ForecastChart(Gtk.DrawingArea):
    def __init__(self):
        super().__init__()
        self.series = []
        self.vocabulary_size = None
        self.set_size_request(480, 320)
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.get_accessible().set_name("Accessible-volume chart")
        self.get_accessible().set_description(
            "Line chart of accessible volume at each probability threshold. The Lab event details provide the text alternative."
        )

    def set_event(self, event: CaseEvent | None) -> None:
        self.series = event.accessible_volume if event and event.event_type == "model_forecast" else []
        measurement = event.details.get("measurement", {}) if event else {}
        self.vocabulary_size = measurement.get("vocabulary_size") if self.series else None
        self.queue_draw()

    def do_draw(self, context: cairo.Context) -> bool:
        allocation = self.get_allocation()
        width = max(1, allocation.width)
        height = max(1, allocation.height)
        style = self.get_style_context()
        background = style.get_background_color(self.get_state_flags())
        foreground = style.get_color(self.get_state_flags())
        context.set_source_rgba(background.red, background.green, background.blue, background.alpha)
        context.paint()
        context.set_source_rgba(foreground.red, foreground.green, foreground.blue, 0.85)
        context.select_font_face("Sans")
        context.set_font_size(12)
        if not self.series:
            context.move_to(28, 42)
            context.show_text("Select a model_forecast event to inspect its threshold sweep.")
            return False
        left, top, right, bottom = 64, 44, max(65, width - 28), max(46, height - 52)
        context.set_font_size(15)
        context.move_to(left, 24)
        title = "Accessible volume by probability threshold"
        if self.vocabulary_size is not None:
            title += f" (vocabulary {self.vocabulary_size})"
        context.show_text(title)
        maximum = max(1, max(count for _tau, count, _normalized in self.series))
        plot_width = max(1, right - left)
        plot_height = max(1, bottom - top)
        context.set_line_width(1)
        for index in range(5):
            value = maximum * index / 4
            y = bottom - plot_height * index / 4
            context.set_source_rgba(foreground.red, foreground.green, foreground.blue, 0.16)
            context.move_to(left, y)
            context.line_to(right, y)
            context.stroke()
            context.set_source_rgba(foreground.red, foreground.green, foreground.blue, 0.75)
            context.move_to(8, y + 4)
            context.show_text(str(round(value)))
        points = []
        for index, (tau, count, _normalized) in enumerate(self.series):
            x = left + (plot_width * index / max(1, len(self.series) - 1))
            y = bottom - plot_height * count / maximum
            points.append((x, y))
            context.set_source_rgba(foreground.red, foreground.green, foreground.blue, 0.8)
            context.move_to(x - 10, bottom + 22)
            context.show_text(f"{tau:.2f}")
            context.move_to(x - 5, y - 9)
            context.show_text(str(count))
        context.set_source_rgba(0.20, 0.45, 0.75, 0.95)
        context.set_line_width(2.5)
        for index, (x, y) in enumerate(points):
            if index == 0:
                context.move_to(x, y)
            else:
                context.line_to(x, y)
        context.stroke()
        for x, y in points:
            context.arc(x, y, 4, 0, 6.283185307179586)
            context.fill()
        context.set_source_rgba(foreground.red, foreground.green, foreground.blue, 0.75)
        context.move_to(left, height - 12)
        context.show_text("Probability threshold τ")
        return False
