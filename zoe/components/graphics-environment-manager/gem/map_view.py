from collections import defaultdict
from dataclasses import dataclass

import gi
gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, Gtk, Pango

from .chart_colors import baobab_hex, readable_text_color


PAGE_SIZE = 20


@dataclass(frozen=True)
class TreemapTile:
    label: str
    status: str
    weight: int
    event: dict | None
    other: bool
    x: int
    y: int
    width: int
    height: int
    position: float
    color: str


def descendant_counts(events):
    by_id = {event["id"]: event for event in events}
    counts = {event["id"]: 0 for event in events}
    for event in events:
        current = event["parent_id"]
        seen = set()
        while current is not None and current not in seen:
            seen.add(current)
            counts[current] += 1
            current = by_id.get(current, {}).get("parent_id")
    return dict(counts)


def treemap_layout(items, x, y, width, height, horizontal=True):
    if not items or width <= 0 or height <= 0:
        return []
    if len(items) == 1:
        weight, payload = items[0]
        return [(weight, payload, x, y, width, height)]
    total = sum(weight for weight, _payload in items)
    if total <= 0:
        raise ValueError("treemap weights must be positive")
    split = min(
        range(1, len(items)),
        key=lambda index: abs(sum(weight for weight, _ in items[:index]) - total / 2),
    )
    left = items[:split]
    right = items[split:]
    left_total = sum(weight for weight, _ in left)
    if horizontal:
        left_width = width * left_total / total
        return treemap_layout(left, x, y, left_width, height, not horizontal) + treemap_layout(
            right, x + left_width, y, width - left_width, height, not horizontal,
        )
    left_height = height * left_total / total
    return treemap_layout(left, x, y, width, left_height, not horizontal) + treemap_layout(
        right, x, y + left_height, width, height - left_height, not horizontal,
    )


class InvestigationMap(Gtk.Fixed):
    def __init__(self, on_select):
        super().__init__()
        self.on_select = on_select
        self.events = []
        self.by_id = {}
        self.children = defaultdict(list)
        self.counts = {}
        self.parent_id = None
        self.selected_id = None
        self.offset = 0
        self.tiles = []
        self.tile_buttons = []
        self.last_size = None
        self.set_size_request(320, 280)

    def do_get_preferred_width(self):
        return (320, 320)

    def do_get_preferred_height(self):
        return (280, 280)

    def do_size_allocate(self, allocation):
        self.set_allocation(allocation)
        size = (max(1, allocation.width), max(1, allocation.height))
        if size != self.last_size:
            self.last_size = size
            self.rebuild()
        if not self.tile_buttons:
            super().do_size_allocate(allocation)
            return
        for tile, button in self.tile_buttons:
            child_allocation = Gdk.Rectangle()
            child_allocation.x = int(tile.x)
            child_allocation.y = int(tile.y)
            child_allocation.width = max(1, int(tile.width))
            child_allocation.height = max(1, int(tile.height))
            button.size_allocate(child_allocation)

    def set_model(self, events, parent_id, selected_id):
        self.events = list(events)
        self.by_id = {event["id"]: event for event in self.events}
        self.children = defaultdict(list)
        for event in self.events:
            self.children[event["parent_id"]].append(event)
        self.counts = descendant_counts(self.events)
        self.parent_id = parent_id
        self.selected_id = selected_id
        self.offset = 0
        self.rebuild()

    def current_children(self):
        return self.children.get(self.parent_id, [])

    def weight(self, event):
        return self.counts.get(event["id"], 0) + 1

    @staticmethod
    def tile_identity(tile):
        return (
            tile.label, tile.status, tile.weight,
            tile.event["id"] if tile.event else None, tile.other,
        )

    def rebuild(self):
        children = sorted(
            self.current_children(),
            key=lambda event: (-self.weight(event), event["label"].casefold()),
        )
        if not children:
            for child in self.get_children():
                child.destroy()
            self.tiles = []
            self.tile_buttons = []
            empty = Gtk.Label(label="No child nodes")
            self.put(empty, 0, 0)
            empty.show()
            self.queue_resize()
            return
        if self.offset >= len(children):
            self.offset = 0
        page = children[self.offset:self.offset + PAGE_SIZE]
        remaining = children[self.offset + PAGE_SIZE:]
        payloads = [(self.weight(event), event) for event in page]
        if remaining:
            payloads.append((sum(self.weight(event) for event in remaining), {"other": len(remaining)}))
        width = max(1, self.get_allocated_width())
        height = max(1, self.get_allocated_height())
        tiles = []
        for weight, event, x, y, tile_width, tile_height in treemap_layout(payloads, 0, 0, width, height):
            other = "other" in event if isinstance(event, dict) else False
            if other:
                label = f"{event['other']} more"
                status = "more"
                event_data = None
            else:
                label = event["label"]
                status = event["status"]
                event_data = event
            position = x / width * 200
            color = "#6a737d" if other else baobab_hex(position)
            tiles.append(TreemapTile(
                label, status, weight, event_data, other, x, y, tile_width, tile_height, position, color,
            ))
        if (
            len(tiles) == len(self.tiles)
            and all(self.tile_identity(new) == self.tile_identity(old) for new, old in zip(tiles, self.tiles))
        ):
            self.tiles = tiles
            self.tile_buttons = [
                (tile, button) for tile, (_old_tile, button) in zip(tiles, self.tile_buttons)
            ]
            for tile, button in self.tile_buttons:
                self.configure_tile(button, tile)
        else:
            for child in self.get_children():
                child.destroy()
            self.tile_buttons = []
            for tile in tiles:
                button = self.make_tile(tile)
                self.tile_buttons.append((tile, button))
                self.put(button, tile.x, tile.y)
            self.tiles = tiles
        self.show_all()
        self.queue_resize()

    def configure_tile(self, button, tile):
        button.set_label(f"{tile.label}\n{tile.status} · {tile.weight} nodes")
        button.set_size_request(1, 1)
        button.set_tooltip_text(self.tile_tooltip(tile))
        label = button.get_child()
        label.set_line_wrap(True)
        label.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        label.set_max_width_chars(24)
        label.set_justify(Gtk.Justification.CENTER)
        hover = tile.color if tile.other else baobab_hex(tile.position, highlighted=True)
        text = readable_text_color(tile.color)
        hover_text = readable_text_color(hover)
        border = "2px solid #e95420" if tile.event and tile.event["id"] == self.selected_id else "1px solid rgba(0, 0, 0, 0.3)"
        provider = Gtk.CssProvider()
        css = (
            f"button {{ background-color: {tile.color}; background-image: none; color: {text}; "
            f"border: {border}; border-radius: 3px; }} "
            f"button:hover {{ background-color: {hover}; background-image: none; color: {hover_text}; }}"
        )
        provider.load_from_data(css.encode())
        context = button.get_style_context()
        previous = getattr(button, "_gem_tile_provider", None)
        if previous is not None:
            context.remove_provider(previous)
        context.add_provider(provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        button._gem_tile_provider = provider

    def make_tile(self, tile):
        button = Gtk.Button()
        self.configure_tile(button, tile)
        button.connect("clicked", lambda _button, selected=tile: self.activate_tile(selected))
        return button

    def tile_tooltip(self, tile):
        if tile.other:
            return "Show the next group of nodes"
        event = tile.event
        lines = [event["label"], f"Type: {event['type']}", f"Status: {event['status']}"]
        if event.get("evidence"):
            lines.append(f"Evidence: {event['evidence']}")
        if event.get("scope"):
            lines.append(f"Scope: {event['scope']}")
        if event.get("note"):
            lines.append(event["note"][:500])
        lines.append("Area = subtree node count · Color = position/depth")
        return "\n".join(lines)

    def activate_tile(self, tile):
        if tile.other:
            children = self.current_children()
            if children:
                self.offset = (self.offset + PAGE_SIZE) % len(children)
                self.rebuild()
            return
        self.on_select(tile.event["id"])
