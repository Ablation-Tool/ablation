# Palette and position/depth coloring adapted from GNOME Baobab 49.1.
# Copyright (C) 2008 Igalia; 2013 Stefano Facchini.
# This file is distributed under GPL-2.0-or-later; see licenses/GPL-2.0.txt.


MAX_DEPTH = 5
CHART_COLORS = ("#e01b24", "#ff7800", "#f6d32d", "#33d17a", "#3584e4", "#9141ac")


def _rgb(value):
    return tuple(int(value[index:index + 2], 16) / 255 for index in (1, 3, 5))


def baobab_color(position, depth, highlighted=False):
    intensity = 1 - ((depth - 1) * 0.3) / MAX_DEPTH
    index = int(position / (100 / 3))
    first = _rgb(CHART_COLORS[index])
    second = _rgb(CHART_COLORS[(index + 1) % len(CHART_COLORS)])
    fraction = (position - index * (100 / 3)) / (100 / 3)
    color = [(a - (a - b) * fraction) * intensity for a, b in zip(first, second)]
    if highlighted:
        maximum = max(color)
        color = [channel / maximum for channel in color]
    return tuple(color)


def baobab_hex(position, depth=1, highlighted=False):
    channels = baobab_color(position, depth, highlighted)
    return "#" + "".join(f"{round(channel * 255):02x}" for channel in channels)


def readable_text_color(color):
    red, green, blue = _rgb(color)
    luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue
    return "#202020" if luminance > 0.58 else "#ffffff"
