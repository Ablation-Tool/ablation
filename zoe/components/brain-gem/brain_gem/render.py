from __future__ import annotations

import math
from pathlib import Path
import xml.etree.ElementTree as ElementTree


NAMED_COLORS = {
    "white": "#ffffff",
    "black": "#000000",
    "red": "#ff0000",
    "green": "#008000",
    "blue": "#0000ff",
    "cyan": "#00ffff",
    "yellow": "#ffff00",
    "magenta": "#ff00ff",
    "orange": "#e95420",
    "gray": "#808080",
    "lightgray": "#d3d3d3",
}


def color(value):
    return NAMED_COLORS.get(value, value)


def _paint(item):
    return {
        "fill": color(item["fill"]),
        "stroke": color(item["stroke"]),
        "stroke-width": str(item["width"]),
    }


def _label(item):
    if not item.get("label") or item["type"] != "rectangle":
        return None
    left, top, right, bottom = item["bounds"]
    size = min(240, (bottom - top) / 3)
    return {
        "position": [(left + right) / 2, (top + bottom) / 2 + size * 0.35],
        "text": item["label"].replace("\n", " · "),
        "size": size,
        "centered": True,
    }


def scene_to_svg(scene, width=1200):
    if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= 16384:
        raise ValueError("SVG width must be an integer from 1 to 16384")
    height = max(1, round(width * scene.canvas["height"] / scene.canvas["width"]))
    root = ElementTree.Element("svg", {
        "xmlns": "http://www.w3.org/2000/svg",
        "width": str(width),
        "height": str(height),
        "viewBox": f"0 0 {scene.canvas['width']:g} {scene.canvas['height']:g}",
        "role": "img",
        "aria-label": scene.document.get("title", scene.document["id"]),
    })
    ElementTree.SubElement(root, "title").text = scene.document.get("title", scene.document["id"])
    ElementTree.SubElement(root, "rect", {
        "x": "0", "y": "0", "width": str(scene.canvas["width"]),
        "height": str(scene.canvas["height"]), "fill": "#ffffff",
    })
    for item in scene.objects:
        paint = _paint(item)
        group = ElementTree.SubElement(root, "g", {"data-object-id": item["id"]})
        ElementTree.SubElement(group, "title").text = item["id"]
        if item["type"] == "rectangle":
            left, top, right, bottom = item["bounds"]
            ElementTree.SubElement(group, "rect", {
                "x": str(left), "y": str(top), "width": str(right - left),
                "height": str(bottom - top), **paint,
            })
        elif item["type"] in {"polygon", "polyline", "line"}:
            tag = "polygon" if item["type"] == "polygon" else "polyline"
            ElementTree.SubElement(group, tag, {
                "points": " ".join(f"{x:g},{y:g}" for x, y in item["points"]),
                "stroke-linejoin": "round", **paint,
            })
        elif item["type"] == "ellipse":
            ElementTree.SubElement(group, "ellipse", {
                "cx": str(item["center"][0]), "cy": str(item["center"][1]),
                "rx": str(item["radii"][0]), "ry": str(item["radii"][1]), **paint,
            })
        elif item["type"] == "text":
            ElementTree.SubElement(group, "text", {
                "x": str(item["position"][0]), "y": str(item["position"][1]),
                "font-family": "sans-serif", "font-size": str(item["size"]),
                "fill": color(item["stroke"]),
            }).text = item["text"]
        label = _label(item)
        if label is not None:
            ElementTree.SubElement(group, "text", {
                "x": str(label["position"][0]), "y": str(label["position"][1]),
                "font-family": "sans-serif", "font-size": str(label["size"]),
                "fill": color(item["stroke"]), "text-anchor": "middle",
            }).text = label["text"]
    ElementTree.indent(root, space="  ")
    return ElementTree.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def write_svg(scene, path, width=1200):
    text = scene_to_svg(scene, width)
    Path(path).write_text(text, encoding="utf-8")
    return len(text.encode("utf-8"))


def draw_cairo(context, scene, width, height, highlight_ids=()):
    import cairo

    scale = min(width / scene.canvas["width"], height / scene.canvas["height"])
    offset_x = (width - scene.canvas["width"] * scale) / 2
    offset_y = (height - scene.canvas["height"] * scale) / 2
    context.save()
    context.set_source_rgb(1, 1, 1)
    context.paint()
    context.translate(offset_x, offset_y)
    context.scale(scale, scale)
    context.set_line_join(cairo.LineJoin.ROUND)
    for item in scene.objects:
        if item["type"] == "rectangle":
            left, top, right, bottom = item["bounds"]
            context.rectangle(left, top, right - left, bottom - top)
        elif item["type"] in {"polygon", "polyline", "line"}:
            points = item["points"]
            context.move_to(*points[0])
            for point in points[1:]:
                context.line_to(*point)
            if item["type"] == "polygon":
                context.close_path()
        elif item["type"] == "ellipse":
            context.save()
            context.translate(*item["center"])
            context.scale(*item["radii"])
            context.arc(0, 0, 1, 0, math.tau)
            context.restore()
        elif item["type"] == "text":
            context.select_font_face("sans-serif")
            context.set_font_size(item["size"])
            context.move_to(*item["position"])
            rgb = color(item["stroke"]).lstrip("#")
            context.set_source_rgb(*(int(rgb[index:index + 2], 16) / 255 for index in (0, 2, 4)))
            context.show_text(item["text"])
            continue
        if item["fill"] != "none":
            rgb = color(item["fill"]).lstrip("#")
            context.set_source_rgb(*(int(rgb[index:index + 2], 16) / 255 for index in (0, 2, 4)))
            context.fill_preserve()
        if item["stroke"] != "none":
            rgb = color(item["stroke"]).lstrip("#")
            context.set_source_rgb(*(int(rgb[index:index + 2], 16) / 255 for index in (0, 2, 4)))
            context.set_line_width(item["width"])
            context.stroke()
        else:
            context.new_path()
        if item["id"] in highlight_ids:
            left, top, right, bottom = _highlight_bounds(item)
            context.set_source_rgb(0.9, 0.1, 0.1)
            context.set_line_width(max(item["width"] * 2, 50 / scale))
            context.set_dash([120, 60])
            context.rectangle(left - 30, top - 30, right - left + 60, bottom - top + 60)
            context.stroke()
            context.set_dash([])
        label = _label(item)
        if label is not None:
            context.select_font_face("sans-serif")
            context.set_font_size(label["size"])
            extents = context.text_extents(label["text"])
            context.move_to(
                label["position"][0] - extents.width / 2 - extents.x_bearing,
                label["position"][1],
            )
            rgb = color(item["stroke"]).lstrip("#")
            context.set_source_rgb(*(int(rgb[index:index + 2], 16) / 255 for index in (0, 2, 4)))
            context.show_text(label["text"])
    context.restore()
    return scale, offset_x, offset_y


def _highlight_bounds(item):
    from .geometry import object_bounds

    bounds = object_bounds(item)
    return bounds.left, bounds.top, bounds.right, bounds.bottom


def write_png(scene, path, width=1200):
    try:
        import cairo
    except ImportError as error:
        raise RuntimeError("PNG output requires the optional PyGObject Cairo integration") from error
    if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= 16384:
        raise ValueError("PNG width must be an integer from 1 to 16384")
    height = max(1, round(width * scene.canvas["height"] / scene.canvas["width"]))
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, width, height)
    draw_cairo(cairo.Context(surface), scene, width, height)
    surface.write_to_png(str(path))
    return Path(path).stat().st_size
