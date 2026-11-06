from __future__ import annotations

import math
from pathlib import Path
import xml.etree.ElementTree as ET

COLORS = {
    "white": "#ffffff", "black": "#202124", "red": "#d3313d", "green": "#16855b",
    "blue": "#3155b7", "orange": "#ee7b30", "gray": "#8b8f98", "lightgray": "#e3e6ea",
}


def color(value):
    return COLORS.get(value, value)


def scene_to_svg(scene, width=1200):
    if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= 16384:
        raise ValueError("SVG width must be an integer from 1 to 16384")
    height = max(1, round(width*scene.height/scene.width))
    root = ET.Element("svg", {
        "xmlns": "http://www.w3.org/2000/svg", "width": str(width), "height": str(height),
        "viewBox": f"0 0 {scene.width:g} {scene.height:g}", "role": "img", "aria-label": scene.title,
    })
    ET.SubElement(root, "title").text = scene.title
    ET.SubElement(root, "rect", {"width": str(scene.width), "height": str(scene.height), "fill": "#ffffff"})
    for item in scene.objects:
        group = ET.SubElement(root, "g", {"data-object-id": item["id"]})
        ET.SubElement(group, "title").text = item["id"]
        paint = {"fill": color(item["fill"]), "stroke": color(item["stroke"]), "stroke-width": str(item["width"])}
        if item["type"] == "rectangle":
            left, top, right, bottom = item["bounds"]
            ET.SubElement(group, "rect", {"x": str(left), "y": str(top), "width": str(right-left), "height": str(bottom-top), **paint})
        elif item["type"] in {"line", "polyline"}:
            ET.SubElement(group, "polyline", {"points": " ".join(f"{x:g},{y:g}" for x, y in item["points"]), "stroke-linejoin": "round", **paint})
        elif item["type"] == "ellipse":
            ET.SubElement(group, "ellipse", {"cx": str(item["center"][0]), "cy": str(item["center"][1]), "rx": str(item["radii"][0]), "ry": str(item["radii"][1]), **paint})
        elif item["type"] == "text":
            ET.SubElement(group, "text", {"x": str(item["position"][0]), "y": str(item["position"][1]), "font-family": "sans-serif", "font-size": str(item["size"]), "fill": color(item["stroke"])}).text = item["text"]
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)+"\n"


def write_svg(scene, path, width=1200):
    path = Path(path)
    path.write_text(scene_to_svg(scene, width), encoding="utf-8")
    return path


def write_scene_json(scene, path, exclusive=True):
    path = Path(path)
    with path.open("x" if exclusive else "w", encoding="utf-8") as stream:
        stream.write(scene.json())
    return path


def scene_layout(scene, width, height):
    scale = min(width/scene.width, height/scene.height)
    return scale, (width-scene.width*scale)/2, (height-scene.height*scale)/2


def draw_cairo(context, scene, width, height):
    import cairo
    scale, offset_x, offset_y = scene_layout(scene, width, height)
    context.save()
    context.set_source_rgb(1, 1, 1)
    context.paint()
    context.translate(offset_x, offset_y)
    context.scale(scale, scale)
    context.set_line_join(cairo.LineJoin.ROUND)
    for item in scene.objects:
        if item["type"] == "rectangle":
            left, top, right, bottom = item["bounds"]
            context.rectangle(left, top, right-left, bottom-top)
        elif item["type"] in {"line", "polyline"}:
            points = item["points"]
            context.move_to(*points[0])
            for point in points[1:]:
                context.line_to(*point)
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
            context.set_source_rgb(*(int(rgb[index:index+2], 16)/255 for index in (0, 2, 4)))
            context.show_text(item["text"])
            continue
        if item["fill"] != "none":
            rgb = color(item["fill"]).lstrip("#")
            context.set_source_rgb(*(int(rgb[index:index+2], 16)/255 for index in (0, 2, 4)))
            context.fill_preserve()
        if item["stroke"] != "none":
            rgb = color(item["stroke"]).lstrip("#")
            context.set_source_rgb(*(int(rgb[index:index+2], 16)/255 for index in (0, 2, 4)))
            context.set_line_width(item["width"])
            context.stroke()
        else:
            context.new_path()
    context.restore()
    return scale, offset_x, offset_y


def write_png(scene, path, width=1200):
    try:
        import cairo
    except ImportError as error:
        raise RuntimeError("HELEN PNG output requires Cairo") from error
    if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= 16384:
        raise ValueError("PNG width must be an integer from 1 to 16384")
    path = Path(path)
    height = max(1, round(width*scene.height/scene.width))
    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, width, height)
    draw_cairo(cairo.Context(surface), scene, width, height)
    surface.write_to_png(str(path))
    return path
