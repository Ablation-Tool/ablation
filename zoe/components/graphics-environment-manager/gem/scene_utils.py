from .model import Scene
from .render import NAMED_COLORS


def _classic_color(value):
    if not isinstance(value, str) or value in NAMED_COLORS or value == "none":
        return value
    if len(value) != 7 or not value.startswith("#") or any(character not in "0123456789abcdefABCDEF" for character in value[1:]):
        return value
    red, green, blue = (int(value[index:index + 2], 16) for index in (1, 3, 5))
    return min(
        NAMED_COLORS,
        key=lambda name: (red - int(NAMED_COLORS[name][1:3], 16)) ** 2
        + (green - int(NAMED_COLORS[name][3:5], 16)) ** 2
        + (blue - int(NAMED_COLORS[name][5:7], 16)) ** 2,
    )


def _scene(identifier, width, height, objects, title):
    normalized = []
    for item in objects:
        item = dict(item)
        if "stroke" in item:
            item["stroke"] = _classic_color(item["stroke"])
        if "fill" in item:
            item["fill"] = _classic_color(item["fill"])
        normalized.append(item)
    return Scene.from_dict({
        "schema_version": 1,
        "id": identifier,
        "title": title,
        "canvas": {"width": width, "height": height},
        "objects": normalized,
        "constraints": [{"type": "inside_canvas", "object": "*"}],
    })


def _text(identifier, position, text, size=14, stroke="black"):
    return {"id": identifier, "type": "text", "position": position, "text": text, "size": size, "stroke": stroke, "fill": "none", "width": 0}


def _line(identifier, first, second, stroke="black", width=1):
    return {"id": identifier, "type": "line", "points": [first, second], "stroke": stroke, "fill": "none", "width": width}


def _ellipse(identifier, center, radii, stroke, fill="none", width=1):
    return {"id": identifier, "type": "ellipse", "center": center, "radii": radii, "stroke": stroke, "fill": fill, "width": width}


def _rectangle(identifier, bounds, stroke, fill="none", width=1):
    return {"id": identifier, "type": "rectangle", "bounds": bounds, "stroke": stroke, "fill": fill, "width": width}
