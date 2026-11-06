from __future__ import annotations

import json
import struct

from .geometry import object_bounds
from .model import Scene


META_OBJECT = 1001
COLOR_INDEX = {
    "white": 0, "black": 1, "red": 2, "green": 3, "blue": 4,
    "cyan": 5, "yellow": 6, "magenta": 7,
}
INDEX_COLOR = {value: key for key, value in COLOR_INDEX.items()}
OPCODE_NAMES = {
    5: "escape", 6: "v_pline", 8: "v_gtext", 9: "v_fillarea",
    11: "gdp", 12: "vst_height", 13: "vs_color", 17: "vsl_color", 22: "vst_color",
    23: "vsf_interior", 25: "vsf_color",
}


def _word(value):
    rounded = int(round(value))
    if not -32768 <= rounded <= 32767:
        raise ValueError(f"VDI word outside signed 16-bit range: {rounded}")
    return rounded


def _record(command, subcommand=0, points=(), values=()):
    flattened = [_word(coordinate) for point in points for coordinate in point]
    integers = [_word(value) for value in values]
    header = struct.pack("<4h", command, len(points), len(integers), subcommand)
    return header + struct.pack(f"<{len(flattened)}h", *flattened) + struct.pack(f"<{len(integers)}h", *integers)


def _object_record(item, part="shape"):
    metadata = {"id": item["id"], "type": item["type"], "part": part}
    for key in ("role", "event_id", "status", "selected", "from", "to", "label", "width", "size"):
        if key in item:
            metadata[key] = item[key]
    payload = json.dumps(metadata, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\0"
    if len(payload) > 4096:
        raise ValueError("VDI object metadata is too large")
    return _record(5, 99, values=[META_OBJECT, *payload])


def _palette_index(value, palette, records):
    if value in COLOR_INDEX:
        return COLOR_INDEX[value]
    if value in palette["custom"]:
        return palette["custom"][value]
    if not value.startswith("#") or len(value) != 7:
        return COLOR_INDEX["black"]
    index = palette["next"]
    if index > 255:
        raise ValueError("scene exceeds the 256-entry VDI palette")
    palette["next"] += 1
    palette["custom"][value] = index
    channels = [int(value[offset:offset + 2], 16) for offset in (1, 3, 5)]
    records.append(_record(13, values=[index, *[round(channel * 1000 / 255) for channel in channels]]))
    return index


def _fill_records(item, palette, records):
    index = _palette_index(item["fill"], palette, records) if item["fill"] != "none" else COLOR_INDEX["white"]
    records.extend([
        _record(25, values=[index]),
        _record(23, values=[0 if item["fill"] == "none" else 1]),
    ])


def _line_records(item, palette, records):
    records.append(_record(17, values=[_palette_index(item["stroke"], palette, records) if item["stroke"] != "none" else COLOR_INDEX["white"]]))


def _text_records(item, palette, records, size=None):
    height = item.get("size", 240) if size is None else size
    records.extend([
        _record(12, points=[(0, height)]),
        _record(22, values=[_palette_index(item["stroke"], palette, records)]),
    ])


def _label_records(item, palette, records):
    if not item.get("label") or item["type"] != "rectangle":
        return
    left, top, right, bottom = item["bounds"]
    size = min(240, (bottom - top) / 3)
    label = item["label"].replace("\n", " · ")
    x = (left + right) / 2 - len(label) * size * 0.31
    y = (top + bottom) / 2 + size * 0.35
    metadata = dict(item)
    metadata["type"] = "text"
    records.append(_object_record(metadata, "label"))
    _text_records(item, palette, records, size)
    records.append(_record(8, points=[(x, y)], values=[*label.encode("cp437", "replace"), 0]))


def _mesh_records(item, palette, records):
    records.append(_record(23, values=[1]))
    points, fills = item["points"], item["fills"]
    for triangle, fill in enumerate(fills):
        records.append(_record(25, values=[_palette_index(fill, palette, records)]))
        corners = points[3 * triangle:3 * triangle + 3]
        records.append(_record(9, points=[*corners, corners[0]]))


def scene_to_metafile(scene):
    objects = scene.objects
    if objects:
        bounds = [object_bounds(item) for item in objects]
        minimum_x = min(item.left for item in bounds)
        minimum_y = min(item.top for item in bounds)
        maximum_x = max(item.right for item in bounds)
        maximum_y = max(item.bottom for item in bounds)
    else:
        minimum_x = minimum_y = maximum_x = maximum_y = 0
    page_width = 2540
    page_height = max(1, round(page_width * scene.canvas["height"] / scene.canvas["width"]))
    header_values = [
        -1, 24, 101, 2,
        _word(minimum_x), _word(minimum_y), _word(maximum_x), _word(maximum_y),
        _word(page_width), _word(page_height),
        0, 0, _word(scene.canvas["width"]), _word(scene.canvas["height"]),
        0, *([0] * 9),
    ]
    records = []
    palette = {"custom": {}, "next": 16}
    for item in objects:
        records.append(_object_record(item))
        if item["type"] == "mesh":
            _mesh_records(item, palette, records)
            continue
        _fill_records(item, palette, records)
        _line_records(item, palette, records)
        if item["type"] == "rectangle":
            points = [item["bounds"][:2], item["bounds"][2:]]
            records.append(_record(11, 1 if item["fill"] != "none" else 8, points=points))
        elif item["type"] in {"polygon", "polyline", "line"}:
            points = list(item["points"])
            if item["type"] == "polygon" and points[0] != points[-1]:
                points.append(points[0])
            if item["type"] == "polygon" and item["fill"] != "none":
                records.append(_record(9, points=points))
            else:
                records.append(_record(6, points=points))
        elif item["type"] == "ellipse":
            records.append(_record(11, 5, points=[item["center"], item["radii"]]))
        elif item["type"] == "text":
            _text_records(item, palette, records)
            text = item["text"].encode("cp437", "replace") + b"\0"
            records.append(_record(8, points=[item["position"]], values=text))
        _label_records(item, palette, records)
    return struct.pack("<24h", *header_values) + b"".join(records) + struct.pack("<h", -1)


def write_metafile(scene, path):
    data = scene_to_metafile(scene)
    with open(path, "wb") as stream:
        stream.write(data)
    return len(data)


def parse_metafile(data):
    if len(data) < 50:
        raise ValueError("metafile is truncated")
    magic, header_words, version, coordinates = struct.unpack_from("<4h", data)
    if magic != -1 or not 2 <= header_words <= 1024 or len(data) < header_words * 2 + 2:
        raise ValueError("invalid GEM metafile header")
    header = {
        "header_words": header_words,
        "version": version,
        "coordinate_system": coordinates,
        "bounds": struct.unpack_from("<4h", data, 8),
        "page_size": struct.unpack_from("<2H", data, 16),
        "coordinate_bounds": struct.unpack_from("<4h", data, 20),
        "flags": struct.unpack_from("<h", data, 28)[0],
    }
    position = header_words * 2
    records = []
    terminated = False
    while position + 2 <= len(data):
        command = struct.unpack_from("<h", data, position)[0]
        if command == -1:
            records.append({"offset": position, "command": -1})
            position += 2
            terminated = True
            break
        if position + 8 > len(data):
            raise ValueError("truncated VDI record header")
        command, points, integers, subcommand = struct.unpack_from("<4h", data, position)
        if points < 0 or integers < 0:
            raise ValueError("negative VDI record length")
        offset = position
        position += 8
        byte_count = points * 4 + integers * 2
        if position + byte_count > len(data):
            raise ValueError("truncated VDI record payload")
        coordinates_flat = struct.unpack_from(f"<{points * 2}h", data, position) if points else ()
        position += points * 4
        values = struct.unpack_from(f"<{integers}h", data, position) if integers else ()
        position += integers * 2
        records.append({
            "offset": offset,
            "command": command,
            "points": points,
            "integers": integers,
            "subcommand": subcommand,
            "coordinates": coordinates_flat,
            "values": values,
        })
    if not terminated or position != len(data):
        raise ValueError("metafile must end with exactly one terminator")
    return {"header": header, "records": records, "bytes_consumed": position}


def _text(record):
    raw = bytes(value & 0xff for value in record["values"])
    return raw.split(b"\0", 1)[0].decode("cp437", "replace")


def _parse_metadata(record):
    values = record["values"]
    if len(values) < 2 or values[0] != META_OBJECT:
        return None
    raw = bytes(value & 0xff for value in values[1:])
    try:
        document = json.loads(raw.split(b"\0", 1)[0].decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid GEM object metadata record") from error
    if not isinstance(document, dict) or not isinstance(document.get("id"), str):
        raise ValueError("GEM object metadata lacks an ID")
    return document


def _points(record):
    values = record["coordinates"]
    return [[values[index], values[index + 1]] for index in range(0, len(values), 2)]


def scene_from_metafile(data, constraints=()):
    parsed = parse_metafile(data)
    objects = {}
    metadata = None
    line_color = fill_color = text_color = "black"
    custom_colors = {}
    interior = 0
    for record in parsed["records"]:
        command = record["command"]
        subcommand = record.get("subcommand", 0)
        if command == -1:
            continue
        if command == 5 and subcommand == 99:
            candidate = _parse_metadata(record)
            if candidate is not None:
                metadata = candidate
            continue
        if command == 13:
            index, red, green, blue = record["values"][:4]
            channels = [min(255, max(0, round(value * 255 / 1000))) for value in (red, green, blue)]
            custom_colors[index] = "#" + "".join(f"{channel:02x}" for channel in channels)
            continue
        if command == 17:
            index = record["values"][0]
            line_color = custom_colors.get(index, INDEX_COLOR.get(index, "black"))
            continue
        if command == 25:
            index = record["values"][0]
            fill_color = custom_colors.get(index, INDEX_COLOR.get(index, "black"))
            continue
        if command == 23:
            interior = record["values"][0]
            continue
        if command == 22:
            index = record["values"][0]
            text_color = custom_colors.get(index, INDEX_COLOR.get(index, "black"))
            continue
        if command == 8 and metadata and metadata.get("part") == "label":
            parent = objects.get(metadata["id"])
            if parent is not None:
                parent["label"] = _text(record)
            continue
        object_id = metadata["id"] if metadata else f"vdi-object-{len(objects)}"
        object_type = metadata.get("type") if metadata else None
        points = _points(record)
        values = record["values"]
        if command == 9 and metadata and metadata.get("type") == "mesh":
            mesh = objects.get(object_id)
            if mesh is None:
                mesh = {
                    "id": object_id, "type": "mesh", "points": [], "fills": [],
                    "fill": "none", "stroke": "none", "width": metadata.get("width", 0),
                }
                objects[object_id] = mesh
            mesh["points"].extend(points[:3])
            mesh["fills"].append(fill_color)
            continue
        current = None
        if command == 11 and subcommand in {1, 8} and len(points) == 2:
            bounds = [*points[0], *points[1]]
            current = {
                "id": object_id, "type": "rectangle", "bounds": bounds,
                "fill": fill_color if interior else "none", "stroke": line_color,
            }
        elif command == 9 and len(points) >= 3:
            current = {
                "id": object_id, "type": object_type or "polygon", "points": points,
                "fill": fill_color if interior else "none", "stroke": line_color,
            }
        elif command == 6 and len(points) >= 2:
            current = {
                "id": object_id, "type": object_type or ("line" if len(points) == 2 else "polyline"),
                "points": points, "fill": "none", "stroke": line_color,
            }
        elif command == 11 and subcommand == 5 and len(points) == 2:
            current = {
                "id": object_id, "type": "ellipse", "center": points[0], "radii": points[1],
                "fill": fill_color if interior else "none", "stroke": line_color,
            }
        elif command == 8 and len(points) == 1:
            current = {
                "id": object_id, "type": "text", "position": points[0], "text": _text(record),
                "size": metadata.get("size", 240) if metadata else 240,
                "fill": "none", "stroke": text_color,
            }
        if current is None:
            continue
        current["type"] = object_type or current["type"]
        current["width"] = metadata.get("width", 20) if metadata else 20
        for key in ("role", "event_id", "status", "selected", "from", "to"):
            if metadata and key in metadata:
                current[key] = metadata[key]
        if object_id in objects:
            objects[object_id].update(current)
        else:
            objects[object_id] = current
        metadata = None
    document = {
        "schema_version": 1,
        "id": "vdi-roundtrip",
        "canvas": {
            "width": parsed["header"]["coordinate_bounds"][2] or 32767,
            "height": parsed["header"]["coordinate_bounds"][3] or 32767,
        },
        "objects": list(objects.values()),
        "constraints": list(constraints),
    }
    return Scene.from_dict(document)


def opcode_inventory(data):
    parsed = parse_metafile(data)
    inventory = {}
    for record in parsed["records"]:
        command = record["command"]
        key = OPCODE_NAMES.get(command, f"opcode_{command}")
        if command == 11:
            key = {1: "v_bar", 5: "v_ellipse", 8: "v_rbox"}.get(record["subcommand"], key)
        if command == 5 and record["subcommand"] == 99:
            key = "v_write_meta"
        inventory[key] = inventory.get(key, 0) + 1
    return inventory
