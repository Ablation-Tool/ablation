from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path


MAX_OBJECTS = 4096
MAX_POINTS = 16384
MAX_CONSTRAINTS = 4096
MAX_JSON_BYTES = 8 * 1024 * 1024
OBJECT_TYPES = {"rectangle", "polygon", "polyline", "line", "ellipse", "text"}
CONSTRAINT_TYPES = {
    "contains", "touches", "symmetric", "aligned", "inside_canvas",
    "nonoverlap", "connected",
}
COLORS = {
    "white", "black", "red", "green", "blue", "cyan", "yellow", "magenta",
    "orange", "gray", "lightgray", "none",
}
TOP_FIELDS = {"schema_version", "id", "title", "prompt", "canvas", "objects", "constraints"}
OBJECT_FIELDS = {
    "id", "type", "role", "label", "fill", "stroke", "width", "bounds", "points",
    "center", "radii", "position", "text", "size", "event_id", "status", "selected",
    "from", "to",
}
CONSTRAINT_FIELDS = {
    "type", "a", "b", "outer", "inner", "object", "objects", "axis", "value",
    "anchor", "endpoint", "epsilon",
}


def _mapping(value, name):
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _sequence(value, name, length=None):
    if not isinstance(value, (list, tuple)) or (length is not None and len(value) != length):
        suffix = f" of length {length}" if length is not None else ""
        raise ValueError(f"{name} must be an array{suffix}")
    return value


def _identifier(value, name="id"):
    if (
        not isinstance(value, str) or not 1 <= len(value) <= 128
        or value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or any(char.isspace() for char in value)
    ):
        raise ValueError(f"{name} must be 1-128 non-whitespace characters")
    return value


def _number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number")
    if abs(value) > 32767:
        raise ValueError(f"{name} exceeds the VDI coordinate range")
    return float(value)


def _point(value, name):
    values = _sequence(value, name, 2)
    return [_number(values[0], f"{name}.x"), _number(values[1], f"{name}.y")]


def _color(value, name):
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a color string")
    normalized = value.casefold()
    if normalized in COLORS:
        return normalized
    if len(value) == 7 and value.startswith("#") and all(char in "0123456789abcdefABCDEF" for char in value[1:]):
        return value
    raise ValueError(f"unsupported color: {value}")


def _check_fields(document, allowed, name):
    unknown = set(document) - allowed
    if unknown:
        raise ValueError(f"{name} contains unsupported fields: {', '.join(sorted(unknown))}")


def _validate_object(document, index):
    _mapping(document, f"objects[{index}]")
    _check_fields(document, OBJECT_FIELDS, f"objects[{index}]")
    result = deepcopy(document)
    _identifier(result.get("id"), f"objects[{index}].id")
    object_type = result.get("type")
    if object_type not in OBJECT_TYPES:
        raise ValueError(f"objects[{index}].type is unsupported")
    if "role" in result:
        _identifier(result["role"], f"objects[{index}].role")
    result["fill"] = _color(result.get("fill", "none"), "fill")
    result["stroke"] = _color(result.get("stroke", "black"), "stroke")
    width = result.get("width", 20)
    result["width"] = _number(width, "width")
    if result["width"] < 0:
        raise ValueError("width cannot be negative")
    if "label" in result and (not isinstance(result["label"], str) or len(result["label"]) > 500):
        raise ValueError("label must contain at most 500 characters")
    if "status" in result and (not isinstance(result["status"], str) or len(result["status"]) > 64):
        raise ValueError("status must contain at most 64 characters")
    if "selected" in result and not isinstance(result["selected"], bool):
        raise ValueError("selected must be boolean")
    for key in ("event_id", "from", "to"):
        if key in result:
            _identifier(result[key], key)
    if object_type == "rectangle":
        bounds = _sequence(result.get("bounds"), "rectangle.bounds", 4)
        result["bounds"] = [_number(value, "rectangle.bounds") for value in bounds]
        if result["bounds"][0] > result["bounds"][2] or result["bounds"][1] > result["bounds"][3]:
            raise ValueError("rectangle bounds must be ordered")
    elif object_type in {"polygon", "polyline", "line"}:
        points = _sequence(result.get("points"), f"{object_type}.points")
        minimum = 2 if object_type == "line" else 2 if object_type == "polyline" else 3
        if len(points) < minimum:
            raise ValueError(f"{object_type} requires at least {minimum} points")
        result["points"] = [_point(point, f"{object_type}.points") for point in points]
        if object_type == "line" and len(points) != 2:
            raise ValueError("line requires exactly two points")
    elif object_type == "ellipse":
        result["center"] = _point(result.get("center"), "ellipse.center")
        radii = _sequence(result.get("radii"), "ellipse.radii", 2)
        result["radii"] = [_number(value, "ellipse.radii") for value in radii]
        if any(value <= 0 for value in result["radii"]):
            raise ValueError("ellipse radii must be positive")
    elif object_type == "text":
        result["position"] = _point(result.get("position"), "text.position")
        if not isinstance(result.get("text"), str) or not 1 <= len(result["text"]) <= 500:
            raise ValueError("text.text must contain 1-500 characters")
        result["size"] = _number(result.get("size", 240), "text.size")
        if result["size"] <= 0:
            raise ValueError("text.size must be positive")
    return result


def _validate_constraint(document, index):
    _mapping(document, f"constraints[{index}]")
    _check_fields(document, CONSTRAINT_FIELDS, f"constraints[{index}]")
    result = deepcopy(document)
    constraint_type = result.get("type")
    if constraint_type not in CONSTRAINT_TYPES:
        raise ValueError(f"constraints[{index}].type is unsupported")
    required = {
        "contains": ("outer", "inner"),
        "touches": ("a", "b"),
        "symmetric": ("a", "b", "axis", "value"),
        "aligned": ("a", "b", "axis"),
        "inside_canvas": ("object",),
        "nonoverlap": ("objects",),
        "connected": ("a", "b", "anchor"),
    }[constraint_type]
    for key in required:
        if key not in result:
            raise ValueError(f"{constraint_type} requires {key}")
    for key in ("a", "b", "outer", "inner", "object"):
        if key in result and result[key] != "*":
            _identifier(result[key], key)
    if "objects" in result:
        objects = _sequence(result["objects"], "objects")
        if len(objects) < 2:
            raise ValueError("nonoverlap requires at least two object IDs")
        for object_id in objects:
            _identifier(object_id, "objects")
    if constraint_type == "symmetric":
        if result["axis"] not in {"x", "y"}:
            raise ValueError("symmetric.axis must be x or y")
        result["value"] = _number(result["value"], "symmetric.value")
    if constraint_type == "aligned" and result["axis"] not in {"left", "right", "top", "bottom", "center_x", "center_y"}:
        raise ValueError("aligned.axis is invalid")
    if constraint_type == "connected":
        if result["anchor"] not in {"left", "right", "top", "bottom", "center"}:
            raise ValueError("connected.anchor is invalid")
        result["endpoint"] = result.get("endpoint", 1)
        if result["endpoint"] not in {0, 1}:
            raise ValueError("connected.endpoint must be 0 or 1")
    if "epsilon" in result:
        result["epsilon"] = _number(result["epsilon"], "epsilon")
        if result["epsilon"] < 0:
            raise ValueError("epsilon cannot be negative")
    return result


@dataclass(frozen=True)
class Scene:
    document: dict

    @classmethod
    def from_dict(cls, document):
        _mapping(document, "scene")
        _check_fields(document, TOP_FIELDS, "scene")
        if document.get("schema_version") != 1:
            raise ValueError("scene schema_version must be 1")
        _identifier(document.get("id"), "scene.id")
        if "title" in document and (not isinstance(document["title"], str) or len(document["title"]) > 500):
            raise ValueError("scene.title must contain at most 500 characters")
        if "prompt" in document and (not isinstance(document["prompt"], str) or len(document["prompt"]) > 50000):
            raise ValueError("scene.prompt must contain at most 50000 characters")
        canvas = _mapping(document.get("canvas"), "canvas")
        _check_fields(canvas, {"width", "height"}, "canvas")
        width = _number(canvas.get("width"), "canvas.width")
        height = _number(canvas.get("height"), "canvas.height")
        if width <= 0 or height <= 0:
            raise ValueError("canvas dimensions must be positive")
        objects = _sequence(document.get("objects"), "objects")
        if len(objects) > MAX_OBJECTS:
            raise ValueError("scene contains too many objects")
        validated_objects = [_validate_object(item, index) for index, item in enumerate(objects)]
        identifiers = [item["id"] for item in validated_objects]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("object IDs must be unique")
        if sum(len(item.get("points", [])) for item in validated_objects) > MAX_POINTS:
            raise ValueError("scene contains too many points")
        constraints = _sequence(document.get("constraints", []), "constraints")
        if len(constraints) > MAX_CONSTRAINTS:
            raise ValueError("scene contains too many constraints")
        validated_constraints = [_validate_constraint(item, index) for index, item in enumerate(constraints)]
        known = set(identifiers)
        for constraint in validated_constraints:
            references = [constraint.get(key) for key in ("a", "b", "outer", "inner", "object")]
            references += constraint.get("objects", [])
            for reference in references:
                if reference is not None and reference != "*" and reference not in known:
                    raise ValueError(f"constraint references unknown object: {reference}")
        normalized = {
            "schema_version": 1,
            "id": document["id"],
            "canvas": {"width": width, "height": height},
            "objects": validated_objects,
            "constraints": validated_constraints,
        }
        for key in ("title", "prompt"):
            if key in document:
                normalized[key] = document[key]
        return cls(normalized)

    @classmethod
    def load(cls, path):
        path = Path(path)
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ValueError("scene file is too large")
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def to_dict(self):
        return deepcopy(self.document)

    def json(self):
        return json.dumps(self.document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    def canonical_bytes(self):
        return json.dumps(self.document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self):
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def save(self, path):
        Path(path).write_text(self.json(), encoding="utf-8")

    @property
    def objects(self):
        return self.document["objects"]

    @property
    def constraints(self):
        return self.document["constraints"]

    @property
    def canvas(self):
        return self.document["canvas"]

    def object(self, object_id):
        for item in self.objects:
            if item["id"] == object_id:
                return item
        raise KeyError(object_id)

    def with_constraints(self, constraints):
        document = self.to_dict()
        document["constraints"] = deepcopy(constraints)
        return Scene.from_dict(document)

    def rescaled(self, width, height, scene_id=None):
        width = _number(width, "width")
        height = _number(height, "height")
        if width <= 0 or height <= 0:
            raise ValueError("scaled dimensions must be positive")
        sx = width / self.canvas["width"]
        sy = height / self.canvas["height"]
        document = self.to_dict()
        document["id"] = scene_id or f"{document['id']}-{width}x{height}"
        document["canvas"] = {"width": width, "height": height}
        for item in document["objects"]:
            if "bounds" in item:
                item["bounds"] = [
                    item["bounds"][0] * sx, item["bounds"][1] * sy,
                    item["bounds"][2] * sx, item["bounds"][3] * sy,
                ]
            for key in ("points",):
                if key in item:
                    item[key] = [[x * sx, y * sy] for x, y in item[key]]
            for key in ("center", "position"):
                if key in item:
                    item[key] = [item[key][0] * sx, item[key][1] * sy]
            if "radii" in item:
                item["radii"] = [item["radii"][0] * sx, item["radii"][1] * sy]
            for key in ("width", "size"):
                if key in item:
                    item[key] = item[key] * min(sx, sy)
        for constraint in document["constraints"]:
            if constraint["type"] == "symmetric":
                constraint["value"] *= sx if constraint["axis"] == "x" else sy
            if "epsilon" in constraint:
                constraint["epsilon"] *= min(sx, sy)
        return Scene.from_dict(document)


def demo_scene():
    return Scene.from_dict({
        "schema_version": 1,
        "id": "gem-house-demo",
        "title": "GEM executable spatial reasoning demo",
        "prompt": "Draw a house with a touching roof, contained door, and symmetric windows.",
        "canvas": {"width": 10000, "height": 6000},
        "objects": [
            {"id": "body", "type": "rectangle", "role": "body", "bounds": [3000, 2500, 7000, 5500], "fill": "white", "label": "body"},
            {"id": "roof", "type": "polygon", "role": "roof", "points": [[2500, 2500], [5000, 500], [7500, 2500]], "fill": "red"},
            {"id": "door", "type": "rectangle", "role": "door", "bounds": [4600, 4000, 5400, 5500], "fill": "yellow"},
            {"id": "left_window", "type": "rectangle", "role": "window", "bounds": [3400, 3200, 4100, 3900], "fill": "blue"},
            {"id": "right_window", "type": "rectangle", "role": "window", "bounds": [5900, 3200, 6600, 3900], "fill": "blue"},
            {"id": "sun", "type": "ellipse", "role": "sun", "center": [8500, 1100], "radii": [600, 600], "fill": "yellow"},
            {"id": "caption", "type": "text", "role": "caption", "position": [3500, 5900], "text": "GEM · executable geometry", "size": 260},
        ],
        "constraints": [
            {"type": "touches", "a": "roof", "b": "body"},
            {"type": "contains", "outer": "body", "inner": "door"},
            {"type": "symmetric", "a": "left_window", "b": "right_window", "axis": "x", "value": 5000},
            {"type": "inside_canvas", "object": "*"},
        ],
    })


def scene_from_events(events, root_id, selected_id=None):
    by_id = {event["id"]: event for event in events}
    if root_id not in by_id:
        root_id = next((event["id"] for event in events if event.get("parent_id") is None), root_id)
    levels = defaultdict(list)
    omitted = 0
    pending = [(root_id, 0)] if root_id in by_id else []
    seen = set()
    while pending:
        node_id, depth = pending.pop(0)
        if node_id in seen:
            continue
        seen.add(node_id)
        if depth > 3 or len(seen) > 24:
            omitted += 1
            continue
        event = by_id[node_id]
        levels[depth].append(event)
        for child in events:
            if child.get("parent_id") == node_id:
                pending.append((child["id"], depth + 1))
    max_depth = max(levels, default=0)
    height = max(6000, 1400 + (max_depth + 1) * 1700)
    objects = []
    constraints = []
    positions = {}
    for depth, items in levels.items():
        count = len(items)
        cell = 10000 / (count + 1)
        width = min(1900, cell * 0.78)
        for index, event in enumerate(items, 1):
            center_x = cell * index
            x = center_x - width / 2
            y = 700 + depth * 1700
            object_id = event["id"]
            positions[object_id] = (x, y, width, 950, depth)
            objects.append({
                "id": object_id,
                "type": "rectangle",
                "role": "event_node",
                "event_id": object_id,
                "bounds": [x, y, x + width, y + 950],
                "label": f"{event['label']} · {event['status']}"[:500],
                "status": event["status"],
                "selected": event["id"] == selected_id,
                "fill": "#fce3d4" if event["id"] == selected_id else "white",
                "stroke": "orange" if event["id"] == selected_id else "black",
            })
            constraints.append({"type": "inside_canvas", "object": object_id})
    for child in events:
        parent_id = child.get("parent_id")
        if child["id"] not in positions or parent_id not in positions:
            continue
        px, py, pw, ph, _ = positions[parent_id]
        cx, cy, cw, ch, _ = positions[child["id"]]
        connector_id = "connector:" + hashlib.sha256(
            f"{parent_id}->{child['id']}".encode("utf-8")
        ).hexdigest()[:24]
        objects.append({
            "id": connector_id,
            "type": "line",
            "role": "connector",
            "from": parent_id,
            "to": child["id"],
            "points": [[px + pw / 2, py + ph], [cx + cw / 2, cy]],
            "stroke": "gray",
        })
        constraints.extend([
            {"type": "connected", "a": connector_id, "b": parent_id, "anchor": "bottom", "endpoint": 0},
            {"type": "connected", "a": connector_id, "b": child["id"], "anchor": "top", "endpoint": 1},
        ])
    node_ids = list(positions)
    if len(node_ids) > 1:
        constraints.append({"type": "nonoverlap", "objects": node_ids})
    title = "GEM investigation scene"
    if omitted:
        title += f" · {omitted} nodes outside display limits"
    return Scene.from_dict({
        "schema_version": 1,
        "id": "gem-investigation-" + hashlib.sha256(str(root_id).encode("utf-8")).hexdigest()[:16],
        "title": title,
        "canvas": {"width": 10000, "height": height},
        "objects": objects,
        "constraints": constraints,
    })
