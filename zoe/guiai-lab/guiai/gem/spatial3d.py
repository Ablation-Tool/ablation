"""Deterministic software 3D rendering for Spatial IR mesh objects.

PLY meshes are projected through an orbit camera and shaded with a fixed
directional light, then flattened into a painter-ordered triangle soup.
The same scene state always produces the same bytes on every backend.
"""

from __future__ import annotations

import math
import re
import struct

MAX_VERTICES = 2_000_000
MAX_FACES = 4_000_000
HEADER_LIMIT = 65536
SCALAR_TYPES = {
    "char": "b", "int8": "b", "uchar": "B", "uint8": "B",
    "short": "h", "int16": "h", "ushort": "H", "uint16": "H",
    "int": "i", "int32": "i", "uint": "I", "uint32": "I",
    "float": "f", "float32": "f", "double": "d", "float64": "d",
}
WORLD_UP = (0.0, -1.0, 0.0)


class Mesh:
    def __init__(self, vertices, faces):
        self.vertices = vertices
        self.faces = faces

    def __len__(self):
        return len(self.faces)


def parse_ply(data):
    if not isinstance(data, bytes) or not data.startswith(b"ply"):
        raise ValueError("not a PLY file")
    match = re.search(rb"end_header\r?\n", data[:HEADER_LIMIT])
    if match is None:
        raise ValueError("PLY header is missing or too large")
    lines = data[:match.start()].decode("ascii", "replace").replace("\r\n", "\n").split("\n")
    body = data[match.end():]
    format_name = None
    elements = []
    for line in lines[1:]:
        words = line.split()
        if not words or words[0] in {"comment", "obj_info", "ply"}:
            continue
        if words[0] == "format" and len(words) == 3:
            format_name = words[1]
            if format_name not in {"ascii", "binary_little_endian", "binary_big_endian"} or words[2] != "1.0":
                raise ValueError(f"unsupported PLY format: {line}")
        elif words[0] == "element" and len(words) == 3:
            elements.append((words[1], int(words[2]), []))
        elif words[0] == "property" and len(words) >= 3 and elements:
            if words[1] == "list" and len(words) == 5:
                elements[-1][2].append(("list", words[2], words[3], words[4]))
            else:
                elements[-1][2].append(("scalar", words[1], words[2]))
        else:
            raise ValueError(f"unsupported PLY header line: {line}")
    if format_name is None or not elements:
        raise ValueError("PLY header lacks a format or elements")
    for name, count, _properties in elements:
        if count < 0 or count > MAX_FACES or (name == "vertex" and count > MAX_VERTICES):
            raise ValueError("PLY element count is outside the supported budget")
    if format_name == "ascii":
        return _parse_ascii(elements, body)
    return _parse_binary(elements, body, "<" if format_name == "binary_little_endian" else ">")


def _element_format(properties, endian):
    codes = []
    for property_ in properties:
        if property_[0] != "scalar" or property_[1] not in SCALAR_TYPES:
            return None
        codes.append(SCALAR_TYPES[property_[1]])
    return struct.Struct(endian + "".join(codes))


def _parse_binary(elements, body, endian):
    vertices = []
    faces = []
    position = 0
    for name, count, properties in elements:
        scalar = _element_format(properties, endian)
        if name == "vertex":
            if scalar is None:
                raise ValueError("PLY vertices must use scalar properties")
            names = [property_[2] for property_ in properties]
            if not {"x", "y", "z"}.issubset(names):
                raise ValueError("PLY vertices require x, y, z properties")
            indices = [names.index(axis) for axis in ("x", "y", "z")]
            end = position + scalar.size * count
            if end > len(body):
                raise ValueError("PLY vertex data is truncated")
            for values in struct.iter_unpack(scalar.format, body[position:end]):
                vertices.append((float(values[indices[0]]), float(values[indices[1]]), float(values[indices[2]])))
            position = end
        elif name == "face":
            list_property = next((p for p in properties if p[0] == "list"), None)
            if list_property is None or len(properties) != 1:
                raise ValueError("PLY faces require a single vertex index list")
            _tag, count_type, index_type, _name = list_property
            if count_type not in SCALAR_TYPES or index_type not in SCALAR_TYPES:
                raise ValueError("unsupported PLY face index types")
            count_struct = struct.Struct(endian + SCALAR_TYPES[count_type])
            index_struct = struct.Struct(endian + SCALAR_TYPES[index_type])
            for _ in range(count):
                if position + count_struct.size > len(body):
                    raise ValueError("PLY face data is truncated")
                length = count_struct.unpack_from(body, position)[0]
                position += count_struct.size
                if not 0 <= length <= 65535 or position + length * index_struct.size > len(body):
                    raise ValueError("PLY face index list is invalid or truncated")
                indices = [value[0] for value in index_struct.iter_unpack(body[position:position + length * index_struct.size])]
                position += length * index_struct.size
                _triangulate(indices, faces)
        else:
            if scalar is None:
                raise ValueError(f"unsupported PLY element: {name}")
            position += scalar.size * count
    if position > len(body):
        raise ValueError("PLY data is truncated")
    return _finish(vertices, faces)


def _parse_ascii(elements, body):
    tokens = body.split()
    position = 0
    vertices = []
    faces = []

    def take(count):
        nonlocal position
        if position + count > len(tokens):
            raise ValueError("ASCII PLY data is truncated")
        values = tokens[position:position + count]
        position += count
        return values

    for name, count, properties in elements:
        for _ in range(count):
            if name == "face":
                list_property = next((p for p in properties if p[0] == "list"), None)
                if list_property is None:
                    raise ValueError("PLY faces require a vertex index list")
                extra = sum(1 for p in properties if p[0] == "scalar")
                values = take(1 + extra)
                length = int(values[0])
                indices = [int(value) for value in take(length)]
                _triangulate(indices, faces)
            else:
                values = take(len(properties))
                if name == "vertex":
                    names = [p[2] for p in properties]
                    vertices.append(tuple(float(values[names.index(axis)]) for axis in ("x", "y", "z")))
    return _finish(vertices, faces)


def _triangulate(indices, faces):
    if len(indices) < 3:
        return
    for index in range(1, len(indices) - 1):
        triangle = (indices[0], indices[index], indices[index + 1])
        if len(set(triangle)) == 3:
            faces.append(triangle)


def _finish(vertices, faces):
    if not vertices or not faces:
        raise ValueError("PLY contains no renderable triangles")
    count = len(vertices)
    for face in faces:
        if any(index < 0 or index >= count for index in face):
            raise ValueError("PLY face references an unknown vertex")
    if any(not math.isfinite(value) for vertex in vertices for value in vertex):
        raise ValueError("PLY vertices must be finite")
    return Mesh(vertices, faces)


def _cross(a, b):
    return (a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0])


def _dot(a, b):
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def _normalize(vector):
    length = math.sqrt(_dot(vector, vector))
    if length == 0:
        raise ValueError("cannot normalize a zero vector")
    return tuple(value / length for value in vector)


class Camera:
    def __init__(self, target, distance, yaw=35.0, pitch=18.0, fov=35.0):
        self.target = tuple(float(value) for value in target)
        self.distance = float(distance)
        self.yaw = float(yaw)
        self.pitch = float(pitch)
        self.fov = float(fov)
        if not 1 <= self.fov <= 120:
            raise ValueError("field of view must be 1-120 degrees")
        if not -89.9 <= self.pitch <= 89.9:
            raise ValueError("pitch must be between -89.9 and 89.9 degrees")
        if self.distance <= 0:
            raise ValueError("camera distance must be positive")
        cy, sy = math.cos(math.radians(self.yaw)), math.sin(math.radians(self.yaw))
        cp, sp = math.cos(math.radians(self.pitch)), math.sin(math.radians(self.pitch))
        self.eye = (
            self.target[0] + self.distance * cp * sy,
            self.target[1] + self.distance * sp,
            self.target[2] + self.distance * cp * cy,
        )
        self.forward = _normalize(tuple(self.target[axis] - self.eye[axis] for axis in range(3)))
        self.right = _normalize(_cross(self.forward, WORLD_UP))
        self.up = _cross(self.right, self.forward)

    @classmethod
    def fit(cls, vertices, yaw=35.0, pitch=18.0, fov=35.0, margin=1.12):
        if not vertices:
            raise ValueError("camera fit requires vertices")
        minimum = [min(vertex[axis] for vertex in vertices) for axis in range(3)]
        maximum = [max(vertex[axis] for vertex in vertices) for axis in range(3)]
        target = tuple((minimum[axis] + maximum[axis]) / 2 for axis in range(3))
        radius = max(math.dist(vertex, target) for vertex in vertices)
        if radius == 0:
            raise ValueError("camera fit requires a nondegenerate point set")
        distance = radius / math.tan(math.radians(fov) / 2) * margin
        return cls(target, distance, yaw=yaw, pitch=pitch, fov=fov)

    def state(self):
        return {
            "target": [round(value, 6) for value in self.target],
            "distance": round(self.distance, 6),
            "yaw": self.yaw,
            "pitch": self.pitch,
            "fov": self.fov,
        }


def _view(camera, vertex):
    relative = (vertex[0] - camera.eye[0], vertex[1] - camera.eye[1], vertex[2] - camera.eye[2])
    return (_dot(relative, camera.right), _dot(relative, camera.up), _dot(relative, camera.forward))


def _clip_near(points, near):
    result = []
    for index, current in enumerate(points):
        previous = points[index - 1]
        current_inside = current[2] >= near
        previous_inside = previous[2] >= near
        if current_inside != previous_inside:
            t = (near - previous[2]) / (current[2] - previous[2])
            result.append((
                previous[0] + t * (current[0] - previous[0]),
                previous[1] + t * (current[1] - previous[1]),
                near,
            ))
        if current_inside:
            result.append(current)
    return result


def _hex_shade(color, level, levels):
    value = 0.35 + 0.65 * (level / (levels - 1) if levels > 1 else 1.0)
    channels = [min(255, max(0, round(int(color[index:index + 2], 16) * value))) for index in (1, 3, 5)]
    return "#" + "".join(f"{channel:02x}" for channel in channels)


def render_triangles(items, camera, width, height, shade_levels=16):
    """Project (identifier, mesh, base_color) items into painter-ordered triangles."""
    if not 2 <= shade_levels <= 64:
        raise ValueError("shade levels must be 2-64")
    focal = height / 2 / math.tan(math.radians(camera.fov) / 2)
    near = camera.distance * 0.001
    light = _normalize((-0.4, 0.65, -0.65))
    center_x, center_y = width / 2, height / 2
    triangles = []
    counts = {}
    sequence = 0
    for identifier, mesh, color in items:
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
            raise ValueError(f"structure {identifier} requires a #rrggbb color")
        view = [_view(camera, vertex) for vertex in mesh.vertices]
        drawn = 0
        for face in mesh.faces:
            points = [view[face[0]], view[face[1]], view[face[2]]]
            if all(point[2] < near for point in points):
                continue
            if any(point[2] < near for point in points):
                clipped = _clip_near(points, near)
                if len(clipped) < 3:
                    continue
                polygons = [(clipped[0], clipped[index], clipped[index + 1]) for index in range(1, len(clipped) - 1)]
            else:
                polygons = [tuple(points)]
            for polygon in polygons:
                a, b, c = polygon
                normal = _cross(
                    (b[0] - a[0], b[1] - a[1], b[2] - a[2]),
                    (c[0] - a[0], c[1] - a[1], c[2] - a[2]),
                )
                length = math.sqrt(_dot(normal, normal))
                if length == 0:
                    continue
                normal = (normal[0] / length, normal[1] / length, normal[2] / length)
                level = min(shade_levels - 1, int(abs(_dot(normal, light)) * shade_levels))
                depth = (a[2] + b[2] + c[2]) / 3
                screen = []
                for point in polygon:
                    screen.append([center_x + focal * point[0] / point[2], center_y - focal * point[1] / point[2]])
                triangles.append((-depth, sequence, screen, _hex_shade(color, level, shade_levels)))
                sequence += 1
                drawn += 1
        counts[identifier] = drawn
    triangles.sort(key=lambda triangle: (triangle[0], triangle[1]))
    return {
        "points": [point for triangle in triangles for point in triangle[2]],
        "fills": [triangle[3] for triangle in triangles],
        "counts": counts,
        "total": len(triangles),
    }
