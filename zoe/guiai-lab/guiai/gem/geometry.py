from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class Bounds:
    left: float
    top: float
    right: float
    bottom: float

    @property
    def center_x(self):
        return (self.left + self.right) / 2

    @property
    def center_y(self):
        return (self.top + self.bottom) / 2

    @property
    def width(self):
        return self.right - self.left

    @property
    def height(self):
        return self.bottom - self.top

    def anchor(self, name):
        return {
            "left": (self.left, self.center_y),
            "right": (self.right, self.center_y),
            "top": (self.center_x, self.top),
            "bottom": (self.center_x, self.bottom),
            "center": (self.center_x, self.center_y),
        }[name]

    def contains(self, other, epsilon=0):
        return (
            self.left <= other.left + epsilon and self.top <= other.top + epsilon
            and self.right + epsilon >= other.right and self.bottom + epsilon >= other.bottom
        )

    def overlaps(self, other, epsilon=0):
        return (
            min(self.right, other.right) - max(self.left, other.left) > epsilon
            and min(self.bottom, other.bottom) - max(self.top, other.top) > epsilon
        )

    def touches(self, other, epsilon=0):
        overlap_x = min(self.right, other.right) - max(self.left, other.left)
        overlap_y = min(self.bottom, other.bottom) - max(self.top, other.top)
        horizontal_contact = (
            min(abs(self.top - other.bottom), abs(self.bottom - other.top)) <= epsilon
            and overlap_x >= -epsilon
        )
        vertical_contact = (
            min(abs(self.left - other.right), abs(self.right - other.left)) <= epsilon
            and overlap_y >= -epsilon
        )
        return horizontal_contact or vertical_contact


def object_bounds(item):
    if item["type"] == "rectangle":
        return Bounds(*item["bounds"])
    if item["type"] in {"polygon", "polyline", "line", "mesh"}:
        xs = [point[0] for point in item["points"]]
        ys = [point[1] for point in item["points"]]
        return Bounds(min(xs), min(ys), max(xs), max(ys))
    if item["type"] == "ellipse":
        x, y = item["center"]
        rx, ry = item["radii"]
        return Bounds(x - rx, y - ry, x + rx, y + ry)
    if item["type"] == "text":
        x, y = item["position"]
        height = item["size"]
        width = len(item["text"]) * height * 0.62
        return Bounds(x, y - height, x + width, y)
    raise ValueError(f"unsupported object type: {item['type']}")


def _epsilon(constraint, scene):
    if "epsilon" in constraint:
        return constraint["epsilon"]
    return min(scene.canvas["width"], scene.canvas["height"]) / 1000


def _references(constraint):
    references = [constraint.get(key) for key in ("a", "b", "outer", "inner", "object")]
    references += constraint.get("objects", [])
    return [value for value in references if value and value != "*"]


def _result(constraint, index, passed, detail):
    return {
        "index": index,
        "type": constraint["type"],
        "objects": _references(constraint),
        "passed": bool(passed),
        "detail": detail,
    }


def evaluate_constraint(scene, constraint, index=0):
    kind = constraint["type"]
    epsilon = _epsilon(constraint, scene)
    if kind == "inside_canvas":
        canvas = Bounds(0, 0, scene.canvas["width"], scene.canvas["height"])
        targets = scene.objects if constraint["object"] == "*" else [scene.object(constraint["object"])]
        failures = [item["id"] for item in targets if not canvas.contains(object_bounds(item), epsilon)]
        return _result(constraint, index, not failures, "all objects inside canvas" if not failures else f"outside canvas: {', '.join(failures)}")
    if kind == "nonoverlap":
        objects = [scene.object(object_id) for object_id in constraint["objects"]]
        failures = []
        for left_index, left in enumerate(objects):
            for right in objects[left_index + 1:]:
                if object_bounds(left).overlaps(object_bounds(right), epsilon):
                    failures.append(f"{left['id']} overlaps {right['id']}")
        return _result(constraint, index, not failures, "no bounding-box overlaps" if not failures else "; ".join(failures))
    if kind == "contains":
        outer = object_bounds(scene.object(constraint["outer"]))
        inner = object_bounds(scene.object(constraint["inner"]))
        passed = outer.contains(inner, epsilon)
        detail = f"{constraint['inner']} bounds {inner} within {constraint['outer']} bounds {outer}"
        return _result(constraint, index, passed, detail)
    if kind == "touches":
        left = object_bounds(scene.object(constraint["a"]))
        right = object_bounds(scene.object(constraint["b"]))
        passed = left.touches(right, epsilon)
        return _result(constraint, index, passed, f"bounding-box boundary contact within ε={epsilon:g}")
    if kind == "symmetric":
        left = object_bounds(scene.object(constraint["a"]))
        right = object_bounds(scene.object(constraint["b"]))
        axis = constraint["axis"]
        value = constraint["value"]
        if axis == "x":
            center_error = abs(left.center_x + right.center_x - 2 * value)
            first_center, second_center = left.center_x, right.center_x
            size_error = abs(left.width - right.width) + abs(left.height - right.height)
        else:
            center_error = abs(left.center_y + right.center_y - 2 * value)
            first_center, second_center = left.center_y, right.center_y
            size_error = abs(left.width - right.width) + abs(left.height - right.height)
        passed = center_error <= 2 * epsilon and size_error <= 2 * epsilon
        detail = f"centers {first_center:g}, {second_center:g} around {axis}={value:g}; size error={size_error:g}"
        return _result(constraint, index, passed, detail)
    if kind == "aligned":
        left = object_bounds(scene.object(constraint["a"]))
        right = object_bounds(scene.object(constraint["b"]))
        axis = constraint["axis"]
        difference = abs(getattr(left, axis) - getattr(right, axis))
        return _result(constraint, index, difference <= epsilon, f"{axis} difference={difference:g}, ε={epsilon:g}")
    if kind == "connected":
        line = scene.object(constraint["a"])
        if line["type"] != "line":
            return _result(constraint, index, False, "connected.a must reference a line")
        point = line["points"][constraint["endpoint"]]
        anchor = object_bounds(scene.object(constraint["b"])).anchor(constraint["anchor"])
        distance = math.dist(point, anchor)
        return _result(constraint, index, distance <= epsilon, f"endpoint {point} to {constraint['anchor']} anchor {anchor}, distance={distance:g}")
    return _result(constraint, index, False, f"unsupported constraint: {kind}")


@dataclass(frozen=True)
class VerificationReport:
    scene_id: str
    results: list
    invariants: dict = None

    @property
    def passed(self):
        return all(result["passed"] for result in self.results) and all((self.invariants or {}).values())

    @property
    def failed_ids(self):
        return {object_id for result in self.results if not result["passed"] for object_id in result["objects"]}

    def to_dict(self):
        passed = sum(result["passed"] for result in self.results)
        document = {
            "scene_id": self.scene_id,
            "passed": self.passed,
            "constraints_total": len(self.results),
            "constraints_passed": passed,
            "constraints_failed": len(self.results) - passed,
            "results": self.results,
        }
        if self.invariants is not None:
            document["invariants"] = self.invariants
        return document

    def text(self):
        lines = [f"{'PASS' if self.passed else 'FAIL'} · {self.scene_id} · {sum(result['passed'] for result in self.results)}/{len(self.results)} constraints"]
        for result in self.results:
            lines.append(f"{'PASS' if result['passed'] else 'FAIL'} [{result['index']}] {result['type']}: {result['detail']}")
        return "\n".join(lines)


def verify(scene):
    return VerificationReport(scene.document["id"], [evaluate_constraint(scene, constraint, index) for index, constraint in enumerate(scene.constraints)])
