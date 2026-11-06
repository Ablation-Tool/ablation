from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import math

MODULES = {
    "procrustes": "Procrustes alignment",
    "ellipses": "Ellipse field",
    "parabola": "Parabolic envelope",
    "circle": "Circle and arc",
    "clock": "Modular clock",
    "graph": "Looped star graph",
    "volume": "Accessible volume",
    "onset": "Onset laboratory",
}
DEFAULT_SOURCE = [[101.0, 114.0], [285.0, 159.0]]
DEFAULT_TARGET = [[345.0, 35.0], [500.0, 205.0]]


@dataclass(frozen=True)
class Scene:
    identifier: str
    title: str
    width: float
    height: float
    objects: tuple

    def document(self):
        return {
            "schema_version": 1,
            "id": self.identifier,
            "title": self.title,
            "canvas": {"width": self.width, "height": self.height},
            "objects": deepcopy(self.objects),
        }

    def json(self):
        return json.dumps(self.document(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    def digest(self):
        packed = json.dumps(self.document(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(packed).hexdigest()


def ellipse(identifier, center, radii, stroke, fill="none", width=1):
    return {"id": identifier, "type": "ellipse", "center": center, "radii": radii, "stroke": stroke, "fill": fill, "width": width}


def line(identifier, first, second, stroke="black", width=1):
    return {"id": identifier, "type": "line", "points": [first, second], "stroke": stroke, "fill": "none", "width": width}


def text(identifier, position, value, size=14, stroke="black"):
    return {"id": identifier, "type": "text", "position": position, "text": value, "size": size, "stroke": stroke, "fill": "none", "width": 0}


def rectangle(identifier, bounds, stroke="black", fill="none", width=1):
    return {"id": identifier, "type": "rectangle", "bounds": bounds, "stroke": stroke, "fill": fill, "width": width}


def make_scene(identifier, width, height, objects, title=None):
    if len(objects) > 4096:
        raise ValueError("HELEN scene exceeds 4096 objects")
    for item in objects:
        if item["type"] == "ellipse":
            (x, y), (rx, ry) = item["center"], item["radii"]
            bounds = [x-rx, y-ry, x+rx, y+ry]
        elif item["type"] in {"line", "polyline"}:
            xs = [point[0] for point in item["points"]]
            ys = [point[1] for point in item["points"]]
            bounds = [min(xs), min(ys), max(xs), max(ys)]
        elif item["type"] == "rectangle":
            bounds = item["bounds"]
        elif item["type"] == "text":
            x, y = item["position"]
            bounds = [x, y-item["size"], x+len(item["text"])*item["size"]*.62, y]
        else:
            raise ValueError(f"unsupported HELEN object: {item['type']}")
        if bounds[0] < 0 or bounds[1] < 0 or bounds[2] > width or bounds[3] > height:
            raise ValueError(f"HELEN object outside canvas: {item['id']}")
    return Scene(identifier, title or MODULES.get(identifier.removeprefix("atlas-"), identifier), width, height, tuple(objects))


def _centroid(points):
    return [sum(point[0] for point in points)/len(points), sum(point[1] for point in points)/len(points)]


def _validate_landmarks(source, target):
    if len(source) != len(target) or not 2 <= len(source) <= 4096:
        raise ValueError("source and target need the same number of 2–4096 landmarks")
    for point in source + target:
        if len(point) != 2 or any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) for value in point):
            raise ValueError("landmarks must be finite two-dimensional points")


def _solve3(matrix, vector):
    rows = [list(matrix[index]) + [vector[index]] for index in range(3)]
    for column in range(3):
        pivot = max(range(column, 3), key=lambda index: abs(rows[index][column]))
        if abs(rows[pivot][column]) < 1e-12:
            raise ValueError("affine alignment needs three noncollinear landmark pairs")
        rows[column], rows[pivot] = rows[pivot], rows[column]
        divisor = rows[column][column]
        rows[column] = [value/divisor for value in rows[column]]
        for index in range(3):
            if index != column:
                factor = rows[index][column]
                rows[index] = [left-factor*right for left, right in zip(rows[index], rows[column])]
    return [rows[index][3] for index in range(3)]


def procrustes(source, target, mode="similarity"):
    source = deepcopy(source)
    target = deepcopy(target)
    _validate_landmarks(source, target)
    if mode not in {"similarity", "rigid", "affine"}:
        raise ValueError("alignment mode must be similarity, rigid, or affine")
    if mode == "affine":
        if len(source) < 3:
            raise ValueError("affine alignment needs at least three landmark pairs")
        normal = [[0.0]*3 for _ in range(3)]
        rhs = [[0.0]*3 for _ in range(2)]
        for point, destination in zip(source, target):
            features = [point[0], point[1], 1.0]
            for row in range(3):
                for column in range(3):
                    normal[row][column] += features[row]*features[column]
                for axis in range(2):
                    rhs[axis][row] += features[row]*destination[axis]
        x_solution = _solve3(normal, rhs[0])
        y_solution = _solve3(normal, rhs[1])
        matrix = [x_solution[:2], y_solution[:2]]
        translation = [x_solution[2], y_solution[2]]
    else:
        source_center, target_center = _centroid(source), _centroid(target)
        dot = cross = denominator = 0.0
        for point, destination in zip(source, target):
            px, py = point[0]-source_center[0], point[1]-source_center[1]
            qx, qy = destination[0]-target_center[0], destination[1]-target_center[1]
            dot += px*qx + py*qy
            cross += px*qy - py*qx
            denominator += px*px + py*py
        if denominator == 0 or math.hypot(dot, cross) == 0:
            raise ValueError("rotation requires nonzero source variance and a defined direction")
        cosine, sine = dot/math.hypot(dot, cross), cross/math.hypot(dot, cross)
        scale = math.hypot(dot, cross)/denominator if mode == "similarity" else 1.0
        matrix = [[scale*cosine, -scale*sine], [scale*sine, scale*cosine]]
        translation = [target_center[axis]-sum(matrix[axis][column]*source_center[column] for column in range(2)) for axis in range(2)]
    mapped = [[matrix[axis][0]*point[0]+matrix[axis][1]*point[1]+translation[axis] for axis in range(2)] for point in source]
    squared_error = sum(math.dist(point, destination)**2 for point, destination in zip(mapped, target))
    determinant = matrix[0][0]*matrix[1][1]-matrix[0][1]*matrix[1][0]
    return {
        "mode": mode,
        "matrix": matrix,
        "translation": translation,
        "mapped": mapped,
        "scale": math.sqrt(abs(determinant)),
        "rotation_degrees": math.degrees(math.atan2(matrix[1][0], matrix[0][0])),
        "determinant": determinant,
        "squared_error": squared_error,
        "rmse_per_landmark": math.sqrt(squared_error/len(source)),
        "rmse_per_coordinate": math.sqrt(squared_error/(2*len(source))),
        "landmark_count": len(source),
    }


def landmark_scene(source, target, result=None):
    _validate_landmarks(source, target)
    objects = []
    for index, (point, destination) in enumerate(zip(source, target)):
        objects.append(line(f"correspondence-{index}", point, destination, "gray"))
    objects.append({"id": "source-segment", "type": "polyline", "points": source, "stroke": "red", "fill": "none", "width": 2})
    objects.append({"id": "target-segment", "type": "polyline", "points": target, "stroke": "blue", "fill": "none", "width": 2})
    for prefix, points, color in (("p", source, "red"), ("q", target, "blue")):
        for index, point in enumerate(points):
            objects.append(ellipse(f"{prefix}{index+1}", point, [5, 5], color, color))
            objects.append(text(f"label-{prefix}{index+1}", [point[0]+9, point[1]-8], f"{prefix}{index+1}", 14, color))
    if result is not None:
        for index, point in enumerate(result["mapped"]):
            objects.append(ellipse(f"mapped-{index}", point, [8, 8], "orange"))
    objects.append(text("formula", [20, 330], "q = A p + t  ·  drag landmarks to recompute", 16))
    return make_scene("atlas-procrustes", 760, 350, objects, MODULES["procrustes"])


def ellipses_scene(count=16, selected=15, a0=99.5, a1=286.5, b0=198, b1=73):
    if not 2 <= count <= 64 or min(a0, a1, b0, b1) <= 0:
        raise ValueError("ellipse count must be 2–64 and radii must be positive")
    selected = min(max(0, int(selected)), count-1)
    objects = [rectangle("frame", [25, 25, 628, 425])]
    for index in range(count):
        t = index/(count-1)
        a, b = a0+(a1-a0)*t, b0+(b1-b0)*t
        objects.append(ellipse(f"ellipse-{index}", [326.5, 225], [a, b], "red" if index == selected else "gray", width=2 if index == selected else 1))
    t = selected/(count-1)
    a, b = a0+(a1-a0)*t, b0+(b1-b0)*t
    objects.append(text("formula", [35, 415], f"i={selected}, t={t:.3f}, a={a:.3f}, b={b:.3f}; X²/a² + Y²/b² = 1", 14))
    return make_scene("atlas-ellipses", 662, 442, objects, MODULES["ellipses"]), {"index": selected, "t": t, "a": a, "b": b, "count": count}


def parabola_scene(segments=32, selected_t=.5):
    if not 2 <= segments <= 256 or not 0 <= selected_t <= 1:
        raise ValueError("segments must be 2–256 and t must be in [0,1]")
    a, b, c = [55.0, 423.0], [652.0, 27.0], [55.0, 27.0]
    objects = [rectangle("frame", [53, 27, 652, 423])]
    for index in range(segments+1):
        t = index/segments
        p = [a[axis]+t*(b[axis]-a[axis]) for axis in range(2)]
        q = [b[axis]+t*(c[axis]-b[axis]) for axis in range(2)]
        objects.append(line(f"rule-{index}", p, q, "gray"))
    envelope = [[(1-(index/128))**2*a[axis]+2*(index/128)*(1-index/128)*b[axis]+(index/128)**2*c[axis] for axis in range(2)] for index in range(129)]
    objects.append({"id": "envelope", "type": "polyline", "points": envelope, "stroke": "red", "fill": "none", "width": 2})
    t = selected_t
    p = [a[axis]+t*(b[axis]-a[axis]) for axis in range(2)]
    q = [b[axis]+t*(c[axis]-b[axis]) for axis in range(2)]
    point = [(1-t)**2*a[axis]+2*t*(1-t)*b[axis]+t*t*c[axis] for axis in range(2)]
    objects.append(line("selected-tangent", p, q, "blue", 2))
    objects.append(ellipse("envelope-point", point, [4, 4], "red", "red"))
    derivative = [1194*(1-2*t), 792*(t-1)]
    objects.append(text("formula", [70, 445], f"t={t:.3f}; C'=({derivative[0]:.1f},{derivative[1]:.1f}); C(t)=(1-t)²A+2t(1-t)B+t²T", 13))
    return make_scene("atlas-parabola", 711, 458, objects, MODULES["parabola"]), {"t": t, "point": point, "derivative": derivative, "segments": segments}


def circle_scene(radius=207, angle=100.1):
    if not 10 <= radius <= 207 or not 1 <= angle <= 360:
        raise ValueError("radius must be 10–207 and angle 1–360 degrees")
    center = [260, 225]
    objects = [ellipse("circle", center, [radius, radius], "gray", width=3)]
    objects.append(line("diameter", [center[0]-radius, center[1]], [center[0]+radius, center[1]], "blue", 3))
    half = math.radians(angle/2)
    start, end = math.pi/2-half, math.pi/2+half
    points = [[center[0]+radius*math.cos(start+(end-start)*i/96), center[1]-radius*math.sin(start+(end-start)*i/96)] for i in range(97)]
    objects.append({"id": "arc", "type": "polyline", "points": points, "stroke": "orange", "fill": "none", "width": 4})
    objects.append(line("radius", center, points[-1], "gray", 2))
    objects.append(ellipse("center", center, [6, 6], "black", "black"))
    for index, point in enumerate((points[0], points[-1])):
        objects.append(ellipse(f"arc-end-{index}", point, [6, 6], "orange", "orange"))
    theta = math.radians(angle)
    for index, formula in enumerate((f"d={2*radius:.1f}", f"C={math.tau*radius:.1f}", f"A={math.pi*radius*radius:.1f}", f"s={radius*theta:.1f}")):
        objects.append(text(f"formula-{index}", [500, 100+40*index], formula, 18))
    return make_scene("atlas-circle", 760, 450, objects, MODULES["circle"]), {"radius": radius, "angle_degrees": angle, "theta_radians": theta, "circumference": math.tau*radius, "area": math.pi*radius*radius, "arc_length": radius*theta, "sector_area": .5*radius*radius*theta}


def clock_scene(modulus=12, value=15):
    if not isinstance(modulus, int) or isinstance(modulus, bool) or not 2 <= modulus <= 48 or not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("modulus and value must be integers; modulus must be 2–48")
    remainder = value % modulus
    objects = [ellipse("clock", [250, 250], [205, 205], "black", width=2)]
    for index in range(modulus):
        angle = math.tau*index/modulus
        position = [250+163*math.sin(angle), 250-163*math.cos(angle)]
        objects.append(text(f"label-{index}", [position[0]-5, position[1]+8], str(index), 22))
    angle = math.tau*remainder/modulus
    endpoint = [250+163*math.sin(angle), 250-163*math.cos(angle)]
    objects.append(line("hand", [250, 250], endpoint, "orange", 5))
    objects.append(ellipse("pin", [250, 250], [7, 7], "gray", "gray"))
    objects.append(text("equation", [110, 490], f"{value} = {value//modulus}·{modulus} + {remainder};  {value} ≡ {remainder} (mod {modulus})", 18))
    return make_scene("atlas-clock", 500, 500, objects, MODULES["clock"]), {"value": value, "modulus": modulus, "quotient": value//modulus, "remainder": remainder, "step_degrees": 360/modulus}


def graph_invariants(crossings=False):
    if crossings:
        return {"vertices": 19, "ordinary_edges": 22, "loops": 6, "edges": 28, "components": 1, "cycle_rank": 10, "hub_degree": 8}
    return {"vertices": 13, "ordinary_edges": 10, "loops": 6, "edges": 16, "components": 3, "cycle_rank": 6, "hub_degree": 8}


def graph_scene(crossings=False):
    hub = [229, 239]
    endpoints = [[229, 40], [303, 105], [365, 239], [267, 354], [229, 410], [177, 354], [116, 239], [168, 115]]
    objects = []
    for index, point in enumerate(endpoints):
        objects.append(line(f"spoke-{index+1}", hub, point, "green"))
        objects.append(text(f"h{index+1}", [point[0]-8, point[1]-8], f"h{index+1}", 14, "green"))
    objects.extend([line("crossbar-upper", [94, 166], [358, 166], "green"), line("crossbar-lower", [97, 280], [359, 280], "green")])
    for index in (1, 2, 3, 5, 6, 7):
        objects.append(ellipse(f"loop-{index+1}", endpoints[index], [8, 8], "green"))
    objects.append(ellipse("hub", hub, [4, 4], "green", "green"))
    objects.append(text("hub-label", [205, 262], "hub", 14, "green"))
    for identifier, position in (("v5", [70, 160]), ("v2", [365, 160]), ("v4", [70, 300]), ("v1", [365, 300])):
        objects.append(text(identifier, position, identifier, 14, "green"))
    if crossings:
        for prefix, y, indices in (("upper", 166, (7, 0, 1)), ("lower", 280, (5, 4, 3))):
            for index in indices:
                ratio = (y-hub[1])/(endpoints[index][1]-hub[1])
                x = hub[0]+ratio*(endpoints[index][0]-hub[0])
                objects.append(ellipse(f"{prefix}-junction-{index}", [x, y], [3, 3], "orange", "orange"))
    report = graph_invariants(crossings)
    objects.append(text("invariants", [80, 445], f"V={report['vertices']} E={report['edges']} C={report['components']} cycle rank={report['cycle_rank']}", 16, "green"))
    return make_scene("atlas-graph", 498, 455, objects, MODULES["graph"]), report


def accessible_volume(probabilities, tau):
    values = [float(value) for value in probabilities]
    if not 1 <= len(values) <= 64 or any(not math.isfinite(value) or value < 0 for value in values) or not math.isclose(sum(values), 1.0, abs_tol=1e-8):
        raise ValueError("HELEN needs 1–64 finite nonnegative probabilities summing to one")
    if not math.isfinite(tau) or not 0 <= tau <= .5:
        raise ValueError("HELEN display threshold must be between 0 and 0.5")
    return sum(value > tau for value in values)


class VolumeBridge:
    def __init__(self, minimum=1, maximum=4):
        self.minimum, self.maximum = minimum, maximum
        self.previous = None

    def observe(self, probabilities, tau):
        current = accessible_volume(probabilities, tau)
        previous = None if self.previous is None else accessible_volume(self.previous, tau)
        momentum = None if previous is None else current-previous
        if momentum is None:
            action = "observe"
        elif current < self.minimum:
            action = "let_breadth_grow" if momentum > 0 else "broaden_context"
        elif current > self.maximum:
            action = "let_breadth_settle" if momentum < 0 else "narrow_context"
        else:
            action = "continue"
        report = {"volume": current, "complement": len(probabilities)-current, "previous_volume": previous, "momentum": momentum, "recommendation": action}
        self.previous = list(probabilities)
        return report


def volume_scene(probabilities, previous=None, tau=.05, minimum=1, maximum=4):
    current = accessible_volume(probabilities, tau)
    momentum = None if previous is None else current-accessible_volume(previous, tau)
    if momentum is None:
        action = "observe"
    elif current < minimum:
        action = "let_breadth_grow" if momentum > 0 else "broaden_context"
    elif current > maximum:
        action = "let_breadth_settle" if momentum < 0 else "narrow_context"
    else:
        action = "continue"
    objects = []
    count = len(probabilities)
    for index, probability in enumerate(probabilities):
        x = 45+index*min(70, 500/count)
        width = min(45, 400/count)
        height = 220*probability
        objects.append(rectangle(f"probability-{index}", [x, 250-height, x+width, 250], "black", "blue" if probability > tau else "lightgray"))
        objects.append(text(f"label-{index}", [x, 270], f"{probability:.2f}", 11))
        if previous is not None:
            objects.append(line(f"previous-{index}", [x-3, 250-220*previous[index]], [x+width+3, 250-220*previous[index]], "red", 2))
    curve = []
    for index in range(101):
        threshold = index/200
        curve.append([560+360*threshold, 250-220*accessible_volume(probabilities, threshold)/count])
    objects.append({"id": "sweep", "type": "polyline", "points": curve, "stroke": "blue", "fill": "none", "width": 2})
    objects.append(line("threshold", [560+360*tau, 25], [560+360*tau, 250], "orange", 2))
    objects.append(text("distribution", [45, 30], "Full categorical distribution", 18))
    objects.append(text("sweep-label", [560, 30], "A(τ) sweep", 18))
    summary = f"τ={tau:.3f} A={current}/{count} complement={count-current}"
    if momentum is not None:
        summary += f" M={momentum:+d} recommendation={action}"
    objects.append(text("measurement", [45, 330], summary, 15))
    objects.append(text("scope", [45, 365], "Forecast breadth, not correctness · strict p > τ · recommendations only", 14))
    return make_scene("atlas-volume", 760, 400, objects, MODULES["volume"]), {"volume": current, "complement": count-current, "momentum": momentum, "recommendation": action, "summary": summary}


def onset_scene(data, tau=.05, temperature=1.0):
    forward, forward_curve = data.condition("forward", temperature)
    retrograde, retrograde_curve = data.condition("retrograde", temperature)
    values = list(forward_curve)+list(retrograde_curve)
    y_min, y_max = min(1.0, math.floor(min(values)*2)/2), max(1.5, math.ceil(max(values)*2)/2)
    objects = []
    for index in range(5):
        value = y_min+(y_max-y_min)*index/4
        y = 320-240*index/4
        objects.append(line(f"grid-{index}", [70, y], [680, y], "lightgray"))
        objects.append(text(f"tick-y-{index}", [20, y+4], f"{value:.1f}", 11))
    for index in range(6):
        objects.append(text(f"tick-x-{index}", [70+120*index-4, 338], f"{index/10:.1f}", 11))
    for name, curve, color in (("forward", forward_curve, "blue"), ("retrograde", retrograde_curve, "orange")):
        points = [[70+1200*data.thresholds[index], 320-240*(curve[index]-y_min)/(y_max-y_min)] for index in range(len(data.thresholds))]
        objects.append({"id": name, "type": "polyline", "points": points, "stroke": color, "fill": "none", "width": 2})
    objects.extend([line("axis-x", [70, 320], [680, 320]), line("axis-y", [70, 60], [70, 320]), line("selected-tau", [70+1200*tau, 60], [70+1200*tau, 320], "gray")])
    forward_at_tau = data.accessible_at("forward", tau, temperature)
    retrograde_at_tau = data.accessible_at("retrograde", tau, temperature)
    objects.append(text("title", [70, 35], "Held-out categorical next-interval forecasts", 18))
    objects.append(text("legend", [480, 35], "blue=forward  orange=retrograde", 14))
    objects.append(text("forward-metrics", [70, 360], f"Forward: top1={forward['top1']:.1%} log-loss={forward['log_loss']:.3f} A(τ)={forward_at_tau:.2f}", 14))
    objects.append(text("retrograde-metrics", [70, 385], f"Retrograde: top1={retrograde['top1']:.1%} log-loss={retrograde['log_loss']:.3f} A(τ)={retrograde_at_tau:.2f}", 14))
    objects.append(text("scope", [70, 410], "Synthetic evidence · breadth is not correctness", 13))
    objects.append(text("scope-hop", [70, 432], "HOP supplies no categorical distribution or accessible volume", 13))
    return make_scene("atlas-onset", 760, 450, objects, MODULES["onset"]), {"forward": forward, "retrograde": retrograde, "forward_at_tau": forward_at_tau, "retrograde_at_tau": retrograde_at_tau, "temperature": temperature, "tau": tau}


def default_document(module, onset_data=None):
    if module == "procrustes":
        result = procrustes(DEFAULT_SOURCE, DEFAULT_TARGET)
        return landmark_scene(DEFAULT_SOURCE, DEFAULT_TARGET, result), result
    if module == "ellipses":
        return ellipses_scene()
    if module == "parabola":
        return parabola_scene()
    if module == "circle":
        return circle_scene()
    if module == "clock":
        return clock_scene()
    if module == "graph":
        return graph_scene()
    if module == "volume":
        return volume_scene([.70, .20, .08, .02])
    if module == "onset":
        if onset_data is None:
            from .onset import load_experiment
            onset_data = load_experiment()
        return onset_scene(onset_data)
    raise ValueError(f"unknown HELEN module: {module}")
