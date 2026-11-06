from __future__ import annotations

from copy import deepcopy
import math

from .model import Scene
from .onset import run_synthetic_experiment, temper
from .volume import measure_probabilities

ATLAS_MODULES = {
    "brain": "Zoe · BRAIN orchestration",
    "field": "Zoe · Bayesian field notebook",
    "procrustes": "Procrustes landmark alignment",
    "ellipses": "Ellipse family",
    "parabola": "Parabolic line envelope",
    "circle": "Circle, arc, and sector",
    "clock": "Modular arithmetic clock",
    "graph": "Hub-and-loop graph",
    "volume": "Accessible volume bridge",
    "onset": "Onset forecast laboratory",
    "horizon": "Multi-horizon accessible volume",
    "research": "Research evidence pack",
}

DEFAULT_SOURCE = [[101, 114], [285, 159]]
DEFAULT_TARGET = [[345, 35], [500, 205]]


def _points(source, target):
    if len(source) != len(target) or not 2 <= len(source) <= 4096:
        raise ValueError("source and target require the same number of 2–4096 landmarks")
    result = []
    for name, points in (("source", source), ("target", target)):
        converted = []
        for point in points:
            if len(point) != 2 or any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) for value in point):
                raise ValueError(f"{name} landmarks must be finite two-dimensional points")
            converted.append([float(point[0]), float(point[1])])
        result.append(converted)
    return result


def _centroid(points):
    count = len(points)
    return [sum(point[0] for point in points) / count, sum(point[1] for point in points) / count]


def _solve3(matrix, vector):
    rows = [list(matrix[index]) + [vector[index]] for index in range(3)]
    for column in range(3):
        pivot = max(range(column, 3), key=lambda index: abs(rows[index][column]))
        if abs(rows[pivot][column]) < 1e-12:
            raise ValueError("affine alignment requires at least three noncollinear landmark pairs")
        rows[column], rows[pivot] = rows[pivot], rows[column]
        divisor = rows[column][column]
        rows[column] = [value / divisor for value in rows[column]]
        for index in range(3):
            if index == column:
                continue
            factor = rows[index][column]
            rows[index] = [left - factor * right for left, right in zip(rows[index], rows[column])]
    return [rows[index][3] for index in range(3)]


def procrustes(source, target, mode="similarity"):
    source, target = _points(source, target)
    if mode not in {"similarity", "rigid", "affine"}:
        raise ValueError("alignment mode must be similarity, rigid, or affine")
    count = len(source)
    if mode == "affine":
        if count < 3:
            raise ValueError("affine alignment requires at least three landmark pairs; two pairs leave two degrees of freedom")
        normal = [[0.0] * 3 for _ in range(3)]
        rhs = [[0.0] * 3 for _ in range(2)]
        for point, destination in zip(source, target):
            features = [point[0], point[1], 1.0]
            for row in range(3):
                for column in range(3):
                    normal[row][column] += features[row] * features[column]
                for axis in range(2):
                    rhs[axis][row] += features[row] * destination[axis]
        x_solution = _solve3(normal, rhs[0])
        y_solution = _solve3(normal, rhs[1])
        matrix = [x_solution[:2], y_solution[:2]]
        translation = [x_solution[2], y_solution[2]]
        scale = math.sqrt(abs(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]))
        angle = math.degrees(math.atan2(matrix[1][0], matrix[0][0]))
    else:
        source_center = _centroid(source)
        target_center = _centroid(target)
        dot = cross = denominator = 0.0
        for point, destination in zip(source, target):
            px, py = point[0] - source_center[0], point[1] - source_center[1]
            qx, qy = destination[0] - target_center[0], destination[1] - target_center[1]
            dot += px * qx + py * qy
            cross += px * qy - py * qx
            denominator += px * px + py * py
        if denominator == 0:
            raise ValueError("alignment requires nonzero source variance")
        if math.hypot(dot, cross) == 0:
            raise ValueError("rotation is undefined for orthogonal centered landmark sets")
        cosine = dot / math.hypot(dot, cross)
        sine = cross / math.hypot(dot, cross)
        scale = math.hypot(dot, cross) / denominator if mode == "similarity" else 1.0
        matrix = [[scale * cosine, -scale * sine], [scale * sine, scale * cosine]]
        translation = [
            target_center[axis] - sum(matrix[axis][column] * source_center[column] for column in range(2))
            for axis in range(2)
        ]
        angle = math.degrees(math.atan2(matrix[1][0], matrix[0][0]))
    mapped = [
        [
            matrix[axis][0] * point[0] + matrix[axis][1] * point[1] + translation[axis]
            for axis in range(2)
        ]
        for point in source
    ]
    residuals = [math.dist(point, destination) for point, destination in zip(mapped, target)]
    squared_error = sum(value * value for value in residuals)
    determinant = matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
    return {
        "mode": mode,
        "matrix": matrix,
        "translation": translation,
        "mapped": mapped,
        "scale": scale,
        "rotation_degrees": angle,
        "determinant": determinant,
        "squared_error": squared_error,
        "rmse_per_landmark": math.sqrt(squared_error / count),
        "rmse_per_coordinate": math.sqrt(squared_error / (2 * count)),
        "landmark_count": count,
    }


def _scene(identifier, width, height, objects, title):
    return Scene.from_dict({
        "schema_version": 1,
        "id": identifier,
        "title": title,
        "canvas": {"width": width, "height": height},
        "objects": objects,
        "constraints": [{"type": "inside_canvas", "object": "*"}],
    })


def _ellipse(identifier, center, radii, stroke, fill="none", width=1):
    return {"id": identifier, "type": "ellipse", "center": center, "radii": radii, "stroke": stroke, "fill": fill, "width": width}


def _line(identifier, first, second, stroke="black", width=1):
    return {"id": identifier, "type": "line", "points": [first, second], "stroke": stroke, "fill": "none", "width": width}


def _text(identifier, position, text, size=14, stroke="black"):
    return {"id": identifier, "type": "text", "position": position, "text": text, "size": size, "stroke": stroke, "fill": "none", "width": 0}


def landmark_scene(source, target, result=None):
    source, target = _points(source, target)
    objects = []
    for index, (point, destination) in enumerate(zip(source, target)):
        objects.append(_line(f"correspondence-{index}", point, destination, "gray"))
    if len(source) >= 2:
        objects.append({"id": "source-segment", "type": "polyline", "points": source, "stroke": "red", "fill": "none", "width": 2})
        objects.append({"id": "target-segment", "type": "polyline", "points": target, "stroke": "blue", "fill": "none", "width": 2})
    for prefix, points, color in (("p", source, "red"), ("q", target, "blue")):
        for index, point in enumerate(points):
            objects.append(_ellipse(f"{prefix}{index + 1}", point, [5, 5], color, color))
            objects.append(_text(f"label-{prefix}{index + 1}", [point[0] + 9, point[1] - 8], f"{prefix}{index + 1}", 14, color))
    if result is not None:
        for index, point in enumerate(result["mapped"]):
            objects.append(_ellipse(f"mapped-{index}", point, [8, 8], "orange", "none", 1))
    objects.append(_text("formula", [20, 330], "q = A p + t  ·  drag landmarks to recompute", 16))
    return _scene("atlas-procrustes", 760, 350, objects, ATLAS_MODULES["procrustes"])


def ellipses_scene(count=16, selected=15, a0=99.5, a1=286.5, b0=198, b1=73):
    if not 2 <= count <= 64:
        raise ValueError("ellipse count must be from 2 to 64")
    if min(a0, a1, b0, b1) <= 0:
        raise ValueError("ellipse radii must be positive")
    selected = min(max(0, int(selected)), count - 1)
    objects = [{"id": "frame", "type": "rectangle", "bounds": [25, 25, 628, 425], "stroke": "black", "fill": "none", "width": 1}]
    for index in range(count):
        t = index / (count - 1)
        a = a0 + (a1 - a0) * t
        b = b0 + (b1 - b0) * t
        color = "red" if index == selected else "gray"
        objects.append(_ellipse(f"ellipse-{index}", [326.5, 225], [a, b], color, "none", 2 if index == selected else 1))
    t = selected / (count - 1)
    a = a0 + (a1 - a0) * t
    b = b0 + (b1 - b0) * t
    objects.append(_text("formula", [35, 415], f"i={selected}, t={t:.3f}, a={a:.3f}, b={b:.3f};  X²/a² + Y²/b² = 1", 14))
    scene = _scene("atlas-ellipses", 662, 442, objects, ATLAS_MODULES["ellipses"])
    return scene, {"index": selected, "t": t, "a": a, "b": b, "count": count}


def parabola_geometry(segments=32, selected_t=.5):
    if not 2 <= segments <= 256:
        raise ValueError("segment count must be from 2 to 256")
    if not 0 <= selected_t <= 1:
        raise ValueError("t must be between zero and one")
    a, b, c = [55.0, 423.0], [652.0, 27.0], [55.0, 27.0]
    objects = [{"id": "frame", "type": "rectangle", "bounds": [53, 27, 652, 423], "stroke": "black", "fill": "none", "width": 1}]
    for index in range(segments + 1):
        t = index / segments
        p = [a[axis] + t * (b[axis] - a[axis]) for axis in range(2)]
        q = [b[axis] + t * (c[axis] - b[axis]) for axis in range(2)]
        objects.append(_line(f"rule-{index}", p, q, "gray"))
    envelope = []
    for index in range(129):
        t = index / 128
        envelope.append([
            (1-t)**2 * a[axis] + 2*t*(1-t) * b[axis] + t*t * c[axis]
            for axis in range(2)
        ])
    objects.append({"id": "envelope", "type": "polyline", "points": envelope, "stroke": "red", "fill": "none", "width": 2})
    t = selected_t
    p = [a[axis] + t * (b[axis] - a[axis]) for axis in range(2)]
    q = [b[axis] + t * (c[axis] - b[axis]) for axis in range(2)]
    point = [(1-t)**2 * a[axis] + 2*t*(1-t) * b[axis] + t*t * c[axis] for axis in range(2)]
    objects.append(_line("selected-tangent", p, q, "blue", 2))
    objects.append(_ellipse("envelope-point", point, [4, 4], "red", "red"))
    derivative = [1194 * (1 - 2*t), 792 * (t - 1)]
    objects.append(_text("formula", [70, 445], f"C(t)=(1-t)²A+2t(1-t)B+t²T; t={t:.3f}; C'=({derivative[0]:.1f},{derivative[1]:.1f})", 13))
    scene = _scene("atlas-parabola", 711, 458, objects, ATLAS_MODULES["parabola"])
    return scene, {"t": t, "point": point, "derivative": derivative, "segments": segments}


def circle_scene(radius=207, angle=100.1):
    if not 10 <= radius <= 207 or not 1 <= angle <= 360:
        raise ValueError("circle radius must be 10–207 and angle 1–360 degrees")
    center = [260, 225]
    objects = [_ellipse("circle", center, [radius, radius], "gray", "none", 3)]
    objects.append(_line("diameter", [center[0]-radius, center[1]], [center[0]+radius, center[1]], "blue", 3))
    half = math.radians(angle / 2)
    start = math.pi / 2 - half
    end = math.pi / 2 + half
    points = [[center[0] + radius * math.cos(start + (end-start)*i/96), center[1] - radius * math.sin(start + (end-start)*i/96)] for i in range(97)]
    objects.append({"id": "arc", "type": "polyline", "points": points, "stroke": "orange", "fill": "none", "width": 4})
    endpoint = points[-1]
    objects.append(_line("radius", center, endpoint, "gray", 2))
    objects.append(_ellipse("center", center, [6, 6], "black", "black"))
    for index, point in enumerate((points[0], points[-1])):
        objects.append(_ellipse(f"arc-end-{index}", point, [6, 6], "orange", "orange"))
    theta = math.radians(angle)
    for index, formula in enumerate((f"d={2*radius:.1f}", f"C={math.tau*radius:.1f}", f"A={math.pi*radius*radius:.1f}", f"s={radius*theta:.1f}")):
        objects.append(_text(f"formula-{index}", [500, 100 + 40 * index], formula, 18))
    scene = _scene("atlas-circle", 760, 450, objects, ATLAS_MODULES["circle"])
    return scene, {"radius": radius, "angle_degrees": angle, "theta_radians": theta, "diameter": 2*radius, "circumference": math.tau*radius, "area": math.pi*radius*radius, "arc_length": radius*theta, "sector_area": .5*radius*radius*theta}


def clock_scene(modulus=12, value=15):
    if not 2 <= modulus <= 48 or not isinstance(value, int):
        raise ValueError("modulus must be 2–48 and value must be an integer")
    remainder = value % modulus
    quotient = value // modulus
    objects = [_ellipse("clock", [250, 250], [205, 205], "black", "none", 2)]
    for index in range(modulus):
        angle = math.tau * index / modulus
        position = [250 + 163 * math.sin(angle), 250 - 163 * math.cos(angle)]
        objects.append(_text(f"label-{index}", [position[0]-5, position[1]+8], str(index), 22))
    angle = math.tau * remainder / modulus
    endpoint = [250 + 163 * math.sin(angle), 250 - 163 * math.cos(angle)]
    objects.append(_line("hand", [250, 250], endpoint, "orange", 5))
    objects.append(_ellipse("pin", [250, 250], [7, 7], "gray", "gray"))
    objects.append(_text("equation", [110, 490], f"{value} = {quotient}·{modulus} + {remainder};  {value} ≡ {remainder} (mod {modulus})", 18))
    scene = _scene("atlas-clock", 500, 500, objects, ATLAS_MODULES["clock"])
    return scene, {"value": value, "modulus": modulus, "quotient": quotient, "remainder": remainder, "step_degrees": 360/modulus, "hand_angle_degrees": 360*remainder/modulus}


def graph_invariants(crossings_are_vertices=False):
    if crossings_are_vertices:
        return {"vertices": 19, "ordinary_edges": 22, "loops": 6, "edges": 28, "components": 1, "cycle_rank": 10, "hub_degree": 8}
    return {"vertices": 13, "ordinary_edges": 10, "loops": 6, "edges": 16, "components": 3, "cycle_rank": 6, "hub_degree": 8}


def graph_scene(crossings_are_vertices=False):
    hub = [229, 239]
    endpoints = [[229, 40], [303, 105], [365, 239], [267, 354], [229, 410], [177, 354], [116, 239], [168, 115]]
    objects = []
    for index, point in enumerate(endpoints):
        objects.append(_line(f"spoke-{index+1}", hub, point, "green"))
        objects.append(_text(f"h{index+1}", [point[0]-8, point[1]-8], f"h{index+1}", 14, "green"))
    objects.append(_line("crossbar-upper", [94, 166], [358, 166], "green"))
    objects.append(_line("crossbar-lower", [97, 280], [359, 280], "green"))
    for index in (1, 2, 3, 5, 6, 7):
        objects.append(_ellipse(f"loop-{index+1}", endpoints[index], [8, 8], "green"))
    objects.append(_ellipse("hub", hub, [4, 4], "green", "green"))
    objects.append(_text("hub-label", [205, 262], "hub", 14, "green"))
    objects.append(_text("v5", [70, 160], "v5", 14, "green"))
    objects.append(_text("v2", [365, 160], "v2", 14, "green"))
    objects.append(_text("v4", [70, 300], "v4", 14, "green"))
    objects.append(_text("v1", [365, 300], "v1", 14, "green"))
    if crossings_are_vertices:
        for prefix, y, indices in (("upper", 166, (7, 0, 1)), ("lower", 280, (5, 4, 3))):
            for index in indices:
                ratio = (y - hub[1]) / (endpoints[index][1] - hub[1])
                x = hub[0] + ratio * (endpoints[index][0] - hub[0])
                objects.append(_ellipse(f"{prefix}-junction-{index}", [x, y], [3, 3], "orange", "orange"))
    report = graph_invariants(crossings_are_vertices)
    objects.append(_text("invariants", [80, 445], f"V={report['vertices']} E={report['edges']} C={report['components']} cycle rank={report['cycle_rank']}", 16, "green"))
    return _scene("atlas-graph", 498, 455, objects, ATLAS_MODULES["graph"]), report


def volume_scene(probabilities, previous=None, tau=.05, minimum=1, maximum=4):
    tau = float(tau)
    if not math.isfinite(tau) or not 0 <= tau <= .5:
        raise ValueError("atlas volume threshold must be between 0 and 0.5")
    if not 1 <= len(probabilities) <= 64:
        raise ValueError("atlas volume displays from 1 to 64 categorical outcomes")
    if previous is not None and len(previous) != len(probabilities):
        raise ValueError("current and previous distributions must use the same vocabulary")
    thresholds = sorted({.005 + index * .495 / 99 for index in range(100)} | {tau})
    report = measure_probabilities(probabilities, thresholds=thresholds, previous=previous, minimum=minimum, maximum=maximum)
    current = next(entry for entry in report["threshold_sweep"] if entry["tau"] == tau)
    objects = []
    count = len(probabilities)
    for index, probability in enumerate(probabilities):
        x = 45 + index * min(70, 500 / count)
        width = min(45, 400 / count)
        height = 220 * probability
        objects.append({"id": f"probability-{index}", "type": "rectangle", "bounds": [x, 250-height, x+width, 250], "fill": "blue" if probability > tau else "lightgray", "stroke": "black", "width": 1})
        objects.append(_text(f"probability-label-{index}", [x, 270], f"{probability:.2f}", 11))
        if previous is not None:
            previous_height = 220 * previous[index]
            objects.append(_line(f"previous-{index}", [x-3, 250-previous_height], [x+width+3, 250-previous_height], "red", 2))
    curve = []
    for entry in report["threshold_sweep"]:
        curve.append([590 + 150*entry["tau"]/.5, 250-220*entry["normalized_accessible_volume"]])
    objects.append({"id": "volume-sweep", "type": "polyline", "points": curve, "stroke": "blue", "fill": "none", "width": 2})
    objects.append(_line("threshold", [590+300*tau, 25], [590+300*tau, 250], "orange", 2))
    objects.append(_text("volume-label", [45, 30], "Full categorical distribution", 18))
    objects.append(_text("sweep-label", [560, 30], "A(τ) sweep", 18))
    summary = f"τ={current['tau']:.3f}  A={current['accessible_volume']}/{count}  complement={current['complement_volume']}"
    if "accessible_momentum" in current:
        summary += f"  M={current['accessible_momentum']:+d}  recommendation={current['suggested_action']}"
    objects.append(_text("measurement", [45, 330], summary, 15))
    objects.append(_text("scope", [45, 365], "Forecast breadth, not correctness · strict p > τ · recommendations only", 14))
    scene = _scene("atlas-volume", 760, 400, objects, ATLAS_MODULES["volume"])
    return scene, {"measurement": current, "report": report, "summary": summary}


def onset_scene(experiment, tau=.05, temperature=1.0):
    forward_metrics, forward_curve = experiment.condition("forward", temperature)
    retrograde_metrics, retrograde_curve = experiment.condition("retrograde", temperature)
    thresholds = list(experiment.thresholds)
    values = list(forward_curve) + list(retrograde_curve)
    y_min = min(1.0, math.floor(min(values) * 2) / 2)
    y_max = max(1.5, math.ceil(max(values) * 2) / 2)
    curves = []
    for curve in (forward_curve, retrograde_curve):
        points = [[70 + 600*thresholds[index]/.5, 320 - 240*(curve[index]-y_min)/(y_max-y_min)] for index in range(len(thresholds))]
        curves.append(points)
    objects = []
    for index in range(5):
        value = y_min + (y_max-y_min) * index / 4
        y = 320 - 240 * index / 4
        objects.append(_line(f"grid-{index}", [70, y], [680, y], "lightgray"))
        objects.append(_text(f"tick-y-{index}", [20, y+4], f"{value:.1f}", 11))
    for index in range(6):
        objects.append(_text(f"tick-x-{index}", [70+120*index-4, 338], f"{index/10:.1f}", 11))
    for name, points, color in (("forward", curves[0], "blue"), ("retrograde", curves[1], "orange")):
        objects.append({"id": name, "type": "polyline", "points": points, "stroke": color, "fill": "none", "width": 2})
    objects.append(_line("axes-x", [70, 320], [680, 320], "black"))
    objects.append(_line("axes-y", [70, 60], [70, 320], "black"))
    objects.append(_line("selected-tau", [70+1200*tau, 60], [70+1200*tau, 320], "gray"))
    forward_at_tau = float((temper(experiment.forward_probabilities, temperature) > tau).sum(axis=1).mean())
    retrograde_at_tau = float((temper(experiment.retrograde_probabilities, temperature) > tau).sum(axis=1).mean())
    objects.append(_text("title", [70, 35], "Held-out categorical next-interval forecasts", 18))
    objects.append(_text("legend", [480, 35], "blue=forward  orange=retrograde", 14))
    objects.append(_text("forward-metrics", [70, 360], f"Forward: top1={forward_metrics['top1']:.1%}  log-loss={forward_metrics['log_loss']:.3f}  A(τ)={forward_at_tau:.2f}", 14))
    objects.append(_text("retrograde-metrics", [70, 385], f"Retrograde: top1={retrograde_metrics['top1']:.1%}  log-loss={retrograde_metrics['log_loss']:.3f}  A(τ)={retrograde_at_tau:.2f}", 14))
    objects.append(_text("scope", [70, 410], "Synthetic training only · breadth is not correctness", 13))
    objects.append(_text("scope-hop", [70, 432], "HOP supplies no categorical distribution or accessible volume", 13))
    scene = _scene("atlas-onset", 760, 450, objects, ATLAS_MODULES["onset"])
    return scene, {"forward": forward_metrics, "retrograde": retrograde_metrics, "forward_at_tau": forward_at_tau, "retrograde_at_tau": retrograde_at_tau, "temperature": temperature, "tau": tau}


def default_document(module, research_root=None):
    if module == "brain":
        from .brain import BrainKernel, brain_scene
        kernel = BrainKernel()
        kernel.observe_onset()
        return brain_scene(kernel)
    if module == "field":
        from .field import FieldNotebook, field_scene
        return field_scene(FieldNotebook.demo())
    if module == "procrustes":
        source, target = deepcopy(DEFAULT_SOURCE), deepcopy(DEFAULT_TARGET)
        result = procrustes(source, target)
        return landmark_scene(source, target, result), result
    if module == "ellipses":
        return ellipses_scene()
    if module == "parabola":
        return parabola_geometry()
    if module == "circle":
        return circle_scene()
    if module == "clock":
        return clock_scene()
    if module == "graph":
        return graph_scene()
    if module == "volume":
        return volume_scene([.70, .20, .08, .02])
    if module == "onset":
        experiment = run_synthetic_experiment()
        return onset_scene(experiment)
    if module == "horizon":
        from .brain import horizon_scene
        return horizon_scene()
    if module == "research":
        from .research import ResearchPack, research_scene
        pack = ResearchPack.load(research_root) if research_root else ResearchPack()
        return research_scene(pack)
    raise ValueError(f"unknown atlas module: {module}")
