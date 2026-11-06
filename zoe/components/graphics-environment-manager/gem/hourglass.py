from __future__ import annotations

import math

from .model import Scene


PAST = "cyan"
FUTURE = "magenta"
PRESENT = "yellow"
PRESENT_INK = "black"
INK = "white"
MUTED = "lightgray"
EXCLUDED = "red"
PAPER = "black"


def _distribution(values):
    if not isinstance(values, dict) or not values:
        raise ValueError("a finite labeled distribution is required")
    if any(not isinstance(state, str) or not state for state in values):
        raise ValueError("distribution states must be nonempty labels")
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 for value in values.values()):
        raise ValueError("distribution probabilities must be finite and nonnegative")
    if not math.isclose(sum(values.values()), 1.0, rel_tol=0, abs_tol=1e-9):
        raise ValueError("distribution probabilities must sum to one")
    return {state: float(value) for state, value in values.items()}


def accessible_set(distribution, tau):
    distribution = _distribution(distribution)
    if isinstance(tau, bool) or not isinstance(tau, (int, float)) or not math.isfinite(tau) or not 0 <= tau < 1:
        raise ValueError("accessible-volume threshold must be finite and in [0, 1)")
    return sorted(state for state, probability in distribution.items() if probability > tau)


def accessible_volume(distribution, tau):
    return len(accessible_set(distribution, tau))


def relative_entropy(actual, reference):
    actual = _distribution(actual)
    reference = _distribution(reference)
    if set(actual) != set(reference):
        raise ValueError("repertoires must cover the same states")
    result = 0.0
    for state, observed in actual.items():
        independent = reference[state]
        if observed and not independent:
            raise ValueError("reference repertoire assigns zero probability to a possible actual state")
        if observed:
            result += observed * math.log2(observed / independent)
    return result


def q_arrow_annotation(before, after, tau):
    before = _distribution(before)
    after = _distribution(after)
    if set(before) != set(after):
        raise ValueError("q-arrow repertoires must cover the same states")
    before_set = set(accessible_set(before, tau))
    after_set = set(accessible_set(after, tau))
    return {
        "tau": float(tau),
        "ei_bits": relative_entropy(after, before),
        "delta_accessible_q_volume": len(after_set) - len(before_set),
        "entered": sorted(after_set - before_set),
        "exited": sorted(before_set - after_set),
    }


def accessible_q_toy():
    before = {state: 0.25 for state in ("00", "01", "10", "11")}
    after = {"00": 1 / 3, "01": 1 / 3, "10": 1 / 3, "11": 0.0}
    future = {"A": 0.70, "B": 0.20, "C": 0.08, "D": 0.02}
    return {
        "before": before,
        "after": after,
        "future": future,
        "arrows": [q_arrow_annotation(before, after, tau) for tau in (0.20, 0.30)],
        "past_accessible_q_volume": accessible_volume(after, 0.20),
        "future_accessible_volume": accessible_volume(future, 0.05),
    }


def _text(identifier, position, value, size=14, color=INK):
    return {"id": identifier, "type": "text", "position": position, "text": value, "size": size, "stroke": color, "fill": "none", "width": 0}


def _centered(identifier, center_x, y, value, size=14, color=INK):
    return _text(identifier, [center_x - len(value) * size * 0.29, y], value, size, color)


def _rectangle(identifier, bounds, stroke, fill="none", width=1):
    return {"id": identifier, "type": "rectangle", "bounds": bounds, "stroke": stroke, "fill": fill, "width": width}


def _ellipse(identifier, center, radii, stroke, fill="none", width=1):
    return {"id": identifier, "type": "ellipse", "center": center, "radii": radii, "stroke": stroke, "fill": fill, "width": width}


def _line(identifier, first, second, color=MUTED, width=1):
    return {"id": identifier, "type": "line", "points": [first, second], "stroke": color, "fill": "none", "width": width}


def _polygon(identifier, points, stroke, fill="none", width=1):
    return {"id": identifier, "type": "polygon", "points": points, "stroke": stroke, "fill": fill, "width": width}


def _sign(first, second, third):
    return (first[0] - third[0]) * (second[1] - third[1]) - (second[0] - third[0]) * (first[1] - third[1])


def _inside_triangle(point, triangle):
    first, second, third = triangle
    d1 = _sign(point, first, second)
    d2 = _sign(point, second, third)
    d3 = _sign(point, third, first)
    tolerance = 1e-9
    has_negative = d1 < -tolerance or d2 < -tolerance or d3 < -tolerance
    has_positive = d1 > tolerance or d2 > tolerance or d3 > tolerance
    return not (has_negative and has_positive)


def _clipped_contours(objects, prefix, center, radii, triangle, color, samples=240):
    segments = []
    segment = []
    for index in range(samples + 1):
        angle = math.tau * index / samples
        point = [center[0] + radii[0] * math.cos(angle), center[1] + radii[1] * math.sin(angle)]
        if _inside_triangle(point, triangle):
            segment.append(point)
        else:
            if len(segment) >= 2:
                segments.append(segment)
            segment = []
    if len(segment) >= 2:
        segments.append(segment)
    for index, points in enumerate(segments):
        objects.append({
            "id": f"{prefix}-contour-{index}",
            "type": "polyline",
            "points": points,
            "stroke": color,
            "fill": "none",
            "width": 1,
        })
    return len(segments)


def _hatching(objects, prefix, triangle, color, spacing=24):
    base_left, base_right, apex = triangle
    minimum_y = min(point[1] for point in triangle)
    maximum_y = max(point[1] for point in triangle)
    center_x = apex[0]
    half_width = abs(base_right[0] - base_left[0]) / 2
    final_y = math.floor(maximum_y / spacing) * spacing
    for index, y in enumerate(range(math.ceil(minimum_y / spacing) * spacing, final_y + 1, spacing)):
        extent = half_width * (apex[1] - y) / (apex[1] - base_left[1])
        objects.append(_line(f"{prefix}-hatch-{index}", [center_x - extent, y], [center_x + extent, y], color))


def hourglass_scene():
    toy = accessible_q_toy()
    past_count = toy["past_accessible_q_volume"]
    future_count = toy["future_accessible_volume"]
    objects = [_rectangle("paper", [0, 0, 1200, 1040], PAPER, PAPER, 0)]
    for index, inset in enumerate((20, 40, 60, 82)):
        objects.append(_rectangle(f"threshold-frame-{index}", [inset, inset, 1200 - inset, 1020 - inset], INK, "none", 1))

    past_triangle = [[250, 190], [950, 190], [600, 480]]
    future_triangle = [[250, 770], [950, 770], [600, 480]]
    objects.append(_polygon("past-hourglass", past_triangle, PAST, PAPER, 2))
    objects.append(_polygon("future-hourglass", future_triangle, FUTURE, PAPER, 2))
    _hatching(objects, "past", past_triangle, PAST)
    _hatching(objects, "future", future_triangle, FUTURE)

    contour_segments = 0
    for index in range(1, 5):
        radii = [80 + index * 80, 35 + index * 55]
        contour_segments += _clipped_contours(objects, f"past-{index}", [600, 480], radii, past_triangle, PAST)
        contour_segments += _clipped_contours(objects, f"future-{index}", [600, 480], radii, future_triangle, FUTURE)

    objects.extend([
        _centered("title", 600, 105, "ZOE / ARTLINE HOURGLASS", 27, INK),
        _centered("subtitle", 600, 135, "ACCESSIBLE Q-VOLUME · CAUSE -> PRESENT -> FORECAST", 15, MUTED),
        _centered("operator", 600, 166, "A(tau)[p] = #{z : p(z) > tau}", 19, INK),
        _centered("past-title", 600, 218, "CAUSAL PASTS / Q-SPACE / N = 2^n", 16, PAST),
        _rectangle("past-repertoire-back", [425, 315, 775, 348], PAPER, PAPER, 0),
        _centered("past-repertoire", 600, 339, "rho_T = ( 1/3   1/3   1/3   0 )", 17, PAST),
        _rectangle("past-count-frame", [455, 360, 745, 402], PAST, PAPER, 2),
        _centered("past-count", 600, 389, f"QA(tau=.20) = {past_count}", 18, PAST),
        _rectangle("past-caption-back", [435, 405, 765, 432], PAPER, PAPER, 0),
        _centered("past-caption", 600, 424, "causes converge / alternatives narrow", 13, PAST),
        _rectangle("present-frame", [440, 447, 760, 513], INK, PRESENT, 2),
        _centered("present-title", 600, 473, "PRESENT / EXPLICIT BRIDGE", 12, PRESENT_INK),
        _centered("present-equation", 600, 500, "x1 --iota--> C_t", 19, PRESENT_INK),
        _rectangle("future-caption-back", [440, 526, 760, 553], PAPER, PAPER, 0),
        _centered("future-caption", 600, 545, "forecasts diverge / alternatives open", 13, FUTURE),
        _rectangle("future-count-frame", [455, 562, 745, 604], FUTURE, PAPER, 2),
        _centered("future-count", 600, 591, f"A(tau=.05) = {future_count}", 18, FUTURE),
        _rectangle("future-repertoire-back", [425, 610, 775, 644], PAPER, PAPER, 0),
        _centered("future-repertoire", 600, 634, "P_h = ( .70   .20   .08   .02 )", 17, FUTURE),
        _rectangle("future-title-back", [370, 730, 830, 760], PAPER, PAPER, 0),
        _centered("future-title", 600, 752, "FORECAST FUTURES / O^h / |O|^h PATHS", 16, FUTURE),
        _text("tau-note", [90, 525], "tau increases inward", 12, MUTED),
        _text("filtration-note", [875, 525], "B(tau3) subset B(tau2) subset B(tau1)", 12, MUTED),
    ])

    for label, x in zip(("00", "01", "10", "11"), (390, 530, 670, 810)):
        excluded = label == "11"
        color = EXCLUDED if excluded else PAST
        objects.append(_ellipse(f"past-node-{label}", [x, 257], [9, 9], color, EXCLUDED if excluded else PAPER, 2))
        objects.append(_centered(f"past-state-{label}", x, 287, "x" if excluded else label, 14, color))
        if excluded:
            objects.append(_centered(f"past-label-{label}", x, 305, label, 12, EXCLUDED))
    for label, x in zip(("A", "B", "C", "D"), (390, 530, 670, 810)):
        excluded = label == "D"
        color = MUTED if excluded else FUTURE
        objects.append(_ellipse(f"future-node-{label}", [x, 697], [9, 9], color, PAPER, 2))
        objects.append(_centered(f"future-state-{label}", x, 727, label, 14, color))

    objects.extend([
        _rectangle("evidence-panel", [110, 810, 1090, 902], MUTED, PAPER, 1),
        _centered("evidence-exact", 600, 840, "FULL LABELED THRESHOLD SWEEP => EXACT REPERTOIRE", 16, INK),
        _centered("evidence-contours", 600, 866, "frames = nested accessible sets / clipped ellipses = repertoire contours", 13, MUTED),
        _centered("evidence-finite", 600, 890, "finite grid = approximate contour map / counts without labels lose identity", 13, MUTED),
        _centered("boundary", 600, 934, "VOLUME != Phi != CORRECTNESS != CONSCIOUSNESS", 17, EXCLUDED),
        _centered("zoe-rule", 600, 961, "ZOE: measure + preserve evidence + human review / executed=False", 14, INK),
        _centered("figure-caption", 600, 1003, "Figure Z.01: ZOE_QVOLUME.C Output — The Two-Way Hourglass", 12, INK),
    ])

    scene = Scene.from_dict({
        "schema_version": 1,
        "id": "zoe-artline-hourglass",
        "title": "Zoe · Accessible Q-Volume as a GEM/Artline two-way hourglass",
        "canvas": {"width": 1200, "height": 1040},
        "objects": objects,
        "constraints": [{"type": "inside_canvas", "object": "*"}],
    })
    report = {
        "module": "hourglass",
        "style": "GEM/Artline geometry using the standard VDI palette",
        "past_accessible_q_volume": past_count,
        "future_accessible_volume": future_count,
        "past_threshold": 0.20,
        "future_threshold": 0.05,
        "q_arrows": toy["arrows"],
        "contour_segments": contour_segments,
        "phi_computed": False,
        "consciousness_measured": False,
        "belief_updated": False,
        "executed": False,
        "summary": "Causal pasts converge into the present; forecast futures diverge. One strict threshold ruler measures both without measuring consciousness or authorizing action.",
    }
    return scene, report
