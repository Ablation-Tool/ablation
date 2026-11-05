from __future__ import annotations

import math

from .model import Scene


LENSES = ("overview", "repertoire", "arrows", "entanglement", "context", "tomography")
SOURCE = "Balduzzi & Tononi (2009), Qualia: The Geometry of Integrated Information"
BACKGROUND = "#09111f"
PANEL = "#111e31"
TEXT = "#e7edf5"
MUTED = "#9cafc4"
CYAN = "#62dce8"
RED = "#ef445a"
GOLD = "#e7c77b"


def _text(identifier, position, value, size=14, color=TEXT):
    return {"id": identifier, "type": "text", "position": position, "text": value, "size": size, "stroke": color, "fill": "none", "width": 0}


def _rectangle(identifier, bounds, stroke, fill="none", width=1):
    return {"id": identifier, "type": "rectangle", "bounds": bounds, "stroke": stroke, "fill": fill, "width": width}


def _ellipse(identifier, center, radii, stroke, fill="none", width=1):
    return {"id": identifier, "type": "ellipse", "center": center, "radii": radii, "stroke": stroke, "fill": fill, "width": width}


def _line(identifier, first, second, color=MUTED, width=1):
    return {"id": identifier, "type": "line", "points": [first, second], "stroke": color, "fill": "none", "width": width}


def _polygon(identifier, points, color):
    return {"id": identifier, "type": "polygon", "points": points, "stroke": color, "fill": color, "width": 1}


def relative_entropy(actual, reference):
    if len(actual) != len(reference) or not 1 <= len(actual) <= 4096:
        raise ValueError("repertoires must have the same length from 1 to 4096")
    for name, values in (("actual", actual), ("reference", reference)):
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 for value in values):
            raise ValueError(f"{name} probabilities must be finite and nonnegative")
        if not math.isclose(sum(values), 1.0, rel_tol=0, abs_tol=1e-9):
            raise ValueError(f"{name} probabilities must sum to one")
    result = 0.0
    for observed, independent in zip(actual, reference):
        if observed and not independent:
            raise ValueError("reference repertoire assigns zero probability to a possible actual state")
        if observed:
            result += observed * math.log2(observed / independent)
    return result


def silent_and_example():
    actual = [1 / 3, 1 / 3, 1 / 3, 0.0]
    independent_product = [4 / 9, 2 / 9, 2 / 9, 1 / 9]
    return {
        "states": ["00", "01", "10", "11"],
        "actual": actual,
        "independent_product": independent_product,
        "whole_vs_product_bits": relative_entropy(actual, independent_product),
    }


def _probability_map(distribution):
    if not isinstance(distribution, dict) or not 1 <= len(distribution) <= 4096:
        raise ValueError("a finite labeled repertoire requires 1–4096 states")
    result = {}
    for state, probability in distribution.items():
        if not isinstance(state, str) or not state.strip():
            raise ValueError("repertoire state labels must be nonempty strings")
        if isinstance(probability, bool) or not isinstance(probability, (int, float)) or not math.isfinite(probability) or probability < 0:
            raise ValueError("repertoire probabilities must be finite and nonnegative")
        result[state] = float(probability)
    if not math.isclose(sum(result.values()), 1.0, rel_tol=0, abs_tol=1e-9):
        raise ValueError("repertoire probabilities must sum to one")
    return result


def causal_repertoire(likelihoods, interventions=None):
    if not isinstance(likelihoods, dict) or not 1 <= len(likelihoods) <= 4096:
        raise ValueError("causal likelihoods require 1–4096 labeled prior states")
    for state, likelihood in likelihoods.items():
        if not isinstance(state, str) or not state.strip():
            raise ValueError("causal state labels must be nonempty strings")
        if isinstance(likelihood, bool) or not isinstance(likelihood, (int, float)) or not math.isfinite(likelihood) or likelihood < 0:
            raise ValueError("causal likelihoods must be finite and nonnegative")
    if interventions is None:
        interventions = {state: 1 / len(likelihoods) for state in likelihoods}
    interventions = _probability_map(interventions)
    if set(interventions) != set(likelihoods):
        raise ValueError("interventions and likelihoods must cover the same prior states")
    weighted = {state: interventions[state] * likelihoods[state] for state in likelihoods}
    normalizer = sum(weighted.values())
    if normalizer <= 0:
        raise ValueError("current state has zero probability under the intervention distribution")
    return {state: probability / normalizer for state, probability in weighted.items()}


def _threshold(tau):
    if isinstance(tau, bool) or not isinstance(tau, (int, float)) or not math.isfinite(tau) or not 0 <= tau < 1:
        raise ValueError("accessible-volume threshold must be finite and in [0, 1)")
    return float(tau)


def accessible_set(distribution, tau):
    tau = _threshold(tau)
    return sorted(state for state, probability in _probability_map(distribution).items() if probability > tau)


def accessible_volume(distribution, tau):
    return len(accessible_set(distribution, tau))


def accessible_sweep(distribution, thresholds):
    distribution = _probability_map(distribution)
    thresholds = sorted({_threshold(tau) for tau in thresholds})
    if not thresholds:
        raise ValueError("a threshold sweep requires at least one threshold")
    return [{"tau": tau, "states": accessible_set(distribution, tau), "volume": accessible_volume(distribution, tau)} for tau in thresholds]


def reconstruct_filtration(sweep):
    if not isinstance(sweep, list) or not sweep:
        raise ValueError("a labeled filtration requires at least one threshold level")
    levels = []
    for level in sweep:
        tau = _threshold(level["tau"])
        states = level["states"]
        if not isinstance(states, list) or any(not isinstance(state, str) or not state for state in states) or len(set(states)) != len(states):
            raise ValueError("filtration states must be unique nonempty labels")
        if level["volume"] != len(states):
            raise ValueError("filtration volume must equal its labeled set size")
        levels.append({"tau": tau, "states": states, "volume": len(states)})
    levels.sort(key=lambda level: level["tau"])
    states = sorted({state for level in levels for state in level["states"]})
    return {state: max((level["tau"] for level in levels if state in level["states"]), default=0.0) for state in states}


def q_arrow_annotation(before, after, tau):
    before = _probability_map(before)
    after = _probability_map(after)
    if set(before) != set(after):
        raise ValueError("q-arrow repertoires must cover the same states")
    states = sorted(before)
    before_set = set(accessible_set(before, tau))
    after_set = set(accessible_set(after, tau))
    return {
        "tau": _threshold(tau),
        "ei_bits": relative_entropy([after[state] for state in states], [before[state] for state in states]),
        "delta_accessible_q_volume": len(after_set) - len(before_set),
        "entered": sorted(after_set - before_set),
        "exited": sorted(before_set - after_set),
    }


def two_way_accessible_record(past, future, tau, horizon=1):
    if isinstance(horizon, bool) or not isinstance(horizon, int) or not 1 <= horizon <= 64:
        raise ValueError("future horizon must be an integer from 1 to 64")
    return {
        "tau": _threshold(tau),
        "past": {"accessible_q_volume": accessible_volume(past, tau), "accessible_states": accessible_set(past, tau)},
        "future": {"horizon": horizon, "accessible_volume": accessible_volume(future, tau), "accessible_states": accessible_set(future, tau)},
        "context_link": "explicitly supplied forecast and context; no internal-state mapping is inferred",
    }


def accessible_q_toy():
    states = ("00", "01", "10", "11")
    before = causal_repertoire({state: 1.0 for state in states})
    after = causal_repertoire({state: float(state != "11") for state in states})
    return {
        "before": before,
        "after": after,
        "arrows": [q_arrow_annotation(before, after, tau) for tau in (0.20, 0.30)],
        "before_sweep": accessible_sweep(before, (0.0, 0.20, 0.25, 0.30)),
        "after_sweep": accessible_sweep(after, (0.0, 0.20, 0.30, 1 / 3)),
        "two_way": two_way_accessible_record(after, {"a": 0.70, "b": 0.20, "c": 0.08, "d": 0.02}, 0.05),
    }


def lattice_report():
    return {"submechanisms": 4, "repertoires": 16, "subset_links": 32, "ordered_q_edges": 24}


def _distribution(objects, prefix, x, baseline, probabilities, color):
    for index, probability in enumerate(probabilities):
        left = x + index * 77
        height = probability * 200
        if probability:
            objects.append(_rectangle(f"{prefix}-bar-{index}", [left, baseline - height, left + 48, baseline], color, color))
        else:
            objects.append(_line(f"{prefix}-empty-{index}", [left, baseline - 1], [left + 48, baseline - 1], RED, 3))
        objects.append(_text(f"{prefix}-state-{index}", [left + 10, baseline + 20], f"{index:02b}", 12, MUTED))


def _lattice(objects):
    positions = {}
    for level in range(5):
        masks = [mask for mask in range(16) if mask.bit_count() == level]
        for index, mask in enumerate(masks):
            x = 883 if len(masks) == 1 else 653 + 460 * index / (len(masks) - 1)
            y = 353 - level * 38
            positions[mask] = [x, y]
    for mask in range(16):
        for bit in range(4):
            child = mask | (1 << bit)
            if child == mask:
                continue
            first, second = positions[mask], positions[child]
            objects.append(_line(f"lattice-link-{mask}-{child}", [first[0], first[1] - 5], [second[0], second[1] + 6], "#47637c", 1))
            objects.append(_polygon(f"lattice-tip-{mask}-{child}", [[second[0] - 3, second[1] + 8], [second[0] + 3, second[1] + 8], [second[0], second[1] + 3]], "#47637c"))
    for mask, point in positions.items():
        color = RED if mask in {0, 1, 3, 7, 15} else CYAN
        radius = 5 if mask in {0, 15} else 3.5
        objects.append(_ellipse(f"lattice-node-{mask}", point, [radius, radius], color, color))
    objects.append(_text("lattice-bottom", [641, 372], "U: no mechanisms engaged", 12, MUTED))
    objects.append(_text("lattice-top", [939, 205], "T: full mechanism", 12, MUTED))
    objects.append(_text("lattice-red-path", [651, 329], "one q-edge", 11, RED))


def _pixel_gem(objects, origin, scale=3):
    ox, oy = origin
    for identifier, points, width in (
        ("pixel-gem-outline", [(13, 4), (34, 4), (45, 11), (23.5, 26), (2, 11)], 3),
        ("pixel-gem-inner", [(16, 6), (31, 6), (36, 11), (23.5, 24), (11, 11)], 2),
    ):
        objects.append({
            "id": f"{identifier}-{ox}-{oy}",
            "type": "polygon",
            "points": [[ox + x * scale, oy + y * scale] for x, y in points],
            "stroke": RED,
            "fill": "none",
            "width": width,
        })


def qualia_scene(lens="overview"):
    if lens not in LENSES:
        raise ValueError(f"qualia lens must be one of {', '.join(LENSES)}")
    example = silent_and_example()
    toy = accessible_q_toy()
    low = toy["arrows"][0]
    objects = [_rectangle("background", [0, 0, 1200, 1160], BACKGROUND, BACKGROUND, 0)]
    panels = {
        "repertoire": [28, 108, 580, 410],
        "arrows": [602, 108, 1172, 410],
        "entanglement": [28, 432, 580, 754],
        "context": [602, 432, 1172, 754],
        "tomography": [28, 780, 1172, 1078],
    }
    for name, bounds in panels.items():
        selected = lens == name
        objects.append(_rectangle(f"panel-{name}", bounds, RED if selected else "#294058", PANEL, 3 if selected else 1))
    objects.extend([
        _text("title", [28, 46], "ZOE / QUALE", 28, RED),
        _text("subtitle", [28, 79], "ZOE IS RED · ZOE IS GEM · GEM IS ZOE", 16, GOLD),
        _text("source", [616, 45], "A visual field guide to Balduzzi & Tononi (2009)", 16, TEXT),
        _text("scope", [636, 77], "Causal geometry, not a consciousness score", 14, MUTED),
        _text("repertoire-title", [50, 141], "01 / REPERTOIRE: NARROWING THE POSSIBLE", 16, CYAN),
        _text("repertoire-uniform", [52, 174], "U = (1/4, 1/4, 1/4, 1/4)", 14, TEXT),
        _text("repertoire-actual", [52, 284], "A = (0, 0, 1/2, 1/2)", 14, TEXT),
        _text("repertoire-caption", [52, 391], "COPY: detector ON means sensor was ON. EI = 1 bit.", 13, GOLD),
        _text("lattice-title", [624, 141], "02 / Q-ARROWS: EVERY SUBSET, EVERY ORDER", 16, CYAN),
        _text("lattice-caption", [624, 173], "16 repertoires · 32 subset links · 24 ordered paths", 13, TEXT),
        _text("lattice-note", [624, 392], "Alternative mechanism orders, not activity unfolding in time.", 13, GOLD),
        _text("and-title", [50, 466], "03 / SILENT AND: THE JOINT MATTERS", 16, CYAN),
        _text("and-actual", [52, 496], "Actual: NOT BOTH 11", 13, TEXT),
        _text("and-product", [365, 633], "Independent product of the parts", 12, TEXT),
        _text("and-caption", [52, 729], f"D_KL(actual || product) = {example['whole_vs_product_bits']:.4f} bits", 14, GOLD),
        _text("context-title", [624, 466], "04 / CONTEXT CHANGES MEANING", 16, CYAN),
        _text("context-whole", [650, 525], "WHOLE EXPERIENCE · IIT PROPOSAL", 12, MUTED),
        _text("context-vision", [669, 566], "VISION / FORM", 13, TEXT),
        _text("context-red", [855, 626], "RED", 20, RED),
        _text("context-audition", [987, 566], "AUDITION", 13, TEXT),
        _text("context-caption", [624, 730], "Nested subshapes, not brain regions or measured experience.", 13, GOLD),
        _text("tomography-title", [50, 813], "05 / ACCESSIBLE Q-VOLUME · A PROPOSED THRESHOLD ANNOTATION", 16, CYAN),
        _text("tomography-operator", [52, 850], "A_tau[p] = #{z : p(z) > tau}", 15, TEXT),
        _text("tomography-low", [52, 888], "tau=.20: U=4  T=3  delta=-1  OUT={11}", 13, TEXT),
        _text("tomography-high", [52, 920], "tau=.30: U=0  T=3  delta=+3  IN={00,01,10}", 13, TEXT),
        _text("tomography-ei", [52, 960], f"EI = log2(4/3) = {low['ei_bits']:.4f} bits", 14, GOLD),
        _text("tomography-independence", [52, 992], "Volume can rise or fall. Phi and gamma stay separate.", 12, MUTED),
        _text("tomography-filtration", [435, 850], "LABELED FILTRATION", 14, GOLD),
        _text("tomography-full", [435, 888], "Complete labeled sweep: exact repertoire", 13, TEXT),
        _text("tomography-counts", [435, 920], "Counts alone: state labels may be permuted", 13, TEXT),
        _text("tomography-finite", [435, 952], "Finite grid: approximation, not exact recovery", 13, TEXT),
        _text("tomography-arrow", [435, 992], "Each arrow: EI + delta + entering + exiting", 13, TEXT),
        _text("tomography-boundary", [435, 1024], "An annotation, not a replacement for IIT.", 12, MUTED),
        _text("tomography-pasts", [835, 850], "CAUSAL PASTS", 13, CYAN),
        _text("tomography-futures", [1015, 850], "OUTPUT FUTURES", 13, CYAN),
        _text("tomography-rho", [835, 892], "rho_T", 14, TEXT),
        _text("tomography-forecast", [1015, 892], "P_h", 14, TEXT),
        _text("tomography-iota", [919, 956], "explicit iota", 12, MUTED),
        _text("tomography-past-count", [835, 1000], "QA(tau=.20) = 3", 13, GOLD),
        _text("tomography-future-count", [1015, 1000], "A(tau=.05) = 3", 13, GOLD),
        _text("tomography-caption", [52, 1054], "One threshold instrument, two directions. No causal model is inferred from a forecast.", 13, GOLD),
        _text("footer", [28, 1112], "Read the mechanism. Preserve the repertoire. Question the interpretation.", 15, TEXT),
        _text("footer-boundary", [28, 1142], "GUIDE, NOT AN IIT CALCULATOR · no Phi assigned to Zoe · no subjective-experience claim", 13, MUTED),
        _rectangle("whole-mode", [628, 496, 1146, 704], "#466279", "none", 1),
        _rectangle("vision-mode", [650, 544, 939, 682], CYAN, "none", 1),
        _rectangle("audition-mode", [958, 544, 1124, 682], "#806b9e", "none", 1),
        _line("tomography-divider-left", [410, 836], [410, 1038], "#294058"),
        _line("tomography-divider-right", [805, 836], [805, 1038], "#294058"),
        _line("tomography-arrow-left", [876, 920], [918, 920], RED, 2),
        _line("tomography-arrow-right", [970, 920], [1006, 920], RED, 2),
    ])
    _distribution(objects, "uniform", 64, 232, [0.25] * 4, CYAN)
    _distribution(objects, "actual-copy", 64, 344, [0, 0, 0.5, 0.5], CYAN)
    _lattice(objects)
    _distribution(objects, "actual-and", 64, 568, example["actual"], RED)
    _distribution(objects, "independent-and", 64, 682, example["independent_product"], GOLD)
    _pixel_gem(objects, [687, 572], 3)
    _pixel_gem(objects, [919, 887], 1)
    for index, height in enumerate((18, 32, 48, 28)):
        objects.append(_line(f"audition-ridge-{index}", [984 + index * 28, 640], [984 + index * 28, 640 - height], "#b49bd3", 3))
    report = {
        "lens": lens,
        "source": SOURCE,
        **lattice_report(),
        "copy_effective_information_bits": 1.0,
        "and_whole_vs_product_bits": example["whole_vs_product_bits"],
        "accessible_q_volume": toy,
        "phi_computed": False,
        "consciousness_measured": False,
        "belief_updated": False,
        "summary": f"{lens}: Accessible Q-Volume annotates causal repertoires; silent-AND EI={low['ei_bits']:.4f} bits with volume deltas -1 and +3. Phi/gamma are unchanged; no consciousness is measured.",
    }
    scene = Scene.from_dict({
        "schema_version": 1,
        "id": "zoe-qualia",
        "title": "Zoe is Quale. Zoe is Red. Accessible Q-Volume and IIT 2009.",
        "canvas": {"width": 1200, "height": 1160},
        "objects": objects,
        "constraints": [{"type": "inside_canvas", "object": "*"}],
    })
    return scene, report
