from __future__ import annotations

from copy import deepcopy
import math

from .helen_onset import load_experiment
from .volume import VolumeBridge


class BrainKernel:
    def __init__(self, minimum=1, maximum=4, onset_loader=load_experiment):
        if minimum < 0 or maximum < minimum:
            raise ValueError("target volume band must satisfy 0 <= minimum <= maximum")
        self.minimum = minimum
        self.maximum = maximum
        self.onset_loader = onset_loader
        self.volume_bridge = VolumeBridge(minimum=minimum, maximum=maximum)
        self.current = None
        self.history = []
        self.observation_count = 0
        self.evidence_exports = 0
        self.onset_positions = {"forward": 0, "retrograde": 0}

    def recommend(self):
        if self.current is None:
            return {"module": "volume", "action": "observe", "reason": "Observe a categorical distribution to establish the first state."}
        volume = self.current["accessible_volume"]
        if volume < self.minimum or volume > self.maximum:
            return {"module": "volume", "action": "inspect", "reason": f"Accessible volume {volume} is outside the target band [{self.minimum}, {self.maximum}]."}
        if self.current.get("top1") is False:
            return {"module": "research", "action": "inspect", "reason": "The top prediction was incorrect; compare breadth and correctness before steering."}
        if self.evidence_exports == 0:
            return {"module": "research", "action": "preserve", "reason": "Preserve the measured state and its source evidence before the next experiment."}
        return {"module": "horizon", "action": "inspect", "reason": "The current band is measured; explore bounded continuations or record another observation."}

    def observe(self, probabilities, tau=.05, target=None, source="categorical", condition=None, index=None, temperature=1.0):
        self.volume_bridge.minimum = self.minimum
        self.volume_bridge.maximum = self.maximum
        report = self.volume_bridge.observe(probabilities, thresholds=[tau])
        values = [float(value) for value in probabilities]
        sweep = report["threshold_sweep"][0]
        if target is not None:
            if isinstance(target, bool) or not isinstance(target, int) or not 0 <= target < len(values):
                raise ValueError("target must be a valid categorical index")
        predicted = max(range(len(values)), key=values.__getitem__)
        self.observation_count += 1
        self.current = {
            "observation": self.observation_count,
            "source": source,
            "condition": condition,
            "index": index,
            "temperature": float(temperature),
            "tau": sweep["tau"],
            "accessible_volume": sweep["accessible_volume"],
            "complement_volume": sweep["complement_volume"],
            "momentum": sweep.get("accessible_momentum"),
            "maximum_probability": values[predicted],
            "predicted_target": predicted,
            "target": target,
            "top1": None if target is None else predicted == target,
            "negative_log_probability": None if target is None else -math.log(values[target] + 1e-15),
            "entropy": -sum(value * math.log(value + 1e-15) for value in values),
            "target_band": [self.minimum, self.maximum],
            "executed": False,
        }
        self.current["recommendation"] = self.recommend()
        self.history.append(deepcopy(self.current))
        if len(self.history) > 128:
            self.history = self.history[-128:]
        return self.state()

    def observe_onset(self, condition="forward", index=None, tau=.05, temperature=1.0):
        data = self.onset_loader()
        if index is None:
            index = self.onset_positions[condition]
        if isinstance(index, bool) or not isinstance(index, int):
            raise ValueError("onset index must be an integer")
        probabilities = data.probabilities(condition, temperature)
        targets = data.targets(condition)
        if not 0 <= index < len(probabilities):
            raise ValueError(f"onset index must be between 0 and {len(probabilities)-1}")
        self.observe(
            probabilities[index], tau=tau, target=targets[index],
            source="helen.seed7", condition=condition, index=index, temperature=temperature,
        )
        self.onset_positions[condition] = (index + 1) % len(probabilities)
        return self.state()

    def mark_exported(self):
        self.evidence_exports += 1
        if self.current is not None:
            self.current["recommendation"] = self.recommend()
        return self.state()

    def state(self):
        return {
            "schema_version": 1,
            "instrument": "Zoe",
            "observation_count": self.observation_count,
            "evidence_exports": self.evidence_exports,
            "current": deepcopy(self.current),
            "recommendation": self.recommend(),
            "onset_positions": dict(self.onset_positions),
            "history": deepcopy(self.history),
            "executed": False,
            "scope": "Experimental observation and recommendation only; no automatic action or universal future prediction.",
        }


def _unit_distribution(weights):
    if not weights:
        raise ValueError("distribution cannot be empty")
    result = {str(token): float(value) for token, value in weights.items()}
    if any(not math.isfinite(value) or value < 0 for value in result.values()):
        raise ValueError("probabilities must be finite and nonnegative")
    if not math.isclose(sum(result.values()), 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError("conditional probabilities must sum to one")
    return result


def enumerate_markov_continuations(horizon, initial, transitions):
    if isinstance(horizon, bool) or not isinstance(horizon, int) or not 1 <= horizon <= 8:
        raise ValueError("horizon must be an integer from 1 to 8")
    initial = _unit_distribution(initial)
    transitions = {token: _unit_distribution(weights) for token, weights in transitions.items()}
    if set(initial) != set(transitions):
        raise ValueError("initial and transition vocabularies must match")
    sequences = {(token,): probability for token, probability in initial.items()}
    for _ in range(1, horizon):
        following = {}
        for sequence, probability in sequences.items():
            for token, conditional in transitions[sequence[-1]].items():
                following[sequence + (token,)] = probability * conditional
        sequences = following
    return sequences


def multi_horizon_measure(sequences, tau):
    if not sequences:
        raise ValueError("continuation set cannot be empty")
    if not math.isfinite(tau) or not 0 <= tau <= 1:
        raise ValueError("tau must be between zero and one")
    if not math.isclose(sum(sequences.values()), 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError("complete continuation probabilities must sum to one")
    accessible = sum(probability > tau for probability in sequences.values())
    total = len(sequences)
    ordered = sorted(sequences.items(), key=lambda item: (-item[1], item[0]))
    return {
        "horizon": len(next(iter(sequences))),
        "tau": tau,
        "universe_size": total,
        "accessible_volume": accessible,
        "complement_volume": total-accessible,
        "exact": True,
        "continuations": [
            {"sequence": list(sequence), "probability": probability, "accessible": probability > tau}
            for sequence, probability in ordered
        ],
    }


def toy_horizon(horizon=3, tau=.1):
    sequences = enumerate_markov_continuations(
        horizon,
        {"A": .6, "B": .4},
        {"A": {"A": .7, "B": .3}, "B": {"A": .4, "B": .6}},
    )
    return multi_horizon_measure(sequences, tau)


def brain_scene(kernel):
    from .atlas import _ellipse, _line, _scene, _text

    state = kernel.state()
    current = state["current"]
    recommended = state["recommendation"]["module"]
    objects = [
        {"id": "background", "type": "rectangle", "bounds": [0, 0, 1000, 620], "stroke": "#070b14", "fill": "#070b14", "width": 1},
        _text("title", [36, 38], "Zoe · living geometry, inspectable futures", 24, "#22d3ee"),
    ]
    center = [500, 275]
    nodes = {
        "procrustes": ("GEOMETRY", [175, 145], "#c4b5fd"),
        "volume": ("FORECAST", [500, 105], "#67e8f9"),
        "onset": ("RHYTHM", [825, 145], "#86efac"),
        "horizon": ("MULTI-HORIZON", [210, 455], "#fdba74"),
        "research": ("EVIDENCE", [790, 455], "#fde68a"),
    }
    for identifier, (label, position, color) in nodes.items():
        active = identifier == recommended
        objects.append(_line(f"link-{identifier}", center, position, color, 3 if active else 1))
        objects.append({"id": f"panel-{identifier}", "type": "rectangle", "bounds": [position[0]-125, position[1]-42, position[0]+125, position[1]+42], "stroke": "#f8fafc" if active else color, "fill": "#17243a", "width": 4 if active else 2})
        objects.append(_text(f"label-{identifier}", [position[0]-108, position[1]-5], label, 15, color))
        status = "RECOMMENDED" if active else "available"
        objects.append(_text(f"status-{identifier}", [position[0]-108, position[1]+21], status, 11, color))
    objects.append(_ellipse("brain-core", center, [145, 82], "#67e8f9", "#102a3a", 4))
    objects.append(_text("brain-label", [435, 263], "BRAIN", 30, "#e5eefb"))
    objects.append(_text("brain-observations", [415, 296], f"{state['observation_count']} observations", 16, "#67e8f9"))
    if current is None:
        summary = "No observation yet · select Forecast or Onset to begin"
    else:
        top1 = "unscored" if current["top1"] is None else ("correct" if current["top1"] else "incorrect")
        summary = (
            f"A={current['accessible_volume']}  complement={current['complement_volume']}  "
            f"momentum={current['momentum']}  top-1={top1}  max-p={current['maximum_probability']:.3f}"
        )
    objects.append(_text("state", [80, 540], summary, 16, "#e5eefb"))
    objects.append(_text("recommendation", [80, 570], f"Next: {recommended} · {state['recommendation']['reason']}", 12, "#fde68a"))
    objects.append(_text("scope", [80, 594], "executed=False · breadth is not correctness · human decides", 12, "#fca5a5"))
    scene = _scene("atlas-brain", 1000, 620, objects, "Zoe orchestration")
    return scene, {"summary": summary, "state": state, "recommended_module": recommended}


def horizon_scene(horizon=3, tau=.1):
    from .atlas import _scene, _text

    report = toy_horizon(horizon, tau)
    objects = [
        {"id": "background", "type": "rectangle", "bounds": [0, 0, 940, 550], "stroke": "#070b14", "fill": "#070b14", "width": 1},
        _text("title", [36, 38], "MULTI-HORIZON · exact toy continuations", 22, "#fdba74"),
        _text("definition", [36, 70], "A(h),τ = Σ 1[P(a₁:ₕ | Cₜ) > τ] over the complete defined toy vocabulary", 13, "#9fb1c8"),
        _text("count", [36, 112], f"h={horizon}  τ={tau:.3f}  A={report['accessible_volume']}  complement={report['complement_volume']}  universe={report['universe_size']}", 18, "#e5eefb"),
    ]
    for index, continuation in enumerate(report["continuations"][:10]):
        sequence = " ".join(continuation["sequence"])
        color = "#86efac" if continuation["accessible"] else "#7d90aa"
        objects.append(_text(f"continuation-{index}", [48, 155+index*31], f"{sequence:<12} p={continuation['probability']:.6f}  {'ACCESSIBLE' if continuation['accessible'] else 'below τ'}", 15, color))
    objects.append(_text("scope", [36, 492], "Exact toy Markov enumeration only · not a real language-model benchmark", 13, "#fca5a5"))
    objects.append(_text("cost", [36, 522], "Full vocabulary enumeration grows as |O|ʰ · bounded counts require explicit approximation labels", 12, "#9fb1c8"))
    return _scene("atlas-horizon", 940, 550, objects, "Multi-horizon accessible volume"), report
