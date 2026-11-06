from __future__ import annotations

from copy import deepcopy

from .forecast import ForecastKernel as BrainKernel
from .onset import load_experiment


class MirroredBrain:
    def __init__(self, minimum=1, maximum=4, onset_loader=load_experiment):
        self.forward = BrainKernel(minimum, maximum, onset_loader)
        self.retrograde = BrainKernel(minimum, maximum, onset_loader)
        self.current = None
        self.history = []
        self.observation_count = 0
        self.evidence_exports = 0

    def recommend(self):
        if self.current is None:
            return {"module": "volume", "action": "observe_pair", "reason": "Observe a matched forward/retrograde pair to establish the mirrored state."}
        current = self.current
        if not current["argmax_agreement"]:
            return {"module": "research", "action": "inspect_disagreement", "reason": "The two directions select different categories; inspect correctness and source distributions before interpreting the pair."}
        if current["volume_delta"]:
            return {"module": "volume", "action": "inspect_difference", "reason": "Accessible volume differs by direction; inspect the threshold and accessible-set membership."}
        if self.evidence_exports == 0:
            return {"module": "research", "action": "preserve", "reason": "Preserve both observations and their matched index before another experiment."}
        return {"module": "horizon", "action": "inspect", "reason": "The mirrored pair is measured; compare a bounded continuation or record another pair."}

    def observe(self, index=None, tau=.05, temperature=1.0, include_history=True):
        if not isinstance(include_history, bool):
            raise ValueError("include_history must be boolean")
        if index is None:
            index = self.forward.onset_positions["forward"]
        forward_state = self.forward.observe_onset("forward", index, tau, temperature)
        retrograde_state = self.retrograde.observe_onset("retrograde", index, tau, temperature)
        forward = forward_state["current"]
        retrograde = retrograde_state["current"]
        self.forward.history.clear()
        self.retrograde.history.clear()
        self.observation_count += 1
        self.current = {
            "observation": self.observation_count,
            "source": "helen.mirror.seed7",
            "condition": "paired-forward-retrograde",
            "index": index,
            "tau": tau,
            "temperature": float(temperature),
            "accessible_volume": {
                "forward": forward["accessible_volume"],
                "retrograde": retrograde["accessible_volume"],
            },
            "complement_volume": {
                "forward": forward["complement_volume"],
                "retrograde": retrograde["complement_volume"],
            },
            "volume_delta": forward["accessible_volume"] - retrograde["accessible_volume"],
            "argmax_agreement": forward["predicted_target"] == retrograde["predicted_target"],
            "forward": forward,
            "retrograde": retrograde,
            "executed": False,
        }
        self.current["recommendation"] = self.recommend()
        self.history.append(deepcopy(self.current))
        if len(self.history) > 128:
            self.history = self.history[-128:]
        return self.state(include_history=include_history)

    def mark_exported(self):
        self.evidence_exports += 1
        if self.current is not None:
            self.current["recommendation"] = self.recommend()
        return self.state()

    def state(self, include_history=True):
        if not isinstance(include_history, bool):
            raise ValueError("include_history must be boolean")
        return {
            "schema_version": 1,
            "instrument": "Zoe mirrored brain",
            "observation_count": self.observation_count,
            "evidence_exports": self.evidence_exports,
            "current": deepcopy(self.current),
            "recommendation": self.recommend(),
            "history": deepcopy(self.history) if include_history else [],
            "history_included": include_history,
            "executed": False,
            "scope": "Paired forward and retrograde evaluation of stored categorical forecasts. This is not a time-reversed model, causal reconstruction, consciousness claim, or automatic action.",
        }


def mirror_scene(brain):
    from .scene_utils import _ellipse, _line, _scene, _text

    state = brain.state()
    current = state["current"]
    objects = [
        {"id": "background", "type": "rectangle", "bounds": [0, 0, 1100, 680], "stroke": "black", "fill": "black", "width": 1},
        _text("title", [36, 43], "ZOE · MIRRORED BRAIN", 25, "cyan"),
        _text("subtitle", [36, 73], "One inspectable pair. Two directions. No hidden averaging.", 14, "lightgray"),
    ]
    for prefix, x, color, title in (("forward", 42, "cyan", "FORWARD"), ("retrograde", 590, "magenta", "RETROGRADE")):
        objects.append({"id": f"panel-{prefix}", "type": "rectangle", "bounds": [x-14, 100, x+466, 486], "stroke": color, "fill": "black", "width": 2})
        objects.append(_text(f"title-{prefix}", [x+14, 135], title, 19, color))
    objects.append(_ellipse("mirror-core", [550, 273], [51, 71], "red", "black", 3))
    objects.append(_text("mirror-label", [528, 265], "ZOE", 18, "red"))
    objects.append(_text("mirror-index", [520, 292], "paired", 12, "lightgray"))
    objects.append(_line("mirror-left", [482, 273], [498, 273], "cyan", 3))
    objects.append(_line("mirror-right", [602, 273], [618, 273], "magenta", 3))
    if current is None:
        objects.append(_text("empty", [42, 527], "Observe a matched pair to measure agreement and volume differences.", 17, "white"))
        summary = "No mirrored observation yet"
    else:
        for prefix, x, color in (("forward", 42, "cyan"), ("retrograde", 590, "magenta")):
            observation = current[prefix]
            objects.append(_text(f"metrics-{prefix}", [x+14, 170], f"A={observation['accessible_volume']}  complement={observation['complement_volume']}  momentum={observation['momentum']}", 14, "white"))
            top1 = "unscored" if observation["top1"] is None else ("correct" if observation["top1"] else "incorrect")
            objects.append(_text(f"correctness-{prefix}", [x+14, 200], f"top-1={top1}  max-p={observation['maximum_probability']:.3f}", 13, color))
            objects.append(_text(f"source-{prefix}", [x+14, 232], f"index={current['index']}  tau={current['tau']:.3f}  T={current['temperature']:.2f}", 12, "lightgray"))
            objects.append(_text(f"prediction-{prefix}", [x+14, 267], f"predicted={observation['predicted_target']}  target={observation['target']}", 13, "white"))
            objects.append(_text(f"entropy-{prefix}", [x+14, 300], f"entropy={observation['entropy']:.3f} bits", 13, "lightgray"))
            objects.append(_text(f"recommendation-{prefix}", [x+14, 337], f"next={observation['recommendation']['module']}", 12, color))
            objects.append(_text(f"condition-{prefix}", [x+14, 370], observation["condition"], 13, color))
            objects.append(_text(f"no-mixture-{prefix}", [x+14, 410], "distribution retained separately", 12, "lightgray"))
        agreement = "same" if current["argmax_agreement"] else "different"
        objects.append(_text("agreement", [42, 527], f"argmax: {agreement}   volume delta (forward - retrograde): {current['volume_delta']:+d}", 17, "white"))
        summary = f"index={current['index']} · argmax {agreement} · forward A={current['accessible_volume']['forward']} · retrograde A={current['accessible_volume']['retrograde']} · delta={current['volume_delta']:+d}"
    objects.append(_text("recommendation", [42, 567], f"Next: {state['recommendation']['module']} · {state['recommendation']['reason']}", 12, "yellow"))
    objects.append(_text("memory", [42, 600], f"{state['observation_count']} mirrored observations · {state['evidence_exports']} exports · both directions preserved", 13, "lightgray"))
    objects.append(_text("scope", [42, 632], "Paired evaluation, not causal reversal or consciousness · executed=False · human decides", 13, "red"))
    objects.append(_text("privacy", [42, 657], "Lazy local HELEN evidence · no model runtime or automatic action", 11, "lightgray"))
    return _scene("gem-mirrored-brain", 1100, 680, objects, "GEM mirrored brain"), {"summary": summary, "state": state, "recommended_module": state["recommendation"]["module"]}


def os_document(module, library_path=None):
    if module == "mirror":
        brain = MirroredBrain()
        brain.observe(0)
        return mirror_scene(brain)
    if module == "library":
        from .library import ManualLibrary, library_scene
        return library_scene(ManualLibrary(library_path))
    if module == "field":
        from .field import FieldNotebook, field_scene
        return field_scene(FieldNotebook.demo())
    raise ValueError(f"unknown GEM OS module: {module}")
