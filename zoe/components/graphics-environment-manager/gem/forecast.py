from __future__ import annotations

from copy import deepcopy

from .measurement import evaluate_outcome, measure_distribution, _numpy
from .onset import load_experiment


class ForecastKernel:
    def __init__(self, minimum=1, maximum=4, onset_loader=load_experiment):
        if minimum < 0 or maximum < minimum:
            raise ValueError("target volume band must satisfy 0 <= minimum <= maximum")
        self.minimum = minimum
        self.maximum = maximum
        self.onset_loader = onset_loader
        self.current = None
        self.previous = None
        self.previous_temperature = None
        self.history = []
        self.observation_count = 0
        self.evidence_exports = 0
        self.onset_positions = {"forward": 0, "retrograde": 0}

    def recommend(self):
        if self.current is None:
            return {"module": "volume", "action": "observe", "reason": "Observe a categorical distribution to establish the first state."}
        if self.current["top1"] is False:
            return {"module": "research", "action": "inspect", "reason": "The top prediction was incorrect; compare breadth and correctness before steering."}
        if self.current["accessible_volume"] < self.minimum or self.current["accessible_volume"] > self.maximum:
            return {"module": "volume", "action": "inspect", "reason": "Accessible volume is outside the target band; inspect the threshold before choosing a next test."}
        if self.evidence_exports == 0:
            return {"module": "research", "action": "preserve", "reason": "Preserve the measured state and its source evidence before the next experiment."}
        return {"module": "horizon", "action": "inspect", "reason": "The current band is measured; explore bounded continuations or record another observation."}

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
        values = _numpy().array(probabilities[index], dtype=float)
        previous = self.previous if self.previous_temperature == temperature else None
        report = measure_distribution(values, [tau], previous=previous)
        sweep = report["threshold_sweep"][0]
        outcome = evaluate_outcome(values, targets[index])
        self.previous = values
        self.previous_temperature = temperature
        self.observation_count += 1
        self.current = {
            "observation": self.observation_count,
            "source": "helen.seed7",
            "condition": condition,
            "index": index,
            "temperature": float(temperature),
            "tau": sweep["tau"],
            "accessible_volume": sweep["accessible_volume"],
            "complement_volume": sweep["complement_volume"],
            "momentum": sweep.get("accessible_momentum"),
            "maximum_probability": report["max_probability"],
            "predicted_target": outcome["top_token_id"],
            "target": targets[index],
            "top1": outcome["correct"],
            "negative_log_probability": outcome["log_loss"],
            "entropy": report["entropy_bits"],
            "target_band": [self.minimum, self.maximum],
            "executed": False,
        }
        self.current["recommendation"] = self.recommend()
        self.history.append(deepcopy(self.current))
        if len(self.history) > 128:
            self.history = self.history[-128:]
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
            "instrument": "GEM forecast observation",
            "observation_count": self.observation_count,
            "evidence_exports": self.evidence_exports,
            "current": deepcopy(self.current),
            "recommendation": self.recommend(),
            "onset_positions": dict(self.onset_positions),
            "history": deepcopy(self.history),
            "executed": False,
            "scope": "Stored categorical measurement and inspection only; no automatic action or universal future prediction.",
        }
