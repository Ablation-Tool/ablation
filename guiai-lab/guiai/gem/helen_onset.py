from __future__ import annotations

from dataclasses import dataclass
import gzip
import json
import math
from importlib import resources


@dataclass(frozen=True)
class OnsetData:
    thresholds: list
    forward: dict
    retrograde: dict
    forward_probabilities: list
    forward_targets: list
    retrograde_probabilities: list
    retrograde_targets: list
    forward_curve: list
    retrograde_curve: list
    deterministic: dict
    hop: dict
    provenance: dict

    def probabilities(self, name, temperature=1.0):
        if name not in {"forward", "retrograde"}:
            raise ValueError("condition must be forward or retrograde")
        if not math.isfinite(temperature) or temperature <= 0:
            raise ValueError("temperature must be positive")
        source = self.forward_probabilities if name == "forward" else self.retrograde_probabilities
        if temperature == 1:
            return source
        transformed = []
        for distribution in source:
            weights = [max(value, 1e-15) ** (1/temperature) for value in distribution]
            total = math.fsum(weights)
            transformed.append([value/total for value in weights])
        return transformed

    def targets(self, name):
        if name not in {"forward", "retrograde"}:
            raise ValueError("condition must be forward or retrograde")
        return self.forward_targets if name == "forward" else self.retrograde_targets

    def accessible_at(self, name, tau, temperature=1.0):
        distributions = self.probabilities(name, temperature)
        return sum(sum(value > tau for value in distribution) for distribution in distributions)/len(distributions)

    def condition(self, name, temperature=1.0):
        if temperature == 1:
            if name == "forward":
                return self.forward, self.forward_curve
            if name == "retrograde":
                return self.retrograde, self.retrograde_curve
            raise ValueError("condition must be forward or retrograde")
        distributions = self.probabilities(name, temperature)
        targets = self.targets(name)
        return _condition_metrics(distributions, targets, self.thresholds)


def _condition_metrics(distributions, targets, thresholds):
    top1 = log_loss = maximum = entropy = 0.0
    for distribution, target in zip(distributions, targets):
        top1 += max(range(len(distribution)), key=distribution.__getitem__) == target
        log_loss -= math.log(distribution[target]+1e-15)
        maximum += max(distribution)
        entropy -= sum(value*math.log(value+1e-15) for value in distribution)
    count = len(distributions)
    curve = [sum(sum(value > tau for value in distribution) for distribution in distributions)/count for tau in thresholds]
    area = sum((curve[index]+curve[index+1])*(thresholds[index+1]-thresholds[index])/2 for index in range(len(thresholds)-1))
    return {
        "observations": count,
        "top1": top1/count,
        "log_loss": log_loss/count,
        "mean_max_probability": maximum/count,
        "predictive_entropy": entropy/count,
        "mean_accessible_volume": sum(curve)/len(curve),
        "sweep_area": area,
        "accessible_at_0_05": sum(sum(value > .05 for value in distribution) for distribution in distributions)/count,
    }, curve


_CACHE = None


def load_experiment():
    global _CACHE
    if _CACHE is None:
        resource = resources.files("guiai.gem").joinpath("data/onset-seed7.json.gz")
        with resource.open("rb") as stream:
            document = json.loads(gzip.decompress(stream.read()).decode("utf-8"))
        if document.get("schema_version") != 1:
            raise ValueError("unsupported HELEN onset artifact")
        _CACHE = OnsetData(**document["payload"])
    return _CACHE
