from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import time

DEFAULT_THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)
MAX_VOCABULARY_SIZE = 5_000_000


def _validate_tau(tau):
    tau = float(tau)
    if not math.isfinite(tau) or not 0.0 <= tau <= 1.0:
        raise ValueError("tau must be a finite probability between 0 and 1")
    return tau


def _validate_probabilities(values):
    probabilities = [float(value) for value in values]
    if not probabilities:
        raise ValueError("probability distribution is empty")
    if len(probabilities) > MAX_VOCABULARY_SIZE:
        raise ValueError("probability distribution exceeds the vocabulary limit")
    if any(not math.isfinite(value) or value < 0 for value in probabilities):
        raise ValueError("probabilities must be finite and nonnegative")
    total = sum(probabilities)
    if not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-8):
        raise ValueError(f"probability distribution sums to {total}, not 1")
    return probabilities


def accessible_volume(probabilities, tau):
    probabilities = _validate_probabilities(probabilities)
    tau = _validate_tau(tau)
    return sum(value > tau for value in probabilities)


def accessible_momentum(current_volume, previous_volume):
    return int(current_volume) - int(previous_volume)


def steering_action(current_volume, momentum, minimum, maximum):
    if minimum < 0 or maximum < minimum:
        raise ValueError("target volume band must satisfy 0 <= minimum <= maximum")
    if current_volume < minimum:
        return "let_breadth_grow" if momentum > 0 else "broaden_context"
    if current_volume > maximum:
        return "let_breadth_settle" if momentum < 0 else "narrow_context"
    return "continue"


def measure_probabilities(probabilities, thresholds=DEFAULT_THRESHOLDS, previous=None, minimum=1, maximum=4):
    probabilities = _validate_probabilities(probabilities)
    previous = _validate_probabilities(previous) if previous is not None else None
    if minimum < 0 or maximum < minimum:
        raise ValueError("target volume band must satisfy 0 <= minimum <= maximum")
    ordered = sorted(range(len(probabilities)), key=lambda index: probabilities[index], reverse=True)
    report = {
        "schema_version": 1,
        "instrument": "accessible_volume",
        "equation": "A_tau(S) = sum_{a in O} 1[P(a | h_T(S)) > tau]",
        "vocabulary_size": len(probabilities),
        "probability_sum": sum(probabilities),
        "top_candidates": [
            {"token_id": index, "probability": probabilities[index]}
            for index in ordered[:10]
        ],
        "threshold_sweep": [],
        "scope": [
            "Token-level distribution shape only; not correctness, safety, or an automatic action.",
            "Steering suggestions require a previous distribution and use the experimental momentum rule.",
        ],
    }
    for threshold in thresholds:
        tau = _validate_tau(threshold)
        current = sum(value > tau for value in probabilities)
        entry = {
            "tau": tau,
            "accessible_volume": current,
            "normalized_accessible_volume": current / len(probabilities),
            "complement_volume": len(probabilities) - current,
            "normalized_complement_volume": 1 - current / len(probabilities),
        }
        if previous is not None:
            previous_count = sum(value > tau for value in previous)
            momentum = accessible_momentum(current, previous_count)
            entry.update({
                "previous_accessible_volume": previous_count,
                "accessible_momentum": momentum,
                "suggested_action": steering_action(current, momentum, minimum, maximum),
            })
        report["threshold_sweep"].append(entry)
    if previous is not None:
        report["steering"] = {
            "equation": "M_tau(t) = A_tau(S_t) - A_tau(S_{t-1})",
            "target_volume_band": [minimum, maximum],
            "status": "experimental_recommendation_only",
        }
    return report


class VolumeBridge:
    """Bidirectional adapter for stateful accessible-volume feedback."""

    def __init__(self, minimum=1, maximum=4):
        if minimum < 0 or maximum < minimum:
            raise ValueError("target volume band must satisfy 0 <= minimum <= maximum")
        self.minimum = minimum
        self.maximum = maximum
        self._previous = None

    def observe(self, probabilities, thresholds=DEFAULT_THRESHOLDS):
        report = measure_probabilities(
            probabilities,
            thresholds=thresholds,
            previous=self._previous,
            minimum=self.minimum,
            maximum=self.maximum,
        )
        self._previous = _validate_probabilities(probabilities)
        return report


def _load_npz(path, key):
    try:
        import numpy as np
    except ImportError as error:
        raise ValueError("NumPy is required to read NPZ probability artifacts") from error
    path = Path(path).expanduser().resolve()
    with np.load(path) as artifact:
        if key not in artifact:
            raise ValueError(f"NPZ artifact does not contain {key!r}")
        probabilities = artifact[key]
    return probabilities, {
        "file": path.name,
        "key": key,
        "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "probability_values_sha256": hashlib.sha256(probabilities.tobytes()).hexdigest(),
    }


def measure_artifact(path, key="probabilities", previous_path=None, previous_key=None,
                     thresholds=DEFAULT_THRESHOLDS, minimum=1, maximum=4):
    started = time.monotonic()
    probabilities, source = _load_npz(path, key)
    previous = None
    if previous_path is not None:
        previous_values, previous = _load_npz(previous_path, previous_key or key)
        previous_values = _validate_probabilities(previous_values)
    else:
        previous_values = None
    report = measure_probabilities(
        probabilities,
        thresholds=thresholds,
        previous=previous_values,
        minimum=minimum,
        maximum=maximum,
    )
    report["source"] = source
    if previous is not None:
        report["previous_source"] = previous
    report["time"] = {
        "observed_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
    }
    return report


def write_report(report, output):
    output = Path(output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return output
