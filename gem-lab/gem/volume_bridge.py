import hashlib
import json
from pathlib import Path
import time

from .accessible_volume import (
    THRESHOLDS,
    accessible_momentum,
    accessible_volume,
    complementary_volume,
    latest_measurement,
    momentum_guidance,
    normalized_thresholds,
    threshold_name,
)
from .events import atomic_write, sha256, utc_now


class VolumeBridge:
    def __init__(self, session=None):
        self.session = session
        self.output = session.root / "accessible-volume" if session else Path.cwd() / "accessible-volume"
        self.output.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def load_distribution(path, key="probabilities"):
        import numpy as np

        path = Path(path).expanduser().resolve(strict=True)
        with np.load(path, allow_pickle=False) as artifact:
            if key not in artifact:
                raise ValueError(f"NPZ artifact does not contain {key!r}")
            probabilities = artifact[key]
            ids = artifact["input_ids"] if "input_ids" in artifact else np.arange(len(probabilities), dtype=np.int64)
        if probabilities.ndim != 1 or ids.ndim != 1 or len(ids) != len(probabilities):
            raise ValueError("distribution arrays must be one-dimensional and have matching lengths")
        accessible_volume(probabilities, [0.0])
        return ids, probabilities

    def forward(self, source, thresholds=THRESHOLDS, key="probabilities"):
        started = time.monotonic_ns()
        ids, probabilities = self.load_distribution(source, key=key)
        thresholds = normalized_thresholds(thresholds)
        counts = accessible_volume(probabilities, thresholds)
        decision_threshold = "0.05" if "0.05" in counts else threshold_name(thresholds[0])
        return {
            "measurement": "next-token accessible volume",
            "source": str(Path(source).expanduser().resolve()),
            "created_utc": utc_now(),
            "elapsed_ns": time.monotonic_ns() - started,
            "vocabulary_size": len(probabilities),
            "counts": counts,
            "complement_counts": complementary_volume(probabilities, thresholds),
            "decision_threshold": decision_threshold,
            "input_ids_sha256": hashlib.sha256(ids.tobytes()).hexdigest(),
            "probability_values_sha256": hashlib.sha256(probabilities.tobytes()).hexdigest(),
            "_ids": ids,
            "_probabilities": probabilities,
        }

    def backward(self, observation, previous=None, momentum_band=1, minimum=None, maximum=None):
        previous_counts = previous.get("counts") if previous else None
        momentum = accessible_momentum(observation["counts"], previous_counts) if previous_counts else None
        if minimum is None and maximum is None:
            guidance = momentum_guidance(momentum, observation["decision_threshold"], momentum_band)
        else:
            if minimum is None or maximum is None:
                raise ValueError("target volume band requires both minimum and maximum")
            from .volume import steering_action

            decision_threshold = observation["decision_threshold"]
            delta = momentum.get(decision_threshold, 0) if momentum is not None else 0
            guidance = {
                "suggestion": steering_action(
                    observation["counts"][decision_threshold], delta, minimum, maximum,
                ),
                "target_volume_band": [minimum, maximum],
                "status": "experimental_recommendation_only",
                "executed": False,
            }
        recommendation = {
            "previous_source": previous.get("source") if previous else None,
            "momentum": momentum,
            "guidance": guidance,
        }
        return {**observation, **recommendation}

    @staticmethod
    def unique_path(path):
        path = Path(path)
        index = 0
        while True:
            candidate = path if index == 0 else path.with_name(f"{path.stem}-{index:03d}{path.suffix}")
            try:
                return candidate, candidate.open("xb")
            except FileExistsError:
                index += 1

    def feedback(self, observation):
        import numpy as np

        public = {key: value for key, value in observation.items() if not key.startswith("_")}
        digest = hashlib.sha256(json.dumps(public, sort_keys=True).encode("utf-8")).hexdigest()[:16]
        timestamp = observation["created_utc"].replace(":", "-")
        probability_path, stream = self.unique_path(self.output / f"volume-{timestamp}-{digest}.npz")
        with stream:
            np.savez(stream, input_ids=observation["_ids"], probabilities=observation["_probabilities"])
        report_path, stream = self.unique_path(self.output / f"volume-{timestamp}-{digest}.json")
        with stream:
            stream.write((json.dumps(public, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
        result = {**observation, "feedback": {"report": str(report_path), "probabilities": str(probability_path)}}
        if self.session is not None:
            state = self.session.current_state()
            self.session.emit(
                f"evidence:accessible-volume:{digest}",
                state["selected_id"],
                "evidence",
                f"Accessible volume: {observation['counts'][observation['decision_threshold']]} above {observation['decision_threshold']}",
                "partial",
                "tool",
                str(report_path),
                "NPZ distribution replay; forecast breadth only, not correctness, safety, or action authorization.",
                "Distribution-to-measurement-to-guidance feedback; no action is authorized or executed.",
            )
        return result

    def observe(self, source, previous=None, thresholds=THRESHOLDS, momentum_band=1,
                key="probabilities", previous_key=None, minimum=None, maximum=None):
        if previous is not None and not isinstance(previous, dict):
            previous = {
                "source": str(Path(previous).expanduser().resolve()),
                "counts": accessible_volume(
                    self.load_distribution(previous, key=previous_key or key)[1],
                    normalized_thresholds(thresholds),
                ),
            }
        else:
            previous_path, previous_report = latest_measurement(self.output)
            if previous is None:
                previous = previous_report
                if previous_report is not None:
                    previous["source"] = previous.get("source") or str(previous_path)
        observation = self.forward(source, thresholds, key=key)
        observation = self.backward(observation, previous, momentum_band, minimum, maximum)
        return self.feedback(observation)
