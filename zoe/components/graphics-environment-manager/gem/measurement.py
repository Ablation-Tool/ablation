import hashlib
import json
import math


DEFAULT_THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)
MAX_THRESHOLDS = 32
MAX_VOCABULARY_SIZE = 1_000_000


def _numpy():
    try:
        import numpy as np
    except ImportError as error:
        raise ValueError("Measurement requires the 'predict' dependencies: python -m pip install -e '.[predict]'") from error
    return np


def normalized_thresholds(values):
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",") if item.strip()]
    try:
        thresholds = sorted({float(item) for item in values})
    except (TypeError, ValueError) as error:
        raise ValueError("thresholds must contain only real numbers") from error
    if not 1 <= len(thresholds) <= MAX_THRESHOLDS:
        raise ValueError(f"thresholds must contain 1 to {MAX_THRESHOLDS} values")
    if any(not math.isfinite(value) or not 0 <= value <= 1 for value in thresholds):
        raise ValueError("thresholds must be finite probabilities between zero and one")
    return tuple(thresholds)


def validate_probabilities(probabilities):
    np = _numpy()
    try:
        values = np.asarray(probabilities, dtype=np.float64)
    except (TypeError, ValueError) as error:
        raise ValueError("probabilities must be a one-dimensional array of real numbers") from error
    if values.ndim != 1 or not 1 <= len(values) <= MAX_VOCABULARY_SIZE:
        raise ValueError(f"probabilities must be a one-dimensional vector with 1 to {MAX_VOCABULARY_SIZE} values")
    if not np.all(np.isfinite(values)):
        raise ValueError("probabilities must contain only finite values")
    if np.any(values < 0):
        raise ValueError("probabilities cannot be negative")
    if not np.isclose(values.sum(), 1.0, rtol=0, atol=1e-8):
        raise ValueError("probabilities must sum to one within 1e-8")
    return values


def probabilities_from_logits(logits):
    np = _numpy()
    try:
        values = np.asarray(logits, dtype=np.float64)
    except (TypeError, ValueError) as error:
        raise ValueError("logits must be a one-dimensional array of real numbers") from error
    if values.ndim != 1 or not 1 <= len(values) <= MAX_VOCABULARY_SIZE:
        raise ValueError(f"logits must be a one-dimensional vector with 1 to {MAX_VOCABULARY_SIZE} values")
    if not np.all(np.isfinite(values)):
        raise ValueError("logits must contain only finite values")
    weights = np.exp(values - values.max())
    return validate_probabilities(weights / weights.sum())


def steering_action(current_volume, momentum, minimum, maximum):
    if minimum < 0 or maximum < minimum:
        raise ValueError("target volume band must satisfy 0 <= minimum <= maximum")
    if current_volume < minimum:
        return "let_breadth_grow" if momentum > 0 else "broaden_context"
    if current_volume > maximum:
        return "let_breadth_settle" if momentum < 0 else "narrow_context"
    return "continue"


def evaluate_outcome(values, actual_token_id):
    np = _numpy()
    if isinstance(actual_token_id, bool) or not isinstance(actual_token_id, (int, np.integer)):
        raise ValueError("actual_token_id must be a vocabulary index")
    actual = int(actual_token_id)
    if not 0 <= actual < len(values):
        raise ValueError("actual_token_id is outside the vocabulary")
    top = int(values.argmax())
    actual_probability = float(values[actual])
    return {
        "actual_token_id": actual,
        "top_token_id": top,
        "correct": top == actual,
        "actual_probability": actual_probability,
        "log_loss": -math.log(max(actual_probability, 1e-300)),
        "brier_score": float(np.sum(values * values) - 2 * actual_probability + 1),
    }


def measure_distribution(probabilities, thresholds=DEFAULT_THRESHOLDS, previous=None,
                         minimum=1, maximum=4, actual_token_id=None):
    np = _numpy()
    values = validate_probabilities(probabilities)
    thresholds = normalized_thresholds(thresholds)
    previous_values = validate_probabilities(previous) if previous is not None else None
    if minimum < 0 or maximum < minimum:
        raise ValueError("target volume band must satisfy 0 <= minimum <= maximum")
    if previous_values is not None and len(previous_values) != len(values):
        raise ValueError("current and previous distributions must use the same vocabulary size")
    sweep = []
    for threshold in thresholds:
        current = int(np.count_nonzero(values > threshold))
        entry = {
            "tau": threshold,
            "accessible_volume": current,
            "normalized_accessible_volume": current / len(values),
            "complement_volume": len(values) - current,
            "normalized_complement_volume": 1 - current / len(values),
        }
        if previous_values is not None:
            previous_count = int(np.count_nonzero(previous_values > threshold))
            momentum = current - previous_count
            entry.update({
                "previous_accessible_volume": previous_count,
                "accessible_momentum": momentum,
                "suggested_action": steering_action(current, momentum, minimum, maximum),
            })
        sweep.append(entry)
    report = {
        "schema_version": 1,
        "instrument": "next-token-accessible-volume",
        "measurement_point": "pre_execution",
        "vocabulary_size": len(values),
        "probability_sum": float(values.sum()),
        "threshold_sweep": sweep,
        "entropy_bits": float(-np.sum(values * np.log2(np.maximum(values, 1e-300)))),
        "max_probability": float(values.max()),
        "top_10_probability_mass": float(np.sort(values)[-10:].sum()),
        "probability_values_sha256": hashlib.sha256(values.tobytes()).hexdigest(),
    }
    if previous_values is not None:
        report["steering"] = {
            "target_volume_band": [minimum, maximum],
            "status": "experimental_recommendation_only",
            "executed": False,
        }
    if actual_token_id is not None:
        report["outcome"] = evaluate_outcome(values, actual_token_id)
    return report


def _joint_values(probabilities, horizon, vocabulary_size):
    np = _numpy()
    if isinstance(horizon, bool) or not isinstance(horizon, (int, np.integer)) or not 1 <= horizon <= 8:
        raise ValueError("horizon must be an integer from 1 to 8")
    values = np.asarray(probabilities, dtype=np.float64)
    if horizon == 1:
        if values.ndim != 1:
            raise ValueError("a one-step distribution must be one-dimensional")
        return validate_probabilities(values), len(values)
    if values.ndim == 1:
        if vocabulary_size is None:
            vocabulary_size = round(len(values) ** (1 / horizon))
        if isinstance(vocabulary_size, bool) or not isinstance(vocabulary_size, (int, np.integer)):
            raise ValueError("vocabulary_size must be a positive integer")
        if vocabulary_size < 1 or vocabulary_size ** horizon != len(values):
            raise ValueError("flat joint distribution length must equal vocabulary_size ** horizon")
    elif values.ndim == horizon:
        if any(size < 1 for size in values.shape) or len(set(values.shape)) != 1:
            raise ValueError("joint distribution axes must have equal nonzero vocabulary dimensions")
        inferred = values.shape[0]
        if vocabulary_size is not None and vocabulary_size != inferred:
            raise ValueError("vocabulary_size does not match the joint distribution shape")
        vocabulary_size = inferred
    else:
        raise ValueError("joint distribution must be flat or have exactly horizon dimensions")
    return validate_probabilities(values.reshape(-1)), int(vocabulary_size)


def measure_joint_distribution(probabilities, horizon, thresholds=DEFAULT_THRESHOLDS, previous=None,
                               vocabulary_size=None, minimum=1, maximum=4):
    if isinstance(horizon, bool):
        raise ValueError("horizon must be an integer, not a boolean")
    if horizon == 1:
        return measure_distribution(
            probabilities, thresholds, previous=previous, minimum=minimum, maximum=maximum,
        )
    values, vocabulary_size = _joint_values(probabilities, horizon, vocabulary_size)
    previous_values = None
    if previous is not None:
        previous_values, previous_vocabulary = _joint_values(previous, horizon, vocabulary_size)
        if previous_vocabulary != vocabulary_size:
            raise ValueError("current and previous joint distributions must use the same vocabulary")
    report = measure_distribution(
        values, thresholds, previous=previous_values, minimum=minimum, maximum=maximum,
    )
    report["horizon"] = int(horizon)
    report["vocabulary_size"] = vocabulary_size
    report["joint_outcome_space"] = len(values)
    report["approximate"] = False
    return report


def canonical_json(document):
    return json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def document_sha256(document):
    return hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()


def gem_forecast_context(snapshot, proposal):
    if not isinstance(snapshot, dict) or not isinstance(proposal, dict):
        raise ValueError("snapshot and proposal must be objects")
    authoritative = snapshot.get("authoritative")
    if not isinstance(authoritative, dict):
        raise ValueError("GEM snapshot has no authoritative state")
    target = authoritative.get("target")
    selected_id = authoritative.get("selected_id")
    revision = snapshot.get("revision")
    if not isinstance(target, str) or not target:
        raise ValueError("GEM snapshot has no valid target")
    if not isinstance(selected_id, str) or not selected_id:
        raise ValueError("GEM snapshot has no selected event")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("GEM snapshot has no valid revision")
    return {
        "schema_version": 1,
        "measurement_point": "pre_execution",
        "environment": "gem",
        "target": target,
        "selected_id": selected_id,
        "revision": revision,
        "proposal": proposal,
    }
