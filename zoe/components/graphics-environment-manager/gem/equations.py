from __future__ import annotations

import math

from .landmarks import affine_procrustes, similarity_procrustes


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
    if len(initial) ** horizon > 1_000_000:
        raise ValueError("continuation space exceeds the exact-enumeration bound")
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


def procrustes_measure(source, target, mode="similarity"):
    if mode not in {"similarity", "rigid", "affine"}:
        raise ValueError("alignment mode must be similarity, rigid, or affine")
    if mode == "affine":
        result = affine_procrustes(source, target)
        matrix = result.matrix
        translation = result.translation
        mapped = result.predicted
        scale = math.sqrt(abs(result.matrix[0][0] * result.matrix[1][1] - result.matrix[0][1] * result.matrix[1][0]))
    else:
        result = similarity_procrustes(source, target)
        scale = 1.0 if mode == "rigid" else result.scale
        matrix = result.rotation * scale
        translation = result.translation
        mapped = result.predicted
    squared_error = sum((float(left) - float(right)) ** 2 for first, second in zip(mapped, target) for left, right in zip(first, second))
    return {
        "mode": mode,
        "matrix": matrix.tolist(),
        "translation": translation.tolist(),
        "mapped": mapped.tolist(),
        "scale": float(scale),
        "rotation_degrees": math.degrees(math.atan2(matrix[1][0], matrix[0][0])),
        "determinant": float(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]),
        "squared_error": squared_error,
        "rmse_per_landmark": math.sqrt(squared_error / len(source)),
        "rmse_per_coordinate": math.sqrt(squared_error / (2 * len(source))),
        "landmark_count": len(source),
    }
