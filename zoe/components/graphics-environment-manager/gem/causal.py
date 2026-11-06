from __future__ import annotations

import math

from .hourglass import accessible_set


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


def two_way_accessible_record(past, future, tau, horizon=1):
    if isinstance(horizon, bool) or not isinstance(horizon, int) or not 1 <= horizon <= 64:
        raise ValueError("future horizon must be an integer from 1 to 64")
    tau = _threshold(tau)
    return {
        "tau": tau,
        "past": {"accessible_q_volume": len(accessible_set(past, tau)), "accessible_states": accessible_set(past, tau)},
        "future": {"horizon": horizon, "accessible_volume": len(accessible_set(future, tau)), "accessible_states": accessible_set(future, tau)},
        "context_link": "explicitly supplied forecast and context; no internal-state mapping is inferred",
    }
