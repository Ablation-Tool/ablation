"""Accessible-volume measurement for guarded investigation forecasts."""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import struct
from collections.abc import Iterable
from numbers import Real
from typing import Any


DEFAULT_THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)
MAX_VOCABULARY_SIZE = 1_000_000
SCHEMA_VERSION = 1


def _numbers(values: Iterable[Real], name: str, maximum: int) -> list[float]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be an array of numbers")
    try:
        source = list(values)
    except TypeError as exc:
        raise ValueError(f"{name} must be an array of numbers") from exc
    if not 1 <= len(source) <= maximum:
        raise ValueError(f"{name} must contain 1 to {maximum} values")
    result = []
    for value in source:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError(f"{name} must contain only real numbers")
        converted = float(value)
        if not math.isfinite(converted):
            raise ValueError(f"{name} must contain only finite numbers")
        result.append(converted)
    return result


def _thresholds(values: Iterable[Real]) -> tuple[float, ...]:
    thresholds = tuple(_numbers(values, "thresholds", 32))
    if any(not 0 < value < 1 for value in thresholds):
        raise ValueError("thresholds must be strictly between zero and one")
    if any(left >= right for left, right in zip(thresholds, thresholds[1:])):
        raise ValueError("thresholds must be strictly increasing")
    return thresholds


def canonical_json(document: Any) -> str:
    return json.dumps(
        document, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    )


def document_sha256(document: Any) -> str:
    return hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()


def probabilities_sha256(probabilities: Iterable[Real]) -> str:
    values = _numbers(probabilities, "probabilities", MAX_VOCABULARY_SIZE)
    packed = bytearray()
    for value in values:
        packed.extend(struct.pack("<d", value))
    return hashlib.sha256(packed).hexdigest()


def input_ids_sha256(input_ids: Iterable[int]) -> str:
    if isinstance(input_ids, (str, bytes, bytearray)):
        raise ValueError("input_ids must be an array of integers")
    packed = bytearray()
    count = 0
    for token_id in input_ids:
        if isinstance(token_id, bool) or not isinstance(token_id, int):
            raise ValueError("input_ids must contain only integers")
        if not 0 <= token_id <= 0x7FFFFFFFFFFFFFFF:
            raise ValueError("input_ids must contain nonnegative signed 64-bit integers")
        packed.extend(struct.pack("<q", token_id))
        count += 1
        if count > MAX_VOCABULARY_SIZE:
            raise ValueError("input_ids exceeds the configured size limit")
    if count == 0:
        raise ValueError("input_ids cannot be empty")
    return hashlib.sha256(packed).hexdigest()


def probabilities_from_logits(logits: Iterable[Real]) -> list[float]:
    values = _numbers(logits, "logits", MAX_VOCABULARY_SIZE)
    maximum = max(values)
    weights = [math.exp(value - maximum) for value in values]
    total = math.fsum(weights)
    probabilities = [value / total for value in weights]
    if not math.isclose(math.fsum(probabilities), 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError("softmax did not produce a normalized distribution")
    return probabilities


def measure_accessible_volume(
    probabilities: Iterable[Real],
    thresholds: Iterable[Real] = DEFAULT_THRESHOLDS,
) -> dict[str, Any]:
    values = _numbers(probabilities, "probabilities", MAX_VOCABULARY_SIZE)
    selected_thresholds = _thresholds(thresholds)
    if any(value < 0 for value in values):
        raise ValueError("probabilities cannot be negative")
    probability_sum = math.fsum(values)
    if not math.isclose(probability_sum, 1.0, rel_tol=0.0, abs_tol=1e-8):
        raise ValueError("probabilities must sum to one within 1e-8")
    sweep = []
    for threshold in selected_thresholds:
        count = sum(value > threshold for value in values)
        sweep.append({
            "tau": threshold,
            "accessible_volume": count,
            "normalized_accessible_volume": count / len(values),
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "instrument": "next-token-accessible-volume",
        "measurement_point": "pre_execution",
        "vocabulary_size": len(values),
        "probability_sum": probability_sum,
        "probability_values_sha256": probabilities_sha256(values),
        "threshold_sweep": sweep,
        "entropy_bits": -math.fsum(value * math.log2(value) for value in values if value > 0),
        "max_probability": max(values),
        "top_10_probability_mass": math.fsum(heapq.nlargest(10, values)),
    }


def gem_forecast_context(snapshot: dict[str, Any], proposal: dict[str, Any]) -> dict[str, Any]:
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
        "schema_version": SCHEMA_VERSION,
        "measurement_point": "pre_execution",
        "environment": "gem",
        "target": target,
        "selected_id": selected_id,
        "revision": revision,
        "proposal": proposal,
    }
