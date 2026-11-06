from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import math

import numpy as np

from .volume import DEFAULT_THRESHOLDS

MOTIFS = [
    [1, 1, 1, 1] * 4,
    [1, .5, .5, 1, .5, .5, 1, 1] * 2,
    [.5, .5, 1, 1, .5, .5, .5, .5, 1, 1] + [1, 1, 1, 1, 1, 1],
    [2, 1, 1, 2, 1, 1, 1, 1, 2, 1, .5, .5, 1, 1, 1, 1],
    [1.5, .5, 1, 1, 1.5, .5, 1, 1] * 2,
    [.75, .25, 1, 1, .75, .25, .5, .5, 1, 1] + [1, 1, 1, 1, 1, 1],
    [1, 1, .5, .5, .5, .5, 2, 1, 1, .5, .5, 1, 1, 1, 1, 1],
    [.5, .5, .5, .5, 2, 1, 1, .5, .5, 1, 1, 1.5, .5, 1, 1, 1],
]
EDGES = np.array([0, .375, .625, .875, 1.125, 1.75, 2.5, 3.5, np.inf])
BIN_COUNT = len(EDGES) - 1
WINDOW = 4
ALPHA = 4.0
BIN_LABELS = ("⅜", "½", "¾", "1", "1½", "2", "3", "3½+")

HOP_BASELINE = {
    "scope": "DistilGPT-2 hidden states; 1,647 positions; measured negative baseline, not a probability distribution",
    "model_1_ahead": {"top1": .466, "top5": .666},
    "linear_1_ahead": {"top1": .413, "top5": .600},
    "hop_1_ahead": {"top1": .113, "top5": .214},
    "repeat_2_ahead": {"top1": .054, "top5": .054},
    "linear_2_ahead": {"top1": .050, "top5": .094},
    "hop_2_ahead": {"top1": .032, "top5": .081},
}


def bin_intervals(values):
    return np.digitize(values, EDGES[1:-1])


def variation(motif, rng):
    beats = np.asarray(motif) + rng.normal(0, .025, len(motif))
    seconds_per_beat = 60 / rng.uniform(65, 150)
    return beats * seconds_per_beat, seconds_per_beat


def shapes_and_contexts(sequences, kmeans=None, fit_kmeans=False, window=WINDOW):
    shapes, records = [], []
    for sequence_index, (seconds, seconds_per_beat) in enumerate(sequences):
        seconds = np.asarray(seconds, dtype=float)
        if seconds.ndim != 1 or len(seconds) <= window or np.any(seconds <= 0) or not np.all(np.isfinite(seconds)):
            raise ValueError("each rhythm must contain finite positive intervals longer than the context window")
        if not math.isfinite(seconds_per_beat) or seconds_per_beat <= 0:
            raise ValueError("seconds per beat must be positive")
        bins = bin_intervals(seconds / seconds_per_beat)
        for index in range(window, len(seconds)):
            trailing = np.r_[0, np.cumsum(seconds[index-window:index])]
            shape = trailing - trailing.mean()
            norm = np.linalg.norm(shape)
            if norm == 0:
                raise ValueError("rhythm shape has zero variance")
            shapes.append(shape / norm)
            records.append((sequence_index, index, bins[index-2], bins[index-1], bins[index]))
    shapes = np.asarray(shapes)
    if fit_kmeans:
        try:
            from sklearn.cluster import KMeans
        except ImportError as error:
            raise RuntimeError("onset experiments require scikit-learn for rhythmic-context clustering") from error
        kmeans = KMeans(n_clusters=len(MOTIFS), random_state=7, n_init=10).fit(shapes)
    if kmeans is None:
        raise ValueError("a fitted rhythmic-context model is required")
    clusters = kmeans.predict(shapes)
    return [(int(cluster), *record) for cluster, record in zip(clusters, records)], kmeans


def counts(records):
    tables = [defaultdict(lambda: np.zeros(BIN_COUNT)) for _ in range(4)]
    for cluster, _, _, previous2, previous1, target in records:
        keys = [(cluster, previous2, previous1), (previous2, previous1), (previous1,), ()]
        for table, key in zip(tables, keys):
            table[key][target] += 1
    return tables


def smoothed(table, key, fallback, alpha=ALPHA):
    counts_for_key = table.get(key)
    if counts_for_key is None:
        return fallback
    return (counts_for_key + alpha * fallback) / (counts_for_key.sum() + alpha)


def predict(tables, cluster, previous2, previous1):
    global_counts = tables[3][()]
    global_probabilities = (global_counts + 1) / (global_counts.sum() + BIN_COUNT)
    first_order = smoothed(tables[2], (previous1,), global_probabilities)
    second_order = smoothed(tables[1], (previous2, previous1), first_order)
    return smoothed(tables[0], (cluster, previous2, previous1), second_order)


def evaluate(records, tables):
    probabilities, targets = [], []
    for cluster, _, _, previous2, previous1, target in records:
        probabilities.append(predict(tables, cluster, previous2, previous1))
        targets.append(target)
    return np.asarray(probabilities), np.asarray(targets, dtype=int)


def align_onsets(source, target):
    source = np.asarray(source, dtype=float)
    target = np.asarray(target, dtype=float)
    if source.shape != target.shape or source.ndim != 1 or len(source) < 3:
        raise ValueError("rhythm alignment requires the same at least three onset positions")
    if not np.all(np.isfinite(source)) or not np.all(np.isfinite(target)):
        raise ValueError("onsets must be finite")
    centered_source = source - source.mean()
    denominator = float(centered_source @ centered_source)
    if denominator == 0:
        raise ValueError("rhythm alignment requires nonzero onset variance")
    scale = float(centered_source @ (target - target.mean()) / denominator)
    if scale <= 0:
        raise ValueError("tempo alignment requires a positive scale")
    offset = float(target.mean() - scale * source.mean())
    residual = target - (scale * source + offset)
    return {
        "scale": scale,
        "offset": offset,
        "aligned": scale * source + offset,
        "rmse": float(np.sqrt(np.mean(residual ** 2))),
    }


def retrograde_intervals(seconds):
    seconds = np.asarray(seconds, dtype=float)
    return seconds[::-1].copy()


def condition_metrics(probabilities, targets, thresholds):
    probabilities = np.asarray(probabilities)
    targets = np.asarray(targets, dtype=int)
    thresholds = np.asarray(thresholds, dtype=float)
    if not len(targets):
        raise ValueError("no prediction targets available")
    accessible = (probabilities[:, None, :] > thresholds[None, :, None]).sum(axis=2).mean(axis=0)
    return {
        "observations": int(len(targets)),
        "top1": float((probabilities.argmax(axis=1) == targets).mean()),
        "log_loss": float(-np.log(probabilities[np.arange(len(targets)), targets] + 1e-15).mean()),
        "mean_max_probability": float(probabilities.max(axis=1).mean()),
        "predictive_entropy": float(-(probabilities * np.log(probabilities + 1e-15)).sum(axis=1).mean()),
        "mean_accessible_volume": float(accessible.mean()),
        "sweep_area": float(np.trapezoid(accessible, thresholds)),
        "accessible_at_0_05": float((probabilities > .05).sum(axis=1).mean()),
    }, accessible


def extrapolation_accuracy(sequences):
    hits = []
    for seconds, seconds_per_beat in sequences:
        intervals = np.asarray(seconds) / seconds_per_beat
        for index in range(3, len(intervals)):
            forecast = intervals[index-1] + (intervals[index-1] - intervals[index-2])
            hits.append(bin_intervals([forecast])[0] == bin_intervals([intervals[index]])[0])
    if not hits:
        raise ValueError("not enough intervals for deterministic extrapolation")
    return float(np.mean(hits))


@dataclass
class OnsetExperiment:
    kmeans: object
    tables: list
    thresholds: object
    forward_probabilities: object
    forward_targets: object
    retrograde_probabilities: object
    retrograde_targets: object
    forward_curve: object
    retrograde_curve: object
    forward: dict
    retrograde: dict
    deterministic_forward: float
    deterministic_retrograde: float

    def condition(self, name, temperature=1.0):
        if name == "forward":
            probabilities, targets = self.forward_probabilities, self.forward_targets
        elif name == "retrograde":
            probabilities, targets = self.retrograde_probabilities, self.retrograde_targets
        else:
            raise ValueError("condition must be forward or retrograde")
        if not math.isfinite(temperature) or temperature <= 0:
            raise ValueError("temperature must be positive")
        transformed = temper(probabilities, temperature)
        return condition_metrics(transformed, targets, self.thresholds)


def temper(probabilities, temperature):
    probabilities = np.asarray(probabilities, dtype=float)
    if not math.isfinite(temperature) or temperature <= 0:
        raise ValueError("temperature must be positive")
    if temperature == 1:
        return probabilities.copy()
    transformed = np.maximum(probabilities, 1e-15) ** (1 / temperature)
    return transformed / transformed.sum(axis=1, keepdims=True)


def run_synthetic_experiment(seed=7, train_count=60, test_count=20, thresholds=None):
    if isinstance(train_count, bool) or isinstance(test_count, bool) or not isinstance(train_count, int) or not isinstance(test_count, int) or not 1 <= train_count <= 1000 or not 1 <= test_count <= 1000:
        raise ValueError("train and test variation counts must be from 1 to 1000")
    rng = np.random.default_rng(seed)
    train = [variation(motif, rng) for motif in MOTIFS for _ in range(train_count)]
    test = [variation(motif, rng) for motif in MOTIFS for _ in range(test_count)]
    retrograde_sequences = [(retrograde_intervals(seconds), spb) for seconds, spb in test]
    train_records, kmeans = shapes_and_contexts(train, fit_kmeans=True)
    forward_records, _ = shapes_and_contexts(test, kmeans=kmeans)
    retrograde_records, _ = shapes_and_contexts(retrograde_sequences, kmeans=kmeans)
    tables = counts(train_records)
    forward_probabilities, forward_targets = evaluate(forward_records, tables)
    retrograde_probabilities, retrograde_targets = evaluate(retrograde_records, tables)
    thresholds = np.asarray(thresholds if thresholds is not None else np.linspace(.005, .5, 100), dtype=float)
    forward_metrics, forward_curve = condition_metrics(forward_probabilities, forward_targets, thresholds)
    retrograde_metrics, retrograde_curve = condition_metrics(retrograde_probabilities, retrograde_targets, thresholds)
    return OnsetExperiment(
        kmeans, tables, thresholds,
        forward_probabilities, forward_targets,
        retrograde_probabilities, retrograde_targets,
        forward_curve, retrograde_curve,
        forward_metrics, retrograde_metrics,
        extrapolation_accuracy(test), extrapolation_accuracy(retrograde_sequences),
    )


def evaluate_rhythm(experiment, seconds, seconds_per_beat, retrograde=False):
    sequence = [(retrograde_intervals(seconds) if retrograde else np.asarray(seconds), seconds_per_beat)]
    records, _ = shapes_and_contexts(sequence, kmeans=experiment.kmeans)
    return evaluate(records, experiment.tables)


def experiment_summary(experiment):
    return {
        "scope": "Synthetic rhythms only: eight motifs; forward training; held-out forward and retrograde evaluation",
        "forward": experiment.forward,
        "retrograde": experiment.retrograde,
        "deterministic_linear_extrapolation": {
            "forward_top1": experiment.deterministic_forward,
            "retrograde_top1": experiment.deterministic_retrograde,
            "accessible_volume": None,
            "reason": "A point forecast supplies no categorical alternative distribution",
        },
        "hop_negative_baseline": HOP_BASELINE,
        "thresholds": np.asarray(experiment.thresholds).tolist(),
        "forward_curve": np.asarray(experiment.forward_curve).tolist(),
        "retrograde_curve": np.asarray(experiment.retrograde_curve).tolist(),
        "default_thresholds": list(DEFAULT_THRESHOLDS),
    }
