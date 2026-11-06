#!/usr/bin/env python3
"""Real-MIDI rhythm forecasts: alignment, accessible volume, calibration, retrograde."""
import json
import os
import pickle
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import mido
import numpy as np
from sklearn.cluster import KMeans

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("NIGHTINGALE_DATA", BASE.parent / "rhythm-lab" / "data" / "nightingale"))
RESULTS = BASE.parent / "evidence" / "rhythm-lab"
RESULTS.mkdir(parents=True, exist_ok=True)
CACHE = RESULTS / "parsed_onsets.pkl"
GENRES = ["classical", "jazz", "folk"]
EDGES = np.array([0, 1/32, 1/16, 1/8, 1/4, 1/2, 3/4, 1, 1.5, 2, 3, 4, 8, np.inf])
K = len(EDGES) - 1
WINDOW = 4
CLUSTERS = 24
ALPHA = 4.0
TAUS = np.linspace(.005, .5, 100)
rng = np.random.default_rng(19)


def parse_file(path, max_intervals=512, min_intervals=64):
    mid = mido.MidiFile(path)
    onsets = set()
    for track in mid.tracks:
        tick = 0
        for msg in track:
            tick += msg.time
            if msg.type == "note_on" and msg.velocity > 0:
                onsets.add(tick)
    ticks = np.asarray(sorted(onsets), dtype=float)
    if len(ticks) < min_intervals + 1:
        return None
    intervals = np.diff(ticks) / mid.ticks_per_beat
    segments, current = [], []
    for value in intervals:
        if value > 8:
            if len(current) >= min_intervals:
                segments.append(current)
            current = []
        elif value > 0:
            current.append(value)
    if len(current) >= min_intervals:
        segments.append(current)
    if not segments:
        return None
    longest = max(segments, key=len)
    return np.asarray(longest[:max_intervals], dtype=float)


def load_corpus():
    if CACHE.exists():
        return pickle.loads(CACHE.read_bytes())
    corpus = {}
    for genre in GENRES:
        paths = sorted(DATA.joinpath(genre).rglob("*.mid*"))
        rng.shuffle(paths)
        sequences, errors = [], 0
        for path in paths:
            try:
                intervals = parse_file(path)
            except Exception:
                errors += 1
                continue
            if intervals is not None:
                sequences.append({"name": path.name, "intervals": intervals})
            if len(sequences) >= 140:
                break
        corpus[genre] = sequences
        print(f"Parsed {genre}: {len(sequences)} usable files, {errors} read errors")
    CACHE.write_bytes(pickle.dumps(corpus))
    return corpus


def bins(x):
    return np.digitize(x, EDGES[1:-1])


def make_records(sequences, kmeans=None, fit=False):
    shapes, raw = [], []
    for sequence_index, sequence in enumerate(sequences):
        intervals = sequence["intervals"]
        b = bins(intervals)
        for t in range(WINDOW, len(intervals)):
            shape = np.r_[0, np.cumsum(intervals[t-WINDOW:t])]
            shape = shape - shape.mean()
            norm = np.linalg.norm(shape)
            if norm < 1e-9:
                continue
            shapes.append(shape / norm)
            raw.append((sequence_index, t, b[t-2], b[t-1], b[t]))
    shapes = np.asarray(shapes)
    if fit:
        sample = shapes[rng.choice(len(shapes), min(50000, len(shapes)), replace=False)]
        kmeans = KMeans(n_clusters=CLUSTERS, random_state=19, n_init=5).fit(sample)
    clusters = kmeans.predict(shapes)
    records = [(int(cluster), *row) for cluster, row in zip(clusters, raw)]
    return records, kmeans


def train_tables(records):
    tables = [defaultdict(lambda: np.zeros(K)) for _ in range(4)]
    for cluster, _, _, prev2, prev1, target in records:
        keys = [(cluster, prev2, prev1), (prev2, prev1), (prev1,), ()]
        for table, key in zip(tables, keys):
            table[key][target] += 1
    return tables


def smoothed(table, key, fallback):
    counts = table.get(key)
    if counts is None:
        return fallback
    return (counts + ALPHA * fallback) / (counts.sum() + ALPHA)


def predict(tables, cluster, prev2, prev1):
    global_counts = tables[3][()]
    global_p = (global_counts + 1) / (global_counts.sum() + K)
    p1 = smoothed(tables[2], (prev1,), global_p)
    p2 = smoothed(tables[1], (prev2, prev1), p1)
    return smoothed(tables[0], (cluster, prev2, prev1), p2)


def evaluate(records, tables, sequences):
    probabilities = np.asarray([predict(tables, c, p2, p1) for c, _, _, p2, p1, _ in records])
    targets = np.asarray([row[-1] for row in records])
    predicted = probabilities.argmax(1)
    confidence = probabilities.max(1)
    correct = predicted == targets
    ece = 0.0
    for low in np.linspace(0, 1, 11)[:-1]:
        mask = (confidence >= low) & (confidence < low + .1)
        if mask.any():
            ece += mask.mean() * abs(correct[mask].mean() - confidence[mask].mean())
    accessible = (probabilities[:, None, :] > TAUS[None, :, None]).sum(2).mean(0)
    persistence = np.asarray([row[4] == row[-1] for row in records]).mean()
    linear_hits = []
    for _, sequence_index, t, _, _, target in records:
        intervals = sequences[sequence_index]["intervals"]
        estimate = intervals[t-1] + intervals[t-1] - intervals[t-2]
        linear_hits.append(bins([estimate])[0] == target)
    return {
        "n": len(records),
        "top1": float(correct.mean()),
        "logloss": float(-np.log(probabilities[np.arange(len(targets)), targets] + 1e-15).mean()),
        "ece": float(ece),
        "mean_max_p": float(confidence.mean()),
        "entropy": float(-(probabilities * np.log(probabilities + 1e-15)).sum(1).mean()),
        "mean_accessible": float(accessible.mean()),
        "sweep_area": float(np.trapezoid(accessible, TAUS)),
        "a_0.1": float((probabilities > .1).sum(1).mean()),
        "persistence_top1": float(persistence),
        "linear_top1": float(np.mean(linear_hits)),
        "curve": accessible.tolist(),
        "probabilities": probabilities,
        "targets": targets,
        "confidence": confidence,
        "correct": correct,
    }


def public(metrics):
    return {key: value for key, value in metrics.items()
            if key not in {"probabilities", "targets", "confidence", "correct", "curve"}}


def collect_stimuli(test_records, tables, test_sequences, genre):
    candidates = []
    for row in test_records:
        cluster, sequence_index, t, prev2, prev1, target = row
        if t < 8:
            continue
        intervals = test_sequences[sequence_index]["intervals"]
        excerpt = intervals[t-8:t+1]
        if excerpt.sum() > 16 or excerpt.max() > 4:
            continue
        p = predict(tables, cluster, prev2, prev1)
        candidates.append({
            "genre": genre,
            "sequence": sequence_index,
            "position": t,
            "intervals": excerpt.tolist(),
            "accessible_0.1": int((p > .1).sum()),
            "negative_log_probability": float(-np.log(p[target] + 1e-15)),
            "entropy": float(-(p * np.log(p + 1e-15)).sum()),
            "max_probability": float(p.max()),
            "correct": bool(p.argmax() == target),
        })
    return candidates


def export_stimuli(candidates):
    selected = []
    for genre in GENRES:
        genre_candidates = [c for c in candidates if c["genre"] == genre]
        values = np.asarray([c["accessible_0.1"] for c in genre_candidates])
        for level, indices in [("low", np.where(values <= 1)[0]),
                               ("medium", np.where(values == 2)[0]),
                               ("high", np.where(values >= 3)[0])]:
            if len(indices):
                chosen = rng.choice(indices, min(2, len(indices)), replace=False)
                for index in chosen:
                    item = dict(genre_candidates[index])
                    item["volume_stratum"] = level
                    selected.append(item)
    rng.shuffle(selected)
    for index, item in enumerate(selected):
        item["id"] = f"clip-{index+1:02d}"
    (RESULTS / "stimuli.json").write_text(json.dumps(selected, indent=2))
    print(f"Exported {len(selected)} rating stimuli")


corpus = load_corpus()
train, test = {}, {}
for genre, sequences in corpus.items():
    split = min(100, int(len(sequences) * .8))
    train[genre], test[genre] = sequences[:split], sequences[split:]
train_flat = [s for genre in GENRES for s in train[genre]]
train_records, kmeans = make_records(train_flat, fit=True)
tables = train_tables(train_records)
print(f"Training positions: {len(train_records)}")

results, curves, reliability = {}, {}, {}
stimulus_candidates = []
for genre in GENRES:
    forward, _ = make_records(test[genre], kmeans=kmeans)
    retro_sequences = [{"name": s["name"], "intervals": s["intervals"][::-1].copy()} for s in test[genre]]
    retro, _ = make_records(retro_sequences, kmeans=kmeans)
    forward_metrics = evaluate(forward, tables, test[genre])
    retro_metrics = evaluate(retro, tables, retro_sequences)
    results[genre] = {"forward": public(forward_metrics), "retrograde": public(retro_metrics)}
    curves[genre] = (forward_metrics["curve"], retro_metrics["curve"])
    reliability[genre] = forward_metrics
    stimulus_candidates.extend(collect_stimuli(forward, tables, test[genre], genre))
    print(f"\n{genre}: files={len(test[genre])}")
    for name, metrics in [("forward", forward_metrics), ("retrograde", retro_metrics)]:
        print(f"  {name:10s} n={metrics['n']:5d} top1={metrics['top1']:.1%} "
              f"NLL={metrics['logloss']:.3f} ECE={metrics['ece']:.3f} "
              f"A(.1)={metrics['a_0.1']:.2f} mean-A={metrics['mean_accessible']:.2f} "
              f"persist={metrics['persistence_top1']:.1%} linear={metrics['linear_top1']:.1%}")
export_stimuli(stimulus_candidates)

(RESULTS / "results.json").write_text(json.dumps(results, indent=2))
fig, axes = plt.subplots(1, 3, figsize=(13, 4), sharey=True)
for axis, genre in zip(axes, GENRES):
    axis.plot(TAUS, curves[genre][0], label="forward")
    axis.plot(TAUS, curves[genre][1], label="retrograde")
    axis.set_title(genre)
    axis.set_xlabel("probability threshold τ")
    axis.legend()
axes[0].set_ylabel("mean accessible volume A(τ)")
fig.suptitle("Real MIDI: next-onset forecast breadth")
fig.tight_layout()
fig.savefig(RESULTS / "real_midi_accessible_volume.png", dpi=150)

fig, axis = plt.subplots(figsize=(5, 5))
for genre in GENRES:
    metrics = reliability[genre]
    conf, correct = metrics["confidence"], metrics["correct"]
    centers, accuracies = [], []
    for low in np.linspace(0, 1, 11)[:-1]:
        mask = (conf >= low) & (conf < low + .1)
        if mask.sum() >= 20:
            centers.append(conf[mask].mean())
            accuracies.append(correct[mask].mean())
    axis.plot(centers, accuracies, marker="o", label=genre)
axis.plot([0, 1], [0, 1], "k--", label="perfect calibration")
axis.set(xlabel="mean predicted confidence", ylabel="observed top-1 accuracy", xlim=(0, 1), ylim=(0, 1))
axis.legend()
axis.set_title("Forward forecast calibration")
fig.tight_layout()
fig.savefig(RESULTS / "real_midi_calibration.png", dpi=150)
print(f"\nSaved results and plots in {RESULTS}")
