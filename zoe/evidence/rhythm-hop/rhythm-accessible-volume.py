#!/usr/bin/env python3
"""Modular rhythm experiment: alignment -> categorical forecast -> accessible volume.

Synthetic data only: eight rhythm motifs with random tempo and onset jitter.
The predictor sees forward training rhythms; retrograde is a held-out transform.
"""
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from sklearn.cluster import KMeans

rng = np.random.default_rng(7)
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
K = len(EDGES) - 1
WINDOW = 4
ALPHA = 4.0


def bin_intervals(x):
    return np.digitize(x, EDGES[1:-1])


def variation(motif):
    beats = np.asarray(motif) + rng.normal(0, .025, len(motif))
    seconds_per_beat = 60 / rng.uniform(65, 150)
    return beats * seconds_per_beat, seconds_per_beat


def shapes_and_contexts(sequences, fit_kmeans=False, kmeans=None):
    shapes, records = [], []
    for seq_index, (seconds, spb) in enumerate(sequences):
        intervals = seconds / spb
        bins = bin_intervals(intervals)
        for t in range(WINDOW, len(seconds)):
            trailing_onsets = np.r_[0, np.cumsum(seconds[t-WINDOW:t])]
            shape = trailing_onsets - trailing_onsets.mean()
            shape = shape / np.linalg.norm(shape)
            shapes.append(shape)
            records.append((seq_index, t, bins[t-2], bins[t-1], bins[t]))
    shapes = np.asarray(shapes)
    if fit_kmeans:
        kmeans = KMeans(n_clusters=len(MOTIFS), random_state=7, n_init=10).fit(shapes)
    clusters = kmeans.predict(shapes)
    return [(cluster, *record) for cluster, record in zip(clusters, records)], kmeans


def counts(records):
    tables = [defaultdict(lambda: np.zeros(K)) for _ in range(4)]
    for cluster, _, _, prev2, prev1, target in records:
        for table, key in zip(tables, [(cluster, prev2, prev1), (prev2, prev1), (prev1,), ()]):
            table[key][target] += 1
    return tables


def smoothed(table, key, fallback):
    c = table.get(key)
    if c is None:
        return fallback
    return (c + ALPHA * fallback) / (c.sum() + ALPHA)


def predict(tables, cluster, prev2, prev1):
    global_p = (tables[3][()] + 1) / (tables[3][()].sum() + K)
    p1 = smoothed(tables[2], (prev1,), global_p)
    p2 = smoothed(tables[1], (prev2, prev1), p1)
    return smoothed(tables[0], (cluster, prev2, prev1), p2)


def evaluate(records, tables):
    probs, targets = [], []
    for cluster, _, _, prev2, prev1, target in records:
        probs.append(predict(tables, cluster, prev2, prev1))
        targets.append(target)
    return np.asarray(probs), np.asarray(targets)


train = [variation(m) for m in MOTIFS for _ in range(60)]
test = [variation(m) for m in MOTIFS for _ in range(20)]
retro = [(seconds[::-1].copy(), spb) for seconds, spb in test]
train_records, kmeans = shapes_and_contexts(train, fit_kmeans=True)
forward_records, _ = shapes_and_contexts(test, kmeans=kmeans)
retro_records, _ = shapes_and_contexts(retro, kmeans=kmeans)
tables = counts(train_records)

thresholds = np.linspace(.005, .5, 100)
print("Synthetic rhythms: 8 motifs; 60 train + 20 test variations per motif")
print(f"Train onsets={len(train_records)}, forward={len(forward_records)}, retrograde={len(retro_records)}")
print("Alignment: trailing onset vectors centered and unit-scaled (1D Procrustes)")
print("\ncondition    top-1    log-loss    mean A(tau)    sweep area")
for name, records in [("forward", forward_records), ("retrograde", retro_records)]:
    p, y = evaluate(records, tables)
    top1 = (p.argmax(1) == y).mean()
    logloss = -np.log(p[np.arange(len(y)), y] + 1e-15).mean()
    accessible = (p[:, None, :] > thresholds[None, :, None]).sum(2).mean(0)
    print(f"{name:11s}  {top1:6.1%}    {logloss:7.3f}    {accessible.mean():10.2f}    {np.trapezoid(accessible, thresholds):9.3f}")
    pred_entropy = -(p * np.log(p + 1e-15)).sum(1).mean()
    at = {tau: (p > tau).sum(1).mean() for tau in [.05, .1, .2, .3]}
    print(f"  mean max-p={p.max(1).mean():.3f}, predictive entropy={pred_entropy:.3f} nats, "
          + ", ".join(f"A({tau})={value:.2f}" for tau, value in at.items()))
    if name == "forward":
        forward_curve = accessible
    else:
        retro_curve = accessible

# Deterministic baseline only: it has no alternative distribution.
def extrapolation_accuracy(records_by_seq):
    hits = []
    for seconds, spb in records_by_seq:
        r = seconds / spb
        for t in range(3, len(r)):
            forecast = r[t-1] + (r[t-1] - r[t-2])
            hits.append(bin_intervals([forecast])[0] == bin_intervals([r[t]])[0])
    return np.mean(hits)

print(f"\nDeterministic linear interval-extrapolation baseline (not an accessible-volume model):")
print(f"forward={extrapolation_accuracy(test):.1%}, retrograde={extrapolation_accuracy(retro):.1%}")

plt.figure(figsize=(7, 4))
plt.plot(thresholds, forward_curve, label="held-out forward")
plt.plot(thresholds, retro_curve, label="held-out retrograde")
plt.xlabel("probability threshold τ")
plt.ylabel("mean accessible volume A(τ)")
plt.title("Synthetic next-onset forecasts")
plt.legend()
plt.tight_layout()
out = Path("evidence/rhythm-hop/rhythm-accessible-volume.png")
out.parent.mkdir(parents=True, exist_ok=True)
plt.savefig(out, dpi=150)
print(f"Plot: {out}")
