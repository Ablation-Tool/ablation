#!/usr/bin/env python3
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import tempfile

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import mido
import numpy as np
import sklearn
from sklearn.cluster import KMeans
from sklearn.model_selection import GroupShuffleSplit

DATASET_URL = "https://storage.googleapis.com/magentadata/datasets/groove/groove-v1.0.0-midionly.zip"
DATASET_SHA256 = "651cbc524ffb891be1a3e46d89dc82a1cecb09a57c748c7b45b844c4841dcc1e"
THRESHOLDS = np.linspace(0.005, 0.5, 100)
FIXED_THRESHOLDS = (0.02, 0.05, 0.10, 0.20, 0.30)


def atomic_write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def array_sha256(array):
    return hashlib.sha256(np.ascontiguousarray(array).tobytes()).hexdigest()


def merged_drum_onsets(path, tolerance):
    midi = mido.MidiFile(path)
    onsets = []
    for track in midi.tracks:
        absolute_tick = 0
        for message in track:
            absolute_tick += message.time
            if (message.type == "note_on" and message.velocity > 0
                    and message.channel == 9):
                onsets.append(absolute_tick / midi.ticks_per_beat)
    groups = []
    for onset in sorted(onsets):
        if not groups or onset - groups[-1][-1] > tolerance:
            groups.append([onset])
        else:
            groups[-1].append(onset)
    return np.asarray([np.mean(group) for group in groups], dtype=np.float64)


def load_performances(root, tolerance, minimum_onsets):
    performances = []
    with (root / "info.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        if row["time_signature"] != "4-4":
            continue
        relative_path = row["midi_filename"]
        path = root / relative_path
        onsets = merged_drum_onsets(path, tolerance)
        if len(onsets) < minimum_onsets:
            continue
        intervals = np.diff(onsets)
        performances.append({
            "id": row["id"],
            "session": row["session"],
            "drummer": row["drummer"],
            "style": row["style"],
            "bpm": int(row["bpm"]),
            "beat_type": row["beat_type"],
            "official_split": row["split"],
            "path": relative_path,
            "sha256": sha256(path),
            "onset_count": len(onsets),
            "intervals": intervals,
        })
    if len(performances) < 2:
        raise ValueError("Not enough usable 4/4 performances")
    return performances


def split_sessions(performances, seed):
    groups = np.asarray([p["session"] for p in performances])
    indices = np.arange(len(performances))
    train, test = next(GroupShuffleSplit(
        n_splits=1, test_size=0.25, random_state=seed,
    ).split(indices, groups=groups))
    train_performances = [performances[i] for i in train]
    test_performances = [performances[i] for i in test]
    train_sessions = {p["session"] for p in train_performances}
    test_sessions = {p["session"] for p in test_performances}
    if train_sessions & test_sessions:
        raise AssertionError("Recording session crossed the train/test boundary")
    return train_performances, test_performances


def quantizer(subdivisions, maximum_beats):
    maximum_bin = int(subdivisions * maximum_beats)

    def quantize(intervals):
        return np.clip(np.rint(intervals * subdivisions).astype(np.int64), 1, maximum_bin) - 1

    return quantize, maximum_bin


def make_records(performances, window, quantize, clusters, seed, kmeans=None):
    shapes = []
    records = []
    for sequence_index, performance in enumerate(performances):
        intervals = performance["intervals"]
        bins = quantize(intervals)
        for target in range(window, len(intervals)):
            trailing = np.r_[0.0, np.cumsum(intervals[target-window:target])]
            shape = trailing - trailing.mean()
            norm = np.linalg.norm(shape)
            shape = shape / norm if norm > 0 else shape
            shapes.append(shape)
            records.append((sequence_index, target, int(bins[target-2]),
                            int(bins[target-1]), int(bins[target])))
    if not records:
        raise ValueError("No prediction windows were produced")
    shapes = np.asarray(shapes)
    if kmeans is None:
        kmeans = KMeans(n_clusters=clusters, random_state=seed, n_init=10).fit(shapes)
    cluster_ids = kmeans.predict(shapes)
    packed = [(int(cluster), *record) for cluster, record in zip(cluster_ids, records)]
    return packed, kmeans


def train_tables(records, order=2):
    tables = [defaultdict(Counter) for _ in range(order + 1)]
    global_counts = Counter()
    for cluster, _, _, previous2, previous1, target in records:
        keys = [(cluster, previous2, previous1), (previous2, previous1), (previous1,)]
        for table, key in zip(tables, keys):
            table[key][target] += 1
        global_counts[target] += 1
    return tables, global_counts


def smoothed(table, key, fallback, alpha):
    counts = table.get(key)
    if counts is None:
        return fallback
    total = sum(counts.values())
    probabilities = fallback * (alpha / (total + alpha))
    for target, count in counts.items():
        probabilities[target] += count / (total + alpha)
    return probabilities


def predictor(tables, global_counts, vocabulary_size, alpha):
    total = sum(global_counts.values())
    global_p = np.full(vocabulary_size, 1.0, dtype=np.float64)
    for target, count in global_counts.items():
        global_p[target] += count
    global_p /= total + vocabulary_size

    def predict(cluster, previous2, previous1):
        p1 = smoothed(tables[2], (previous1,), global_p, alpha)
        p2 = smoothed(tables[1], (previous2, previous1), p1, alpha)
        return smoothed(tables[0], (cluster, previous2, previous1), p2, alpha)

    return predict


def evaluate(records, predict, vocabulary_size):
    probabilities = np.empty((len(records), vocabulary_size), dtype=np.float32)
    targets = np.empty(len(records), dtype=np.int64)
    sequence_indices = np.empty(len(records), dtype=np.int64)
    target_positions = np.empty(len(records), dtype=np.int64)
    for index, (cluster, sequence_index, target, previous2, previous1, actual) in enumerate(records):
        probabilities[index] = predict(cluster, previous2, previous1)
        targets[index] = actual
        sequence_indices[index] = sequence_index
        target_positions[index] = target
    if not np.all(np.isfinite(probabilities)):
        raise AssertionError("Non-finite probability")
    if not np.allclose(probabilities.sum(axis=1), 1.0, rtol=0, atol=2e-6):
        raise AssertionError("A probability distribution did not sum to one")
    return {
        "probabilities": probabilities,
        "targets": targets,
        "sequence_indices": sequence_indices,
        "target_positions": target_positions,
    }


def calibration(probabilities, targets):
    predicted = probabilities.argmax(axis=1)
    confidence = probabilities.max(axis=1)
    correct = predicted == targets
    edges = np.linspace(0.0, 1.0, 11)
    rows = []
    ece = 0.0
    for lower, upper in zip(edges[:-1], edges[1:]):
        mask = (confidence >= lower) & (confidence < upper if upper < 1 else confidence <= upper)
        count = int(mask.sum())
        if count:
            mean_confidence = float(confidence[mask].mean())
            accuracy = float(correct[mask].mean())
            ece += count / len(targets) * abs(mean_confidence - accuracy)
        else:
            mean_confidence = None
            accuracy = None
        rows.append({"lower": float(lower), "upper": float(upper), "count": count,
                     "mean_confidence": mean_confidence, "accuracy": accuracy})
    return rows, float(ece)


def metrics(result):
    p = result["probabilities"].astype(np.float64)
    y = result["targets"]
    order = np.argsort(-p, axis=1)
    predicted = order[:, 0]
    correct = predicted == y
    accessible = np.asarray([(p > threshold).sum(axis=1).mean() for threshold in THRESHOLDS])
    fixed = {}
    for threshold in FIXED_THRESHOLDS:
        per_onset = (p > threshold).sum(axis=1)
        fixed[str(threshold)] = {
            "mean": float(per_onset.mean()),
            "correct_mean": float(per_onset[correct].mean()) if correct.any() else None,
            "incorrect_mean": float(per_onset[~correct].mean()) if (~correct).any() else None,
        }
    reliability, ece = calibration(p, y)
    return {
        "predictions": len(y),
        "top_1_accuracy": float(correct.mean()),
        "top_5_accuracy": float((order[:, :5] == y[:, None]).any(axis=1).mean()),
        "log_loss_nats": float(-np.log(p[np.arange(len(y)), y] + 1e-15).mean()),
        "mean_max_probability": float(p.max(axis=1).mean()),
        "mean_entropy_nats": float(-(p * np.log(p + 1e-15)).sum(axis=1).mean()),
        "expected_calibration_error": ece,
        "accessible_volume_fixed_thresholds": fixed,
        "mean_accessible_volume_over_sweep": float(accessible.mean()),
        "accessible_volume_sweep_area": float(np.trapezoid(accessible, THRESHOLDS)),
        "calibration_bins": reliability,
    }, accessible


def procrustes_retrograde(intervals):
    source = np.r_[0.0, np.cumsum(intervals)]
    target = np.r_[0.0, np.cumsum(intervals[::-1])]
    centered_source = source - source.mean()
    centered_target = target - target.mean()
    denominator = float(centered_source @ centered_source)
    if denominator == 0:
        return None
    scale = float((centered_source @ centered_target) / denominator)
    scale = max(0.0, scale)
    translation = float(target.mean() - scale * source.mean())
    residual = target - (scale * source + translation)
    target_rms = float(np.sqrt(np.mean(centered_target ** 2)))
    rms = float(np.sqrt(np.mean(residual ** 2)))
    return {
        "scale": scale,
        "translation_beats": translation,
        "rms_residual_beats": rms,
        "normalized_residual": rms / target_rms if target_rms > 0 else 0.0,
        "degenerate_scale": scale == 0.0,
    }


def save_plot(output, curves, map_result, map_performance, quantize):
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for name, curve in curves.items():
        ax.plot(THRESHOLDS, curve, label=name.replace("_", " "))
    ax.set(xlabel="probability threshold τ", ylabel="mean accessible volume A(τ)",
           title="Held-out Groove MIDI next-onset forecasts")
    ax.legend()
    fig.tight_layout()
    fig.savefig(output / "accessible-volume.png", dpi=150)
    plt.close(fig)

    p = map_result["probabilities"]
    y = map_result["targets"]
    positions = map_result["target_positions"]
    intervals = map_performance["intervals"]
    onset_times = np.r_[0.0, np.cumsum(intervals)]
    times = onset_times[positions + 1]
    visible = times <= 256
    times = times[visible]
    confidence = p.max(axis=1)[visible]
    accessible = (p > 0.05).sum(axis=1)[visible]
    correct = (p.argmax(axis=1) == y)[visible]
    fig, axes = plt.subplots(2, 1, figsize=(11, 6), sharex=True)
    axes[0].plot(times, accessible, linewidth=1.2)
    axes[0].set(ylabel="A(0.05)",
                title=f"Held-out predictability map: {map_performance['id']} (first 256 beats)")
    axes[1].plot(times, confidence, linewidth=1.0, label="maximum probability")
    axes[1].scatter(times[~correct], confidence[~correct], s=8, color="crimson",
                    alpha=0.6, label="incorrect top-1")
    axes[1].set(xlabel="onset position (beats from performance start)", ylabel="confidence",
                ylim=(0, 1.02), xlim=(0, 256))
    axes[1].legend()
    fig.tight_layout()
    fig.savefig(output / "predictability-map.png", dpi=150)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Song-grouped Groove MIDI timing and accessible-volume experiment")
    parser.add_argument("--dataset-root", type=Path,
                        default=Path.home() / ".cache/rhythm-midi/groove-v1.0.0/groove")
    parser.add_argument("--output", type=Path, default=Path.home() / "rhythm_midi_results")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--clusters", type=int, default=16)
    parser.add_argument("--window", type=int, default=4)
    parser.add_argument("--alpha", type=float, default=4.0)
    parser.add_argument("--merge-tolerance", type=float, default=0.02,
                        help="Merge drum onsets this many beats apart or closer")
    parser.add_argument("--subdivisions", type=int, default=48,
                        help="Target interval quantization bins per beat")
    parser.add_argument("--maximum-beats", type=float, default=4.0)
    parser.add_argument("--minimum-onsets", type=int, default=32)
    args = parser.parse_args()
    if args.window < 2:
        raise ValueError("Window must be at least two intervals")
    if args.alpha <= 0 or args.subdivisions <= 0 or args.clusters <= 0:
        raise ValueError("Alpha, subdivisions, and clusters must be positive")
    root = args.dataset_root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    example = np.asarray([0.70, 0.20, 0.08, 0.02])
    if int((example > 0.05).sum()) != 3:
        raise AssertionError("Accessible-volume primitive check failed")

    performances = load_performances(root, args.merge_tolerance, args.minimum_onsets)
    train, test = split_sessions(performances, args.seed)
    quantize, vocabulary_size = quantizer(args.subdivisions, args.maximum_beats)
    train_records, forward_kmeans = make_records(
        train, args.window, quantize, args.clusters, args.seed,
    )
    forward_records, _ = make_records(
        test, args.window, quantize, args.clusters, args.seed, forward_kmeans,
    )
    retrograde_train = [{**p, "intervals": p["intervals"][::-1].copy()} for p in train]
    retrograde_test = [{**p, "intervals": p["intervals"][::-1].copy()} for p in test]
    retrograde_records, _ = make_records(
        retrograde_test, args.window, quantize, args.clusters, args.seed, forward_kmeans,
    )
    backward_train_records, backward_kmeans = make_records(
        retrograde_train, args.window, quantize, args.clusters, args.seed,
    )
    backward_records, _ = make_records(
        retrograde_test, args.window, quantize, args.clusters, args.seed, backward_kmeans,
    )

    forward_tables, forward_global = train_tables(train_records)
    backward_tables, backward_global = train_tables(backward_train_records)
    forward_predict = predictor(forward_tables, forward_global, vocabulary_size, args.alpha)
    backward_predict = predictor(backward_tables, backward_global, vocabulary_size, args.alpha)
    results = {
        "forward": evaluate(forward_records, forward_predict, vocabulary_size),
        "reversal_transfer": evaluate(retrograde_records, forward_predict, vocabulary_size),
        "backward_matched": evaluate(backward_records, backward_predict, vocabulary_size),
    }
    first = forward_records[0]
    repeated = forward_predict(first[0], first[3], first[4])
    if not np.allclose(results["forward"]["probabilities"][0], repeated, rtol=0, atol=1e-7):
        raise AssertionError("Repeated prediction differed")

    reports = {}
    curves = {}
    for name, result in results.items():
        reports[name], curves[name] = metrics(result)

    distances = [procrustes_retrograde(p["intervals"]) for p in test]
    distances = [distance for distance in distances if distance is not None]
    distance_summary = {
        "performances": len(distances),
        "mean_rms_residual_beats": float(np.mean([d["rms_residual_beats"] for d in distances])),
        "median_rms_residual_beats": float(np.median([d["rms_residual_beats"] for d in distances])),
        "mean_normalized_residual": float(np.mean([d["normalized_residual"] for d in distances])),
        "degenerate_scale_count": sum(d["degenerate_scale"] for d in distances),
    }

    npz_path = output / "predictions.npz"
    arrays = {}
    for name, result in results.items():
        for field, values in result.items():
            arrays[f"{name}_{field}"] = values
    np.savez_compressed(npz_path, **arrays)

    sources = []
    for split, items in (("train", train), ("test", test)):
        for performance in items:
            sources.append({key: value for key, value in performance.items() if key != "intervals"}
                           | {"experiment_split": split})
    sources_path = output / "sources.json"
    atomic_write_text(sources_path, json.dumps(sources, indent=2) + "\n")

    map_index = max(range(len(test)), key=lambda index: len(test[index]["intervals"]))
    map_performance = test[map_index]
    map_result = {
        key: value[results["forward"]["sequence_indices"] == map_index]
        for key, value in results["forward"].items()
    }
    save_plot(output, curves, map_result, map_performance, quantize)

    report = {
        "schema_version": 1,
        "dataset": {
            "name": "Magenta Groove MIDI Dataset v1.0.0 MIDI-only",
            "url": DATASET_URL,
            "archive_sha256": DATASET_SHA256,
            "license": "CC BY 4.0",
            "usable_4_4_performances": len(performances),
            "train_performances": len(train),
            "test_performances": len(test),
            "train_sessions": sorted({p["session"] for p in train}),
            "test_sessions": sorted({p["session"] for p in test}),
            "session_overlap": False,
            "official_split_not_used": "17 recording sessions cross the official train/test boundaries",
        },
        "preprocessing": {
            "drum_channel_zero_indexed": 9,
            "simultaneous_onset_merge_tolerance_beats": args.merge_tolerance,
            "interval_units": "MIDI quarter-note beats; tempo cancels",
            "target_quantization_bins_per_beat": args.subdivisions,
            "maximum_interval_beats": args.maximum_beats,
            "vocabulary_size": vocabulary_size,
            "minimum_onsets_per_performance": args.minimum_onsets,
            "trailing_intervals_per_context": args.window,
            "context_clusters": args.clusters,
            "split_before_context_clustering_and_window_training": True,
        },
        "model": {
            "type": "clustered previous-two-interval categorical model with hierarchical smoothing",
            "alpha": args.alpha,
            "forward_training_windows": len(train_records),
            "backward_training_windows": len(backward_train_records),
            "backward_model_trained_on_reversed_training_performances": True,
        },
        "conditions": reports,
        "retrograde_procrustes": distance_summary,
        "runtime": {
            "python": os.sys.version.split()[0],
            "numpy": np.__version__,
            "mido": version("mido"),
            "scikit_learn": sklearn.__version__,
            "matplotlib": matplotlib.__version__,
        },
        "artifacts": {},
        "scope": [
            "Measurements describe this categorical model, quantization, and session-grouped held-out split.",
            "Reversal transfer evaluates reversed test performances with the forward-trained model.",
            "Backward matched trains the same architecture on reversed training performances and evaluates reversed test performances.",
            "Accessible volume measures forecast breadth, not correctness or human surprise.",
            "No claim is made about other instruments, genres, models, or all future events.",
        ],
    }
    for name, result in results.items():
        report["artifacts"][f"{name}_probabilities_sha256"] = array_sha256(result["probabilities"])
        report["artifacts"][f"{name}_targets_sha256"] = array_sha256(result["targets"])
    for filename in ("predictions.npz", "sources.json", "accessible-volume.png", "predictability-map.png"):
        report["artifacts"][f"{filename}_sha256"] = sha256(output / filename)
    report_path = output / "report.json"
    atomic_write_text(report_path, json.dumps(report, indent=2) + "\n")

    with np.load(npz_path) as saved:
        for name, result in results.items():
            for field, values in result.items():
                if not np.array_equal(saved[f"{name}_{field}"], values):
                    raise AssertionError(f"Saved artifact mismatch: {name} {field}")
        saved_forward = saved["forward_probabilities"]
        saved_targets = saved["forward_targets"]
        for threshold in FIXED_THRESHOLDS:
            recomputed = float((saved_forward > threshold).sum(axis=1).mean())
            expected = reports["forward"]["accessible_volume_fixed_thresholds"][str(threshold)]["mean"]
            if not np.isclose(recomputed, expected, rtol=0, atol=1e-12):
                raise AssertionError("Saved accessible-volume recomputation failed")
        recomputed_accuracy = float((saved_forward.argmax(axis=1) == saved_targets).mean())
        if not np.isclose(recomputed_accuracy, reports["forward"]["top_1_accuracy"], rtol=0, atol=1e-12):
            raise AssertionError("Saved top-1 recomputation failed")

    print(json.dumps({
        "performances": {"train": len(train), "test": len(test)},
        "training_windows": len(train_records),
        "conditions": {name: {key: value for key, value in report.items()
                              if key in ("top_1_accuracy", "top_5_accuracy", "log_loss_nats",
                                         "mean_max_probability", "expected_calibration_error",
                                         "mean_accessible_volume_over_sweep",
                                         "accessible_volume_sweep_area")}
                       for name, report in reports.items()},
        "retrograde_procrustes": distance_summary,
        "output": str(output),
    }, indent=2))


if __name__ == "__main__":
    main()
