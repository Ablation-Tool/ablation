#!/usr/bin/env python3
import csv
import json
from pathlib import Path

import numpy as np

ROOT = Path("evidence/biobert-optimization")
THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)


def independent_metrics(scores, labels):
    positives = [score for score, label in zip(scores, labels) if label]
    negatives = [score for score, label in zip(scores, labels) if not label]
    auc = sum((p > n) + 0.5 * (p == n) for p in positives for n in negatives) / (len(positives) * len(negatives))
    previous_recall = 0.0
    average_precision = 0.0
    for threshold in sorted(set(scores), reverse=True):
        predicted = [label for score, label in zip(scores, labels) if score >= threshold]
        true_positives = sum(predicted)
        recall = true_positives / len(positives)
        precision = true_positives / len(predicted)
        average_precision += (recall - previous_recall) * precision
        previous_recall = recall
    return auc, average_precision


def main():
    optimization = json.loads((ROOT / "optimization.json").read_text())
    alpha = optimization["selected_parameters"]["alpha"]
    beta = optimization["selected_parameters"]["beta"]
    assert len(optimization["candidate_search"]) == 54
    assert all(set(row) == {"alpha", "beta", "development", "validation"} for row in optimization["candidate_search"])
    with (ROOT / "optimization-scores.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 120
    scorers = {
        "adaptive": lambda p: int(np.count_nonzero(p > max(beta, alpha * p.max()))),
        "original_tau_0.05": lambda p: int(np.count_nonzero(p > 0.05)),
        "best_validation_original": lambda p: int(np.count_nonzero(p > 0.02)),
        "entropy": lambda p: float(-np.sum(p * np.log2(np.maximum(p, 1e-300)))),
        "one_minus_max_probability": lambda p: 1.0 - float(p.max()),
        "one_minus_top_10_mass": lambda p: 1.0 - float(np.sort(p)[-10:].sum()),
    }
    records = []
    for row in rows:
        with np.load(ROOT / "raw" / f"{row['case_id']}.npz") as artifact:
            probabilities = artifact["probabilities"]
        assert scorers["adaptive"](probabilities) == int(row["adaptive_score"])
        assert float(row["alpha"]) == alpha and float(row["beta"]) == beta
        for threshold in THRESHOLDS:
            assert int(np.count_nonzero(probabilities > threshold)) == int(row[f"original_tau_{threshold:.2f}"])
        records.append((row, probabilities))
    for split in ("development", "validation", "test"):
        subset = [(row, p) for row, p in records if row["split"] == split]
        for name, scorer in scorers.items():
            scores = [scorer(p) for row, p in subset]
            labels = [int(row["error"]) for row, p in subset]
            auc, average_precision = independent_metrics(scores, labels)
            expected = optimization["evaluation"][name][split]
            assert np.isclose(auc, expected["auroc"], rtol=0, atol=1e-12)
            assert np.isclose(average_precision, expected["auprc"], rtol=0, atol=1e-12)
    result = {
        "verified": True,
        "cases": len(rows),
        "candidate_count": len(optimization["candidate_search"]),
        "selected_parameters": optimization["selected_parameters"],
        "test_adaptive": optimization["evaluation"]["adaptive"]["test"],
        "test_original_tau_0.05": optimization["evaluation"]["original_tau_0.05"]["test"],
        "verification": "Independent pairwise AUROC and threshold-grouped AUPRC recomputation passed for every scorer and split",
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
