#!/usr/bin/env python3
import csv
import hashlib
import io
import json
from pathlib import Path

import numpy as np

from ablation_gem_artifacts import atomic_write_bytes, atomic_write_text

ROOT = Path("evidence/biobert-optimization")
ALPHAS = (0.001, 0.005, 0.01, 0.02, 0.05, 0.10, 0.20, 0.30, 0.50)
BETAS = (0, 0.001, 0.005, 0.01, 0.02, 0.05)
THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)


def auroc(scores, labels):
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return None
    order = sorted(range(len(scores)), key=lambda index: scores[index])
    ranks = [0.0] * len(scores)
    index = 0
    while index < len(order):
        end = index + 1
        while end < len(order) and scores[order[end]] == scores[order[index]]:
            end += 1
        rank = (index + end + 1) / 2
        for position in range(index, end):
            ranks[order[position]] = rank
        index = end
    positive_rank_sum = sum(rank for rank, label in zip(ranks, labels) if label)
    return (positive_rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def auprc(scores, labels):
    positives = sum(labels)
    if not positives:
        return None
    order = sorted(range(len(scores)), key=lambda index: -scores[index])
    true_positives = 0
    previous_recall = 0.0
    average_precision = 0.0
    index = 0
    while index < len(order):
        end = index + 1
        while end < len(order) and scores[order[end]] == scores[order[index]]:
            end += 1
        true_positives += sum(labels[order[position]] for position in range(index, end))
        recall = true_positives / positives
        precision = true_positives / end
        average_precision += (recall - previous_recall) * precision
        previous_recall = recall
        index = end
    return average_precision


def metrics(records, score_function):
    scores = [score_function(record) for record in records]
    labels = [record["error"] for record in records]
    return {
        "auroc": auroc(scores, labels),
        "auprc": auprc(scores, labels),
        "cases": len(records),
        "errors": sum(labels),
        "correct": len(labels) - sum(labels),
    }


def adaptive_score(record, alpha, beta):
    probabilities = record["probabilities"]
    threshold = max(beta, alpha * float(probabilities.max()))
    return int(np.count_nonzero(probabilities > threshold))


def original_score(record, threshold):
    return int(np.count_nonzero(record["probabilities"] > threshold))


def load_records():
    summary_bytes = (ROOT / "baseline-summary.json").read_bytes()
    summary = json.loads(summary_bytes)
    assert summary["verified_case_count"] == 120
    records = []
    for report in summary["results"]:
        with np.load(ROOT / "raw" / f"{report['case_id']}.npz") as artifact:
            probabilities = artifact["probabilities"]
        assert probabilities.shape == (report["vocabulary_size"],)
        assert np.all(np.isfinite(probabilities))
        assert np.all(probabilities >= 0)
        assert np.isclose(probabilities.sum(), 1.0, rtol=0, atol=1e-8)
        assert hashlib.sha256(probabilities.tobytes()).hexdigest() == report["probability_values_sha256"]
        assert int(np.count_nonzero(probabilities > 0)) == report["vocabulary_size"]
        assert [int(np.count_nonzero(probabilities > threshold)) for threshold in THRESHOLDS] == report["threshold_sweep"]
        order = np.argsort(-probabilities)
        assert (int(order[0]) == report["target_token_id"]) == bool(report["top1_correct"])
        assert report["error"] == int(not report["top1_correct"])
        assert int(np.flatnonzero(order == report["target_token_id"])[0]) + 1 == report["target_rank"]
        records.append({
            "case_id": report["case_id"],
            "source_document_id": report["source_document_id"],
            "split": report["split"],
            "target": report["target"],
            "error": report["error"],
            "probabilities": probabilities,
            "entropy_bits": report["entropy_bits"],
            "maximum_probability": report["maximum_probability"],
            "top_10_probability_mass": report["top_10_probability_mass"],
            "target_probability": report["target_probability"],
            "target_rank": report["target_rank"],
            "original_scores": dict(zip(THRESHOLDS, report["threshold_sweep"])),
        })
    return summary, summary_bytes, records


def main():
    summary, summary_bytes, records = load_records()
    development = [record for record in records if record["split"] == "development"]
    validation = [record for record in records if record["split"] == "validation"]
    test = [record for record in records if record["split"] == "test"]
    assert (len(development), len(validation), len(test)) == (60, 20, 40)
    for split in ("development", "validation", "test"):
        documents = {record["source_document_id"] for record in records if record["split"] == split}
        for other in ("development", "validation", "test"):
            if other != split:
                assert not documents & {record["source_document_id"] for record in records if record["split"] == other}

    candidates = []
    for alpha in ALPHAS:
        for beta in BETAS:
            scorer = lambda record, a=alpha, b=beta: adaptive_score(record, a, b)
            candidates.append({
                "alpha": alpha,
                "beta": beta,
                "development": metrics(development, scorer),
                "validation": metrics(validation, scorer),
            })
    candidates.sort(key=lambda row: (
        -row["validation"]["auroc"],
        -row["validation"]["auprc"],
        -row["development"]["auroc"],
        row["alpha"],
        -row["beta"],
    ))
    selected = candidates[0]
    alpha = selected["alpha"]
    beta = selected["beta"]

    original_candidates = []
    for threshold in THRESHOLDS:
        scorer = lambda record, value=threshold: original_score(record, value)
        original_candidates.append({
            "tau": threshold,
            "development": metrics(development, scorer),
            "validation": metrics(validation, scorer),
        })
    original_candidates.sort(key=lambda row: (
        -row["validation"]["auroc"],
        -row["validation"]["auprc"],
        -row["development"]["auroc"],
        -row["tau"],
    ))
    best_original = original_candidates[0]["tau"]

    scorers = {
        "adaptive": lambda record: adaptive_score(record, alpha, beta),
        "original_tau_0.05": lambda record: original_score(record, 0.05),
        "best_validation_original": lambda record: original_score(record, best_original),
        "entropy": lambda record: record["entropy_bits"],
        "one_minus_max_probability": lambda record: 1.0 - record["maximum_probability"],
        "one_minus_top_10_mass": lambda record: 1.0 - record["top_10_probability_mass"],
    }
    split_records = {"development": development, "validation": validation, "test": test}
    evaluation = {
        name: {split: metrics(split_records[split], scorer) for split in ("development", "validation", "test")}
        for name, scorer in scorers.items()
    }
    original_evaluation = {
        str(threshold): {split: metrics(split_records[split], lambda record, value=threshold: original_score(record, value)) for split in ("development", "validation", "test")}
        for threshold in THRESHOLDS
    }
    optimized = {
        "schema_version": 1,
        "generated_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "model": summary["model"],
        "model_revision": summary["model_revision"],
        "baseline_summary_sha256": hashlib.sha256(summary_bytes).hexdigest(),
        "objective": "Top-1 masked-token prediction error detection; higher scores represent broader distributions",
        "equation": "A_alpha_beta(x) = sum_i 1[p_i > max(beta, alpha * p_max(x))]",
        "strict_comparison": True,
        "alpha_grid": list(ALPHAS),
        "beta_grid": list(BETAS),
        "selection_rule": "Validation AUROC, validation AUPRC, development AUROC, lower alpha, then higher beta; all descending except alpha",
        "selection_data": "60 development and 20 validation cases only; test parameters were frozen before test evaluation",
        "selected_parameters": {"alpha": alpha, "beta": beta},
        "selected_candidate": selected,
        "candidate_search": candidates,
        "best_validation_original_tau": best_original,
        "original_candidate_search": original_candidates,
        "evaluation": evaluation,
        "original_threshold_evaluation": original_evaluation,
        "raw_artifact_verification": "All 120 probability vectors, hashes, threshold counts, ranks, and error labels recomputed successfully",
    }
    atomic_write_text(ROOT / "optimization.json", json.dumps(optimized, indent=2, ensure_ascii=False) + "\n")

    output = io.StringIO()
    fields = ["case_id", "source_document_id", "split", "target", "error", "adaptive_score", "alpha", "beta"]
    fields += [f"original_tau_{threshold:.2f}" for threshold in THRESHOLDS]
    fields += ["entropy_bits", "one_minus_max_probability", "one_minus_top_10_mass", "target_probability", "target_rank"]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for record in records:
        writer.writerow({
            "case_id": record["case_id"],
            "source_document_id": record["source_document_id"],
            "split": record["split"],
            "target": record["target"],
            "error": record["error"],
            "adaptive_score": adaptive_score(record, alpha, beta),
            "alpha": alpha,
            "beta": beta,
            **{f"original_tau_{threshold:.2f}": record["original_scores"][threshold] for threshold in THRESHOLDS},
            "entropy_bits": record["entropy_bits"],
            "one_minus_max_probability": 1.0 - record["maximum_probability"],
            "one_minus_top_10_mass": 1.0 - record["top_10_probability_mass"],
            "target_probability": record["target_probability"],
            "target_rank": record["target_rank"],
        })
    atomic_write_bytes(ROOT / "optimization-scores.csv", output.getvalue().encode("utf-8"))
    print("SELECTED", json.dumps(optimized["selected_parameters"]))
    print("BEST ORIGINAL TAU", best_original)
    print("EVALUATION", json.dumps(evaluation, indent=2))


if __name__ == "__main__":
    main()
