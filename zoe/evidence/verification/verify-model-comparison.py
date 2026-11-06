#!/usr/bin/env python3
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re

import numpy as np

from ablation_gem_artifacts import atomic_write_bytes, atomic_write_text


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Verify raw comparison artifacts and generate the paper summary")
    parser.add_argument("--manifest", type=Path, default=Path(__file__).parent.parent / "evidence" / "comparison" / "model-comparison-cases.json")
    parser.add_argument("--evidence", type=Path, default=Path("evidence/comparison"))
    args = parser.parse_args()
    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    thresholds = manifest["thresholds"]
    if len(manifest["cases"]) != 16:
        raise ValueError("The planned comparison contains exactly sixteen cases")
    rows = []
    for case in manifest["cases"]:
        slug = re.sub(r"[^a-z0-9._-]+", "-", case["model"].rsplit("/", 1)[-1].lower())
        report_path = args.evidence / f"{slug}-accessible-volume.json"
        probability_path = args.evidence / f"{slug}-probabilities.npz"
        report_bytes = report_path.read_bytes()
        report = json.loads(report_bytes)
        with np.load(probability_path) as artifact:
            probabilities = artifact["probabilities"]
            input_ids = artifact["input_ids"]
            original_ids = artifact["original_input_ids"]
        assert report["model"] == case["model"]
        assert report["model_revision"] == case["revision"]
        assert report["requested_revision"] == case["revision"]
        assert report["prediction_style"] == case["style"]
        assert report["text"] == case["text"]
        assert report["target_token"].strip() == case["target"]
        assert probabilities.shape == (report["vocabulary_size"],)
        assert np.all(np.isfinite(probabilities))
        assert np.all(probabilities >= 0)
        assert np.isclose(probabilities.sum(), 1.0, rtol=0, atol=1e-8)
        assert sha256_bytes(probabilities.tobytes()) == report["probability_values_sha256"]
        assert sha256_bytes(input_ids.tobytes()) == report["input_ids_sha256"]
        assert sha256_bytes(original_ids.tobytes()) == report["original_input_ids_sha256"]
        assert original_ids.shape == (report["sequence_length"],)
        assert report["checks"]["repeated_probabilities_identical"] is True
        target = report["target_position"]
        target_id = report["target_token_id"]
        assert int(original_ids[target]) == target_id
        if case["style"] == "masked":
            assert report["checks"]["target_replaced_with_mask"] is True
            assert report["checks"]["mask_count"] == 1
            assert input_ids.shape == original_ids.shape
            assert np.array_equal(input_ids[:target], original_ids[:target])
            assert np.array_equal(input_ids[target + 1:], original_ids[target + 1:])
            assert int(input_ids[target]) != target_id
        else:
            assert report["checks"]["target_absent_from_input_by_construction"] is True
            assert len(input_ids) == target
            assert np.array_equal(input_ids, original_ids[:target])
        sweep = [int(np.count_nonzero(probabilities > threshold)) for threshold in thresholds]
        assert sweep == [entry["accessible_volume"] for entry in report["threshold_sweep"]]
        order = np.argsort(-probabilities)
        entropy = float(-np.sum(probabilities * np.log2(np.maximum(probabilities, 1e-300))))
        top_10_mass = float(probabilities[order[:10]].sum())
        rank = int(np.flatnonzero(order == target_id)[0]) + 1
        assert rank == report["target_rank"]
        assert np.isclose(entropy, report["entropy_bits"], rtol=0, atol=1e-12)
        assert np.isclose(top_10_mass, report["top_10_probability_mass"], rtol=0, atol=1e-12)
        assert probabilities[target_id] == report["target_probability"]
        assert [int(index) for index in order[:10]] == [entry["token_id"] for entry in report["top_tokens"]]
        row = {
            "category": case["category"],
            "model": case["model"],
            "model_revision": case["revision"],
            "prediction_style": case["style"],
            "text": case["text"],
            "target": case["target"],
            "target_token_id": target_id,
            "vocabulary_size": report["vocabulary_size"],
            "threshold_sweep": sweep,
            "target_probability": report["target_probability"],
            "target_rank": rank,
            "top_token": report["top_tokens"][0],
            "entropy_bits": entropy,
            "maximum_probability": float(probabilities[order[0]]),
            "top_10_probability_mass": top_10_mass,
            "probability_values_sha256": report["probability_values_sha256"],
            "input_ids_sha256": report["input_ids_sha256"],
            "original_input_ids_sha256": report["original_input_ids_sha256"],
            "report_sha256": sha256_bytes(report_bytes),
            "raw_artifact_sha256": sha256_bytes(probability_path.read_bytes()),
            "runtime": report["runtime"],
            "checks": report["checks"],
        }
        rows.append(row)
        print("VERIFIED", case["category"], case["model"], sweep)
    summary = {
        "schema_version": 1,
        "generated_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "thresholds": thresholds,
        "comparison": "strict_probability_greater_than_threshold",
        "verified_case_count": len(rows),
        "verification": [
            "Every saved probability vector is finite, nonnegative, and sums to one within 1e-8.",
            "Every raw probability, model-input, and original-input hash matches its report.",
            "Every threshold count, target rank, entropy, top-10 mass, and top-token ordering recomputes from raw values.",
            "Every repeated inference was bit-identical; masked inputs changed only the target; causal inputs exclude the target.",
        ],
        "scope": "One fixed case per model. These measurements describe distribution shape, not model quality, security, safety, correctness, or actions.",
        "results": rows,
    }
    summary_path = args.evidence / "model-comparison-summary.json"
    atomic_write_text(summary_path, json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    output = io.StringIO()
    fieldnames = [
        "category", "model", "model_revision", "prediction_style", "target",
        "vocabulary_size", "tau_0.02", "tau_0.05", "tau_0.10", "tau_0.15",
        "tau_0.30", "tau_0.50", "target_probability", "target_rank", "top_token",
        "top_probability", "entropy_bits", "top_10_probability_mass", "probability_values_sha256",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "category": row["category"],
            "model": row["model"],
            "model_revision": row["model_revision"],
            "prediction_style": row["prediction_style"],
            "target": row["target"],
            "vocabulary_size": row["vocabulary_size"],
            **{f"tau_{threshold:.2f}": count for threshold, count in zip(thresholds, row["threshold_sweep"])},
            "target_probability": row["target_probability"],
            "target_rank": row["target_rank"],
            "top_token": row["top_token"]["token"],
            "top_probability": row["top_token"]["probability"],
            "entropy_bits": row["entropy_bits"],
            "top_10_probability_mass": row["top_10_probability_mass"],
            "probability_values_sha256": row["probability_values_sha256"],
        })
    atomic_write_bytes(args.evidence / "model-comparison-summary.csv", output.getvalue().encode("utf-8"))
    print("SUMMARY", summary_path)
    print("VERIFIED CASE COUNT", len(rows))


if __name__ == "__main__":
    main()
