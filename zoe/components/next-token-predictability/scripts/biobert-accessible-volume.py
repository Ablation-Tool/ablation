#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

import numpy as np
import torch
import transformers
from transformers import AutoModelForMaskedLM, AutoTokenizer

from ablation_gem_artifacts import atomic_savez, atomic_write_text

MODEL = "dmis-lab/biobert-base-cased-v1.2"
REVISION = "67c9c25b46986521ca33df05d8540da1210b3256"
THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)
ROOT = Path("evidence/biobert-optimization")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def predict(model, inputs, position):
    with torch.inference_mode():
        logits = model(**inputs).logits[0, position].cpu().numpy().astype(np.float64)
    weights = np.exp(logits - np.max(logits))
    probabilities = weights / weights.sum()
    assert np.all(np.isfinite(probabilities))
    assert np.all(probabilities >= 0)
    assert np.isclose(probabilities.sum(), 1.0, rtol=0, atol=1e-10)
    return probabilities


def main():
    manifest_bytes = (ROOT / "cases.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    assert manifest["model"] == MODEL and manifest["model_revision"] == REVISION
    assert manifest["case_count"] == 120
    raw_dir = ROOT / "raw"
    report_dir = ROOT / "reports"
    raw_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    tokenizer = AutoTokenizer.from_pretrained(MODEL, revision=REVISION)
    model = AutoModelForMaskedLM.from_pretrained(MODEL, revision=REVISION).eval()
    results = []
    for index, case in enumerate(manifest["cases"], 1):
        encoded = tokenizer(case["context"], return_tensors="pt", return_offsets_mapping=True)
        original_ids = encoded["input_ids"]
        offsets = encoded["offset_mapping"][0].tolist()
        span = (case["target_start"], case["target_end"])
        positions = [position for position, offset in enumerate(offsets) if tuple(offset) == span]
        assert positions == [case["target_position"]], (case["case_id"], positions, span)
        position = positions[0]
        target_id = int(original_ids[0, position])
        assert target_id == case["target_token_id"]
        assert tokenizer.decode([target_id]) == case["target"]
        inputs = {name: value.clone() for name, value in encoded.items() if name != "offset_mapping"}
        inputs["input_ids"][0, position] = tokenizer.mask_token_id
        assert int(torch.count_nonzero(inputs["input_ids"] == tokenizer.mask_token_id)) == 1
        assert int(inputs["input_ids"][0, position]) != target_id
        probabilities = predict(model, inputs, position)
        repeated = predict(model, inputs, position)
        assert np.array_equal(probabilities, repeated)
        order = np.argsort(-probabilities)
        target_rank = int(np.flatnonzero(order == target_id)[0]) + 1
        top1_correct = int(order[0]) == target_id
        sweep = [int(np.count_nonzero(probabilities > threshold)) for threshold in THRESHOLDS]
        ids = inputs["input_ids"][0].numpy()
        originals = original_ids[0].numpy()
        probability_path = raw_dir / f"{case['case_id']}.npz"
        atomic_savez(
            probability_path,
            probabilities=probabilities,
            input_ids=ids,
            original_input_ids=originals,
        )
        with np.load(probability_path) as artifact:
            assert np.array_equal(artifact["probabilities"], probabilities)
            assert np.array_equal(artifact["input_ids"], ids)
            assert np.array_equal(artifact["original_input_ids"], originals)
            assert [int(np.count_nonzero(artifact["probabilities"] > threshold)) for threshold in THRESHOLDS] == sweep
        report = {
            "schema_version": 1,
            "model": MODEL,
            "model_revision": REVISION,
            "runtime": {"torch": torch.__version__, "transformers": transformers.__version__},
            "case_id": case["case_id"],
            "source_document_id": case["source_document_id"],
            "split": case["split"],
            "context_sha256": sha256(case["context"].encode("utf-8")),
            "target": case["target"],
            "target_position": position,
            "target_token_id": target_id,
            "vocabulary_size": len(probabilities),
            "probability_sum": float(probabilities.sum()),
            "thresholds": list(THRESHOLDS),
            "threshold_sweep": sweep,
            "entropy_bits": float(-np.sum(probabilities * np.log2(np.maximum(probabilities, 1e-300)))),
            "maximum_probability": float(probabilities[order[0]]),
            "top_10_probability_mass": float(probabilities[order[:10]].sum()),
            "target_probability": float(probabilities[target_id]),
            "target_rank": target_rank,
            "top1_correct": top1_correct,
            "error": int(not top1_correct),
            "top_tokens": [{
                "token_id": int(token_id),
                "token": tokenizer.decode([int(token_id)]),
                "probability": float(probabilities[token_id]),
            } for token_id in order[:10]],
            "checks": {
                "repeated_probabilities_identical": True,
                "single_prediction_mask": True,
                "target_replaced_with_mask": True,
                "saved_probabilities_bit_identical": True,
                "threshold_counts_recomputed": True,
            },
            "probability_values_sha256": sha256(probabilities.tobytes()),
            "input_ids_sha256": sha256(ids.tobytes()),
            "original_input_ids_sha256": sha256(originals.tobytes()),
        }
        atomic_write_text(report_dir / f"{case['case_id']}.json", json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        results.append(report)
        print(
            f"BASELINE {index:03d}/120 {case['split']} {case['case_id']} "
            f"counts={sweep} error={report['error']} target={case['target']!r}", flush=True,
        )
    summary = {
        "schema_version": 1,
        "generated_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "instrument": "Original accessible-volume equation with strict probability thresholds",
        "model": MODEL,
        "model_revision": REVISION,
        "cases_sha256": sha256(manifest_bytes),
        "thresholds": list(THRESHOLDS),
        "case_count": len(results),
        "verified_case_count": len(results),
        "error_counts": {
            split: {
                "cases": sum(report["split"] == split for report in results),
                "errors": sum(report["split"] == split and report["error"] for report in results),
                "correct": sum(report["split"] == split and report["top1_correct"] for report in results),
            }
            for split in ("development", "validation", "test")
        },
        "results": results,
    }
    atomic_write_text(ROOT / "baseline-summary.json", json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    print("BASELINE COMPLETE", json.dumps(summary["error_counts"]), flush=True)


if __name__ == "__main__":
    main()
