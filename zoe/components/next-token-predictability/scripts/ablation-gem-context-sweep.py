#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer
from ablation_gem_artifacts import atomic_savez, atomic_write_text, prepare_model

THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)
MODEL_ID = "onnx-community/distilgpt2-ONNX"
MODEL_SHA256 = "0f79f192f3137e9a90213f1b5d4a52b6d896b735f9cb82160e5de7cc6e539c41"
TOKENIZER_SHA256 = "a6aa29bf8416d74ad795a73262b1aa3f985564ee338adbee7ffbc5861f78b6b8"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def forward(tokenizer, session, prompt):
    ids = tokenizer.encode(prompt).ids
    assert len(ids) <= 1024, len(ids)
    inputs = {
        "input_ids": np.array([ids], dtype=np.int64),
        "attention_mask": np.ones((1, len(ids)), dtype=np.int64),
        "position_ids": np.arange(len(ids), dtype=np.int64)[None, :],
    }
    for layer in range(6):
        for kind in ("key", "value"):
            inputs[f"past_key_values.{layer}.{kind}"] = np.zeros((1, 12, 0, 64), dtype=np.float32)
    logits = session.run(["logits"], inputs)[0][0, -1, :].astype(np.float64)
    weights = np.exp(logits - np.max(logits))
    probabilities = weights / weights.sum()
    assert np.all(np.isfinite(probabilities))
    assert np.isclose(probabilities.sum(), 1.0, rtol=0, atol=1e-10)
    return np.array(ids, dtype=np.int64), probabilities


def sweep(probabilities):
    return [{
        "tau": tau,
        "accessible_volume": int(np.count_nonzero(probabilities > tau)),
        "normalized_accessible_volume": int(np.count_nonzero(probabilities > tau)) / len(probabilities),
    } for tau in THRESHOLDS]


def main():
    parser = argparse.ArgumentParser(description="Measure accessible-volume sensitivity across controlled GEM contexts")
    parser.add_argument("--model-dir", type=Path, default=Path("/tmp/gem-distilgpt2"))
    args = parser.parse_args()
    model_root = args.model_dir.resolve()
    prepare_model(model_root, MODEL_ID, MODEL_SHA256, TOKENIZER_SHA256)
    tokenizer = Tokenizer.from_file(str(model_root / "tokenizer.json"))
    session = ort.InferenceSession(str(model_root / "onnx/model.onnx"), providers=["CPUExecutionProvider"])
    root = Path(__file__).resolve().parent
    evidence = root / "evidence"
    baseline_report = json.loads((evidence / "ablation-gem-accessible-volume.json").read_text())
    baseline = baseline_report["gem_context"]["prompt"]
    with np.load(evidence / "ablation-gem-next-token-probabilities.npz") as artifact:
        expected_ids = artifact["input_ids"]
        expected_probabilities = artifact["probabilities"]
    assert digest(expected_ids.tobytes()) == baseline_report["input_ids_sha256"], "baseline input-ID hash mismatch"
    assert digest(expected_probabilities.tobytes()) == baseline_report["probability_values_sha256"], "baseline probability hash mismatch"
    ids, probabilities = forward(tokenizer, session, baseline)
    if not np.array_equal(ids, expected_ids):
        raise ValueError("baseline prompt does not match preserved input IDs")
    if not np.array_equal(probabilities, expected_probabilities):
        raise ValueError("baseline forward pass does not match preserved probabilities")
    prefix, remainder = baseline.split("Actual Ablation evidence follows:\n", 1)
    evidence_text, request = remainder.rsplit("\nSuggest the next investigation action.", 1)
    prefix += "Actual Ablation evidence follows:\n"
    request = "Suggest the next investigation action." + request
    variants = {
        "baseline": baseline,
        "metadata_only": prefix + evidence_text.split("Entropy regions", 1)[0] + request,
        "abbreviated_evidence": prefix + evidence_text[:400] + "\n" + request,
        "no_evidence": prefix + request,
        "summary_request": prefix + evidence_text + "\nSummarize the evidence rather than choosing an action.",
        "repeated_short_evidence": prefix + evidence_text[:400] + "\n" + evidence_text[:400] + "\n" + request,
    }
    results = {}
    arrays = {}
    for name, prompt in variants.items():
        ids, probabilities = forward(tokenizer, session, prompt)
        order = np.argsort(-probabilities)
        results[name] = {
            "context_tokens": len(ids),
            "prompt": prompt,
            "input_ids_sha256": digest(ids.tobytes()),
            "probability_values_sha256": digest(probabilities.tobytes()),
            "threshold_sweep": sweep(probabilities),
            "entropy_bits": float(-np.sum(probabilities * np.log2(np.maximum(probabilities, 1e-300)))),
            "max_probability": float(probabilities[order[0]]),
            "top_token": tokenizer.decode([int(order[0])], skip_special_tokens=False),
            "top_10_probability_mass": float(probabilities[order[:10]].sum()),
        }
        arrays[f"{name}_input_ids"] = ids
        arrays[f"{name}_probabilities"] = probabilities
    second_ids, second_probabilities = forward(tokenizer, session, baseline)
    assert np.array_equal(second_ids, arrays["baseline_input_ids"])
    assert np.array_equal(second_probabilities, arrays["baseline_probabilities"])
    for name, result in results.items():
        result["delta_from_baseline"] = [
            entry["accessible_volume"] - baseline_entry["accessible_volume"]
            for entry, baseline_entry in zip(result["threshold_sweep"], results["baseline"]["threshold_sweep"])
        ]
    raw_path = evidence / "ablation-gem-context-sweep.npz"
    atomic_savez(raw_path, **arrays)
    report = {
        "schema_version": 1,
        "instrument": "accessible-volume context sensitivity",
        "model": {
            "id": "onnx-community/distilgpt2-ONNX",
            "model_sha256": MODEL_SHA256,
            "runtime": f"onnxruntime {ort.__version__}",
        },
        "baseline_probability_values_sha256": results["baseline"]["probability_values_sha256"],
        "variants": results,
        "checks": {
            "baseline_repeated_identical": True,
            "reference_strict_threshold": [int(np.count_nonzero(np.array([0.40, 0.20, 0.12, 0.06, 0.04] + [0.02] * 9) > tau)) for tau in THRESHOLDS] == [5, 4, 3, 2, 1, 0],
            "normalized_probability_vectors": all(np.isclose(np.sum(arrays[f"{name}_probabilities"]), 1.0, rtol=0, atol=1e-10) for name in variants),
            "monotonic_threshold_sweeps": all(
                all(left["accessible_volume"] >= right["accessible_volume"] for left, right in zip(result["threshold_sweep"], result["threshold_sweep"][1:]))
                for result in results.values()
            ),
            "raw_artifact_sha256": digest(raw_path.read_bytes()),
        },
        "scope": [
            "Controlled prompt perturbations using the same model and actual Ablation + GEM baseline context.",
            "The no-evidence and abbreviated variants intentionally remove context; they are not expected to preserve meaning.",
            "Differences describe these model/context pairs only, not universal token sensitivity or action quality.",
            "No claim is made about other agents, other prompts, complete actions, or multi-step trajectories.",
        ],
    }
    destination = evidence / "ablation-gem-context-sweep.json"
    atomic_write_text(destination, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    with np.load(raw_path) as raw:
        for name in variants:
            assert np.array_equal(raw[f"{name}_input_ids"], arrays[f"{name}_input_ids"])
            assert np.array_equal(raw[f"{name}_probabilities"], arrays[f"{name}_probabilities"])
    print("CONTEXT_SWEEP_PASS")
    for name, result in results.items():
        print(name, [entry["accessible_volume"] for entry in result["threshold_sweep"]], "delta", result["delta_from_baseline"], "tokens", result["context_tokens"], "top", repr(result["top_token"]))
    print("REPORT", destination)
    print("RAW", raw_path)


if __name__ == "__main__":
    main()
