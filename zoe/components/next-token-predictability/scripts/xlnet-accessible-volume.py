#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import torch
import transformers
from transformers import XLNetLMHeadModel, XLNetTokenizer

from ablation_gem_artifacts import atomic_savez, atomic_write_text

MODEL_ID = "xlnet/xlnet-base-cased"
THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)
TEXT = (
    "A language model's output tells us what it generated. It does not, by itself, "
    "tell us how many plausible continuations preceded that output. "
    "Accessible volume addresses this gap"
)


def probabilities_for(model, inputs, target_mapping, perm_mask):
    with torch.no_grad():
        logits = model(
            **inputs,
            target_mapping=target_mapping,
            perm_mask=perm_mask,
        ).logits[0, 0].cpu().numpy().astype(np.float64)
    weights = np.exp(logits - np.max(logits))
    probabilities = weights / weights.sum()
    assert np.all(np.isfinite(probabilities))
    assert np.isclose(probabilities.sum(), 1.0, rtol=0, atol=1e-10)
    return probabilities


def main():
    parser = argparse.ArgumentParser(description="Measure accessible volume with XLNet's query stream")
    parser.add_argument("--model", default=MODEL_ID)
    parser.add_argument("--output", type=Path, default=Path("evidence"))
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    tokenizer = XLNetTokenizer.from_pretrained(args.model)
    model = XLNetLMHeadModel.from_pretrained(args.model).eval()
    inputs = tokenizer(TEXT, return_tensors="pt")
    input_ids = inputs["input_ids"]
    sequence_length = input_ids.shape[1]
    special_token_ids = set(tokenizer.all_special_ids)
    target = max(
        index for index, token_id in enumerate(input_ids[0].tolist())
        if token_id not in special_token_ids
    )
    target_id = int(input_ids[0, target])

    target_mapping = torch.zeros((1, 1, sequence_length), dtype=torch.float32)
    target_mapping[0, 0, target] = 1.0
    perm_mask = torch.zeros((1, sequence_length, sequence_length), dtype=torch.float32)
    perm_mask[0, :, target] = 1.0

    probabilities = probabilities_for(model, inputs, target_mapping, perm_mask)
    repeated = probabilities_for(model, inputs, target_mapping, perm_mask)
    assert np.array_equal(probabilities, repeated)

    leakage_checks = []
    for replacement_id in (tokenizer.unk_token_id, 1, 2):
        changed = {name: value.clone() for name, value in inputs.items()}
        changed["input_ids"][0, target] = replacement_id
        changed_probabilities = probabilities_for(model, changed, target_mapping, perm_mask)
        identical = np.array_equal(probabilities, changed_probabilities)
        assert identical, f"Target identity leaked through replacement {replacement_id}"
        leakage_checks.append({"replacement_token_id": replacement_id, "probabilities_identical": identical})

    order = np.argsort(-probabilities)
    sweep = [{
        "tau": threshold,
        "accessible_volume": int(np.count_nonzero(probabilities > threshold)),
        "normalized_accessible_volume": float(np.count_nonzero(probabilities > threshold) / len(probabilities)),
    } for threshold in THRESHOLDS]
    ids = input_ids[0].numpy()
    probability_path = output / "xlnet-hidden-token-probabilities.npz"
    atomic_savez(probability_path, input_ids=ids, probabilities=probabilities)
    report = {
        "schema_version": 1,
        "instrument": "hidden-token accessible volume using XLNet query-stream self-attention",
        "model": args.model if args.model == MODEL_ID else Path(args.model).name,
        "runtime": {"torch": torch.__version__, "transformers": transformers.__version__},
        "text": TEXT,
        "sequence_length": sequence_length,
        "target_position": target,
        "target_token_id": target_id,
        "target_token": tokenizer.decode([target_id], skip_special_tokens=False),
        "vocabulary_size": len(probabilities),
        "probability_sum": float(probabilities.sum()),
        "threshold_sweep": sweep,
        "entropy_bits": float(-np.sum(probabilities * np.log2(np.maximum(probabilities, 1e-300)))),
        "top_10_probability_mass": float(probabilities[order[:10]].sum()),
        "target_probability": float(probabilities[target_id]),
        "target_rank": int(np.flatnonzero(order == target_id)[0]) + 1,
        "top_tokens": [{
            "token_id": int(index),
            "token": tokenizer.decode([int(index)], skip_special_tokens=False),
            "probability": float(probabilities[index]),
        } for index in order[:10]],
        "leakage_checks": leakage_checks,
        "probability_values_sha256": hashlib.sha256(probabilities.tobytes()).hexdigest(),
        "input_ids_sha256": hashlib.sha256(ids.tobytes()).hexdigest(),
        "scope": [
            f"One {report['model']} distribution for the final token of text quoted from the paper.",
            "The query stream can attend to every other token but not the target token.",
            "This is a token-level measurement, not a distribution over actions or complete responses.",
        ],
    }
    report_path = output / "xlnet-hidden-token-accessible-volume.json"
    atomic_write_text(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    with np.load(probability_path) as artifact:
        saved = artifact["probabilities"]
        assert np.array_equal(saved, probabilities)
        assert np.array_equal(artifact["input_ids"], ids)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print("REPORT", report_path)
    print("PROBABILITIES", probability_path)


if __name__ == "__main__":
    main()
