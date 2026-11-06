#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import re

import numpy as np
import torch
import transformers
from transformers import AutoModelForCausalLM, AutoModelForMaskedLM, AutoTokenizer

from ablation_gem_artifacts import atomic_savez, atomic_write_text

THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)
DEFAULT_TEXT = (
    "A language model's output tells us what it generated. It does not, by itself, "
    "tell us how many plausible continuations preceded that output. "
    "Accessible volume addresses this gap"
)


def probabilities_for(model, inputs, position):
    with torch.inference_mode():
        logits = model(**inputs).logits[0, position].cpu().numpy().astype(np.float64)
    weights = np.exp(logits - np.max(logits))
    probabilities = weights / weights.sum()
    if not np.all(np.isfinite(probabilities)):
        raise ValueError("Non-finite model probabilities")
    if not np.isclose(probabilities.sum(), 1.0, rtol=0, atol=1e-10):
        raise ValueError("Probability vector does not sum to one")
    return probabilities


def masked_prediction(model, tokenizer, inputs, target, target_id):
    if tokenizer.mask_token_id is None:
        raise ValueError("Model tokenizer has no mask token")
    changed = {name: value.clone() for name, value in inputs.items()}
    changed["input_ids"][0, target] = tokenizer.mask_token_id
    if int(changed["input_ids"][0, target]) == target_id:
        raise ValueError("Mask token did not replace the target")
    if tokenizer.convert_ids_to_tokens(int(inputs["input_ids"][0, target])) == tokenizer.mask_token:
        raise ValueError("Target is already masked")
    probabilities = probabilities_for(model, changed, target)
    repeated = probabilities_for(model, changed, target)
    if not np.array_equal(probabilities, repeated):
        raise ValueError("Repeated masked prediction was not identical")
    return changed, probabilities, {
        "repeated_probabilities_identical": True,
        "target_replaced_with_mask": True,
        "mask_count": int(torch.count_nonzero(changed["input_ids"] == tokenizer.mask_token_id)),
    }


def causal_prediction(model, inputs, target):
    if target < 1:
        raise ValueError("Causal prediction requires preceding context")
    prefix = {
        name: value[:, :target].clone()
        for name, value in inputs.items()
        if name in ("input_ids", "attention_mask", "token_type_ids")
    }
    probabilities = probabilities_for(model, prefix, -1)
    repeated = probabilities_for(model, prefix, -1)
    if not np.array_equal(probabilities, repeated):
        raise ValueError("Repeated causal prediction was not identical")
    return prefix, probabilities, {
        "repeated_probabilities_identical": True,
        "target_absent_from_input_by_construction": True,
        "prefix_length": target,
    }


def main():
    parser = argparse.ArgumentParser(description="Measure accessible volume for masked or causal token predictions")
    parser.add_argument("--model", required=True, help="Public Hugging Face model ID")
    parser.add_argument("--style", choices=("masked", "causal"), required=True)
    parser.add_argument("--revision", help="Optional immutable model revision")
    parser.add_argument("--text", default=DEFAULT_TEXT)
    parser.add_argument("--target", help="Expected final non-special token, ignoring surrounding whitespace")
    parser.add_argument("--output", type=Path, default=Path("evidence/comparison"))
    parser.add_argument("--local-files-only", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    model_name = args.model if not Path(args.model).exists() else Path(args.model).name

    tokenizer = AutoTokenizer.from_pretrained(
        args.model, revision=args.revision, local_files_only=args.local_files_only,
    )
    model_class = AutoModelForMaskedLM if args.style == "masked" else AutoModelForCausalLM
    model = model_class.from_pretrained(
        args.model, revision=args.revision, local_files_only=args.local_files_only,
    ).eval()
    inputs = tokenizer(args.text, return_tensors="pt")
    input_ids = inputs["input_ids"]
    special_token_ids = set(tokenizer.all_special_ids)
    content_positions = [
        index for index, token_id in enumerate(input_ids[0].tolist())
        if token_id not in special_token_ids
    ]
    if not content_positions:
        raise ValueError("Input has no non-special tokens")
    target = content_positions[-1]
    target_id = int(input_ids[0, target])
    target_token = tokenizer.decode([target_id], skip_special_tokens=False)
    if args.target is not None and target_token.strip() != args.target:
        raise ValueError(f"Final token {target_token!r} does not match target {args.target!r}")
    if args.style == "masked":
        model_inputs, probabilities, checks = masked_prediction(
            model, tokenizer, inputs, target, target_id,
        )
    else:
        model_inputs, probabilities, checks = causal_prediction(model, inputs, target)

    order = np.argsort(-probabilities)
    sweep = [{
        "tau": threshold,
        "accessible_volume": int(np.count_nonzero(probabilities > threshold)),
        "normalized_accessible_volume": float(np.count_nonzero(probabilities > threshold) / len(probabilities)),
    } for threshold in THRESHOLDS]
    original_ids = input_ids[0].numpy()
    ids = model_inputs["input_ids"][0].numpy()
    slug = re.sub(r"[^a-z0-9._-]+", "-", model_name.rsplit("/", 1)[-1].lower())
    probability_path = output / f"{slug}-probabilities.npz"
    atomic_savez(
        probability_path,
        input_ids=ids,
        original_input_ids=original_ids,
        probabilities=probabilities,
    )
    report = {
        "schema_version": 1,
        "instrument": "accessible volume of a full-vocabulary token distribution",
        "model": model_name,
        "model_revision": getattr(model.config, "_commit_hash", None),
        "requested_revision": args.revision,
        "runtime": {"torch": torch.__version__, "transformers": transformers.__version__},
        "prediction_style": args.style,
        "text": args.text,
        "sequence_length": input_ids.shape[1],
        "target_position": target,
        "target_token_id": target_id,
        "target_token": target_token,
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
        "checks": checks,
        "probability_values_sha256": hashlib.sha256(probabilities.tobytes()).hexdigest(),
        "input_ids_sha256": hashlib.sha256(ids.tobytes()).hexdigest(),
        "original_input_ids_sha256": hashlib.sha256(original_ids.tobytes()).hexdigest(),
        "scope": [
            f"One {model_name} distribution for the final non-special token of the recorded text.",
            "The target is replaced by a mask token." if args.style == "masked"
            else "The target is absent because the model input ends immediately before it.",
            "This is a token-level measurement, not a model-quality, security, or action-level benchmark.",
        ],
    }
    report_path = output / f"{slug}-accessible-volume.json"
    atomic_write_text(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    with np.load(probability_path) as artifact:
        assert np.array_equal(artifact["probabilities"], probabilities)
        assert np.array_equal(artifact["input_ids"], ids)
        assert np.array_equal(artifact["original_input_ids"], original_ids)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print("REPORT", report_path)
    print("PROBABILITIES", probability_path)


if __name__ == "__main__":
    main()
