#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import numpy as np
import onnxruntime as ort
from huggingface_hub import hf_hub_download
from tokenizers import Tokenizer
from ablation_gem_artifacts import atomic_savez, atomic_write_bytes, atomic_write_text, prepare_model as prepare_model_files

MODEL_ID = "onnx-community/distilgpt2-ONNX"
MODEL_SHA256 = "0f79f192f3137e9a90213f1b5d4a52b6d896b735f9cb82160e5de7cc6e539c41"
TOKENIZER_SHA256 = "a6aa29bf8416d74ad795a73262b1aa3f985564ee338adbee7ffbc5861f78b6b8"
THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare_model(root):
    prepare_model_files(root, MODEL_ID, MODEL_SHA256, TOKENIZER_SHA256)


def check_reference_distribution():
    probabilities = np.array([0.40, 0.20, 0.12, 0.06, 0.04] + [0.02] * 9)
    assert np.isclose(probabilities.sum(), 1.0)
    actual = [int(np.count_nonzero(probabilities > tau)) for tau in THRESHOLDS]
    assert actual == [5, 4, 3, 2, 1, 0], actual


def forward_probabilities(tokenizer, session, prompt):
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
    assert probabilities.shape == (50257,)
    assert np.all(np.isfinite(probabilities))
    assert np.all(probabilities >= 0)
    assert np.isclose(probabilities.sum(), 1.0, rtol=0, atol=1e-10)
    return np.array(ids, dtype=np.int64), probabilities


def main():
    parser = argparse.ArgumentParser(description="Measure next-token accessible volume using actual Ablation + GEM evidence")
    parser.add_argument("--project", type=Path, default=Path("/home/cowboy/_projects/ablation-standard"))
    parser.add_argument("--output", type=Path, default=Path.home() / "Desktop")
    parser.add_argument("--model-dir", type=Path, default=Path("/tmp/gem-distilgpt2"))
    args = parser.parse_args()
    project = args.project.resolve()
    output = args.output.resolve()
    model_root = args.model_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(project / "gem-lab"))
    sys.path.insert(0, str(project))
    from gem.events import Session
    from gem.host import GemLabHost

    started = time.monotonic()
    check_reference_distribution()
    prepare_model(model_root)
    tokenizer = Tokenizer.from_file(str(model_root / "tokenizer.json"))
    model = ort.InferenceSession(str(model_root / "onnx/model.onnx"), providers=["CPUExecutionProvider"])

    with tempfile.TemporaryDirectory(prefix="gem-accessible-volume-") as temporary:
        session_root = Path(temporary) / "session"
        session = Session(session_root, "/bin/true")
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join((str(project), str(project / "gem-lab")))
        analysis = subprocess.run(
            [sys.executable, "-m", "ablation.cli", "analyze", "/bin/true", "--entropy"],
            cwd=project, env=environment, capture_output=True, text=True, check=True, timeout=30,
        )
        evidence_path = session_root / "analysis" / "system-true-entropy.txt"
        evidence_path.parent.mkdir(exist_ok=True)
        atomic_write_text(evidence_path, analysis.stdout)
        state = session.current_state()
        session.begin_selected_work(state["selected_id"], state["revision"])
        observation = session.emit(
            "observation:system-true-entropy", session.root_id, "observation",
            "System binary entropy inspection", "complete_scoped", "tool",
            "analysis/system-true-entropy.txt",
            "Actual Ablation output; no target execution or semantic conclusion.",
            "Static metadata and entropy inspection only; no target execution",
        )
        snapshot = GemLabHost(session).snapshot()
        prompt = (
            "You are the AI Agent in an Ablation + GEM reverse-engineering Lab.\n"
            f"Target: {snapshot['authoritative']['target']}\n"
            f"Selected event: {snapshot['authoritative']['selected_id']}\n"
            f"Recorded observation: {observation['label']} ({observation['status']})\n"
            "Actual Ablation evidence follows:\n"
            f"{analysis.stdout[:1600]}\n"
            "Suggest the next investigation action."
        )
        ids, probabilities = forward_probabilities(tokenizer, model, prompt)
        inference_started = time.monotonic()
        _, probabilities = forward_probabilities(tokenizer, model, prompt)
        inference_ms = round((time.monotonic() - inference_started) * 1000, 3)
        measurements = []
        for threshold in THRESHOLDS:
            count = int(np.count_nonzero(probabilities > threshold))
            measurements.append({
                "tau": threshold,
                "accessible_volume": count,
                "normalized_accessible_volume": count / len(probabilities),
            })
        order = np.argsort(-probabilities)
        top_tokens = [{
            "token_id": int(index),
            "token": tokenizer.decode([int(index)], skip_special_tokens=False),
            "probability": float(probabilities[index]),
        } for index in order[:10]]
        probability_path = output / "ablation-gem-next-token-probabilities.npz"
        atomic_savez(probability_path, input_ids=ids, probabilities=probabilities)
        config_path = output / "ablation-gem-distilgpt2-config.json"
        atomic_write_bytes(config_path, (model_root / "config.json").read_bytes())
        entropy_output_path = output / "ablation-gem-entropy-evidence.txt"
        atomic_write_text(entropy_output_path, analysis.stdout)
        report = {
            "schema_version": 1,
            "instrument": "next-token accessible volume",
            "formula": "A_tau(S) = sum over tokens a in O of 1[P(a | h_T(S)) > tau]",
            "model": {
                "id": MODEL_ID,
                "runtime": f"onnxruntime {ort.__version__}",
                "model_sha256": MODEL_SHA256,
                "tokenizer_sha256": TOKENIZER_SHA256,
                "config_sha256": sha256(config_path),
                "inference_ms": inference_ms,
            },
            "gem_context": {
                "target": snapshot["authoritative"]["target"],
                "selected_id": snapshot["authoritative"]["selected_id"],
                "revision": snapshot["revision"],
                "evidence_event_id": observation["id"],
                "evidence_sha256": sha256(evidence_path),
                "context_tokens": len(ids),
                "prompt": prompt,
            },
            "vocabulary_size": len(probabilities),
            "probability_sum": float(probabilities.sum()),
            "threshold_sweep": measurements,
            "entropy_bits": float(-np.sum(probabilities * np.log2(np.maximum(probabilities, 1e-300)))),
            "max_probability": float(probabilities[order[0]]),
            "top_10_probability_mass": float(probabilities[order[:10]].sum()),
            "top_tokens": top_tokens,
            "scope": [
                "One real forward pass by distilgpt2-ONNX using actual Ablation + GEM session evidence.",
                "This is not a measurement of Kimi, Claude, Ablation semantic encoders, or human judgment.",
                "This is a next-token distribution, not a distribution over complete GEM actions.",
                "Accessible volume measures breadth only; it is not autonomy, safety, compliance, or cascade evidence.",
                "No empirical predictive or cross-model claim is made.",
            ],
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "probability_artifact": probability_path.name,
            "probability_sha256": sha256(probability_path),
            "probability_values_sha256": hashlib.sha256(probabilities.tobytes()).hexdigest(),
            "input_ids_sha256": hashlib.sha256(ids.tobytes()).hexdigest(),
        }
        metric_path = session_root / "analysis" / "accessible-volume.json"
        atomic_write_text(metric_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        metric_event = session.emit(
            "observation:accessible-volume:distilgpt2", session.root_id, "observation",
            "DistilGPT2 next-token breadth measurement", "complete_scoped", "tool",
            "analysis/accessible-volume.json",
            "Real local forward pass; threshold sweep only. No action-level, safety, autonomy, or cross-model inference.",
            "One distilgpt2-ONNX next-token distribution and accessible-volume threshold sweep",
        )
        report["measurement_event_id"] = metric_event["id"]
        report_path = output / "ablation-gem-accessible-volume.json"
        atomic_write_text(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")

        with np.load(probability_path) as artifact:
            assert np.array_equal(artifact["input_ids"], ids)
            saved = artifact["probabilities"]
        assert np.array_equal(saved, probabilities)
        for measurement in measurements:
            assert int(np.count_nonzero(saved > measurement["tau"])) == measurement["accessible_volume"]
        print("EQUATION_VERIFIED: reference distribution and real forward-pass threshold sweep")
        for measurement in measurements:
            print(f"tau={measurement['tau']:.2f} A(S)={measurement['accessible_volume']} normalized={measurement['normalized_accessible_volume']:.8f}")
        print("REPORT", report_path)
        print("PROBABILITIES", probability_path)


if __name__ == "__main__":
    main()
