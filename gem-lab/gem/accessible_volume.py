import hashlib
import json
import math
from pathlib import Path
import tempfile

from .events import atomic_write, sha256, utc_now


MODEL_ID = "onnx-community/distilgpt2-ONNX"
MODEL_SHA256 = "0f79f192f3137e9a90213f1b5d4a52b6d896b735f9cb82160e5de7cc6e539c41"
TOKENIZER_SHA256 = "a6aa29bf8416d74ad795a73262b1aa3f985564ee338adbee7ffbc5861f78b6b8"
CONFIG_SHA256 = "dffb0253be590126da5dc43b75475f6f6ef4576439dec46e8ec83bf0408fcf83"
THRESHOLDS = (0.02, 0.05, 0.10, 0.15, 0.30, 0.50)
MAX_CANDIDATES = 16
MAX_CONTEXT_CHARACTERS = 6000


def threshold_name(value):
    return f"{value:.2f}"


def normalized_thresholds(values):
    if not values:
        raise ValueError("at least one threshold is required")
    thresholds = []
    for value in values:
        value = float(value)
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("thresholds must be finite values between zero and one")
        if value not in thresholds:
            thresholds.append(value)
    return tuple(thresholds)


def accessible_volume(probabilities, thresholds=THRESHOLDS):
    thresholds = normalized_thresholds(thresholds)
    probabilities = [float(value) for value in probabilities]
    if not probabilities:
        raise ValueError("a complete non-empty probability distribution is required")
    if any(not math.isfinite(value) or value < 0 for value in probabilities):
        raise ValueError("probabilities must be finite and non-negative")
    if not math.isclose(math.fsum(probabilities), 1.0, rel_tol=0, abs_tol=1e-6):
        raise ValueError("probabilities must sum to one")
    return {
        threshold_name(threshold): sum(value > threshold for value in probabilities)
        for threshold in thresholds
    }


def complementary_volume(probabilities, thresholds=THRESHOLDS):
    counts = accessible_volume(probabilities, thresholds)
    return {name: len(probabilities) - count for name, count in counts.items()}


def accessible_momentum(current_counts, previous_counts):
    return {
        name: current_counts[name] - previous_counts[name]
        for name in current_counts.keys() & previous_counts.keys()
    }


def momentum_guidance(momentum, decision_threshold, target_band):
    if momentum is None or decision_threshold not in momentum:
        return {
            "trend": "unmeasured",
            "suggestion": "Collect another measurement to evaluate momentum",
            "target_band": target_band,
            "executed": False,
        }
    delta = momentum[decision_threshold]
    if delta > target_band:
        trend, suggestion = "broadening", "Broaden context"
    elif delta < -target_band:
        trend, suggestion = "narrowing", "Narrow context"
    elif delta == 0:
        trend, suggestion = "steady", "Proceed within a target band"
    else:
        trend, suggestion = "steady", "Let the current trend continue"
    return {
        "trend": trend,
        "suggestion": suggestion,
        "target_band": target_band,
        "executed": False,
    }


def latest_measurement(output):
    candidates = sorted(output.glob("*.json"), key=lambda path: path.stat().st_mtime_ns, reverse=True)
    for path in candidates:
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(report.get("counts"), dict):
            return path, report
    return None, None


def build_context(session):
    state, events = session.investigation_snapshot()
    document = {
        "instruction": "Measure only the shape of the next forecast; do not execute any action.",
        "selected": state["selected"],
        "selected_revision": state["revision"],
        "recent_evidence": events[-16:],
    }
    context = json.dumps(document, ensure_ascii=False, sort_keys=True)
    if len(context) > MAX_CONTEXT_CHARACTERS:
        context = context[-MAX_CONTEXT_CHARACTERS:]
    return context, state


class DistilGpt2Provider:
    def __init__(self):
        try:
            import numpy as np
            import onnxruntime as ort
            from huggingface_hub import hf_hub_download
            from tokenizers import Tokenizer
        except ImportError as error:
            raise RuntimeError(
                "Accessible-volume measurement requires the optional measurement dependencies: "
                "python -m pip install 'gem-lab[measurement]'",
            ) from error
        self.np = np
        self.ort = ort
        self.hf_hub_download = hf_hub_download
        self.Tokenizer = Tokenizer

    def download(self, filename, expected_sha256):
        path = Path(self.hf_hub_download(MODEL_ID, filename))
        actual = sha256(path)
        if actual != expected_sha256:
            raise RuntimeError(f"Model artifact integrity check failed for {filename}: {actual}")
        return path

    def forward(self, context):
        np = self.np
        model_path = self.download("onnx/model.onnx", MODEL_SHA256)
        tokenizer_path = self.download("tokenizer.json", TOKENIZER_SHA256)
        config_path = self.download("config.json", CONFIG_SHA256)
        tokenizer = self.Tokenizer.from_file(str(tokenizer_path))
        session = self.ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
        ids = tokenizer.encode(context).ids[-1024:]
        if not ids:
            raise ValueError("the measurement context must contain at least one token")
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
        if probabilities.shape != (50257,):
            raise RuntimeError(f"Unexpected vocabulary shape: {probabilities.shape}")
        if not np.all(np.isfinite(probabilities)) or not np.all(probabilities >= 0):
            raise RuntimeError("Model returned invalid probabilities")
        order = np.argsort(-probabilities)
        metadata = {
            "model": {
                "id": MODEL_ID,
                "runtime": f"onnxruntime {self.ort.__version__}",
                "model_sha256": MODEL_SHA256,
                "tokenizer_sha256": TOKENIZER_SHA256,
                "config_sha256": sha256(config_path),
            },
            "top_tokens": [{
                "token_id": int(index),
                "token": tokenizer.decode([int(index)], skip_special_tokens=False),
                "probability": float(probabilities[index]),
            } for index in order[:10]],
        }
        return np.asarray(ids, dtype=np.int64), probabilities, metadata


def measure_session(session, thresholds=THRESHOLDS, provider=None, candidates=(), momentum_band=1):
    provider = provider or DistilGpt2Provider()
    thresholds = normalized_thresholds(thresholds)
    if type(momentum_band) is not int or momentum_band < 0:
        raise ValueError("momentum target band must be a non-negative integer")
    candidates = list(candidates)
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"at most {MAX_CANDIDATES} candidate actions are allowed")
    for action in candidates:
        if not isinstance(action, str) or not action.strip():
            raise ValueError("candidate actions must be non-empty strings")
    context, state = build_context(session)
    ids, probabilities, metadata = provider.forward(context)
    counts = accessible_volume(probabilities, thresholds)
    complement_counts = complementary_volume(probabilities, thresholds)
    candidate_reports = []
    candidate_artifacts = {}
    for index, action in enumerate(candidates):
        candidate_context = context + "\n" + json.dumps({
            "proposed_future_action": action.strip()[:2000],
            "execution": "not selected or executed",
        }, ensure_ascii=False)
        candidate_context = candidate_context[-MAX_CONTEXT_CHARACTERS:]
        candidate_ids, candidate_probabilities, candidate_metadata = provider.forward(candidate_context)
        candidate_counts = accessible_volume(candidate_probabilities, thresholds)
        candidate_artifacts[f"candidate_{index}_input_ids"] = candidate_ids
        candidate_artifacts[f"candidate_{index}_probabilities"] = candidate_probabilities
        candidate_reports.append({
            "action": action.strip(),
            "token_count": len(candidate_ids),
            "counts": candidate_counts,
            "complement_counts": complementary_volume(candidate_probabilities, thresholds),
            "normalized_counts": {
                name: count / len(candidate_probabilities) for name, count in candidate_counts.items()
            },
            "delta": {name: candidate_counts[name] - counts[name] for name in counts},
            "top_tokens": candidate_metadata["top_tokens"],
            "input_ids_sha256": hashlib.sha256(candidate_ids.tobytes()).hexdigest(),
            "probability_values_sha256": hashlib.sha256(candidate_probabilities.tobytes()).hexdigest(),
        })
    digest_source = context + "\n" + "\n".join(report["action"] for report in candidate_reports)
    digest = hashlib.sha256(digest_source.encode("utf-8") + ids.tobytes()).hexdigest()
    output = session.root / "accessible-volume"
    output.mkdir(parents=True, exist_ok=True)
    probability_path = output / f"{digest[:16]}.npz"
    with tempfile.NamedTemporaryFile(dir=output, prefix=".probabilities-", delete=False) as stream:
        temporary = Path(stream.name)
        provider.np.savez(stream, input_ids=ids, probabilities=probabilities, **candidate_artifacts)
    try:
        temporary.replace(probability_path)
    finally:
        if temporary.exists():
            temporary.unlink()
    report_path = output / f"{digest[:16]}.json"
    decision_threshold = "0.05" if "0.05" in counts else threshold_name(thresholds[0])
    most_concentrated = None
    if candidate_reports:
        most_concentrated = min(candidate_reports, key=lambda candidate: candidate["counts"][decision_threshold])
    previous_path, previous_report = latest_measurement(output)
    momentum = accessible_momentum(counts, previous_report["counts"]) if previous_report else None
    guidance = momentum_guidance(momentum, decision_threshold, momentum_band)
    report = {
        "schema_version": 1,
        "measurement": "next-token accessible volume",
        "created_utc": utc_now(),
        "context": {
            "sha256": hashlib.sha256(context.encode("utf-8")).hexdigest(),
            "token_count": len(ids),
            "selected_id": state["selected_id"],
            "selected_revision": state["revision"],
        },
        "model": metadata["model"],
        "vocabulary_size": len(probabilities),
        "counts": counts,
        "complement_counts": complement_counts,
        "previous_report": str(previous_path) if previous_path else None,
        "momentum": momentum,
        "guidance": guidance,
        "normalized_counts": {name: count / len(probabilities) for name, count in counts.items()},
        "top_tokens": metadata["top_tokens"],
        "input_ids_sha256": hashlib.sha256(ids.tobytes()).hexdigest(),
        "probability_values_sha256": hashlib.sha256(probabilities.tobytes()).hexdigest(),
        "probability_artifact": str(probability_path),
        "candidates": candidate_reports,
        "most_concentrated_candidate": most_concentrated,
        "decision_threshold": decision_threshold,
        "scope": (
            "DistilGPT2 next-token forecasts for the recorded Lab context and explicitly proposed future actions. "
            "It does not measure the interactive agent, correctness, or safety. "
            "Candidate concentration is advisory only; no action is authorized or executed."
        ),
    }
    first_threshold = threshold_name(thresholds[0])
    event = session.emit(
        f"evidence:accessible-volume:{digest[:16]}",
        state["selected_id"],
        "evidence",
        f"Accessible volume: {counts[first_threshold]} above {first_threshold}",
        "partial",
        "tool",
        str(report_path),
        "Measured with distilgpt2-ONNX; forecast breadth only, not correctness, safety, or action authorization.",
        "Local-model forecasts for the recorded Lab context and proposed actions; no interactive-agent measurement or action execution.",
    )
    report["evidence_event_id"] = event["id"]
    atomic_write(report_path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return report, event
