import hashlib
import json
import math

from .events import atomic_write
from .prediction import (
    PredictionRun, _atomic_savez, measure_probabilities, measure_session,
    validate_probabilities,
)
from .steering import evaluate_advisory


ALPHAS = (0.001, 0.01, 0.1, 0.5)
BETAS = (0.0, 0.01, 0.05)
CONTEXT_ATTACKS = ("evidence_removed", "repeated_evidence", "irrelevant_context")


def adaptive_accessible_volume(probabilities, alpha, beta):
    if not isinstance(alpha, (int, float)) or not math.isfinite(alpha) or not 0 < alpha <= 1:
        raise ValueError("alpha must be finite and in (0, 1]")
    if not isinstance(beta, (int, float)) or not math.isfinite(beta) or not 0 <= beta < 1:
        raise ValueError("beta must be finite and in [0, 1)")
    values = validate_probabilities(probabilities)
    cutoff = max(beta, alpha * float(values.max()))
    count = int((values > cutoff).sum())
    return {
        "alpha": float(alpha),
        "beta": float(beta),
        "cutoff": cutoff,
        "accessible_volume": count,
        "normalized_accessible_volume": count / len(values),
    }


def _variant_prompt(prompt, attack):
    prefix, separator, encoded = prompt.partition("SESSION CONTEXT (JSON):\n")
    if not separator:
        raise ValueError("prediction context has an invalid format")
    context = json.loads(encoded)
    evidence = context.get("selected_evidence_text", "")
    if attack == "evidence_removed":
        context["selected_evidence_text"] = ""
        context["selected_evidence_path"] = "selected evidence removed for equation tournament"
    elif attack == "repeated_evidence":
        context["selected_evidence_text"] = (evidence + "\n") * 3
        context["selected_evidence_path"] = "selected evidence repeated three times for equation tournament"
    elif attack == "irrelevant_context":
        filler = "This deliberately unrelated sentence is context noise, not inspected evidence.\n" * 20
        context["selected_evidence_text"] = filler + evidence
        context["selected_evidence_path"] = "irrelevant context prepended for equation tournament"
    else:
        raise ValueError(f"unknown context attack: {attack}")
    return prefix + separator + json.dumps(context, ensure_ascii=False, separators=(",", ":"))


def _advisory_with_adaptive_score(report, adaptive):
    sweep = [
        {"tau": 0.02, "accessible_volume": adaptive["accessible_volume"]},
        {"tau": 0.05, "accessible_volume": adaptive["accessible_volume"]},
    ]
    return evaluate_advisory({**report, "threshold_sweep": sweep})["mode"]


def _evaluate_variant(prediction, prompt, model, context, decoder, thresholds):
    measurements = measure_probabilities(prediction.probabilities, thresholds, decoder=decoder)
    context = {
        **context,
        "context_tokens": len(prediction.input_ids),
        "context_truncated": prediction.context_truncated,
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
    }
    report = {"model": model, "gem_context": context, **measurements}
    fixed_mode = evaluate_advisory(report)["mode"]
    candidates = []
    for alpha in ALPHAS:
        for beta in BETAS:
            adaptive = adaptive_accessible_volume(prediction.probabilities, alpha, beta)
            adaptive_mode = _advisory_with_adaptive_score(report, adaptive)
            candidates.append({
                **adaptive,
                "fixed_005_delta": adaptive["accessible_volume"] - next(
                    item["accessible_volume"] for item in measurements["threshold_sweep"] if item["tau"] == 0.05
                ),
                "advisory_mode": adaptive_mode,
                "mode_flip": adaptive_mode != fixed_mode,
            })
    flips = [candidate for candidate in candidates if candidate["mode_flip"]]
    largest = max(candidates, key=lambda candidate: abs(candidate["fixed_005_delta"]))
    return report, {
        "fixed_advisory_mode": fixed_mode,
        "adaptive_candidates": candidates,
        "advisory_flip_count": len(flips),
        "largest_disagreement": largest,
        "probability_values_sha256": hashlib.sha256(prediction.probabilities.tobytes()).hexdigest(),
        "input_ids_sha256": hashlib.sha256(prediction.input_ids.tobytes()).hexdigest(),
    }


def run_tournament(session, model_dir=None, thresholds=None, predictor=None):
    from types import SimpleNamespace
    from .prediction import OnnxPredictor, _numpy

    if thresholds is None:
        from .prediction import THRESHOLDS
        thresholds = THRESHOLDS
    predictor = predictor or OnnxPredictor(model_dir)
    measurement = measure_session(
        session, model_dir=model_dir, thresholds=thresholds, predictor=predictor,
    )
    base_report = measurement.report
    context = base_report["gem_context"]
    model = base_report["model"]
    np = _numpy()
    with np.load(measurement.path / "probabilities.npz") as artifact:
        baseline_prediction = SimpleNamespace(
            input_ids=artifact["input_ids"], probabilities=artifact["probabilities"],
            context_truncated=context["context_truncated"],
        )
    decoder = getattr(predictor, "decode", None)
    computed_baseline, baseline_evaluation = _evaluate_variant(
        baseline_prediction, context["prompt"], model, context, decoder, thresholds,
    )
    variants = [{
        "name": "baseline",
        "gem_context": context,
        **{key: value for key, value in computed_baseline.items() if key not in {"model", "gem_context"}},
        **baseline_evaluation,
        "probability_artifact": "probabilities.npz",
    }]
    for attack in CONTEXT_ATTACKS:
        prompt = _variant_prompt(context["prompt"], attack)
        prediction = predictor.predict(prompt)
        report, evaluation = _evaluate_variant(
            prediction, prompt, model, context, decoder, thresholds,
        )
        artifact_name = f"probabilities-{attack}.npz"
        _atomic_savez(
            measurement.path / artifact_name,
            prediction.input_ids, prediction.probabilities,
        )
        variants.append({
            "name": attack,
            "gem_context": report["gem_context"],
            **{key: value for key, value in report.items() if key not in {"model", "gem_context"}},
            **evaluation,
            "probability_artifact": artifact_name,
        })
    tournament_digest = hashlib.sha256(
        json.dumps(variants, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    flip_count = sum(variant["advisory_flip_count"] for variant in variants)
    document = {
        "schema_version": 1,
        "instrument": "fixed and adaptive accessible-volume equation tournament",
        "run_digest": tournament_digest,
        "measurement_event_id": measurement.evidence["id"],
        "alpha_grid": ALPHAS,
        "beta_grid": BETAS,
        "adaptive_policy_mapping": "Each adaptive count replaces both A(0.02) and A(0.05) in the advisory heuristic for a like-for-like sensitivity comparison.",
        "advisory_flip_count": flip_count,
        "variants": variants,
        "scope": [
            "This is a sensitivity experiment, not a correctness benchmark or proof that either equation is better.",
            "Context attacks test measurement and advisory stability; they do not establish that a flipped recommendation is wrong.",
            "Verified task outcomes are required before declaring an equation or policy winner.",
        ],
    }
    path = measurement.path / "tournament.json"
    atomic_write(path, json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    latest = session.current_state()
    if latest["selected_id"] != context["selected_id"] or latest["revision"] != context["revision"]:
        raise ValueError("selection changed during equation tournament; results retained without an event")
    event = session.emit(
        f"observation:equation-tournament:{tournament_digest[:24]}",
        measurement.evidence["id"],
        "observation",
        f"Equation tournament · {flip_count} advisory flips",
        "complete_scoped",
        "tool",
        path.relative_to(session.root).as_posix(),
        f"Fixed and adaptive equations compared on identical distributions plus context attacks. Advisory flips: {flip_count}. No winner is inferred without verified task outcomes.",
        "Read-only equation and context sensitivity experiment; no correctness, safety, authorization, or equation-ranking claim",
    )
    document["tournament_event_id"] = event["id"]
    atomic_write(path, json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    report = {**base_report, "tournament": document}
    atomic_write(
        measurement.path / "accessible-volume.json",
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
    )
    return PredictionRun(measurement.path, report, event)
