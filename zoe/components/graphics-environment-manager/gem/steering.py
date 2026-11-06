import json

from .events import atomic_write
from .prediction import PredictionRun, measure_session


MODES = {
    "propose_with_verification": {
        "level": 0,
        "label": "Propose with verification",
        "summary": "The distribution is comparatively narrow under these heuristics. A proposal may proceed only to deterministic verification.",
        "allowed_actions": ["read", "inspect evidence", "propose", "verify"],
    },
    "review_with_human": {
        "level": 1,
        "label": "Review with a human",
        "summary": "The distribution is broad enough to warrant human review or comparison of alternatives before further work.",
        "allowed_actions": ["read", "inspect evidence", "compare alternatives", "request human review"],
    },
    "gather_evidence": {
        "level": 2,
        "label": "Gather evidence",
        "summary": "The distribution is broad under these heuristics. Stay read-only and gather more evidence before proposing an action.",
        "allowed_actions": ["read", "search", "inspect evidence", "request human guidance"],
    },
}


def _sweep_value(report, threshold):
    return next((item["accessible_volume"] for item in report["threshold_sweep"] if item["tau"] == threshold), None)


def evaluate_advisory(report, previous=None):
    a002 = _sweep_value(report, 0.02)
    a005 = _sweep_value(report, 0.05)
    entropy = report["entropy_bits"]
    signals = {
        "accessible_volume_002": a002,
        "accessible_volume_005": a005,
        "entropy_bits": entropy,
        "max_probability": report["max_probability"],
        "top_10_probability_mass": report["top_10_probability_mass"],
    }
    reasons = []
    if a002 >= 8 or a005 >= 4 or entropy >= 6.0:
        level = 2
        reasons.append(f"Broad baseline: A(0.02)={a002}, A(0.05)={a005}, entropy={entropy:.3f} bits.")
    elif a005 >= 2 or entropy >= 5.0:
        level = 1
        reasons.append(f"Review baseline: A(0.05)={a005}, entropy={entropy:.3f} bits.")
    else:
        level = 0
        reasons.append(f"Narrow baseline: A(0.05)={a005}, entropy={entropy:.3f} bits; this does not establish correctness.")
    trend = {"status": "no previous measurement", "escalated": False}
    if previous is not None and previous.get("model_id") == report["model"]["id"] and previous.get("selected_id") == report["gem_context"]["selected_id"]:
        old = previous["signals"]
        volume_delta = a005 - old["accessible_volume_005"]
        entropy_delta = entropy - old["entropy_bits"]
        escalated = abs(volume_delta) >= 4 or abs(entropy_delta) >= 1.0
        if escalated and level < 2:
            level += 1
            reasons.append("A large change from the previous measurement increased the caution level by one step.")
        trend = {
            "status": "compared with previous measurement",
            "accessible_volume_005_delta": volume_delta,
            "entropy_bits_delta": entropy_delta,
            "escalated": escalated,
        }
    elif previous is not None:
        trend = {"status": "previous measurement used a different model or selection; no trend comparison", "escalated": False}
    mode = next(name for name, configuration in MODES.items() if configuration["level"] == level)
    configuration = MODES[mode]
    return {
        "schema_version": 1,
        "instrument": "deterministic accessible-volume advisory",
        "model_id": report["model"]["id"],
        "selected_id": report["gem_context"]["selected_id"],
        "revision": report["gem_context"]["revision"],
        "mode": mode,
        "label": configuration["label"],
        "summary": configuration["summary"],
        "reasons": reasons,
        "signals": signals,
        "trend": trend,
        "allowed_actions": configuration["allowed_actions"],
        "prohibited_actions": [
            "autonomous execution",
            "permission escalation based on breadth or entropy",
            "using a narrow distribution as proof of correctness or safety",
        ],
        "heuristics": {
            "gather_evidence": "A(0.02) >= 8 or A(0.05) >= 4 or entropy >= 6 bits",
            "review_with_human": "A(0.05) >= 2 or entropy >= 5 bits",
            "trend_escalation": "absolute A(0.05) delta >= 4 or absolute entropy delta >= 1 bit, by at most one level",
        },
        "scope": [
            "This is an inspectable heuristic recommendation, not an authorization decision or a correctness/safety judgment.",
            "Narrow breadth never unlocks execution; every proposal still requires the existing action gate and verification.",
            "Trends are compared only for measurements from the same model and selected item.",
        ],
    }


def latest_advisory(session):
    paths = sorted(
        (session.root / "prediction-runs").glob("*/advisory.json"),
        key=lambda path: path.stat().st_mtime_ns,
    )
    if not paths:
        return None
    path = paths[-1]
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("signals"), dict):
        raise ValueError(f"invalid previous advisory: {path}")
    return document


def advise_session(session, model_dir=None, thresholds=None, predictor=None):
    previous = latest_advisory(session)
    if thresholds is None:
        from .prediction import THRESHOLDS
        thresholds = THRESHOLDS
    measurement = measure_session(
        session, model_dir=model_dir, thresholds=thresholds, predictor=predictor,
    )
    advisory = evaluate_advisory(measurement.report, previous)
    advisory["measurement_event_id"] = measurement.evidence["id"]
    advisory_path = measurement.path / "advisory.json"
    atomic_write(advisory_path, json.dumps(advisory, indent=2, ensure_ascii=False) + "\n")
    report = {**measurement.report, "advisory": advisory}
    atomic_write(
        measurement.path / "accessible-volume.json",
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
    )
    latest = session.current_state()
    context = measurement.report["gem_context"]
    if latest["selected_id"] != context["selected_id"] or latest["revision"] != context["revision"]:
        raise ValueError("selection changed before advisory emission; measurement retained without a new advisory node")
    event = session.emit(
        f"observation:advisory:{report['run_digest'][:24]}",
        measurement.evidence["id"],
        "observation",
        f"Advisory · {advisory['label']}",
        "complete_scoped",
        "tool",
        advisory_path.relative_to(session.root).as_posix(),
        "\n".join([
            advisory["summary"],
            *advisory["reasons"],
            "Allowed action categories: " + ", ".join(advisory["allowed_actions"]),
            "No autonomous execution or permission escalation is authorized by this recommendation.",
        ]),
        "Heuristic next-action advisory from one local token distribution; read-only guidance only, never correctness, safety, or execution authority",
    )
    advisory["advisory_event_id"] = event["id"]
    report["advisory"] = advisory
    atomic_write(advisory_path, json.dumps(advisory, indent=2, ensure_ascii=False) + "\n")
    atomic_write(
        measurement.path / "accessible-volume.json",
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
    )
    return PredictionRun(measurement.path, report, event)
