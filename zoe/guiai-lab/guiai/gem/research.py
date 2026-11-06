from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from .brain import toy_horizon
from .volume import accessible_volume


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _close(actual, expected, tolerance=1e-12):
    return math.isclose(actual, expected, rel_tol=0.0, abs_tol=tolerance)


class ResearchPack:
    def __init__(self, root=None):
        self.root = Path(root).expanduser().resolve() if root is not None else None
        self.document = None
        self.groove = None
        self.nightingale = None
        self._npz = None
        self._prediction_hash_checked = False

    @classmethod
    def load(cls, root):
        pack = cls(root)
        path = pack.root / "evidence/master-gem/conformance.json"
        pack.document = json.loads(path.read_text(encoding="utf-8"))
        if pack.document.get("schema_version") != 1:
            raise ValueError("unsupported MASTER GEM conformance schema")
        pack.groove = pack._read_json(pack.document["groove"]["report"], pack.document["groove"]["report_sha256"])
        pack.nightingale = pack._read_json(pack.document["nightingale"]["results"], pack.document["nightingale"]["results_sha256"])
        return pack

    def _read_json(self, relative, expected_hash):
        path = self.root / relative
        if _sha256(path) != expected_hash:
            raise ValueError(f"research evidence hash mismatch: {relative}")
        return json.loads(path.read_text(encoding="utf-8"))

    def cases(self):
        if self.document is None:
            return []
        rows = []
        labels = {"forward": "Forward", "reversal_transfer": "Reversal transfer", "backward_matched": "Backward matched"}
        for condition, metrics in self.groove["conditions"].items():
            rows.append({
                "id": f"groove:{condition}", "dataset": "Magenta Groove",
                "label": f"Groove · {labels[condition]}", "condition": condition,
                "observations": metrics["predictions"], "metrics": metrics, "observable": True,
            })
        for genre, conditions in self.nightingale.items():
            for direction, metrics in conditions.items():
                rows.append({
                    "id": f"nightingale:{genre}:{direction}", "dataset": f"Nightingale {genre}",
                    "label": f"Nightingale {genre} · {direction}", "condition": direction,
                    "observations": metrics["n"], "metrics": metrics, "observable": False,
                })
        return rows

    def case(self, identifier):
        for row in self.cases():
            if row["id"] == identifier:
                return row
        raise ValueError(f"unknown research case: {identifier}")

    def observe(self, identifier, index):
        row = self.case(identifier)
        if not row["observable"]:
            raise ValueError("Nightingale evidence in this pack is aggregate-only; no saved per-onset distributions")
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < row["observations"]:
            raise ValueError(f"research index must be between 0 and {row['observations']-1}")
        relative = self.document["groove"]["predictions"]
        if not self._prediction_hash_checked:
            if _sha256(self.root / relative) != self.document["groove"]["predictions_sha256"]:
                raise ValueError("Groove prediction archive hash mismatch")
            self._prediction_hash_checked = True
        if self._npz is None:
            import numpy as np
            self._npz = np.load(self.root / relative, allow_pickle=False)
        condition = row["condition"]
        probabilities = self._npz[f"{condition}_probabilities"][index].astype(float).tolist()
        target = int(self._npz[f"{condition}_targets"][index])
        return probabilities, target

    def verify_conformance(self):
        if self.document is None:
            raise ValueError("no research pack loaded")
        checks = []
        strict = self.document["strict_volume"]
        count = accessible_volume(strict["probabilities"], strict["tau"])
        checks.append({"case": "strict-volume", "passed": count == strict["accessible_volume"] and len(strict["probabilities"])-count == strict["complement_volume"]})
        from .field import EquationRegistry, bayes_binary
        field = self.document["bayesian_field"]
        update = field["worked_update"]
        result = bayes_binary(update["prior"], update["likelihood_true"], update["likelihood_false"])
        checks.append({"case": "bayes-binary", "passed": _close(result["posterior"], update["posterior"])})
        checks.append({"case": "field-equation-count", "passed": len(EquationRegistry().specifications()) == field["equation_sections"]})
        from .atlas import procrustes
        expected = self.document["procrustes"]
        result = procrustes(expected["source"], expected["target"])
        passed = _close(result["scale"], expected["scale"], 1e-10) and result["rmse_per_landmark"] <= expected["rmse_per_landmark_tolerance"]
        passed = passed and all(_close(value, target, 1e-9) for row, expected_row in zip(result["matrix"], expected["matrix"]) for value, target in zip(row, expected_row))
        checks.append({"case": "procrustes", "passed": passed, "rmse_per_landmark": result["rmse_per_landmark"]})
        for case in self.document["toy_markov_chain"]["cases"]:
            result = toy_horizon(case["horizon"], case["tau"])
            checks.append({
                "case": f"toy-h{case['horizon']}-tau{case['tau']}",
                "passed": result["accessible_volume"] == case["accessible_volume"] and result["complement_volume"] == case["complement_volume"],
            })
        for condition, expected_metrics in self.document["groove"]["conditions"].items():
            actual = self.groove["conditions"][condition]
            passed = all(_close(actual[key], value) for key, value in expected_metrics.items())
            checks.append({"case": f"groove-{condition}", "passed": passed})
        total = 0
        for genre, expected_conditions in self.document["nightingale"]["genres"].items():
            for direction, expected_metrics in expected_conditions.items():
                actual = self.nightingale[genre][direction]
                if direction == "forward":
                    total += actual["n"]
                passed = all(_close(actual[key], value) for key, value in expected_metrics.items())
                checks.append({"case": f"nightingale-{genre}-{direction}", "passed": passed})
        checks.append({"case": "nightingale-total", "passed": total == self.document["nightingale"]["predictions_per_direction"]})
        return checks


def research_scene(pack, identifier=None):
    from .atlas import _scene, _text

    height = 230 if pack.document is None else 390
    background = {"id": "background", "type": "rectangle", "bounds": [0, 0, 1000, height], "stroke": "#070b14", "fill": "#070b14", "width": 1}
    if pack.document is None:
        objects = [
            background,
            _text("title", [36, 38], "RESEARCH PACK · external evidence adapter", 22, "#fde68a"),
            _text("instructions", [36, 82], "Launch with MASTER_GEM_RESEARCH_ROOT=/path/to/next-token-predictability", 14, "#e5eefb"),
            _text("lazy", [36, 118], "Reports load on demand · Groove NPZ loads only when an observation is requested", 12, "#9fb1c8"),
            _text("scope", [36, 154], "No source data is copied into the native runtime", 12, "#fca5a5"),
        ]
        return _scene("atlas-research", 1000, 230, objects, "Research evidence pack"), {"summary": "No research pack loaded", "cases": []}
    rows = pack.cases()
    selected = pack.case(identifier or rows[0]["id"])
    metrics = selected["metrics"]
    objects = [
        background,
        _text("title", [36, 38], "RESEARCH PACK · verified real evidence", 22, "#fde68a"),
        _text("case", [36, 76], selected["label"], 19, "#e5eefb"),
        _text("observations", [36, 106], f"Held-out observations: {selected['observations']:,}", 13, "#9fb1c8"),
    ]
    if selected["observable"]:
        lines = [
            f"Top-1 {metrics['top_1_accuracy']:.4%}   Top-5 {metrics['top_5_accuracy']:.4%}",
            f"Log-loss {metrics['log_loss_nats']:.6f}   ECE {metrics['expected_calibration_error']:.6f}",
            f"Mean accessible volume over sweep {metrics['mean_accessible_volume_over_sweep']:.6f}",
            f"Sweep area {metrics['accessible_volume_sweep_area']:.6f}",
            "Individual saved distributions available to BRAIN on demand",
        ]
    else:
        lines = [
            f"Top-1 {metrics['top1']:.4%}   Log-loss {metrics['logloss']:.6f}",
            f"A(0.1) {metrics['a_0.1']:.6f}   ECE {metrics['ece']:.6f}",
            f"Persistence {metrics['persistence_top1']:.4%}   Linear {metrics['linear_top1']:.4%}",
            "Aggregate-only evidence: no saved per-onset distributions",
            "Use the separate real-MIDI script to regenerate individual forecasts",
        ]
    for index, line in enumerate(lines):
        objects.append(_text(f"metric-{index}", [48, 150+index*35], line, 15, "#9fb1c8" if index != 4 else "#67e8f9"))
    objects.append(_text("scope", [36, 350], "Metrics belong to their model, context, quantization, and held-out split · breadth is not correctness", 12, "#fca5a5"))
    summary = f"{selected['label']}: " + " · ".join(lines[:3])
    return _scene("atlas-research", 1000, 390, objects, "Research evidence pack"), {"summary": summary, "case": selected}
