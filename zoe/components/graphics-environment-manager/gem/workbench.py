from __future__ import annotations

import math

from .field import EquationRegistry
from .mirror import MirroredBrain
from .causal import causal_repertoire, two_way_accessible_record
from .hourglass import q_arrow_annotation


MIRROR_ID = "brain/mirror@v1"


def _matches(expected, actual):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and _matches(value, actual[key]) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(expected) == len(actual) and all(_matches(left, right) for left, right in zip(expected, actual))
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        return isinstance(actual, (int, float)) and not isinstance(actual, bool) and math.isclose(expected, actual, rel_tol=1e-9, abs_tol=1e-9)
    return expected == actual


class Workbench:
    def __init__(self, registry=None, mirror=None):
        self.registry = registry or EquationRegistry()
        self.registry.register("causal/repertoire@v1", causal_repertoire, chamber="deterministic", equation="rho_m(x0|x1) = K_m(x1|x0) mu(x0) / normalization", status="toy_verified", provenance="Balduzzi & Tononi (2009), with explicit causal likelihoods and interventions", scope="A causal posterior, not a next-token forecast or general IIT calculator.")
        self.registry.register("causal/q-arrow@v1", q_arrow_annotation, chamber="deterministic", equation="(ei, delta QA_tau, states in, states out)", status="toy_verified", provenance="Accessible Q-Volume annotation proposed in the Zoe collaboration", scope="Information and accessible-set annotation; Phi and gamma remain separate.")
        self.registry.register("causal/two-way@v1", two_way_accessible_record, chamber="deterministic", equation="(accessible causal pasts, accessible forecast futures)", status="toy_verified", provenance="Nicholas's threshold operator applied in two explicitly separate directions", scope="An explicit forecast and context are required; no internal-state mapping is inferred.")
        self.mirror = mirror or MirroredBrain()

    def catalog(self):
        specifications = self.registry.specifications()
        specifications.append({
            "id": MIRROR_ID,
            "chamber": "stochastic",
            "equation": "paired forward/retrograde observations; agreement and forward minus retrograde volume",
            "status": "stored_evidence_verified",
            "provenance": "HELEN seed-7 held-out categorical distributions",
            "scope": "Paired evaluation, not a time-reversed model, implicit mixture, causal reconstruction, or consciousness measurement.",
        })
        return specifications

    def evaluate(self, identifier, **inputs):
        if identifier == MIRROR_ID:
            result = self.mirror.observe(**inputs)
        else:
            result = self.registry.evaluate(identifier, **inputs)
        return {"equation": identifier, "inputs": inputs, "result": result, "belief_updated": False, "executed": False}

    @staticmethod
    def fixtures():
        baseline = [0.70, 0.20, 0.08, 0.02]
        transitions = {"A": {"A": 0.7, "B": 0.3}, "B": {"A": 0.4, "B": 0.6}}
        before = {state: 0.25 for state in ("00", "01", "10", "11")}
        after = {"00": 1 / 3, "01": 1 / 3, "10": 1 / 3, "11": 0.0}
        future = {"A": 0.70, "B": 0.20, "C": 0.08, "D": 0.02}
        return {
            "bayes/binary@v1": ({"prior": 0.5, "likelihood_true": 0.8, "likelihood_false": 0.2}, {"posterior": 0.8}),
            "volume/strict@v1": ({"probabilities": baseline, "tau": 0.05}, {"accessible_volume": 3, "normalized_accessible_volume": 0.75}),
            "forecast/measure@v1": ({"probabilities": baseline, "tau": 0.05, "target": 0}, {"accessible_volume": 3, "outcome": {"correct": True}}),
            "volume/adaptive@v1": ({"probabilities": baseline, "alpha": 0.1, "beta": 0.05}, {"effective_threshold": 0.07, "accessible_volume": 3}),
            "volume/joint@v1": ({"probabilities": [0.36, 0.24, 0.24, 0.16], "horizon": 2, "vocabulary_size": 2, "tau": 0.2}, {"accessible_volume": 3, "exact": True}),
            "volume/momentum@v1": ({"current_count": 3, "previous_count": 2}, {"accessible_momentum": 1}),
            "distribution/temperature@v1": ({"probabilities": baseline, "temperature": 2.0}, {"probabilities": [math.sqrt(value) / sum(math.sqrt(item) for item in baseline) for value in baseline]}),
            "sample/categorical@v1": ({"probabilities": baseline, "seed": 7}, {"selected_index": 0, "generator": "Python random MT19937; one reproducible pseudo-random draw"}),
            "process/markov-step@v1": ({"initial": {"A": 0.6, "B": 0.4}, "transitions": transitions}, {"following": {"A": 0.58, "B": 0.42}}),
            "process/continuation@v1": ({"horizon": 3, "initial": {"A": 0.6, "B": 0.4}, "transitions": transitions, "tau": 0.1}, {"accessible_volume": 5, "exact": True}),
            "timing/rmse@v1": ({"predicted": [0, 1, 2], "observed": [0, 2, 4]}, {"rmse": math.sqrt(5 / 3)}),
            "geometry/procrustes@v1": ({"source": [[0, 0], [1, 0], [0, 1]], "target": [[1, 1], [3, 1], [1, 3]]}, {"scale": 2.0, "rmse_per_landmark": 0.0}),
            "heuristic/inspection-priority@v1": ({"decision_value": 10, "expected_information_gain": 0.5, "effort": 2}, {"priority": 2.5, "status": "heuristic_not_a_probability_or_validated_control_policy"}),
            "causal/repertoire@v1": ({"likelihoods": {"00": 1, "01": 1, "10": 1, "11": 0}}, after),
            "causal/q-arrow@v1": ({"before": before, "after": after, "tau": 0.2}, {"delta_accessible_q_volume": -1, "exited": ["11"], "ei_bits": math.log2(4 / 3)}),
            "causal/two-way@v1": ({"past": after, "future": future, "tau": 0.05}, {"past": {"accessible_q_volume": 3}, "future": {"accessible_volume": 3}}),
            MIRROR_ID: ({"index": 0}, {"observation_count": 1, "current": {"index": 0, "source": "helen.mirror.seed7", "executed": False}}),
        }

    def verify(self):
        results = []
        fixtures = self.fixtures()
        for specification in self.catalog():
            identifier = specification["id"]
            inputs, expected = fixtures[identifier]
            if identifier == MIRROR_ID:
                evaluator = Workbench()
                outcome = evaluator.evaluate(identifier, **inputs)["result"]
                current = outcome["current"]
                invariant = (
                    current["volume_delta"] == current["accessible_volume"]["forward"] - current["accessible_volume"]["retrograde"]
                    and current["argmax_agreement"] == (current["forward"]["predicted_target"] == current["retrograde"]["predicted_target"])
                    and current["accessible_volume"]["forward"] + current["complement_volume"]["forward"] == 8
                    and current["accessible_volume"]["retrograde"] + current["complement_volume"]["retrograde"] == 8
                    and outcome["history"] == [current]
                )
            else:
                outcome = self.registry.evaluate(identifier, **inputs)
                invariant = True
            passed = _matches(expected, outcome) and invariant
            results.append({"equation": identifier, "passed": passed, "expected": expected, "result": outcome, "scope": specification["scope"]})
        passed = sum(result["passed"] for result in results)
        return {
            "schema_version": 1,
            "instrument": "Zoe unified workbench verification",
            "algorithm_count": len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "executed": False,
            "results": results,
        }
