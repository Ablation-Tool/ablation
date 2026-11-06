from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import random


MAX_PROBABILITIES = 1_000_000
DISPOSITIONS = {"active", "experimental", "rejected", "quarantined"}
CLAIM_STATUSES = {"unknown", "speculative", "supported", "rejected", "quarantined"}


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _text(value, label, maximum=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} must contain 1–{maximum} characters")
    return value.strip()


def _number(value, label, minimum=None, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    result = float(value)
    if minimum is not None and result < minimum or maximum is not None and result > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return result


def _probability(value, label, endpoints=False):
    result = _number(value, label, 0, 1)
    if not endpoints and not 0 < result < 1:
        raise ValueError(f"{label} must be strictly between zero and one")
    return result


def _likelihood(value, label):
    result = _probability(value, label, endpoints=True)
    if result == 0:
        raise ValueError(f"{label} must be greater than zero")
    return result


def _distribution(values):
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= MAX_PROBABILITIES:
        raise ValueError(f"probabilities must contain 1–{MAX_PROBABILITIES} values")
    result = [_number(value, "probability", 0, 1) for value in values]
    if not math.isclose(sum(result), 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError("probabilities must sum to one within 1e-9")
    return result


def _index(value, size, label="target"):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < size:
        raise ValueError(f"{label} must be a valid categorical index")
    return value


def bayes_binary(prior, likelihood_true, likelihood_false):
    prior = _probability(prior, "prior")
    likelihood_true = _likelihood(likelihood_true, "likelihood_true")
    likelihood_false = _likelihood(likelihood_false, "likelihood_false")
    ratio = likelihood_true / likelihood_false
    if not math.isfinite(ratio):
        raise ValueError("likelihood ratio must be finite")
    prior_log_odds = math.log(prior) - math.log1p(-prior)
    log_ratio = math.log(ratio)
    posterior_log_odds = prior_log_odds + log_ratio
    if posterior_log_odds >= 0:
        posterior = 1 / (1 + math.exp(-posterior_log_odds))
    else:
        odds = math.exp(posterior_log_odds)
        posterior = odds / (1 + odds)
    return {
        "prior": prior,
        "posterior": posterior,
        "likelihood_true": likelihood_true,
        "likelihood_false": likelihood_false,
        "likelihood_ratio": ratio,
        "prior_log_odds": prior_log_odds,
        "log_likelihood_ratio": log_ratio,
        "posterior_log_odds": posterior_log_odds,
        "model": "independent binary claim; posterior is conditional on the supplied likelihood model",
    }


def volume_strict(probabilities, tau):
    values = _distribution(probabilities)
    tau = _probability(tau, "tau", endpoints=True)
    count = sum(value > tau for value in values)
    return {
        "tau": tau,
        "vocabulary_size": len(values),
        "accessible_volume": count,
        "normalized_accessible_volume": count / len(values),
        "complement_volume": len(values) - count,
        "normalized_complement_volume": 1 - count / len(values),
        "strict_comparison": True,
    }


def volume_adaptive(probabilities, alpha, beta):
    values = _distribution(probabilities)
    alpha = _number(alpha, "alpha", 0)
    beta = _probability(beta, "beta", endpoints=True)
    threshold = max(beta, alpha * max(values))
    count = sum(value > threshold for value in values)
    return {
        "alpha": alpha,
        "beta": beta,
        "effective_threshold": threshold,
        "accessible_volume": count,
        "normalized_accessible_volume": count / len(values),
        "complement_volume": len(values) - count,
        "strict_comparison": True,
        "evidence_status": "The selected adaptive rule transferred worse than fixed tau=0.05 in the held-out BioBERT experiment.",
    }


def forecast_measure(probabilities, tau, target=None):
    values = _distribution(probabilities)
    report = volume_strict(values, tau)
    predicted = max(range(len(values)), key=values.__getitem__)
    report.update({
        "entropy_bits": -sum(value * math.log2(value) for value in values if value > 0),
        "maximum_probability": values[predicted],
        "top_10_probability_mass": sum(sorted(values, reverse=True)[:10]),
        "predicted_target": predicted,
        "probability_values_sha256": _digest(values),
        "forecast_breadth_is_correctness": False,
    })
    if target is not None:
        target = _index(target, len(values))
        report["outcome"] = {
            "target": target,
            "correct": predicted == target,
            "actual_probability": values[target],
            "negative_log_probability": -math.log(max(values[target], 1e-300)),
            "brier_score": sum(value * value for value in values) - 2 * values[target] + 1,
        }
    return report


def volume_joint(probabilities, horizon, vocabulary_size, tau, complete=True):
    if isinstance(horizon, bool) or not isinstance(horizon, int) or not 1 <= horizon <= 8:
        raise ValueError("horizon must be an integer from 1 to 8")
    if isinstance(vocabulary_size, bool) or not isinstance(vocabulary_size, int) or vocabulary_size < 1:
        raise ValueError("vocabulary_size must be a positive integer")
    universe = vocabulary_size ** horizon
    if universe > MAX_PROBABILITIES:
        raise ValueError("joint outcome space exceeds the exact-enumeration bound")
    if not isinstance(complete, bool):
        raise ValueError("complete must be a boolean")
    if not isinstance(probabilities, (list, tuple)) or not 1 <= len(probabilities) <= universe:
        raise ValueError("joint probabilities must be a nonempty bounded candidate vector")
    values = [_number(value, "joint probability", 0, 1) for value in probabilities]
    if complete and len(values) != universe:
        raise ValueError("a complete joint distribution must contain vocabulary_size ** horizon values")
    included_mass = sum(values)
    if complete and not math.isclose(included_mass, 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError("a complete joint distribution must sum to one")
    if not complete and included_mass > 1 + 1e-9:
        raise ValueError("restricted candidate mass cannot exceed one")
    tau = _probability(tau, "tau", endpoints=True)
    count = sum(value > tau for value in values)
    return {
        "horizon": horizon,
        "vocabulary_size": vocabulary_size,
        "joint_outcome_space": universe,
        "candidate_count": len(values),
        "tau": tau,
        "accessible_volume": count,
        "complement_volume": universe - count if complete else None,
        "included_probability_mass": included_mass,
        "excluded_probability_mass": max(0.0, 1 - included_mass),
        "exact": complete,
        "lower_bound_only": not complete,
        "strict_comparison": True,
    }


def volume_momentum(current_count, previous_count):
    current = _number(current_count, "current_count", 0)
    previous = _number(previous_count, "previous_count", 0)
    if not current.is_integer() or not previous.is_integer():
        raise ValueError("accessible-volume counts must be integers")
    return {
        "current_count": int(current),
        "previous_count": int(previous),
        "accessible_momentum": int(current - previous),
        "scope": "Equal counts do not imply identical probabilities or accessible-set membership.",
    }


def temperature_transform(probabilities, temperature):
    values = _distribution(probabilities)
    temperature = _number(temperature, "temperature", 1e-9)
    weights = [value ** (1 / temperature) for value in values]
    total = sum(weights)
    if not math.isfinite(total) or total == 0:
        raise ValueError("temperature transform underflowed or overflowed")
    return {"temperature": temperature, "probabilities": [value / total for value in weights]}


def categorical_sample(probabilities, seed):
    values = _distribution(probabilities)
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    draw = random.Random(seed).random()
    cumulative = 0.0
    selected = len(values) - 1
    for index, probability in enumerate(values):
        cumulative += probability
        if draw < cumulative:
            selected = index
            break
    return {
        "seed": seed,
        "generator": "Python random MT19937; one reproducible pseudo-random draw",
        "unit_draw": draw,
        "selected_index": selected,
        "selected_probability": values[selected],
        "scope": "A sampled outcome is not evidence of correctness and authorizes no action.",
    }


def markov_step(initial, transitions):
    if not isinstance(initial, dict) or not initial:
        raise ValueError("initial must be a nonempty state-probability object")
    states = list(initial)
    initial_values = _distribution([initial[state] for state in states])
    if not isinstance(transitions, dict) or set(transitions) != set(states):
        raise ValueError("transitions must define every initial state")
    following = {state: 0.0 for state in states}
    for source, weight in zip(states, initial_values):
        row = transitions[source]
        if not isinstance(row, dict) or set(row) != set(states):
            raise ValueError("each transition row must cover the complete state vocabulary")
        probabilities = _distribution([row[state] for state in states])
        for destination, probability in zip(states, probabilities):
            following[destination] += weight * probability
    return {"initial": initial, "following": following, "equation": "pi_(n+1) = pi_n P"}


def markov_continuations(horizon, initial, transitions, tau):
    if isinstance(horizon, bool) or not isinstance(horizon, int) or not 1 <= horizon <= 8:
        raise ValueError("horizon must be an integer from 1 to 8")
    if not isinstance(initial, dict) or len(initial) ** horizon > MAX_PROBABILITIES:
        raise ValueError("continuation space exceeds the exact-enumeration bound")
    from .brain import enumerate_markov_continuations, multi_horizon_measure
    sequences = enumerate_markov_continuations(horizon, initial, transitions)
    return multi_horizon_measure(sequences, tau)


def timing_rmse(predicted, observed):
    if not isinstance(predicted, (list, tuple)) or not isinstance(observed, (list, tuple)) or not predicted or len(predicted) != len(observed):
        raise ValueError("predicted and observed must be equal-length nonempty vectors")
    errors = [
        _number(actual, "observed") - _number(forecast, "predicted")
        for forecast, actual in zip(predicted, observed)
    ]
    return {"errors": errors, "rmse": math.sqrt(sum(error * error for error in errors) / len(errors))}


def procrustes_measure(source, target, mode="similarity"):
    from .atlas import procrustes
    return procrustes(source, target, mode)


def inspection_priority(decision_value, expected_information_gain, effort):
    value = _number(decision_value, "decision_value", 0)
    information = _number(expected_information_gain, "expected_information_gain", 0)
    effort = _number(effort, "effort", 1e-12)
    return {
        "priority": value * information / effort,
        "status": "heuristic_not_a_probability_or_validated_control_policy",
    }


class EquationRegistry:
    def __init__(self, include_defaults=True):
        self._equations = {}
        if include_defaults:
            self._register_defaults()

    def register(self, identifier, function, *, chamber="both", equation="", status="experimental", provenance="custom", scope=""):
        identifier = _text(identifier, "equation identifier", 128)
        if identifier in self._equations or not callable(function):
            raise ValueError("equation must be new and callable")
        if chamber not in {"deterministic", "stochastic", "both"}:
            raise ValueError("equation chamber must be deterministic, stochastic, or both")
        self._equations[identifier] = {
            "id": identifier,
            "function": function,
            "chamber": chamber,
            "equation": equation,
            "status": status,
            "provenance": provenance,
            "scope": scope,
        }
        return self.specification(identifier)

    def _register_defaults(self):
        source = "next-token-predictability and Zoe numerical conformance"
        self.register("bayes/binary@v1", bayes_binary, equation="P(H|E) = LR · P(H) / (1 - P(H) + LR · P(H))", status="core", provenance="Bayes' theorem", scope="Binary claims with explicit likelihoods; dependent evidence requires adjusted likelihoods.")
        self.register("volume/strict@v1", volume_strict, equation="A_tau = sum_i 1[p_i > tau]; A_norm = A_tau / |O|", status="core", provenance=source, scope="Forecast breadth, not correctness; tokens exactly at tau are excluded.")
        self.register("forecast/measure@v1", forecast_measure, equation="A_tau with entropy, maximum mass, optional log loss and Brier score", status="core", provenance=source, scope="A deterministic measurement of a supplied stochastic or deterministic forecast.")
        self.register("volume/adaptive@v1", volume_adaptive, equation="A_alpha,beta = sum_i 1[p_i > max(beta, alpha · p_max)]", status="tested_negative_transfer", provenance=source, scope="Retain as a comparison; the selected adaptive rule did not transfer better on held-out BioBERT cases.")
        self.register("volume/joint@v1", volume_joint, equation="A_tau^(h) = sum 1[P_h(a_1:h | C_t) > tau]", status="core", provenance=source, scope="Complete vectors produce exact counts; restricted vectors produce lower bounds only.")
        self.register("volume/momentum@v1", volume_momentum, chamber="deterministic", equation="M_tau,i = A_tau,i - A_tau,i-1", status="core", provenance=source)
        self.register("distribution/temperature@v1", temperature_transform, chamber="stochastic", equation="p'_k(T) = p_k^(1/T) / sum_j p_j^(1/T)", status="experimental", provenance=source)
        self.register("sample/categorical@v1", categorical_sample, chamber="stochastic", equation="X ~ categorical(p); seed and generator recorded", status="experimental", provenance="Brian D. Ripley, Stochastic Simulation: record the generator and treat simulation as experiment")
        self.register("process/markov-step@v1", markov_step, chamber="stochastic", equation="pi_(n+1) = pi_n P", status="core", provenance="Giuseppe Modica and Laura Poggiolini, A First Course in Probability and Markov Chains")
        self.register("process/continuation@v1", markov_continuations, chamber="stochastic", equation="P_h(a_1:h | C_t) = product_j p(a_j | C_t+j-1, a_<j)", status="core", provenance=source, scope="Exact bounded Markov enumeration only; not a real language-model benchmark.")
        self.register("timing/rmse@v1", timing_rmse, chamber="deterministic", equation="E = sqrt((1/n) sum_i (t_i - t_hat_i)^2)", status="core", provenance=source)
        self.register("geometry/procrustes@v1", procrustes_measure, chamber="deterministic", equation="D(p,q) after similarity, rigid, or affine alignment", status="core", provenance="Zoe geometry atlas and next-token-predictability")
        self.register("heuristic/inspection-priority@v1", inspection_priority, equation="priority = decision value · expected information gain / effort", status="heuristic", provenance="Zoe field notebook", scope="Inspection triage only; not a probability, reward, or authorization rule.")

    def specification(self, identifier):
        if identifier not in self._equations:
            raise ValueError(f"unknown equation: {identifier}")
        return {key: deepcopy(value) for key, value in self._equations[identifier].items() if key != "function"}

    def specifications(self):
        return [self.specification(identifier) for identifier in sorted(self._equations)]

    def evaluate(self, identifier, **inputs):
        specification = self.specification(identifier)
        try:
            result = self._equations[identifier]["function"](**inputs)
        except TypeError as error:
            raise ValueError(f"invalid inputs for {identifier}: {error}") from error
        _canonical(result)
        return result


class FieldNotebook:
    def __init__(self, registry=None):
        self.registry = registry or EquationRegistry()
        self.events = []
        self.questions = []
        self.claims = []
        self.evidence = []
        self.chambers = []
        self.measurements = []
        self.observations = []
        self.tests = []
        self.decisions = []

    def _append(self, kind, payload):
        event = {
            "sequence": len(self.events) + 1,
            "kind": kind,
            "payload": deepcopy(payload),
            "previous_hash": self.events[-1]["hash"] if self.events else None,
        }
        event["hash"] = _digest(event)
        self.events.append(event)
        self._apply(event)
        return deepcopy(payload)

    def _apply(self, event):
        kind = event["kind"]
        payload = event["payload"]
        if kind == "question_added":
            self.questions.append(deepcopy(payload["question"]))
        elif kind == "claim_added":
            self.claims.append(deepcopy(payload["claim"]))
        elif kind == "evidence_added":
            self.evidence.append(deepcopy(payload["evidence"]))
            claim = self.claim(payload["evidence"]["claim_id"])
            claim["posterior"] = payload["update"]["posterior"]
            claim["updates"].append(deepcopy(payload["update"]))
        elif kind == "chamber_added":
            self.chambers.append(deepcopy(payload["chamber"]))
        elif kind == "measurement_recorded":
            self.measurements.append(deepcopy(payload["measurement"]))
        elif kind == "brain_observation_recorded":
            self.observations.append(deepcopy(payload["observation"]))
        elif kind == "test_added":
            self.tests.append(deepcopy(payload["test"]))
        elif kind == "decision_recorded":
            self.decisions.append(deepcopy(payload["decision"]))
        else:
            raise ValueError(f"unsupported field event: {kind}")

    def question(self, identifier):
        for question in self.questions:
            if question["id"] == identifier:
                return question
        raise ValueError(f"unknown question: {identifier}")

    def claim(self, identifier):
        for claim in self.claims:
            if claim["id"] == identifier:
                return claim
        raise ValueError(f"unknown claim: {identifier}")

    def chamber(self, identifier):
        for chamber in self.chambers:
            if chamber["id"] == identifier:
                return chamber
        raise ValueError(f"unknown chamber: {identifier}")

    def add_question(self, text, context=""):
        question = {
            "id": f"q-{len(self.questions)+1}",
            "text": _text(text, "question", 1000),
            "context": context.strip() if isinstance(context, str) else "",
            "status": "open",
        }
        return self._append("question_added", {"question": question})["question"]

    def add_claim(self, question_id, statement, prior=.5, falsifier="", status="speculative"):
        self.question(question_id)
        prior = _probability(prior, "prior")
        if status not in CLAIM_STATUSES:
            raise ValueError("invalid claim status")
        claim = {
            "id": f"c-{len(self.claims)+1}",
            "question_id": question_id,
            "statement": _text(statement, "claim", 2000),
            "falsifier": falsifier.strip() if isinstance(falsifier, str) else "",
            "prior": prior,
            "posterior": prior,
            "status": status,
            "updates": [],
            "model": "independent binary claim; claims in a question are not automatically mutually exclusive",
        }
        return self._append("claim_added", {"claim": claim})["claim"]

    def add_evidence(self, claim_id, text, likelihood_true, likelihood_false, *, source="human", family=None, direction="supports", chamber_id=None, dependence_acknowledged=False):
        claim = self.claim(claim_id)
        text = _text(text, "evidence", 4000)
        source = _text(source, "evidence source", 1000)
        if direction not in {"supports", "challenges", "mixed", "unknown"}:
            raise ValueError("evidence direction must be supports, challenges, mixed, or unknown")
        if family is not None:
            family = _text(family, "evidence family", 256)
            related = [item for item in self.evidence if item["claim_id"] == claim_id and item["family"] == family]
            if related and not dependence_acknowledged:
                raise ValueError("evidence family already updated this claim; acknowledge dependence and adjust likelihoods before counting it again")
        if chamber_id is not None:
            self.chamber(chamber_id)
        update = bayes_binary(claim["posterior"], likelihood_true, likelihood_false)
        evidence = {
            "id": f"e-{len(self.evidence)+1}",
            "claim_id": claim_id,
            "text": text,
            "source": source,
            "family": family,
            "direction": direction,
            "chamber_id": chamber_id,
            "dependence_acknowledged": bool(dependence_acknowledged),
            "verification": "user-supplied likelihood assessment; not an automatic truth judgment",
        }
        update.update({"evidence_id": evidence["id"], "prior": claim["posterior"]})
        self._append("evidence_added", {"evidence": evidence, "update": update})
        return deepcopy(self.evidence[-1])

    def add_chamber(self, name, mode, equation, *, disposition="experimental", parameters=None, provenance="custom"):
        if mode not in {"deterministic", "stochastic"}:
            raise ValueError("chamber mode must be deterministic or stochastic")
        if disposition not in DISPOSITIONS:
            raise ValueError("invalid chamber disposition")
        specification = self.registry.specification(equation)
        if specification["chamber"] not in {"both", mode}:
            raise ValueError(f"{equation} cannot run in a {mode} chamber")
        chamber = {
            "id": f"ch-{len(self.chambers)+1}",
            "name": _text(name, "chamber name", 256),
            "mode": mode,
            "equation": equation,
            "disposition": disposition,
            "parameters": deepcopy(parameters or {}),
            "provenance": provenance,
            "executed": False,
        }
        _canonical(chamber["parameters"])
        return self._append("chamber_added", {"chamber": chamber})["chamber"]

    def run_chamber(self, chamber_id, **inputs):
        chamber = self.chamber(chamber_id)
        if chamber["disposition"] == "quarantined":
            raise ValueError("quarantined chambers are inspectable but cannot be evaluated")
        combined = deepcopy(chamber["parameters"])
        combined.update(inputs)
        result = self.registry.evaluate(chamber["equation"], **combined)
        stored_inputs = deepcopy(combined)
        storage = "complete"
        probabilities = stored_inputs.get("probabilities")
        if isinstance(probabilities, list) and len(probabilities) > 64:
            stored_inputs["probabilities"] = {
                "length": len(probabilities),
                "sha256": _digest(probabilities),
            }
            storage = "probability-digest-only; full vector not embedded"
        measurement = {
            "id": f"m-{len(self.measurements)+1}",
            "chamber_id": chamber_id,
            "mode": chamber["mode"],
            "disposition": chamber["disposition"],
            "equation": chamber["equation"],
            "inputs": stored_inputs,
            "input_storage": storage,
            "result": result,
            "belief_updated": False,
            "executed": False,
        }
        return self._append("measurement_recorded", {"measurement": measurement})["measurement"]

    def record_brain_observation(self, current, question_id=None):
        if not isinstance(current, dict) or "accessible_volume" not in current:
            raise ValueError("a current BRAIN observation is required")
        if question_id is not None:
            self.question(question_id)
        observation = {
            "id": f"o-{len(self.observations)+1}",
            "question_id": question_id,
            "source": current,
            "belief_updated": False,
            "executed": False,
            "scope": "MASTER GEM forecast observation preserved without treating breadth as evidence of truth",
        }
        return self._append("brain_observation_recorded", {"observation": observation})["observation"]

    def add_test(self, question_id, statement, decision_value, expected_information_gain, effort):
        self.question(question_id)
        result = inspection_priority(decision_value, expected_information_gain, effort)
        test = {
            "id": f"t-{len(self.tests)+1}",
            "question_id": question_id,
            "statement": _text(statement, "test", 2000),
            "decision_value": float(decision_value),
            "expected_information_gain": float(expected_information_gain),
            "effort": float(effort),
            "priority": result["priority"],
            "status": result["status"],
            "completed": False,
        }
        return self._append("test_added", {"test": test})["test"]

    def record_decision(self, question_id, choice, rationale):
        self.question(question_id)
        decision = {
            "id": f"d-{len(self.decisions)+1}",
            "question_id": question_id,
            "choice": _text(choice, "decision choice", 1000),
            "rationale": _text(rationale, "decision rationale", 4000),
            "review_required": True,
            "executed": False,
        }
        return self._append("decision_recorded", {"decision": decision})["decision"]

    def state(self):
        return {
            "schema_version": 1,
            "instrument": "Zoe Bayesian field notebook",
            "questions": deepcopy(self.questions),
            "claims": deepcopy(self.claims),
            "evidence": deepcopy(self.evidence),
            "chambers": deepcopy(self.chambers),
            "measurements": deepcopy(self.measurements),
            "observations": deepcopy(self.observations),
            "tests": deepcopy(self.tests),
            "decisions": deepcopy(self.decisions),
            "equations": self.registry.specifications(),
            "event_count": len(self.events),
            "head_hash": self.events[-1]["hash"] if self.events else None,
            "executed": False,
        }

    def document(self):
        return {
            "schema_version": 1,
            "instrument": "zoe-field-notebook",
            "integrity": "canonical-json-sha256-chain; tamper evidence, not authentication",
            "events": deepcopy(self.events),
        }

    def save(self, path):
        path = Path(path)
        if path.suffix.lower() != ".json":
            raise ValueError("field notebook memory must use a .json path")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            json.dump(self.document(), stream, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
            stream.write("\n")
        return path

    @classmethod
    def load(cls, path, registry=None):
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("schema_version") != 1 or document.get("instrument") != "zoe-field-notebook":
            raise ValueError("unsupported field notebook document")
        events = document.get("events")
        if not isinstance(events, list):
            raise ValueError("field notebook events must be a list")
        notebook = cls(registry=registry)
        for event in events:
            if not isinstance(event, dict) or not isinstance(event.get("kind"), str) or "payload" not in event:
                raise ValueError("invalid field notebook event")
            notebook._append(event["kind"], event["payload"])
            if notebook.events[-1] != event:
                raise ValueError(f"field notebook hash-chain mismatch at event {len(notebook.events)}")
        return notebook

    @classmethod
    def demo(cls):
        notebook = cls()
        question = notebook.add_question(
            "What is DEMOMENU in the 1986 Programmer's Guide to GEM?",
            "A worked example showing primary-source claims, counterevidence, deterministic measurement, and stochastic sampling.",
        )
        claim = notebook.add_claim(
            question["id"],
            "DEMOMENU names the DEMO application's main menu object tree: resource tree 0.",
            prior=.62,
            falsifier="A primary-source definition assigning DEMOMENU to a different resource kind or tree index.",
            status="supported",
        )
        strict = notebook.add_chamber("Strict threshold observatory", "deterministic", "volume/strict@v1", disposition="active", provenance="Nicholas Michael Kloster's accessible-volume equation")
        notebook.add_chamber("Seeded categorical futures", "stochastic", "sample/categorical@v1", parameters={"seed": 7}, provenance="Stochastic Simulation: preserve generator, seed, and experiment scope")
        notebook.add_chamber("Adaptive threshold comparison", "deterministic", "volume/adaptive@v1", disposition="rejected", parameters={"alpha": .001, "beta": 0}, provenance="Held-out BioBERT negative-transfer result")
        notebook.add_evidence(
            claim["id"],
            "DEMO.H defines DEMOMENU as 0 with the TREE annotation in Listing 5.18.",
            .96, .03,
            source="Programmer's Guide to GEM, Listing 5.18, PDF p.324",
            family="gem-guide-listing-5.18",
        )
        notebook.add_evidence(
            claim["id"],
            "GEM versions change menu placement, so appearance alone cannot establish the resource identity.",
            .40, .60,
            source="Programmer's Guide to GEM, GEM 1/2 comparison, PDF p.294",
            family="gem-guide-version-appearance",
            direction="challenges",
        )
        notebook.add_evidence(
            claim["id"],
            "rsrc_gaddr(R_TREE, DEMOMENU, &addr_menu) is followed by menu_bar(addr_menu, TRUE).",
            .95, .08,
            source="Programmer's Guide to GEM, initialization code, PDF p.301",
            family="gem-guide-initialization-p301",
        )
        notebook.run_chamber(strict["id"], probabilities=[.70, .20, .08, .02], tau=.05)
        notebook.add_test(question["id"], "Inspect an independently generated RCS resource header and compare its tree identifiers.", .8, .7, .3)
        return notebook


def _fit(value, length):
    value = str(value)
    return value if len(value) <= length else value[:max(1, length-1)] + "…"


def field_scene(notebook):
    from .atlas import _ellipse, _line, _scene, _text

    state = notebook.state()
    objects = [
        {"id": "background", "type": "rectangle", "bounds": [0, 0, 1200, 760], "stroke": "#070b14", "fill": "#070b14", "width": 1},
        _text("title", [32, 40], "ZOE · BAYESIAN FIELD NOTEBOOK", 24, "#67e8f9"),
        _text("subtitle", [32, 68], "questions / claims / evidence / unified memory / next useful test", 13, "#9fb1c8"),
    ]
    question = state["questions"][-1] if state["questions"] else None
    objects.append({"id": "question-panel", "type": "rectangle", "bounds": [28, 94, 650, 410], "stroke": "#334155", "fill": "#0d1526", "width": 2})
    objects.append(_text("question-label", [48, 122], "QUESTION / COMPETING CLAIMS", 13, "#c4b5fd"))
    if question is None:
        objects.append(_text("empty-question", [48, 164], "Begin with a question, not a folder.", 21, "#e5eefb"))
        objects.append(_text("empty-claim", [48, 202], "Add a claim, its falsifier, and explicit evidence likelihoods.", 13, "#9fb1c8"))
        objects.append(_text("empty-memory", [48, 234], "Measurements remain separate from belief until you define the update.", 13, "#9fb1c8"))
    else:
        objects.append(_text("question-text", [48, 156], _fit(question["text"], 58), 19, "#e5eefb"))
        claims = [claim for claim in state["claims"] if claim["question_id"] == question["id"]]
        for index, claim in enumerate(claims[:3]):
            y = 202 + index * 68
            posterior = claim["posterior"]
            color = "#86efac" if posterior >= .65 else "#fdba74" if posterior >= .4 else "#fca5a5"
            objects.append(_text(f"claim-{index}", [48, y], _fit(claim["statement"], 76), 13, "#e5eefb"))
            objects.append({"id": f"belief-track-{index}", "type": "rectangle", "bounds": [48, y+14, 448, y+26], "stroke": "#334155", "fill": "#1e293b", "width": 1})
            objects.append({"id": f"belief-fill-{index}", "type": "rectangle", "bounds": [48, y+14, 48+400*posterior, y+26], "stroke": color, "fill": color, "width": 1})
            objects.append(_text(f"belief-value-{index}", [466, y+26], f"{posterior:.1%} · {claim['status']}", 12, color))
            if claim["updates"]:
                update = claim["updates"][-1]
                delta = f"last Δ {update['posterior']-update['prior']:+.3f} · LR {update['likelihood_ratio']:.3g}"
            else:
                delta = "no evidence updates yet"
            objects.append(_text(f"belief-delta-{index}", [48, y+45], _fit(delta + " · model-dependent", 80), 11, "#9fb1c8"))
    objects.append(_text("bayes", [48, 402], "log-odds posterior = log-odds prior + log likelihood ratio", 12, "#67e8f9"))
    chamber_x = {"deterministic": 770, "stochastic": 1010}
    objects.append(_line("question-to-deterministic", [650, 235], [690, 235], "#67e8f9", 2))
    objects.append(_line("question-to-stochastic", [650, 270], [690, 270], "#f0abfc", 2))
    for mode, x in chamber_x.items():
        color = "#67e8f9" if mode == "deterministic" else "#f0abfc"
        objects.append(_text(f"mode-{mode}", [x-80, 122], mode.upper(), 13, color))
        chambers = [chamber for chamber in state["chambers"] if chamber["mode"] == mode]
        for index, chamber in enumerate(chambers[:3]):
            y = 160 + index * 75
            objects.append(_ellipse(f"chamber-{mode}-{index}", [x, y], [112, 28], color, "#111c31", 2))
            objects.append(_text(f"chamber-name-{mode}-{index}", [x-98, y-3], _fit(chamber["name"], 27), 11, "#e5eefb"))
            objects.append(_text(f"chamber-state-{mode}-{index}", [x-98, y+14], _fit(chamber["disposition"], 27), 9, color))
            objects.append(_line(f"chamber-link-{mode}-{index}", [x, y+29], [x, 410], "#334155", 1))
        if not chambers:
            objects.append(_text(f"no-chamber-{mode}", [x-95, 190], "registry available", 12, "#64748b"))
    objects.append(_text("registry", [704, 388], f"{len(state['equations'])} replaceable equation sections · quarantined chambers blocked", 11, "#9fb1c8"))
    objects.append({"id": "memory-panel", "type": "rectangle", "bounds": [28, 438, 1172, 674], "stroke": "#334155", "fill": "#0d1526", "width": 2})
    objects.append(_text("memory-title", [48, 468], f"UNIFIED MEMORY · {state['event_count']} append-only events", 14, "#fde68a"))
    objects.append(_text("memory-hash", [48, 491], _fit(f"head {state['head_hash'] or 'empty'}", 90), 10, "#64748b"))
    events = notebook.events[-14:]
    if events:
        start_x = 62
        spacing = min(82, 1050 / max(1, len(events)-1))
        objects.append(_line("event-chain", [start_x, 541], [start_x+spacing*(len(events)-1), 541], "#334155", 2))
        for index, event in enumerate(events):
            x = start_x + index * spacing
            kind = event["kind"]
            color = "#f0abfc" if kind == "measurement_recorded" else "#86efac" if kind == "evidence_added" else "#67e8f9" if kind in {"question_added", "claim_added"} else "#fde68a"
            objects.append({"id": f"event-{index}", "type": "polygon", "points": [[x, 534], [x+7, 541], [x, 548], [x-7, 541]], "stroke": color, "fill": color, "width": 1})
            objects.append(_text(f"event-label-{index}", [x-22, 570], str(event["sequence"]), 9, color))
    else:
        objects.append(_text("no-events", [48, 540], "The first event will establish the memory chain.", 13, "#64748b"))
    tests = sorted(state["tests"], key=lambda test: test["priority"], reverse=True)
    if tests:
        objects.append(_text("next-test", [48, 612], _fit(f"NEXT TEST · {tests[0]['statement']}", 104), 12, "#86efac"))
        objects.append(_text("test-score", [48, 637], f"heuristic priority {tests[0]['priority']:.3f} · not an authorization rule", 10, "#9fb1c8"))
    else:
        objects.append(_text("memory-boundary", [48, 620], "Measurements do not silently become evidence. Every belief change retains its prior, likelihoods, and source.", 12, "#9fb1c8"))
    objects.append(_text("scope", [32, 710], "Posteriors follow supplied likelihoods · breadth is not correctness · no autonomous action · executed=False", 12, "#fca5a5"))
    objects.append(_text("inspiration", [32, 735], "Bayesian process models · stochastic simulation · Markov transitions · accessible volume · negative results preserved", 10, "#64748b"))
    summary = "No question yet" if question is None else f"{_fit(question['text'], 90)} · {len(state['claims'])} claims · {len(state['measurements'])} measurements · {state['event_count']} memory events"
    scene = _scene("zoe-field-notebook", 1200, 760, objects, "Zoe Bayesian field notebook")
    return scene, {"summary": summary, "memory": notebook.document(), "state": state, "recommended_module": "field"}
