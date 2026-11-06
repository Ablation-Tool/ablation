from __future__ import annotations

import math


def _validate_events(events):
    if not isinstance(events, list) or len(events) < 40:
        raise ValueError("feed analysis requires at least 40 chronological binary observations")
    outcomes = []
    for index, event in enumerate(events):
        if isinstance(event, bool):
            outcomes.append(event)
            continue
        if not isinstance(event, dict):
            raise ValueError(f"observation {index} is not a boolean or outcome object")
        outcome = event.get("outcome")
        if outcome not in {"like", "not_like"}:
            raise ValueError(f"observation {index} must have outcome like or not_like")
        outcomes.append(outcome == "like")
    return outcomes


def _conditional_probability(counts, previous, outcome, alpha):
    following = counts.get(previous, {})
    total = sum(following.values())
    return (following.get(outcome, 0) + alpha) / (total + 2*alpha)


def _fit(events, order, alpha):
    if order == 0:
        likes = sum(events)
        return {"likes": likes, "total": len(events), "probability": (likes+alpha)/(len(events)+2*alpha)}
    counts = {}
    for index in range(order, len(events)):
        previous = tuple(events[index-order:index])
        outcome = events[index]
        counts.setdefault(previous, {})[outcome] = counts.setdefault(previous, {}).get(outcome, 0) + 1
    return {"counts": counts}


def _probability(model, history, outcome, alpha):
    if model["order"] == 0:
        return model["probability"]
    previous = tuple(history[-model["order"]:]) if model["order"] else ()
    return _conditional_probability(model["counts"], previous, outcome, alpha)


def _metrics(events, model, alpha):
    if not events:
        raise ValueError("held-out observations must not be empty")
    log_loss = 0.0
    brier = 0.0
    correct = 0
    for index, outcome in enumerate(events):
        probability = _probability(model, events[:index], True, alpha)
        probability = min(max(probability, 1e-12), 1-1e-12)
        log_loss -= math.log(probability if outcome else 1-probability)
        brier += (probability-int(outcome))**2
        correct += (probability >= .5) == outcome
    return {
        "observations": len(events),
        "log_loss": log_loss/len(events),
        "brier_score": brier/len(events),
        "accuracy": correct/len(events),
    }


def evaluate_feed(events, alpha=.5, trial_train=24, trial_test=8):
    outcomes = _validate_events(events)
    if isinstance(alpha, bool) or not isinstance(alpha, (int, float)) or not 0 < alpha <= 100:
        raise ValueError("alpha must be greater than zero and at most 100")
    if trial_train < 8 or trial_test < 1:
        raise ValueError("trial_train must be at least 8 and trial_test at least 1")
    trials = []
    for start in range(trial_train, len(outcomes)-trial_test+1, trial_test):
        train = outcomes[:start]
        test = outcomes[start:start+trial_test]
        trial = {"train_observations": start, "test_observations": len(test), "models": {}}
        for order in (0, 1, 2):
            model = _fit(train, order, alpha)
            model["order"] = order
            trial["models"][f"order_{order}"] = _metrics(test, model, alpha)
        trials.append(trial)
    if not trials:
        raise ValueError("not enough observations for an expanding train/test trial")
    summaries = {}
    for order in (0, 1, 2):
        name = f"order_{order}"
        summaries[name] = {
            "log_loss": sum(trial["models"][name]["log_loss"]*trial["test_observations"] for trial in trials)/sum(trial["test_observations"] for trial in trials),
            "brier_score": sum(trial["models"][name]["brier_score"]*trial["test_observations"] for trial in trials)/sum(trial["test_observations"] for trial in trials),
            "accuracy": sum(trial["models"][name]["accuracy"]*trial["test_observations"] for trial in trials)/sum(trial["test_observations"] for trial in trials),
        }
    best = min(summaries, key=lambda name: summaries[name]["log_loss"])
    first_order_counts = _fit(outcomes, 1, alpha)["counts"]
    transitions = {}
    for previous, counts in sorted(first_order_counts.items()):
        transitions[str(previous[0])] = {
            str(outcome): _conditional_probability(first_order_counts, previous, outcome, alpha)
            for outcome in (False, True)
        }
    report = {
        "schema_version": 1,
        "instrument": "binary feed transition experiment",
        "model_scope": "black-box candidate models only; not recovery of TikTok's proprietary algorithm or proof of causation",
        "observations": len(outcomes),
        "likes": sum(outcomes),
        "not_likes": len(outcomes)-sum(outcomes),
        "alpha": float(alpha),
        "smoothing": "symmetric Dirichlet prior",
        "validation": "expanding chronological train windows with disjoint later test windows; no future observations in fitting",
        "trial_train": trial_train,
        "trial_test": trial_test,
        "trials": trials,
        "summary": summaries,
        "best_by_held_out_log_loss": best,
        "previous_observation_helps": summaries["order_1"]["log_loss"] < summaries["order_0"]["log_loss"],
        "second_order_helps_beyond_first": summaries["order_2"]["log_loss"] < summaries["order_1"]["log_loss"],
        "transition_probabilities": transitions,
        "autonomous_action": False,
    }
    return report
