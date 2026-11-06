import math

from .measurement import document_sha256


MAX_CASES = 1_000_000


def auroc(scores, labels):
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return None
    order = sorted(range(len(scores)), key=lambda index: scores[index])
    ranks = [0.0] * len(scores)
    index = 0
    while index < len(order):
        end = index + 1
        while end < len(order) and scores[order[end]] == scores[order[index]]:
            end += 1
        rank = (index + end + 1) / 2
        for position in range(index, end):
            ranks[order[position]] = rank
        index = end
    positive_rank_sum = math.fsum(rank for rank, label in zip(ranks, labels) if label)
    return (positive_rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def auprc(scores, labels):
    positives = sum(labels)
    if not positives:
        return None
    order = sorted(range(len(scores)), key=lambda index: -scores[index])
    true_positives = 0
    previous_recall = 0.0
    average_precision = 0.0
    index = 0
    while index < len(order):
        end = index + 1
        while end < len(order) and scores[order[end]] == scores[order[index]]:
            end += 1
        true_positives += sum(labels[order[position]] for position in range(index, end))
        recall = true_positives / positives
        precision = true_positives / end
        average_precision += (recall - previous_recall) * precision
        previous_recall = recall
        index = end
    return average_precision


def calibration_metrics(records, bins=10):
    if isinstance(bins, bool) or not isinstance(bins, int) or not 1 <= bins <= 100:
        raise ValueError("bins must be an integer from 1 to 100")
    records = list(records)
    if not 1 <= len(records) <= MAX_CASES:
        raise ValueError(f"calibration requires 1 to {MAX_CASES} labeled observations")
    grouped = [[] for _ in range(bins)]
    confidences = []
    labels = []
    losses = []
    briers = []
    complete_losses = True
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("outcome"), dict):
            raise ValueError("every calibration record must contain an outcome")
        outcome = record["outcome"]
        if not isinstance(outcome.get("correct"), bool):
            raise ValueError("every outcome must contain a boolean correct field")
        try:
            confidence = float(record["max_probability"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("every record must contain a finite max_probability") from error
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("max_probability must be between zero and one")
        correct = outcome["correct"]
        confidences.append(confidence)
        labels.append(correct)
        grouped[min(int(confidence * bins), bins - 1)].append((confidence, correct))
        if "log_loss" not in outcome or "brier_score" not in outcome:
            complete_losses = False
        else:
            loss = float(outcome["log_loss"])
            brier = float(outcome["brier_score"])
            if not math.isfinite(loss) or loss < 0 or not math.isfinite(brier) or brier < 0:
                raise ValueError("outcome log_loss and brier_score must be finite and nonnegative")
            losses.append(loss)
            briers.append(brier)
    count = len(records)
    documents = []
    expected_error = 0.0
    for index, group in enumerate(grouped):
        if group:
            mean_confidence = math.fsum(item[0] for item in group) / len(group)
            accuracy = sum(item[1] for item in group) / len(group)
            gap = abs(mean_confidence - accuracy)
            expected_error += len(group) / count * gap
        else:
            mean_confidence = accuracy = gap = None
        documents.append({
            "lower": index / bins,
            "upper": (index + 1) / bins,
            "count": len(group),
            "mean_confidence": mean_confidence,
            "accuracy": accuracy,
            "gap": gap,
        })
    correct = sum(labels)
    return {
        "schema_version": 1,
        "instrument": "forecast outcome calibration",
        "cases": count,
        "correct": correct,
        "errors": count - correct,
        "accuracy": correct / count,
        "mean_confidence": math.fsum(confidences) / count,
        "expected_calibration_error": expected_error,
        "log_loss": math.fsum(losses) / count if complete_losses else None,
        "brier_score": math.fsum(briers) / count if complete_losses else None,
        "auroc_correctness": auroc(confidences, labels),
        "auprc_correctness": auprc(confidences, labels),
        "bins": documents,
        "records_sha256": document_sha256(records),
        "scope": [
            "AUROC and AUPRC rank correct outcomes using maximum forecast probability as the confidence score.",
            "Calibration measures observed confidence against outcomes; it does not measure accessible-volume breadth or reasoning quality.",
        ],
    }
