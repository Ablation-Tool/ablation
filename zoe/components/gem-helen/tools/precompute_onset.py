from pathlib import Path
import gzip
import hashlib
import json

from guiai.gem.onset import HOP_BASELINE, run_synthetic_experiment

ROOT = Path(__file__).resolve().parents[1]
experiment = run_synthetic_experiment()
payload = {
    "thresholds": experiment.thresholds.tolist(),
    "forward": experiment.forward,
    "retrograde": experiment.retrograde,
    "forward_probabilities": experiment.forward_probabilities.tolist(),
    "forward_targets": experiment.forward_targets.tolist(),
    "retrograde_probabilities": experiment.retrograde_probabilities.tolist(),
    "retrograde_targets": experiment.retrograde_targets.tolist(),
    "forward_curve": experiment.forward_curve.tolist(),
    "retrograde_curve": experiment.retrograde_curve.tolist(),
    "deterministic": {
        "forward_top1": experiment.deterministic_forward,
        "retrograde_top1": experiment.deterministic_retrograde,
        "accessible_volume": None,
        "reason": "A point forecast supplies no categorical alternative distribution",
    },
    "hop": HOP_BASELINE,
    "provenance": {
        "kind": "synthetic rhythm experiment",
        "seed": 7,
        "motifs": 8,
        "training_variations_per_motif": 60,
        "held_out_variations_per_motif": 20,
        "observations_per_condition": 1920,
        "source": "Ablation guiai.gem.onset",
        "source_sha256": hashlib.sha256(Path('/home/cowboy/ablation/guiai-lab/guiai/gem/onset.py').read_bytes()).hexdigest(),
    },
}
document = {"schema_version": 1, "payload": payload}
target = ROOT / "helen_gem" / "data" / "onset-seed7.json.gz"
target.parent.mkdir(parents=True, exist_ok=True)
target.write_bytes(gzip.compress((json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n").encode(), compresslevel=9))
print(target, target.stat().st_size)
print("forward", experiment.forward)
print("retrograde", experiment.retrograde)
