#!/usr/bin/env python3
"""Correlate real human surprise ratings with model uncertainty measurements."""
import json
import sys
from pathlib import Path

import numpy as np
from scipy.stats import spearmanr

BASE = Path(__file__).resolve().parent
path = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE / "surprise_ratings.json"
data = json.loads(path.read_text())
rows = data["ratings"]
if len(rows) < 3:
    raise SystemExit("At least three ratings are needed")
ratings = np.asarray([row["rating"] for row in rows], dtype=float)
measurements = {
    "accessible volume A(.1)": "accessible_0.1",
    "negative log probability": "negative_log_probability",
    "predictive entropy": "entropy",
    "maximum probability": "max_probability",
}
results = {"n": len(rows), "correlations": {}}
print(f"Human surprise ratings: {len(rows)}")
print("measurement                    Spearman rho    p-value")
for label, key in measurements.items():
    values = np.asarray([row[key] for row in rows], dtype=float)
    rho, pvalue = spearmanr(values, ratings)
    results["correlations"][key] = {"spearman_rho": float(rho), "p_value": float(pvalue)}
    print(f"{label:30s} {rho:11.3f} {pvalue:11.4f}")
results["strata"] = {}
for stratum in ["low", "medium", "high"]:
    subset = [row["rating"] for row in rows if row.get("volume_stratum") == stratum]
    if subset:
        results["strata"][stratum] = {"n": len(subset), "mean_rating": float(np.mean(subset))}
        print(f"{stratum:8s} volume: n={len(subset)}, mean surprise={np.mean(subset):.2f}")
output = BASE / "human_correlations.json"
output.write_text(json.dumps(results, indent=2))
print(f"Saved {output}")
print("Preliminary listening test only; small samples do not establish a perceptual effect.")
