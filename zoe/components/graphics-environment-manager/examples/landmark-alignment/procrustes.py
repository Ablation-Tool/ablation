#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gem.landmarks import affine_design, similarity_procrustes


def similarity_dict(alignment):
    return {
        "scale": alignment.scale,
        "rotation": alignment.rotation.tolist(),
        "translation": alignment.translation.tolist(),
        "determinant": alignment.determinant,
        "angle_degrees": alignment.angle_degrees,
        "predicted": alignment.predicted.tolist(),
        "rms": alignment.rms,
        "allow_reflection": alignment.allow_reflection,
    }


def main():
    parser = argparse.ArgumentParser(description="Reproduce the two-pair landmark Procrustes example")
    parser.add_argument("--output", type=Path, help="optional JSON report path")
    args = parser.parse_args()
    example = Path(__file__).resolve().parent
    document = json.loads((example / "landmarks.json").read_text(encoding="utf-8"))
    pairs = document["correspondences"]
    source = np.array([pair["source"] for pair in pairs], dtype=np.float64)
    target = np.array([pair["target"] for pair in pairs], dtype=np.float64)
    proper = similarity_procrustes(source, target)
    reflected = similarity_procrustes(source, target, allow_reflection=True)
    design, _ = affine_design(source, target)
    report = {
        "landmarks": pairs,
        "proper_similarity": similarity_dict(proper),
        "reflection_allowed_similarity": similarity_dict(reflected),
        "affine": {
            "design_rank": int(np.linalg.matrix_rank(design)),
            "required_rank_for_unique_solution": 6,
            "unique": False,
            "reason": "Two correspondences provide four scalar equations for six affine unknowns; a third non-collinear pair is required.",
        },
    }
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
