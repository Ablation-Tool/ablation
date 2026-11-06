#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description="Run the frozen accessible-volume model comparisons sequentially")
    parser.add_argument("--manifest", type=Path, default=Path(__file__).parent.parent / "evidence" / "comparison" / "model-comparison-cases.json")
    parser.add_argument("--output", type=Path, default=Path("evidence/comparison"))
    parser.add_argument("--cache-dir", type=Path, help="Parent directory for temporary per-model caches")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--model", action="append", help="Run only this exact model ID; repeat to select several")
    selection.add_argument("--all", action="store_true", help="Run all sixteen cases and verify the resulting artifacts")
    args = parser.parse_args()
    cases = json.loads(args.manifest.read_text())["cases"]
    by_model = {case["model"]: case for case in cases}
    if args.all:
        selected = cases
    else:
        unknown = [model for model in args.model if model not in by_model]
        if unknown:
            parser.error(f"Unknown model IDs: {', '.join(unknown)}")
        selected = [by_model[model] for model in dict.fromkeys(args.model)]
    if args.cache_dir is not None:
        args.cache_dir.mkdir(parents=True, exist_ok=True)
    harness = Path(__file__).with_name("prediction-accessible-volume.py").resolve()
    verifier = Path(__file__).with_name("verify-model-comparison.py").resolve()
    for case in selected:
        with tempfile.TemporaryDirectory(prefix="accessible-volume-model-cache.", dir=args.cache_dir) as cache:
            env = os.environ.copy()
            env.update({
                "HF_HOME": cache,
                "HF_HUB_CACHE": str(Path(cache) / "hub"),
                "HF_HUB_DISABLE_PROGRESS_BARS": "1",
                "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
                "HF_HUB_DISABLE_TELEMETRY": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "TOKENIZERS_PARALLELISM": "false",
                "TRANSFORMERS_VERBOSITY": "error",
            })
            command = [
                sys.executable, str(harness),
                "--model", case["model"],
                "--revision", case["revision"],
                "--style", case["style"],
                "--text", case["text"],
                "--target", case["target"],
                "--output", str(args.output),
            ]
            print("RUN", case["category"], case["model"], flush=True)
            subprocess.run(command, env=env, check=True)
    if args.all:
        subprocess.run([
            sys.executable, str(verifier),
            "--manifest", str(args.manifest),
            "--evidence", str(args.output),
        ], check=True)


if __name__ == "__main__":
    main()
