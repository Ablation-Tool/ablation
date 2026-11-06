#!/usr/bin/env python3
"""Run accessible-volume guarded GEM actions and preserve CEROTTO evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from investigation.forecast import (
    canonical_json,
    document_sha256,
    gem_forecast_context,
    input_ids_sha256,
    measure_accessible_volume,
    probabilities_from_logits,
)
from investigation.gem_events import export_gem_events, session_event_prefix, write_jsonl_new
from investigation.guard import GuardedGemBroker


MODEL_ID = "onnx-community/distilgpt2-ONNX"
MODEL_SHA256 = "0f79f192f3137e9a90213f1b5d4a52b6d896b735f9cb82160e5de7cc6e539c41"
TOKENIZER_SHA256 = "a6aa29bf8416d74ad795a73262b1aa3f985564ee338adbee7ffbc5861f78b6b8"
CONFIG_SHA256 = "dffb0253be590126da5dc43b75475f6f6ef4576439dec46e8ec83bf0408fcf83"
MAX_JSON_BYTES = 1024 * 1024
MAX_PROCESS_OUTPUT = 64 * 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path) -> dict:
    source = path.expanduser().resolve()
    with source.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON input exceeds the size limit")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("JSON input is invalid") from exc
    if not isinstance(document, dict):
        raise ValueError("JSON input must contain an object")
    return document


def checked_model_file(root: Path, relative: str, expected: str) -> Path:
    path = (root / relative).resolve(strict=True)
    if not path.is_file() or sha256(path) != expected:
        raise ValueError(f"model artifact failed identity verification: {relative}")
    return path


def onnx_forecast(context: dict, model_root: Path, artifacts: Path, action_id: str) -> dict:
    try:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
    except ImportError as exc:
        raise RuntimeError("ONNX forecasting requires numpy, onnxruntime, and tokenizers") from exc
    model_path = checked_model_file(model_root, "onnx/model.onnx", MODEL_SHA256)
    tokenizer_path = checked_model_file(model_root, "tokenizer.json", TOKENIZER_SHA256)
    config_path = checked_model_file(model_root, "config.json", CONFIG_SHA256)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    context_text = canonical_json(context)
    tokenizer = Tokenizer.from_file(str(tokenizer_path))
    ids = tokenizer.encode(context_text).ids
    context_limit = int(config.get("n_ctx", 1024))
    if not 1 <= len(ids) <= context_limit:
        raise ValueError(f"forecast context must contain 1 to {context_limit} tokens")
    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    inputs = {
        "input_ids": np.array([ids], dtype=np.int64),
        "attention_mask": np.ones((1, len(ids)), dtype=np.int64),
        "position_ids": np.arange(len(ids), dtype=np.int64)[None, :],
    }
    layers = int(config["n_layer"])
    heads = int(config["n_head"])
    head_size = int(config["n_embd"]) // heads
    for layer in range(layers):
        for kind in ("key", "value"):
            inputs[f"past_key_values.{layer}.{kind}"] = np.zeros(
                (1, heads, 0, head_size), dtype=np.float32,
            )
    logits = session.run(["logits"], inputs)[0][0, -1, :].astype(np.float64)
    probabilities = probabilities_from_logits(logits.tolist())
    measurement = measure_accessible_volume(probabilities)
    artifacts.mkdir(parents=True, exist_ok=True)
    artifacts = artifacts.resolve()
    if not artifacts.is_dir():
        raise ValueError("forecast artifact destination is not a directory")
    artifact_path = artifacts / f"{action_id}-forecast.npz"
    with artifact_path.open("xb") as stream:
        np.savez_compressed(
            stream,
            input_ids=np.array(ids, dtype=np.int64),
            probabilities=np.array(probabilities, dtype=np.float64),
            context_json=np.array(context_text),
        )
        stream.flush()
        os.fsync(stream.fileno())
    return {
        "schema_version": 1,
        "instrument": "next-token-accessible-volume",
        "context_sha256": document_sha256(context),
        "context_tokens": len(ids),
        "input_ids_sha256": input_ids_sha256(ids),
        "model": {
            "id": MODEL_ID,
            "runtime": f"onnxruntime {ort.__version__}",
            "model_sha256": MODEL_SHA256,
            "tokenizer_sha256": TOKENIZER_SHA256,
            "config_sha256": CONFIG_SHA256,
        },
        "measurement": measurement,
        "artifact": {
            "format": "npz",
            "path": str(artifact_path),
            "sha256": sha256(artifact_path),
            "contains": "input_ids, probabilities, and context_json",
        },
    }


def gem_broker(gem_lab: Path):
    root = gem_lab.expanduser().resolve()
    if not (root / "gem" / "host.py").is_file():
        raise ValueError("gem-lab path does not contain gem/host.py")
    sys.path.insert(0, str(root))
    from gem.events import Session
    from gem.host import GemCommandBroker, GemLabHost

    return GemCommandBroker, GemLabHost, Session


def ingest(binary: Path, database: Path, case_id: str, events_path: Path) -> None:
    executable = binary.expanduser().resolve(strict=True)
    if not executable.is_file():
        raise ValueError("CEROTTO binary is not a regular file")
    command = [
        str(executable), "ingest", "--db", str(database.expanduser().resolve()),
        "--case", case_id, "--input", str(events_path),
    ]
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        except OSError as exc:
            raise RuntimeError(f"could not start CEROTTO ingestion: {exc}") from exc
        try:
            returncode = process.wait(timeout=60)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise RuntimeError("CEROTTO ingestion timed out") from exc
        stdout.seek(0)
        output = stdout.read(MAX_PROCESS_OUTPUT + 1)
        stderr.seek(0)
        errors = stderr.read(MAX_PROCESS_OUTPUT + 1)
    if len(output) > MAX_PROCESS_OUTPUT or len(errors) > MAX_PROCESS_OUTPUT:
        raise RuntimeError("CEROTTO ingestion output exceeds the configured limit")
    if returncode:
        detail = errors.decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"CEROTTO ingestion failed with exit {returncode}: {detail}")


def add_evidence_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("--session", required=True, type=Path)
    command.add_argument("--output", required=True, type=Path)
    command.add_argument("--host", required=True)
    command.add_argument("--conversation", required=True)
    command.add_argument("--db", type=Path)
    command.add_argument("--case")
    command.add_argument("--cerotto-binary", type=Path, default=ROOT / "build" / "cerotto")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="cerotto-gem-defense")
    commands = result.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="measure, guard, execute, and preserve one GEM action")
    add_evidence_options(run)
    run.add_argument("--gem-lab", required=True, type=Path)
    run.add_argument("--proposal", required=True, type=Path)
    run.add_argument("--model-dir", required=True, type=Path)
    run.add_argument("--artifacts", required=True, type=Path)
    run.add_argument("--action-id", default="action-" + uuid.uuid4().hex)
    export = commands.add_parser("export-gem", help="convert GEM history to CEROTTO JSONL")
    add_evidence_options(export)
    export.add_argument("--session-id")
    export.add_argument("--start-line", type=int, default=1)
    return result


def validate_ingestion(args: argparse.Namespace) -> None:
    if args.db is not None and not args.case:
        raise ValueError("--case is required with --db")
    if args.case and args.db is None:
        raise ValueError("--db is required with --case")


def preflight_output(output_path: Path) -> Path:
    supplied = output_path.expanduser()
    if supplied.is_symlink():
        raise ValueError("output path cannot be a symbolic link")
    output = supplied.resolve()
    if output.exists():
        raise FileExistsError(f"output already exists: {output}")
    if not output.parent.is_dir():
        raise ValueError("output directory does not exist")
    return output


def run_action(args: argparse.Namespace) -> tuple[int, dict]:
    if not _IDENTIFIER.fullmatch(args.action_id):
        raise ValueError("action_id must be a bounded identifier")
    output = preflight_output(args.output)
    proposal = load_object(args.proposal)
    broker_class, host_class, session_class = gem_broker(args.gem_lab)
    broker = broker_class(host_class(session_class(args.session)))
    snapshot = broker.execute({"command": "snapshot"})
    context = gem_forecast_context(snapshot, proposal)
    forecast = onnx_forecast(context, args.model_dir, args.artifacts, args.action_id)
    guard = GuardedGemBroker(broker, args.host, args.conversation)
    result = guard.execute(args.action_id, proposal, forecast)
    write_jsonl_new(result.events, output)
    if args.db is not None:
        ingest(args.cerotto_binary, args.db, args.case, output)
    summary = {
        "action_id": args.action_id,
        "decision": result.decision,
        "reason": result.reason,
        "executed": result.executed,
        "succeeded": result.succeeded,
        "events": len(result.events),
        "output": str(output),
        "ingested": args.db is not None,
    }
    if result.succeeded:
        return 0, summary
    if result.executed:
        return 1, summary
    return 3, summary


def export_history(args: argparse.Namespace) -> tuple[int, dict]:
    session = args.session.expanduser().resolve()
    session_id = args.session_id or session_event_prefix(session)
    events, next_line = export_gem_events(
        session / "events.jsonl", args.host, args.conversation, session_id, args.start_line,
    )
    output = write_jsonl_new(events, args.output)
    if args.db is not None:
        ingest(args.cerotto_binary, args.db, args.case, output)
    return 0, {
        "events": len(events),
        "next_line": next_line,
        "output": str(output),
        "ingested": args.db is not None,
    }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        validate_ingestion(args)
        status, summary = run_action(args) if args.command == "run" else export_history(args)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        print(f"cerotto-gem-defense: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
