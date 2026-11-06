"""Conversion of GEM investigation history into CEROTTO JSONL events."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


MAX_EVENT_BYTES = 1024 * 1024
MAX_EVENTS = 100_000
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def session_event_prefix(session_root: Path) -> str:
    resolved = str(session_root.expanduser().resolve()).encode("utf-8")
    return "session-" + hashlib.sha256(resolved).hexdigest()[:16]


def export_gem_events(
    events_path: Path,
    host_id: str,
    conversation_id: str,
    session_id: str,
    start_line: int = 1,
) -> tuple[list[dict[str, Any]], int]:
    host_id = _identifier(host_id, "host_id")
    conversation_id = _identifier(conversation_id, "conversation_id")
    session_id = _identifier(session_id, "session_id")
    if isinstance(start_line, bool) or not isinstance(start_line, int) or start_line < 1:
        raise ValueError("start_line must be a positive integer")
    source = events_path.expanduser().resolve()
    if not source.is_file():
        raise ValueError("GEM events path is not a regular file")
    converted = []
    next_line = start_line
    with source.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if line_number < start_line:
                continue
            next_line = line_number + 1
            if len(line.encode("utf-8")) > MAX_EVENT_BYTES:
                raise ValueError(f"GEM event at line {line_number} exceeds the size limit")
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid GEM event at line {line_number}") from exc
            if not isinstance(event, dict) or not isinstance(event.get("timestamp_utc"), str):
                raise ValueError(f"invalid GEM event at line {line_number}")
            if not isinstance(event.get("id"), str) or not isinstance(event.get("type"), str):
                raise ValueError(f"invalid GEM event at line {line_number}")
            evidence = event.get("evidence", "")
            if not isinstance(evidence, str) or len(evidence) > 4096:
                raise ValueError(f"invalid GEM evidence path at line {line_number}")
            record_digest = hashlib.sha256(line.encode("utf-8")).hexdigest()[:16]
            converted.append({
                "id": f"gem:{session_id}:{line_number:08d}:{record_digest}",
                "observed_at": event["timestamp_utc"],
                "host_id": host_id,
                "source_tool": "gem-lab",
                "event_type": "gem_investigation_event",
                "conversation_id": conversation_id,
                "path": evidence,
                "details": {
                    "session_id": session_id,
                    "source_line": line_number,
                    "gem_event": event,
                },
            })
            if len(converted) >= MAX_EVENTS:
                next_line = line_number + 1
                break
    return converted, next_line


def write_jsonl_new(events: list[dict[str, Any]], output_path: Path) -> Path:
    output = output_path.expanduser().resolve()
    if not output.parent.is_dir():
        raise ValueError("output directory does not exist")
    lines = []
    for event in events:
        line = json.dumps(
            event, ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        )
        if len(line.encode("utf-8")) > MAX_EVENT_BYTES:
            raise ValueError(f"CEROTTO event {event.get('id', '')} exceeds the size limit")
        lines.append(line + "\n")
    with output.open("x", encoding="utf-8") as stream:
        stream.writelines(lines)
        stream.flush()
        os.fsync(stream.fileno())
    return output
