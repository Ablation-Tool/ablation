"""Read-only CEROTTO CLI adapter with fixed investigation scope."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class AdapterError(RuntimeError):
    pass


class CerottoAdapter:
    def __init__(self, binary: str, database: str, case_id: str, conversation_id: str,
                 scope_host: str = "", scope_from: str = "", scope_to: str = "",
                 default_limit: int = 200, max_result_chars: int = 64000, timeout: int = 60):
        self.binary = str(Path(binary).expanduser().resolve())
        self.database = database
        self.case_id = case_id
        self.conversation_id = conversation_id
        self.scope_host = scope_host
        self.scope_from = scope_from
        self.scope_to = scope_to
        self.default_limit = default_limit
        self.max_result_chars = max_result_chars
        self.timeout = timeout
        self._events: dict[str, dict[str, Any]] = {}
        self.calls: list[dict[str, Any]] = []
        if isinstance(default_limit, bool) or not isinstance(default_limit, int) or not 1 <= default_limit <= 500:
            raise ValueError("default_limit must be an integer between 1 and 500")
        if max_result_chars < 1024 or max_result_chars > 1_000_000:
            raise ValueError("max_result_chars must be between 1024 and 1000000")
        if not Path(self.binary).is_file():
            raise AdapterError(f"CEROTTO binary not found: {self.binary}")

    @property
    def known_event_ids(self) -> frozenset[str]:
        return frozenset(self._events)

    def query_timeline(self, host: str | None = None, from_: str | None = None,
                       to: str | None = None, limit: int | None = None) -> dict:
        host = self.scope_host if host is None else host
        from_ = self.scope_from if from_ is None else from_
        to = self.scope_to if to is None else to
        limit = self.default_limit if limit is None else limit
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise AdapterError("timeline limit must be an integer between 1 and 500")
        for name, value in (("host", host), ("from", from_), ("to", to)):
            if not isinstance(value, str):
                raise AdapterError(f"{name} must be a string")
        if self.scope_host and host != self.scope_host:
            raise AdapterError("host is outside the configured investigation scope")
        base_args = self._timeline_args(host="", from_=from_, to=to, limit=limit)
        base = self._run_json(base_args, "query_timeline")
        allowed_hosts = {event.get("host_id", "") for event in base.get("events", [])}
        if host and host not in allowed_hosts:
            raise AdapterError(f"host is outside the conversation evidence scope: {host}")
        if not host:
            self._record_events(base)
            self._record_call("query_timeline", len(base.get("events", [])))
            return base
        narrowed = self._run_json(self._timeline_args(host, from_, to, limit), "query_timeline")
        self._record_events(narrowed)
        self._record_call("query_timeline", len(narrowed.get("events", [])), host=host)
        return narrowed

    def get_event(self, event_id: str) -> dict:
        if not isinstance(event_id, str) or event_id not in self._events:
            raise AdapterError("event ID was not returned in the current investigation scope")
        self._record_call("get_event", 1)
        return self._events[event_id]

    def get_manifest(self) -> dict:
        result = self._run_json(["manifest", "--db", self.database, "--case", self.case_id], "get_manifest")
        self._record_call("get_manifest", len(result.get("sources", [])))
        return result

    def verify_case(self) -> dict:
        result = self._run_json(["verify", "--db", self.database, "--case", self.case_id],
                                "verify_case", allow_mismatch=True)
        self._record_call("verify_case", int(result.get("verified") is True))
        return result

    def _timeline_args(self, host: str, from_: str, to: str, limit: int) -> list[str]:
        args = [
            "timeline", "--db", self.database, "--case", self.case_id,
            "--conversation", self.conversation_id, "--limit", str(limit),
        ]
        if host:
            args.extend(["--host", host])
        if from_:
            args.extend(["--from", from_])
        if to:
            args.extend(["--to", to])
        return args

    def _record_events(self, timeline: dict) -> None:
        events = timeline.get("events")
        if not isinstance(events, list):
            raise AdapterError("timeline response has no event array")
        for event in events:
            event_id = event.get("event_id")
            if not isinstance(event_id, str) or not event_id:
                raise AdapterError("timeline contains an event without a valid ID")
            self._events[event_id] = event

    def _record_call(self, action: str, count: int, host: str = "") -> None:
        self.calls.append({"action": action, "count": count, "host": host})

    def _run_json(self, args: list[str], action: str, allow_mismatch: bool = False) -> dict:
        command = [self.binary, *args]
        try:
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                with subprocess.Popen(command, stdout=stdout, stderr=stderr) as proc:
                    try:
                        returncode = proc.wait(timeout=self.timeout)
                    except subprocess.TimeoutExpired as exc:
                        proc.kill()
                        proc.wait()
                        raise AdapterError(f"{action} timed out after {self.timeout} seconds") from exc
                stdout.seek(0)
                raw_output = stdout.read(self.max_result_chars + 1)
                stderr.seek(0)
                error_output = stderr.read(500).decode("utf-8", errors="replace")
        except OSError as exc:
            raise AdapterError(f"{action} failed: {exc}") from exc
        if returncode and not (allow_mismatch and returncode == 1):
            raise AdapterError(f"{action} failed with exit {returncode}: {error_output}")
        if len(raw_output) > self.max_result_chars:
            raise AdapterError(f"{action} output exceeds {self.max_result_chars} characters")
        try:
            result = json.loads(raw_output)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AdapterError(f"{action} returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise AdapterError(f"{action} returned a non-object JSON result")
        return result
