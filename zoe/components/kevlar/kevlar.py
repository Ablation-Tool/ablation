"""
Kevlar — MCP stdio proxy firewall.

Sits transparently between an MCP client and server, intercepting JSON-RPC
messages in both directions to apply CDR (Content Disarm & Reconstruct) and
indicator analysis from policy.py.

Usage:
    kevlar [--mode strict|lenient|audit] [--log PATH] -- <server-cmd> [args...]

Protocol layer handled here:
  - Bounded line reads (max LINE_LIMIT bytes)
  - Strict JSON parsing: reject duplicate keys, NaN/Infinity, batch arrays
  - Re-serialize all messages (never forward original bytes)
  - Request-id table to route server responses to correct CDR path
  - Fail-closed: any exception → synthesized isError / error response

Security posture:
  - All attacker-controlled content is untrusted until after CDR
  - Raw indicator text never reaches stdout
  - Logs go to stderr and optional JSONL file — never stdout (protocol channel)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import time
from typing import Optional
from uuid import uuid4

from policy import (
    VALID_MODES,
    LINE_LIMIT,
    cdr_initialize_result,
    cdr_tools_list,
    analyze_content_blocks,
    cdr_resources_list,
    cdr_prompts_list,
    analyze_prompt_get,
    scan_tool_call_args,
    Indicator,
)

# --------------------------------------------------------------------------- #
# Logging — stderr only; stdout is the protocol channel
# --------------------------------------------------------------------------- #
log = logging.getLogger("kevlar")


def _setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s kevlar %(message)s"
    ))
    logging.root.addHandler(handler)
    logging.root.setLevel(level)


# --------------------------------------------------------------------------- #
# JSONL audit log
# --------------------------------------------------------------------------- #
class AuditLog:
    def __init__(self, path: Optional[str]) -> None:
        self._fh = open(path, "a", encoding="utf-8") if path else None

    def write(self, event: dict) -> None:
        if self._fh:
            self._fh.write(json.dumps(event, default=str) + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()


# --------------------------------------------------------------------------- #
# Strict JSON parsing
# --------------------------------------------------------------------------- #
def _reject_duplicate_keys(pairs: list[tuple]) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate JSON keys detected")
    return dict(pairs)


def _parse_strict(data: bytes) -> object:
    """Parse JSON rejecting duplicate keys and NaN/Infinity literals.
    Also rejects batch arrays at the top level.
    Pre-screens for pathologically deep nesting before calling json.loads
    (DDIA Ch8: unbounded recursion blocks the event loop)."""
    # O(n) bracket pre-screen: deeply nested JSON requires O(n) stack in json.loads
    if data.count(b"[") + data.count(b"{") > 200:
        raise ValueError("JSON rejected: nesting depth pre-screen exceeded")
    try:
        obj = json.loads(
            data,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda c: (_ for _ in ()).throw(
                ValueError(f"disallowed JSON constant: {c}")
            ),
        )
    except ValueError as exc:
        raise ValueError(f"JSON parse error: {exc}") from exc
    if isinstance(obj, list):
        raise ValueError("JSON-RPC batch arrays are not supported")
    if not isinstance(obj, dict):
        raise ValueError("top-level JSON must be an object")
    return obj


# --------------------------------------------------------------------------- #
# Bounded line reader
# --------------------------------------------------------------------------- #
async def _read_line(reader: asyncio.StreamReader, limit: int = LINE_LIMIT) -> Optional[bytes]:
    """Read exactly one newline-terminated line, returning None on EOF.
    Uses readline() so multi-line bursts are not silently discarded.
    Raises ValueError if the line exceeds `limit` bytes or no newline arrives
    within 30 seconds (Slowloris defence — DDIA Ch8)."""
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=30.0)
    except asyncio.TimeoutError:
        raise ValueError("readline timeout: possible Slowloris / hung peer")
    if not line:
        return None
    if len(line) > limit:
        raise ValueError(f"incoming line exceeds {limit} bytes")
    return line.rstrip(b"\n")


# --------------------------------------------------------------------------- #
# Synthesise error responses (fail-closed)
# --------------------------------------------------------------------------- #
def _synthesize_error(msg_id: object, code: int, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id":      msg_id,
        "error": {"code": code, "message": message},
    }


def _synthesize_tool_error(msg_id: object, text: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id":      msg_id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": True,
        },
    }


# --------------------------------------------------------------------------- #
# Main proxy state
# --------------------------------------------------------------------------- #
class KevlarProxy:
    def __init__(self, mode: str, audit: AuditLog) -> None:
        self.mode  = mode
        self.audit = audit
        # Maps request id (from client) → method name, so we know how to route
        # the server's response.
        self._pending: dict[object, str] = {}
        # Set of tool names that survived CDR; calls for unknown names are blocked.
        self._sanitized_tool_names: set[str] = set()
        # Track negotiated protocol version from initialize
        self._protocol_version: Optional[str] = None

    # ----------------------------------------------------------------------- #
    # Client → Server direction: forward requests, record pending ids
    # ----------------------------------------------------------------------- #
    async def handle_client_message(
        self,
        raw: bytes,
        server_writer: asyncio.StreamWriter,
        client_write_fn,
    ) -> None:
        """Forward a client message to the server after recording its id/method.
        client_write_fn is used to send synthetic error responses back when a
        call is blocked — without it, the client would hang waiting for a response."""
        try:
            msg = _parse_strict(raw)
        except ValueError as exc:
            log.warning("client→server parse error, dropping: %s", exc)
            return

        method = msg.get("method")
        msg_id = msg.get("id")

        if isinstance(msg_id, (str, int)) and method:
            self._pending[msg_id] = method

        params = msg.get("params") or {}

        # Block tools/call for any tool not in the CDR-sanitized set.
        if method == "tools/call":
            tool_name = params.get("name", "")
            if tool_name not in self._sanitized_tool_names:
                log.warning("tools/call blocked for unsanitized tool %r", tool_name)
                self._pending.pop(msg_id, None)
                err = _synthesize_tool_error(msg_id, f"kevlar: tool {tool_name!r} was not in CDR-sanitized set")
                client_write_fn(json.dumps(err).encode() + b"\n")
                return
            # Egress DLP: scan outbound arguments for credential exfiltration.
            indics, score, disposition = scan_tool_call_args(params, self.mode)
            if indics:
                self._log_event("egress-dlp", msg_id, indics, score, disposition)
                log.info(
                    "egress DLP: tool=%r score=%d disposition=%s indicators=%d",
                    tool_name, score, disposition, len(indics),
                )
            if disposition == "reject":
                log.warning("egress DLP blocked tools/call %r (score %d)", tool_name, score)
                self._pending.pop(msg_id, None)
                err = _synthesize_tool_error(msg_id, f"kevlar: egress DLP blocked call to {tool_name!r} (score {score})")
                client_write_fn(json.dumps(err).encode() + b"\n")
                return

        line = json.dumps(msg).encode() + b"\n"
        server_writer.write(line)
        await server_writer.drain()

    # write_fn signature: Callable[[bytes], None]
    async def handle_server_message(
        self,
        raw: bytes,
        write_fn,
    ) -> None:
        """Parse a server message, apply CDR/analysis, and write the result.
        Returns None from _intercept means the message is intentionally dropped.
        On any other exception, synthesize a safe error response — never forward raw."""
        msg_id: object = None
        try:
            msg = _parse_strict(raw)
            msg_id = msg.get("id")
            out = await self._intercept(msg)
        except Exception as exc:
            log.error("server message handling failed (%s), sending synthetic error", exc)
            out = _synthesize_error(msg_id, -32603, "kevlar: internal error")

        if out is None:
            return  # intentionally dropped (e.g. list_changed in strict mode)
        line = json.dumps(out).encode() + b"\n"
        write_fn(line)

    async def _intercept(self, msg: dict) -> dict:
        """Route a server message to the correct CDR handler."""
        msg_id = msg.get("id")
        result = msg.get("result")
        error  = msg.get("error")
        method = msg.get("method")  # server-initiated notification/request

        # Error responses: scan error.message but forward (it's diagnostic, not signal)
        if error is not None:
            return self._handle_error_response(msg)

        # Notifications (no id): forward method notifications, log
        if msg_id is None and method:
            if method == "notifications/tools/list_changed":
                if self.mode == "strict":
                    # In strict mode, lock the tool registry for the life of the
                    # session. Drop the notification so the client never re-fetches
                    # and a mid-session poisoned list can't replace the clean one.
                    log.warning(
                        "tools/list_changed DROPPED in strict mode "
                        "(tool registry locked at session start)"
                    )
                    self._log_event("list-changed-blocked", None, [], 0, "reject")
                    return None
                else:
                    self._sanitized_tool_names.clear()
                    log.info("tools/list_changed: cleared sanitized tool set")
            return msg  # notifications are forwarded as-is (re-serialized)

        # Match response to pending request
        pending_method = self._pending.pop(msg_id, None) if msg_id is not None else None

        if result is None:
            return msg  # malformed but not our business

        if pending_method == "initialize":
            return self._handle_initialize(msg_id, result)
        elif pending_method == "tools/list":
            return self._handle_tools_list(msg_id, result)
        elif pending_method == "tools/call":
            return self._handle_tools_call(msg_id, result)
        elif pending_method in ("resources/list", "resources/templates/list"):
            return self._handle_resources_list(msg_id, result)
        elif pending_method == "prompts/list":
            return self._handle_prompts_list(msg_id, result)
        elif pending_method == "prompts/get":
            return self._handle_prompts_get(msg_id, result)
        else:
            # Unknown method: forward re-serialized (never original bytes)
            return msg

    def _handle_initialize(self, msg_id: object, result: dict) -> dict:
        sanitized, indicators, score, disposition = cdr_initialize_result(result, self.mode)
        self._protocol_version = sanitized.get("protocolVersion")
        self._log_event("initialize", msg_id, indicators, score, disposition)
        return {"jsonrpc": "2.0", "id": msg_id, "result": sanitized}

    def _handle_tools_list(self, msg_id: object, result: dict) -> dict:
        sanitized, indicators, score, disposition = cdr_tools_list(result, self.mode)

        # Update the set of known-safe tool names
        self._sanitized_tool_names = {
            t["name"] for t in sanitized.get("tools", []) if isinstance(t, dict)
        }

        self._log_event("tools/list", msg_id, indicators, score, disposition,
                        extra={"tool_count": len(sanitized.get("tools", []))})
        log.info(
            "tools/list CDR: %d tools, %d indicators, score=%d disposition=%s",
            len(sanitized.get("tools", [])), len(indicators), score, disposition,
        )

        if disposition == "reject":
            # Return an empty tools list — do not return the original
            sanitized["tools"] = []
            log.warning("tools/list rejected: returning empty tool set")

        return {"jsonrpc": "2.0", "id": msg_id, "result": sanitized}

    def _handle_tools_call(self, msg_id: object, result: dict) -> dict:
        sanitized, indicators, score, disposition = analyze_content_blocks(result, self.mode)
        self._log_event("tools/call", msg_id, indicators, score, disposition)

        if indicators:
            log.info(
                "tools/call: %d indicators, score=%d disposition=%s",
                len(indicators), score, disposition,
            )

        return {"jsonrpc": "2.0", "id": msg_id, "result": sanitized}

    def _handle_resources_list(self, msg_id: object, result: dict) -> dict:
        sanitized, indicators, score, disposition = cdr_resources_list(result, self.mode)
        self._log_event("resources/list", msg_id, indicators, score, disposition)
        if indicators:
            log.info(
                "resources/list CDR: %d indicators score=%d disposition=%s",
                len(indicators), score, disposition,
            )
        if disposition == "reject":
            key = "resourceTemplates" if "resourceTemplates" in sanitized else "resources"
            sanitized[key] = []
            log.warning("resources/list rejected: returning empty resource set")
        return {"jsonrpc": "2.0", "id": msg_id, "result": sanitized}

    def _handle_prompts_list(self, msg_id: object, result: dict) -> dict:
        sanitized, indicators, score, disposition = cdr_prompts_list(result, self.mode)
        self._log_event("prompts/list", msg_id, indicators, score, disposition)
        if indicators:
            log.info(
                "prompts/list CDR: %d indicators score=%d disposition=%s",
                len(indicators), score, disposition,
            )
        if disposition == "reject":
            sanitized["prompts"] = []
            log.warning("prompts/list rejected: returning empty prompt set")
        return {"jsonrpc": "2.0", "id": msg_id, "result": sanitized}

    def _handle_prompts_get(self, msg_id: object, result: dict) -> dict:
        sanitized, indicators, score, disposition = analyze_prompt_get(result, self.mode)
        self._log_event("prompts/get", msg_id, indicators, score, disposition)
        if indicators:
            log.info(
                "prompts/get: %d indicators score=%d disposition=%s",
                len(indicators), score, disposition,
            )
        return {"jsonrpc": "2.0", "id": msg_id, "result": sanitized}

    def _handle_error_response(self, msg: dict) -> dict:
        # Scan error.message for credential leakage but forward the error
        error = msg.get("error", {})
        err_msg = error.get("message", "")
        if isinstance(err_msg, str):
            indicators = scan_text(err_msg, CONTENT_PATTERNS, "error:message")
            if indicators:
                log.warning("error.message contained %d indicators", len(indicators))
                self._log_event("error", msg.get("id"), indicators, 0, "allow")
        return msg

    def _log_event(
        self,
        event_type: str,
        msg_id: object,
        indicators: list[Indicator],
        score: int,
        disposition: str,
        extra: Optional[dict] = None,
    ) -> None:
        record: dict = {
            "ts":           time.time(),
            "event":        event_type,
            "id":           msg_id,
            "mode":         self.mode,
            "score":        score,
            "disposition":  disposition,
            "indicators":   [i.to_dict() for i in indicators],
        }
        if extra:
            record.update(extra)
        self.audit.write(record)


# --------------------------------------------------------------------------- #
# Process lifecycle
# --------------------------------------------------------------------------- #
async def run(
    server_cmd: list[str],
    mode: str,
    audit: AuditLog,
) -> int:
    """Spawn the server subprocess and pump messages until EOF or error."""
    proxy = KevlarProxy(mode=mode, audit=audit)

    try:
        proc = await asyncio.create_subprocess_exec(
            *server_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # lets us kill the whole process group
        )
    except FileNotFoundError:
        log.error("server command not found: %s", server_cmd[0])
        return 1

    log.info("spawned server pid=%d cmd=%s mode=%s", proc.pid, server_cmd[0], mode)

    # Async stdin reader for client input
    loop = asyncio.get_running_loop()
    stdin_reader = asyncio.StreamReader(limit=LINE_LIMIT)
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(stdin_reader), sys.stdin.buffer
    )

    def _write_to_client(data: bytes) -> None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    async def pump_client_to_server() -> None:
        """stdin → server: forward client requests until stdin EOF.
        Closing server stdin after EOF signals the server to flush stdout."""
        while True:
            try:
                raw = await _read_line(stdin_reader)
            except ValueError as exc:
                log.warning("oversized/invalid client line: %s", exc)
                continue
            if raw is None:
                break
            if not raw.strip():
                continue
            await proxy.handle_client_message(raw, proc.stdin, _write_to_client)
        try:
            proc.stdin.close()
        except Exception:
            pass

    async def pump_server_to_client() -> None:
        """server stdout → client: CDR and forward until server stdout EOF."""
        while True:
            try:
                raw = await _read_line(proc.stdout)
            except ValueError as exc:
                log.warning("oversized/invalid server line: %s", exc)
                continue
            if raw is None:
                break
            if not raw.strip():
                continue
            await proxy.handle_server_message(raw, _write_to_client)

    async def drain_server_stderr() -> None:
        """Drain server stderr → our stderr to prevent pipe stall."""
        while True:
            chunk = await proc.stderr.read(4096)
            if not chunk:
                break
            sys.stderr.buffer.write(chunk)
            sys.stderr.buffer.flush()

    stderr_task = asyncio.create_task(drain_server_stderr(), name="stderr-drain")

    try:
        # Both pumps run to natural completion. client pump EOF → closes server
        # stdin → server flushes stdout → server pump EOF → gather returns.
        await asyncio.gather(
            pump_client_to_server(),
            pump_server_to_client(),
        )
    finally:
        stderr_task.cancel()
        await asyncio.gather(stderr_task, return_exceptions=True)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass

    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    return proc.returncode or 0


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kevlar — MCP stdio firewall proxy",
        epilog="Example: kevlar --mode strict --log /tmp/kevlar.jsonl -- npx -y @modelcontextprotocol/server-filesystem /tmp",
    )
    parser.add_argument(
        "--mode", choices=sorted(VALID_MODES), default="strict",
        help="Firewall mode: strict (default) | lenient | audit",
    )
    parser.add_argument(
        "--log", metavar="PATH", default=None,
        help="Append forensic JSONL events to this file",
    )
    parser.add_argument(
        "server_cmd", nargs=argparse.REMAINDER,
        help="Server command (after --)",
    )

    args = parser.parse_args()

    # Strip leading '--' separator
    server_cmd = args.server_cmd
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]
    if not server_cmd:
        parser.error("server command required after --")

    _setup_logging()
    audit = AuditLog(args.log)

    try:
        exit_code = asyncio.run(run(server_cmd, args.mode, audit))
    finally:
        audit.close()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
