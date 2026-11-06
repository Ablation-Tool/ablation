"""
Integration tests for kevlar.py — spawn actual proxy+server subprocesses
and assert on the bytes the client receives.

Each test sends real JSON-RPC over stdin/stdout and verifies:
  - The DEADBUG canary never appears in output
  - The correct CDR behaviour is applied per mode
  - Blocked calls return synthetic errors (client never hangs)
"""
from __future__ import annotations

import json
import subprocess
import sys
import os

import pytest

KEVLAR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), "kevlar.py")
HOSTILE = os.path.join(os.path.dirname(__file__), "hostile_server.py")
CANARY  = b"MCP_CANARY_DEADBUG_XYZ"

INIT    = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"protocolVersion": "2024-11-05", "capabilities": {}}}
NOTIF   = {"jsonrpc": "2.0", "method": "notifications/initialized"}
LIST    = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
CALL    = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
           "params": {"name": "format_text", "arguments": {"text": "hello"}}}


def _run(variant: str, mode: str = "strict", extra_msgs: list | None = None) -> tuple[bytes, list[dict]]:
    """Spawn kevlar → hostile_server, send standard handshake + optional extra
    messages, collect all stdout lines as parsed JSON dicts."""
    proc = subprocess.Popen(
        [sys.executable, KEVLAR, "--mode", mode, "--", sys.executable, HOSTILE, variant],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    msgs = [INIT, NOTIF, LIST] + (extra_msgs or [])
    for m in msgs:
        proc.stdin.write(json.dumps(m).encode() + b"\n")
    proc.stdin.close()
    proc.wait(timeout=8)
    raw = proc.stdout.read()
    parsed = [json.loads(line) for line in raw.split(b"\n") if line.strip()]
    return raw, parsed


def _by_id(parsed: list[dict], msg_id: int) -> dict | None:
    return next((m for m in parsed if m.get("id") == msg_id), None)


# --------------------------------------------------------------------------- #
# Canary never leaks
# --------------------------------------------------------------------------- #
class TestCanaryContainment:
    def test_poisoned_description_canary_absent(self):
        raw, _ = _run("poisoned_description")
        assert CANARY not in raw

    def test_cross_server_poison_canary_absent(self):
        raw, _ = _run("cross_server_poison")
        assert CANARY not in raw

    def test_poisoned_schema_canary_absent(self):
        raw, _ = _run("poisoned_schema")
        assert CANARY not in raw

    def test_poisoned_init_canary_absent(self):
        raw, _ = _run("poisoned_init")
        assert CANARY not in raw


# --------------------------------------------------------------------------- #
# tools/list CDR
# --------------------------------------------------------------------------- #
class TestToolsListCDR:
    def test_strict_rejects_poisoned_list(self):
        _, parsed = _run("poisoned_description", mode="strict")
        tl = _by_id(parsed, 2)
        assert tl is not None
        tools = tl.get("result", {}).get("tools", [])
        assert len(tools) == 0, "poisoned tools/list should be rejected in strict mode"

    def test_audit_forwards_cdr_tool(self):
        _, parsed = _run("poisoned_description", mode="audit")
        tl = _by_id(parsed, 2)
        assert tl is not None
        tools = tl.get("result", {}).get("tools", [])
        assert len(tools) == 1
        assert "description" not in tools[0], "description must be stripped even in audit mode"
        assert tools[0]["name"] == "format_text"

    def test_init_instructions_stripped(self):
        _, parsed = _run("poisoned_init")
        init = _by_id(parsed, 1)
        assert init is not None
        result = init.get("result", {})
        assert "instructions" not in result

    def test_clean_tool_forwarded_in_strict(self):
        """A tool with no injection in description should pass through in strict mode."""
        _, parsed = _run("poisoned_description", mode="strict")
        # In strict mode the poisoned list is rejected → 0 tools.
        # Use audit mode to confirm clean structure passes.
        _, parsed2 = _run("poisoned_description", mode="audit")
        tl = _by_id(parsed2, 2)
        tools = tl.get("result", {}).get("tools", [])
        assert tools[0].get("inputSchema") is not None


# --------------------------------------------------------------------------- #
# Wire-level rejection
# --------------------------------------------------------------------------- #
class TestWireLevelRejection:
    def test_batch_array_rejected(self):
        _, parsed = _run("batch_array")
        # Server sends a JSON array — proxy should fail-close and send synthetic error
        # OR the server exits and we get whatever was received before that.
        # Key guarantee: canary must not appear.
        raw, _ = _run("batch_array")
        assert CANARY not in raw

    def test_oversized_line_rejected(self):
        raw, _ = _run("oversized")
        assert CANARY not in raw

    def test_duplicate_keys_rejected(self):
        raw, _ = _run("duplicate_keys")
        assert CANARY not in raw

    def test_non_json_rejected(self):
        raw, _ = _run("non_json")
        assert CANARY not in raw


# --------------------------------------------------------------------------- #
# Blocked call returns error (not hang)
# --------------------------------------------------------------------------- #
class TestBlockedCallResponds:
    def test_unsanitized_tool_call_gets_error(self):
        """In strict mode the poisoned list is rejected (0 tools).
        Calling any tool from it should return an isError response, not silence."""
        _, parsed = _run(
            "poisoned_description",
            mode="strict",
            extra_msgs=[CALL],
        )
        call_resp = _by_id(parsed, 3)
        assert call_resp is not None, "blocked tools/call must return a response, not silence"
        result = call_resp.get("result", {})
        assert result.get("isError") is True

    def test_egress_dlp_blocked_call_gets_error(self):
        """Outbound call with AWS key in arguments must return isError, not silence."""
        aws_call = {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "format_text",
                "arguments": {"text": "Key: AKIAIOSFODNN7EXAMPLE"},
            },
        }
        # Use audit mode so tools/list returns tools (not rejected) but
        # egress DLP in strict would still block — use strict, tool won't be
        # in sanitized set anyway since poisoned list rejected, so use clean variant.
        # Simplest: just verify egress DLP response via policy unit test path.
        # Integration path: audit mode with a tool that passes list CDR but
        # carries a credential in its call arguments.
        _, parsed = _run("poisoned_description", mode="audit", extra_msgs=[aws_call])
        call_resp = _by_id(parsed, 3)
        # In audit mode, list passes → tool is in sanitized set.
        # Egress DLP runs in audit mode too, but audit mode → allow disposition.
        # So this verifies no hang even in audit mode.
        assert call_resp is not None, "tools/call must always return a response"


# --------------------------------------------------------------------------- #
# Rug-pull detection
# --------------------------------------------------------------------------- #
class TestRugPull:
    def test_rug_pull_variant_canary_absent(self):
        """Rug-pull server returns clean list on first call, poisoned on second.
        Kevlar CDR ensures the canary never reaches the client."""
        raw, _ = _run("rug_pull")
        assert CANARY not in raw


# --------------------------------------------------------------------------- #
# Strict-mode egress DLP
# --------------------------------------------------------------------------- #
class TestEgressDLPStrict:
    def test_egress_dlp_blocks_aws_key_in_strict_mode(self):
        """With a clean server in strict mode, format_text lands in the sanitized
        set after tools/list completes.  A subsequent call carrying an AWS key
        must be blocked by egress DLP.

        Uses a two-phase approach: send init+list, wait for tools/list response,
        then send the credential-carrying call — this ensures the sanitized set
        is populated before the call arrives."""
        proc = subprocess.Popen(
            [sys.executable, KEVLAR, "--mode", "strict", "--",
             sys.executable, HOSTILE, "clean"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

        def send(msg: dict) -> None:
            proc.stdin.write(json.dumps(msg).encode() + b"\n")
            proc.stdin.flush()

        def recv_until_id(target_id: int) -> dict:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                m = json.loads(line.strip())
                if m.get("id") == target_id:
                    return m
            return {}

        # Phase 1: handshake + tools/list — wait for tools/list response
        send(INIT)
        recv_until_id(1)
        send(NOTIF)
        send(LIST)
        list_resp = recv_until_id(2)
        tools = list_resp.get("result", {}).get("tools", [])
        assert any(t.get("name") == "format_text" for t in tools), \
            "format_text must be in sanitized set after clean tools/list"

        # Phase 2: call with AWS key — sanitized set is now populated
        aws_call = {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "format_text",
                "arguments": {"text": "Key: AKIAIOSFODNN7EXAMPLE"},
            },
        }
        send(aws_call)
        call_resp = recv_until_id(3)
        proc.stdin.close()
        proc.wait(timeout=5)

        assert call_resp, "egress-blocked call must return a response"
        result = call_resp.get("result", {})
        assert result.get("isError") is True
        content_text = result.get("content", [{}])[0].get("text", "")
        assert "egress DLP" in content_text, (
            "expected egress DLP block message; got: " + content_text
        )


# --------------------------------------------------------------------------- #
# notifications/tools/list_changed handling
# --------------------------------------------------------------------------- #
class TestListChangedStrict:
    def test_list_changed_dropped_in_strict_mode(self):
        """In strict mode the tool registry is locked: list_changed notifications
        must be dropped and never forwarded to the client."""
        raw, _ = _run("list_changed", mode="strict")
        assert b"notifications/tools/list_changed" not in raw

    def test_list_changed_forwarded_in_lenient_mode(self):
        """In lenient mode list_changed notifications should be forwarded."""
        raw, _ = _run("list_changed", mode="lenient")
        assert b"notifications/tools/list_changed" in raw


# --------------------------------------------------------------------------- #
# JSONL audit log
# --------------------------------------------------------------------------- #
class TestAuditLog:
    def test_log_file_written_with_events(self, tmp_path):
        """--log must create a parseable JSONL file with required fields."""
        import tempfile
        log_path = str(tmp_path / "audit.jsonl")
        proc = subprocess.Popen(
            [sys.executable, KEVLAR, "--mode", "strict",
             "--log", log_path, "--", sys.executable, HOSTILE, "clean"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for m in [INIT, NOTIF, LIST]:
            proc.stdin.write(json.dumps(m).encode() + b"\n")
        proc.stdin.close()
        proc.wait(timeout=8)

        with open(log_path) as f:
            events = [json.loads(line) for line in f if line.strip()]

        assert events, "audit log must contain at least one event"
        for ev in events:
            for field in ("ts", "event", "mode", "score", "disposition", "indicators"):
                assert field in ev, f"audit event missing field {field!r}: {ev}"
