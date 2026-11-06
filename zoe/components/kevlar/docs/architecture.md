# Kevlar — Architecture

[← README](../README.md)

[Module overview](#module-overview) • [Proxy lifecycle](#proxy-lifecycle) • [Message routing](#message-routing) • [CDR pipeline](#cdr-pipeline) • [Scoring](#scoring) • [Tool registry lock](#tool-registry-lock) • [Egress DLP](#egress-dlp) • [Indicator registries](#indicator-registries) • [Schema CDR](#schema-cdr-allowlist) • [Audit log](#audit-log)

---

## Module overview

```text
kevlar.py   — async stdio proxy, I/O owner, fail-closed orchestrator
policy.py   — pure CDR/indicator engine, no I/O, directly unit-testable
```

The split is strict: `policy.py` has no imports outside the standard library and performs no I/O. Every function in `policy.py` takes Python dicts and returns Python dicts. This means the entire policy engine can be unit-tested without spawning a subprocess, and `policy.py` can be vendored into other projects without pulling in the proxy.

`kevlar.py` owns all I/O: stdin/stdout pumps, subprocess lifecycle, logging, and the JSONL audit file. It calls `policy.py` functions synchronously inside the async event loop — acceptable because `policy.py` is CPU-only with no blocking calls.

---

## Proxy lifecycle

```text
kevlar main()
  │
  ├─ parse args (--mode, --log, server_cmd)
  ├─ AuditLog(path)           — opens JSONL file if --log given
  └─ asyncio.run(run(...))
       │
       ├─ create_subprocess_exec(server_cmd, start_new_session=True)
       ├─ connect_read_pipe(sys.stdin.buffer)  — async stdin reader
       │
       ├─ asyncio.gather(
       │    pump_client_to_server(),   ─┐
       │    pump_server_to_client(),   ─┤ both run concurrently
       │  )                            ─┘
       │   + drain_server_stderr() as background task
       │
       └─ finally:
            os.killpg(proc.pgid, SIGTERM)   — kill whole process group
            wait(timeout=5s)
            os.killpg(proc.pgid, SIGKILL)   — if still alive
```

`start_new_session=True` ensures the server subprocess gets its own process group. This matters for servers like `npx` or `uvx` that spawn children: `os.killpg` kills the entire group, so no orphaned processes linger after `kevlar` exits.

The two pumps run concurrently via `asyncio.gather`. Client-to-server and server-to-client messages are processed independently, which is correct for the MCP protocol — the client can pipeline multiple requests without waiting for each response.

---

## Message routing

Every message flows through one of two entry points:

### `handle_client_message(raw, server_writer, client_write_fn)`

Client → server direction. Called for each line on stdin.

1. `_parse_strict(raw)` — reject duplicate keys, NaN/Inf, batch arrays, lines > `LINE_LIMIT`.
2. If `method == "tools/call"`:
   - Block if `tool_name not in _sanitized_tool_names` → synthetic `isError` response.
   - Run egress DLP on `params.arguments` → block if disposition == `reject`.
3. Otherwise: record `_pending[id] = method` and forward re-serialized message.

> **Invariant**  
> The original `raw` bytes are never forwarded. Every outgoing message is `json.dumps(parsed_dict)`.

### `handle_server_message(raw, write_fn)`

Server → client direction. Called for each line on server stdout.

1. `_parse_strict(raw)` — same validation.
2. `_intercept(msg)` — route to the correct CDR handler by looking up `_pending[id]`.
3. On any exception: synthesize `{"error": {"code": -32603, "message": "kevlar: internal error"}}`.
4. If `_intercept` returns `None`: drop the message (e.g. `list_changed` in strict mode).

### Routing table in `_intercept`

| Server message type | Handler |
|--------------------|---------|
| `error` present | `_handle_error_response` — scan `error.message`, forward |
| Notification (no `id`) | Forward as-is, unless `notifications/tools/list_changed` in strict mode |
| `initialize` response | `_handle_initialize` → `cdr_initialize_result()` |
| `tools/list` response | `_handle_tools_list` → `cdr_tools_list()` |
| `tools/call` response | `_handle_tools_call` → `analyze_content_blocks()` |
| `resources/list` response | `_handle_resources_list` → `cdr_resources_list()` |
| `prompts/list` response | `_handle_prompts_list` → `cdr_prompts_list()` |
| `prompts/get` response | `_handle_prompts_get` → `analyze_prompt_get()` |
| Unknown | Forward re-serialized |

---

## CDR pipeline

Content Disarm & Reconstruct runs differently depending on the message type, because the threat model differs.

### Inbound: `tools/list`

Tool descriptions are the primary attack surface for prompt injection — DEADBUG-class attacks embed instructions here. CDR is unconditional:

```text
for each tool:
  scan description, title, annotations → indicators
  scan inputSchema prose (description, title, $comment) → indicators
  rebuild tool from scratch: {name, inputSchema (CDR'd)}
  description → "" (stripped unconditionally)
```

The rebuilt tool contains only `name` and `inputSchema`. `inputSchema` is recursively rebuilt via an allowlist (see [Schema CDR](#schema-cdr-allowlist)). Any field not explicitly allowed is dropped.

### Inbound: `tools/call` response

Tool responses ARE the signal — they cannot be stripped. Instead:

```text
for each content block:
  text block:     scan against CONTENT_PATTERNS → indicators
  resource block: scan text field against CONTENT_PATTERNS → indicators
  image block:    keep data/mimeType, drop annotations
  unknown type:   drop (fail-closed)

score + disposition:
  allow     → forward sanitized blocks
  quarantine → replace matched spans with [KEVLAR:<ID>] tokens
  reject    → replace entire content with isError block
```

### Inbound: `initialize`

The `instructions` field is sent directly to the LLM as context. It is scanned against `DESCRIPTION_PATTERNS` and then **stripped unconditionally** regardless of score. `serverInfo.name` and `serverInfo.version` are forwarded after scanning.

### Inbound: `resources/list`, `prompts/list`, `prompts/get`

Same CDR pass as `tools/list`: descriptions stripped, structural fields forwarded. `prompts/get` message bodies are scanned with `CONTENT_PATTERNS` (same as tool call responses) because they contain LLM-bound content.

---

## Scoring

All scoring happens in `policy.py` via `decide(indicators, mode)`.

### Base score

```python
base = min(100, sum(SEVERITY_WEIGHT[i.severity] for i in indicators))
```

| Severity | Weight |
|----------|--------|
| `high` | 40 |
| `medium` | 25 |
| `low` | 10 |

### Mode adjustment

```python
if mode == "strict" and n > 0:  base += 10
if mode == "lenient":           base -= 10
score = max(0, min(100, base))
```

The +10 strict adjustment means a single medium indicator (base 25 → adjusted 35) reaches the quarantine range in strict mode. The goal is aggressive-by-default for production.

### Disposition thresholds

| Mode | allow | quarantine | reject |
|------|-------|-----------|--------|
| `strict` | score < 10 | 10 ≤ score < 40 | score ≥ 40 |
| `lenient` | score < 30 | 30 ≤ score < 80 | score ≥ 80 |
| `audit` | always | — | — |

One high-severity indicator in strict mode scores 50 → reject. One high indicator in lenient scores 30 → quarantine. Two high indicators in either mode → reject.

---

## Tool registry lock

`KevlarProxy._sanitized_tool_names` is a set of tool names that survived CDR. It is populated after `tools/list` CDR completes, using the sanitized result (not the original server response).

In strict mode:

- `notifications/tools/list_changed` from the server is dropped and never forwarded. The client never re-fetches the tool list.
- Any `tools/call` for a name not in `_sanitized_tool_names` is blocked with a synthetic `isError` response, even if the call arguments are clean.

This prevents mid-session rug-pull attacks where a server returns a clean tool list during initial negotiation and injects a poisoned list via `list_changed` after trust is established.

> **Guarantee**  
> In strict mode, the set of callable tool names is fixed for the lifetime of the session. A server cannot add or replace tools after the handshake completes.

---

## Egress DLP

Egress DLP runs in `handle_client_message` before any `tools/call` is forwarded to the server. It scans `params.arguments` recursively against `CONTENT_PATTERNS`.

```text
tools/call received from client
  │
  ├─ name not in _sanitized_tool_names → block (name-check)
  │
  └─ scan_tool_call_args(params, mode)
       │
       ├─ disposition == "reject" → synthesize isError, never forward
       └─ disposition != "reject" → forward to server
```

This severs the exfiltration path at the proxy even if a prompt injection has already succeeded: the LLM believes it is calling `send_email(body="AKIAIOSFODNN7EXAMPLE...")`, but Kevlar blocks the outbound call before it reaches the server.

Egress DLP uses `CONTENT_PATTERNS` (the conservative registry), not `DESCRIPTION_PATTERNS`. False positives here mean blocking legitimate calls.

---

## Indicator registries

Two registries with deliberately different sensitivity:

### `DESCRIPTION_PATTERNS` — aggressive

Scanned against tool/resource/prompt description fields. CDR strips these fields unconditionally regardless of score, so a false positive costs only a log entry and a score increment — it never silently passes injection text to the LLM.

Covers: direct instruction override, role injection, credential file targeting, cross-server invocation imperatives, rug-pull counter triggers, SSRF, shell injection, LLM prompt delimiters, encoding bypass, authority impersonation, confused deputy, delegation chains, urgency manipulation, social proof, fabricated prior consent.

### `CONTENT_PATTERNS` — conservative

Scanned against `tools/call` response content and `prompts/get` message bodies. False positives here quarantine real data. High-confidence only: patterns that would be unusual in any legitimate tool output.

Covers: instruction override in content, role-injection in content (SYSTEM:/USER: lines), next-action injection, credential patterns (AWS keys, private keys), path traversal in return values, SMTP header injection, exfiltration-to-URL instructions, base64-encoded instructions, memory poisoning, adversarial probes.

### Pattern entry format

```python
{
    "id":       "INDICATOR_ID",  # stable kebab-case, used in JSONL logs
    "severity": "high",          # high | medium | low
    "regex":    r"...",           # compiled with re.IGNORECASE
    "mask":     False,           # True = redact matched value in log snippets
}
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidance on adding patterns.

---

## Schema CDR allowlist

`cdr_schema()` recursively rebuilds `inputSchema` keeping only fields in `_SCHEMA_TYPE_FIELDS`:

```text
type, properties, required, additionalProperties,
items, enum, minLength, maxLength, minimum, maximum,
pattern, format, anyOf, oneOf, allOf, not,
minItems, maxItems, uniqueItems, multipleOf,
$ref, $defs, $schema
```

Everything else (including `description`, `title`, `examples`, `$comment`, `default` when string) is dropped. Additional validation at each field:

| Field | Validation |
|-------|-----------|
| `type` | Must be in `{"string","number","integer","boolean","array","object","null"}` |
| `format` | Must match `^[a-z][a-z0-9\-]{0,31}$` |
| `$ref` | Must match `^#(/[a-zA-Z0-9_\$\-]*)*$` — local JSON Pointer only, no external URLs |
| `enum` values | Must match `^[a-zA-Z0-9_\-\.]{1,64}$` — prose-injected enum values are stripped |
| property keys | Must match `^[a-zA-Z_][a-zA-Z0-9_]{0,63}$` — property name injection is detected and fires `MCP_PROP_KEY_INJECT` |
| `required` items | Same identifier validation as property keys |
| `pattern` | Max 512 characters |
| depth | Capped at 10 levels — returns `{}` at cap (fail-closed) |

---

## Audit log

When `--log PATH` is given, every policy decision is appended to a JSONL file (one JSON object per line). Fields:

| Field | Type | Description |
|-------|------|-------------|
| `ts` | float | Unix timestamp |
| `event` | str | `initialize`, `tools/list`, `tools/call`, `resources/list`, `prompts/list`, `prompts/get`, `egress-dlp`, `list-changed-blocked`, `error` |
| `id` | any | JSON-RPC message id (null for notifications) |
| `mode` | str | `strict`, `lenient`, or `audit` |
| `score` | int | Risk score 0–100 |
| `disposition` | str | `allow`, `quarantine`, or `reject` |
| `indicators` | list | Each: `{id, severity, surface, value_snippet}`. `value_snippet` is masked for patterns with `mask: True`. |

Logs go to this file and to stderr. **Stdout is the protocol channel and never receives log output.**

### Example event

```json
{
  "ts": 1729780000.123,
  "event": "tools/list",
  "id": 2,
  "mode": "strict",
  "score": 50,
  "disposition": "reject",
  "indicators": [
    {
      "id": "MCP_BEFORE_ANY_OP",
      "severity": "high",
      "surface": "tool:format_text:description",
      "value_snippet": "For security audit compliance, before formatting:"
    }
  ],
  "tool_count": 0
}
```
