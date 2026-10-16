# MCP Tool Taint Scanner

**File:** `ablation/analyzers/mcp_tool_taint_scanner.py`

## Why this exists

FortiManager v8.0.0 ships an AI/MCP stack (`ai/agent/agent_framework/`). Two confirmed findings required manual source analysis because no automated scanner existed:

1. **FMG-AI-1 (CWE-214, MEDIUM)**, `mcp.py` serializes `request.COOKIES` to JSON and passes it as `--cookies` CLI argument to `/usr/bin/webmcpserver`. The session token is visible in `/proc/<pid>/cmdline` for the subprocess lifetime, world-readable on Linux by default.

2. **FMG-AI-2 (CWE-77, MEDIUM)**, `agent_views.py` places a user-supplied FortiGate CLI script as the system-role content to an LLM security analyzer, enabling prompt injection into the AI's trust context.

Gap closed: 2026-10-16. Both FMG findings re-detected automatically in validation run.

---

## Finding classes

| Class | CWE | Severity | Pattern |
|---|---|---|---|
| `CREDENTIAL_EXPOSURE` | CWE-214 | MEDIUM | `json.dumps(request.COOKIES/headers)` → CLI arg within 30 lines |
| `PROMPT_INJECTION` | CWE-77 | HIGH/MEDIUM | User-input variable near system-role message assignment |
| `TRANSPORT_EXPOSURE` | CWE-284 | MEDIUM/LOW | `host="0.0.0.0"` in MCP server config without auth context |
| `AUTH_BYPASS` | CWE-306 | MEDIUM | `/mcp` route without recognized auth decorator in preceding 8 lines |

## Key API

```python
from ablation.analyzers.mcp_tool_taint_scanner import McpToolTaintScanner

# Directory tree
findings = McpToolTaintScanner.from_path('/tmp/fortimanager/ai/').scan()
print(McpToolTaintScanner.report(findings))

# Single file
findings = McpToolTaintScanner.scan_file('/tmp/app/mcp.py')

# Filter by severity
highs = [f for f in findings if f.severity in ('HIGH', 'CRITICAL')]
```

## Severity escalation

`PROMPT_INJECTION` starts at MEDIUM, escalates to HIGH when the user-input variable is directly assigned as the `content=` field of a system-role message (direct assignment = higher exploitability).

`TRANSPORT_EXPOSURE` starts at MEDIUM, drops to LOW when auth-related keywords (`auth`, `middleware`, `jwt`, `bearer`) appear in the surrounding ±10-line context.

## Detection limitations

- **CREDENTIAL_EXPOSURE** uses a 30-line window to track `json.dumps(COOKIES)` → launch site. Two-hop taint via an intermediate list variable (e.g., `all_cli_args = ['--cookies', cookies]`) is the maximum tracked depth.
- **PROMPT_INJECTION** uses a ±20-line window around the system-role assignment; it does not perform full dataflow analysis.
- **AUTH_BYPASS** only checks decorators in the 8 lines before the route registration; middleware registered at app-init level is not detected.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No subprocess, eval, shell=True, or network I/O. All file reads use `errors="replace"` encoding guard. OSError handled. Taint window bounded at 30 lines. Regex patterns compiled at module level.

Validated on FortiManager v8.0.0 AI stack: FMG-AI-1 (CREDENTIAL_EXPOSURE) and FMG-AI-2 (PROMPT_INJECTION) re-detected automatically.
