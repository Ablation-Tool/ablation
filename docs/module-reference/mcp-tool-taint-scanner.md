# MCPToolTaintScanner

## Why this exists

Three things were not possible before in Ablation:

1. **Detecting BIND_WIDE in MCP HTTP transports** — FMGMCP-1 (HIGH: unauthenticated code execution via FortiManager admin token) required manually reading `transport.ts` to find `httpServer.listen(config.mcpHttpPort)` with no host argument. Node.js defaults a no-host `listen(port)` call to 0.0.0.0. No scanner detected this; this module automates it for both JS/TS and Python.

2. **Detecting exec-class methods in ALLOWED_METHODS** — FMGMCP-2 (CRITICAL: prompt injection → FortiGate device control) required manually reading `code-executor.ts` to find `'exec'` in the `ALLOWED_METHODS` Set. Any LLM receiving a server-controlled response can call `fortimanager.request('exec', ...)` to run scripts on managed devices. This module catches the pattern regardless of how the set is defined (TypeScript `new Set([])`, Python `set()` or `{}`).

3. **Detecting missing auth on /mcp endpoints** — MCP server frameworks (Express, FastAPI, FastMCP) have no built-in auth requirement on HTTP transports. The `/mcp` endpoint in fortimanager-code-mode-mcp has only rate limiting (60 req/min). This module flags route definitions without visible auth middleware in a 15-line window.

## What it does

Scans TypeScript, JavaScript, and Python source files for three issue types:

| Type | Pattern | Severity | CWE |
|---|---|---|---|
| BIND_WIDE | `.listen(port)` without host (Node.js defaults to 0.0.0.0), or `host='0.0.0.0'` | HIGH | CWE-668 |
| EXEC_IN_ALLOWED | `ALLOWED_METHODS` contains exec-class method (`exec`, `execute`, `run`, `shell`, `eval`, `spawn`) | CRITICAL | CWE-284 |
| NO_AUTH | `/mcp` route or MCP HTTP transport defined without auth middleware nearby | HIGH | CWE-306 |

## Usage

```python
from ablation.analyzers.mcp_tool_taint_scanner import MCPToolTaintScanner

results = MCPToolTaintScanner.from_path('/path/to/mcp-server').scan()
print(MCPToolTaintScanner.report(results))
```

CLI:
```
python3 -m ablation.analyzers.mcp_tool_taint_scanner /path/to/mcp-server
python3 -m ablation.analyzers.mcp_tool_taint_scanner /path/to/mcp-server --severity HIGH
```

## FMGMCP-1 reproduction

```typescript
// transport.ts:214
httpServer.listen(config.mcpHttpPort, () => {
    console.log(`MCP server listening`);
});
```

Scanner detects: BIND_WIDE (no host arg → 0.0.0.0). Severity HIGH.

## FMGMCP-2 reproduction

```typescript
// code-executor.ts
const ALLOWED_METHODS = new Set(['get', 'set', 'add', 'update', 'delete', 'exec', ...])
```

Scanner detects: EXEC_IN_ALLOWED (`'exec'` in ALLOWED_METHODS). Severity CRITICAL.

## Known limitations

- **BIND_WIDE false negatives**: multi-line `.listen(...)` calls where the closing `)` is on a different line than the opening `(` are not detected by the regex (the `[^)]` pattern doesn't cross newlines).
- **NO_AUTH proximity heuristic**: auth middleware 16+ lines away from the route won't be detected. Cross-file middleware registration (e.g., `app.use(authMiddleware)` in a separate module) won't be detected.
- **FastMCP multiline run()**: `mcp.run(\n    transport='http',\n)` with transport on a different line is not detected as HTTP.
- **LLM_PROXY not implemented**: detecting which MCP tools receive LLM output and proxy it to privileged API calls requires cross-function/cross-file taint analysis not implemented here.
