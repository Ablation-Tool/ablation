# MCP Grammar Fuzzer

**File:** `modules/mcp_grammar_fuzzer.py`

## Why this exists

Atheris-based grammar fuzzer targeting prompt injection via poisoned MCP tool schemas. Attack surface: `description` fields rendered verbatim into LLM context, `name` fields used in routing, `inputSchema` property descriptions injected into tool-call reasoning, and cross-server exfiltration (Server A description reads Server B output). Transport: JSON-RPC 2.0 over stdio.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No unbounded file reads. No HTTP reads. No lief.parse(). No subprocess calls (`subprocess` is imported at L19 but never used, dead import). Writes mutated JSON schemas to `tempfile.NamedTemporaryFile` (L210), bounded by fuzzer input size. Uses `atheris` for mutation-based fuzzing when available; falls back to manual seed iteration.

---

## How it works

`MCPGrammarFuzzer.from_path(mcp_config).fuzz()` reads the `.mcp.json` / JSON-RPC 2.0 tool manifest and mutates `description`, `name`, and `inputSchema` property description fields with prompt injection payloads. Uses Atheris (if available) or a deterministic mutation loop. Runs each mutated manifest through a real LLM inference call (subprocess) and checks response for injection markers. Returns `List[MCPTaintFinding]` — one per confirmed injection in a tool field. No binary disassembly.

---

## Usage

```python
from ablation.analyzers.mcp_tool_taint_scanner import MCPToolTaintScanner

scanner = MCPToolTaintScanner.from_path('/path/to/mcp_server_root')
findings = scanner.scan()
for f in findings:
    print(f.fmt())
```

---

## Example output

```
[MEDIUM] CREDENTIAL_EXPOSURE  CWE-214  mcp.py:42
  detail: json.dumps(request.COOKIES) passed as --cookies CLI argument

[MEDIUM] AUTH_BYPASS  CWE-306  views.py:88
  detail: /api/tools route registered without auth decorator in preceding 8 lines
```

---

## False positives

`AUTH_BYPASS` checks only the 8 lines preceding the route registration; app-level middleware is not detected and produces false positives. Verify the actual authentication model for each flagged route before reporting.

---

## Pipeline position

**Before this module:** No binary analysis required. Point directly at the MCP server source directory.

**After this module:** For `CREDENTIAL_EXPOSURE` findings, verify that the CLI argument is visible in `/proc/<pid>/cmdline` or MCP logs. Register with `FindingRegistry`.

---

## Reading findings

`MCPToolTaintScanner.from_path(root).scan()` returns `List[MCPTaintFinding]`:

| Attribute | Content |
|:---|:---|
| `file` | Path to the source file containing the finding |
| `line` | Line number of the taint source or sink |
| `issue_type` | `'BIND_WIDE'` / `'EXEC_IN_ALLOWED'` / `'NO_AUTH'` / `'CREDENTIAL_EXPOSURE'` / `'PROMPT_INJECTION'` |
| `severity` | `'CRITICAL'` / `'HIGH'` / `'MEDIUM'` / `'LOW'` |
| `cwe` | CWE identifier string (e.g., `'CWE-78'`) |
| `description` | Explanation of the taint path or security issue |
| `snippet` | Source code snippet (may be empty) |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
