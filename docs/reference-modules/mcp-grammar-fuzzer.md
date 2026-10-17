# MCP Grammar Fuzzer

**File:** `modules/mcp_grammar_fuzzer.py`

## Why this exists

Atheris-based grammar fuzzer targeting prompt injection via poisoned MCP tool schemas. Attack surface: `description` fields rendered verbatim into LLM context, `name` fields used in routing, `inputSchema` property descriptions injected into tool-call reasoning, and cross-server exfiltration (Server A description reads Server B output). Transport: JSON-RPC 2.0 over stdio.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No unbounded file reads. No HTTP reads. No lief.parse(). No subprocess calls (`subprocess` is imported at L19 but never used, dead import). Writes mutated JSON schemas to `tempfile.NamedTemporaryFile` (L210), bounded by fuzzer input size. Uses `atheris` for mutation-based fuzzing when available; falls back to manual seed iteration.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

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
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

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
