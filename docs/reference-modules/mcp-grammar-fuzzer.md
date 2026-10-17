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
from ablation.analyzers.mcp_grammar_fuzzer import MCPGrammarFuzzer

results = MCPGrammarFuzzer.from_context(ctx).run()
for r in results:
    print(r)
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

## Reading output

`mcp_grammar_fuzzer.run(argv)` is a CLI entry point — it writes results to stdout and to a JSONL output file. There is no typed finding dataclass.

Each JSONL record written to the output file is a dict:

| Key | Content |
|:---|:---|
| `tool` | MCP tool name being fuzzed |
| `case_id` | Integer case identifier within this run |
| `input` | The generated input dict sent to the tool |
| `response` | Raw tool response string |
| `anomaly` | `True` if the response triggered a grammar anomaly |
| `verdict` | `'CRASH'` / `'ERROR'` / `'ANOMALY'` / `'OK'` |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
