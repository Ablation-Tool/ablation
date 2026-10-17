# GoDangerousCallers

**File:** `modules/go_dangerous_callers.py`

## Why this exists

Pre-built callgraph scanner for Go binaries: identifies dangerous call sites (unsafe.Pointer casts, reflect.NewAt, os.exec, net/http.Get) with rodata-first string extraction and Go itab resolution. Single text scan builds the full callgraph; subsequent lookups are O(1).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. `lief.parse()` used in `_build_section_map()` (L167), wrapped in `try/except Exception` + `if self._lb is None` check. No HTTP reads.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Usage

```python
from ablation.analyzers.go_dangerous_callers import GoDangerousCallers

results = GoDangerousCallers.from_context(ctx).run()
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

## Reading findings

`GoDangerousCallerScanner.build(ctx).query_dangerous_callers()` returns `List[DangerousCallHit]`:

| Attribute | Content |
|:---|:---|
| `func_name` | Name of the function containing the dangerous call |
| `func_va` | Start VA of the containing function |
| `call_va` | VA of the specific call instruction |
| `call_target_va` | VA of the dangerous function being called |
| `call_target_name` | Resolved name of the dangerous callee |
| `string_refs` | `List[Tuple[int, str]]` — (VA, string) pairs for string refs in the same function |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
