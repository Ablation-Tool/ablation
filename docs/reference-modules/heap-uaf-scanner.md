# HeapUAFScanner

**File:** `modules/heap_uaf_scanner.py`

## Why this exists

Detects use-after-free and double-free patterns in stripped binaries via taint-tracking of heap allocation return values (malloc/jemalloc/tcmalloc). Tracks object lifetimes across function boundaries to identify sites where a freed pointer is used after its free, the primary primitive class for modern heap exploitation.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Usage

```python
from modules.heap_uaf_scanner import HeapUAFScanner

scanner = HeapUAFScanner.from_context(ctx)
findings = scanner.scan()
for f in findings:
    print(f)
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

`HeapUAFScanner.from_path(path).scan()` returns `List[HeapFinding]`:

| Attribute | Content |
|:---|:---|
| `binary` | Path of the analyzed binary |
| `func_va` | Start VA of the function containing the vulnerability site |
| `func_name` | Name of the function (if resolved) |
| `site_va` | VA of the specific instruction flagged |
| `kind` | `UAF` / `DOUBLE_FREE` / `HEAP_OVERFLOW` / `TYPE_CONFUSION` |
| `description` | Description of the specific vulnerability pattern |
| `severity` | `HIGH` / `MEDIUM` |

`HeapFinding.fmt()` returns a one-line summary with severity tag, kind, and function context.

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
