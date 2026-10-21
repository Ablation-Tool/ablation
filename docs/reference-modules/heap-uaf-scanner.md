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
[HIGH] UAF  func_0x1a3c40 (RequestHandler::free_user_data)
  site: 0x1a3c88  use-after-free: ptr stored at +0x18 accessed after free at 0x1a3c74

[MEDIUM] DOUBLE_FREE  func_0x2b4010 (cleanup_buffer)
  site: 0x2b4058  double free: same ptr freed at 0x2b4040 and 0x2b4058
```

---

## False positives

UAF findings may fire when the freeing and the subsequent access are in different functions that the scanner cannot prove are reachable in order. Verify that the code path `free → use` is actually reachable (not guarded by a condition that prevents both from executing) before reporting.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to resolve func_starts and names. Optionally run `SemanticSearcher.query()` to narrow to allocation/free patterns first.

**After this module:** Verify UAF findings with `PathSolver` to confirm the use-after-free path is feasible. Register with `FindingRegistry`.

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
