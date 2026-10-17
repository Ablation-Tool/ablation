# CallsiteTracer

**File:** `modules/callsite_tracer.py`

## Why this exists

Backward-slices argument registers (x0–x7) at ARM64 BL call sites to confirm that a target function receives a specific value. Primary use: verifying GOT-based struct pointer aliasing in stripped ARM64 shared objects (e.g., WeChat libwechatnetwork.so).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_SO_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `if binary is None` check. `_MAX_SO_BYTES=256MB`. No HTTP reads.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Usage

```python
from ablation.analyzers.callsite_tracer import CallsiteTracer

results = CallsiteTracer.from_context(ctx).run()
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

`backward_slice(raw, binary, callsite_va, arg_regs)` returns `Dict[str, SymbolicVal]` — a map from register name to symbolic value at `callsite_va`. The four symbolic value types:

| Type | Meaning |
|:---|:---|
| `Const(v)` | Register holds an immediate constant `v` at the callsite |
| `Global(name, delta)` | Register holds a known global symbol address + byte delta |
| `Add(base, imm)` | Register holds `base` (Arg or Global) plus an immediate offset |
| `Arg(idx, delta)` | Register holds the function's `idx`-th argument + delta |
| `Unknown(reg, pc)` | Provenance not resolved within the look-back window |

Check `isinstance(v, Arg)` to identify argument-derived values before reporting as taintable.

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
