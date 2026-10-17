# InterprocFieldWriter

**File:** `modules/interproc_field_writer.py`

## Why this exists

Demand-driven inter-procedural field-writer finder for stripped ARM64 binaries. Given a struct field offset, traces all functions that write to that field across call boundaries, used to identify all code paths that can corrupt a security-sensitive struct member.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Usage

```python
from ablation.analyzers.interproc_field_writer import InterprocFieldWriter

results = InterprocFieldWriter.from_context(ctx).run()
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

`interprocedural_field_writes(ctx, target_gv)` returns a `Dict[int, FuncSummary]` keyed by function VA. Each `FuncSummary`:

| Attribute | Content |
|:---|:---|
| `addr` | Function VA |
| `global_field_writes` | `List[Tuple[name, field_offset, store_pc, store_bytes]]` — stores to a known global struct field |
| `global_to_callee` | `List[Tuple[callee_va, global_name, callee_arg_idx, call_pc]]` — global forwarded to a callee |
| `arg_field_writes` | `List[Tuple[arg_idx, field_offset, store_pc, store_bytes]]` — stores to a field of an argument struct |
| `arg_to_callee` | `List[Tuple[callee_va, caller_arg_idx, callee_arg_idx, call_pc]]` — argument forwarded to a callee |
| `direct_callees` | `Set[int]` — all direct callee VAs found in BL instructions |
| `insns_scanned` | Number of instructions analyzed |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
