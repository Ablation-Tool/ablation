# ChunkWalkerValidator

**File:** `modules/chunk_walker_validator.py`

## Why this exists

Detects TLV/chunk parsers in stripped x86-64 binaries that advance the chunk pointer by raw user-supplied length without rounding up to the next 4-byte boundary. Many protocols (SCTP RFC 9260, DNS RFC 1035, GRE, PPTP, IS-IS) require chunk/TLV boundaries to be 4-byte aligned; a parser that does `ptr += raw_length` instead of `ptr += (raw_length + 3) & ~3` will misparse the next chunk because padding bytes become the next type and length fields.

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
from modules.chunk_walker_validator import ChunkWalkerValidator

validator = ChunkWalkerValidator.from_context(ctx)
findings = validator.scan()
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

`ChunkWalkerValidator.from_context(ctx).scan()` returns `List[ChunkWalkFinding]`:

| Attribute | Content |
|:---|:---|
| `func_va` | Start VA of the function containing the unaligned chunk advance |
| `advance_va` | VA of the pointer advance instruction (`ptr += raw_length`) |
| `advance_reg` | Register holding the chunk pointer being advanced |
| `length_reg` | Register holding the raw user-supplied length value |
| `aligned` | `True` if an alignment rounding pattern was found in the instruction lookahead |
| `read_va` | VA of the next field read after the advance (0 if not found in window) |

`ChunkWalkFinding.fmt()` returns a formatted string tagged `[ALIGNED]` or `[UNALIGNED]`.

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
