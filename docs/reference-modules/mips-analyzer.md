# MIPS Analyzer

**File:** `modules/mips_analyzer.py`

## Why this exists

MIPS32/MIPS64 binary analysis: function boundary detection using MIPS prologue patterns (addiu sp/sw ra), delay slot handling, GP-relative addressing ($gp + offset), and MIPS calling convention (a0–a3 argument registers). Used for embedded firmware targets that are MIPS-based (routers, cable modems, DSL equipment).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.

---

## How it works

`MIPS32TaintTracker.trace(func_va, tainted_regs)` runs source-to-sink taint tracking over MIPS32/MIPS32r2 function bodies. Sources: `recv`, `read`, and similar input functions. Register model follows O32 ABI: $a0–$a3 seeded as ARG at function entry; $v0–$v1 tainted after source calls; $t0–$t9 caller-saved (killed across calls); $s0–$s7 callee-saved (survive calls). `MIPS32FuncProfiler.profile(va)` does quick function profiling: call count, string xrefs, sink detection, without full taint propagation.

---

## Usage

```python
from modules.mips_analyzer import MIPS32TaintTracker

tracker = MIPS32TaintTracker.from_context(ctx)
findings = tracker.run_interprocedural(depth=4)
for f in findings:
    print(f)
```

---

## Example output

```
# MIPS32TaintResult.__str__() for each sink hit:
[MIPS32-TAINT] parse_packet (0x400a00) -> memcpy($a0, $a1) @ 0x400b20  [src: recv]
[MIPS32-TAINT] parse_packet (0x400a00) -> strcpy($a0) @ 0x400c40  [src: recv]

# MIPS32FuncProfiler.fmt() for quick profiling:
[mips_profiler] parse_packet @ 0x400a00
  8 calls, 3 sinks, 2 strings
  STRINGS:
    0x400b00  'Content-Length'
    0x400b14  'Transfer-Encoding'
```

---

## False positives

Symbol resolution errors produce phantom function boundaries. Verify any candidate VA against `ctx.func_starts` before analysis. Compiler-synthesized stubs (PLT entries, thunks) appear as functions in some loaders — `BinaryContext` filters known stub patterns but custom thunks may slip through.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` for symbol and import resolution. For stripped binaries, run `SemanticSearcher` first to identify candidate function VAs.

**After this module:** Pass resolved call edges and function VAs to `TaintTracker` or `SinkArgClassifier`.

---

## Reading findings

`MIPS32TaintTracker.from_context(ctx).run_interprocedural()` returns `List[TaintFinding32Mips]`:

| Attribute | Content |
|:---|:---|
| `binary` | Path of the analyzed binary |
| `func_va` | Start VA of the function containing the taint path |
| `func_name` | Name of the function (if resolved) |
| `sink_va` | VA of the dangerous sink call |
| `sink_name` | Name of the dangerous sink function |
| `tainted_args` | `List[int]` — 0-indexed positions of tainted arguments at the sink |
| `source_name` | Name of the taint source function |

`MIPS32FuncProfiler.profile(ctx, va)` returns a `MipsFuncProfile` with: `func_va`, `func_name`, `calls: List[MipsCallProfile]`, `strings: List[Tuple[int, str]]`.

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
