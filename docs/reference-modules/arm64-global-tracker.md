# ARM64GlobalTracker

**File:** `modules/arm64_global_tracker.py`

## Why this exists

Tracks ARM64 global variable access patterns (ADRP+LDR/STR sequences) to map BSS/data section usage in stripped binaries. Enables identification of state variables and persistent buffers without symbols.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `read_bytes()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.

---

## How it works

Reads the binary image and resolves the target-specific data structures (PLT, GOT, `.eh_frame`, symbol tables) to build a function and import index. Architecture-specific calling conventions and instruction encodings are applied to recover call edges, argument registers, and return value locations. Results are stored in the session `BinaryContext` so downstream tools can use resolved names and edges.

---

## Usage

```python
from ablation.analyzers.arm64_global_tracker import ARM64GlobalTracker

results = ARM64GlobalTracker.from_context(ctx).run()
for r in results:
    print(r)
```

---

## Example output

```
Resolved 847 PLT entries
Recovered 312 function starts from .eh_frame
Named 28 functions from DWARF remnants

va=0x401200  name=verify_admin_token  confidence=HIGH
va=0x4015C0  name=process_http_request  confidence=HIGH
va=0x403A00  name=''  confidence=MEDIUM  (stripped)
```

---

## False positives

Symbol resolution errors produce phantom function boundaries. Verify any candidate VA against `ctx.func_starts` before analysis. Compiler-synthesized stubs (PLT entries, thunks) appear as functions in some loaders — `BinaryContext` filters known stub patterns but custom thunks may slip through.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` for symbol and import resolution. For stripped binaries, run `SemanticSearcher` first to identify candidate function VAs.

**After this module:** Pass resolved call edges and function VAs to `TaintTracker` or `SinkArgClassifier`.

---

## Reading output

The slicer returns a list of `WriteRecord` objects per target global symbol.

| Field | Type | Content |
|:---|:---|:---|
| `pc` | `int` | VA of the STR/STP instruction performing the write |
| `insn` | `str` | Disassembled instruction text |
| `symbol` | `str` | Target global name (e.g., `mmtls::gILinkKey`) |
| `field_off` | `int` | Byte offset from the symbol base being written |
| `size` | `int` | Write size in bytes: 8 for STR, 16 for STP pair |
| `base_sse` | `SSE` | SSE expression for the base register before `field_off` is applied |

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
