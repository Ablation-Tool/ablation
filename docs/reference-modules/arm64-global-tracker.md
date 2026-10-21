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

`scan(binary_path, text_start, text_size)` reads the binary with a 256 MB size guard, then walks the `.text` range in 4-byte steps. For each word it checks for `STR Xt, [Xn, #imm]` and `STUR Xt, [Xn, #simm]` instructions. For each write, it back-traces the register's SSE (Symbolic Stack Expression) state: `ADRP + ADD/LDR` sequences that resolve to a known GOT slot map the write to a named global symbol. Writes to unknown registers record the raw SSE. Returns `List[WriteRecord]` — one per global variable write site. `report(records)` groups writes by symbol name and prints them.

---

## Usage

```python
from modules.arm64_global_tracker import scan, report
from pathlib import Path
import lief

binary = lief.parse('/path/to/arm64_firmware.elf')
text_sec = binary.get_section('.text')
text_data = bytes(text_sec.content)
text_start = text_sec.virtual_address

records = scan(Path('/path/to/arm64_firmware.elf'), text_start=text_start,
               text_size=len(text_data))
report(records)
```

---

## Example output

```
============================================================
GLOBAL: __mmtls_ctx  (3 writes)
============================================================
  pc=0x246364  field=+0x00  STR x0,[x19,#0x0]
        base_sse=Global('__mmtls_ctx', 0)
  pc=0x246380  field=+0x08  STR x1,[x19,#0x8]
        base_sse=Global('__mmtls_ctx', 0)
  pc=0x246390  field=+0x10  STR x2,[x19,#0x10]
        base_sse=Global('__mmtls_ctx', 0)
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
