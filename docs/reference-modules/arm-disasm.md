# ARM Disassembler

**File:** `modules/arm_disasm.py`

## Why this exists

Pure-Python ARM32 disassembler. Decodes the fixed 4-byte ARM instruction set (data processing, load/store, branch, multiply, coprocessor) with no external library dependency. Used as the disassembly layer by `arm_symbolic.py` for path-insensitive symbolic execution on ARM32 targets where Capstone is unavailable or where a lightweight dependency-free decoder is required.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.

---

## How it works

Reads the binary image and resolves the target-specific data structures (PLT, GOT, `.eh_frame`, symbol tables) to build a function and import index. Architecture-specific calling conventions and instruction encodings are applied to recover call edges, argument registers, and return value locations. Results are stored in the session `BinaryContext` so downstream tools can use resolved names and edges.

---

## Usage

```python
from ablation.analyzers.arm_disasm import ARMDisassembler

results = ARMDisassembler.from_context(ctx).run()
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

`ARMDisassembler.from_bytes(data, base=0).disassemble()` returns `List[ARMInstruction]`:

| Attribute | Content |
|:---|:---|
| `address` | Virtual address of the instruction |
| `encoding` | Raw 32-bit instruction encoding |
| `mnemonic` | Instruction mnemonic string (e.g., `'ldr'`, `'bl'`, `'mov'`) |
| `operands` | Decoded operands as a string (e.g., `'r0, [r1, #4]'`) |

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
