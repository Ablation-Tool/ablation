# ARM Symbolic Execution

**File:** `modules/arm_symbolic.py`

## Why this exists

Light symbolic execution for ARM32/ARM64 binaries to determine register values at specific call sites. Used for confirming that a vulnerable sink receives attacker-controlled input before investing in full exploit development.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.

---

## How it works

`ARMSymbolicExecutor` runs path-insensitive symbolic execution over ARM32 function bodies to build per-function summaries. Symbolic domain: `Arg(index)` (function arg register r0–r3), `InputBuf(id)` (protocol buffer pointer), `Add(base, off)` (flattened pointer arithmetic), and `Unknown` (merge points or complex operations). Transfer functions for MOV, ADD, SUB, LDR, STR, BL, BLX. Output: `arg_field_writes: [(arg_idx, offset)]`, which function arguments write to which struct field offsets. No SMT solver; no path forking.

---

## Usage

```python
from pathlib import Path
from modules.arm_symbolic import ARMSymbolicAnalyzer

raw = Path('/path/to/firmware').read_bytes()
analyzer = ARMSymbolicAnalyzer(data=raw, base_addr=0x10000)

# Analyze a specific function — returns a FuncSummary
summary = analyzer.analyze_function(addr=0x11234)
print(summary)

# Mark arg 0 (r0) as the untrusted input buffer and trace writes
summary = analyzer.analyze_function(addr=0x11234, mark_inputbuf=0)
for arg_idx, field_off in summary.arg_field_writes:
    print(f"  arg[{arg_idx}] → field+0x{field_off:x}")
for off in summary.inputbuf_reads:
    print(f"  inputbuf read at +0x{off:x}")
```

---

## Example output

```
FuncSummary @ 0x11234
  arg_field_writes: [(0, 0x10), (0, 0x18)]
  inputbuf_reads: ['0x0', '0x4', '0x8']
  const_stores: {0x1c: 1}
  calls: 3 direct calls
  vcalls: 1 vtable calls
```

---

## False positives

**Merge-point precision.** The path-insensitive model assigns `Unknown` at all join points (after `if/else` merges). A value that is `Arg(0)` on one branch and a constant on the other is assigned `Unknown` at the merge. This causes false negatives for protocol fields that are only reachable via one branch.

---

## Pipeline position

**Before this module:** Use ARM32 Capstone disassembly to obtain the instruction list for the function.

**After this module:** Use the returned `arg_field_writes` summary to seed `TaintTracker`: for each `(arg_idx, offset)` pair, `arg_idx` is the tainted argument register and `offset` is the struct field the write targets.

---

## Reading findings

`ARMSymbolicAnalyzer.analyze_function(addr, mark_inputbuf=None)` returns a `FuncSummary`.

| Field | Type | Content |
|:---|:---|:---|
| `addr` | `int` | Function start address passed to `analyze_function()` |
| `name` | `str` | Name if known from symbol table; empty string if stripped |
| `arg_field_writes` | `List[Tuple[int,int]]` | `(arg_index, field_offset)` pairs: argument register written to an object field |
| `inputbuf_reads` | `List[int]` | Byte offsets into the `mark_inputbuf` arg that are read by this function |
| `const_stores` | `Dict[int,int]` | `{field_offset: constant_value}`: constants stored to object fields |
| `calls` | `List[Tuple[int, List[SymVal]]]` | `(callee_va, arg_symvals)` for direct calls made by this function |
| `vcalls` | `List[Optional[int]]` | Vtable slot indices for indirect `BLX`/`BLR` dispatches; `None` if slot unknown |

---

## See also

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md): behavioral candidate search on the binary
