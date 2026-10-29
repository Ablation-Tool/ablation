<a id="arm64-symbolic-slicing"></a>
# ARM64 Data-Flow Slicing

Trace ARM64 store addresses backward through structured symbolic expressions (SSE) to find writes to a selected global address, global object, or structure field.

**Files:** `modules/sse_slicer.py` · `modules/arm64_global_tracker.py`

---

## Why these scanners exist

A taint tracker asks where a value goes. These scanners answer the inverse address question: which stores might write here? That is useful when a global flag or structure field changes behavior and its writers are more important than a general network-to-sink path.

The backward walk builds a small symbolic expression for each store base, resolving constants, pointer arithmetic, selected loads, and configured GOT entries. Exact and possible results are kept separate so unresolved memory does not become a fabricated address. Users gain a focused provenance aid that complements CFG taint analysis rather than replacing it. The slicer and GOT catalogue can be extended independently as new address idioms are validated; unresolved cases remain explicit instead of being treated as proof of no writes.

## When to use this

Use these scanners when you know a global address or GOT-backed object and need to answer **which instructions write to it?** They are useful for reconstructing global state initialization, configuration structures, and writes through pointers recovered from the GOT.

These are backward address-provenance scanners, not CFG taint trackers. They do not determine whether attacker-controlled input reaches a sink and do not replace `ARM64TaintTracker` or `PathSolver`.

## Inputs and prerequisites

- A little-endian AArch64 binary.
- The file offset and size of the `.text` region to scan.
- For `sse_slicer.scan()`, the target virtual address and object size in bytes.
- For `arm64_global_tracker.scan()`, GOT entries in that module's `GOT_CATALOGUE` describing the globals to resolve.

The scanners interpret `text_start` as a file offset. Addresses printed for instructions and SSE expressions use the same address space as the supplied binary mapping; confirm this mapping for binaries whose `.text` file offset differs from its virtual address. Both scanners reject files larger than 256 MiB.

## How it works

`backward_sse()` walks backward from a store's base register and builds an expression for its origin:

| Expression | Meaning |
|:---|:---|
| `Const(value)` | A constant or page address resolved from an immediate or `ADRP`. |
| `Add(base, offset)` / `Sub(base, offset)` | Constant pointer arithmetic. |
| `Mem(base, offset)` | A pointer load that requires a memory value to resolve. |
| `Global(name, delta)` / `GlobAdd(...)` | A GOT-backed global recognized by the global tracker. |
| `Unknown(register, pc)` | The origin could not be resolved within the supported instruction set or depth limit. |

The slicer recognizes a bounded subset of ARM64 address-construction instructions, including `ADRP`, immediate arithmetic, selected loads/stores, and register moves. Calls invalidate unresolved caller-saved registers. The global tracker also recognizes configured GOT slots.

`sse_slicer.scan()` examines `STR` and `STP` stores and returns two lists:

- **exact writers:** the effective address evaluates inside the requested target range;
- **possible writers:** the expression contains an unresolved memory load, so the destination remains uncertain.

`arm64_global_tracker.scan()` examines `STR`, `STUR`, and `STP` stores and returns `WriteRecord` objects for destinations resolved to configured globals. Each record includes the instruction address and text, symbol, field offset, write size, and base SSE.

## Python usage

```python
from pathlib import Path
from modules.sse_slicer import scan as scan_target

exact, possible = scan_target(
    binary=Path('/path/to/arm64-binary.so'),
    target=0x3D4648,
    target_size=72,
    text_start=0xDD130,  # .text file offset
    text_size=0x2DE650,
    verbose=True,
)

for pc, source_reg, base_reg, offset, address, expression in exact:
    print(f'0x{pc:x}: writes 0x{address:x}; base={expression!r}')
```

To scan configured GOT-backed globals:

```python
from pathlib import Path
from modules.arm64_global_tracker import report, scan

records = scan(
    binary=Path('/path/to/arm64-binary.so'),
    text_start=0xDD130,
    text_size=0x2DE650,
)
report(records)

for record in records:
    print(record.symbol, hex(record.field_off), hex(record.pc))
```

## Command-line usage

```bash
python modules/sse_slicer.py \
  --binary /path/to/arm64-binary.so \
  --target 0x3d4648 --size 72 \
  --text-start 0xdd130 --text-size 0x2de650 \
  --verbose
```

```bash
python modules/arm64_global_tracker.py \
  --binary /path/to/arm64-binary.so \
  --text-start 0xdd130 --text-size 0x2de650
```

## Limitations

- This is a bounded, linear backward slice, not a whole-program alias analysis. Unsupported instructions, indirect pointers, interprocedural values, and unresolved memory loads can prevent an exact result.
- An exact address match identifies a write destination; it does not establish runtime reachability, attacker control, or exploitability.
- A possible writer is only a review candidate. Inspect the memory expression and calling context before treating it as a write to the target.
- The global tracker only resolves globals represented in its GOT catalogue. It does not discover arbitrary symbols or every global in a binary.
- Confirm file-offset/virtual-address mapping and store width during manual review, especially for packed or unusually linked binaries.

## Related tools

- [Data-Flow Taint Analysis](taint-analysis.md): tracks attacker-controlled values to security-sensitive operations.
- [Register & Argument Tracking](call-argument-annotation.md): annotates call arguments with symbolic provenance.
- [Control & Data-Flow Analysis](control-flow-graph-construction.md): provides CFG-based constant propagation and reaching definitions.
