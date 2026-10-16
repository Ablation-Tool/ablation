# PPC32HeapSlotScanner

## Why this exists

Three things were not possible before in Ablation:

1. **Detect the heap slot overflow class systematically on PPC32 XCOFF binaries.** The VIOS ioscli IZ22147 analysis (VIOS-VTD-001) found a heap overflow in `getBackingDevices()` where `mulli r3,r3,0x44` computes a 68-byte slot size, then `bl.strcpy` copies a 2048-byte `fgets` buffer into each slot with no bounds check. `TaintTracker` and `SinkArgClassifier` do not detect this class because the slot boundary is arithmetic. The overflow condition is slot\_N vs. fgets\_max, where slot\_N requires interpreting the `mulli` immediate.

2. **Avoid per-target manual disassembly for a known pattern.** AIX ioscli, VIOS utilities, and IBM network daemons share this pattern in ODM attribute reader code. A dedicated scanner runs in under 60 seconds and produces byte-verifiable findings with exact VAs and instruction encodings.

3. **Handle XCOFF32 text section discontinuities.** AIX XLC inserts trap stubs and null-padded inter-function gaps that terminate Capstone disassembly at the first null word when `skipdata` is not enabled. The scanner enables `cs.skipdata = True`, which skips over padding words and ensures all functions in the section are reached.

## Pattern detected

Within one function in `.text`:

1. `mulli rD, rS, N`: slot size N, where `0x10 <= N <= 0x400`
2. `bl <malloc>`: within 6 instructions of the `mulli`
3. `bl <strcpy/strcat/sprintf>`: within 512 instructions of `malloc`, without an intervening `cmpwi`/`cmplwi` that bounds-checks the source

The `has_size_check` field is `True` when any `cmpwi`/`cmplwi` appears between `malloc` and the copy call. Note: a size check on the `malloc` return value (null pointer check) also triggers `has_size_check`. Analysts should verify whether the comparison guards the copy size or only the allocation result.

## Usage

```python
from modules.ppc32_heap_slot_scanner import PPC32HeapSlotScanner

scanner = PPC32HeapSlotScanner('/path/to/ioscli')
findings = scanner.scan()
print(PPC32HeapSlotScanner.report(findings))

# From BinaryContext
scanner = PPC32HeapSlotScanner.from_context(ctx)
```

## Key API

| Symbol | Description |
|--------|-------------|
| `PPC32HeapSlotScanner(binary_path)` | Constructor; accepts ELF32 PPC or XCOFF32 executable |
| `PPC32HeapSlotScanner.from_context(ctx)` | Construct from `BinaryContext` |
| `PPC32HeapSlotScanner.scan()` | Returns `list[HeapSlotFinding]` |
| `PPC32HeapSlotScanner.report(findings)` | Human-readable summary string |
| `HeapSlotFinding.func_name` | Enclosing function name (best-effort from symtab) |
| `HeapSlotFinding.mulli_va` | VA of the `mulli` instruction |
| `HeapSlotFinding.slot_size` | N bytes per heap slot |
| `HeapSlotFinding.malloc_va` | VA of the `bl malloc` instruction |
| `HeapSlotFinding.strcpy_va` | VA of the `bl strcpy/strcat/sprintf` instruction |
| `HeapSlotFinding.has_size_check` | `True` if a comparison appears between malloc and copy |
| `HeapSlotFinding.mulli_bytes` | 4 raw bytes at `mulli_va` (for byte-verification) |
| `HeapSlotFinding.strcpy_bytes` | 4 raw bytes at `strcpy_va` (for byte-verification) |

## Known positives

| Binary | Function | mulli VA | Slot | strcpy VA | Note |
|--------|----------|----------|------|-----------|------|
| VIOS ioscli (IZ22147) | `getBackingDevices` | `0x10001514` | 68B | `0x10001668` | VIOS-VTD-001 CONFIRMED HIGH |

## FORGE audit

Gate: **PASSED** (2 INFO findings).

- INFO: Slice at `mulli_va - text_va_base` is not guarded for underflow. Not reachable in practice since Capstone iterates from `text_va_base`.
- INFO: `list(cs.disasm(...))` materialises ~130K instruction objects for a 512KB text section (~26MB). Acceptable for analyst tooling.

---

## How it works

Reads the binary image and resolves the target-specific data structures (PLT, GOT, `.eh_frame`, symbol tables) to build a function and import index. Architecture-specific calling conventions and instruction encodings are applied to recover call edges, argument registers, and return value locations. Results are stored in the session `BinaryContext` so downstream tools can use resolved names and edges.

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

## Reading findings

| Field | Content |
|:---|:---|
| `va` | Virtual address of the resolved symbol, function, or instruction |
| `name` | Recovered name if available, empty string if stripped |
| `detail` | What was resolved or decoded |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` — how certain the resolution is |

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
