# PPC32 Function Discovery

**File:** `modules/ppc32_func_discovery.py`

## Why this exists

Discovers function entry points in stripped PowerPC 32-bit ELF binaries: ELF entry point, direct branch targets (bl/bla), and standard PPC32 prologue patterns (mflr r0; stw r0; stwu r1). Used before ppc32-got2-resolver and ppc32-taint-tracker to build the function map.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `lief.parse()`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.

---

## How it works

`PPC32FuncDiscovery.discover(data, entry_va)` finds function entry points in stripped PowerPC 32-bit ELF binaries. Three discovery passes: (1) ELF header entry point; (2) direct branch targets: `bl` (0x48000001) and `bla` (0x48000003): whose targets are within the text section; (3) prologue scan for standard PPC32 patterns: `mflr r0` (0x7C0802A6) + `stw r0, …(r1)` + `stwu r1, …` or frameless `stwu r1`. Returns a sorted `List[int]` of discovered function VAs.

---

## Usage

```python
from modules.ppc32_func_discovery import PPC32FuncDiscovery

scanner = PPC32FuncDiscovery.from_path('/path/to/ppc32_firmware.elf')
func_starts = scanner.discover()
print(scanner.report(func_starts))
```

---

## Example output

```
# PPC32FuncDiscovery.report(func_starts):
PowerPC 32-bit Function Discovery Report
==================================================
Binary VA range: 0x10000000 - 0x10025000
Entry point: 0x10001200
Total functions discovered: 47

  0x10001200  [entry point]
  0x10001280  [bl target @ 0x10001234]
  0x10001300  [prologue: mflr+stw+stwu @ 0x10001300]
  ...
```

---

## False positives

**False starts from data.** `bl` instructions in data sections (jump tables stored as immediates) produce false function starts. The PPC32 `bl` encoding is `0x48000001 | target`: any data word matching this pattern is recorded. Filter by checking that the discovered VA aligns to 4 bytes and that the first instruction matches a standard prologue.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to get the ELF layout. Pass the `.text` section data and base VA to `PPC32FuncDiscovery`.

**After this module:** Pass the discovered function starts to `PPC32TaintTracker` as `func_starts` to enable interprocedural analysis.

---

## Reading output

`PPC32FuncDiscovery.discover()` returns `Set[int]`: VA of every function entry point found.

The module-level helper `discover_ppc32_functions(elf_path)` is equivalent to `PPC32FuncDiscovery.from_path(elf_path).discover()`.

`PPC32FuncDiscovery.report(func_starts)` accepts the `Set[int]` returned by `discover()` and returns a formatted string listing all start VAs.

---

## See also

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md): behavioral candidate search on the binary
