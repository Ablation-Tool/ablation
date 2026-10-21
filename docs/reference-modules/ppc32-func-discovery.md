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

`PPC32FuncDiscovery.discover(data, entry_va)` finds function entry points in stripped PowerPC 32-bit ELF binaries. Three discovery passes: (1) ELF header entry point; (2) direct branch targets — `bl` (0x48000001) and `bla` (0x48000003) — whose targets are within the text section; (3) prologue scan for standard PPC32 patterns: `mflr r0` (0x7C0802A6) + `stw r0, …(r1)` + `stwu r1, …` or frameless `stwu r1`. Returns a sorted `List[int]` of discovered function VAs.

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

`PPC32FuncDiscovery.discover()` returns `Set[int]` — VA of every function entry point found.

The module-level helper `discover_ppc32_functions(elf_path)` is equivalent to `PPC32FuncDiscovery.from_path(elf_path).discover()`.

`PPC32FuncDiscovery.report(func_starts)` accepts the `Set[int]` returned by `discover()` and returns a formatted string listing all start VAs.

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
