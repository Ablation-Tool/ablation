# GoX86StripScanner

`ablation/analyzers/go_x86_strip_scanner.py`

## Why this exists

Three gaps hit simultaneously on any stripped x86-64 Go binary:

1. **BinaryContext yields only 3 func_starts.** Go's `-ldflags="-s -w"` strips DWARF
 and.symtab but always embeds `.gopclntab` in.rodata (the runtime needs it for stack
 unwinding). After stripping, the section header for `.gopclntab` is gone. BinaryContext's
 ELF-based extraction finds nothing. fos_server (FortiClientEMS v7.4.5, 21 MB, Go 1.22.6):
 3 func_starts vs 23,396 in the pclntab.

2. **All downstream tools break with 3 boundaries.** SemanticSearcher, FuncProfiler, and
 TaintTracker iterate ctx.func_starts to slice function windows. With 3 boundaries the
 effective coverage is near zero.

3. **Go pclntab magic and pcHeader layout differ across versions.** Go 1.2–1.17 use a
 different header layout than Go 1.18+. Scanning for the wrong magic produces false
 positives. This module detects version from magic, validates the header (pad=0, quantum=1,
 ptrSize=8 for x86-64), and parses the correct layout.

## Constructor patterns

```python
from ablation.analyzers.go_x86_strip_scanner import GoX86StripScanner

# From file path:
scanner = GoX86StripScanner.from_path('/path/to/stripped_go_binary')

# From existing BinaryContext:
scanner = GoX86StripScanner.from_context(ctx)

# Detection helper:
GoX86StripScanner.is_go_x86_64('/path/to/binary')  # → bool
```

## Key methods

```python
result = scanner.scan()          # → GoScanResult (cached after first call)
print(result.summary())          # one-block summary: version, offset, nfunc, named count
result.funcs                     # {va: name} — name='' when not recovered
result.func_starts               # sorted list of VAs
result.named_funcs               # {va: name} for named subset only
result.go_version                # 'Go1.20+', 'Go1.18-1.19', etc.

added = scanner.patch_context(ctx)   # adds VAs + sets names in ctx; returns count added
```

## Typical workflow

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.go_x86_strip_scanner import GoX86StripScanner

ctx = BinaryContext.load_or_build('/path/to/stripped_go.elf')
# ctx.func_starts may have only a handful of entries here

scanner = GoX86StripScanner.from_context(ctx)
if scanner.is_go_x86_64(ctx.path):
    added = scanner.patch_context(ctx)
    print(f'Added {added} pclntab-recovered function starts')
# Now ctx.func_starts has all pclntab entries; downstream tools work normally
```

## Notes

- **Name recovery is partial.** Only functions whose `funcoff` aligns with the start of a
 null-terminated string in the funcnametab get a name. In Go 1.22 (fos_server), this was
 276/23,396. VA recovery is complete (all 23,396 recovered). This is a known gap: the
  `funcoff` interpretation for intra-string offsets in the funcnametab is not yet resolved.
- **Go 1.16–1.17 and 1.2–1.15** name recovery is not implemented; VAs are recovered.
- Run `patch_context` BEFORE SemanticSearcher, FuncProfiler, or TaintTracker on any
 stripped Go binary, otherwise those tools have no function windows to work with.
- The pclntab scan is O(filesize) and typically takes < 1 second for binaries up to 100 MB.

---

## How it works

`GoX86StripScanner.scan()` locates the Go pclntab (magic `0xFFFFFAFF` / `0xFFFFFAFB` at the start of the table) in the binary image, parses the function table, and recovers the name and entry VA for every function in the table. No func_starts iteration — it reads the pclntab structure directly. The result is a `GoScanResult` with a complete `Dict[int, str]` VA-to-name map. `result.func_starts` returns just the entry VAs as a sorted list for injection into `BinaryContext`.

---

## Usage

```python
from ablation.analyzers.go_x86_strip_scanner import GoX86StripScanner
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/go_binary.elf')
scanner = GoX86StripScanner.from_context(ctx)
result = scanner.scan()
print(result)
```

---

## Example output

```
GoScanResult  /path/to/service  go1.21.3  nfunc=2847
  text_start=0x00401000  pclntab_file_off=0x01234560
  funcs: {0x00401000: 'main.main', 0x00401840: 'main.handleRequest', ...}
  named_funcs: 2840 / 2847  (7 anonymous)
```

---

## False positives

None — pclntab parsing is structural and produces exact function starts. The only failure mode is a binary where the Go toolchain was deliberately modified to strip or corrupt the pclntab, in which case the scanner returns an empty `funcs` dict.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` for the stripped Go binary. Confirm `ctx.func_starts` is empty or incomplete (pclntab was not found by default extraction).

**After this module:** Call `scanner.scan()` and inject the result: `ctx.set_func_starts(result.func_starts)`. Then run `SemanticSearcher.query()` with the populated starts.

---

## Reading output

`GoX86StripScanner(path).scan()` returns a `GoScanResult`:

| Attribute | Content |
|:---|:---|
| `binary_path` | Path to the analyzed binary |
| `funcs` | `Dict[int, str]` — VA-to-name map for all recovered functions |
| `go_version` | Go version string extracted from pclntab (e.g., `'go1.21.3'`) |
| `text_start` | VA of the `.text` section start |
| `nfunc` | Number of functions in the pclntab |
| `pclntab_file_off` | File offset of the pclntab header |
| `func_starts` | Property — `List[int]` of all function entry VAs sorted |
| `named_funcs` | Property — `Dict[int, str]` for only functions with non-empty names |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
