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

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Usage

```python
from ablation.analyzers.go_x86_strip_scanner import GoX86StripScanner

results = GoX86StripScanner.from_context(ctx).run()
for r in results:
    print(r)
```

---

## Example output

```
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

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
