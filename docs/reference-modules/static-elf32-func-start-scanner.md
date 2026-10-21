# StaticELF32FuncStartScanner

`ablation/analyzers/static_elf32_func_start_scanner.py`

## Why this exists

Two things were not possible before in Ablation:

1. **`BinaryContext` cannot find function starts in stripped static ELF32 binaries.** `BinaryContext._extract_func_starts()` relies on `.symtab` / `.dynsym` (no entries in stripped binaries) and `.eh_frame` (absent in non-exception-aware or `--strip-all` builds). For stripped static i386 ELF binaries, `ctx.func_starts` is empty and `SemanticSearcher`, `SinkArgClassifier`, and `TaintTracker` all return 0 results — not because the binary is safe, but because the analysis has no entry points.

2. **FPO binaries compiled with `-fomit-frame-pointer` produce no recognizable prologues.** The primary recovery method for x86 (prologue pattern `55 89 e5`: `push ebp; mov ebp, esp`) works for ~95% of GCC i386 output, but GCC with `-fomit-frame-pointer` omits `push ebp` entirely. A second fallback is required for these binaries.

---

## How it works

`from_path(path)` reads the binary with `open(path, "rb").read()`, then `_scan_internal()` does:

1. Validates ELF magic, `EI_CLASS=1` (ELFCLASS32), `EI_DATA=1` (little-endian).
2. Reads the program header table (`e_phoff`, `e_phentsize`, `e_phnum`).
3. Collects all `PT_LOAD` segments with `PF_X` (execute flag).
4. **Primary scan:** searches each executable segment for `\x55\x89\xe5` (`push ebp; mov ebp, esp`).
5. **Secondary scan** (activates when primary finds < 10 starts): searches for `\x55\x57\x56` (`push ebp; push edi; push esi`) and `\x55\x53` (`push ebp; push ebx`).
6. **FPO fallback** (activates when primary+secondary still find < 10 starts): collects all `CALL rel32` (`E8 xx xx xx xx`) targets that land within an executable segment. This covers `-fomit-frame-pointer` binaries where no `push ebp` prologue exists.

Returns a sorted `List[int]` of function entry VAs.

---

## Usage

```python
from ablation.analyzers.static_elf32_func_start_scanner import StaticELF32FuncStartScanner

scanner = StaticELF32FuncStartScanner.from_path('/path/to/stripped.elf')
starts = scanner.scan()
print(f"{len(starts)} function starts found")

# Full result with pattern diagnostics
result = scanner.scan_full()
print(result.report())

# Inject into an existing BinaryContext (only when ctx.func_starts is empty)
scanner.inject(ctx)
```

`inject(ctx)` updates `ctx.func_starts` in place and returns the count injected. It is a no-op when `ctx.func_starts` is already populated (to avoid overwriting `.eh_frame`-derived starts).

---

## Integration

`BinaryContext._extract_func_starts()` calls this scanner automatically for `x86_32` binaries when fewer than 50 starts are found via other means.

---

## Scan result fields

| Attribute | Content |
|:---|:---|
| `path` | Path to the binary |
| `starts` | Sorted `List[int]` of function entry VAs |
| `patterns_used` | List of pattern names that contributed starts (e.g. `['primary (55 89 e5)', 'fpo_call_target (E8 rel32)']`) |
| `segment_count` | Number of executable `PT_LOAD` segments scanned |

---

## Limitations

**Little-endian i386 only.** Returns empty results for big-endian or non-ELFCLASS32 inputs.

**FPO fallback has a higher false-positive rate.** Indirect calls (`CALL [reg]`) decoded as `CALL rel32` by pattern matching produce false targets. For FPO binaries, expect false entries in the starts list and validate with `FuncProfiler` before running `TaintTracker`.

**Pattern scan produces no confidence scores.** All discovered starts are treated equally; there is no per-entry confidence. Use `scan_full().patterns_used` to check whether the FPO fallback fired.

---

## Pipeline position

**Before:** Confirm `BinaryContext` returns `func_starts=0` for a stripped static binary. This scanner runs automatically via `inject()` in that case.

**After:** Use the populated `ctx.func_starts` with `SemanticSearcher.query()`, `SinkArgClassifier.from_context(ctx)`, and `TaintTracker`.

---

## See also

- [BinaryContext](binary-context.md) — calls this scanner via `inject()` when func_starts is empty
- [FlatBinaryFuncStartScanner](flat-binary-func-start-scanner.md) — equivalent for flat ROM images (no ELF header, ISA-agnostic)
- [SinkArgClassifier](sink-arg-classifier.md) — next step after func_starts are populated
