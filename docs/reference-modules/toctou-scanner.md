# TOCTOUScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Detect `access()`-before-`open()` race conditions statically.** The Linux `access(2)` manpage states: "do not use `access()` in security-critical code." When `access()` and `open()` are called on the same path in the same function, there is a window between them where an attacker can replace the file with a symlink. `TaintTracker` finds exec-sink paths; no prior Ablation module found this distinct race condition class. `TOCTOUScanner` identifies it by detecting both PLT calls within the same function and checking that the same first argument reaches both.

## Usage

```python
from ablation.analyzers.toctou_scanner import TOCTOUScanner

scanner = TOCTOUScanner('/path/to/binary')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
scanner = TOCTOUScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: TOCTOUFinding

| Field | Type | Description |
|-------|------|-------------|
| `func_va` | int | VA of the function containing both calls |
| `func_name` | str | Demangled name or `sub_VA` if stripped |
| `access_va` | int | VA of the `access()` call instruction |
| `open_va` | int | VA of the `open()`/`fopen()` call instruction |
| `path_note` | str | Description of the shared path argument |
| `confidence` | str | `HIGH` if path arguments match exactly, `MEDIUM` otherwise |

## Detection logic

1. Scan PLT imports for `access`, `faccessat`, `euidaccess` and `open`, `open64`, `fopen`, `fopen64`, `openat`.
2. For each function, collect all call sites reaching either group.
3. For each `access()` call followed by an `open()` call in the same function, compare the first argument register before each call: `rdi` on x86-64, `x0` on ARM64, `a0` on MIPS.
4. Identical argument origin: `HIGH` confidence. Same register family: `MEDIUM` confidence.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on:
- Matching argument `rdi, [rbp-0x20]` for both calls: `HIGH` confidence.
- Same register family (`rdi`) with different operands: `MEDIUM` confidence.
- Empty arguments: `MEDIUM` confidence with note.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to build function and PLT maps.

**After this module:** Verify each finding manually with `WindowAnalyzer.dump_text(func_va)`. Confirm that the same path variable feeds both calls and that no lock or atomic rename protects the window between them.

## See also

- [BinaryContext](binary-context.md): function starts and PLT entry resolution
- [SinkArgClassifier](sink-arg-classifier.md): classify `open()` argument sources
- [TaintTracker](taint-analysis.md): trace user-controlled input to exec sinks
