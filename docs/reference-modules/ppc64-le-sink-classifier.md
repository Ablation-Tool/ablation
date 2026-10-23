# SinkArgClassifierPPC64

## Why this exists

1 gap that blocked automated exec-class sink classification on PPC64LE ELFs
(IBM Advance Toolchain at17.0, Go cross-compiler, ppc64le Linux binaries):

1. **SinkArgClassifier is x86-64-only.** `SinkArgClassifier.classify_all()` scans for
   x86-64 `call` instructions and traces `rdi`. On PPC64, the calling convention uses
   `bl` for calls and `r3-r10` for argument registers. For any ppc64le binary the result
   is zero classifications: every exec-class call site is invisibly missed.
   This is ARCH-GAP-PPC64LE (IBM AdvanceToolchain at17.0 analysis, 2026-10-18).

---

## What it does

`SinkArgClassifierPPC64` classifies the argument passed to exec-class functions
(`system`, `popen`, `execvp`, `execve`, `execl`, `execlp`, `execle`, `execvpe`)
at every call site in a PPC64 LE/BE ELF binary.

Four verdicts:
- `RODATA_CONST`: arg is an address-of string in `.rodata` (hardcoded constant).
- `SNPRINTF_RODATA`: arg is a stack buffer filled by snprintf with a rodata format.
- `ARG_PROPAGATED`: arg traces back to a function entry-point register (r3-r10).
- `UNKNOWN`: cannot be resolved within the lookback window.

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.sink_arg_classifier_ppc64 import SinkArgClassifierPPC64

ctx = BinaryContext.load_or_build('/path/to/ppc64le_binary')
clf = SinkArgClassifierPPC64.from_context(ctx)
results = clf.classify_all()
print(clf.report(results))
```

## Key implementation details

- Handles both ppc64le (EI_DATA=1) and ppc64 BE (EI_DATA=2) via Capstone mode detection.
- TOC base resolved from `.TOC.` symbol or `.got`/`.toc` section VA (needed for ABIv2
  `addis rX, r2, HI; addi rX, rX, LO` TOC-relative address loads).
- Tracks `ld rX, N(rY)` (64-bit load), `std rX, N(rY)` (64-bit store) for stack
  save/restore detection: complements `lwz`/`stw` used in ppc32.
- `addis rX, r2, HI` + `addi rX, rX, LO`: resolves to `toc_base + (HI<<16) + LO`;
  if in `.rodata` → `RODATA_CONST`.
- `addis rX, r2, HI` + `ld rX, LO(rX)`: pointer load from TOC; dereferences and checks
  if the pointed-to address is in `.rodata`.
