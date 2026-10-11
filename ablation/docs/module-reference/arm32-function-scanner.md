# ARM32FunctionScanner

## Why this exists

2 things that weren't possible before in Ablation:

1. **Taint analysis on stripped ARM32 ELFs without `.eh_frame`.** Before this module, `ARM32TaintTracker` found function starts only from DWARF EH_CFI entries and the dynamic symbol table. On stripped AMI SPX BMC binaries (`spx_restservice`, 1.4 MB, zero eh_frame entries), this produced 633 function starts — leaving 388 reachable functions invisible to the taint pipeline. Running `ARM32FunctionScanner` on the same binary and injecting the result into the taint tracker raises the total to 1,021 (61% improvement).

2. **Distinguish ARM32 PUSH prologues from Thumb code collisions.** A naïve byte scan for `0xB5` (Thumb-1 LR-PUSH high byte) hits inside ARM32 BL instructions at a 100% false-positive rate in ARM-mode binaries. This module suppresses the Thumb-1 scan in ARM32 mode and applies it only when the ELF entry point indicates Thumb (`entry & 1 == 1`), eliminating that FP class entirely.

## What it does

Scans the `.text` section of an ARM32 ELF for three PUSH-with-lr prologue patterns, each encoding the saving of the link register (LR) as part of a function entry:

| Pattern | Mode | Bytes (LE) | Alignment |
|---|---|---|---|
| `STMFD r13!, {rN.., lr}` | ARM32 | `?? [4x..Cx] 2D E9` | 4-byte |
| `STMDB SP!, {rN.., lr}` | Thumb-2 32-bit | `E9 2D ?? [4x..Cx]` | 2-byte |
| `PUSH {rN.., lr}` | Thumb-1 16-bit | `[rlist] B5` | 2-byte |

ARM32 mode (`entry & 1 == 0`): ARM32 + Thumb-2 patterns only.
Thumb mode (`entry & 1 == 1`): Thumb-2 + Thumb-1 patterns only.

## Usage

```python
from ablation.analyzers.arm32_function_scanner import ARM32FunctionScanner

# From a binary path
scanner = ARM32FunctionScanner.from_path('/path/to/spx_restservice')
starts = scanner.scan()
print(ARM32FunctionScanner.report(starts))

# Inject into BinaryContext (most common use)
added = scanner.inject_into_context(ctx)
print(f"{added} new function starts injected")

# From a BinaryContext directly
scanner = ARM32FunctionScanner.from_context(ctx)
scanner.inject_into_context(ctx)

# Then run ARM32TaintTracker with the augmented context
from ablation.analyzers.taint_tracker_arm32 import ARM32TaintTracker
tracker = ARM32TaintTracker(path, ctx=ctx)
findings = tracker.run_interprocedural()
```

## Confirmed targets

- QTECH/Gooxi BMC `spx_restservice` (ARM32 ET_EXEC, 1.4 MB, stripped, no eh_frame)
  - 593 starts from scanner; 388 new beyond ARM32TaintTracker baseline (633 → 1,021 total)
- Expected to work on any ARM32 Linux ELF compiled with `-O2` or higher (function frames always push lr)

## Known limitations

- Functions that do not push lr (leaf functions with no calls, tail-call-only functions) are not found by this scanner. Use call-target BFS to supplement.
- Thumb-1 scan is not run in ARM32-mode binaries. If a mixed-mode binary has Thumb-1 functions, those will be missed unless `thumb_only=True` is set manually.
- Thumb-2 scan can match inside ARM32 literal pools: the `E9 2D` byte pair can appear in ARM32 constant data. Alignment check reduces this; post-filtering by call-target intersection gives higher precision if needed.
