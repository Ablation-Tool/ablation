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
