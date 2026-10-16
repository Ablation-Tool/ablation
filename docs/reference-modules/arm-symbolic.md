# ARM Symbolic Execution

**File:** `modules/arm_symbolic.py`

## Why this exists

Light symbolic execution for ARM32/ARM64 binaries to determine register values at specific call sites. Used for confirming that a vulnerable sink receives attacker-controlled input before investing in full exploit development.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.
