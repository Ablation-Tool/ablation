# ARM64GlobalTracker

**File:** `modules/arm64_global_tracker.py`

## Why this exists

Tracks ARM64 global variable access patterns (ADRP+LDR/STR sequences) to map BSS/data section usage in stripped binaries. Enables identification of state variables and persistent buffers without symbols.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `read_bytes()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.
