# ChunkWalkerValidator

**File:** `modules/chunk_walker_validator.py`

## Why this exists

Validates that heap chunk walking logic in stripped binaries correctly handles chunk header parsing and size field extraction. Used for confirming heap overflow primitives where the chunk size field is not properly validated.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.
