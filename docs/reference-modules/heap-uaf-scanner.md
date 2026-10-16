# HeapUAFScanner

**File:** `modules/heap_uaf_scanner.py`

## Why this exists

Detects use-after-free and double-free patterns in stripped binaries via taint-tracking of heap allocation return values (malloc/jemalloc/tcmalloc). Tracks object lifetimes across function boundaries to identify sites where a freed pointer is used after its free — the primary primitive class for modern heap exploitation.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.
