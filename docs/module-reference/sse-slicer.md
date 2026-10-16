# SSE Slicer

**File:** `modules/sse_slicer.py`

## Why this exists

Slices SSE/AVX vectorized code in stripped x86-64 binaries: identifies SIMD memory operations (movdqu/movaps/vmovdqu), extracts stride patterns and buffer length calculations, and maps vector shuffle operations to their scalar equivalents for taint tracking.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `read_bytes()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.
