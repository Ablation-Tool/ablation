# CallsiteTracer

**File:** `modules/callsite_tracer.py`

## Why this exists

Backward-slices argument registers (x0–x7) at ARM64 BL call sites to confirm that a target function receives a specific value. Primary use: verifying GOT-based struct pointer aliasing in stripped ARM64 shared objects (e.g., WeChat libwechatnetwork.so).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_SO_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `if binary is None` check. `_MAX_SO_BYTES=256MB`. No HTTP reads.
