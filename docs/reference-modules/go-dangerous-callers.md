# GoDangerousCallers

**File:** `modules/go_dangerous_callers.py`

## Why this exists

Pre-built callgraph scanner for Go binaries: identifies dangerous call sites (unsafe.Pointer casts, reflect.NewAt, os.exec, net/http.Get) with rodata-first string extraction and Go itab resolution. Single text scan builds the full callgraph; subsequent lookups are O(1).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. `lief.parse()` used in `_build_section_map()` (L167), wrapped in `try/except Exception` + `if self._lb is None` check. No HTTP reads.
