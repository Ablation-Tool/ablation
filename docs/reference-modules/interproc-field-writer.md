# InterprocFieldWriter

**File:** `modules/interproc_field_writer.py`

## Why this exists

Demand-driven inter-procedural field-writer finder for stripped ARM64 binaries. Given a struct field offset, traces all functions that write to that field across call boundaries, used to identify all code paths that can corrupt a security-sensitive struct member.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.
