# Go Garble RE

**File:** `modules/go_garble_re.py`

## Why this exists

Reverse engineering of garble-obfuscated Go binaries: deobfuscates symbol names using hash correlation against known Go stdlib and common import paths, reconstructs pclntab when name hashes have been overwritten, and identifies garbled type assertion patterns.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.
