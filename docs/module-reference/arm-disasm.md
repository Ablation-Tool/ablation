# ARM Disassembler

**File:** `modules/arm_disasm.py`

## Why this exists

Pure-Python ARM32 disassembler. Decodes the fixed 4-byte ARM instruction set (data processing, load/store, branch, multiply, coprocessor) with no external library dependency. Used as the disassembly layer by `arm_symbolic.py` for path-insensitive symbolic execution on ARM32 targets where Capstone is unavailable or where a lightweight dependency-free decoder is required.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.
