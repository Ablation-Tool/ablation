# ARM Disassembler

**File:** `modules/arm_disasm.py`

## Why this exists

Capstone-based ARM32/ARM64 disassembler wrapper with function boundary detection, branch target resolution, and PLT call identification. Provides the disassembly layer used by semantic search and taint trackers.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.
