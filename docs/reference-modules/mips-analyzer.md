# MIPS Analyzer

**File:** `modules/mips_analyzer.py`

## Why this exists

MIPS32/MIPS64 binary analysis: function boundary detection using MIPS prologue patterns (addiu sp/sw ra), delay slot handling, GP-relative addressing ($gp + offset), and MIPS calling convention (a0–a3 argument registers). Used for embedded firmware targets that are MIPS-based (routers, cable modems, DSL equipment).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.
