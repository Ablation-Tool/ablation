# LibFuncDB: PLT Slot Classifier

**File:** `modules/libfunc_db.py`

## Why this exists

Classifies PLT slots in stripped ARM64 binaries without symbol names. Profiles each PLT stub via ABI-visible call-site behavior (argument kinds, return usage) and scores against a `LibFuncSummary` database to identify common libc/libstdc++ functions. Needed when BinaryContext has no imports and SemanticSearcher needs to know whether a call site targets `memcpy` vs. `malloc` vs. `strcmp`.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `lief.parse()`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.
