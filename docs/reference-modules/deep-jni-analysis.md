# DeepJNIAnalysis

**File:** `modules/deep_jni_analysis.py`

## Why this exists

Deep disassembly analysis of JNI functions: vtable dispatch patterns, structure field accesses, and internal state management. Goes beyond surface-level JNI registration to trace how native methods interact with Java objects via JNIEnv.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_LIB_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `f.read()`; `_MAX_LIB_BYTES=256MB`. No lief.parse(). No HTTP reads.
