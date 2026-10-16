# AnalyzeAllJNI

**File:** `modules/analyze_all_jni.py`

## Why this exists

Automated JNI (Java Native Interface) attack surface mapping for Android shared libraries. Identifies all native methods registered via `RegisterNatives` or exported with `Java_` prefixes, maps them to their Java class/method counterparts, and flags dangerous parameter patterns (string buffers without length bounds, direct `ByteBuffer` access).

## Key API

| Symbol | Description |
|---|---|
| `analyze_all_jni(so_path)` | Full JNI surface analysis — returns list of `JNIMethod` findings |
| `JNIMethod` | dataclass: `va`, `java_class`, `method_name`, `signature`, `risk_level` |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `_MAX_LIB_BYTES=256MB`; `os.path.getsize()` guard before `open().read()` (L45-47). No lief — binary loaded as raw bytes via `open(lib_path, 'rb').read()` and passed to `ARMSymbolicAnalyzer`. No HTTP reads. No subprocess.
