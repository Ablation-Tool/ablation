# Java RE

**File:** `modules/java_re.py`

## Why this exists

Java.class/.jar reverse engineering: constant pool analysis, method signature extraction, field access mapping, and cross-reference building. Provides the Java-tier analysis complement to native ARM64/x86 RE for mixed Java+JNI targets.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_FILE_BYTES` | 64 MB |.class/.jar file read cap |
| `_MAX_ENTRY_BYTES` | 16 MB | ZIP entry read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. ZIP entry sizes checked via `zf.getinfo(cname).file_size > _MAX_ENTRY_BYTES` before extraction. `_MAX_FILE_BYTES=64MB`. No lief.parse(). No HTTP reads.
