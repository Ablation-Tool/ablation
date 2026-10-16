# Java Bytecode Analysis

**File:** `modules/java_decompiler.py`

## Why this exists

Java bytecode analysis for .class and .jar files: decompiles bytecode to readable form, identifies dangerous API calls (Runtime.exec, ProcessBuilder, URLClassLoader, reflection-based deserialization), and maps injection points in servlet and REST endpoint handlers.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_CLASS_BYTES` | 64 MB | .class/.jar file read cap |
| `_MAX_ENTRY_BYTES` | 16 MB | ZIP entry read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `f.read()`; ZIP entry sizes checked against `_MAX_ENTRY_BYTES` before extraction. `_MAX_CLASS_BYTES=64MB`. No lief.parse(). No HTTP reads.
