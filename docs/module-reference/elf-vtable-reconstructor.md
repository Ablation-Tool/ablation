# ELF VTable Reconstructor

**File:** `modules/elf_vtable_reconstructor.py`

## Why this exists

Reconstructs C++ virtual dispatch tables from stripped ELF binaries using GOT/PLT cross-references and rodata pointer patterns. Enables identifying polymorphic sinks without RTTI or debug symbols.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_ELF_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `lief.parse()`; `_MAX_ELF_BYTES=256MB`. No HTTP reads.
