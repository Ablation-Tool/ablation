# ELF VTable Reconstructor

**File:** `modules/elf_vtable_reconstructor.py`

## Why this exists

Reconstructs C++ virtual dispatch tables from x86-64 ET_DYN ELF shared libraries without executing the binary. Walks `.rela.dyn` for R_X86_64_RELATIVE (type 8, in-library functions) and R_X86_64_64 (type 1, exported symbol references) relocation entries to build a slot-index → function-VA map. Uses pure-Python ELF parsing (`struct.unpack_from`), no lief, no Capstone dependency. Enables identifying polymorphic sinks without RTTI or debug symbols.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_ELF_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard in `__init__()` before `f.read()`; `_MAX_ELF_BYTES=256MB`. Pure-Python ELF parser, no lief.parse(). No HTTP reads. `c++filt` subprocess uses `timeout=2`.
