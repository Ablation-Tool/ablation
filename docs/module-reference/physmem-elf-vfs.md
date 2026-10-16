# PhysmemElfVfs — Physical Memory ELF Extractor

**File:** `modules/physmem_elf_vfs.py`

## Why this exists

Reconstructs ELF binaries from physical memory dumps (QEMU ELF core format) without page table walking. Scans the dump for ELF64 x86_64 EXEC/DYN headers, builds a VFS index by content proximity, and extracts each binary by checking PT_LOAD window coverage.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap (digest pass) |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` used for dump size tracking. Digest pass uses `_fh.read(_MAX_BINARY_BYTES)`. No lief.parse(). No HTTP reads.
