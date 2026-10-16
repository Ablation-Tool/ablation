# PhysmemElfVfs — Physical Memory ELF Extractor

**File:** `modules/physmem_elf_vfs.py`

## Why this exists

Reconstructs ELF binaries from physical memory dumps (QEMU ELF core format) without page table walking. Scans the dump for ELF64 x86_64 EXEC/DYN headers, builds a VFS index by content proximity, and extracts each binary by checking PT_LOAD window coverage. Also provides VM RE helpers for `/proc/maps` parsing and call-argument analysis.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap (SHA256 digest pass) |

## Key API

```python
from modules.physmem_elf_vfs import PhysmemVFS, parse_proc_maps, match_elf_to_maps

# Build VFS index from dump
with PhysmemVFS('/tmp/memory-dump.elf') as vfs:
    vfs.build_index()                         # scan for ELF64 headers
    hits = vfs.find_strings('sdnproxy')       # find string occurrences
    owners = vfs.find_owner_contiguous(off)   # fast contiguous path
    owners = vfs.find_owner_proximity(off,    # non-contiguous heuristic
                proc_maps_text_foff=0x1000, proc_maps_text_sz=0x80000)
    vfs.extract_binary(cand, '/tmp/bins/sdnproxy')
    funcs = vfs.extract_functions(cand)       # CET-aware prologue detection

# VM RE helpers (process-aware analysis)
maps_text = open('/proc/1234/maps').read()
regions = parse_proc_maps(maps_text)
by_bin = group_maps_by_binary(regions)
best = match_elf_to_maps(vfs._index, by_bin['/usr/bin/sdnproxy'])
```

## CET-aware function detection

Detects both `endbr64` (f3 0f 1e fa, CET/IBT compiled) and `push rbp; mov rbp, rsp` (55 48 89 e5, classic frame) as function prologues.

## FORGE audit

Gate: **PASSED**. All dump access via `mmap` (no `.read()` on dump file). `_MAX_BINARY_BYTES` (256 MB) applied at SHA256 digest pass (line 577). `min(end, self._size)` bounds mmap slice in `extract_functions`. No lief.parse(). No bare `except:`. No network I/O.
