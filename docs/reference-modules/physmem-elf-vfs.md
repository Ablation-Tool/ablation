# PhysmemElfVfs: Physical Memory ELF Extractor

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

---

## How it works

Reads the binary header to validate the container magic, walks the partition or directory table, and yields the raw bytes of each embedded payload. Format detection runs on the first 512 bytes of each partition to classify the content as ELF, SquashFS, ext4, JFFS2, or unknown before extraction begins. Checksum validation (CRC32 or SHA256 depending on container format) runs on the extracted bytes and raises `ExtractionError` if the digest does not match the stored value.

---

## Usage

```python
from modules.physmem_elf_vfs import PhysmemVFS

with PhysmemVFS('/path/to/memory-dump.bin') as vfs:
    n = vfs.build_index()
    print(f"Indexed {n} ELF candidates")
    for cand in vfs.find_proc_maps():
        print(cand)
```

---

## Example output

```
Extracted 4 partitions from firmware.bin:
  [0] boot      512 KB  ELF (ARM64)
  [1] rootfs    18 MB   SquashFS
  [2] data      4 MB    ext4
  [3] config    128 KB  JFFS2
Written to /tmp/extracted/
```

---

## False positives

Extraction either succeeds or raises an exception, there are no false positives in the traditional sense. Check for incomplete downloads (`.aria2` sidecar present) before analysis: partial images produce truncated or zero-filled partitions that pass validation but contain no useful data.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to identify the outer binary format and confirm the container is present.

**After this module:** Feed extracted partition bytes to `BinaryContext.load_or_build()` or the appropriate ISA taint tracker for each extracted payload.

---

## Reading findings

| Field | Content |
|:---|:---|
| `path` | Filesystem path to the extracted file or partition |
| `partition_name` | Partition label or index from the container header |
| `size` | Size of the extracted payload in bytes |
| `format` | Detected format of the extracted payload (`ext4`, `squashfs`, `ELF`, etc.) |

---

## See also

- [BinaryContext](binary-context.md): load extracted payloads for analysis
- [FirmwareContainers](firmware-containers.md): higher-level firmware partition walker
- [EntropyMapper](entropy-mapper.md): locate encrypted or compressed regions before extraction
