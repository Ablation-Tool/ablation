# DiskImageExtractor

**Module**: `ablation/analyzers/disk_image_extractor.py`
**Gap**: DISK-IMG-GAP-001

---

## Why this exists

1. Analyzing embedded Linux disk images required knowing the Sleuth Kit CLI (`fls`/`icat`), computing partition sector offsets from `fdisk` output, and running per-file commands manually. No ablation API existed for structured, path-navigable filesystem access.
2. The facility ATLAS GEP PetaLinux session required 30+ individual `fls`/`icat` invocations to read the rootfs. These were ad-hoc Bash commands. EmbeddedRootfsScanner and future scanners need a clean Python API.
3. The module enables `EmbeddedRootfsScanner.from_image()` to work without manual sector arithmetic.

---

## Dependencies

- **Required**: `sleuthkit` (`fls`, `icat`, `istat`) — ext2/3/4 filesystem access
- **Optional**: `mtools` — FAT12/16/32 filesystem access (not yet implemented)
- **Required**: `fdisk` — partition table parsing (available on all Linux systems)

Install on Debian/Ubuntu: `apt install sleuthkit`

---

## Constructor patterns

```python
from ablation.analyzers.disk_image_extractor import DiskImageExtractor

# Automatic: use second partition (index 1 = rootfs in typical WIC layout)
ext = DiskImageExtractor.from_path('/path/to/image.wic', partition_index=1)

# Probe partition table first
partitions = DiskImageExtractor.probe('/path/to/image.wic')
for p in partitions:
    print(f'  part {p.index}: start={p.start_sector} fs={p.fs_type} {p.size_mb}MB')

# Use a specific partition
ext = DiskImageExtractor(image_path, partitions[1])

# Read operations
entries  = ext.list_path('/')                          # root directory entries
shadow   = ext.read_path('/etc/shadow')                # bytes or None
exists   = ext.path_exists('/usr/bin/versalTcpIpbusShim')
binary   = ext.read_path('/usr/bin/versalTcpIpbusShim')  # firmware binary bytes

# Extract to temp file for BinaryContext
import tempfile, pathlib
with tempfile.NamedTemporaryFile(suffix='.elf', delete=False) as f:
    f.write(binary)
    path = f.name
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build(path)

# Find SUID binaries (slow — uses istat per file, capped at 2000 files)
suid = ext.find_suid()
```

---

## PartitionInfo fields

```python
part.index         # 0-based partition index
part.start_sector  # first sector (512 bytes each)
part.end_sector    # last sector
part.fs_type       # 'ext4', 'fat32', 'fat16', 'unknown'
part.size_mb       # approximate size in MB
part.label         # 'boot', 'rootfs', 'part0', etc.
```

---

## Typical WIC layout

| Partition | Index | FS | Content |
|-----------|-------|----|---------|
| 0 | 0 | FAT32 | BOOT.BIN, image.ub, boot.scr, system.dtb |
| 1 | 1 | ext4 | Linux rootfs (/, /etc, /usr, /bin, ...) |

For PetaLinux WIC images, `partition_index=1` gives the rootfs. This is the default.

---

## Sector offset arithmetic

The sector offset passed to Sleuth Kit (`-o N`) is the number of 512-byte sectors from the start of the image file to the start of the partition. `fdisk -l` reports this as the `Start` column.

Example for a WIC image:
```
Device           Boot     Start      End  Sectors  Size Id Type
image.wic1         *          8  4194311  4194304    2G  b W95 FAT32
image.wic2           4194312 12582919  8388608    4G 83 Linux
```

`ext = DiskImageExtractor.from_path(wic, partition_index=1)` → `start_sector=4194312`.
Equivalent manual command: `fls -o 4194312 image.wic`.

---

## Heuristic fallback

If `fdisk` fails (e.g., raw NAND image without MBR), `_probe_by_magic()` scans for ext4 superblock magic bytes (`\x53\xef` at offset `0x438` from each candidate start). This is less reliable — prefer explicit `fdisk` output.

---

## Known limitations

- FAT partition reading (`list_path`/`read_path`) on FAT partitions is not yet implemented — mtools integration is deferred.
- `find_suid()` is slow on large rootfs (uses `istat` per file, capped at 2000 regular files).
- Path navigation is O(depth × entries_per_dir) — no inode-to-path index is built upfront.
- GPT partition tables produce less reliable output from `fdisk -l`; prefer `gdisk -l` or manual sector inspection for GPT images.

[↑ Back to INDEX](../INDEX.md)
