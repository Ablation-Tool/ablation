# JFFS2 Filesystem Reader

`Jffs2Image` reconstructs paths and file contents from little-endian JFFS2 images. It validates format checksums, applies versioned updates, and returns files in memory without mounting the image, requiring kernel support, or creating device nodes.

---

## Why reconstruct a filesystem?

A firmware image may contain an entire appliance rather than one program. Its web server, startup scripts, service configuration, and credentials can be separate files. Disassembling whatever appears first in the byte stream misses those relationships and can produce incomplete programs.

JFFS2 adds another challenge: it is a log-structured flash filesystem. Instead of storing every file as one contiguous block, it records directory entries and inode fragments over time. A later fragment can replace part of a file, and a later directory entry can remove a name.

`Jffs2Image` turns those records back into a readable filesystem snapshot. It was added to recover the CAEN C111C services and configuration, after which its six bFLT executables could be analyzed with `BfltImage`.

For the larger workflow, see [Firmware Parsing: From Artifacts to Analysis](firmware-parsing.md).

---

## The format in plain terms

A filesystem image contains a sequence of records called nodes. Two kinds matter most for file reconstruction:

- A **dirent**, short for directory entry, connects a name under a parent inode to another inode. An entry with inode number zero unlinks the name.
- An **inode** stores metadata such as type, permissions, ownership, and file size. File inodes may also store one compressed or uncompressed extent at a file offset.

An inode number identifies an object; a path identifies a link to that object. Multiple paths can refer to the same file data through hard links. Directories and inodes also carry versions so that newer records can supersede older state.

This is why finding a valid filename and one data block is not enough to reconstruct a file.

---

## How reconstruction works

1. Walk node headers with explicit length checks and four-byte alignment.
2. Validate each recognized node header before trusting its type or contents.
3. For dirents, check the format-defined header CRC and filename CRC, then retain the highest version for each parent/name pair.
4. For inodes, validate metadata, file extent bounds, the inode CRC, and the stored-payload CRC.
5. Decompress supported extents and require their expanded length to equal the declared `dsize`.
6. Keep the highest version for each inode/file-offset pair. Reject conflicting records with the same version.
7. Resolve parent links into absolute paths, preserving hard-linked files and detecting directory cycles.
8. Assemble each file from its selected extents. Fill unwritten holes with zeros up to the declared file size.

If inode 1 is absent, the reader supplies the conventional implicit root directory. `entries` then provides an immutable mapping from absolute paths to reconstructed objects.

The supported compression modes are none (`0`), zero fill (`1`), copy (`4`), and zlib (`6`). Other modes raise `Jffs2Error` rather than returning compressed bytes as program code.

---

## Why this works

The node records provide both location and history. Lengths establish record boundaries, CRCs check the expected byte ranges, versions order changes, and offsets place expanded data within each file. Combining those fields reconstructs the state represented by the supplied log.

CRC means cyclic redundancy check. Like the CAEN additive checksum, it is useful for detecting corruption but is not a digital signature. JFFS2 uses several CRC-covered regions rather than one undifferentiated whole-file value.

The CRC helper used for the relevant fields is:

```python
(zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF
```

The inode `data_crc` covers the stored payload before decompression. The expanded length is checked separately, so a valid CRC does not excuse a truncated or oversized decompression result.

---

## From filesystem to executable

```python
from ablation.parsers.jffs2 import Jffs2Image
from ablation.parsers.bflt import BfltImage

fs = Jffs2Image.from_path('/path/to/rootfs.jffs2')
print(fs.metadata())
print(fs.file_paths())

raw = fs.read_file('/tinyws')
program = BfltImage.from_bytes(raw)
print(program.metadata())
```

There is no temporary-file step in this handoff. `read_file()` returns file or symlink bytes without following the symlink; reading a directory raises `IsADirectoryError`.

Each `Jffs2Entry` exposes `ino`, `mode`, `uid`, `gid`, `mtime`, `size`, `data`, `is_dir`, and `is_symlink`. `file_paths()` returns sorted non-directory paths, including symlink paths.

Input, per-file, and expanded-output limits default to 64 MiB each. The expanded-output budget includes accepted inode chunks even when a later version supersedes them, because decompression still consumes resources before version selection.

---

## What this adds for the user

The reader makes embedded filesystem analysis accessible without root privileges, a compatible host kernel, or a mount operation. It gives batch tools and interactive users the same reproducible file bytes, metadata, and rejection counts.

It is a foundational component rather than a complete appliance audit. Recovering a startup script establishes what the image contains, not whether the corresponding service is reachable on a deployed device. Recovering a credential file likewise does not prove an authentication bypass.

A later safe extraction interface or general filesystem framework could reuse this reader. That interface would need to preserve the current no-follow and no-special-file policies. The in-memory reader can also remain useful on its own, or be replaced independently if a better validated implementation becomes available.

---

## Safety and limitations

- Only little-endian JFFS2 is supported.
- Names containing `/`, NUL, empty names, `.` or `..` are rejected as links and counted in `rejected_dirents`.
- Directory depth is limited to 256 and encoded paths to 4096 bytes. Ambiguous directory hard links and directory-parent cycles fail.
- There is no extraction-to-disk API. The reader does not create symlinks, devices, sockets, or executable files.
- Unrecognized node types with valid headers are skipped. `unparsed_bytes` counts bytes not recognized as node headers plus trailing bytes; it is not a count of every skipped valid node.
- Identical duplicate state is tolerated. Conflicting same-version metadata or extents fail instead of being resolved by input order.
- Reconstruction reflects the supplied image, not a live filesystem, a changed deployment, or proof of secure runtime configuration.

---

## See also

- [Firmware Parsing: From Artifacts to Analysis](firmware-parsing.md)
- [bFLT v4 Executables](bflt.md)
- [CAEN ASCII-Hex Firmware Containers](caen-ascii-hex.md)
- [IoT Firmware Unpacker](iot-firmware-unpacker.md)
