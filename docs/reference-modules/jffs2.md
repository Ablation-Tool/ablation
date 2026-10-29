# JFFS2 Filesystem Reader

`Jffs2Image` reconstructs little-endian JFFS2 directory entries and file contents without mounting, kernel support, or third-party packages. It validates node, dirent, filename, inode, and stored-payload checksums.

---

## Why this exists

1. A filesystem listing alone cannot recover executable contents for disassembly.
2. Some readers return only an initial block of large files. Analysis must reconstruct every versioned extent rather than accept a truncated binary.
3. Dirent and inode layouts contain distinct CRC-covered fields. Treating names or compressed data as unchecked text can corrupt paths and analysis results.
4. Filesystem extraction must not follow symlinks, create device nodes, or allow directory traversal by default.

---

## Validated layout

Each node header is checked for magic, bounds, and its header CRC. Directory entries include `node_crc` and `name_crc`; filenames are validated before becoming path components. Inodes use `ino` before `version`, and `csize` before `dsize`.

The CRC helper is:

```python
(zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF
```

For inodes, `node_crc` covers the header through the fields before `data_crc` and `node_crc`. `data_crc` covers the stored, potentially compressed payload. Decompressed length is independently checked against `dsize`.

Supported compression modes are none (`0`), zero fill (`1`), copy (`4`), and zlib (`6`). Other modes fail explicitly rather than returning compressed bytes as code.

---

## Usage

```python
from ablation.parsers.jffs2 import Jffs2Image
from ablation.parsers.bflt import BfltImage

fs = Jffs2Image.from_path('/path/to/rootfs.jffs2')
print(fs.metadata())
print(fs.file_paths())
raw = fs.read_file('/tinyws')
program = BfltImage.from_bytes(raw)
```

`entries` is an immutable mapping of absolute filesystem paths to `Jffs2Entry` objects. Each entry exposes `ino`, `mode`, `uid`, `gid`, `mtime`, `size`, `data`, `is_dir`, and `is_symlink`. `read_file()` returns file or symlink bytes but never follows the symlink. Directory reads raise `IsADirectoryError`.

The parser uses the highest version for each dirent and extent, tolerates identical duplicates, and rejects conflicting same-version extents. Unwritten holes are zero filled. A missing inode 1 produces the standard implicit root directory.

Input, per-file, and expanded-output limits default to 64 MiB each. The expanded-output limit includes all accepted inode chunks, including versions later superseded.

---

## Safety and limitations

- Only little-endian JFFS2 is supported.
- Paths containing `/`, NUL, empty names, `.` or `..` are rejected as links and counted in `rejected_dirents`; they are never written to disk.
- Directory depth is limited to 256 and encoded paths to 4096 bytes. Hard-linked files are preserved; ambiguous directory hard links fail.
- The reader has no extraction-to-disk API. It does not create symlinks, devices, sockets, or executable files.
- Unknown valid node types are skipped after header validation. `unparsed_bytes` counts non-node padding or skipped bytes.
- Reconstruction reflects the supplied image, not a live filesystem or proof of safe runtime configuration.

---

## See also

- [bFLT v4 Executables](bflt.md)
- [CAEN ASCII-Hex Firmware Containers](caen-ascii-hex.md)
- [IoT Firmware Unpacker](iot-firmware-unpacker.md)
