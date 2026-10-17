# AmiCramFSExtractor

## Why this exists

Three things were not possible before in Ablation:

1. **Extract files from AMI BMC firmware.** Standard CramFS tools (`cramfsck`, `unsquashfs`, binwalk's cramfs handler) all fail on AMI-modified CramFS because the directory inode structure changed. Before this module, analyzing the Redfish REST service (`spx_restservice`) inside an AMI SPX BMC image required guessing file offsets manually.

2. **Resolve AMI's 16-byte extended inode format.** AMI moved the data offset out of `w2` (bits[6:31], standard CramFS) into a separate 4th word `w3`, and relocated `namelen` from bits[0:5] to bits[8:13] of `w2`. No tool or public writeup documents this layout. This module reverse-engineered and encodes the format.

3. **Feed the ARM32 taint pipeline.** Once `spx_restservice` and `psme-rest-server` are extractable, `ARM32TaintTracker` can trace HTTP FastCGI input to `system()`/`strcpy()` sinks. Before this module, the attack surface of AMI-based QTECH, Supermicro, and Lenovo BMCs was opaque.

## Format notes

AMI CramFS is standard CramFS (`magic=0x28cd3d45`) with one structural change: the inode is extended from 12 to 16 bytes.

**Standard CramFS inode (12 bytes):**
```
[w0: mode(16) | uid(16)]
[w1: size(24) | gid(8)]
[w2: namelen(6,bits0-5) | offset(26,bits6-31)]
```

**AMI extended inode (16 bytes):**
```
[w0: mode(16) | uid(16)]
[w1: size(24) | gid(8)]
[w2: 0 | namelen(6,bits8-13) | other_flags(bits0-7,14+)]
[w3: data_off — absolute offset in 4-byte units from CramFS start]
```

Data storage is **unchanged** from standard CramFS:
- Directories: raw uncompressed inode list, bounded by `size` from parent inode
- Regular files: zlib-compressed 4 KB blocks with an end-pointer table at `data_off × 4`
- Symlinks: same block structure as files, target string is the "file content"

Confirmed on: QTECH BMC `G4DCL-UX-V3R29A-L01-C06087.ima`, CramFS at offset `0x160000` (36.5 MB), 3532 files.

## Usage

```python
from modules.ami_cramfs_extractor import AmiCramFSExtractor

# From a raw CramFS image
ext = AmiCramFSExtractor.from_path('/path/to/rootfs.cramfs')

# From inside a multi-partition firmware image
ext = AmiCramFSExtractor.from_image('/path/to/bmc.ima', offset=0x160000)

# List all files
for path in ext.list_files():
    print(path)

# Extract one binary
data = ext.extract_file('/usr/local/bin/spx_restservice')
with open('/tmp/spx_restservice', 'wb') as f:
    f.write(data)

# Extract everything
ext.extract_all('/tmp/bmc_root/', progress=print)
```

## Known targets

- QTECH BMC (ASPEED AST2xxx, SPX Redfish): confirmed
- Supermicro BMC (same AMI SPX stack): expected to work
- Lenovo BMC (AMI SPX): expected to work

## Size limits

`from_path()` and `from_image()` raise `ValueError` when the file or the image slice exceeds
`_MAX_IMAGE_BYTES` (256 MB). This guards against loading an inadvertent full-disk image as a
CramFS partition. The limit is enforced via `os.path.getsize()` before any `read()` call.

## Block-0 prefix handling

Some AMI firmware images prefix block 0 with a raw (uncompressed) data section, typically
a pre-relocated GOT table, before the zlib-compressed file content. When initial decompression
of a block fails, `_decompress_file` scans for the first valid zlib CMF byte (0x78 followed by
a valid FLG byte: 0x01, 0x5e, 0x9c, or 0xda) and decompresses from that offset. Prefix bytes
before the zlib header are discarded as storage overhead. Confirmed on psme-rest-server
(QTECH G4DCL, 16 384-byte GOT prefix in block 0).

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `_MAX_IMAGE_BYTES=256MB`; `os.path.getsize()` guard in `from_path()` before `f.read()`; `from_image()` reads header (8 bytes) then validates `total_size` against `_MAX_IMAGE_BYTES` and file bounds before reading the partition. No lief.parse(). No HTTP reads. No subprocess.

---

## How it works

`AmiCramFSExtractor.from_path()` reads the entire image into memory (size-limited to 256 MB via `os.path.getsize()` guard) and validates the CramFS magic (`0x28cd3d45`). `from_image()` reads only the 8-byte header at the given offset, validates the magic and `total_size`, then reads the exact partition slice. Directory enumeration uses `_parse_entries()`, which reads 16-byte AMI extended inodes at each entry offset: `w0` holds mode and uid, `w1` holds size and gid, `w2` holds `namelen` in bits[8:13], and `w3` holds the data offset in 4-byte units. For regular files, `_decompress_file()` reads the block pointer table at `data_off × 4` and decompresses each 4 KB block with `zlib.decompress()`. When block 0 fails decompression (GOT prefix variant), the function scans for the first valid zlib CMF byte (`0x78` followed by `0x01`, `0x5e`, `0x9c`, or `0xda`) and decompresses from that offset, discarding the prefix.

---

## Example output

```python
>>> ext = AmiCramFSExtractor.from_image('/path/to/bmc.ima', offset=0x160000)
>>> list(ext.list_files())[:8]
['/bin/sh', '/bin/busybox', '/etc/passwd', '/usr/local/bin/spx_restservice',
 '/usr/local/lib/libnetwork.so', '/usr/local/lib/libspx.so',
 '/usr/local/sbin/psme-rest-server', '/var/www/redfish/v1/index.html']

>>> data = ext.extract_file('/usr/local/bin/spx_restservice')
>>> len(data)
2387456
>>> data[:4].hex()
'7f454c46'    # ELF magic — ARM32 binary, ready for BinaryContext
```

---

## False positives

**Truncated archive yields fewer entries than expected without an error.** `_parse_entries()` stops silently when it reaches the end of the directory block or when `next_off > len(cramfs)`. A partially downloaded firmware image passes the magic check at the start but produces an incomplete file tree. Verify download integrity with the firmware manifest before relying on `list_files()` count.

**Block-0 GOT prefix scan may match on binary content.** The zlib header scan in `_decompress_file()` looks for `0x78` followed by a valid FLG byte. In rare cases a raw binary file with no zlib content may contain `0x78 0x9c` as data bytes before any actual zlib stream, causing `zlib.decompress()` to fail. When this happens the extractor raises `zlib.error` rather than silently producing garbage. Catch and report the path and block index for manual analysis.

---

## Pipeline position

**Before this module:** Locate the CramFS partition offset in the BMC firmware image by scanning for the `0x28cd3d45` magic bytes (e.g., `data.find(b'\x45\x3d\xcd\x28')`). Confirm the AMI format by checking that the inode at offset 8 (root inode) has a 16-byte stride — standard CramFS root inodes are 12 bytes. On known AMI SPX images the CramFS typically starts at offset `0x160000`.

**After this module:** Write each extracted binary to a temp file and load with `BinaryContext.load_or_build()`. The ARM32 `spx_restservice` and `psme-rest-server` binaries are the primary RE targets — both take HTTP input via FastCGI and call shell sinks. Run `ARM32TaintTracker` after loading.

---

## Reading findings

`AmiCramFSExtractor.list_entries(dir_path='')` returns `List[AmiCramFSEntry]`:

| Attribute | Content |
|:---|:---|
| `name` | Entry filename |
| `mode` | Unix file mode integer (includes file type bits: `S_IFREG`, `S_IFDIR`, `S_IFLNK`) |
| `uid` | Owner UID |
| `gid` | Owner GID |
| `size` | Uncompressed file size in bytes |
| `data_off` | Data offset in 4-byte units from the start of the CramFS image |
| `is_dir` | Property — `True` for directory entries |
| `is_reg` | Property — `True` for regular files |
| `is_lnk` | Property — `True` for symbolic links |
| `byte_offset` | Property — `data_off × 4` in bytes |

`AmiCramFSExtractor.list_files()` yields all file paths as strings (recursive walk).
`AmiCramFSExtractor.extract_file(path)` returns `bytes` — decompressed content of a file at `path`.
`AmiCramFSExtractor.extract_all(out_dir)` extracts all files to `out_dir`.

---

## See also

- [BinaryContext](binary-context.md) — load extracted payloads for analysis
- [FirmwareContainers](firmware-containers.md) — higher-level firmware partition walker
- [EntropyMapper](entropy-mapper.md) — locate encrypted or compressed regions before extraction
