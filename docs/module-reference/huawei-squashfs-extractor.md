# HuaweiSquashfsExtractor

**File:** `ablation/analyzers/huawei_squashfs_extractor.py`

Pure-Python squashfs v4 reader for Huawei VRP firmware. Handles the ARM64 BCJ filter that
causes standard tools to fail on V600R024+ images, and fixes two squashfs header field
misreadings that cause silent truncation when parsing directory tables.

---

## Why this exists

Three things that were not possible in Ablation before this module:

1. Extract files from Huawei VRP squashfs images at all. `unsquashfs` and `7z` both reject
   V600R024+ images with "Corrupt input data" because the XZ blocks carry the ARM64 BCJ
   branch-filter (filter ID 0x0A), and Python's `lzma` C extension compiled against pre-5.4.0
   liblzma headers rejects any XZ stream that declares an unsupported filter in FORMAT_XZ mode.
   No extraction means no triage, no `batch_plt_intersect`, no taint trace.

2. Parse Huawei squashfs directory entries correctly. The squashfs `dir_entry.size` field is
   a `__le16` across the full 8-byte entry header, not an `__le8` as some third-party
   implementations assume. Using `__le8` causes off-by-one misalignment on every directory
   entry after the first in a multi-entry block, silently missing files.

3. Decode inode refs without the standard inode table. Huawei VRP images pack the inode ref
   as `(block_byte_offset << 16) | within_decompressed_offset`, which differs from the
   conventional field layout used by most squashfs parsers. Wrong inode ref decoding reads
   the wrong metadata block and produces zero-byte files.

---

## Usage

```python
from ablation.analyzers.huawei_squashfs_extractor import HuaweiSquashfsExtractor

with HuaweiSquashfsExtractor("/path/to/sqfs_00_00001984.sqfs") as ext:
    data = ext.extract("aarch64/0x10644_7500/usr/local/lib/libhttpstackcore.so")
    open("/tmp/libhttpstackcore.so", "wb").write(data)
```

To list all paths in the image before extracting:

```python
with HuaweiSquashfsExtractor("/path/to/image.sqfs") as ext:
    for path in ext.list_files():
        print(path)
```

For batch triage after extraction, pass the extracted rootfs directory to
`batch_plt_intersect`:

```python
from ablation.analyzers.sink_arg_classifier import batch_plt_intersect
hits = batch_plt_intersect("/tmp/vrp_rootfs/")
for path, sinks in sorted(hits.items()):
    print(path, sinks)
```

---

## ARM64 BCJ filter bypass

Python's `lzma.decompress(data, format=lzma.FORMAT_XZ)` checks the XZ filter chain declared
in the block header. When the chain lists filter ID `0x0A` (ARM64 BCJ), pre-5.4.0 liblzma
raises `lzma.LZMAError: Corrupt input data`.

The fix: parse the XZ stream header to locate the raw LZMA2 payload (skipping the filter
chain), then call `lzma.decompress(payload, format=lzma.FORMAT_RAW, filters=[...])`. The
BCJ filter only adjusts absolute branch target offsets post-decompression. For inode tables,
directory entries, and ELF files being extracted for static analysis, the branch offsets in
the decompressed output are correct. Only executable code run on real hardware would need
the filter applied.

Confirmed on: Huawei VRP S6750-H V600R024C00SPC500 (`sqfs_00_00001984.sqfs`).

---

## Format notes

Squashfs v4 XZ images only. No zstd, lz4, lzo, or zlib support.

The module validates the magic (`0x73717368`), major version (must be 4), and compression
ID (must be 4 = XZ) at open time. Block size must be a non-zero power of two and at most 1 MB.

Decompression is bounded: each metadata block decompresses to at most 8 MB
(`_MAX_DECOMPRESS_BYTES`). Each extracted file is capped at 512 MB (`_MAX_EXTRACT_BYTES`).
These limits prevent OOM on adversarially crafted images.

Not thread-safe: all methods share a single file handle. Use one instance per thread or
protect with an external lock.

---

## Limitations

XZ compression only. Other squashfs compression algorithms raise `ValueError` at open time.

Fragment table support is partial. Regular file fragments are resolved; fragment-only small
files (no full data block) require `_read_frag_entry` to be called. This is handled
internally for `extract()`.

Inode type coverage is limited to regular files (type 2/9) and directories (type 1/8).
Symlinks, device nodes, FIFOs, and sockets are not traversed.
