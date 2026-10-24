# BFFDecompressor

## Why this exists

Three things were not possible before in Ablation:

1. **Detect compressed BFF archives before trying to parse them.** `bff_extractor.iter_entries` fails with a corrupt-data error on Huffman and LZW BFF archives. Without detection, the failure looked the same as a malformed archive. AIX 4.3.3 network daemon packages including `imapd`, `named8`, `gated`, and `telnetd` are compressed; they were silently skipped in the analysis pipeline.

2. **Give analysts the correct remediation path for each compression type.** IBM Huffman pack format type 0x0C is proprietary and requires `restore(8)` on an AIX system. LZW (type 0x0E) may be decompressible locally with the system `uncompress`. Without per-type guidance, analysts lost time testing decompression approaches that cannot work.

3. **Integrate compressed BFF handling into the analysis chain.** The BFF extractor (`bff_extractor`) only handles type 0x09 (plain). Callers had to detect the format themselves before choosing a parser. `BFFDecompressor.open()` provides a single entry point that delegates to `bff_extractor` for plain archives, attempts `uncompress` for LZW, and raises `BFFCompressedError` with specific instructions for Huffman.

## Format notes

BFF volume header type byte. The type is determined by the low byte of the LE uint16 at offset 0:

| Value | Format | Handled by |
|-------|--------|------------|
| `0x09` | plain backup | `bff_extractor.iter_entries` no decompression |
| `0x0C` | IBM Huffman / `pack` | AIX `restore(8)` required |
| `0x0E` | compress(1) / LZW | `uncompress -c` system tool |
| `0x10` | gzip variant AIX 5.2+ | `restore(8)` |

No compressed BFF samples are currently in the IBM research collection. The Huffman format is proprietary; byte-diffing `pack`/`unpack` output against raw compressed data on an AIX 4.3.3 system is the path to a Python implementation tracked as XLC-GAP-014.

## Usage

```python
from modules.bff_decompressor import BFFDecompressor, BFFCompressedError, detect

# Detect format without opening
with open('package.bff', 'rb') as f:
    data = f.read()
print(detect(data))   # 'plain', 'huffman', 'lzw', 'gzip-variant', 'not-bff', 'unknown'

# Open and extract (handles plain and LZW automatically)
try:
    entries = BFFDecompressor.open('package.bff')
    for entry in entries:
        print(entry.rel_path, len(entry.data))
except BFFCompressedError as e:
    # Contains specific restore(8) instructions for the analyst
    print(e)
```

## Key API

| Symbol | Description |
|--------|-------------|
| `detect(data)` | Returns format string for raw BFF bytes |
| `BFFDecompressor(path)` | Constructor |
| `BFFDecompressor.open(path)` | Class method; returns `list[BffEntry]` or raises |
| `BFFDecompressor.from_context(ctx)` | Construct from `BinaryContext` |
| `BFFDecompressor.entries()` | Instance method; delegates to `open()` |
| `BFFCompressedError` | Raised with remediation text when decompression is not possible |

## Limits

| Constant | Value | Applied to |
|----------|-------|------------|
| `_MAX_BFF_BYTES` | 256 MB | BFF archive file read in `BFFDecompressor.open()` |

## FORGE audit

Gate: **PASSED**.

- CWE-770 MEDIUM fixed: Added `os.path.getsize()` check against `_MAX_BFF_BYTES` before `open().read()` in `BFFDecompressor.open()`. Archives over 256 MB raise `ValueError`.

---

## How it works

Reads the binary header to validate the container magic, walks the partition or directory table, and yields the raw bytes of each embedded payload. Format detection runs on the first 512 bytes of each partition to classify the content as ELF, SquashFS, ext4, JFFS2, or unknown before extraction begins. Checksum validation CRC32 or SHA256 depending on container format runs on the extracted bytes and raises `ExtractionError` if the digest does not match the stored value.

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
| `format` | Detected format of the extracted payload `ext4`, `squashfs`, and `ELF`, and so on |

---

## See also

- [BinaryContext](binary-context.md): load extracted payloads for analysis
- [FirmwareContainers](firmware-containers.md): higher-level firmware partition walker
- [EntropyMapper](entropy-mapper.md): locate encrypted or compressed regions before extraction
