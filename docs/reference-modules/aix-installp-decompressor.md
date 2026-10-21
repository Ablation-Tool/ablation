# AixInstallpDecompressor

Decompress IBM AIX installp BFF archive entries whose magic bytes indicate IBM proprietary compression (types 0x0e, 0x0f, 0x10, 0x11) — entries that zlib, bzip2, lzma, and binwalk all fail to handle.

---

## Why this exists

1. **IBM AIX installp packages compress executables with a proprietary algorithm.** Entries with type bytes 0x0e, 0x0f, 0x10, or 0x11 are IBM-compressed XCOFF32 binaries, not plain XCOFF32. Before this module, these entries were opaque — every standard decompressor failed.

2. **The compression algorithm has been reverse-engineered through four steps.** This module implements all four steps of the decompression pipeline as derived from IBM `liblpp.a` and empirical analysis of real installp entries.

3. **Step 4 uses a single-level escape-byte hypothesis** for rare bytes absent from the K-byte common alphabet. These are encoded as `[escape_byte, term]` pairs in the BWT buffer. Entry data past the Huffman stream is appended as a raw trailing block.

---

## How it works

```
AixInstallpDecompressor(raw)
         │
         ├── Parse 16-byte header: type byte, version, field_A, field_B, field_C
         │   (field semantics differ by type: 0x0e vs 0x0f swap bwt_index/uncompressed_size)
         ├── Read sym_table: d[16:272] — frequency-sorted permutation of 256 byte values
         ├── Compressed payload: d[272:] — unary MSB-first Huffman codes
         │
         └── decompress() — full 4-step pipeline:
             Step 1: unary_huffman_decode → MTF index stream
             Step 2: inverse_mtf(sym_table) → BWT last column
             Step 3: inverse_bwt(bwt_index) → BWT buffer (K-byte common alphabet)
             Step 4: step4_escape_decode → decoded bytes + trailing_raw_block
```

**Header layout:**

| Offset | Field | Notes |
|:---|:---|:---|
| d[0] | type byte | 0x0e, 0x0f, 0x10, 0x11 |
| d[1:4] | version | 0x00 0x01 0x00 for type 0x0e |
| d[4:8] | field A (big-endian) | uncompressed_size (0x0e) or bwt_index (0x0f) |
| d[8:12] | field B (big-endian) | purpose unknown |
| d[12:16] | field C (little-endian) | bwt_index (0x0e) or uncompressed_size (0x0f) |

---

## Usage

```python
from ablation.core.aix_installp_decompressor import AixInstallpDecompressor

decomp = AixInstallpDecompressor(raw_entry_bytes)
xcoff_bytes = decomp.decompress()

# Verify XCOFF32 magic
assert xcoff_bytes[:2] == b'\x01\xdf', f"Expected XCOFF32, got {xcoff_bytes[:2].hex()}"

# Pass to downstream analysis
from ablation.analyzers.aix_bff_extractor import XCOFF32Info
info = XCOFF32Info(xcoff_bytes)
print(info.dangerous_imports())
```

---

## Step 4: escape-byte decode

```
K = unique bytes in BWT buffer (common alphabet)
escape_byte = sym_table[0]  (most common byte in entry)

For each byte b in BWT buffer:
  b != escape_byte  → emit b
  b == escape_byte  → read next byte n:
    n == escape_byte → emit escape_byte  (self-escape)
    n in common_set  → emit sym_table[K + rank(n)]  (rare byte encoding)
```

For entries where K < 256 and rare-byte ranks exceed K-1, use `AixInstallpStep4Multilevel` instead.

---

## Limitations

**Multi-cycle BWT.** When K < 256, the LF-map traversal from `bwt_index` may not reach all rows (multiple disjoint cycles). For affected entries, `BwtEulerianReconstructor` recovers the full text.

**Type 0x0f secondary streams.** Type 0x0f entries may contain a second Huffman stream after the primary. Use `AixType0fStreamSplitter` to recover both streams before calling this module's step 2–4.

---

## Pipeline position

**Dispatch:** Called from `AixBffExtractor` when entry type byte is in `{0x0e, 0x0f, 0x10, 0x11}`.

**After:** Pass decompressed bytes to `XCOFF32Info` and then `BinaryContext.load_or_build()`.

---

## See also

- [AIX BFF Extractor](aix-bff-extractor.md) — outer BFF container; dispatches to this module
- [AIX Installp Step4 Multilevel](aix-installp-step4-multilevel.md) — multi-level rare byte decoder
- [BWT Eulerian Reconstructor](bwt-eulerian-reconstructor.md) — multi-cycle BWT recovery
- [AIX Type0f Stream Splitter](aix-type0f-stream-splitter.md) — two-stream type 0x0f decoder
