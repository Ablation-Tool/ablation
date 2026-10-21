# AixType0fStreamSplitter

Decode and split IBM AIX installp BFF type 0x0f entries — which contain two Huffman-compressed streams in one payload — recovering both the primary XCOFF32 text and the secondary block that was previously silently discarded.

---

## Why this exists

1. **AIX 5.2 type 0x0f BFF entries contain TWO Huffman-compressed streams in a single payload.** The primary stream decodes `uncompressed_size` MTF indices; the secondary stream begins at the byte boundary immediately following the primary sentinel. Standard tools see only the primary stream.

2. **`AixInstallpDecompressor._unary_huffman_decode` decodes only the primary stream** and stops after `uncompressed_size` symbols. Any secondary content is silently discarded, preventing analysis of type 0x0f secondary blocks. Trigger: IBM MQSeries `amqzxma0_nd` (AIX 5.2), where 14,064 bytes of secondary block were being lost.

3. **AIX 5.0 type 0x0f entries are SINGLE-STREAM** — no sentinel, no secondary block. This module auto-detects the version-specific format and handles both cases transparently.

---

## How it works

```
AixType0fStreamSplitter(raw)
         │
         ├── Parse header (d[0] type byte, d[1:4] version, sym_table at d[16:272])
         ├── Primary stream: Huffman decode until 256-consecutive-1-bit sentinel
         │   └── Sentinel: 32 × 0xFF bytes, then 0-bit
         ├── Detect format: AIX 5.2 (sentinel found) vs AIX 5.0 (no sentinel)
         └── Secondary stream (AIX 5.2 only):
             ├── Starts at next byte boundary after sentinel
             └── Decodes with shared sym_table + final MTF state from primary
```

**Shared MTF state:** Both streams share the same `sym_table` (raw[16:272]) and the same K-byte common alphabet. The secondary stream's Huffman decode begins from the final MTF list state at end of primary decode.

---

## Usage

```python
from ablation.analyzers.aix_type0f_stream_splitter import AixType0fStreamSplitter

splitter = AixType0fStreamSplitter(raw)
result = splitter.split()

print(f'Format: {result.format}')  # 'two_stream' | 'single_stream'
print(f'Primary decoded: {len(result.primary_bwt_last)} bytes')
if result.secondary_raw:
    print(f'Secondary block: {len(result.secondary_raw)} bytes (unidentified format)')
```

---

## Result fields (Type0fSplitResult)

| Field | Type | Content |
|:---|:---|:---|
| `format` | `str` | `'two_stream'` (AIX 5.2) or `'single_stream'` (AIX 5.0) |
| `primary_mtf_indices` | `list[int]` | Primary stream MTF symbol indices |
| `primary_bwt_last` | `bytes` | Primary stream inverse-MTF output (BWT last column) |
| `secondary_raw` | `bytes` | Raw secondary block payload (AIX 5.2 only; empty otherwise) |
| `secondary_mtf_indices` | `list[int]` | Secondary MTF indices decoded using final primary MTF state |
| `secondary_bwt_last` | `bytes` | Inverse-MTF of secondary stream using shared MTF state |
| `final_mtf_state` | `list[int]` | MTF list state at end of primary decode |

---

## Limitations

**Secondary block format is unidentified.** Empirical RE on MQSeries `amqzxma0_nd` (AIX 5.2, 50848-byte entry): the secondary block is not XCOFF32 and not a standard installp format. Decompression of the secondary stream produces bytes, but their semantic structure requires further RE against IBM `liblpp.a`.

**Single-stream detection is heuristic.** The module detects AIX 5.0 single-stream by the absence of the 0xFF sentinel within the expected bit range. Edge cases with unusual Huffman symbol distributions could misclassify a 5.2 entry if the primary stream happens to produce 256 consecutive 1-bits legitimately.

---

## Pipeline position

**Before:** `AixInstallpDecompressor._unary_huffman_decode` for type 0x0f entries only.

**After:** Pass `primary_bwt_last` to `AixInstallpDecompressor._step3_bwt_inverse` as usual. Secondary block requires separate RE to determine format.

---

## See also

- [AIX Installp Decompressor](aix-installp-decompressor.md) — full 4-step installp decompression pipeline
- [BWT Eulerian Reconstructor](bwt-eulerian-reconstructor.md) — multi-cycle BWT recovery for K < 256 cases
