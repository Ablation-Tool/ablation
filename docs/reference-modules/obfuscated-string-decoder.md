# ObfuscatedStringDecoder

## Why this exists

Three gaps motivated this module:

1. Firmware droppers commonly use multi-layer encoding chains such as Base64 to deflate to XOR. The existing IOC extractor handled single-layer cases but not chained decoding.
2. High-entropy string literals in .rodata are a reliable indicator of encoded payloads, but no automated decoder existed to extract their plaintext.
3. Manual decoding of each suspect string added hours of analyst time per binary.

## What it does

`ObfuscatedStringDecoder` scans a binary for null-terminated byte sequences with Shannon entropy above 4.0 bits per byte, then attempts multi-layer decoding via BFS. Each candidate string passes through up to three decode layers in sequence until a printable ASCII result is produced.

**Decode methods attempted:**

1. Base64 standard
2. Base64 URL-safe
3. Hex-encoded ASCII
4. ASCII ordinal (comma-separated decimal)
5. zlib decompression
6. Raw deflate (wbits=-15)
7. Single-byte XOR brute force across all single-byte keys, selecting the key that maximizes printable-character fraction

## Constructor

```python
from modules.obfuscated_string_decoder import ObfuscatedStringDecoder

# From path
decoder = ObfuscatedStringDecoder('/path/to/binary')

# From BinaryContext
decoder = ObfuscatedStringDecoder.from_context(ctx)
```

## Methods

| Method | Returns | Notes |
| ------ | ------- | ----- |
| `scan(max_depth=3)` | `list[DecodedString]` | Scans all high-entropy string literals |
| `report(results=None)` | `str` | Formatted text report |

## DecodedString dataclass

```python
@dataclass
class DecodedString:
    offset:         int        # byte offset in binary
    raw:            bytes      # original encoded bytes
    raw_entropy:    float      # Shannon entropy of raw bytes
    decoded_layers: list[str]  # decode chain, e.g. ['base64', 'zlib', 'xor:0x42']
    plaintext:      bytes      # decoded result
```

## Entropy threshold

Only strings with entropy greater than 4.0 bits per byte are processed. Normal English text typically measures at 3.5 to 4.0 bits per byte. Encoded data produced by Base64, deflate, or XOR of high-entropy input typically measures at 4.5 to 6.0 bits per byte. The 4.0 threshold keeps false positives low while catching most encoded payloads.

## Severity and triage

Results from `ObfuscatedStringDecoder` are informational. Decoded strings that match IOC patterns such as IP addresses, URLs, command strings, and registry keys should be registered with `FindingRegistry` at HIGH severity and fed to `PatternLibrary.record_hit()`. Strings that do not match IOC patterns after decoding are low-priority.
