# ChunkWalkerValidator

**File:** `modules/chunk_walker_validator.py`

## Why this exists

Detects TLV/chunk parsers in stripped x86-64 binaries that advance the chunk pointer by raw user-supplied length without rounding up to the next 4-byte boundary. Many protocols (SCTP RFC 9260, DNS RFC 1035, GRE, PPTP, IS-IS) require chunk/TLV boundaries to be 4-byte aligned; a parser that does `ptr += raw_length` instead of `ptr += (raw_length + 3) & ~3` will misparse the next chunk because padding bytes become the next type and length fields.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.
