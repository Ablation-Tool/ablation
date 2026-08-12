#!/usr/bin/env python3
"""
bv41 — Apple Compression.framework proprietary chunked LZ4 container decoder
=========================================================================

WHAT
----
bv41 is Apple's internal chunked framing for LZ4-compressed data, defined in
Compression.framework (private API, `COMPRESSION_LZ4`). It is distinct from
the public LZ4 frame format (Yann Collet, magic 0x184D2204). Standard LZ4
decoders, 7-Zip, lz4-enabled forks, and APFS forensic suites (BlackBag,
Cellebrite, RECON LAB) do not handle it — they reject the payload at the magic
byte check or treat it as corrupt data.

WHERE IT APPEARS
----------------
- MacStadium Orka engine: VM disk image layers stored in OCI registries and
  served over NFS as `application/vnd.macstadium.orka-engine.disk.layer.v1+lz4`
- APFS snapshots and sealed-volume layer files on macOS 11+
- Any binary that calls `AppleArchive.ByteStream.decompressionStream(using: .lz4)`

The Orka engine (`com.macstadium.orka-engine.server`) and runvz both decode
these layers via the private framework API before handing them to
`Virtualization.framework`. Without this decoder, offline RE of Orka VM image
contents requires running inside a live macOS process — not viable for
supply-chain inspection, forensics, or layer diffing.

WIRE FORMAT
-----------
A bv41 stream is a sequence of chunks, each with the same header, terminated
by a 4-byte sentinel:

  Chunk header:
    Offset  Size  Field
      0     4B    magic (see values below)
      4     4B    uncompressed_size (uint32 little-endian)
      8     4B    compressed_size   (uint32 little-endian)
     12     N     raw LZ4 block payload (N = compressed_size bytes)

  Magic values:
    b'bv41'  — chunk is LZ4-compressed; payload is a raw LZ4 block
    b'bv4-'  — chunk is uncompressed passthrough; payload is verbatim data
    b'bv4$'  — stream terminator; no size fields, no payload, stop here

The payload for b'bv41' chunks is a raw LZ4 block — NOT an LZ4 frame. Correct
decode requires `lz4.block.decompress(payload, uncompressed_size=N)` where N
comes from the bv41 header. Passing the payload to any frame-format decoder
fails because there is no LZ4 frame magic.

WHY STANDARD TOOLS FAIL
------------------------
The frame-format check is the first gate in every LZ4 implementation: if the
first 4 bytes are not 0x184D2204 (little-endian), the decoder returns an error.
bv41 payloads have no such prefix — they start directly with the LZ4 block
header. Additionally, bv41 chains multiple chunks without an enclosing frame,
which means even partial frame-format support will stop after one chunk and
miss the rest of the stream. Multi-tool pipelines (binwalk, carving, Entropy)
also miss it because the magic bytes bv41/bv4- are not in any public format
registry.

This module is currently the only publicly available offline decoder for this
format.

API
---
  decode_bv41(data: bytes) -> bytes
      Full decode of a bv41 stream. Requires: pip install lz4

  decode_bv41_file(path: str, output_path: str = None) -> bytes
      Read a file, decode, optionally write output.

  probe_bv41(data: bytes) -> dict
      Inspect stream metadata (chunk count, compression ratio, sizes) without
      full decode. Useful for triage before pulling 500+ MB layers.

  is_bv41(data: bytes) -> bool
      Quick magic-byte check.

CLI
---
  python3 bv41_decoder.py input.bv41             # probe: print chunk stats
  python3 bv41_decoder.py input.bv41 output.bin  # decode to file

REFERENCE
---------
Discovered via static RE of com.macstadium.orka-engine.server:
  OrkaEngineCore.ChunkInputStream -> Compression.Algorithm.lz4
  Symbol: _AppleArchive_StreamOpen + lz4BlockDecompress internal dispatch
"""

import struct
import io


MAGIC_COMPRESSED   = b'bv41'
MAGIC_UNCOMPRESSED = b'bv4-'
MAGIC_TERMINATOR   = b'bv4$'


def decode_bv41(data: bytes) -> bytes:
    """Decode a complete bv41 stream to raw bytes."""
    try:
        import lz4.block as lz4block
    except ImportError:
        raise RuntimeError("lz4 required: pip install lz4")

    buf = io.BytesIO(data)
    out = io.BytesIO()

    while True:
        magic = buf.read(4)
        if not magic:
            break

        if magic == MAGIC_TERMINATOR:
            break

        if magic not in (MAGIC_COMPRESSED, MAGIC_UNCOMPRESSED):
            raise ValueError(f"Unknown bv41 chunk magic at offset {buf.tell()-4}: {magic!r}")

        uncomp_size, comp_size = struct.unpack_from('<II', buf.read(8))
        payload = buf.read(comp_size)

        if len(payload) < comp_size:
            raise ValueError(f"Truncated payload: expected {comp_size}, got {len(payload)}")

        if magic == MAGIC_UNCOMPRESSED:
            out.write(payload[:uncomp_size])
        else:
            decompressed = lz4block.decompress(payload, uncompressed_size=uncomp_size)
            out.write(decompressed)

    return out.getvalue()


def decode_bv41_file(path: str, output_path: str = None) -> bytes:
    """Decode a bv41 file on disk."""
    with open(path, 'rb') as f:
        data = f.read()

    decoded = decode_bv41(data)

    if output_path:
        with open(output_path, 'wb') as f:
            f.write(decoded)

    return decoded


def probe_bv41(data: bytes) -> dict:
    """Inspect a bv41 stream without full decode. Returns metadata."""
    buf = io.BytesIO(data)
    chunks = []
    total_uncomp = 0
    total_comp = 0

    while True:
        magic = buf.read(4)
        if not magic or magic == MAGIC_TERMINATOR:
            break
        if magic not in (MAGIC_COMPRESSED, MAGIC_UNCOMPRESSED):
            break

        uncomp_size, comp_size = struct.unpack_from('<II', buf.read(8))
        buf.seek(comp_size, 1)

        chunks.append({
            'type': 'compressed' if magic == MAGIC_COMPRESSED else 'passthrough',
            'uncomp_size': uncomp_size,
            'comp_size': comp_size,
            'ratio': round(uncomp_size / comp_size, 2) if comp_size else 0,
        })
        total_uncomp += uncomp_size
        total_comp += comp_size

    return {
        'chunk_count': len(chunks),
        'total_uncompressed_bytes': total_uncomp,
        'total_compressed_bytes': total_comp,
        'overall_ratio': round(total_uncomp / total_comp, 2) if total_comp else 0,
        'chunks': chunks,
    }


def is_bv41(data: bytes) -> bool:
    """Quick magic check."""
    return data[:4] in (MAGIC_COMPRESSED, MAGIC_UNCOMPRESSED)


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: bv41_decoder.py <input.bv41> [output]")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, 'rb') as f:
        raw = f.read()

    info = probe_bv41(raw)
    print(f"bv41 stream: {info['chunk_count']} chunks, "
          f"{info['total_uncompressed_bytes']/1024/1024:.2f} MB uncompressed, "
          f"ratio {info['overall_ratio']}x")

    if len(sys.argv) > 2:
        out_path = sys.argv[2]
        decoded = decode_bv41(raw)
        with open(out_path, 'wb') as f:
            f.write(decoded)
        print(f"Decoded {len(decoded)} bytes -> {out_path}")
