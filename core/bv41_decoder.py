#!/usr/bin/env python3
"""
bv41 decoder — Apple Compression.framework proprietary LZ4 container

Used by MacStadium Orka engine for VM disk image layers. Wraps raw LZ4 block
compression (NOT the standard lz4 frame format) in Apple's own chunked framing.

Format (per chunk):
  4B  magic: b'bv41' (compressed) | b'bv4-' (uncompressed passthrough)
  4B  uncompressed size (uint32 little-endian)
  4B  compressed size   (uint32 little-endian)
  N   raw LZ4 payload   (compressed size bytes)

Stream terminator: b'bv4$' (4 bytes, no size fields)

Reference: discovered via static RE of com.macstadium.orka-engine.server
           (OrkaEngineCore.ChunkInputStream, Compression.Algorithm.lz4)
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
