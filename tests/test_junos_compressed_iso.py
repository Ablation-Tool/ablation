import struct
import zlib

import pytest

from modules.junos_compressed_iso import BLOCK_SIZE, COMPOSITE_MAGIC, decompress, probe


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-15)
    return compressor.compress(data) + compressor.flush()


def _build_image(blocks: list[bytes], composite: bool = False) -> tuple[bytes, bytes]:
    encoded = [_raw_deflate(block) for block in blocks]
    header_size = 8 + len(blocks) * 8
    first_data_offset = header_size + 8
    data_offset = first_data_offset
    entries = []
    payload = bytearray()
    for block in encoded:
        entries.append((data_offset, len(block)))
        payload.extend(block)
        data_offset += len(block)
    uncompressed_size = len(blocks) * BLOCK_SIZE - 137
    header = struct.pack(">II", len(blocks), uncompressed_size)
    header += b"".join(struct.pack(">II", *entry) for entry in entries)
    image = header + b"\x00" * (first_data_offset - len(header)) + payload
    if composite:
        image = COMPOSITE_MAGIC + struct.pack(">I", 0) + image
    expected = b"".join(blocks)[:uncompressed_size]
    return image, expected


def test_probe_plain_image(tmp_path):
    image, _ = _build_image([b"a" * BLOCK_SIZE])
    path = tmp_path / "plain.img"
    path.write_bytes(image)

    info = probe(path)

    assert info.base == 0
    assert info.block_count == 1
    assert info.uncompressed_size == BLOCK_SIZE - 137
    assert not info.composite


def test_decompress_plain_image(tmp_path):
    blocks = [b"a" * BLOCK_SIZE, b"b" * BLOCK_SIZE]
    image, expected = _build_image(blocks)
    source = tmp_path / "plain.img"
    output = tmp_path / "plain.iso"
    source.write_bytes(image)

    decompress(source, output)

    assert output.read_bytes() == expected
    assert not output.with_name(output.name + ".tmp").exists()


def test_decompress_composite_image(tmp_path):
    blocks = [b"\x00" * BLOCK_SIZE, bytes(range(256)) * 256]
    image, expected = _build_image(blocks, composite=True)
    source = tmp_path / "composite.img"
    output = tmp_path / "composite.iso"
    source.write_bytes(image)

    info = decompress(source, output)

    assert info.composite
    assert info.base == 8
    assert output.read_bytes() == expected


def test_rejects_invalid_image(tmp_path):
    source = tmp_path / "invalid.img"
    output = tmp_path / "invalid.iso"
    source.write_bytes(b"not a Junos image")

    with pytest.raises(ValueError, match="compressed-ISO"):
        decompress(source, output)

    assert not output.exists()


def test_rejects_truncated_block(tmp_path):
    image, _ = _build_image([b"a" * BLOCK_SIZE])
    source = tmp_path / "truncated.img"
    output = tmp_path / "truncated.iso"
    source.write_bytes(image[:-20])

    with pytest.raises(ValueError, match="Invalid compressed block"):
        decompress(source, output)

    assert not output.exists()
    assert not output.with_name(output.name + ".tmp").exists()
