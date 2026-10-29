import gzip
import struct

import pytest

from ablation.parsers.bflt import BfltError, BfltImage


HEADER_SIZE = 64


def image(flags=1, text=b"\x00\xb0\xa0\xe3", data=b"data", bss=16,
          relocations=b"\x00\x00\x00\x01", trailing=b"", reserved=None):
    data_end = HEADER_SIZE + len(text) + len(data)
    uncompressed = text + data + relocations
    if flags & 0x04:
        stored = gzip.compress(uncompressed, mtime=0)
        reloc_start = data_end
    elif flags & 0x08:
        stored = text + gzip.compress(data + relocations, mtime=0)
        reloc_start = data_end
    else:
        stored = uncompressed
        reloc_start = data_end
    header = struct.pack(
        ">4s15I", b"bFLT", 4, 0x40, HEADER_SIZE + len(text), data_end,
        data_end + bss, 0x1000, reloc_start, len(relocations) // 4,
        flags, 0, *(reserved or [0] * 5),
    )
    assert len(header) == HEADER_SIZE
    return header + stored + trailing


def test_parse_flat_memory_layout_and_metadata():
    parsed = BfltImage.from_bytes(image())
    assert parsed.entry == 0x40
    assert parsed.text_bytes == b"\x00\xb0\xa0\xe3"
    assert parsed.data_bytes == b"data"
    assert parsed.read_memory(0x40, 4) == parsed.text_bytes
    assert parsed.relocations == b"\x00\x00\x00\x01"
    assert not parsed.compressed
    assert parsed.metadata()["text_range"] == [64, 68]
    assert parsed.metadata()["data_range"] == [68, 72]


def test_gzip_payload_is_bounded_and_relocations_stay_in_file():
    raw = image(flags=0x05)
    parsed = BfltImage.from_bytes(raw)
    assert parsed.compressed
    assert parsed.compression == "gzip"
    assert parsed.metadata()["compression"] == "gzip"
    assert parsed.text_bytes == b"\x00\xb0\xa0\xe3"
    assert parsed.data_bytes == b"data"
    assert parsed.relocations == b"\x00\x00\x00\x01"
    assert parsed.trailing_bytes == 0


def test_gzdata_preserves_text_and_expands_data_and_relocations():
    parsed = BfltImage.from_bytes(image(flags=0x09))
    assert parsed.compressed
    assert parsed.compression == "gzdata"
    assert parsed.text_bytes == b"\x00\xb0\xa0\xe3"
    assert parsed.data_bytes == b"data"
    assert parsed.relocations == b"\x00\x00\x00\x01"
    assert parsed.trailing_bytes == 0


def test_ktrace_does_not_change_layout():
    parsed = BfltImage.from_bytes(image(flags=0x10))
    assert not parsed.compressed
    assert parsed.compression is None


def test_from_path_and_trailing_bytes(tmp_path):
    path = tmp_path / "tinyws"
    path.write_bytes(image(trailing=b"trailer"))
    parsed = BfltImage.from_path(path)
    assert parsed.trailing_bytes == 7
    with pytest.raises(BfltError, match="input size"):
        BfltImage.from_path(path, max_input_bytes=10)


@pytest.mark.parametrize("raw, message", [
    (b"bFLT", "shorter"),
    (b"NOPE" + image()[4:], "magic"),
    (image()[:4] + b"\x00\x00\x00\x03" + image()[8:], "revision"),
    (image(reserved=[0, 0, 0, 0, 1]), "reserved"),
    (image(flags=0x20), "flags"),
    (image(flags=0x02), "GOT-PIC"),
    (image(flags=0x0C), "multiple compressed"),
    (image()[:-1], "relocation"),
])
def test_malformed_headers_fail_closed(raw, message):
    with pytest.raises(BfltError, match=message):
        BfltImage.from_bytes(raw)


def test_compressed_relocation_offset_must_be_logical():
    raw = bytearray(image(flags=0x05))
    struct.pack_into(">I", raw, 0x1C, len(raw))
    with pytest.raises(BfltError, match="relocation offset"):
        BfltImage.from_bytes(raw)


def test_invalid_gzip_and_output_size_are_rejected():
    raw = bytearray(image(flags=0x05))
    raw[80] ^= 0xFF
    with pytest.raises(BfltError, match="gzip|data_end"):
        BfltImage.from_bytes(raw)
    with pytest.raises(BfltError, match="memory size"):
        BfltImage.from_bytes(image(flags=0x05), max_memory_bytes=10)


def test_memory_reads_and_limits_are_checked():
    parsed = BfltImage.from_bytes(image())
    with pytest.raises(BfltError, match="outside"):
        parsed.read_memory(parsed.data_end + 1, 1)
    with pytest.raises(ValueError, match="nonnegative"):
        parsed.read_memory(0, -1)
    with pytest.raises(ValueError, match="nonnegative"):
        BfltImage.from_bytes(image(), max_input_bytes=-1)
