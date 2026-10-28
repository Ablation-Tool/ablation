import pytest

from ablation.parsers.intel_hex import IntelHexError, IntelHexImage
from modules.isa_8051 import IntelHexLoader, Mcs51Decoder


def record(record_type, address, payload):
    body = bytes([
        len(payload),
        (address >> 8) & 0xFF,
        address & 0xFF,
        record_type,
        *payload,
    ])
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes([checksum])).hex().upper()


def data(address, payload):
    return record(0, address, payload)


def image_with(*records):
    return "\n".join([*records, record(1, 0, b"")]) + "\n"


def test_extended_linear_address_spans_and_dense_fill():
    text = image_with(
        record(4, 0, b"\x00\x01"),
        data(0xC000, b"\xAA"),
        data(0xC002, b"\xBB"),
        record(4, 0, b"\x00\x02"),
        data(0x0000, b"\xCC"),
    )
    image = IntelHexImage.from_bytes(text)
    assert image.address_range() == (0x1C000, 0x20001)
    assert image.spans == ((0x1C000, 0x1C001), (0x1C002, 0x1C003), (0x20000, 0x20001))
    small = IntelHexImage.from_bytes(image_with(data(0xC000, b"\xAA"), data(0xC002, b"\xBB")))
    assert small.to_bytes() == b"\xAA\xFF\xBB"
    assert small.to_bytes(fill=0) == b"\xAA\x00\xBB"
    absolute = image.to_bytes(base=0)
    assert len(absolute) == 0x20001
    assert absolute[0x1C000:0x1C003] == b"\xAA\xFF\xBB"
    assert absolute[0x20000] == 0xCC


def test_extended_segment_address_and_start_records():
    segment = IntelHexImage.from_bytes(image_with(
        record(3, 0, b"\x12\x34\x56\x78"),
        record(2, 0, b"\x00\x10"),
        data(0x20, b"\xAB"),
    ))
    assert segment.to_sparse() == {0x120: 0xAB}
    assert segment.start_address == ("segment", 0x12345678)
    assert segment.metadata()["start_address"] == {
        "type": "segment", "value": 0x12345678,
    }

    linear = IntelHexImage.from_bytes(image_with(
        record(5, 0, b"\x00\x02\x01\x04"),
        data(0, b"\xCD"),
    ))
    assert linear.start_address == ("linear", 0x20104)


def test_record_counts_and_sparse_copy_are_independent():
    image = IntelHexImage.from_bytes(image_with(data(4, b"\x01\x02")))
    sparse = image.to_sparse()
    sparse[4] = 0xFF
    assert image.to_sparse() == {4: 1, 5: 2}
    assert image.record_types == {0: 1, 1: 1}
    assert image.metadata()["record_types"] == {"0": 1, "1": 1}
    with pytest.raises(TypeError):
        image.data[4] = 0xFF
    with pytest.raises(TypeError):
        image.record_types[0] = 99


def test_identical_overlap_is_accepted_but_conflict_is_rejected():
    text = image_with(data(0x10, b"\xAA"), data(0x10, b"\xAA"))
    assert IntelHexImage.from_bytes(text).to_sparse() == {0x10: 0xAA}
    with pytest.raises(IntelHexError, match="line 2: conflicting overlap"):
        IntelHexImage.from_bytes(image_with(data(0x10, b"\xAA"), data(0x10, b"\xBB")))


@pytest.mark.parametrize("text, message", [
    ("not-a-record\n", "missing record marker"),
    (data(0, b"\x01")[:-2] + "00\n", "checksum mismatch"),
    (":0200000001FD\n", "invalid record length"),
    (record(6, 0, b"") + "\n" + record(1, 0, b"") + "\n", "unsupported record type"),
    (record(1, 0, b"\x00") + "\n" + record(1, 0, b"") + "\n", "invalid payload length"),
    (record(2, 1, b"\x00\x00") + "\n" + record(1, 0, b"") + "\n", "nonzero address"),
    (data(0, b"\xAA") + "\n", "missing EOF"),
    (image_with(data(0, b"\xAA")) + data(1, b"\xBB") + "\n", "content after EOF"),
])
def test_malformed_records_fail_closed(text, message):
    with pytest.raises(IntelHexError, match=message):
        IntelHexImage.from_bytes(text)


def test_conflicting_start_addresses_are_rejected():
    text = image_with(
        record(3, 0, b"\x00\x00\x00\x01"),
        record(3, 0, b"\x00\x00\x00\x02"),
        data(0, b"\xAA"),
    )
    with pytest.raises(IntelHexError, match="conflicting start-address"):
        IntelHexImage.from_bytes(text)


def test_dense_limits_and_arguments_are_validated():
    image = IntelHexImage.from_bytes(image_with(data(0x10, b"\xAA"), data(0x12, b"\xBB")))
    with pytest.raises(IntelHexError, match="dense size"):
        image.to_bytes(max_dense_bytes=2)
    with pytest.raises(ValueError, match="fill"):
        image.to_bytes(fill=256)
    with pytest.raises(ValueError, match="base"):
        image.to_bytes(base=0x11)
    with pytest.raises(IntelHexError, match="input size"):
        IntelHexImage.from_bytes(image_with(data(0, b"\xAA")), max_input_bytes=2)
    with pytest.raises(IntelHexError, match="not ASCII"):
        IntelHexImage.from_bytes(b"\xff")


def test_from_path_enforces_input_limit(tmp_path):
    path = tmp_path / "image.hex"
    text = image_with(data(0, b"\xAA"))
    path.write_text(text, encoding="ascii")
    assert IntelHexImage.from_path(path).to_sparse() == {0: 0xAA}
    with pytest.raises(IntelHexError, match="input size"):
        IntelHexImage.from_path(path, max_input_bytes=2)


def test_8051_loader_preserves_api_and_strict_behavior():
    text = image_with(data(0x100, b"\xAA"), data(0x102, b"\xBB"))
    loader = IntelHexLoader.from_bytes(text)
    assert loader.address_range() == (0x100, 0x103)
    assert loader.to_sparse() == {0x100: 0xAA, 0x102: 0xBB}
    assert loader.to_bytes(fill=0xEE) == b"\xAA\xEE\xBB"
    with pytest.raises(IntelHexError, match="checksum mismatch"):
        IntelHexLoader.from_bytes(data(0, b"\x01")[:-2] + "00\n")


def test_8051_decoder_rejects_negative_offsets():
    with pytest.raises(IndexError, match="out of range"):
        Mcs51Decoder().decode_one(b"\x00", -1)
