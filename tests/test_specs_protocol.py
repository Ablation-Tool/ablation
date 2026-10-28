import random
from itertools import count

import pytest

from ablation.analyzers.specs_protocol import (
    SpecsSimulationHeader,
    SpecsWord,
    decode_frame,
    encode_frame,
    first_header_byte,
    header_checksum,
    is_long_frame_count,
    parse_simulation_headers,
    payload_checksum,
    reported_read_count,
)


def test_known_frame_and_checksums():
    header = [0x55, 0x02, 0x01]
    payload = [0xDE, 0xAD, 0xBE, 0xEF]
    words = encode_frame(header, payload)
    assert [word.value for word in words] == [
        0x55, 0x02, 0x01, 0x03, 0xDE, 0xAD, 0xBE, 0xEF, 0x22,
    ]
    assert [index for index, word in enumerate(words) if word.last] == [7]
    assert decode_frame(words) == (header, payload)
    assert header_checksum([0x55, 0x02, 0x01, 0]) == 3
    assert payload_checksum(payload) == 0x22


def test_empty_payload_has_no_last_data_word():
    words = encode_frame([1, 2, 3], [])
    assert len(words) == 5
    assert not any(word.last for word in words)
    assert decode_frame(words) == ([1, 2, 3], [])


def test_decode_rejects_header_payload_and_marker_corruption():
    header_error = list(encode_frame([1, 2, 3], [4, 5]))
    header_error[0] = SpecsWord(header_error[0].value ^ 1)
    with pytest.raises(ValueError, match="header checksum"):
        decode_frame(header_error)

    payload_error = list(encode_frame([1, 2, 3], [4, 5]))
    payload_error[-2] = SpecsWord(payload_error[-2].value ^ 1, True)
    with pytest.raises(ValueError, match="payload checksum"):
        decode_frame(payload_error)

    marker_error = list(encode_frame([1, 2, 3], [4, 5]))
    marker_error[-2] = SpecsWord(marker_error[-2].value, False)
    with pytest.raises(ValueError, match="last-data bit"):
        decode_frame(marker_error)

    with pytest.raises(ValueError, match="too short"):
        decode_frame([])
    with pytest.raises(TypeError, match="SpecsWord"):
        decode_frame([1, 2, 3, 4, 5])


def test_first_header_byte_and_input_validation():
    assert first_header_byte(0x15, "jtag") == 0x55
    assert first_header_byte(0x3F, "register") == 0xFF
    with pytest.raises(ValueError, match="six bits"):
        first_header_byte(0x40, "i2c")
    with pytest.raises(ValueError, match="invalid SPECS mode"):
        first_header_byte(1, "invalid")
    with pytest.raises(ValueError, match="four bytes"):
        header_checksum([1, 2, 3])
    with pytest.raises(ValueError, match="three header bytes"):
        encode_frame([1, 2], [])
    with pytest.raises(ValueError, match="word value"):
        SpecsWord(256)
    with pytest.raises(ValueError, match="three bytes"):
        SpecsSimulationHeader((1, 2))


def test_unbounded_iterables_are_rejected_at_frame_limit():
    with pytest.raises(ValueError, match="word limit"):
        payload_checksum(count())
    with pytest.raises(ValueError, match="word limit"):
        decode_frame(count())


def test_all_read_counts_match_rtl_threshold_and_mask():
    for count in range(256):
        assert is_long_frame_count(count) is (count > 0x80)
        assert reported_read_count(count) == (count & 0x7F)
    assert not is_long_frame_count(0x80)
    assert is_long_frame_count(0x81)
    assert reported_read_count(0x80) == 0
    assert reported_read_count(0x81) == 1
    with pytest.raises(ValueError, match="8-bit"):
        is_long_frame_count(256)


def test_archived_long_read_headers_and_comment_stripping():
    text = """
    1_0000_76543210
    //1_0000_0C04010f
    1_0000_1304810f
    1_0000_76543210
    1_0000_1C00820F
    """
    headers = parse_simulation_headers(text)
    assert len(headers) == 2
    assert headers[0].header == (0x04, 0x81, 0x0F)
    assert headers[0].read_count == 129
    assert headers[0].long_frame is True
    assert headers[0].reported_count == 1
    assert headers[0].computed_header_checksum == 2
    assert headers[1].header == (0x00, 0x82, 0x0F)
    assert headers[1].read_count == 130
    assert headers[1].reported_count == 2
    assert headers[1].computed_header_checksum == 5
    assert parse_simulation_headers("no frame marker") == []


def test_random_round_trips_and_single_bit_corruption_rejection():
    rng = random.Random(985471)
    for _ in range(1000):
        header = [rng.randrange(256) for _ in range(3)]
        payload = [rng.randrange(256) for _ in range(rng.randrange(256))]
        assert decode_frame(encode_frame(header, payload)) == (header, payload)

    for case in range(1000):
        header = [rng.randrange(256) for _ in range(3)]
        payload = [rng.randrange(256) for _ in range(rng.randrange(1, 64))]
        words = list(encode_frame(header, payload))
        index = rng.randrange(len(words))
        old = words[index]
        words[index] = SpecsWord(old.value ^ (1 << rng.randrange(8)), old.last)
        try:
            decode_frame(words)
        except ValueError:
            pass
        else:
            pytest.fail(f"single-bit corruption accepted at case {case}")


def test_xor_checksum_does_not_reject_every_byte_substitution():
    words = list(encode_frame([0x00, 0x01, 0x02], [0xAA]))
    words[0] = SpecsWord(0xFF, words[0].last)
    header, payload = decode_frame(words)
    assert header == [0xFF, 0x01, 0x02]
    assert payload == [0xAA]
