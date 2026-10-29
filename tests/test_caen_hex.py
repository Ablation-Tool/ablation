import pytest

from ablation.parsers.caen_hex import CaenHexError, CaenHexFirmware


def container(payload=b"\x7fELFpayload", board="A1676", checksum=None):
    body = (f"#NuovoFirmware{board}#".encode() + payload).hex().upper().encode()
    body += b"\n"
    if checksum is None:
        checksum = sum(value for value in body if value != 0x0A) & 0xFFFFFFFF
    return body + b"\x04\n" + f"{checksum:08X}\n".encode()


def test_decode_verified_payload_and_metadata():
    image = CaenHexFirmware.from_bytes(container())
    assert image.board == "A1676"
    assert image.payload == b"\x7fELFpayload"
    assert image.checksum == image.computed_checksum
    assert image.metadata() == {
        "format": "caen-ascii-hex",
        "board": "A1676",
        "payload_bytes": 11,
        "checksum": f"0x{image.checksum:08X}",
        "checksum_verified": True,
    }


def test_from_path_enforces_input_limit(tmp_path):
    path = tmp_path / "firmware.hex"
    path.write_bytes(container())
    assert CaenHexFirmware.from_path(path).payload.startswith(b"\x7fELF")
    with pytest.raises(CaenHexError, match="input size"):
        CaenHexFirmware.from_path(path, max_input_bytes=2)
    with pytest.raises(ValueError, match="nonnegative"):
        CaenHexFirmware.from_path(path, max_input_bytes=-1)


@pytest.mark.parametrize("raw, message", [
    (b"no terminator", "end-of-text"),
    (container()[:-2] + b"0\n", "trailer"),
    (container().lower(), "body"),
    (container().replace(b"7F", b"7f", 1), "body"),
    (b"00\x04" + b"00000000", "header"),
    (b"234e756f766f4669726d7761726541".upper() + b"\x04" + b"00000000", "unterminated"),
    (container(payload=b""), "no firmware payload"),
    (b"00\n\x04\n00000000\n", "header"),
])
def test_malformed_containers_fail_closed(raw, message):
    with pytest.raises(CaenHexError, match=message):
        CaenHexFirmware.from_bytes(raw)


def test_checksum_mismatch_is_rejected():
    with pytest.raises(CaenHexError, match="checksum mismatch"):
        CaenHexFirmware.from_bytes(container(checksum=0))


def test_invalid_board_identifier_is_rejected():
    raw = container().replace(b"4131363736", b"412F363736", 1)
    with pytest.raises(CaenHexError, match="board identifier"):
        CaenHexFirmware.from_bytes(raw)
