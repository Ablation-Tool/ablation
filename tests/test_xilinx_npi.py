import struct

import pytest

from ablation.analyzers.versal_pdi import CDO_CMD_END_WORD, CDO_MAGIC
from ablation.analyzers.xilinx_npi import XilinxNpiHex


def _cdo_words():
    prefix = 4
    magic = struct.unpack("<I", CDO_MAGIC)[0]
    version = 0x200
    length = 1
    checksum = (~(prefix + magic + version + length)) & 0xFFFFFFFF
    return [prefix, magic, version, length, checksum, CDO_CMD_END_WORD]


def _image(words=None, bits=None, magic="Xilinx ASCII NPI Deviceimage"):
    words = _cdo_words() if words is None else words
    bits = len(words) * 32 if bits is None else bits
    header = [
        magic,
        "Created by Deviceimage 2024.2 SW Build 5239630",
        "Design name: felix_top;Version=2024.2",
        "Architecture: versalprime",
        "Part: xcvm1802-vsva2197-1MP-e-S",
        "Date: Wed Mar 25 18:07:05 2026",
        f"Bits: {bits}",
    ]
    body = "\n".join(f"{word:08x}" for word in words)
    return ("\n".join(header) + "\n" + body + "\n").encode("ascii")


def test_decode_metadata_and_words():
    image = XilinxNpiHex.from_bytes(_image())
    assert image.metadata.design_name == "felix_top;Version=2024.2"
    assert image.metadata.architecture == "versalprime"
    assert image.metadata.part == "xcvm1802-vsva2197-1MP-e-S"
    assert image.metadata.date == "Wed Mar 25 18:07:05 2026"
    assert image.metadata.bits == 192
    assert image.metadata.byte_count == 24
    assert image.word_count == 6
    assert image.decode() == struct.pack("<6I", *_cdo_words())


def test_decode_to_versal_pdi():
    pdi = XilinxNpiHex.from_bytes(_image()).to_versal_pdi()
    sections = pdi.cdo_sections()
    assert len(sections) == 1
    assert sections[0].offset == 4
    assert sections[0].header_checksum_valid is True
    assert sections[0].end_detected is True


def test_uppercase_hex_is_accepted():
    image = XilinxNpiHex.from_bytes(_image().replace(b"004f4443", b"004F4443"))
    assert image.word_count == 6


def test_from_path(tmp_path):
    path = tmp_path / "image.rnpi"
    path.write_bytes(_image())
    image = XilinxNpiHex.from_path(str(path))
    assert image.label == "image.rnpi"
    assert image.word_count == 6


@pytest.mark.parametrize("word", ["0", "1234567g", "12345678 # comment", ""])
def test_invalid_word(word):
    data = _image(words=[], bits=32) + word.encode("ascii") + b"\n"
    with pytest.raises(ValueError, match="invalid NPI word|more words"):
        XilinxNpiHex.from_bytes(data)


def test_missing_magic():
    with pytest.raises(ValueError, match="missing Xilinx"):
        XilinxNpiHex.from_bytes(_image(magic="not an NPI image"))


def test_truncated_header():
    with pytest.raises(ValueError, match="truncated NPI metadata"):
        XilinxNpiHex.from_bytes(b"Xilinx ASCII NPI Deviceimage\n")


@pytest.mark.parametrize("line", [
    "Created by Deviceimage 2024.2",
    "Design name: ",
    "Architecture: versalprime",
])
def test_invalid_metadata(line):
    data = _image().split(b"\n")
    data[2] = line.encode("ascii")
    with pytest.raises(ValueError, match="invalid NPI metadata|empty NPI metadata"):
        XilinxNpiHex.from_bytes(b"\n".join(data))


@pytest.mark.parametrize("bits", [0, -32, 31])
def test_invalid_bit_count(bits):
    with pytest.raises(ValueError, match="positive multiple of 32"):
        XilinxNpiHex.from_bytes(_image(bits=bits))


def test_bit_count_must_be_decimal():
    data = _image().replace(b"Bits: 192", b"Bits: 0xc0")
    with pytest.raises(ValueError, match="invalid NPI bit count"):
        XilinxNpiHex.from_bytes(data)


@pytest.mark.parametrize("bits", [224, 160])
def test_word_count_mismatch(bits):
    with pytest.raises(ValueError, match="word count mismatch|more words"):
        XilinxNpiHex.from_bytes(_image(bits=bits))


def test_non_ascii_is_rejected():
    with pytest.raises(ValueError, match="not ASCII"):
        XilinxNpiHex.from_bytes(_image() + b"\xff\n")


def test_text_size_limit_for_buffer_and_path(monkeypatch, tmp_path):
    monkeypatch.setattr(XilinxNpiHex, "MAX_TEXT_BYTES", 8)
    with pytest.raises(ValueError, match="exceeds 8 bytes"):
        XilinxNpiHex.from_bytes(_image())
    path = tmp_path / "large.rcdo"
    path.write_bytes(_image())
    with pytest.raises(ValueError, match="exceeds 8 bytes"):
        XilinxNpiHex.from_path(str(path))


def test_decoded_size_limit(monkeypatch):
    monkeypatch.setattr(XilinxNpiHex, "MAX_DECODED_BYTES", 16)
    with pytest.raises(ValueError, match="payload exceeds 16 bytes"):
        XilinxNpiHex.from_bytes(_image())


def test_line_length_limit(monkeypatch):
    monkeypatch.setattr(XilinxNpiHex, "MAX_LINE_BYTES", 32)
    with pytest.raises(ValueError, match="line 2 exceeds 32 bytes"):
        XilinxNpiHex.from_bytes(_image())
