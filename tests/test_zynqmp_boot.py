import struct
from pathlib import Path

import pytest

from ablation.analyzers.zynqmp_boot import ZynqMpBootError, ZynqMpBootImage


def _checksum(data, offset, size):
    words = struct.unpack_from(f"<{size // 4}I", data, offset)
    return (~sum(words)) & 0xFFFFFFFF


def _image(payload=b"0123456789abcdef", name="zynqmp_fsbl.elf"):
    data = bytearray(0x400 + len(payload))
    struct.pack_into("<II", data, 0x20, 0xAA995566, 0x584C4E58)
    struct.pack_into("<II", data, 0x98, 0x100, 0x200)
    struct.pack_into("<I", data, 0x48, _checksum(data, 0x20, 0x28))

    struct.pack_into("<IIII", data, 0x100, 0x01020000, 1, 0x80, 0x50)
    struct.pack_into("<I", data, 0x13C, _checksum(data, 0x100, 0x3C))

    struct.pack_into("<IIII", data, 0x140, 0, 0x80, 0, 1)
    raw_name = name.encode("ascii") + b"\0"
    encoded_name = b"".join(
        raw_name[position:position + 4][::-1]
        for position in range(0, len(raw_name), 4)
    )
    data[0x150:0x150 + len(encoded_name)] = encoded_name

    struct.pack_into(
        "<16I", data, 0x200,
        len(payload) // 4, len(payload) // 4, len(payload) // 4, 0,
        0xFFFC0000, 0, 0xFFFC0000, 0,
        0x100, 0x110, 1, 0, 0x50, 0, 0, 0,
    )
    struct.pack_into("<I", data, 0x23C, _checksum(data, 0x200, 0x3C))
    data[0x400:] = payload
    return bytes(data)


def test_parses_and_extracts_partition(tmp_path):
    image = ZynqMpBootImage.from_bytes(_image())
    assert image.boot_header_checksum_valid
    assert image.iht_checksum_valid
    assert image.images[0].name == "zynqmp_fsbl.elf"
    partition = image.partitions[0]
    assert partition.name == "zynqmp_fsbl.elf.0"
    assert partition.offset == 0x400
    assert partition.exec_address == 0xFFFC0000
    assert partition.destination_device == "PS"
    assert partition.destination_cpu == "A53-0"
    assert partition.payload == b"0123456789abcdef"

    paths = image.extract_all(str(tmp_path))
    assert paths == [tmp_path / "00-zynqmp_fsbl.elf.0.bin"]
    assert paths[0].read_bytes() == partition.payload


def test_rejects_bad_magic_and_truncation():
    with pytest.raises(ZynqMpBootError, match="not a Zynq"):
        ZynqMpBootImage.from_bytes(bytes(0xA0))
    with pytest.raises(ZynqMpBootError, match="truncated ZynqMP boot header"):
        ZynqMpBootImage.from_bytes(_image()[:0x80])


def test_rejects_checksum_damage():
    data = bytearray(_image())
    struct.pack_into("<I", data, 0x2C, 0x1234)
    with pytest.raises(ZynqMpBootError, match="checksum mismatch"):
        ZynqMpBootImage.from_bytes(bytes(data))


def test_rejects_out_of_bounds_payload():
    data = bytearray(_image())
    struct.pack_into("<I", data, 0x220, 0x1000)
    with pytest.raises(ZynqMpBootError, match="partition 0"):
        ZynqMpBootImage.from_bytes(bytes(data), validate_checksums=False)


def test_rejects_cyclic_image_headers():
    data = bytearray(_image())
    struct.pack_into("<I", data, 0x140, 0x50)
    with pytest.raises(ZynqMpBootError, match="cyclic"):
        ZynqMpBootImage.from_bytes(bytes(data), validate_checksums=False)


def test_rejects_unterminated_image_name():
    data = bytearray(_image())
    data[0x150:0x24F] = b"A" * 0xFF
    with pytest.raises(ZynqMpBootError, match="unterminated"):
        ZynqMpBootImage.from_bytes(bytes(data), validate_checksums=False)


def test_real_zynqmp_boot_partitions():
    source = Path("/media/cowboy/research/CERN/fw/emp/sdcard.bak/bootpart/BOOT.BIN")
    if not source.is_file():
        pytest.skip("research boot image not found")
    image = ZynqMpBootImage.from_path(str(source))
    assert [part.name for part in image.partitions] == [
        "zynqmp_fsbl.elf.0",
        "emp_firmware_TE0807_wrapper.bit.0",
        "bl31.elf.0",
        "system.dtb.0",
        "u-boot.elf.0",
    ]
    assert [part.offset for part in image.partitions] == [
        0x2800, 0x3B500, 0x7AB0C0, 0x7B7880, 0x7C10C0,
    ]
    assert image.partitions[0].payload[:4] == bytes.fromhex("ddff00b0")
    assert image.partitions[3].payload[:4] == bytes.fromhex("d00dfeed")
    assert not any(part.encrypted or part.authenticated for part in image.partitions)
