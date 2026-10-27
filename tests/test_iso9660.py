import struct

import pytest

from ablation.parsers.iso9660 import ISO9660, SECTOR_SIZE


def _both32(value: int) -> bytes:
    return struct.pack("<I", value) + struct.pack(">I", value)


def _susp(signature: bytes, payload: bytes) -> bytes:
    return signature + bytes([len(payload) + 4, 1]) + payload


def _record(name: bytes, extent: int, size: int, flags: int = 0, susp: bytes = b"") -> bytes:
    padding = 1 if len(name) % 2 == 0 else 0
    length = 33 + len(name) + padding + len(susp)
    record = bytearray()
    record.append(length)
    record.append(0)
    record.extend(_both32(extent))
    record.extend(_both32(size))
    record.extend(b"\x00" * 7)
    record.extend([flags, 0, 0])
    record.extend(struct.pack("<H", 1) + struct.pack(">H", 1))
    record.append(len(name))
    record.extend(name)
    record.extend(b"\x00" * padding)
    record.extend(susp)
    if len(record) % 2:
        record.append(0)
    record[0] = len(record)
    return bytes(record)


def _directory(extent: int, entries: list[bytes]) -> bytes:
    records = [_record(b"\x00", extent, SECTOR_SIZE, 2), _record(b"\x01", extent, SECTOR_SIZE, 2)]
    records.extend(entries)
    return b"".join(records).ljust(SECTOR_SIZE, b"\x00")


def _iso() -> bytes:
    root_entries = [
        _record(b"etc", 19, SECTOR_SIZE, 2),
        _record(b"hello.txt;1", 20, 5),
        _record(b"long", 20, 5, susp=_susp(b"NM", b"\x00long-name.txt")),
        _record(b"hard", 20, 5),
        _record(
            b"link",
            0,
            0,
            susp=_susp(b"SL", b"\x00\x08\x00\x00\x03etc\x00\x09hello.txt"),
        ),
        _record(b"multi", 21, 3, 0x80),
        _record(b"multi", 22, 3),
        _record(b"etc", 0, 0, susp=_susp(b"SL", b"\x00\x08\x00\x00\x02cf\x00\x03etc")),
    ]
    etc_entries = [_record(b"nested", 23, 6)]
    image = bytearray(24 * SECTOR_SIZE)
    descriptor = bytearray(SECTOR_SIZE)
    descriptor[0] = 1
    descriptor[1:6] = b"CD001"
    descriptor[6] = 1
    root_record = _record(b"\x00", 18, SECTOR_SIZE, 2)
    descriptor[156:156 + len(root_record)] = root_record
    image[16 * SECTOR_SIZE:17 * SECTOR_SIZE] = descriptor
    image[18 * SECTOR_SIZE:19 * SECTOR_SIZE] = _directory(18, root_entries)
    image[19 * SECTOR_SIZE:20 * SECTOR_SIZE] = _directory(19, etc_entries)
    image[20 * SECTOR_SIZE:20 * SECTOR_SIZE + 5] = b"hello"
    image[21 * SECTOR_SIZE:21 * SECTOR_SIZE + 3] = b"abc"
    image[22 * SECTOR_SIZE:22 * SECTOR_SIZE + 3] = b"def"
    image[23 * SECTOR_SIZE:23 * SECTOR_SIZE + 6] = b"nested"
    return bytes(image)


def test_entries_cover_rock_ridge_and_multi_extent(tmp_path):
    path = tmp_path / "test.iso"
    path.write_bytes(_iso())

    with ISO9660(path) as image:
        entries = {entry.path: entry for entry in image.entries()}
        assert entries["long-name.txt"].size == 5
        assert entries["multi"].extents == ((21, 0, 3), (22, 0, 3))
        assert image.read_file(entries["multi"]) == b"abcdef"
        assert image.read_file(entries["etc/nested"]) == b"nested"
        assert entries["link"].symlink_target == "/etc/hello.txt"


def test_extract_all_preserves_internal_links_and_hardlinks(tmp_path):
    source = tmp_path / "test.iso"
    output = tmp_path / "root"
    source.write_bytes(_iso())

    with ISO9660(source) as image:
        image.extract_all(output)

    assert (output / "hello.txt").read_bytes() == b"hello"
    assert (output / "long-name.txt").read_bytes() == b"hello"
    assert (output / "multi").read_bytes() == b"abcdef"
    assert (output / "link").is_symlink()
    assert (output / "link").readlink().as_posix() == "etc/hello.txt"
    assert (output / "hard").stat().st_ino == (output / "hello.txt").stat().st_ino


def test_rejects_non_iso(tmp_path):
    path = tmp_path / "invalid.iso"
    path.write_bytes(b"not an iso")
    with pytest.raises(ValueError, match="ISO9660"):
        ISO9660(path)
