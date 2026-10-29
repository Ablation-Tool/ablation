import stat
import struct
import zlib

import pytest

from ablation.parsers.jffs2 import Jffs2Error, Jffs2Image

NODE_HEADER = struct.Struct("<HHII")
DIRENT = struct.Struct("<4IBB2x2I")
INODE = struct.Struct("<3I2H7I2BH2I")


def crc(data):
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def node(kind, body):
    header = NODE_HEADER.pack(0x1985, kind, NODE_HEADER.size + len(body), 0)
    header = header[:8] + struct.pack("<I", crc(header[:8]))
    result = header + body
    return result + b"\xff" * ((-len(result)) % 4)


def dirent(name, ino=2, pino=1, version=1, file_type=8):
    encoded = name.encode()
    body = DIRENT.pack(pino, version, ino, 0, len(encoded), file_type, 0, crc(encoded))
    body = body[:20] + struct.pack("<I", crc(body[:20])) + body[24:]
    return node(0xE001, body + encoded)


def inode(data=b"", ino=2, version=1, offset=0, isize=None, mode=None,
          compression=6):
    if mode is None:
        mode = stat.S_IFREG | 0o744
    if isize is None:
        isize = offset + len(data)
    if compression == 6:
        payload = zlib.compress(data) if data else b""
    elif compression == 1:
        payload = b""
    else:
        payload = data
    body = INODE.pack(
        ino, version, mode, 0, 0, isize, 0, 0, 0, offset, len(payload),
        len(data), compression, compression, 0, crc(payload), 0,
    )
    body = body[:52] + struct.pack("<I", crc(body[:48]))
    return node(0xE002, body + payload)


def root():
    return inode(ino=1, mode=stat.S_IFDIR | 0o755)


def filesystem(*nodes):
    return root() + b"".join(nodes)


def test_reconstruct_zlib_file_and_metadata():
    image = Jffs2Image.from_bytes(filesystem(
        dirent("hello"),
        inode(b"hello ", version=1, offset=0, isize=12),
        inode(b"world\n", version=2, offset=6, isize=12),
    ))
    assert image.read_file("/hello") == b"hello world\n"
    assert image.entries["/"].is_dir
    assert image.file_paths() == ("/hello",)
    assert image.metadata()["entries"] == 2
    assert image.metadata()["inode_count"] == 3
    with pytest.raises(IsADirectoryError):
        image.read_file("/")
    with pytest.raises(KeyError, match="not found"):
        image.read_file("/missing")
    with pytest.raises(TypeError):
        image.entries["/other"] = image.entries["/hello"]


def test_latest_extent_and_dirent_versions_win():
    image = Jffs2Image.from_bytes(filesystem(
        dirent("file", ino=0, version=1),
        dirent("file", version=2),
        inode(b"oldbad", version=1, isize=6),
        inode(b"new", version=2, offset=0, isize=6),
        inode(b"end", version=3, offset=3, isize=6),
    ))
    assert image.read_file("/file") == b"newend"
    deleted = Jffs2Image.from_bytes(filesystem(
        dirent("file", version=3),
        dirent("file", ino=0, version=4),
        inode(b"data", version=3),
    ))
    assert deleted.file_paths() == ()


@pytest.mark.parametrize("compression, data", [
    (0, b"uncompressed"),
    (1, b"\x00" * 32),
    (4, b"copied"),
    (6, b"zlib data"),
])
def test_supported_compression_modes(compression, data):
    image = Jffs2Image.from_bytes(filesystem(
        dirent("file"), inode(data, compression=compression),
    ))
    assert image.read_file("/file") == data


def test_implicit_root_hardlinks_and_unsafe_names():
    image = Jffs2Image.from_bytes(
        dirent("one", version=1) + dirent("two", version=2)
        + inode(b"shared", version=2),
    )
    assert image.entries["/"].is_dir
    assert image.read_file("/one") == b"shared"
    assert image.read_file("/two") == b"shared"
    unsafe = Jffs2Image.from_bytes(filesystem(dirent("..")))
    assert unsafe.rejected_dirents == 1
    assert unsafe.file_paths() == ()
    assert unsafe.metadata()["rejected_dirents"] == 1


def test_dirent_name_crc_is_checked():
    raw = bytearray(filesystem(dirent("file"), inode(b"data")))
    dirent_offset = raw.find(b"\x85\x19\x01\xe0")
    raw[dirent_offset + 40] ^= 1
    with pytest.raises(Jffs2Error, match="dirent-name CRC"):
        Jffs2Image.from_bytes(raw)


@pytest.mark.parametrize("raw, message", [
    (b"not a filesystem", "no valid"),
    (filesystem(dirent("file"), inode(b"data", compression=2)), "compression"),
    (filesystem(dirent("file"), inode(b"data"))[:-2], "node length"),
])
def test_malformed_images_fail_closed(raw, message):
    with pytest.raises(Jffs2Error, match=message):
        Jffs2Image.from_bytes(raw)


def test_header_crc_is_checked():
    raw = bytearray(filesystem())
    raw[8] ^= 1
    with pytest.raises(Jffs2Error, match="header CRC"):
        Jffs2Image.from_bytes(raw)


def test_inode_and_payload_crc_are_checked():
    raw = bytearray(filesystem(dirent("file"), inode(b"data")))
    inode_offset = raw.find(b"\x85\x19\x02\xe0")
    raw[inode_offset + 59] ^= 1
    with pytest.raises(Jffs2Error, match="inode CRC"):
        Jffs2Image.from_bytes(raw)
    raw = bytearray(filesystem(dirent("file"), inode(b"data")))
    raw[inode_offset + 60] ^= 1
    with pytest.raises(Jffs2Error, match="data CRC"):
        Jffs2Image.from_bytes(raw)


def test_conflicting_same_version_extent_is_rejected():
    with pytest.raises(Jffs2Error, match="conflicting inode extent"):
        Jffs2Image.from_bytes(filesystem(
            dirent("file"), inode(b"one", isize=3), inode(b"two", isize=3),
        ))
    with pytest.raises(Jffs2Error, match="conflicting inode metadata"):
        Jffs2Image.from_bytes(filesystem(
            dirent("file"), inode(b"one", isize=3), inode(b"two", isize=4),
        ))
    trailing = Jffs2Image.from_bytes(filesystem() + b"\x01")
    assert trailing.unparsed_bytes == 1


def test_directory_cycle_is_rejected():
    with pytest.raises(Jffs2Error, match="cycle"):
        Jffs2Image.from_bytes(filesystem(
            dirent("child", ino=2, pino=3),
            dirent("parent", ino=3, pino=2),
            inode(ino=2, mode=stat.S_IFDIR | 0o755),
            inode(ino=3, mode=stat.S_IFDIR | 0o755),
        ))


def test_limits_and_path_loading(tmp_path):
    path = tmp_path / "image.jffs2"
    path.write_bytes(filesystem(dirent("file"), inode(b"data")))
    assert Jffs2Image.from_path(path).read_file("/file") == b"data"
    with pytest.raises(Jffs2Error, match="input size"):
        Jffs2Image.from_path(path, max_input_bytes=1)
    with pytest.raises(Jffs2Error, match="extent"):
        Jffs2Image.from_bytes(
            filesystem(dirent("file"), inode(b"data")), max_file_bytes=2,
        )
    with pytest.raises(Jffs2Error, match="output limit"):
        Jffs2Image.from_bytes(
            filesystem(dirent("file"), inode(b"data")), max_output_bytes=2,
        )
    with pytest.raises(ValueError, match="nonnegative"):
        Jffs2Image.from_bytes(b"", max_input_bytes=-1)
