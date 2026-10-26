"""Tests for IoTFirmwareUnpacker."""

import gzip
import io
import struct
import tarfile
import tempfile
from pathlib import Path

import pytest

from ablation.analyzers.iot_firmware_unpacker import IoTFirmwareUnpacker, FirmwareInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_squashfs_le() -> bytes:
    """Minimal squashfs-le header (just magic + padding to 96 bytes)."""
    return b'sqsh' + b'\x00' * 92


def _make_gzip_tar(members: dict[str, bytes]) -> bytes:
    """Create a gzip-compressed tar archive with given name->content members."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tf:
        for name, content in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_vivotek_pkg(inner_tar_members: dict[str, bytes]) -> bytes:
    """Create a fake VIVOTEK .flash.pkg: 49-byte header + gzip tar."""
    header = b'VIVOTEK_HDR_FAKE' + b'\x00' * (49 - 16)
    gz_tar = _make_gzip_tar(inner_tar_members)
    return header + gz_tar


def _make_uimage(inner: bytes) -> bytes:
    """64-byte U-Boot uImage header + payload."""
    magic = struct.pack('>I', 0x27051956)
    header = magic + b'\x00' * 60
    return header + inner


# ---------------------------------------------------------------------------
# probe() format detection
# ---------------------------------------------------------------------------

class TestProbe:

    def test_probe_gzip(self, tmp_path):
        fw = tmp_path / 'fw.gz'
        fw.write_bytes(gzip.compress(b'hello world'))
        info = IoTFirmwareUnpacker.probe(str(fw))
        assert info.format == 'gzip'
        assert not info.encrypted

    def test_probe_openssl_encrypted(self, tmp_path):
        fw = tmp_path / 'fw.img'
        fw.write_bytes(b'Salted__' + b'\x00' * 24)
        info = IoTFirmwareUnpacker.probe(str(fw))
        assert info.format == 'openssl_aes'
        assert info.encrypted

    def test_probe_uimage(self, tmp_path):
        fw = tmp_path / 'rootfs.img'
        fw.write_bytes(_make_uimage(b'squashfs_payload'))
        info = IoTFirmwareUnpacker.probe(str(fw))
        assert info.format == 'uimage'
        assert info.inner_offset == 64

    def test_probe_squashfs_le(self, tmp_path):
        fw = tmp_path / 'rootfs.sqfs'
        fw.write_bytes(_make_squashfs_le())
        info = IoTFirmwareUnpacker.probe(str(fw))
        assert info.format == 'squashfs_le'

    def test_probe_tar(self, tmp_path):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tf:
            info_entry = tarfile.TarInfo('file.txt')
            info_entry.size = 5
            tf.addfile(info_entry, io.BytesIO(b'hello'))
        fw = tmp_path / 'archive.tar'
        fw.write_bytes(buf.getvalue())
        info = IoTFirmwareUnpacker.probe(str(fw))
        assert info.format == 'tar'

    def test_probe_vivotek_pkg(self, tmp_path):
        fw = tmp_path / 'firmware.flash.pkg'
        fw.write_bytes(_make_vivotek_pkg({'rootfs.img': b'sqsh' + b'\x00' * 92}))
        info = IoTFirmwareUnpacker.probe(str(fw))
        assert info.format == 'vivotek_pkg'
        assert info.inner_offset == 49

    def test_probe_unknown(self, tmp_path):
        fw = tmp_path / 'blob.bin'
        fw.write_bytes(b'\x00\x01\x02\x03' * 64)
        info = IoTFirmwareUnpacker.probe(str(fw))
        assert info.format == 'unknown'
        assert not info.encrypted

    def test_probe_elf(self, tmp_path):
        fw = tmp_path / 'binary'
        fw.write_bytes(b'\x7fELF' + b'\x00' * 60)
        info = IoTFirmwareUnpacker.probe(str(fw))
        assert info.format == 'elf'

    def test_probe_ext2(self, tmp_path):
        fw = tmp_path / 'rootfs.ext2'
        # ext2 magic at offset 1080
        data = bytearray(2048)
        data[1080] = 0x53
        data[1081] = 0xEF
        fw.write_bytes(bytes(data))
        info = IoTFirmwareUnpacker.probe(str(fw))
        assert info.format == 'ext2'


# ---------------------------------------------------------------------------
# unpack() — basic extraction
# ---------------------------------------------------------------------------

class TestUnpack:

    def test_unpack_encrypted_returns_error(self, tmp_path):
        fw = tmp_path / 'fw.img'
        fw.write_bytes(b'Salted__' + b'\x00' * 24)
        result = IoTFirmwareUnpacker.unpack(str(fw), outdir=str(tmp_path / 'out'))
        assert result.error is not None
        assert 'encrypted' in result.error.lower() or 'Salted' in result.error

    def test_unpack_gzip_tar(self, tmp_path):
        gz_tar = _make_gzip_tar({'rootfs.img': _make_squashfs_le()})
        fw = tmp_path / 'fw.tar.gz'
        fw.write_bytes(gz_tar)
        outdir = tmp_path / 'out'
        result = IoTFirmwareUnpacker.unpack(str(fw), outdir=str(outdir))
        assert result.error is None or 'squashfs' in result.error.lower() or result.error == 'None'
        assert 'gzip' in result.format_chain or 'tar' in result.format_chain

    def test_unpack_vivotek_pkg_chain(self, tmp_path):
        pkg = _make_vivotek_pkg({'rootfs.img': _make_squashfs_le()})
        fw = tmp_path / 'firmware.flash.pkg'
        fw.write_bytes(pkg)
        outdir = tmp_path / 'out'
        result = IoTFirmwareUnpacker.unpack(str(fw), outdir=str(outdir))
        assert 'vivotek_pkg' in result.format_chain
        assert 'gzip' in result.format_chain
        assert 'tar' in result.format_chain

    def test_unpack_uimage_stripped(self, tmp_path):
        payload = _make_squashfs_le()
        fw = tmp_path / 'rootfs.img'
        fw.write_bytes(_make_uimage(payload))
        outdir = tmp_path / 'out'
        result = IoTFirmwareUnpacker.unpack(str(fw), outdir=str(outdir))
        assert 'uimage' in result.format_chain
        # inner.bin should be the squashfs payload
        inner = outdir / 'inner.bin'
        assert inner.exists()
        assert inner.read_bytes()[:4] == b'sqsh'

    def test_no_outdir_uses_tempdir(self, tmp_path):
        fw = tmp_path / 'fw.gz'
        fw.write_bytes(gzip.compress(b'hello'))
        result = IoTFirmwareUnpacker.unpack(str(fw))
        assert result.outdir is not None
        assert Path(result.outdir).exists()


# ---------------------------------------------------------------------------
# FirmwareInfo __str__
# ---------------------------------------------------------------------------

class TestFirmwareInfoStr:

    def test_str_encrypted_shows_warning(self, tmp_path):
        fw = tmp_path / 'fw.img'
        fw.write_bytes(b'Salted__' + b'\x00' * 24)
        info = IoTFirmwareUnpacker.probe(str(fw))
        s = str(info)
        assert 'ENCRYPTED' in s or 'encrypted' in s.lower()

    def test_str_normal_no_warning(self, tmp_path):
        fw = tmp_path / 'fw.gz'
        fw.write_bytes(gzip.compress(b'hello'))
        info = IoTFirmwareUnpacker.probe(str(fw))
        s = str(info)
        assert 'gzip' in s


# ---------------------------------------------------------------------------
# VIVOTEK regression (requires mounted rootfs)
# ---------------------------------------------------------------------------

VIVOTEK_PKG = Path('/media/cowboy/research/VIVOTEK/FD8369A/FD8369A-VVTK-0200f.flash.pkg')

@pytest.mark.skipif(not VIVOTEK_PKG.exists(), reason='VIVOTEK firmware not available')
def test_probe_real_vivotek_pkg():
    info = IoTFirmwareUnpacker.probe(str(VIVOTEK_PKG))
    assert info.format == 'vivotek_pkg'
    assert not info.encrypted
    assert info.inner_offset == 49
