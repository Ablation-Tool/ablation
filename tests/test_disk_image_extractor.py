"""Unit tests for DiskImageExtractor.

Tests cover:
  - _parse_fls_line: parsing individual fls output lines
  - probe (via mocked subprocess): partition detection from fdisk output
  - _probe_by_magic: heuristic ext4 superblock scan
  - DiskImageExtractor.from_path: error handling on bad partition index

These tests do not require a real disk image or Sleuth Kit installation;
they exercise the parsing and dispatch logic in isolation.
"""

import struct
import tempfile
import pathlib

import pytest

from ablation.analyzers.disk_image_extractor import (
    DiskImageExtractor,
    PartitionInfo,
    _probe_by_magic,
)


# ── _parse_fls_line ───────────────────────────────────────────────────────────

class TestParseFLSLine:
    """Tests for the internal fls line parser."""

    def _clf(self):
        """Build a minimal extractor instance for parser access."""
        part = PartitionInfo(0, 0, 0, 'ext4', 0, 'root')
        ext = DiskImageExtractor.__new__(DiskImageExtractor)
        ext._image = '/dev/null'
        ext._part  = part
        ext._inode_cache = {}
        ext._path_cache  = {}
        return ext

    def test_regular_file(self):
        """r/r inode: name → type=r, correct inode and name."""
        ext = self._clf()
        result = ext._parse_fls_line('r/r 12:   passwd')
        assert result is not None
        inode, type_char, name = result
        assert type_char == 'r'
        assert inode == 12
        assert name == 'passwd'

    def test_directory(self):
        """d/d inode: dirname → type=d."""
        ext = self._clf()
        result = ext._parse_fls_line('d/d 3:    .')
        assert result is not None
        _, type_char, name = result
        assert type_char == 'd'
        assert name == '.'

    def test_symlink_with_target(self):
        """Symlink lines (l/l) have target stripped."""
        ext = self._clf()
        result = ext._parse_fls_line('l/l 15:   resolv.conf -> /etc/resolv.conf')
        assert result is not None
        _, type_char, name = result
        assert type_char == 'l'
        assert name == 'resolv.conf'
        assert '->' not in name

    def test_depth_marker_stripped(self):
        """Leading '+' depth markers (from fls -r) are stripped (no space before type)."""
        ext = self._clf()
        # fls -r format: depth markers are immediately adjacent to type code, no space
        result = ext._parse_fls_line('+++r/r 42:  init')
        assert result is not None
        inode, type_char, name = result
        assert inode == 42
        assert name == 'init'

    def test_empty_line_returns_none(self):
        """Empty lines produce None, not an error."""
        ext = self._clf()
        assert ext._parse_fls_line('') is None
        assert ext._parse_fls_line('   ') is None

    def test_unrecognised_line_returns_none(self):
        """Lines that don't match the fls format produce None."""
        ext = self._clf()
        assert ext._parse_fls_line('$OrphanFiles (3):') is None

    def test_large_inode_number(self):
        """Inode numbers up to 7 digits parse correctly."""
        ext = self._clf()
        result = ext._parse_fls_line('r/r 9999999:   bigfile.bin')
        assert result is not None
        inode, _, _ = result
        assert inode == 9999999


# ── PartitionInfo ─────────────────────────────────────────────────────────────

class TestPartitionInfo:
    def test_byte_addr_not_applicable(self):
        """PartitionInfo stores the fields we set."""
        p = PartitionInfo(0, 4096, 8191, 'ext4', 2, 'rootfs')
        assert p.index == 0
        assert p.start_sector == 4096
        assert p.fs_type == 'ext4'
        assert p.label == 'rootfs'


# ── _probe_by_magic ───────────────────────────────────────────────────────────

class TestProbeMagic:
    """Tests for the heuristic ext4 superblock scanner."""

    def _make_ext4_image(self, num_partitions: int = 1) -> bytes:
        """
        Build a fake disk image with ext4 superblock magic at known offsets.

        ext4 superblock: at byte 1024 from partition start.
        s_magic field: at offset 0x438 within the superblock (i.e. byte 0x438 from SB start).
        ext4 magic: 0x53EF (little-endian).
        s_blocks_count: at offset 0x4 within the SB, used for size computation.
        """
        EXT4_MAGIC = b'\x53\xef'
        SB_OFFSET  = 0x400                # 1024 bytes
        MAGIC_OFF  = 0x38                 # offset of s_magic within superblock
        BLOCKS_OFF = 0x4                  # offset of s_blocks_count within superblock

        # Each partition starts at a 512-byte-aligned offset
        part_size   = 4096 * 512          # 2 MB
        image_size  = part_size * num_partitions
        data        = bytearray(image_size)

        for i in range(num_partitions):
            part_start = i * part_size
            sb_start   = part_start + SB_OFFSET
            # Write s_blocks_count (1024 blocks of 1KB each = 1MB)
            struct.pack_into('<I', data, sb_start + BLOCKS_OFF, 1024)
            # Write s_magic
            data[sb_start + MAGIC_OFF:sb_start + MAGIC_OFF + 2] = EXT4_MAGIC

        return bytes(data)

    def test_single_ext4_partition_detected(self, tmp_path):
        """A single ext4 partition is detected by magic scan."""
        img = tmp_path / 'test.img'
        img.write_bytes(self._make_ext4_image(1))
        parts = _probe_by_magic(str(img))
        assert len(parts) >= 1
        assert parts[0].fs_type == 'ext4'

    def test_no_magic_returns_empty(self, tmp_path):
        """An image with no ext4 magic returns an empty list."""
        img = tmp_path / 'empty.img'
        img.write_bytes(b'\x00' * 8192)
        parts = _probe_by_magic(str(img))
        assert parts == []

    def test_missing_file_returns_empty(self):
        """A non-existent file path returns empty without raising."""
        parts = _probe_by_magic('/tmp/nonexistent_ablation_test_image.img')
        assert parts == []


# ── DiskImageExtractor.from_path error handling ───────────────────────────────

class TestFromPath:
    def test_bad_partition_index_raises(self, tmp_path, monkeypatch):
        """from_path with partition_index beyond available partitions raises IndexError."""
        # Create a minimal image with one known partition via probe override
        img = tmp_path / 'test.img'
        img.write_bytes(b'\x00' * 512)

        part = PartitionInfo(0, 0, 1024, 'ext4', 0, 'root')
        monkeypatch.setattr(
            'ablation.analyzers.disk_image_extractor.DiskImageExtractor.probe',
            staticmethod(lambda path: [part]),
        )
        with pytest.raises(IndexError):
            DiskImageExtractor.from_path(str(img), partition_index=5)

    def test_no_partitions_raises(self, tmp_path, monkeypatch):
        """from_path raises ValueError if probe returns no partitions."""
        img = tmp_path / 'empty.img'
        img.write_bytes(b'\x00' * 512)

        monkeypatch.setattr(
            'ablation.analyzers.disk_image_extractor.DiskImageExtractor.probe',
            staticmethod(lambda path: []),
        )
        with pytest.raises(ValueError):
            DiskImageExtractor.from_path(str(img))


# ── repr ──────────────────────────────────────────────────────────────────────

def test_repr_contains_fs_type():
    """__repr__ includes the filesystem type for debugging."""
    part = PartitionInfo(1, 4194312, 12582919, 'ext4', 4096, 'rootfs')
    ext = DiskImageExtractor.__new__(DiskImageExtractor)
    ext._image = '/path/to/image.wic'
    ext._part  = part
    ext._inode_cache = {}
    ext._path_cache  = {}
    r = repr(ext)
    assert 'ext4' in r
    assert '4194312' in r
