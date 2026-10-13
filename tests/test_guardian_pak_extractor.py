"""Tests for GuardianPakExtractor — Tandem NonStop NSK PAK archive parser."""

import struct
import zlib
from pathlib import Path

import pytest

from ablation.core.guardian_pak_extractor import (
    GUARDIAN_PAK_MAGIC,
    GuardianFile,
    extract_to,
    iter_chunks,
    iter_files,
    _parse_guardian_path,
)


# ------------------------------------------------------------------ #
# Synthetic PAK construction helpers
# ------------------------------------------------------------------ #

def _compress_chunk(raw: bytes) -> bytes:
    """Return the length-prefixed zlib-compressed chunk bytes (+ alignment pad)."""
    compressed = zlib.compress(raw)
    out = struct.pack('>H', len(compressed)) + compressed
    if len(compressed) & 1:
        out += b'\x00'
    return out


def _build_pak(*records: bytes) -> bytes:
    """Build a minimal Guardian PAK archive containing the given decompressed records."""
    header = GUARDIAN_PAK_MAGIC + b'\x00\x01\x00\x00'  # 8-byte magic
    subtype = b'\x00\x0a'                               # 2-byte subtype
    body = b''
    for rec in records:
        body += _compress_chunk(rec)
    # Terminator: two 0xFFFF group separators
    body += struct.pack('>H', 0xFFFF) + struct.pack('>H', 0xFFFF)
    return header + subtype + body


def _tape_label() -> bytes:
    """200-byte tape volume label record."""
    base = b'Tandem Archive Tape'
    return base + b'\x00' * (200 - len(base))


def _file_catalog() -> bytes:
    """222-byte file catalog record."""
    base = b'File Backup'
    return base + b'\x00' * (222 - len(base))


def _file_header(volume: str, subvolume: str, filename: str) -> bytes:
    """358-byte file header record with Guardian path at offset 0x2E."""
    rec = bytearray(358)
    path = (volume.ljust(8) + subvolume.ljust(8) + filename.ljust(8)).encode('ascii')
    rec[0x2E:0x2E + 24] = path
    return bytes(rec)


def _data_chunk(payload: bytes) -> bytes:
    """Raw data chunk (no header stripping — whole chunk is file data)."""
    return payload


# ------------------------------------------------------------------ #
# iter_chunks
# ------------------------------------------------------------------ #

class TestIterChunks:
    def test_bad_magic_raises(self):
        with pytest.raises(ValueError, match="not a Guardian PAK"):
            list(iter_chunks(b'\x00' * 64))

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            list(iter_chunks(b'PAK '))

    def test_group_separator_skipped(self):
        """0xFFFF group separators are silently skipped, not yielded."""
        sep = struct.pack('>H', 0xFFFF)
        payload = b'hello world'
        chunk_bytes = _compress_chunk(payload)
        data = GUARDIAN_PAK_MAGIC + b'\x00\x01\x00\x00' + b'\x00\x0a' + sep + chunk_bytes
        chunks = list(iter_chunks(data))
        assert len(chunks) == 1
        assert chunks[0] == payload

    def test_single_chunk_roundtrip(self):
        raw = b'test data ' * 10
        pak = _build_pak(raw)
        chunks = list(iter_chunks(pak))
        assert raw in chunks

    def test_multiple_chunks_ordered(self):
        rec_a = _tape_label()
        rec_b = _file_catalog()
        pak = _build_pak(rec_a, rec_b)
        chunks = list(iter_chunks(pak))
        assert chunks[0] == rec_a
        assert chunks[1] == rec_b

    def test_corrupt_chunk_skipped(self):
        """A chunk whose compressed data is garbage is silently skipped."""
        good = _compress_chunk(b'good chunk')
        bad = struct.pack('>H', 8) + b'\xDE\xAD\xBE\xEF\x01\x02\x03\x04'
        data = (
            GUARDIAN_PAK_MAGIC + b'\x00\x01\x00\x00' + b'\x00\x0a'
            + good + bad + good
        )
        chunks = list(iter_chunks(data))
        assert len(chunks) == 2  # two good chunks; bad one skipped


# ------------------------------------------------------------------ #
# _parse_guardian_path
# ------------------------------------------------------------------ #

class TestParseGuardianPath:
    def test_standard_path(self):
        rec = _file_header('$DEV2', 'ZMQP001E', 'ALTMQFLS')
        vol, subvol, fname = _parse_guardian_path(rec)
        assert vol == '$DEV2'
        assert subvol == 'ZMQP001E'
        assert fname == 'ALTMQFLS'

    def test_short_names_no_padding(self):
        rec = _file_header('$VOL', 'SUB', 'FILE')
        vol, subvol, fname = _parse_guardian_path(rec)
        assert vol == '$VOL'
        assert subvol == 'SUB'
        assert fname == 'FILE'

    def test_missing_dollar_returns_empty(self):
        rec = bytes(358)  # all zeros, no $ at 0x2E
        vol, subvol, fname = _parse_guardian_path(rec)
        assert vol == '' and subvol == '' and fname == ''

    def test_fallback_dollar_scan(self):
        """If $ is not exactly at 0x2E, fallback scan finds it."""
        rec = bytearray(358)
        # Place valid path at offset 0x30 instead of 0x2E
        path = b'$ALT    SUBVOL  FNAME   '
        rec[0x30:0x30 + 24] = path
        vol, subvol, fname = _parse_guardian_path(bytes(rec))
        assert vol == '$ALT'


# ------------------------------------------------------------------ #
# iter_files
# ------------------------------------------------------------------ #

class TestIterFiles:
    def test_single_file_extracted(self):
        payload = b'\xDE\xAD\xBE\xEF' * 64
        pak = _build_pak(
            _tape_label(),
            _file_catalog(),
            _file_header('$VOL1', 'SUBVOL1', 'MYFILE'),
            _data_chunk(payload),
        )
        files = list(iter_files(pak))
        assert len(files) == 1
        f = files[0]
        assert f.volume == '$VOL1'
        assert f.subvolume == 'SUBVOL1'
        assert f.filename == 'MYFILE'
        assert f.data == payload
        assert f.path == '$VOL1.SUBVOL1.MYFILE'
        assert f.arch == 'mips32be'

    def test_two_files_in_sequence(self):
        pak = _build_pak(
            _tape_label(),
            _file_header('$VOL', 'SUBVOL', 'FILE1'),
            _data_chunk(b'data1'),
            _file_header('$VOL', 'SUBVOL', 'FILE2'),
            _data_chunk(b'data2'),
        )
        files = list(iter_files(pak))
        assert len(files) == 2
        assert files[0].filename == 'FILE1'
        assert files[0].data == b'data1'
        assert files[1].filename == 'FILE2'
        assert files[1].data == b'data2'

    def test_multi_chunk_data_concatenated(self):
        """Multiple data chunks for one file are concatenated."""
        pak = _build_pak(
            _file_header('$V', 'S', 'F'),
            _data_chunk(b'chunk_a'),
            _data_chunk(b'chunk_b'),
            _data_chunk(b'chunk_c'),
        )
        files = list(iter_files(pak))
        assert len(files) == 1
        assert files[0].data == b'chunk_achunk_bchunk_c'

    def test_tape_label_flushes_file(self):
        """A tape label mid-archive correctly flushes the current file."""
        pak = _build_pak(
            _file_header('$V', 'S', 'FIRST'),
            _data_chunk(b'first_data'),
            _tape_label(),
            _file_header('$V', 'S', 'SECOND'),
            _data_chunk(b'second_data'),
        )
        files = list(iter_files(pak))
        assert len(files) == 2
        assert files[0].filename == 'FIRST'
        assert files[1].filename == 'SECOND'

    def test_data_before_any_file_header_discarded(self):
        """Chunks before any file header record are silently discarded."""
        pak = _build_pak(
            _data_chunk(b'orphan_data'),
            _file_header('$V', 'S', 'REAL'),
            _data_chunk(b'real_data'),
        )
        files = list(iter_files(pak))
        assert len(files) == 1
        assert files[0].filename == 'REAL'
        assert files[0].data == b'real_data'

    def test_file_with_no_data_chunks_not_yielded(self):
        """A file header with zero data chunks yields nothing."""
        pak = _build_pak(
            _file_header('$V', 'S', 'EMPTY'),
            _file_header('$V', 'S', 'HASDATA'),
            _data_chunk(b'payload'),
        )
        files = list(iter_files(pak))
        assert len(files) == 1
        assert files[0].filename == 'HASDATA'

    def test_guardian_file_is_dataclass(self):
        pak = _build_pak(
            _file_header('$VOL', 'SUB', 'FILE'),
            _data_chunk(b'x' * 32),
        )
        f = next(iter_files(pak))
        assert isinstance(f, GuardianFile)

    def test_bad_magic_propagates(self):
        with pytest.raises(ValueError):
            list(iter_files(b'\x00' * 64))


# ------------------------------------------------------------------ #
# extract_to
# ------------------------------------------------------------------ #

class TestExtractTo:
    def test_creates_directory_hierarchy(self, tmp_path):
        payload = b'binary_content'
        pak = _build_pak(
            _file_header('$DEV2', 'ZMQP001E', 'ALTMQFLS'),
            _data_chunk(payload),
        )
        extracted = extract_to(pak, tmp_path)
        assert len(extracted) == 1
        expected = tmp_path / 'DEV2' / 'ZMQP001E' / 'ALTMQFLS'
        assert expected.exists()
        assert expected.read_bytes() == payload

    def test_strips_dollar_from_volume(self, tmp_path):
        pak = _build_pak(
            _file_header('$VOL', 'SUBVOL', 'FILE'),
            _data_chunk(b'data'),
        )
        extract_to(pak, tmp_path)
        # $VOL → VOL (dollar stripped for filesystem safety)
        assert (tmp_path / 'VOL' / 'SUBVOL' / 'FILE').exists()

    def test_multiple_files_multiple_dirs(self, tmp_path):
        pak = _build_pak(
            _file_header('$V', 'SUB', 'A'),
            _data_chunk(b'aaa'),
            _file_header('$V', 'SUB', 'B'),
            _data_chunk(b'bbb'),
        )
        extracted = extract_to(pak, tmp_path)
        assert len(extracted) == 2
        assert (tmp_path / 'V' / 'SUB' / 'A').read_bytes() == b'aaa'
        assert (tmp_path / 'V' / 'SUB' / 'B').read_bytes() == b'bbb'

    def test_returns_guardian_file_list(self, tmp_path):
        pak = _build_pak(
            _file_header('$V', 'S', 'F'),
            _data_chunk(b'x'),
        )
        result = extract_to(pak, tmp_path)
        assert isinstance(result, list)
        assert isinstance(result[0], GuardianFile)
