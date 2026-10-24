"""Tests for AixBffExtractor._scan_blob and compressed-entry path.

These tests cover the changes introduced for BFF-DECOMP-GAP-001:
  - AixBffExtractor.extract() now attempts AixInstallpDecompressor on entries
    with first byte in {0x0e, 0x0f, 0x10, 0x11}.
  - Decompressed output is validated: only XCOFF-magic output is yielded.
  - Invalid decompression output (multi-cycle BWT, garbage bytes) is silently
    discarded — not propagated to callers.
  - _scan_blob() handles both direct XCOFF blobs and blobs containing embedded
    XCOFF (e.g. .a library archives).
"""
from __future__ import annotations

import struct
import pytest
from pathlib import Path
from unittest.mock import patch

from ablation.analyzers.aix_bff_extractor import AixBffExtractor, XCOFF32_MAGIC

# ---------------------------------------------------------------------------
# Synthetic data helpers
# ---------------------------------------------------------------------------

def _make_minimal_xcoff32(text_size: int = 64) -> bytes:
    """Build a minimal valid XCOFF32 binary with one .text section.

    Layout:
      FILHDR    20 bytes  (magic, nscns=1, opthdr=0)
      SCNHDR    40 bytes  (.text section header, flags=0x20=STYP_TEXT)
      .text     text_size bytes (fill 0xAA)
    """
    text_offset = 20 + 40  # FILHDR + 1 SCNHDR
    total = text_offset + text_size

    # FILHDR: magic(2)+nscns(2)+timdat(4)+symptr(4)+nsyms(4)+opthdr(2)+flags(2) = 20 bytes
    filhdr = (
        struct.pack('>H', XCOFF32_MAGIC) +
        struct.pack('>H', 1) +              # nscns = 1
        struct.pack('>I', 0) +              # timdat
        struct.pack('>I', 0) +              # symptr
        struct.pack('>I', 0) +              # nsyms
        struct.pack('>H', 0) +              # opthdr
        struct.pack('>H', 0)               # flags
    )
    assert len(filhdr) == 20

    # SCNHDR (40 bytes):
    # s_name(8) + s_paddr(4) + s_vaddr(4) + s_size(4) + s_scnptr(4) +
    # s_relptr(4) + s_lnnoptr(4) + s_nreloc(2) + s_nlnno(2) + s_flags(4) = 40
    scnhdr = (
        b'.text\x00\x00\x00' +                  # s_name
        struct.pack('>I', 0x10000100) +         # s_paddr
        struct.pack('>I', 0x10000100) +         # s_vaddr
        struct.pack('>I', text_size) +          # s_size
        struct.pack('>I', text_offset) +        # s_scnptr
        struct.pack('>I', 0) +                  # s_relptr
        struct.pack('>I', 0) +                  # s_lnnoptr
        struct.pack('>H', 0) +                  # s_nreloc
        struct.pack('>H', 0) +                  # s_nlnno
        struct.pack('>I', 0x00000020)           # s_flags (STYP_TEXT)
    )
    assert len(scnhdr) == 40

    text_data = b'\xaa' * text_size
    return filhdr + scnhdr + text_data


def _make_bff_entry(name: str, data: bytes, mode: int = 0o100644) -> bytes:
    """Build one BFF entry block (ext_stat + size + zero + name + stat + data)."""
    # Extended stat: 56 bytes (all zeros except mtime at offset 28)
    ext_stat = b'\x00' * 56

    # File size LE (4 bytes) + zero field (4 bytes)
    size_field = struct.pack('<II', len(data), 0)

    # Name: null-terminated, padded to 8-byte boundary
    raw_name = name.encode('utf-8') + b'\x00'
    pad = (8 - len(raw_name) % 8) % 8
    name_block = raw_name + b'\x00' * pad

    # Stat summary: 40 bytes (uid=0 gid=0 at fixed offsets, mode at offset 12)
    stat_blk = bytearray(40)
    struct.pack_into('<I', stat_blk, 12, mode)

    # Data: padded to 8-byte boundary
    data_pad = (8 - len(data) % 8) % 8 if len(data) % 8 else 0
    data_block = data + b'\x00' * data_pad

    return ext_stat + size_field + name_block + bytes(stat_blk) + data_block


def _make_bff_dir_entry(name: str) -> bytes:
    """Build a directory entry (size=0)."""
    return _make_bff_entry(name, b'', mode=0o040755)


def _make_bff(entries: list[tuple[str, bytes | None]]) -> bytes:
    """Build a complete BFF archive.

    entries: list of (name, data_or_None); None → directory entry.
    """
    vol_hdr = b'\x09\x00' + b'\x00' * 70  # 72-byte volume header, magic at [0:2]
    body = b''
    for name, data in entries:
        if data is None:
            body += _make_bff_dir_entry(name)
        else:
            body += _make_bff_entry(name, data)
    return vol_hdr + body


# ---------------------------------------------------------------------------
# Tests — _scan_blob
# ---------------------------------------------------------------------------

class TestScanBlob:
    """Unit tests for AixBffExtractor._scan_blob()."""

    def setup_method(self):
        # _scan_blob uses self._min_size; use min_size=20 so small test binaries pass.
        self.ext = AixBffExtractor(b'\x09\x00' + b'\x00' * 100, min_size=20)

    def test_scan_blob_direct_xcoff32(self):
        """A blob that IS a valid XCOFF32 binary is yielded directly."""
        xcoff = _make_minimal_xcoff32(64)  # 84 bytes — above min_size=20
        results = list(self.ext._scan_blob('myprog', xcoff))
        assert len(results) == 1
        name, data = results[0]
        assert name == 'myprog'
        assert data == xcoff

    def test_scan_blob_blob_too_small(self):
        """A blob smaller than min_size is silently dropped."""
        small_ext = AixBffExtractor(b'\x09\x00' + b'\x00' * 100, min_size=500)
        xcoff = _make_minimal_xcoff32(64)  # 84 bytes — below min_size=500
        results = list(small_ext._scan_blob('small', xcoff))
        assert results == []

    def test_scan_blob_blob_not_xcoff_no_xcoff_inside(self):
        """A blob that is not XCOFF and contains no XCOFF magic yields nothing."""
        blob = b'\x00' * 512
        results = list(self.ext._scan_blob('blob', blob))
        assert results == []

    def test_scan_blob_embedded_xcoff(self):
        """A blob containing XCOFF magic at a non-zero offset yields that XCOFF."""
        xcoff = _make_minimal_xcoff32(128)
        # Prepend junk bytes (not an XCOFF header themselves)
        junk = b'\xfe\xfe' * 32  # 64 bytes, not XCOFF magic (0xfefe ≠ 0x01df)
        blob = junk + xcoff
        # Align blob length to 4 bytes
        results = list(self.ext._scan_blob('libfoo', blob))
        # We should find the embedded XCOFF
        assert len(results) >= 1
        _, data = results[0]
        assert data[:2] == struct.pack('>H', XCOFF32_MAGIC)


# ---------------------------------------------------------------------------
# Tests — extract() uncompressed path (regression)
# ---------------------------------------------------------------------------

class TestExtractUncompressed:
    """Verify existing uncompressed XCOFF extraction still works after the change."""

    def test_uncompressed_xcoff_in_bff_is_yielded(self):
        """An uncompressed XCOFF entry is yielded by the structured path."""
        xcoff = _make_minimal_xcoff32(256)
        bff_data = _make_bff([
            ('./usr/bin/myprog', xcoff),
        ])
        extractor = AixBffExtractor(bff_data, min_size=20)
        results = list(extractor.extract())
        assert len(results) == 1
        name, data = results[0]
        assert name == 'myprog'
        assert data[:2] == struct.pack('>H', XCOFF32_MAGIC)

    def test_directory_entries_are_skipped(self):
        """Directory entries in the BFF do not cause errors or spurious yields."""
        xcoff = _make_minimal_xcoff32(256)
        bff_data = _make_bff([
            ('./usr', None),
            ('./usr/bin', None),
            ('./usr/bin/myprog', xcoff),
        ])
        extractor = AixBffExtractor(bff_data, min_size=20)
        results = list(extractor.extract())
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Tests — extract() compressed-entry path
# ---------------------------------------------------------------------------

class TestExtractCompressed:
    """Tests for the new compressed-entry decompression path in extract()."""

    def _make_bff_with_compressed_entry(
        self, entry_data: bytes, entry_name: str = './usr/bin/daemon'
    ) -> bytes:
        """Build a BFF where the named entry has compressed-looking first byte."""
        return _make_bff([(entry_name, entry_data)])

    def test_compressed_entry_that_decompresses_to_xcoff_is_yielded(self, tmp_path):
        """When AixInstallpDecompressor returns valid XCOFF, extract() yields it."""
        from ablation.analyzers.aix_bff_extractor import _DECOMP_OK
        if not _DECOMP_OK:
            pytest.skip('AixInstallpDecompressor not available')

        xcoff = _make_minimal_xcoff32(512)
        # Build a fake 'compressed' entry: first byte 0x0e, then padding.
        # We mock the decompressor to return our XCOFF bytes.
        fake_compressed = b'\x0e' + b'\x00' * 271 + b'\xaa' * 100  # >= 272 bytes

        bff_data = _make_bff([('./usr/bin/daemon', fake_compressed)])
        extractor = AixBffExtractor(bff_data, min_size=20)

        with patch(
            'ablation.analyzers.aix_bff_extractor._AixDecompressor'
        ) as MockDecomp:
            instance = MockDecomp.return_value
            instance.decompress.return_value = xcoff
            results = list(extractor.extract())

        assert len(results) == 1
        name, data = results[0]
        assert name == 'daemon'
        assert data[:2] == struct.pack('>H', XCOFF32_MAGIC)

    def test_compressed_entry_that_decompresses_to_garbage_is_silently_dropped(self):
        """When decompression yields non-XCOFF bytes, extract() yields nothing."""
        from ablation.analyzers.aix_bff_extractor import _DECOMP_OK
        if not _DECOMP_OK:
            pytest.skip('AixInstallpDecompressor not available')

        garbage = b'\x80\x80' + b'\x00' * 500  # not XCOFF magic
        fake_compressed = b'\x0e' + b'\x00' * 271 + b'\xaa' * 100

        bff_data = _make_bff([('./usr/bin/daemon', fake_compressed)])
        extractor = AixBffExtractor(bff_data, min_size=20)

        with patch(
            'ablation.analyzers.aix_bff_extractor._AixDecompressor'
        ) as MockDecomp:
            instance = MockDecomp.return_value
            instance.decompress.return_value = garbage
            results = list(extractor.extract())

        assert results == []

    def test_compressed_entry_where_decompressor_raises_is_skipped(self):
        """When AixInstallpDecompressor raises, that entry is silently skipped."""
        from ablation.analyzers.aix_bff_extractor import _DECOMP_OK
        if not _DECOMP_OK:
            pytest.skip('AixInstallpDecompressor not available')

        fake_compressed = b'\x0e' + b'\x00' * 271 + b'\xaa' * 100
        bff_data = _make_bff([('./usr/bin/daemon', fake_compressed)])
        extractor = AixBffExtractor(bff_data, min_size=20)

        with patch(
            'ablation.analyzers.aix_bff_extractor._AixDecompressor'
        ) as MockDecomp:
            MockDecomp.side_effect = ValueError('decompression failed')
            results = list(extractor.extract())

        assert results == []

    def test_non_compressed_first_byte_entry_is_not_decompressed(self):
        """Entries with first byte not in 0x0e-0x11 are not passed to decompressor."""
        from ablation.analyzers.aix_bff_extractor import _DECOMP_OK
        if not _DECOMP_OK:
            pytest.skip('AixInstallpDecompressor not available')

        # First byte 0x23 = '#' — a script file, not compressed
        script = b'#!/bin/sh\necho hello\n' + b'\x00' * 300
        bff_data = _make_bff([('./usr/bin/script.sh', script)])
        extractor = AixBffExtractor(bff_data, min_size=20)

        with patch(
            'ablation.analyzers.aix_bff_extractor._AixDecompressor'
        ) as MockDecomp:
            results = list(extractor.extract())
            MockDecomp.assert_not_called()

        assert results == []

    @pytest.mark.skipif(
        not Path('/tmp/aix433_tcp/rsct.basic.rte.1.1.1.3.bff').exists(),
        reason='RSCT BFF not available in /tmp/aix433_tcp/'
    )
    def test_rsct_bff_compressed_entries_do_not_crash(self):
        """RSCT BFF processing: compressed entries may yield 0 results but must not crash."""
        bff_data = Path('/tmp/aix433_tcp/rsct.basic.rte.1.1.1.3.bff').read_bytes()
        extractor = AixBffExtractor(bff_data)
        # This exercises the full pipeline including decompression; may yield 0
        # valid XCOFF32 binaries due to multi-cycle BWT limitation, but must not
        # raise an exception.
        results = list(extractor.extract())
        assert isinstance(results, list)
        # All yielded items must have valid XCOFF32 magic
        for _name, data in results:
            assert data[:2] == struct.pack('>H', XCOFF32_MAGIC), \
                f"Non-XCOFF32 data yielded: magic={data[:2].hex()}"
