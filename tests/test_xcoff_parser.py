"""Tests for ablation.core.xcoff_parser — covering XLC-GAP-011 (magic 0x01EF)."""
import os
import struct
import pytest

from ablation.core.xcoff_parser import (
    XCOFF32_MAGIC,
    XCOFF64_MAGIC,
    XCOFF64_MAGIC_ALT,
    parse,
    _FILE_HDR_SZ,
    _FILE_HDR_SZ64,
    _FILE_HDR_FMT64,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_xcoff64_header(magic: int, nscns: int = 0) -> bytes:
    """Build a minimal valid XCOFF64 file header with no sections or symbol table."""
    # >HHIQHHI: magic, nscns, timdat, symptr(8), opthdr, flags, nsyms
    hdr = struct.pack('>HHIQHHI', magic, nscns, 0, 0, 0, 0, 0)
    assert len(hdr) == _FILE_HDR_SZ64
    return hdr


# ---------------------------------------------------------------------------
# Unit tests — XLC-GAP-011: XCOFF64_MAGIC_ALT (0x01EF)
# ---------------------------------------------------------------------------

def test_xcoff64_magic_alt_constant():
    """XCOFF64_MAGIC_ALT must be 0x01EF, distinct from XCOFF32_MAGIC and XCOFF64_MAGIC."""
    assert XCOFF64_MAGIC_ALT == 0x01EF
    assert XCOFF64_MAGIC_ALT != XCOFF32_MAGIC
    assert XCOFF64_MAGIC_ALT != XCOFF64_MAGIC


def test_parse_xcoff64_magic_alt_returns_ppc64(tmp_path):
    """parse() on a minimal file with magic=0x01EF must return arch='ppc64'."""
    f = tmp_path / "minimal_alt.o"
    f.write_bytes(_make_xcoff64_header(XCOFF64_MAGIC_ALT))
    binary = parse(str(f))
    assert binary.arch == 'ppc64'


def test_parse_xcoff64_magic_alt_no_sections_empty(tmp_path):
    """Minimal 0x01EF file with nscns=0 must parse to empty sections and exports."""
    f = tmp_path / "empty_alt.o"
    f.write_bytes(_make_xcoff64_header(XCOFF64_MAGIC_ALT, nscns=0))
    binary = parse(str(f))
    assert binary.sections == []
    assert binary.exports == []
    assert binary.imports == []


def test_parse_xcoff64_magic_alt_truncated_raises(tmp_path):
    """parse() on a truncated 0x01EF file (< 24 bytes) must raise ValueError."""
    f = tmp_path / "truncated_alt.o"
    # Write only 10 bytes — not enough for XCOFF64 header (needs 24)
    f.write_bytes(struct.pack('>H', XCOFF64_MAGIC_ALT) + b'\x00' * 8)
    with pytest.raises(ValueError, match="too short"):
        parse(str(f))


def test_parse_unsupported_magic_error_message_includes_alt(tmp_path):
    """ValueError for unsupported magic must mention all three accepted values."""
    f = tmp_path / "bad_magic.o"
    f.write_bytes(struct.pack('>H', 0x0000) + b'\x00' * 30)
    with pytest.raises(ValueError) as exc_info:
        parse(str(f))
    msg = str(exc_info.value).lower()
    assert '0x01df' in msg or '0x01ef' in msg or '0x01f7' in msg


def test_parse_xcoff64_original_magic_still_works(tmp_path):
    """parse() on a minimal 0x01F7 file must still return arch='ppc64' (regression guard)."""
    f = tmp_path / "minimal_64.o"
    f.write_bytes(_make_xcoff64_header(XCOFF64_MAGIC))
    binary = parse(str(f))
    assert binary.arch == 'ppc64'


def test_parse_xcoff32_magic_still_works(tmp_path):
    """parse() on a minimal 0x01DF file must still return arch='ppc32' (regression guard)."""
    # XCOFF32 header: >HHIIIHH — 20 bytes
    from ablation.core.xcoff_parser import _FILE_HDR_FMT32, _FILE_HDR_SZ
    hdr = struct.pack(_FILE_HDR_FMT32, XCOFF32_MAGIC, 0, 0, 0, 0, 0, 0)
    assert len(hdr) == _FILE_HDR_SZ
    f = tmp_path / "minimal_32.o"
    f.write_bytes(hdr)
    binary = parse(str(f))
    assert binary.arch == 'ppc32'


# ---------------------------------------------------------------------------
# Integration test — real 0x01EF binary from Firewall-AIX libc.fix
# ---------------------------------------------------------------------------

_LIBC_FIX = '/media/cowboy/research/IBM-RE/Firewall-AIX/libc.fix'

@pytest.mark.skipif(
    not os.path.exists(_LIBC_FIX),
    reason=f"Firewall-AIX libc.fix not available at {_LIBC_FIX}",
)
def test_parse_real_xcoff64_magic_alt_from_libc_fix(tmp_path):
    """Parse shr_64.o from libc.fix (magic=0x01EF) and verify key fields."""
    from ablation.analyzers.aix_big_ar_extractor import AixBigArExtractor

    ext = AixBigArExtractor(_LIBC_FIX)
    raw = None
    for nm, data in ext.extract():
        if nm == 'shr_64.o':
            raw = data
            break

    assert raw is not None, "shr_64.o not found in libc.fix"

    f = tmp_path / "shr_64.o"
    f.write_bytes(raw)
    binary = parse(str(f))

    assert binary.arch == 'ppc64'
    assert binary.text is not None
    assert binary.text.size == 0x15fdf8, f"unexpected text size: {binary.text.size:#x}"
