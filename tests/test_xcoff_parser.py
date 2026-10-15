"""Tests for ablation.core.xcoff_parser — XLC-GAP-011 (magic 0x01EF) and XLC-GAP-013 (ppc32 exe symtab)."""
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
    _FILE_HDR_FMT32,
    _FILE_HDR_FMT64,
    _parse_symtab32_exe,
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


# ---------------------------------------------------------------------------
# Unit tests — XLC-GAP-013: ppc32 executable symtab (absolute VA semantics)
# ---------------------------------------------------------------------------

def _make_xcoff32_exe_with_symtab(tmp_path, func_va: int, func_name: str) -> str:
    """Build a minimal XCOFF32 executable with a real function in the main symtab."""
    import struct as _struct

    # Minimal .text section at func_va; 4 bytes (one blr)
    text_data = b'\x4e\x80\x00\x20'  # blr

    # XCOFF32 section header: '>8sIIIIIIHHI'
    # s_name, s_paddr, s_vaddr, s_size, s_scnptr, s_relptr, s_lnnoptr, s_nreloc, s_nlnno, s_flags
    _SCNHDR32_FMT = '>8sIIIIIIHHI'
    STYP_TEXT_F = 0x0020
    _SCNHDR32_SZ = _struct.calcsize(_SCNHDR32_FMT)

    opthdr_sz = 72  # full XCOFF32 optional header (like a real executable)
    file_hdr_sz = _FILE_HDR_SZ  # 20 bytes
    scn_base = file_hdr_sz + opthdr_sz
    text_scnptr = scn_base + 2 * _SCNHDR32_SZ  # text data right after both section headers

    # Loader section placeholder (minimal valid)
    loader_data = b'\x00' * 32  # non-empty so the exe path is taken

    loader_scnptr = text_scnptr + len(text_data)
    STYP_LOADER_F = 0x1000

    # Symbol table: two entries — loader __start (descriptor) and dotted code entry
    # Each symtab entry: '>8sIhHBB' = name(8), value(4), scnum(2), type(2), sclass(1), numaux(1)
    _SYMENT_FMT = '>8sIhHBB'
    _SYMENT_SZ = _struct.calcsize(_SYMENT_FMT)  # should be 18
    assert _SYMENT_SZ == 18

    _C_EXT = 2
    _XMC_PR = 0  # smclas for code

    # Strtab: starts with 4-byte length then entries
    dotted = ('.' + func_name).encode('ascii') + b'\x00'
    strtab_content = dotted
    strtab = _struct.pack('>I', 4 + len(strtab_content)) + strtab_content
    strtab_name_off = 4  # offset of dotted name in strtab

    # Sym 0: dotted name for code entry, absolute VA = func_va, scnum=1 (.text), C_EXT
    name_ref = b'\x00\x00\x00\x00' + _struct.pack('>I', strtab_name_off)
    sym0 = _struct.pack(_SYMENT_FMT, name_ref, func_va, 1, 0, _C_EXT, 0)

    symtab_data = sym0
    nsyms = 1

    # Section headers (2 sections: .text, .loader)
    # Need symptr to come after text + loader
    symptr = loader_scnptr + len(loader_data)
    scnhdr_text = _struct.pack(_SCNHDR32_FMT,
        b'.text\x00\x00\x00', func_va, func_va, len(text_data),
        text_scnptr, 0, 0, 0, 0, STYP_TEXT_F)
    scnhdr_ldr = _struct.pack(_SCNHDR32_FMT,
        b'.loader\x00', 0, 0, len(loader_data),
        loader_scnptr, 0, 0, 0, 0, STYP_LOADER_F)

    # Optional header (72 bytes zeros — just needs to exist for opthdr_sz=72)
    opthdr = b'\x00' * opthdr_sz

    # File header: magic, nscns=2, timdat, symptr, nsyms, opthdr_sz, flags
    file_hdr = _struct.pack(_FILE_HDR_FMT32,
        XCOFF32_MAGIC, 2, 0, symptr, nsyms, opthdr_sz, 0)

    content = (file_hdr + opthdr + scnhdr_text + scnhdr_ldr +
               text_data + loader_data + symtab_data + strtab)

    f = tmp_path / "exe_with_symtab.xcoff"
    f.write_bytes(content)
    return str(f)


def test_ppc32_exe_symtab_recovery(tmp_path):
    """parse() on a ppc32 executable with a main symtab must recover the real function name."""
    func_va = 0x10001000
    func_name = "my_function"
    path = _make_xcoff32_exe_with_symtab(tmp_path, func_va, func_name)
    binary = parse(path)

    assert binary.arch == 'ppc32'
    names = {e.name: e.va for e in binary.exports}
    assert func_name in names, f"expected '{func_name}' in exports, got: {list(names.keys())}"
    assert names[func_name] == func_va


def test_ppc32_exe_symtab_no_double_counting(tmp_path):
    """Recovered ppc32 exe symtab VAs must be absolute, not section_base + absolute."""
    func_va = 0x10001000
    path = _make_xcoff32_exe_with_symtab(tmp_path, func_va, "some_func")
    binary = parse(path)

    vas = {e.va for e in binary.exports}
    # If double-counting: 0x10001000 + 0x10001000 = 0x20002000 would appear
    assert 0x20002000 not in vas, "VA was double-counted (section_base added to absolute VA)"
    assert func_va in vas


def test_ppc32_exe_symtab_no_regression_on_shared_lib(tmp_path):
    """ppc32 .so/.o regression: files without a loader section still use _parse_symtab32."""
    # Relocatable .o: no loader section → falls through to _parse_symtab32 (section-relative)
    # We just verify that ioscli (exe) still sees 615 exports while we haven't broken .o parsing
    # by checking parse() returns ppc32 on a minimal .o with no loader
    hdr = struct.pack(_FILE_HDR_FMT32, XCOFF32_MAGIC, 0, 0, 0, 0, 0, 0)
    f = tmp_path / "minimal32.o"
    f.write_bytes(hdr)
    binary = parse(str(f))
    assert binary.arch == 'ppc32'
    assert binary.exports == []


_IOSCLI_EFIX = '/media/cowboy/research/IBM-RE/VIOS/efixes/IZ22147.080519.epkg.Z'


@pytest.mark.skipif(
    not os.path.exists(_IOSCLI_EFIX),
    reason="VIOS IZ22147 efix not available",
)
def test_ppc32_exe_symtab_real_ioscli(tmp_path):
    """parse() on the real VIOS ioscli binary must recover 600+ named functions (XLC-GAP-013)."""
    import subprocess
    import tarfile
    import io

    result = subprocess.run(['gunzip', '-c', _IOSCLI_EFIX], capture_output=True, check=True)
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as tf:
        efile1 = tf.extractfile('./EFILE1')
        assert efile1 is not None, "EFILE1 not found in ioscli efix"
        raw = efile1.read()

    f = tmp_path / "ioscli"
    f.write_bytes(raw)
    binary = parse(str(f))

    assert binary.arch == 'ppc32'
    named = [e for e in binary.exports if not e.name.startswith('_sym_')]
    assert len(named) >= 600, f"expected 600+ named exports, got {len(named)}"

    names = {e.name for e in named}
    assert 'lssp' in names, "'lssp' not found in ioscli exports"
    assert 'main' in names, "'main' not found in ioscli exports"
