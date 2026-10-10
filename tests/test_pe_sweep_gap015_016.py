"""
Tests for GAP-015 (FirmwareAuthBypassProfile) and GAP-016 (BorlandVCLStringIndex)
additions to sweeps/pe_sweep.py.

Covers:
  _scan_section_strings:
    - normal .rdata with strings ≥ 5 chars
    - virtual-only section (offset=0) skipped — no MZ-header scan
    - truncated file (offset+size > len(data)) — silent, no crash
    - section absent
    - string of exactly 4 chars excluded; exactly 5 chars included
    - non-ASCII byte splitting a run (only null-terminated runs accepted)
    - section size 0

  _build_rdata_strings:
    - non-empty .rdata → returns .rdata result, no fallback
    - empty .rdata, non-empty .data → fallback triggered, diagnostic printed
    - both empty → empty dict returned, no crash, no diagnostic

  _check_firmware_auth_bypass:
    - firmware DLL in imports + no signing IAT → FIRMWARE_AUTH_BYPASS
    - signing import present alongside firmware DLL → None
    - named DevIAP* in IAT + no signing → FIRMWARE_AUTH_BYPASS
    - no firmware → None
    - pe.imports property raises → no crash, diagnostic printed, returns None
    - lib.name = None mid-loop → inner try/continue; remaining entries collected
    - mixed-case firmware IAT entry → matched after lowercasing
    - large IAT (1000 entries), no firmware → None, fast
    - both firmware DLL and named firmware import → both evidence lines
    - signing import in non-standard uppercase → still detected (case-insensitive)
    - empty IAT, no imports → None
"""
import types

import pytest

from sweeps.pe_sweep import (
    FirmwareAuthBypassFinding,
    _build_rdata_strings,
    _check_firmware_auth_bypass,
    _scan_section_strings,
)


# ── stub helpers ──────────────────────────────────────────────────────────────

def _make_section(name: str, offset: int, size: int, virtual_address: int):
    s = types.SimpleNamespace()
    s.name = name
    s.offset = offset
    s.size = size
    s.virtual_address = virtual_address
    return s


def _make_pe(imagebase: int, sections=None, imports=None):
    pe = types.SimpleNamespace()
    pe.optional_header = types.SimpleNamespace()
    pe.optional_header.imagebase = imagebase
    pe.sections = sections or []
    pe.imports = imports or []
    return pe


def _make_lib(name):
    return types.SimpleNamespace(name=name)


def _data_with_section(offset: int, chunk: bytes, total: int = 0) -> bytes:
    size = max(total, offset + len(chunk))
    buf = bytearray(size)
    buf[offset: offset + len(chunk)] = chunk
    return bytes(buf)


# ── _scan_section_strings ─────────────────────────────────────────────────────

def test_scan_normal_strings():
    imagebase = 0x10000
    rva = 0x1000
    offset = 100
    chunk = b"Hello\x00World\x00FooBar\x00Hi\x00"
    data = _data_with_section(offset, chunk)
    sec = _make_section(".rdata", offset, len(chunk), rva)
    pe = _make_pe(imagebase, [sec])

    result = _scan_section_strings(pe, data, ".rdata")

    abs_base = imagebase + rva
    assert result[abs_base + 0] == "Hello"
    assert result[abs_base + 6] == "World"
    assert result[abs_base + 12] == "FooBar"
    assert len(result) == 3   # "Hi" (2 chars) excluded


def test_scan_virtual_only_section_skipped():
    """Section with offset=0 must not scan the MZ/PE header bytes."""
    imagebase = 0x10000
    sec = _make_section(".rdata", 0, 50, 0x1000)
    data = b"Hello\x00World\x00" + b"\x00" * 50
    pe = _make_pe(imagebase, [sec])

    result = _scan_section_strings(pe, data, ".rdata")

    assert result == {}


def test_scan_truncated_file_no_crash():
    """offset+size > len(data): slice is silently shorter, no exception."""
    imagebase = 0x10000
    offset = 10
    chunk = b"LongStr\x00"  # 7 chars
    data = _data_with_section(offset, chunk)
    sec = _make_section(".rdata", offset, 1000, 0x1000)  # claims 1000 bytes
    pe = _make_pe(imagebase, [sec])

    result = _scan_section_strings(pe, data, ".rdata")

    assert "LongStr" in result.values()


def test_scan_section_absent():
    pe = _make_pe(0x10000, [])
    result = _scan_section_strings(pe, b"Hello\x00World\x00", ".rdata")
    assert result == {}


def test_scan_four_char_excluded():
    imagebase = 0x10000
    offset = 10
    chunk = b"Four\x00ABCDE\x00"
    data = _data_with_section(offset, chunk)
    sec = _make_section(".rdata", offset, len(chunk), 0x1000)
    pe = _make_pe(imagebase, [sec])

    result = _scan_section_strings(pe, data, ".rdata")

    values = list(result.values())
    assert "ABCDE" in values
    assert "Four" not in values


def test_scan_five_char_included():
    imagebase = 0x10000
    offset = 10
    chunk = b"ABCDE\x00"
    data = _data_with_section(offset, chunk)
    sec = _make_section(".rdata", offset, len(chunk), 0x1000)
    pe = _make_pe(imagebase, [sec])

    result = _scan_section_strings(pe, data, ".rdata")

    assert len(result) == 1
    assert "ABCDE" in result.values()


def test_scan_non_ascii_split():
    """Run ending with non-ASCII (not null) is not null-terminated → excluded."""
    imagebase = 0x10000
    offset = 10
    # "Hello" followed by 0x80 (non-ASCII, non-null), then "World\0"
    chunk = b"Hello\x80World\x00"
    data = _data_with_section(offset, chunk)
    sec = _make_section(".rdata", offset, len(chunk), 0x1000)
    pe = _make_pe(imagebase, [sec])

    result = _scan_section_strings(pe, data, ".rdata")

    values = list(result.values())
    assert "World" in values
    assert "Hello" not in values


def test_scan_zero_size_section():
    imagebase = 0x10000
    sec = _make_section(".rdata", 10, 0, 0x1000)
    data = b"\x00" * 50
    pe = _make_pe(imagebase, [sec])

    result = _scan_section_strings(pe, data, ".rdata")

    assert result == {}


def test_scan_va_computation():
    """Returned abs VAs = imagebase + section.virtual_address + string_offset."""
    imagebase = 0x400000
    rva = 0x5000
    offset = 200
    chunk = b"\x00\x00Hello\x00"  # string starts at index 2 within chunk
    data = _data_with_section(offset, chunk)
    sec = _make_section(".rdata", offset, len(chunk), rva)
    pe = _make_pe(imagebase, [sec])

    result = _scan_section_strings(pe, data, ".rdata")

    expected_va = imagebase + rva + 2
    assert expected_va in result
    assert result[expected_va] == "Hello"


# ── _build_rdata_strings ──────────────────────────────────────────────────────

def test_build_uses_rdata_when_non_empty(capsys):
    imagebase = 0x10000
    rdata_off = 10
    rdata_chunk = b"FromRdata\x00"
    data_off = 50
    data_chunk = b"FromData\x00"

    buf = bytearray(data_off + len(data_chunk))
    buf[rdata_off: rdata_off + len(rdata_chunk)] = rdata_chunk
    buf[data_off: data_off + len(data_chunk)] = data_chunk
    data = bytes(buf)

    rdata_sec = _make_section(".rdata", rdata_off, len(rdata_chunk), 0x1000)
    data_sec = _make_section(".data", data_off, len(data_chunk), 0x2000)
    pe = _make_pe(imagebase, [rdata_sec, data_sec])

    result = _build_rdata_strings(pe, data)
    out = capsys.readouterr().out

    assert "FromRdata" in result.values()
    assert "FromData" not in result.values()
    assert "falling back" not in out


def test_build_falls_back_to_data_when_rdata_empty(capsys):
    imagebase = 0x10000
    rdata_off = 10
    rdata_chunk = b"Hi\x00Lo\x00"        # 2-char strings, all below 5-char minimum
    data_off = 30
    data_chunk = b"FromData\x00"          # 8 chars

    buf = bytearray(data_off + len(data_chunk))
    buf[rdata_off: rdata_off + len(rdata_chunk)] = rdata_chunk
    buf[data_off: data_off + len(data_chunk)] = data_chunk
    data = bytes(buf)

    rdata_sec = _make_section(".rdata", rdata_off, len(rdata_chunk), 0x1000)
    data_sec = _make_section(".data", data_off, len(data_chunk), 0x2000)
    pe = _make_pe(imagebase, [rdata_sec, data_sec])

    result = _build_rdata_strings(pe, data)
    out = capsys.readouterr().out

    assert "FromData" in result.values()
    assert "falling back" in out


def test_build_both_empty_no_crash(capsys):
    imagebase = 0x10000
    rdata_off = 10
    rdata_chunk = b"Hi\x00Lo\x00"
    data_off = 30
    data_chunk = b"AB\x00CD\x00"

    buf = bytearray(data_off + len(data_chunk))
    buf[rdata_off: rdata_off + len(rdata_chunk)] = rdata_chunk
    buf[data_off: data_off + len(data_chunk)] = data_chunk
    data = bytes(buf)

    rdata_sec = _make_section(".rdata", rdata_off, len(rdata_chunk), 0x1000)
    data_sec = _make_section(".data", data_off, len(data_chunk), 0x2000)
    pe = _make_pe(imagebase, [rdata_sec, data_sec])

    result = _build_rdata_strings(pe, data)
    out = capsys.readouterr().out

    assert result == {}
    assert "falling back" not in out


# ── _check_firmware_auth_bypass ───────────────────────────────────────────────

def test_fwab_firmware_dll_no_signing():
    pe = _make_pe(0x10000, imports=[_make_lib("hiddapi.dll"), _make_lib("kernel32.dll")])
    iat = {0x1000: "kernel32.dll!CreateFileA"}

    result = _check_firmware_auth_bypass(pe, iat)

    assert result is not None
    assert result["id"] == "FIRMWARE_AUTH_BYPASS"
    assert result["severity"] == "HIGH"
    assert any("hiddapi.dll" in ev for ev in result["evidence"])


def test_fwab_signing_present_suppresses_finding():
    pe = _make_pe(0x10000, imports=[_make_lib("hiddapi.dll")])
    iat = {
        0x1000: "wintrust.dll!WinVerifyTrust",
        0x1004: "kernel32.dll!CreateFileA",
    }

    result = _check_firmware_auth_bypass(pe, iat)

    assert result is None


def test_fwab_named_iat_entry_no_signing():
    pe = _make_pe(0x10000, imports=[_make_lib("kernel32.dll")])
    iat = {
        0x1000: "kernel32.dll!CreateFileA",
        0x1004: "hiddapi.dll!DevIAPFlashErase",
    }

    result = _check_firmware_auth_bypass(pe, iat)

    assert result is not None
    assert any("DevIAPFlashErase" in ev for ev in result["evidence"])


def test_fwab_no_firmware_returns_none():
    pe = _make_pe(0x10000, imports=[_make_lib("kernel32.dll"), _make_lib("user32.dll")])
    iat = {
        0x1000: "kernel32.dll!CreateFileA",
        0x1004: "user32.dll!MessageBoxA",
    }

    result = _check_firmware_auth_bypass(pe, iat)

    assert result is None


def test_fwab_imports_property_raises_no_crash(capsys):
    class BadPE:
        @property
        def imports(self):
            raise RuntimeError("lief internal failure")

    result = _check_firmware_auth_bypass(BadPE(), {})

    assert result is None
    assert "pe.imports failed" in capsys.readouterr().out


def test_fwab_none_name_mid_loop_continues():
    """lib.name=None on entry 3; hiddapi.dll on entry 4 must still be collected."""
    pe = types.SimpleNamespace()
    pe.imports = [
        _make_lib("kernel32.dll"),
        _make_lib("user32.dll"),
        _make_lib(None),            # entry 3: triggers inner try/continue
        _make_lib("hiddapi.dll"),   # entry 4: must still be collected
        _make_lib("ntdll.dll"),
    ]
    iat = {}

    result = _check_firmware_auth_bypass(pe, iat)

    assert result is not None
    assert result["id"] == "FIRMWARE_AUTH_BYPASS"


def test_fwab_mixed_case_iat_entry():
    """DevIAPflasherase (lowercase middle) must match via lowercasing."""
    pe = _make_pe(0x10000, imports=[_make_lib("kernel32.dll")])
    iat = {0x1000: "hiddapi.dll!DevIAPflasherase"}

    result = _check_firmware_auth_bypass(pe, iat)

    assert result is not None


def test_fwab_large_iat_no_firmware():
    pe = _make_pe(0x10000, imports=[_make_lib("kernel32.dll")])
    iat = {i: f"kernel32.dll!Func{i:04d}" for i in range(1000)}

    result = _check_firmware_auth_bypass(pe, iat)

    assert result is None


def test_fwab_both_dll_and_named_evidence():
    """When both a firmware DLL and a named IAT entry match, both appear in evidence."""
    pe = _make_pe(0x10000, imports=[_make_lib("hiddapi.dll"), _make_lib("kernel32.dll")])
    iat = {
        0x1000: "hiddapi.dll!DevIAPFlashErase",
        0x1004: "kernel32.dll!CreateFileA",
    }

    result = _check_firmware_auth_bypass(pe, iat)

    assert result is not None
    evidence_text = " | ".join(result["evidence"])
    assert "firmware DLL imported" in evidence_text
    assert "named firmware imports" in evidence_text


def test_fwab_signing_detection_is_case_insensitive():
    """CRYPTHASHDATA (all caps) must suppress the finding."""
    pe = _make_pe(0x10000, imports=[_make_lib("hiddapi.dll")])
    iat = {0x1000: "crypt32.dll!CRYPTHASHDATA"}

    result = _check_firmware_auth_bypass(pe, iat)

    assert result is None


def test_fwab_empty_iat_empty_imports():
    pe = _make_pe(0x10000, imports=[])
    result = _check_firmware_auth_bypass(pe, {})
    assert result is None


def test_fwab_return_is_typed_dict():
    """Return value must be a FirmwareAuthBypassFinding (TypedDict) instance."""
    pe = _make_pe(0x10000, imports=[_make_lib("hiddapi.dll")])
    iat = {}

    result = _check_firmware_auth_bypass(pe, iat)

    assert result is not None
    assert isinstance(result, dict)
    assert set(result.keys()) >= {"id", "title", "severity", "evidence", "note"}
    assert isinstance(result["evidence"], list)
