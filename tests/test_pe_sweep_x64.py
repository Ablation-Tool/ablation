"""
Tests for the AMD64 path in sweeps/pe_sweep.py.

Covers:
  - _find_prologue_starts_x86_64: all three prologue patterns, deduplication, bounds
  - _resolve_call_target_x64: RIP+, RIP-, direct, unresolvable
  - _LEA_RIP_RE / _LEA_RIP_NEG_RE: string VA computation logic
"""
import pytest
from sweeps.pe_sweep import (
    _find_prologue_starts_x86_64,
    _resolve_call_target_x64,
    _LEA_RIP_RE,
    _LEA_RIP_NEG_RE,
    _IAT_RIP_RE,
    _IAT_RIP_NEG_RE,
)


# ── _find_prologue_starts_x86_64 ──────────────────────────────────────────────

def test_prologue_push_rbp_mov_rbp_rsp():
    """55 48 89 E5 — GCC/Clang frame-pointer prologue."""
    data = bytes([0x00, 0x55, 0x48, 0x89, 0xE5, 0x00, 0x00, 0x00])
    hits = _find_prologue_starts_x86_64(data, 0, len(data))
    assert 1 in hits


def test_prologue_sub_rsp_imm8():
    """48 83 EC XX — MSVC typical stack allocation."""
    data = bytes([0x00, 0x48, 0x83, 0xEC, 0x28, 0x00, 0x00, 0x00])
    hits = _find_prologue_starts_x86_64(data, 0, len(data))
    assert 1 in hits


def test_prologue_mov_rsp_rbx():
    """48 89 5C 24 XX — MSVC callee-save preamble."""
    data = bytes([0x00, 0x48, 0x89, 0x5C, 0x24, 0x10, 0x00, 0x00])
    hits = _find_prologue_starts_x86_64(data, 0, len(data))
    assert 1 in hits


def test_prologue_all_three_patterns():
    """All three patterns in a single buffer."""
    data = bytes([
        0x00, 0x00,
        0x55, 0x48, 0x89, 0xE5,          # offset 2
        0x00, 0x00,
        0x48, 0x83, 0xEC, 0x28,          # offset 8
        0x00, 0x00,
        0x48, 0x89, 0x5C, 0x24, 0x10,   # offset 14
        0x00, 0x00,
    ])
    hits = _find_prologue_starts_x86_64(data, 0, len(data))
    assert hits == [2, 8, 14]


def test_prologue_no_duplicates():
    """Two different patterns at adjacent offsets — no duplicate entries."""
    # 48 83 EC starts at offset 0; also check 48 89 5C 24 at offset 0
    # These are distinct patterns so both can't match at offset 0 simultaneously.
    # Verify the deduplication via the set-based implementation.
    data = bytes([0x48, 0x83, 0xEC, 0x28, 0x00, 0x00, 0x00, 0x00])
    hits = _find_prologue_starts_x86_64(data, 0, len(data))
    assert hits.count(0) == 1


def test_prologue_respects_start_offset():
    """Prologue before start_offset is not returned."""
    data = bytes([0x55, 0x48, 0x89, 0xE5, 0x00, 0x55, 0x48, 0x89, 0xE5, 0x00])
    hits = _find_prologue_starts_x86_64(data, 4, len(data))
    assert 0 not in hits
    assert 5 in hits


def test_prologue_respects_end_offset():
    """Prologue at or past end_offset is not returned."""
    data = bytes([0x00, 0x55, 0x48, 0x89, 0xE5, 0x00, 0x00, 0x00])
    hits = _find_prologue_starts_x86_64(data, 0, 1)
    assert hits == []


def test_prologue_empty_data():
    assert _find_prologue_starts_x86_64(b"", 0, 0) == []


def test_prologue_too_short():
    assert _find_prologue_starts_x86_64(b"\x55\x48", 0, 2) == []


# ── _resolve_call_target_x64 ──────────────────────────────────────────────────

def test_resolve_rip_plus():
    """qword ptr [rip + 0x1234] resolves via IAT when slot VA matches."""
    iat = {0x140001000 + 6 + 0x1234: "kernel32.dll!VirtualAlloc"}
    result = _resolve_call_target_x64("qword ptr [rip + 0x1234]", 0x140001000, 6, iat)
    assert result == "kernel32.dll!VirtualAlloc"


def test_resolve_rip_minus():
    """qword ptr [rip - 0x10] resolves via IAT when slot VA matches."""
    iat = {0x140001000 + 6 - 0x10: "ntdll.dll!NtAllocateVirtualMemory"}
    result = _resolve_call_target_x64("qword ptr [rip - 0x10]", 0x140001000, 6, iat)
    assert result == "ntdll.dll!NtAllocateVirtualMemory"


def test_resolve_direct_call():
    """Direct call 0xXXXXXXXX resolves if VA is in IAT (thunk)."""
    iat = {0x14000A000: "user32.dll!MessageBoxA"}
    result = _resolve_call_target_x64("0x14000a000", 0x140001000, 5, iat)
    assert result == "user32.dll!MessageBoxA"


def test_resolve_unresolvable_register():
    """call rax — not resolvable; returns op_str verbatim."""
    result = _resolve_call_target_x64("rax", 0x140001000, 2, {})
    assert result == "rax"


def test_resolve_rip_plus_miss():
    """IAT miss — returns raw op_str."""
    result = _resolve_call_target_x64("qword ptr [rip + 0x1234]", 0x140001000, 6, {})
    assert result == "qword ptr [rip + 0x1234]"


# ── regex correctness ─────────────────────────────────────────────────────────

def test_iat_rip_re_matches():
    m = _IAT_RIP_RE.search("qword ptr [rip + 0x12ab]")
    assert m and m.group(1) == "12ab"


def test_iat_rip_neg_re_matches():
    m = _IAT_RIP_NEG_RE.search("qword ptr [rip - 0xff00]")
    assert m and m.group(1) == "ff00"


def test_lea_rip_re_matches():
    m = _LEA_RIP_RE.search("lea rcx, [rip + 0x1abc]")
    assert m and m.group(1) == "1abc"


def test_lea_rip_neg_re_matches():
    m = _LEA_RIP_NEG_RE.search("lea rdx, [rip - 0x20]")
    assert m and m.group(1) == "20"


def test_lea_rip_string_va_computation():
    """String VA = insn_address + insn_size + offset."""
    insn_va = 0x140001000
    insn_size = 7
    offset = 0x1abc
    m = _LEA_RIP_RE.search("lea rcx, [rip + 0x1abc]")
    assert m
    str_va = insn_va + insn_size + int(m.group(1), 16)
    assert str_va == 0x140001000 + 7 + 0x1abc
