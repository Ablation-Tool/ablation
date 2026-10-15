"""Tests for EcuSecurityAccessScanner (M68K, PPC32, and VLE static-seed fingerprints)."""

import struct

import pytest

from ablation.analyzers.ecu_security_access_scanner import (
    EcuSecurityAccessScanner,
    SecurityAccessFinding,
)


# ------------------------------------------------------------------ #
# M68K helpers                                                        #
# ------------------------------------------------------------------ #

def _m68k_moveb_67_d16_a5() -> bytes:
    """MOVE.B #$67, $34(A5) — confirmed GM P01 requestSeed encoding."""
    # Opcode: MOVE.B #imm, (d16,A5)
    # byte[0]=0x1B, byte[1]=0x7C (top nibble 1=MOVE.B, dst=d16,A5; low 6=0x3C=#imm)
    # immediate: 0x0067
    # displacement: 0x0034
    return bytes([0x1B, 0x7C, 0x00, 0x67, 0x00, 0x34])


def _m68k_clrb_d16_a5(disp: int) -> bytes:
    """CLR.B disp(A5) — opcode 0x4228 + disp word."""
    return bytes([0x42, 0x28]) + struct.pack(">H", disp)


def _m68k_clrb_abs_w(addr: int) -> bytes:
    """CLR.B addr.W — opcode 0x4238 + 16-bit address."""
    return bytes([0x42, 0x38]) + struct.pack(">H", addr & 0xFFFF)


def _pad(n: int) -> bytes:
    return bytes([0x4E, 0x75]) * (n // 2)  # NOP-like (RTS) padding


# ------------------------------------------------------------------ #
# M68K — positive cases                                               #
# ------------------------------------------------------------------ #

def test_m68k_static_seed_minimal():
    """Exact GM P01 requestSeed pattern: move.b #$67 + 2x clr.b."""
    body = (
        _m68k_moveb_67_d16_a5()
        + _m68k_clrb_d16_a5(0x35)
        + _m68k_clrb_d16_a5(0x36)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    m68k = [f for f in findings if f.arch == "M68K"]
    assert len(m68k) == 1
    assert m68k[0].offset == 0
    assert m68k[0].pattern == "static-seed-requestSeed"


def test_m68k_static_seed_with_padding_between():
    """2x clr.b reachable within default window despite intervening instructions."""
    body = (
        _m68k_moveb_67_d16_a5()
        + _pad(4)                        # 4 padding bytes between
        + _m68k_clrb_d16_a5(0x35)
        + _m68k_clrb_d16_a5(0x36)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    m68k = [f for f in findings if f.arch == "M68K"]
    assert len(m68k) == 1


def test_m68k_static_seed_abs_w_destination():
    """MOVE.B #$67, abs.W variant (opcode 0x11FC)."""
    # MOVE.B #$67, abs.W: byte[0]=0x11, byte[1]=0xFC (0xFC & 0x3F == 0x3C)
    body = (
        bytes([0x11, 0xFC, 0x00, 0x67, 0x10, 0x00])  # MOVE.B #$67, $1000
        + _m68k_clrb_abs_w(0x1001)
        + _m68k_clrb_abs_w(0x1002)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    m68k = [f for f in findings if f.arch == "M68K"]
    assert len(m68k) == 1


# ------------------------------------------------------------------ #
# M68K — negative cases                                               #
# ------------------------------------------------------------------ #

def test_m68k_only_one_clrb_no_match():
    """One CLR.B is not enough — two are required."""
    body = _m68k_moveb_67_d16_a5() + _m68k_clrb_d16_a5(0x35)
    findings = EcuSecurityAccessScanner(body).scan()
    assert not [f for f in findings if f.arch == "M68K"]


def test_m68k_no_clrb_no_match():
    """MOVE.B #$67 alone, no CLR.B."""
    body = _m68k_moveb_67_d16_a5() + bytes(32)
    findings = EcuSecurityAccessScanner(body).scan()
    assert not [f for f in findings if f.arch == "M68K"]


def test_m68k_clrb_outside_window_no_match():
    """CLR.B instructions present but beyond the 256-byte default window."""
    padding = _pad(260)  # > 256-byte default window
    body = (
        _m68k_moveb_67_d16_a5()
        + padding
        + _m68k_clrb_d16_a5(0x35)
        + _m68k_clrb_d16_a5(0x36)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    assert not [f for f in findings if f.arch == "M68K"]


def test_m68k_wrong_immediate_no_match():
    """MOVE.B #$68 (not 0x67) — should not trigger."""
    body = bytes([0x1B, 0x7C, 0x00, 0x68, 0x00, 0x34])
    body += _m68k_clrb_d16_a5(0x35) + _m68k_clrb_d16_a5(0x36)
    findings = EcuSecurityAccessScanner(body).scan()
    assert not [f for f in findings if f.arch == "M68K"]


def test_m68k_empty_rom():
    findings = EcuSecurityAccessScanner(b"").scan()
    assert findings == []


# ------------------------------------------------------------------ #
# PPC32 helpers                                                       #
# ------------------------------------------------------------------ #

def _ppc32_li(rd: int, simm: int) -> bytes:
    """li rD, simm = addi rD, r0, simm."""
    # opcode 14 (0xE), RA=0, RD=rd, simm16
    word = (14 << 26) | (rd << 21) | (0 << 16) | (simm & 0xFFFF)
    return struct.pack(">I", word)


def _ppc32_stb(rs: int, d: int, ra: int) -> bytes:
    """stb rS, d(rA)."""
    word = (38 << 26) | (rs << 21) | (ra << 16) | (d & 0xFFFF)
    return struct.pack(">I", word)


def _ppc32_nop() -> bytes:
    """ori r0, r0, 0 — canonical PPC32 NOP."""
    return struct.pack(">I", 0x60000000)


# ------------------------------------------------------------------ #
# PPC32 — positive cases                                              #
# ------------------------------------------------------------------ #

def test_ppc32_static_seed_minimal():
    """Exact GM E38 pattern: li r3,0x67; stb; li r4,0; stb; li r5,0; stb."""
    body = (
        _ppc32_li(3, 0x67)
        + _ppc32_stb(3, 0, 4)
        + _ppc32_li(4, 0)
        + _ppc32_stb(4, 1, 4)
        + _ppc32_li(5, 0)
        + _ppc32_stb(5, 2, 4)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    ppc = [f for f in findings if f.arch == "PPC32"]
    assert len(ppc) == 1
    assert ppc[0].offset == 0
    assert ppc[0].pattern == "static-seed-requestSeed"


def test_ppc32_static_seed_different_registers():
    """Pattern holds regardless of which registers are used."""
    body = (
        _ppc32_li(10, 0x67)
        + _ppc32_stb(10, 0x10, 31)
        + _ppc32_li(11, 0)
        + _ppc32_stb(11, 0x11, 31)
        + _ppc32_li(12, 0)
        + _ppc32_stb(12, 0x12, 31)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    ppc = [f for f in findings if f.arch == "PPC32"]
    assert len(ppc) == 1


def test_ppc32_static_seed_with_nops_between():
    """NOPs between li and stb pairs — within window."""
    body = (
        _ppc32_li(3, 0x67)
        + _ppc32_stb(3, 0, 4)
        + _ppc32_nop() * 4
        + _ppc32_li(4, 0)
        + _ppc32_stb(4, 1, 4)
        + _ppc32_nop() * 4
        + _ppc32_li(5, 0)
        + _ppc32_stb(5, 2, 4)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    ppc = [f for f in findings if f.arch == "PPC32"]
    assert len(ppc) == 1


# ------------------------------------------------------------------ #
# PPC32 — negative cases                                              #
# ------------------------------------------------------------------ #

def test_ppc32_only_one_zero_pair_no_match():
    """Only one (li r0 + stb) pair — two required."""
    body = (
        _ppc32_li(3, 0x67)
        + _ppc32_stb(3, 0, 4)
        + _ppc32_li(4, 0)
        + _ppc32_stb(4, 1, 4)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    assert not [f for f in findings if f.arch == "PPC32"]


def test_ppc32_li_67_without_stb_no_match():
    """li rX, 0x67 not immediately followed by stb — no match."""
    body = (
        _ppc32_li(3, 0x67)
        + _ppc32_nop()                  # NOT a stb
        + _ppc32_li(4, 0)
        + _ppc32_stb(4, 1, 4)
        + _ppc32_li(5, 0)
        + _ppc32_stb(5, 2, 4)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    assert not [f for f in findings if f.arch == "PPC32"]


def test_ppc32_wrong_immediate_no_match():
    """li rX, 0x68 (not 0x67) does not trigger."""
    body = (
        _ppc32_li(3, 0x68)
        + _ppc32_stb(3, 0, 4)
        + _ppc32_li(4, 0)
        + _ppc32_stb(4, 1, 4)
        + _ppc32_li(5, 0)
        + _ppc32_stb(5, 2, 4)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    assert not [f for f in findings if f.arch == "PPC32"]


def test_ppc32_zero_pairs_outside_window_no_match():
    """Zero li+stb pairs present but beyond the 256-byte default window."""
    body = (
        _ppc32_li(3, 0x67)
        + _ppc32_stb(3, 0, 4)
        + _ppc32_nop() * 70             # 280 bytes > 256-byte default window
        + _ppc32_li(4, 0)
        + _ppc32_stb(4, 1, 4)
        + _ppc32_li(5, 0)
        + _ppc32_stb(5, 2, 4)
    )
    findings = EcuSecurityAccessScanner(body).scan()
    assert not [f for f in findings if f.arch == "PPC32"]


def test_ppc32_empty_rom():
    findings = EcuSecurityAccessScanner(b"").scan()
    assert findings == []


# ------------------------------------------------------------------ #
# Mixed ROM: M68K and PPC32 patterns in the same buffer              #
# ------------------------------------------------------------------ #

def test_mixed_rom_both_arches_found():
    """Both M68K and PPC32 patterns in one buffer are independently reported."""
    m68k_part = (
        _m68k_moveb_67_d16_a5()
        + _m68k_clrb_d16_a5(0x35)
        + _m68k_clrb_d16_a5(0x36)
    )
    ppc_part = (
        _ppc32_li(3, 0x67)
        + _ppc32_stb(3, 0, 4)
        + _ppc32_li(4, 0)
        + _ppc32_stb(4, 1, 4)
        + _ppc32_li(5, 0)
        + _ppc32_stb(5, 2, 4)
    )
    # Pad M68K section to 4-byte boundary so PPC scanner aligns correctly
    pad_len = (-len(m68k_part)) % 4
    body = m68k_part + bytes(pad_len) + ppc_part

    findings = EcuSecurityAccessScanner(body).scan()
    arches = {f.arch for f in findings}
    assert "M68K" in arches
    assert "PPC32" in arches


# ------------------------------------------------------------------ #
# SecurityAccessFinding string representation                         #
# ------------------------------------------------------------------ #

def test_finding_str_format():
    f = SecurityAccessFinding(
        offset=0xB60,
        arch="M68K",
        pattern="static-seed-requestSeed",
        evidence=bytes([0x1B, 0x7C, 0x00, 0x67]),
        note="test note",
    )
    s = str(f)
    assert "0x00000B60" in s
    assert "M68K" in s
    assert "test note" in s
    assert "1b 7c 00 67" in s


# ------------------------------------------------------------------ #
# from_path constructor smoke test                                    #
# ------------------------------------------------------------------ #

def test_from_path_matches_from_bytes(tmp_path):
    """from_path and from_bytes produce identical findings."""
    body = (
        _m68k_moveb_67_d16_a5()
        + _m68k_clrb_d16_a5(0x35)
        + _m68k_clrb_d16_a5(0x36)
    )
    rom_file = tmp_path / "test.bin"
    rom_file.write_bytes(body)

    from_path_findings = EcuSecurityAccessScanner.from_path(rom_file).scan()
    from_bytes_findings = EcuSecurityAccessScanner.from_bytes(body).scan()

    assert len(from_path_findings) == len(from_bytes_findings)
    for fp, fb in zip(from_path_findings, from_bytes_findings):
        assert fp.offset == fb.offset
        assert fp.arch == fb.arch
        assert fp.pattern == fb.pattern


# ------------------------------------------------------------------ #
# VLE helpers                                                         #
# ------------------------------------------------------------------ #

def _vle_se_li(rx: int, imm7: int) -> bytes:
    """se_li Rx, imm7 (SE16, 4-bit compact register, 7-bit unsigned immediate).

    Compact register encoding: rx < 8 → raw=rx; rx >= 24 → raw=rx-16.
    """
    assert 0 <= imm7 <= 127, f"imm7 {imm7} out of range"
    rx_raw = rx if rx < 8 else rx - 16
    assert 0 <= rx_raw <= 15, f"rx {rx} not representable in se_li"
    hw = 0x4800 | (rx_raw << 7) | imm7
    return struct.pack(">H", hw)


def _vle_se_stb(rz: int, rx: int, disp: int) -> bytes:
    """se_stb Rz, Rx, disp (SE16 SD4, 3-bit regs r0-r7, byte-scale displacement 0-15)."""
    assert 0 <= rz <= 7 and 0 <= rx <= 7, f"se_stb: registers {rz},{rx} out of 3-bit range"
    assert 0 <= disp <= 15, f"se_stb: disp {disp} exceeds SD4 range"
    hw = 0x9000 | (rz << 9) | (disp << 5) | (rx << 2)
    return struct.pack(">H", hw)


def _vle_e_stb(rs: int, ra: int, disp: int) -> bytes:
    """e_stb rs, disp(ra) (VLE32, op6=13, full 5-bit register fields)."""
    word = (13 << 26) | (rs << 21) | (ra << 16) | (disp & 0xFFFF)
    return struct.pack(">I", word)


def _vle_se_blr() -> bytes:
    """se_blr — return from leaf function (SE16)."""
    return struct.pack(">H", 0x0004)


def _vle_se_nop() -> bytes:
    """se_or r0, r0 — SE16 NOP-equivalent for padding."""
    # se_or: 0x4400 | (rx << 4) | ry
    return struct.pack(">H", 0x4400)


# ------------------------------------------------------------------ #
# VLE — positive cases                                               #
# ------------------------------------------------------------------ #

def test_vle_se_li_se_stb_r0():
    """se_li r0,0x67 + se_stb r0,r4,3 → 1 VLE finding."""
    body = _vle_se_li(0, 0x67) + _vle_se_stb(0, 4, 3)
    findings = EcuSecurityAccessScanner(body).scan()
    vle = [f for f in findings if f.arch == "VLE"]
    assert len(vle) == 1
    assert vle[0].offset == 0
    assert vle[0].pattern == "static-seed-requestSeed"
    assert vle[0].arch == "VLE"


def test_vle_se_li_e_stb_r5():
    """se_li r5,0x67 + e_stb r5,r31,8 → 1 VLE finding (e_stb full 5-bit register)."""
    body = _vle_se_li(5, 0x67) + _vle_e_stb(5, 31, 8)
    findings = EcuSecurityAccessScanner(body).scan()
    vle = [f for f in findings if f.arch == "VLE"]
    assert len(vle) == 1
    assert vle[0].offset == 0


def test_vle_se_li_r24_e_stb_r24():
    """se_li r24,0x67 + e_stb r24,r1,0 — compact register 8 → r24, stored via e_stb."""
    # rx_raw = 24 - 16 = 8 → hw = 0x4800 | (8<<7) | 0x67 = 0x4C67
    body = _vle_se_li(24, 0x67) + _vle_e_stb(24, 1, 0)
    findings = EcuSecurityAccessScanner(body).scan()
    vle = [f for f in findings if f.arch == "VLE"]
    assert len(vle) == 1
    assert vle[0].offset == 0


def test_vle_offset_nonzero():
    """Pattern at non-zero offset is reported at the correct offset."""
    prefix = bytes(12)  # 12 zero bytes of padding
    body = prefix + _vle_se_li(0, 0x67) + _vle_se_stb(0, 4, 3)
    findings = EcuSecurityAccessScanner(body).scan()
    vle = [f for f in findings if f.arch == "VLE"]
    assert any(f.offset == 12 for f in vle)


def test_vle_evidence_contains_trigger_bytes():
    """Finding evidence starts with the se_li + se_stb bytes."""
    li_bytes = _vle_se_li(0, 0x67)
    stb_bytes = _vle_se_stb(0, 4, 3)
    body = li_bytes + stb_bytes
    findings = EcuSecurityAccessScanner(body).scan()
    vle = [f for f in findings if f.arch == "VLE"]
    assert len(vle) == 1
    assert vle[0].evidence[:4] == li_bytes + stb_bytes


# ------------------------------------------------------------------ #
# VLE — negative cases                                               #
# ------------------------------------------------------------------ #

def test_vle_wrong_immediate_no_match():
    """se_li r0,0x68 + se_stb r0,r4,3 — wrong immediate, no VLE finding."""
    body = _vle_se_li(0, 0x68) + _vle_se_stb(0, 4, 3)
    findings = EcuSecurityAccessScanner(body).scan()
    vle = [f for f in findings if f.arch == "VLE"]
    assert vle == []


def test_vle_different_register_se_stb_no_match():
    """se_li r0,0x67 + se_stb r1,r4,3 — different stored register, no VLE finding."""
    body = _vle_se_li(0, 0x67) + _vle_se_stb(1, 4, 3)
    findings = EcuSecurityAccessScanner(body).scan()
    vle = [f for f in findings if f.arch == "VLE"]
    assert vle == []


def test_vle_different_register_e_stb_no_match():
    """se_li r3,0x67 + e_stb r4,r31,0 — different stored register, no VLE finding."""
    body = _vle_se_li(3, 0x67) + _vle_e_stb(4, 31, 0)
    findings = EcuSecurityAccessScanner(body).scan()
    vle = [f for f in findings if f.arch == "VLE"]
    assert vle == []


def test_vle_se_li_without_stb_no_match():
    """se_li r0,0x67 + se_blr — no stb, no VLE finding."""
    body = _vle_se_li(0, 0x67) + _vle_se_blr()
    findings = EcuSecurityAccessScanner(body).scan()
    vle = [f for f in findings if f.arch == "VLE"]
    assert vle == []


def test_vle_truncated_at_se_li_no_crash():
    """Buffer ending mid-se_li does not crash."""
    li_bytes = _vle_se_li(0, 0x67)
    findings = EcuSecurityAccessScanner(li_bytes).scan()
    # May or may not find anything — must not raise
    assert isinstance(findings, list)


# ------------------------------------------------------------------ #
# VLE — mixed ROM (VLE + M68K in same buffer)                        #
# ------------------------------------------------------------------ #

def test_vle_and_m68k_both_found():
    """VLE and M68K patterns in one buffer are independently reported."""
    m68k_part = (
        _m68k_moveb_67_d16_a5()
        + _m68k_clrb_d16_a5(0x35)
        + _m68k_clrb_d16_a5(0x36)
    )
    vle_part = _vle_se_li(0, 0x67) + _vle_se_stb(0, 4, 3)
    body = m68k_part + vle_part

    findings = EcuSecurityAccessScanner(body).scan()
    arches = {f.arch for f in findings}
    assert "M68K" in arches
    assert "VLE" in arches


# ------------------------------------------------------------------ #
# Window default regression: from_path/from_bytes default is 256     #
# ------------------------------------------------------------------ #

def test_from_path_default_window_256_finds_m68k_with_gap():
    """from_path default window (256) covers CLR.B pairs >32 bytes past MOVE.B #$67."""
    # Build a buffer where the 2x CLR.B are 40 bytes past the trigger
    gap = _pad(40)
    body = _m68k_moveb_67_d16_a5() + gap + _m68k_clrb_d16_a5(0x35) + _m68k_clrb_d16_a5(0x36)

    findings_default = EcuSecurityAccessScanner.from_bytes(body).scan()
    findings_narrow = EcuSecurityAccessScanner.from_bytes(body, window=32).scan()
    m68k_default = [f for f in findings_default if f.arch == "M68K"]
    m68k_narrow = [f for f in findings_narrow if f.arch == "M68K"]

    assert len(m68k_default) == 1, "default window=256 should reach CLR.B at +40"
    assert len(m68k_narrow) == 0, "window=32 is too narrow to reach CLR.B at +40"
