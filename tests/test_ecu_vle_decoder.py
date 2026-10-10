"""Tests for EcuVLEDecoder (PPC VLE / SE16 decoder for e200-class ECU ROMs)."""

import struct

import pytest

from ablation.analyzers.ecu_vle_decoder import EcuVLEDecoder, VLEInsn


# ------------------------------------------------------------------ #
# Encoding helpers — build minimal instruction streams from spec macros
# ------------------------------------------------------------------ #

def _se_blr() -> bytes:
    """se_blr = C_LK(2,0) = 0x0004."""
    return struct.pack(">H", 0x0004)


def _se_mflr(rx: int) -> bytes:
    """se_mflr rX = SE_R(0,8) = 0x0080 | rX."""
    return struct.pack(">H", 0x0080 | (rx & 0xF))


def _se_mtlr(rx: int) -> bytes:
    """se_mtlr rX = SE_R(0,9) = 0x0090 | rX."""
    return struct.pack(">H", 0x0090 | (rx & 0xF))


def _se_li(rx: int, ui7: int) -> bytes:
    """se_li rX, UI7 = IM7(9) | (rx<<7) | ui7 = 0x4800 | ..."""
    return struct.pack(">H", 0x4800 | ((rx & 0xF) << 7) | (ui7 & 0x7F))


def _se_lwz(rz: int, disp: int, rx: int, scale: int = 4) -> bytes:
    """se_lwz rZ, disp(rX) = SD4(12) encoding."""
    sd4 = disp // scale
    hw = 0xC000 | ((rz & 0x7) << 9) | ((sd4 & 0xF) << 5) | ((rx & 0x7) << 2)
    return struct.pack(">H", hw)


def _se_stw(rz: int, disp: int, rx: int, scale: int = 4) -> bytes:
    """se_stw rZ, disp(rX) = SD4(13) encoding."""
    sd4 = disp // scale
    hw = 0xD000 | ((rz & 0x7) << 9) | ((sd4 & 0xF) << 5) | ((rx & 0x7) << 2)
    return struct.pack(">H", hw)


def _se_b(bd8: int) -> bytes:
    """se_b BD8 = BD8(58,0,0) | bd8 = 0xE800 | (bd8 & 0xFF)."""
    return struct.pack(">H", 0xE800 | (bd8 & 0xFF))


def _se_bl(bd8: int) -> bytes:
    """se_bl BD8 = BD8(58,0,1) | bd8 = 0xE900 | (bd8 & 0xFF)."""
    return struct.pack(">H", 0xE900 | (bd8 & 0xFF))


def _se_bc(bo16: int, bi16: int, bd8: int) -> bytes:
    """se_bc BO16,BI16,BD8 = BD8IO(28) = 0xE000 | (bo16<<10) | (bi16<<8) | bd8."""
    hw = 0xE000 | ((bo16 & 1) << 10) | ((bi16 & 3) << 8) | (bd8 & 0xFF)
    return struct.pack(">H", hw)


def _e_stwu(rs: int, ra: int, d8: int) -> bytes:
    """e_stwu rS, D8(rA) = OPVUP(6,6) | (rs<<21) | (ra<<16) | (d8&0xFF)."""
    word = 0x18000600 | ((rs & 0x1F) << 21) | ((ra & 0x1F) << 16) | (d8 & 0xFF)
    return struct.pack(">I", word)


def _e_b(bd24: int, base_va: int = 0, cur_off: int = 0) -> bytes:
    """e_b BD24 — encode absolute displacement from current instruction."""
    # bd24 should already be the signed byte displacement
    raw = bd24 & 0x01FFFFFE
    word = 0x78000000 | raw
    return struct.pack(">I", word)


def _e_bl(bd24: int) -> bytes:
    """e_bl BD24 = e_b with LK=1."""
    raw = bd24 & 0x01FFFFFE
    word = 0x78000001 | raw
    return struct.pack(">I", word)


def _e_add16i(rd: int, ra: int, si: int) -> bytes:
    """e_add16i rD, rA, SI = OP(7) | ..."""
    word = 0x1C000000 | ((rd & 0x1F) << 21) | ((ra & 0x1F) << 16) | (si & 0xFFFF)
    return struct.pack(">I", word)


def _e_stw(rs: int, ra: int, disp: int) -> bytes:
    """e_stw rS, D(rA) = OP(21)."""
    word = 0x54000000 | ((rs & 0x1F) << 21) | ((ra & 0x1F) << 16) | (disp & 0xFFFF)
    return struct.pack(">I", word)


def _e_lwz(rd: int, ra: int, disp: int) -> bytes:
    """e_lwz rD, D(rA) = OP(20)."""
    word = 0x50000000 | ((rd & 0x1F) << 21) | ((ra & 0x1F) << 16) | (disp & 0xFFFF)
    return struct.pack(">I", word)


# ------------------------------------------------------------------ #
# Section 1: insn_length() — length discrimination rule
# ------------------------------------------------------------------ #

def test_insn_length_se16_returns_2():
    """16-bit SE instruction: first byte does NOT satisfy (b & 0x90) == 0x10."""
    # se_blr = 0x0004: first byte 0x00 → (0x00 & 0x90) = 0x00 ≠ 0x10
    data = _se_blr() + bytes(10)
    dec = EcuVLEDecoder(data)
    assert dec.insn_length(0) == 2


def test_insn_length_32bit_returns_4():
    """32-bit VLE instruction: first byte satisfies (b & 0x90) == 0x10."""
    # e_stwu r1,-8(r1): first byte = 0x18 → (0x18 & 0x90) = 0x10
    data = _e_stwu(1, 1, -8)
    dec = EcuVLEDecoder(data)
    assert dec.insn_length(0) == 4


def test_insn_length_at_eof_returns_0():
    dec = EcuVLEDecoder(b"")
    assert dec.insn_length(0) == 0


def test_insn_length_covers_all_32bit_opcodes():
    """All 32-bit VLE opcodes (6,7,12-15,20-22,28,30) have (byte0 & 0x90) == 0x10."""
    opcodes_32 = [6, 7, 12, 13, 14, 15, 20, 21, 22, 28, 30]
    for op in opcodes_32:
        b0 = op << 2  # top-6-bit opcode → first byte top bits
        assert (b0 & 0x90) == 0x10, f"opcode {op} first byte 0x{b0:02x} fails length test"


# ------------------------------------------------------------------ #
# Section 2: decode_one() — SE 16-bit instructions
# ------------------------------------------------------------------ #

def test_decode_se_blr():
    dec = EcuVLEDecoder(_se_blr())
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.mnemonic == "se_blr"
    assert insn.insn_type == "RETURN"
    assert insn.is_16bit is True
    assert len(insn.raw) == 2


def test_decode_se_mflr_r0():
    dec = EcuVLEDecoder(_se_mflr(0))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_mflr"
    assert insn.insn_type == "LR_SAVE"
    assert insn.rd == 0


def test_decode_se_mflr_r7():
    dec = EcuVLEDecoder(_se_mflr(7))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_mflr"
    assert insn.rd == 7


def test_decode_se_mtlr_r0():
    dec = EcuVLEDecoder(_se_mtlr(0))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_mtlr"
    assert insn.insn_type == "LR_RESTORE"
    assert insn.rd == 0


def test_decode_se_li():
    """se_li r3, 10 — IM7 form; compact field 3 maps to GPR3."""
    dec = EcuVLEDecoder(_se_li(3, 10))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_li"
    assert insn.rd == 3       # compact field 3 → GPR3 (< 8, direct mapping)
    assert insn.imm == 10


def test_decode_se_li_compact_reg_high():
    """se_li with compact field 9 maps to GPR25 (9 + 16 = 25)."""
    dec = EcuVLEDecoder(_se_li(9, 5))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_li"
    assert insn.rd == 25      # compact field 9 → GPR25 (9 >= 8, so 9 + 16)
    assert insn.imm == 5


def test_decode_se_lwz():
    """se_lwz r0, 0(r1) — SD4 form, scale=4."""
    dec = EcuVLEDecoder(_se_lwz(0, 0, 1, scale=4))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_lwz"
    assert insn.insn_type == "LOAD"


def test_decode_se_stw():
    """se_stw r3, 4(r1) — SD4 form, scale=4, disp=4."""
    dec = EcuVLEDecoder(_se_stw(3, 4, 1, scale=4))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_stw"
    assert insn.insn_type == "STORE"
    assert insn.imm == 4


def test_decode_se_b_forward():
    """se_b +4 — forward unconditional branch."""
    dec = EcuVLEDecoder(_se_b(4), base_va=0x1000)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_b"
    assert insn.insn_type == "BRANCH"
    # target = CIA + exts(BD8 || 0) = 0x1000 + 4*2 = 0x1008
    assert insn.target == 0x1008


def test_decode_se_b_backward():
    """se_b -2 — backward branch (loop)."""
    dec = EcuVLEDecoder(_se_b(-2), base_va=0x1000)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_b"
    # target = 0x1000 + (-2)*2 = 0xFFC
    assert insn.target == 0xFFC


def test_decode_se_bl():
    """se_bl calls a subroutine."""
    dec = EcuVLEDecoder(_se_bl(10), base_va=0x2000)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_bl"
    assert insn.insn_type == "CALL"


def test_decode_se_bc():
    """se_bc (conditional branch) — BD8IO form."""
    dec = EcuVLEDecoder(_se_bc(1, 0, 4), base_va=0x500)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_bc"
    assert insn.insn_type == "BRANCH"


# ------------------------------------------------------------------ #
# Section 3: decode_one() — 32-bit VLE instructions
# ------------------------------------------------------------------ #

def test_decode_e_stwu_r1_neg8():
    """e_stwu r1, -8(r1) — standard frame allocation."""
    dec = EcuVLEDecoder(_e_stwu(1, 1, -8), base_va=0x4000)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "e_stwu"
    assert insn.insn_type == "PROLOGUE"
    assert insn.rs == 1
    assert insn.ra == 1
    assert insn.imm == -8
    assert insn.is_16bit is False
    assert len(insn.raw) == 4


def test_decode_e_stwu_positive_is_not_prologue():
    """e_stwu r1, +8(r1) — positive D8 is NOT a prologue (stack grows down)."""
    dec = EcuVLEDecoder(_e_stwu(1, 1, 8))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "e_stwu"
    assert insn.insn_type != "PROLOGUE"


def test_decode_e_b_forward():
    """e_b with forward displacement."""
    dec = EcuVLEDecoder(_e_b(0x80), base_va=0x10000)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "e_b"
    assert insn.insn_type == "BRANCH"
    assert insn.target == 0x10000 + 0x80


def test_decode_e_bl():
    """e_bl calls a subroutine."""
    dec = EcuVLEDecoder(_e_bl(0x100), base_va=0x20000)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "e_bl"
    assert insn.insn_type == "CALL"


def test_decode_e_add16i():
    """e_add16i r1, r1, 16 — standard frame restoration in epilogue."""
    dec = EcuVLEDecoder(_e_add16i(1, 1, 16))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "e_add16i"
    assert insn.rd == 1
    assert insn.ra == 1
    assert insn.imm == 16


def test_decode_e_stw():
    """e_stw r31, 0(r1)."""
    dec = EcuVLEDecoder(_e_stw(31, 1, 0))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "e_stw"
    assert insn.insn_type == "STORE"
    assert insn.rs == 31


def test_decode_e_lwz():
    """e_lwz r3, 8(r1)."""
    dec = EcuVLEDecoder(_e_lwz(3, 1, 8))
    insn = dec.decode_one(0)
    assert insn.mnemonic == "e_lwz"
    assert insn.insn_type == "LOAD"
    assert insn.rd == 3
    assert insn.imm == 8


# ------------------------------------------------------------------ #
# Section 4: disassemble()
# ------------------------------------------------------------------ #

def test_disassemble_simple_prologue_sequence():
    """A minimal VLE function: mflr r0, e_stwu, ..., mtlr r0, se_blr."""
    body = (
        _se_mflr(0)       # 2 bytes
        + _e_stwu(1, 1, -8)  # 4 bytes
        + _e_stw(0, 1, 4)    # 4 bytes: e_stw r0, 4(r1)
        + _e_add16i(1, 1, 8) # 4 bytes: restore stack
        + _se_mtlr(0)        # 2 bytes
        + _se_blr()          # 2 bytes: return
    )
    dec = EcuVLEDecoder(body)
    insns = dec.disassemble()
    assert len(insns) == 6
    assert insns[0].mnemonic == "se_mflr"
    assert insns[1].mnemonic == "e_stwu"
    assert insns[4].mnemonic == "se_mtlr"
    assert insns[5].mnemonic == "se_blr"


def test_disassemble_respects_start_end():
    """Only the [start, end) slice is decoded."""
    body = _se_blr() + _e_stwu(1, 1, -8) + _se_blr()
    dec = EcuVLEDecoder(body)
    # Decode only the middle 4 bytes (e_stwu)
    insns = dec.disassemble(start=2, end=6)
    assert len(insns) == 1
    assert insns[0].mnemonic == "e_stwu"


def test_disassemble_empty_data():
    dec = EcuVLEDecoder(b"")
    assert dec.disassemble() == []


def test_disassemble_handles_truncated_32bit():
    """If a 32-bit instruction is truncated, stop gracefully (no crash)."""
    # First byte = 0x18 → 32-bit VLE indicated, but only 3 bytes present
    data = bytes([0x18, 0x21, 0x06])  # truncated e_stwu
    dec = EcuVLEDecoder(data)
    insns = dec.disassemble()
    # Should produce 0 instructions (decode_one returns None on truncation)
    assert insns == []


def test_disassemble_offsets_use_base_va():
    """Each decoded instruction carries its correct VA, not buffer offset."""
    data = _se_blr() + _se_mflr(0)
    dec = EcuVLEDecoder(data, base_va=0x40000000)
    insns = dec.disassemble()
    assert insns[0].offset == 0x40000000
    assert insns[1].offset == 0x40000002


# ------------------------------------------------------------------ #
# Section 5: function_starts()
# ------------------------------------------------------------------ #

def test_function_starts_finds_e_stwu_prologue():
    """Primary prologue: e_stwu r1, -N(r1) at any 4-byte-aligned offset."""
    data = bytes(16) + _e_stwu(1, 1, -32) + bytes(32)
    dec = EcuVLEDecoder(data, base_va=0)
    starts = dec.function_starts()
    assert 16 in starts


def test_function_starts_finds_se_mflr_leaf():
    """Leaf function: se_mflr r0 at 2-byte-aligned offset not inside another frame."""
    data = bytes(8) + _se_mflr(0) + bytes(10)
    dec = EcuVLEDecoder(data, base_va=0)
    starts = dec.function_starts()
    assert 8 in starts


def test_function_starts_positive_e_stwu_ignored():
    """e_stwu with positive D8 (not a stack-allocating prologue) must not trigger."""
    data = _e_stwu(1, 1, 8) + bytes(16)  # positive displacement
    dec = EcuVLEDecoder(data, base_va=0)
    starts = dec.function_starts()
    assert 0 not in starts


def test_function_starts_multiple_functions():
    """Two separate functions in a block are both found."""
    fn1 = _e_stwu(1, 1, -8) + _se_blr() + bytes(2)  # 8 bytes
    fn2 = _e_stwu(1, 1, -16) + _se_blr() + bytes(2)
    data = fn1 + fn2
    dec = EcuVLEDecoder(data, base_va=0x8000)
    starts = dec.function_starts()
    assert 0x8000 in starts
    assert 0x8008 in starts


def test_function_starts_returns_sorted():
    """Returned VAs are always in ascending order."""
    fn1 = _e_stwu(1, 1, -8) + bytes(4)
    fn2 = _e_stwu(1, 1, -16) + bytes(4)
    data = fn1 + fn2
    dec = EcuVLEDecoder(data, base_va=0)
    starts = dec.function_starts()
    assert starts == sorted(starts)


def test_function_starts_empty_data():
    dec = EcuVLEDecoder(b"")
    assert dec.function_starts() == []


def test_function_starts_uses_base_va():
    """Returned values are VAs, not buffer offsets."""
    data = _e_stwu(1, 1, -8) + bytes(4)
    dec = EcuVLEDecoder(data, base_va=0xFF000000)
    starts = dec.function_starts()
    assert len(starts) == 1
    assert starts[0] == 0xFF000000


# ------------------------------------------------------------------ #
# Section 6: from_bytes() / from_path() constructors
# ------------------------------------------------------------------ #

def test_from_bytes_constructor():
    data = _se_blr()
    dec = EcuVLEDecoder.from_bytes(data)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_blr"


def test_from_path_constructor(tmp_path):
    path = tmp_path / "test.bin"
    path.write_bytes(_se_blr())
    dec = EcuVLEDecoder.from_path(path)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "se_blr"


def test_from_path_missing_file_raises_informative_error():
    """FileNotFoundError from a missing path wraps with module context."""
    import pytest
    with pytest.raises(FileNotFoundError, match="EcuVLEDecoder"):
        EcuVLEDecoder("/nonexistent/path/firmware.bin")


def test_decode_e_li_immediate_20bit():
    """e_li LI20 immediate: verify high-5 + low-15 bit assembly for a known value."""
    # Build e_li r3, 0x1234F (= 0x1234F, 20-bit value)
    # bits[20:16] = 0x1234F >> 15 = 0x02 (high 5 bits)
    # bits[14:0]  = 0x1234F & 0x7FFF = 0x234F (low 15 bits)
    imm20 = 0x1234F
    rd = 3
    imm_hi = (imm20 >> 15) & 0x1F
    imm_lo = imm20 & 0x7FFF
    word = 0x70000000 | (rd << 21) | (imm_hi << 16) | imm_lo
    data = struct.pack(">I", word)
    dec = EcuVLEDecoder(data)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "e_li"
    assert insn.rd == rd
    assert insn.imm == imm20


# ------------------------------------------------------------------ #
# Section 7: VLEInsn.__str__()
# ------------------------------------------------------------------ #

def test_vle_insn_str_contains_mnemonic():
    dec = EcuVLEDecoder(_se_blr(), base_va=0x1000)
    insn = dec.decode_one(0)
    text = str(insn)
    assert "se_blr" in text
    assert "0x00001000" in text


def test_vle_insn_str_contains_target():
    dec = EcuVLEDecoder(_se_b(4), base_va=0x1000)
    insn = dec.decode_one(0)
    text = str(insn)
    assert "->" in text


# ------------------------------------------------------------------ #
# Section 8: Length discrimination boundary — all 32-bit opcodes
# ------------------------------------------------------------------ #

@pytest.mark.parametrize("op6,first_byte", [
    (6, 0x18),   # e_stwu (OPVUP(6,...))
    (7, 0x1C),   # e_add16i
    (12, 0x30),  # e_lbz
    (13, 0x34),  # e_stb
    (14, 0x38),  # e_lha
    (20, 0x50),  # e_lwz
    (21, 0x54),  # e_stw
    (22, 0x58),  # e_lhz
    (28, 0x70),  # e_li
    (30, 0x78),  # e_b/e_bl
])
def test_32bit_vle_opcode_first_byte(op6, first_byte):
    """Verify first-byte of each 32-bit VLE opcode satisfies (b & 0x90) == 0x10."""
    assert (first_byte & 0x90) == 0x10
    data = struct.pack(">I", op6 << 26) + bytes(4)
    dec = EcuVLEDecoder(data)
    assert dec.insn_length(0) == 4
