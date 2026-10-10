"""Tests for EcuSH2aDecoder — Renesas SH-2A ECU decoder."""

import struct
import pytest
from ablation.analyzers.ecu_sh2a_decoder import EcuSH2aDecoder, SH2aInsn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hw(hw: int) -> bytes:
    return struct.pack(">H", hw)

def _2hw(hw1: int, hw2: int) -> bytes:
    return struct.pack(">HH", hw1, hw2)

def _dec(data: bytes, base_va: int = 0) -> EcuSH2aDecoder:
    return EcuSH2aDecoder(data, base_va)


# ---------------------------------------------------------------------------
# insn_length — 16-bit vs 32-bit discrimination
# ---------------------------------------------------------------------------

class TestInsnLength:
    def test_returns_2_for_ordinary_16bit(self):
        data = _hw(0x4F22)  # STS.L PR, @-R15
        dec = _dec(data)
        assert dec.insn_length(0) == 2

    def test_returns_4_for_movi20(self):
        data = _2hw(0x00E5, 0x0000)  # MOVI20 with Rn=0
        dec = _dec(data)
        assert dec.insn_length(0) == 4

    def test_returns_4_for_movi20s(self):
        # MOVI20S Rn=1, imm_hi=3: 0000 0001 0011 0111 = 0x0137
        data = _2hw(0x0137, 0x1234)
        dec = _dec(data)
        assert dec.insn_length(0) == 4

    def test_returns_4_for_mov12(self):
        data = _2hw(0x3001, 0x1200)  # MOV with 12-bit disp
        dec = _dec(data)
        assert dec.insn_length(0) == 4

    def test_returns_4_for_bit_op(self):
        data = _2hw(0x3009, 0x1030)
        dec = _dec(data)
        assert dec.insn_length(0) == 4

    def test_returns_0_at_eof(self):
        dec = _dec(b"")
        assert dec.insn_length(0) == 0

    def test_returns_0_when_only_1_byte_left(self):
        dec = _dec(b"\x4F")
        assert dec.insn_length(0) == 0

    def test_rts_is_16bit(self):
        data = _hw(0x000B)
        dec = _dec(data)
        assert dec.insn_length(0) == 2


# ---------------------------------------------------------------------------
# decode_one — prologue and return
# ---------------------------------------------------------------------------

class TestDecodeOnePrologueReturn:
    def test_decode_sts_l_pr(self):
        insn = _dec(_hw(0x4F22)).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "sts.l"
        assert insn.insn_type == "LR_SAVE"
        assert insn.is_32bit is False

    def test_decode_rts(self):
        insn = _dec(_hw(0x000B)).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "rts"
        assert insn.insn_type == "RETURN"

    def test_decode_rts_n(self):
        insn = _dec(_hw(0x0063)).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "rts/n"
        assert insn.insn_type == "RETURN"

    def test_decode_lds_l_pr(self):
        insn = _dec(_hw(0x4F26)).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "lds.l"
        assert insn.insn_type == "LR_RESTORE"

    def test_decode_sts_pr_r5(self):
        # STS PR, R5 = 0000 0101 0010 1010 = 0x052A (Rn=5 in bits[11:8])
        insn = _dec(_hw(0x052A)).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "sts"
        assert insn.insn_type == "LR_SAVE"
        assert insn.rd == 5

    def test_decode_lds_r3_pr(self):
        # LDS R3, PR = 0x432A
        insn = _dec(_hw(0x432A)).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "lds"
        assert insn.insn_type == "LR_RESTORE"
        assert insn.rs == 3

    def test_decode_nop(self):
        insn = _dec(_hw(0x0009)).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "nop"
        assert insn.insn_type == "MISC"


# ---------------------------------------------------------------------------
# decode_one — branches and calls
# ---------------------------------------------------------------------------

class TestDecodeOneBranches:
    def test_decode_bsr_forward(self):
        # BSR +0x10: disp12 = 8, target = VA + 4 + 8*2 = 0 + 4 + 16 = 0x14
        hw = 0xB008  # BSR 0x008
        insn = _dec(_hw(hw), base_va=0).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "bsr"
        assert insn.insn_type == "CALL"
        assert insn.target == 0x14

    def test_decode_bsr_backward(self):
        # BSR disp12 = 0xFFF (-1): target = 0 + 4 + (-1)*2 = 2
        hw = 0xBFFF
        insn = _dec(_hw(hw), base_va=0).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "bsr"
        assert insn.insn_type == "CALL"
        assert insn.target == 2

    def test_decode_bra_forward(self):
        # BRA disp12 = 4: target = 0 + 4 + 4*2 = 12
        hw = 0xA004
        insn = _dec(_hw(hw), base_va=0).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "bra"
        assert insn.insn_type == "BRANCH"
        assert insn.target == 12

    def test_decode_bt_forward(self):
        # BT disp8 = 2: target = 0 + 4 + 2*2 = 8
        hw = 0x8902
        insn = _dec(_hw(hw), base_va=0).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "bt"
        assert insn.insn_type == "BRANCH"
        assert insn.target == 8

    def test_decode_bf_backward(self):
        # BF disp8 = 0xFF (-1): target = 0x100 + 4 + (-1)*2 = 0x102
        hw = 0x8BFF
        insn = _dec(_hw(hw), base_va=0x100).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "bf"
        assert insn.insn_type == "BRANCH"
        assert insn.target == 0x102

    def test_decode_bt_s(self):
        hw = 0x8D04
        insn = _dec(_hw(hw), base_va=0).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "bt/s"
        assert insn.insn_type == "BRANCH"

    def test_decode_jsr(self):
        # JSR @R6 = 0x460B
        hw = 0x460B
        insn = _dec(_hw(hw), base_va=0).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "jsr"
        assert insn.insn_type == "CALL"
        assert insn.rs == 6
        assert insn.target is None  # indirect

    def test_decode_movl_pc_relative(self):
        # MOV.L @(disp4*4, PC), R3 = 0xD303
        hw = 0xD303
        insn = _dec(_hw(hw), base_va=0x200).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "mov.l"
        assert insn.insn_type == "LOAD"
        assert insn.rd == 3
        # PC-aligned target: (0x200 + 4 & ~3) + 3*4 = 0x204 + 12 = 0x210
        assert insn.imm == 0x210


# ---------------------------------------------------------------------------
# decode_one — 32-bit SH-2A instructions
# ---------------------------------------------------------------------------

class TestDecodeOne32bit:
    def test_decode_movi20(self):
        # MOVI20 #0x1ABCD, R2: 0000 0010 0001 0101 = 0x0215, lo = 0xABCD
        # bits[11:8]=Rn=2, bits[7:4]=imm_hi=1, bits[3:0]=5 (opcode, fixed)
        hw = 0x0215
        lo = 0xABCD
        insn = _dec(_2hw(hw, lo), base_va=0).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "movi20"
        assert insn.is_32bit is True
        assert insn.rd == 2
        assert insn.imm == 0x1ABCD

    def test_decode_movi20s(self):
        # MOVI20S Rn=1, imm_hi=3: 0000 0001 0011 0111 = 0x0137
        hw = 0x0137
        lo = 0x1234
        insn = _dec(_2hw(hw, lo), base_va=0).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "movi20s"
        assert insn.is_32bit is True

    def test_decode_mov12(self):
        data = _2hw(0x3001, 0x4500)
        insn = _dec(data, base_va=0).decode_one(0)
        assert insn is not None
        assert insn.is_32bit is True
        assert insn.insn_type in ("LOAD", "STORE", "MISC")

    def test_32bit_insn_raw_is_4_bytes(self):
        data = _2hw(0x00E5, 0x0000)
        insn = _dec(data, base_va=0).decode_one(0)
        assert insn is not None
        assert len(insn.raw) == 4

    def test_movi20_negative_immediate(self):
        # MOVI20 with imm_hi=0xF → imm20=0xF0000 → negative: 0000 0000 1111 0101 = 0x00F5
        hw = 0x00F5
        lo = 0x0000
        insn = _dec(_2hw(hw, lo), base_va=0).decode_one(0)
        assert insn is not None
        assert insn.mnemonic == "movi20"
        assert insn.imm < 0


# ---------------------------------------------------------------------------
# decode_one — EOF behaviour
# ---------------------------------------------------------------------------

class TestDecodeOneEOF:
    def test_returns_none_at_eof(self):
        dec = _dec(b"")
        assert dec.decode_one(0) is None

    def test_returns_none_when_32bit_truncated(self):
        # First halfword triggers 32-bit but there is no second halfword
        dec = _dec(_hw(0x00E5))
        assert dec.decode_one(0) is None


# ---------------------------------------------------------------------------
# disassemble
# ---------------------------------------------------------------------------

class TestDisassemble:
    def test_single_rts(self):
        insns = _dec(_hw(0x000B)).disassemble()
        assert len(insns) == 1
        assert insns[0].mnemonic == "rts"

    def test_sequence(self):
        # STS.L PR, @-R15 + RTS + NOP (3 instructions)
        data = _hw(0x4F22) + _hw(0x000B) + _hw(0x0009)
        insns = _dec(data).disassemble()
        assert len(insns) == 3
        assert insns[0].mnemonic == "sts.l"
        assert insns[1].mnemonic == "rts"
        assert insns[2].mnemonic == "nop"

    def test_range_start_end(self):
        data = _hw(0x0009) + _hw(0x000B) + _hw(0x0009)
        # Only decode the middle instruction
        insns = _dec(data).disassemble(start=2, end=4)
        assert len(insns) == 1
        assert insns[0].mnemonic == "rts"

    def test_32bit_in_sequence(self):
        # MOVI20 R0, #0 (32-bit) followed by NOP (16-bit)
        data = _2hw(0x00E5, 0x0000) + _hw(0x0009)
        insns = _dec(data).disassemble()
        assert len(insns) == 2
        assert insns[0].is_32bit is True
        assert insns[1].mnemonic == "nop"

    def test_base_va_applied(self):
        data = _hw(0x000B)
        insns = _dec(data, base_va=0x1000).disassemble()
        assert insns[0].offset == 0x1000

    def test_empty_data_returns_empty_list(self):
        assert _dec(b"").disassemble() == []


# ---------------------------------------------------------------------------
# function_starts
# ---------------------------------------------------------------------------

class TestFunctionStarts:
    def test_detects_primary_prologue(self):
        # STS.L PR, @-R15 at offset 0
        data = _hw(0x4F22) + _hw(0x000B)
        starts = _dec(data).function_starts()
        assert 0 in starts

    def test_detects_leaf_prologue(self):
        # STS PR, R5 = 0x052A at offset 4 (not after STS.L PR)
        data = _hw(0x0009) + _hw(0x0009) + _hw(0x052A) + _hw(0x000B)
        starts = _dec(data, base_va=0).function_starts()
        assert 4 in starts

    def test_leaf_after_sts_l_not_counted_twice(self):
        # STS.L PR at 0, STS PR,R5 at 2 — should yield exactly one start (0)
        data = _hw(0x4F22) + _hw(0x052A)
        starts = _dec(data).function_starts()
        assert starts == [0]

    def test_multiple_functions(self):
        # STS.L at 0, NOP, NOP, STS.L at 6
        data = _hw(0x4F22) + _hw(0x0009) + _hw(0x0009) + _hw(0x4F22)
        starts = _dec(data).function_starts()
        assert 0 in starts
        assert 6 in starts

    def test_base_va_applied(self):
        data = _hw(0x4F22) + _hw(0x000B)
        starts = _dec(data, base_va=0x8000).function_starts()
        assert 0x8000 in starts

    def test_returns_sorted_list(self):
        # Two STS.L instructions, ensure sorted order
        data = _hw(0x4F22) + _hw(0x0009) + _hw(0x4F22)
        starts = _dec(data, base_va=0).function_starts()
        assert starts == sorted(starts)

    def test_no_false_positives_from_rts(self):
        data = _hw(0x000B) * 10  # 10 RTS — no function starts
        starts = _dec(data).function_starts()
        assert len(starts) == 0

    def test_empty_data_returns_empty(self):
        assert _dec(b"").function_starts() == []


# ---------------------------------------------------------------------------
# _is_32bit static method
# ---------------------------------------------------------------------------

class TestIs32bit:
    @pytest.mark.parametrize("hw", [
        0x3001, 0x3009,    # base forms (Rn=0, Rm=0)
        0x3231, 0x3FF9,    # Rn/Rm vary in bits[11:4]; bits[15:12]=3 and bits[3:0]=1/9 fixed
    ])
    def test_32bit_patterns_3001_3009(self, hw):
        assert EcuSH2aDecoder._is_32bit(hw) is True

    @pytest.mark.parametrize("hw", [
        0x0005,  # MOVI20 Rn=0, imm_hi=0
        0x05E5,  # MOVI20 Rn=5, imm_hi=0xE
        0x00F5,  # MOVI20 Rn=0, imm_hi=0xF
    ])
    def test_32bit_movi20(self, hw):
        assert EcuSH2aDecoder._is_32bit(hw) is True

    @pytest.mark.parametrize("hw", [
        0x0007,  # MOVI20S Rn=0, imm_hi=0
        0x0307,  # MOVI20S Rn=3, imm_hi=0
        0x05E7,  # MOVI20S Rn=5, imm_hi=0xE
    ])
    def test_32bit_movi20s(self, hw):
        assert EcuSH2aDecoder._is_32bit(hw) is True

    @pytest.mark.parametrize("hw", [
        0x4F22, 0x000B, 0x0009, 0xA000, 0xB000, 0xD000, 0x8900,
    ])
    def test_16bit_patterns(self, hw):
        assert EcuSH2aDecoder._is_32bit(hw) is False


# ---------------------------------------------------------------------------
# FileNotFoundError wrapping
# ---------------------------------------------------------------------------

class TestFileNotFoundError:
    def test_wraps_missing_file(self):
        with pytest.raises(FileNotFoundError, match="EcuSH2aDecoder"):
            EcuSH2aDecoder("/no/such/file.bin")


# ---------------------------------------------------------------------------
# from_path and from_bytes constructors
# ---------------------------------------------------------------------------

class TestConstructors:
    def test_from_bytes_returns_instance(self):
        dec = EcuSH2aDecoder.from_bytes(_hw(0x000B))
        assert dec is not None

    def test_from_path_missing_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            EcuSH2aDecoder.from_path(tmp_path / "missing.bin")

    def test_from_path_valid(self, tmp_path):
        p = tmp_path / "test.bin"
        p.write_bytes(_hw(0x000B))
        dec = EcuSH2aDecoder.from_path(p)
        assert dec.decode_one(0).mnemonic == "rts"


# ---------------------------------------------------------------------------
# SH2aInsn __str__
# ---------------------------------------------------------------------------

class TestSH2aInsnStr:
    def test_str_contains_mnemonic(self):
        insn = _dec(_hw(0x000B)).decode_one(0)
        assert "rts" in str(insn)

    def test_str_contains_va(self):
        insn = _dec(_hw(0x000B), base_va=0x2000).decode_one(0)
        assert "2000" in str(insn).lower()

    def test_str_shows_width(self):
        insn = _dec(_hw(0x4F22)).decode_one(0)
        assert "SH16" in str(insn)

    def test_str_32bit_shows_width(self):
        insn = _dec(_2hw(0x00E5, 0x0000)).decode_one(0)
        assert "SH32" in str(insn)
