"""Tests for ablation/analyzers/isa_riscv.py utilities pulled from rvtaint."""
import pytest

from ablation.analyzers.isa_riscv import (
    canon_reg,
    is_reg,
    norm_imm12,
    andi_bound,
    andi_propagates,
)


# ---------------------------------------------------------------------------
# canon_reg
# ---------------------------------------------------------------------------

class TestCanonReg:
    def test_abi_name_passthrough(self):
        assert canon_reg("a0") == "a0"

    def test_x_numbered(self):
        assert canon_reg("x10") == "a0"

    def test_x0_is_zero(self):
        assert canon_reg("x0") == "zero"

    def test_x1_is_ra(self):
        assert canon_reg("x1") == "ra"

    def test_fp_alias(self):
        assert canon_reg("fp") == "s0"

    def test_uppercase_rejected(self):
        # canon_reg lowercases internally
        assert canon_reg("A0") == "a0"

    def test_immediate_returns_none(self):
        assert canon_reg("-16") is None
        assert canon_reg("0xff") is None
        assert canon_reg("4") is None

    def test_memory_expr_returns_none(self):
        assert canon_reg("0(sp)") is None

    def test_is_reg_true(self):
        assert is_reg("a1") is True
        assert is_reg("x2") is True

    def test_is_reg_false(self):
        assert is_reg("42") is False


# ---------------------------------------------------------------------------
# norm_imm12
# ---------------------------------------------------------------------------

class TestNormImm12:
    def test_negative_literal(self):
        assert norm_imm12(-16) == -16

    def test_unsigned_12bit(self):
        # 0xff0 = 4080 unsigned; signed 12-bit: 4080 - 4096 = -16
        assert norm_imm12(0xff0) == -16
        assert norm_imm12(4080) == -16

    def test_full_xlen64_form(self):
        # 0xfffffffffffffff0 sign-extended from -16
        assert norm_imm12(0xfffffffffffffff0, xlen=64) == -16

    def test_full_xlen32_form(self):
        # 0xfffffff0 sign-extended from -16 on RV32
        assert norm_imm12(0xfffffff0, xlen=32) == -16

    def test_positive_passthrough(self):
        assert norm_imm12(255) == 255
        assert norm_imm12(0) == 0

    def test_negative_one(self):
        # -1 as raw int
        assert norm_imm12(-1) == -1
        # -1 as full 12-bit unsigned: 0xfff = 4095 -> 4095 - 4096 = -1
        assert norm_imm12(0xfff) == -1

    def test_min_signed_12bit(self):
        assert norm_imm12(-2048) == -2048
        assert norm_imm12(0x800) == -2048

    def test_max_positive_12bit(self):
        assert norm_imm12(2047) == 2047
        assert norm_imm12(0x7ff) == 2047


# ---------------------------------------------------------------------------
# andi_bound
# ---------------------------------------------------------------------------

class TestAndiBound:
    def test_positive_imm_returns_bound(self):
        assert andi_bound(255) == 255
        assert andi_bound(0) == 0

    def test_negative_imm_returns_none(self):
        assert andi_bound(-16) is None
        assert andi_bound(-1) is None
        assert andi_bound(-2048) is None


# ---------------------------------------------------------------------------
# andi_propagates (the taint decision)
# ---------------------------------------------------------------------------

class TestAndiPropagates:
    def test_negative_literal_propagates(self):
        # -16 is alignment mask: no bound -> propagate
        assert _andi_propagates("-16") is True

    def test_negative_hex_propagates(self):
        assert _andi_propagates("-0x10") is True

    def test_unsigned_hex_alignment_propagates(self):
        # 0xff0 = -16 normalized -> propagate
        assert _andi_propagates("0xff0") is True

    def test_identity_mask_propagates(self):
        # -1 = rs & ~0 = rs: exact copy, MUST propagate
        assert _andi_propagates("-1") is True
        assert _andi_propagates("0xfff") is True

    def test_positive_imm_does_not_propagate(self):
        # 0xff = 255: bounding mask, sanitizes
        assert _andi_propagates("0xff") is False
        assert _andi_propagates("255") is False

    def test_zero_does_not_propagate(self):
        # andi rd, rs, 0: result is always 0 -- sanitizes
        assert _andi_propagates("0") is False

    def test_invalid_token_returns_false(self):
        assert _andi_propagates("a0") is False
        assert _andi_propagates("") is False


def _andi_propagates(token: str, xlen: int = 64) -> bool:
    return andi_propagates(token, xlen)
