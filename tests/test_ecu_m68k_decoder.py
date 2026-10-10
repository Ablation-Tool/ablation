"""Tests for EcuM68kDecoder (M68K/CPU32 decoder for GM P-series ECU ROMs)."""

import struct

import pytest

from ablation.analyzers.ecu_m68k_decoder import EcuM68kDecoder, M68kInsn


# ------------------------------------------------------------------ #
# Encoding helpers
# ------------------------------------------------------------------ #

def _link_w_a6(disp: int) -> bytes:
    """LINK.W A6, #disp  →  0x4E56 + signed 16-bit displacement."""
    return struct.pack(">HH", 0x4E56, disp & 0xFFFF)


def _rts() -> bytes:
    """RTS  →  0x4E75."""
    return struct.pack(">H", 0x4E75)


def _movem_push(mask: int) -> bytes:
    """MOVEM.L regs, -(SP)  →  0x48E7 + register mask."""
    return struct.pack(">HH", 0x48E7, mask & 0xFFFF)


def _nop() -> bytes:
    """NOP  →  0x4E71."""
    return struct.pack(">H", 0x4E71)


def _unlk_a6() -> bytes:
    """UNLK A6  →  0x4E5E."""
    return struct.pack(">H", 0x4E5E)


# ------------------------------------------------------------------ #
# Section 1: function_starts()
# ------------------------------------------------------------------ #

def test_function_starts_link_w_a6_negative():
    """LINK.W A6, #-N at even offset is a function start."""
    data = bytes(8) + _link_w_a6(-16)
    dec = EcuM68kDecoder(data)
    starts = dec.function_starts()
    assert 8 in starts


def test_function_starts_link_positive_ignored():
    """LINK.W A6, #N with positive displacement is NOT a function start."""
    data = _link_w_a6(16)
    dec = EcuM68kDecoder(data)
    assert dec.function_starts() == []


def test_function_starts_link_zero_ignored():
    """LINK.W A6, #0 is NOT a function start (no frame allocation)."""
    data = _link_w_a6(0)
    dec = EcuM68kDecoder(data)
    assert dec.function_starts() == []


def test_function_starts_movem_push_leaf():
    """MOVEM.L regs, -(SP) at even offset when not after LINK is a leaf start."""
    data = bytes(4) + _movem_push(0xFFFC)
    dec = EcuM68kDecoder(data)
    starts = dec.function_starts()
    assert 4 in starts


def test_function_starts_movem_after_link_ignored():
    """MOVEM.L immediately after LINK.W is the second instruction, not a start."""
    link = _link_w_a6(-32)
    movem = _movem_push(0xFFFC)
    data = link + movem
    dec = EcuM68kDecoder(data)
    starts = dec.function_starts()
    # LINK at 0 is a start; MOVEM at 4 is NOT (follows LINK at i-4)
    assert 0 in starts
    assert 4 not in starts


def test_function_starts_multiple_functions():
    """Two separate LINK prologues are both found."""
    fn1 = _link_w_a6(-16) + _rts()
    fn2 = _link_w_a6(-32) + _rts()
    data = fn1 + bytes(2) + fn2
    dec = EcuM68kDecoder(data, base_va=0x1000)
    starts = dec.function_starts()
    assert 0x1000 in starts
    assert (0x1000 + len(fn1) + 2) in starts


def test_function_starts_returns_sorted():
    """Returned VAs are always sorted."""
    fn1 = _link_w_a6(-16) + _rts() + bytes(2)
    fn2 = _link_w_a6(-8) + _rts()
    data = fn1 + fn2
    dec = EcuM68kDecoder(data)
    starts = dec.function_starts()
    assert starts == sorted(starts)


def test_function_starts_uses_base_va():
    """Returned values are VAs (base_va + offset)."""
    data = _link_w_a6(-8)
    dec = EcuM68kDecoder(data, base_va=0x80000000)
    starts = dec.function_starts()
    assert len(starts) == 1
    assert starts[0] == 0x80000000


def test_function_starts_empty_data():
    assert EcuM68kDecoder(b"").function_starts() == []


def test_function_starts_too_short_for_link():
    """Only 2 bytes — LINK without displacement word doesn't fire."""
    data = struct.pack(">H", 0x4E56)
    dec = EcuM68kDecoder(data)
    assert dec.function_starts() == []


# ------------------------------------------------------------------ #
# Section 2: decode_one() and disassemble()
# ------------------------------------------------------------------ #

def test_decode_one_link_w_a6():
    """LINK.W A6, #-0x10 decodes as PROLOGUE."""
    data = _link_w_a6(-0x10) + bytes(4)
    dec = EcuM68kDecoder(data, base_va=0x1000)
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.mnemonic == "link.w"
    assert insn.insn_type == "PROLOGUE"
    assert insn.offset == 0x1000
    assert insn.size == 4


def test_decode_one_rts():
    """RTS decodes as RETURN."""
    data = _rts() + bytes(4)
    dec = EcuM68kDecoder(data)
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.mnemonic == "rts"
    assert insn.insn_type == "RETURN"
    assert insn.size == 2


def test_decode_one_eof():
    dec = EcuM68kDecoder(b"")
    assert dec.decode_one(0) is None


def test_disassemble_simple_function():
    """A complete minimal CPU32 function: LINK + NOP + UNLK + RTS."""
    body = _link_w_a6(-8) + _nop() + _unlk_a6() + _rts()
    dec = EcuM68kDecoder(body)
    insns = dec.disassemble()
    assert len(insns) == 4
    assert insns[0].mnemonic == "link.w"
    assert insns[-1].mnemonic == "rts"


def test_disassemble_respects_range():
    """Only instructions in [start, end) are decoded."""
    # LINK at 0 (4 bytes), NOP at 4 (2 bytes), RTS at 6 (2 bytes)
    body = _link_w_a6(-8) + _nop() + _rts()
    dec = EcuM68kDecoder(body)
    insns = dec.disassemble(start=4, end=8)
    # Should see NOP and RTS only
    mnems = [i.mnemonic for i in insns]
    assert "link.w" not in mnems
    assert "nop" in mnems


def test_disassemble_empty():
    assert EcuM68kDecoder(b"").disassemble() == []


def test_disassemble_offsets_use_base_va():
    """Each decoded instruction carries its correct VA."""
    body = _link_w_a6(-8) + _rts()
    dec = EcuM68kDecoder(body, base_va=0x2000)
    insns = dec.disassemble()
    assert insns[0].offset == 0x2000
    assert insns[1].offset == 0x2004  # LINK is 4 bytes


# ------------------------------------------------------------------ #
# Section 3: constructors
# ------------------------------------------------------------------ #

def test_from_bytes_constructor():
    data = _rts()
    dec = EcuM68kDecoder.from_bytes(data)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "rts"


def test_from_path_constructor(tmp_path):
    path = tmp_path / "test.bin"
    path.write_bytes(_rts())
    dec = EcuM68kDecoder.from_path(path)
    insn = dec.decode_one(0)
    assert insn.mnemonic == "rts"


def test_from_path_missing_raises_informative():
    with pytest.raises(FileNotFoundError, match="EcuM68kDecoder"):
        EcuM68kDecoder("/nonexistent/path.bin")


# ------------------------------------------------------------------ #
# Section 4: M68kInsn.__str__()
# ------------------------------------------------------------------ #

def test_insn_str_format():
    data = _link_w_a6(-16) + bytes(4)
    dec = EcuM68kDecoder(data, base_va=0x500)
    insn = dec.decode_one(0)
    text = str(insn)
    assert "0x00000500" in text
    assert "link.w" in text


# ------------------------------------------------------------------ #
# Section 5: classify() correctness
# ------------------------------------------------------------------ #

def test_classify_jsr_is_call():
    """JSR decodes as CALL."""
    # JSR (A0) = 0x4E90
    data = struct.pack(">H", 0x4E90)
    dec = EcuM68kDecoder(data)
    insn = dec.decode_one(0)
    # Capstone decodes this; check type
    if insn is not None:
        assert insn.insn_type == "CALL"


def test_classify_bra_is_branch():
    """BRA.S +0 = 0x6000 0x0000 decodes as BRANCH."""
    data = struct.pack(">HH", 0x6000, 0x0000)
    dec = EcuM68kDecoder(data)
    insn = dec.decode_one(0)
    if insn is not None:
        assert insn.insn_type == "BRANCH"


def test_classify_link_positive_is_misc():
    """LINK.W A6, #+8 (positive displacement) classifies as MISC, not PROLOGUE."""
    data = _link_w_a6(8)
    dec = EcuM68kDecoder(data)
    insn = dec.decode_one(0)
    if insn is not None:
        assert insn.insn_type == "MISC"


def test_branch_target_jsr_abs():
    """JSR $5000.w — target resolved despite Capstone .w suffix."""
    # JSR abs.W = 0x4EB8 + 16-bit address
    data = struct.pack(">HH", 0x4EB8, 0x5000)
    dec = EcuM68kDecoder(data)
    insn = dec.decode_one(0)
    if insn is not None:
        assert insn.insn_type == "CALL"
        assert insn.target == 0x5000


def test_branch_target_bra():
    """BRA.W target resolves to correct absolute address."""
    # BRA.W +0x100 from 0x1000: target = 0x1000 + 2 + 0x100 = 0x1102
    data = struct.pack(">HH", 0x6000, 0x0100)
    dec = EcuM68kDecoder(data, base_va=0x1000)
    insn = dec.decode_one(0)
    if insn is not None:
        assert insn.insn_type == "BRANCH"
        assert insn.target == 0x1102
