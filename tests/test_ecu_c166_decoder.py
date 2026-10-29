"""Tests for EcuC166Decoder (Infineon/Siemens C166/C167 ISA, AG-8)."""

import struct

import pytest

from ablation.analyzers.ecu_c166_decoder import (
    C166Insn,
    EcuC166Decoder,
    IVTEntry,
)


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _mov_imm(reg: int, imm: int) -> bytes:
    """E6 Rn, #imm16  (4 bytes, LE immediate)."""
    return bytes([0xE6, 0xF0 | (reg & 0xF)]) + struct.pack('<H', imm & 0xFFFF)


def _cmp_imm(reg: int, imm: int) -> bytes:
    """46 Rn, #imm16  (4 bytes, LE immediate)."""
    return bytes([0x46, 0xF0 | (reg & 0xF)]) + struct.pack('<H', imm & 0xFFFF)


def _jmps(seg: int, addr: int) -> bytes:
    """FA seg lo hi  (4 bytes)."""
    return bytes([0xFA, seg & 0xFF]) + struct.pack('<H', addr & 0xFFFF)


def _calls(seg: int, addr: int) -> bytes:
    """DA seg lo hi  (4 bytes)."""
    return bytes([0xDA, seg & 0xFF]) + struct.pack('<H', addr & 0xFFFF)


def _ld_mem(reg: int, addr: int) -> bytes:
    """F2 Rn lo hi — load from direct address (4 bytes)."""
    return bytes([0xF2, 0xF0 | (reg & 0xF)]) + struct.pack('<H', addr & 0xFFFF)


def _st_mem(reg: int, addr: int) -> bytes:
    """F6 Rn lo hi — store to direct address (4 bytes)."""
    return bytes([0xF6, 0xF0 | (reg & 0xF)]) + struct.pack('<H', addr & 0xFFFF)


def _ld_direct(reg: int, addr: int) -> bytes:
    """F2 Rn lo hi — MOV Rn, [addr] direct load (4 bytes)."""
    return bytes([0xF2, 0xF0 | (reg & 0xF)]) + struct.pack('<H', addr & 0xFFFF)


def _ld_indirect(dst: int, base: int) -> bytes:
    """D4 — MOV Rdst, [Rbase + #0] register-indirect load."""
    return bytes([0xD4, ((dst & 0xF) << 4) | (base & 0xF), 0x00, 0x00])


def _st_indirect(src: int, base: int) -> bytes:
    """C4 — MOV [Rbase + #0], Rsrc register-indirect store."""
    return bytes([0xC4, ((src & 0xF) << 4) | (base & 0xF), 0x00, 0x00])


def _nop_2b() -> bytes:
    """An undefined two-byte operation used as a walk placeholder."""
    return bytes([0xF8, 0x00])


def _ivt_entry(seg: int, addr: int) -> bytes:
    """Single 4-byte IVT entry: JMPS seg, addr."""
    return _jmps(seg, addr)


def _make_rom(body: bytes, size: int = 0x8000) -> bytes:
    """Pad body to a power-of-2 size with 0xFF fill."""
    assert len(body) <= size
    return body + bytes([0xFF] * (size - len(body)))


def _make_ivt_rom(num_vectors: int = 64, size: int = 0x8000) -> bytes:
    """Build a synthetic ROM whose first num_vectors×4 bytes are valid FA entries."""
    ivt = b''
    for i in range(num_vectors):
        ivt += _ivt_entry(0x00, 0x1000 + i * 0x10)
    return _make_rom(ivt, size)


# ---------------------------------------------------------------------------
# Section 1 — is_c166_rom()
# ---------------------------------------------------------------------------

def test_is_c166_rom_true_64_fa_entries():
    """A ROM with 64 JMPS (FA) entries in the IVT is detected as C166."""
    rom = _make_ivt_rom(64)
    dec = EcuC166Decoder(rom)
    assert dec.is_c166_rom() is True


def test_is_c166_rom_32_entries_still_true():
    """32 FA entries out of 64 meets the ≥32 threshold."""
    ivt = b''
    for i in range(64):
        ivt += _ivt_entry(0x00, 0x1000) if i % 2 == 0 else bytes([0x00, 0x01, 0x02, 0x03])
    dec = EcuC166Decoder(_make_rom(ivt))
    assert dec.is_c166_rom() is True


def test_is_c166_rom_false_for_zero_fill():
    """A ROM filled with zeros has no 0xFA opcodes → not C166."""
    dec = EcuC166Decoder(bytes(0x8000))
    assert dec.is_c166_rom() is False


def test_is_c166_rom_false_for_random_non_fa():
    """A ROM with 0x00 IVT entries (M68K-style) is not detected as C166."""
    body = bytes([0x4E, 0x56, 0x00, 0x00] * 64)  # M68K LINK.W pattern
    dec = EcuC166Decoder(_make_rom(body))
    assert dec.is_c166_rom() is False


# ---------------------------------------------------------------------------
# Section 2 — insn_length()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('opcode', [0xE6, 0x66, 0xFA, 0xDA, 0xF2, 0xF6, 0xC2, 0xA2, 0xB2])
def test_insn_length_4_for_known_4byte_opcodes(opcode):
    data = _make_rom(bytes([opcode, 0xF0, 0x00, 0x00]))
    dec = EcuC166Decoder(data)
    assert dec.insn_length(0) == 4


@pytest.mark.parametrize('opcode', [0x00, 0x0D, 0x2D, 0xF8, 0xF0, 0xEC, 0xFC])
def test_insn_length_2_for_known_2byte_opcodes(opcode):
    data = _make_rom(bytes([opcode, 0x00]))
    dec = EcuC166Decoder(data)
    assert dec.insn_length(0) == 2


def test_insn_length_0_at_end_of_data():
    data = _make_rom(b'')
    dec = EcuC166Decoder(data)
    assert dec.insn_length(len(data)) == 0


# ---------------------------------------------------------------------------
# Section 3 — decode_one(): E6 MOV_IMM
# ---------------------------------------------------------------------------

def test_decode_mov_imm_register_and_value():
    """MOV R12, #0x96AE — confirmed MS43 byte pattern."""
    raw = _mov_imm(12, 0x96AE)  # e6 fc ae 96
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'MOV_IMM'
    assert insn.reg == 12
    assert insn.imm == 0x96AE
    assert insn.raw == raw


def test_decode_mov_imm_r0_response_0x67():
    """MOV RC, #0x0067 — SA response code."""
    raw = _mov_imm(12, 0x0067)  # e6 fc 67 00
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.imm == 0x0067
    assert insn.reg == 12


def test_decode_mov_imm_all_registers():
    """Register nibble extraction is correct for R0–R15."""
    for r in range(16):
        raw = _mov_imm(r, 0x1234)
        dec = EcuC166Decoder(_make_rom(raw))
        insn = dec.decode_one(0)
        assert insn is not None and insn.reg == r


# ---------------------------------------------------------------------------
# Section 4 — decode_one(): 46 CMP_IMM
# ---------------------------------------------------------------------------

def test_decode_cmp_imm_r4_0x0020():
    raw = _cmp_imm(4, 0x0020)
    assert raw == bytes.fromhex('46 F4 20 00')
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'CMP_IMM'
    assert insn.reg == 4
    assert insn.imm == 0x0020


# ---------------------------------------------------------------------------
# Section 5 — decode_one(): FA JMPS / DA CALLS
# ---------------------------------------------------------------------------

def test_decode_jmps_seg0_same_rom():
    """JMPS within the same ROM segment resolves to file offset = addr."""
    raw = _jmps(0x00, 0x2D06)   # fa 00 06 2d — confirmed reset vector
    dec = EcuC166Decoder(_make_rom(raw, 0x80000))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'JMPS'
    assert insn.seg == 0x00
    assert insn.imm == 0x2D06
    assert insn.target == 0x2D06


def test_decode_calls_seg0a_mirror():
    """CALLS 0x0A,0xB46E — seg 0x0A in 512KB ROM resolves to file off 0x02B46E."""
    raw = _calls(0x0A, 0xB46E)  # da 0a 6e b4 — confirmed seed_fetch call
    dec = EcuC166Decoder(_make_rom(raw, 0x80000))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'CALLS'
    assert insn.seg == 0x0A
    assert insn.imm == 0xB46E
    # seg 0x0A in 512KB (0x80000): (0x0A*0x10000 + 0xB46E) & 0x7FFFF = 0x02B46E
    assert insn.target == 0x02B46E


def test_decode_jmps_seg0e_mirror():
    """JMPS 0x0E,0x4 in 512KB ROM folds seg 0x0E → seg 0x06."""
    raw = _jmps(0x0E, 0x0004)
    dec = EcuC166Decoder(_make_rom(raw, 0x80000))
    insn = dec.decode_one(0)
    assert insn.target == (0x0E * 0x10000 + 0x0004) & 0x7FFFF


# ---------------------------------------------------------------------------
# Section 6 — decode_one(): F2/F6 memory load/store
# ---------------------------------------------------------------------------

def test_decode_ld_mem_from_sfr():
    """MOV R0, [0xF024] — load from ESFR (confirmed reset handler pattern)."""
    raw = _ld_mem(0, 0xF024)    # f2 f0 24 f0
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'MOV_LD'
    assert insn.reg == 0
    assert insn.imm == 0xF024


def test_decode_st_mem_to_peripheral():
    """MOV [0xE18E], R4 — store to DS2 peripheral register."""
    raw = _st_mem(4, 0xE18E)    # f6 f4 8e e1
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'MOV_ST'
    assert insn.reg == 4
    assert insn.imm == 0xE18E


# ---------------------------------------------------------------------------
# Section 7 — decode_one(): F2 direct-address load
# ---------------------------------------------------------------------------

def test_decode_ld_direct_r4_xram():
    raw = _ld_direct(4, 0x96B8)
    assert raw == bytes.fromhex('F2 F4 B8 96')
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'MOV_LD'
    assert insn.reg == 4
    assert insn.imm == 0x96B8


# ---------------------------------------------------------------------------
# Section 8 — decode_one(): D4/C4 register-indirect
# ---------------------------------------------------------------------------

def test_decode_ld_indirect():
    raw = _ld_indirect(dst=4, base=12)
    assert raw == bytes.fromhex('D4 4C 00 00')
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'MOV_LD'
    assert insn.reg == 4


def test_decode_st_indirect():
    raw = _st_indirect(src=4, base=12)
    assert raw == bytes.fromhex('C4 4C 00 00')
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'MOV_ST'
    assert insn.reg == 4


# ---------------------------------------------------------------------------
# Section 9 — decode_one(): unknown 2-byte
# ---------------------------------------------------------------------------

def test_decode_unknown_2b():
    """Undefined opcode 0xF8 remains an explicit two-byte unknown."""
    data = _make_rom(bytes([0xF8, 0x07, 0xE6, 0xF4, 0x20, 0x00]))
    dec = EcuC166Decoder(data)
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'UNKNOWN_2B'
    assert len(insn.raw) == 2


def test_decode_returns_none_at_end():
    data = _make_rom(b'')
    dec = EcuC166Decoder(data)
    # offset past the end should return None
    assert dec.decode_one(len(data)) is None


def test_decode_returns_none_for_truncated_4b():
    """A 4-byte opcode at the last 3 bytes returns None (not enough data)."""
    data = _make_rom(bytes([0xE6, 0xF4, 0x20]))   # only 3 bytes for E6 instruction
    dec = EcuC166Decoder(data)
    # The E6 is at offset 0, but there are 0x7FFD more 0xFF bytes after it —
    # so it won't actually truncate at offset 0. Put it at the very end:
    body = bytes([0xFF] * (0x8000 - 3)) + bytes([0xE6, 0xF4, 0x20])
    dec2 = EcuC166Decoder(body)
    assert dec2.decode_one(0x8000 - 3) is None


# ---------------------------------------------------------------------------
# Section 10 — disassemble()
# ---------------------------------------------------------------------------

def test_disassemble_mixed_sequence():
    """A synthetic sequence with 4-byte and 2-byte instructions."""
    body = (
        _mov_imm(12, 0x96AE)    # 4B E6
        + _nop_2b()              # 2B unknown
        + _cmp_imm(4, 0x0020)   # 4B 46
        + _calls(0x0A, 0xB46E)  # 4B DA
    )
    rom = _make_rom(body)
    dec = EcuC166Decoder(rom)
    insns = dec.disassemble(0, len(body))
    assert len(insns) == 4
    assert insns[0].insn_type == 'MOV_IMM'
    assert insns[1].insn_type == 'UNKNOWN_2B'
    assert insns[2].insn_type == 'CMP_IMM'
    assert insns[3].insn_type == 'CALLS'


def test_disassemble_pa_range():
    """disassemble(start_pa, end_pa) uses physical addresses, not file offsets."""
    body = _mov_imm(12, 0x1234) + _cmp_imm(4, 0x5678)
    rom = _make_rom(body)
    dec = EcuC166Decoder(rom, base_pa=0x1000)
    insns = dec.disassemble(0x1000, 0x1008)
    assert len(insns) == 2
    assert insns[0].pa == 0x1000
    assert insns[1].pa == 0x1004


def test_disassemble_empty_range():
    dec = EcuC166Decoder(_make_rom(b''))
    assert dec.disassemble(0, 0) == []


# ---------------------------------------------------------------------------
# Section 11 — parse_ivt()
# ---------------------------------------------------------------------------

def test_parse_ivt_all_fa_entries():
    """All 64 FA IVT entries are parsed with correct seg/addr/target."""
    rom = _make_ivt_rom(64, size=0x8000)
    dec = EcuC166Decoder(rom)
    ivt = dec.parse_ivt()
    assert len(ivt) == 64
    for i, e in enumerate(ivt):
        assert e.index == i
        assert e.pa == i * 4
        assert e.seg == 0x00
        assert e.addr == 0x1000 + i * 0x10
        assert e.target_pa == 0x1000 + i * 0x10


def test_parse_ivt_skips_non_fa():
    """IVT entries whose first byte is not 0xFA are skipped."""
    ivt = _ivt_entry(0, 0x1000) + bytes([0x00, 0x01, 0x02, 0x03]) + _ivt_entry(0, 0x2000)
    rom = _make_rom(ivt)
    dec = EcuC166Decoder(rom)
    parsed = dec.parse_ivt(num_vectors=3)
    assert len(parsed) == 2
    assert parsed[0].index == 0
    assert parsed[1].index == 2


def test_parse_ivt_target_pa_for_mirror_seg():
    """IVT entry with seg=0x0E in 512KB ROM folds to a valid file offset."""
    ivt = _jmps(0x0E, 0xEE04)
    rom = _make_rom(ivt, size=0x80000)
    dec = EcuC166Decoder(rom)
    e = dec.parse_ivt(1)[0]
    assert e.seg == 0x0E
    assert e.addr == 0xEE04
    # (0x0E * 0x10000 + 0xEE04) & 0x7FFFF = 0x06EE04
    assert e.target_pa == 0x06EE04


# ---------------------------------------------------------------------------
# Section 12 — scan_xram_loads() / scan_xram_stores()
# ---------------------------------------------------------------------------

def test_scan_xram_loads_finds_mov_imm():
    """scan_xram_loads finds all E6 MOV_IMM instructions loading a pointer value."""
    body = (
        _mov_imm(12, 0x96AE)     # hit 1
        + _cmp_imm(4, 0x0020)    # not a hit
        + _mov_imm(13, 0x96AE)   # hit 2
    )
    dec = EcuC166Decoder(_make_rom(body))
    hits = dec.scan_xram_loads(0x96AE)
    assert len(hits) == 2
    assert all(h.insn_type == 'MOV_IMM' for h in hits)
    assert hits[0].reg == 12
    assert hits[1].reg == 13


def test_scan_xram_loads_finds_ld_direct():
    """scan_xram_loads finds F2 direct-address loads of the target address."""
    body = _ld_direct(4, 0x96B8)
    dec = EcuC166Decoder(_make_rom(body))
    hits = dec.scan_xram_loads(0x96B8)
    assert len(hits) == 1
    assert hits[0].insn_type == 'MOV_LD'


def test_scan_xram_stores_finds_f6():
    """scan_xram_stores finds F6 store instructions writing to the target address."""
    body = (
        _st_mem(4, 0xE18E)   # hit
        + _ld_mem(4, 0xE18E)  # not a hit (it's a load)
    )
    dec = EcuC166Decoder(_make_rom(body))
    hits = dec.scan_xram_stores(0xE18E)
    assert len(hits) == 1
    assert hits[0].insn_type == 'MOV_ST'
    assert hits[0].imm == 0xE18E


def test_scan_xram_loads_no_false_positive_on_store():
    """An F6 store to 0x96AE is NOT returned by scan_xram_loads."""
    body = _st_mem(4, 0x96AE)
    dec = EcuC166Decoder(_make_rom(body))
    assert dec.scan_xram_loads(0x96AE) == []


# ---------------------------------------------------------------------------
# Section 13 — function_starts()
# ---------------------------------------------------------------------------

def test_function_starts_returns_calls_targets():
    """function_starts returns resolved PAs for all DA (CALLS) instructions."""
    body = (
        _mov_imm(12, 0x96AE)   # not a call
        + _calls(0x0A, 0xB46E)  # call → target 0x02B46E in 512KB ROM
        + _calls(0x0C, 0x23EC)  # call → target 0x0423EC
    )
    dec = EcuC166Decoder(_make_rom(body, 0x80000))
    starts = dec.function_starts()
    assert 0x02B46E in starts
    assert 0x0423EC in starts


def test_function_starts_excludes_jmps():
    """JMPS (FA) targets are NOT included in function_starts."""
    body = _jmps(0x00, 0x1234)
    dec = EcuC166Decoder(_make_rom(body, 0x80000))
    assert dec.function_starts() == []


# ---------------------------------------------------------------------------
# Section 14 — resolve_pa()
# ---------------------------------------------------------------------------

def test_resolve_pa_seg0_identity():
    """Segment 0 maps directly to the address as file offset."""
    dec = EcuC166Decoder(_make_rom(b'', 0x80000))
    assert dec.resolve_pa(0x00, 0x2D06) == 0x2D06


def test_resolve_pa_mirror_seg0a():
    """Segment 0x0A in a 512KB ROM mirrors to segment 0x02."""
    dec = EcuC166Decoder(_make_rom(b'', 0x80000))
    # (0x0A * 0x10000 + 0xB46E) & 0x7FFFF = 0x02B46E
    assert dec.resolve_pa(0x0A, 0xB46E) == 0x02B46E


def test_resolve_pa_mirror_seg0c():
    """Segment 0x0C in a 512KB ROM mirrors to segment 0x04."""
    dec = EcuC166Decoder(_make_rom(b'', 0x80000))
    assert dec.resolve_pa(0x0C, 0x23EC) == 0x0423EC


def test_resolve_pa_mirror_seg0e():
    """Segment 0x0E in a 512KB ROM mirrors to segment 0x06."""
    dec = EcuC166Decoder(_make_rom(b'', 0x80000))
    assert dec.resolve_pa(0x0E, 0xEE04) == 0x06EE04


# ---------------------------------------------------------------------------
# Section 15 — constructor validation
# ---------------------------------------------------------------------------

def test_from_path_raises_on_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        EcuC166Decoder(tmp_path / 'nonexistent.bin')


def test_non_power_of_2_size_is_accepted_without_mirror_mask():
    dec = EcuC166Decoder(bytes(0x1234))
    assert dec.resolve_pa(0x0A, 0xB46E) == 0x0AB46E


def test_from_bytes_constructor():
    rom = _make_rom(_mov_imm(4, 0x1234))
    dec = EcuC166Decoder.from_bytes(rom)
    insn = dec.decode_one(0)
    assert insn is not None and insn.insn_type == 'MOV_IMM'


def test_from_path_constructor(tmp_path):
    rom = _make_rom(_mov_imm(4, 0xABCD))
    p = tmp_path / 'test.bin'
    p.write_bytes(rom)
    dec = EcuC166Decoder.from_path(p)
    insn = dec.decode_one(0)
    assert insn is not None and insn.imm == 0xABCD


# ---------------------------------------------------------------------------
# Section 16 — C166Insn properties
# ---------------------------------------------------------------------------

def test_insn_is_call_property():
    raw = _calls(0x00, 0x1234)
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn.is_call is True
    assert insn.is_branch is False


def test_insn_is_branch_property():
    raw = _jmps(0x00, 0x1234)
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn.is_branch is True
    assert insn.is_call is False


def test_insn_is_load_mov_imm():
    raw = _mov_imm(4, 0x1234)
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn.is_load is True
    assert insn.is_store is False


def test_insn_is_store():
    raw = _st_mem(4, 0x1234)
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn.is_store is True
    assert insn.is_load is False


def test_insn_str_format():
    raw = _mov_imm(12, 0x96AE)
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    s = str(insn)
    assert '0x000000' in s
    assert 'MOV' in s


# ---------------------------------------------------------------------------
# Section 17 — decode_one(): 2-byte confirmed encodings
# ---------------------------------------------------------------------------

def _push(reg: int) -> bytes:
    """PUSH reg: EC F0|reg, confirmed by C166 epilogues."""
    return bytes([0xEC, 0xF0 | (reg & 0xF)])


def _pop(reg: int) -> bytes:
    """POP reg: FC F0|reg, confirmed by C166 epilogues."""
    return bytes([0xFC, 0xF0 | (reg & 0xF)])


def _ret() -> bytes:
    """RETS: DB 00, the segmented return used by C166 applications."""
    return bytes([0xDB, 0x00])


def _jmpr(cc: int, rel: int) -> bytes:
    """JMPR cc, rel8: (cc<<4)|0x0D, signed rel — confirmed post-CMP branches."""
    return bytes([(cc & 0xF) << 4 | 0x0D, rel & 0xFF])


def _mov_reg(dst: int, src: int) -> bytes:
    """MOV Rdst, Rsrc: 0xF0 (dst<<4)|src — confirmed from seed_fetch prologue."""
    return bytes([0xF0, ((dst & 0xF) << 4) | (src & 0xF)])


def test_decode_push_r9():
    raw = _push(9)
    assert raw == bytes.fromhex('EC F9')
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'PUSH'
    assert insn.reg == 9
    assert 'PUSH' in insn.mnemonic and 'R9' in insn.mnemonic


def test_decode_push_r14():
    raw = _push(14)
    assert raw == bytes.fromhex('EC FE')
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'PUSH'
    assert insn.reg == 14


def test_decode_push_all_registers():
    """PUSH encodes all R0–R15 correctly."""
    for r in range(16):
        raw = _push(r)
        dec = EcuC166Decoder(_make_rom(raw))
        insn = dec.decode_one(0)
        assert insn is not None and insn.insn_type == 'PUSH' and insn.reg == r


def test_decode_pop_r8():
    raw = _pop(8)
    assert raw == bytes.fromhex('FC F8')
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'POP'
    assert insn.reg == 8


def test_decode_pop_all_registers():
    """POP encodes all R0–R15 correctly."""
    for r in range(16):
        raw = _pop(r)
        dec = EcuC166Decoder(_make_rom(raw))
        insn = dec.decode_one(0)
        assert insn is not None and insn.insn_type == 'POP' and insn.reg == r


def test_decode_rets():
    raw = _ret()
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'RETS'
    assert insn.mnemonic == 'RETS'


def test_decode_ret_is_not_branch_or_call():
    raw = _ret()
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn.is_branch is False
    assert insn.is_call is False


def test_decode_jmpr_uc_forward():
    """JMPR UC, +6: 0x0D 0x06 — confirmed unconditional branch."""
    raw = _jmpr(cc=0, rel=6)  # 0D 06
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'JMPR'
    assert insn.is_branch is True
    # target = 0 + 2 + 6*2 = 14 = 0x00000E
    assert insn.target == 14
    assert insn.imm == 6
    assert 'UC' in insn.mnemonic


def test_decode_jmpr_nz_condition():
    """JMPR NZ, +16: 0x2D 0x10 — confirmed post-CMP branch in init_ds2_sa_ctx."""
    raw = _jmpr(cc=2, rel=16)  # 2D 10
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'JMPR'
    assert insn.target == 2 + 32  # 0 + 2 + 16*2
    assert 'NZ' in insn.mnemonic


def test_decode_jmpr_backward_branch():
    """JMPR with negative rel — backward loop-back branch."""
    # cd ed: cc=C=SLE, rel=0xED=-19 (signed) → target = 0 + 2 + (-19)*2 = -36
    raw = bytes([0xCD, 0xED])
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'JMPR'
    # target = 0 + 2 + (-19)*2 = -36 (wraps in 32-bit, fine for a 24-bit addr space)
    assert insn.imm == -19
    assert 'SLE' in insn.mnemonic


def test_decode_jmpr_all_conditions():
    """JMPR decodes all 16 condition codes without error."""
    cc_names = ['UC','Z','NZ','V','NV','N','NN','C','NC','UGT','ULE','SGT','SLE','SLT','SGE','NET']
    for cc, name in enumerate(cc_names):
        raw = _jmpr(cc=cc, rel=1)
        dec = EcuC166Decoder(_make_rom(raw))
        insn = dec.decode_one(0)
        assert insn is not None and insn.insn_type == 'JMPR'
        assert name in insn.mnemonic


def test_decode_mov_reg_r8_rd():
    """MOV R8, RD: 0xF0 0x8D — confirmed seed_fetch prologue (save arg RD)."""
    raw = _mov_reg(dst=8, src=13)  # F0 8D
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'MOV_REG'
    assert insn.reg == 8
    assert 'MOV' in insn.mnemonic and 'R8' in insn.mnemonic and 'RD' in insn.mnemonic


def test_decode_mov_reg_r9_rc():
    """MOV R9, RC: 0xF0 0x9C — confirmed seed_fetch prologue (save arg RC)."""
    raw = _mov_reg(dst=9, src=12)  # F0 9C
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'MOV_REG'
    assert insn.reg == 9


def test_decode_mov_reg_all_pairs():
    """MOV_REG decodes all 256 register pair combinations without error."""
    for dst in range(16):
        for src in range(16):
            raw = _mov_reg(dst, src)
            dec = EcuC166Decoder(_make_rom(raw))
            insn = dec.decode_one(0)
            assert insn is not None
            assert insn.insn_type == 'MOV_REG'
            assert insn.reg == dst


def test_mov_reg_is_load_property():
    """MOV_REG is classified as a load (register ← register)."""
    raw = _mov_reg(dst=4, src=9)
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn.is_load is True
    assert insn.is_store is False


def test_disassemble_with_2byte_decoded():
    """disassemble() correctly steps through a mix with decoded 2-byte ops."""
    body = (
        _push(9)
        + _push(8)
        + _mov_reg(dst=8, src=13)
        + _mov_imm(4, 0x1234)
        + _jmpr(cc=2, rel=1)
        + _pop(8)
        + _pop(9)
        + _ret()
    )
    dec = EcuC166Decoder(_make_rom(body))
    insns = dec.disassemble(0, len(body))
    types = [i.insn_type for i in insns]
    assert types == ['PUSH', 'PUSH', 'MOV_REG', 'MOV_IMM', 'JMPR', 'POP', 'POP', 'RETS']


@pytest.mark.parametrize('hex_bytes, insn_type, mnemonic', [
    ('EC FD', 'PUSH', 'PUSH RD'),
    ('FC FD', 'POP', 'POP RD'),
    ('DB 00', 'RETS', 'RETS'),
    ('66 F4 20 00', 'AND_IMM', 'AND R4, #0x0020'),
    ('C2 FB 15 A1', 'MOVBZ', 'MOVBZ RH5, [0xa115]'),
    ('E0 14', 'MOV_IMM4', 'MOV R4, #1'),
    ('A6 F4 2C 01', 'CMPD', 'CMPD1 R4, #0x012c'),
    ('D4 44 96 8A', 'MOV_LD', 'MOV R4, [R4+#0x8a96]'),
    ('F4 CF 84 73', 'MOV_LD', 'MOVB RL6, [RF+#0x7384]'),
    ('E1 18', 'MOV_IMM4', 'MOVB RL4, #1'),
])
def test_cern_verified_decodes(hex_bytes, insn_type, mnemonic):
    raw = bytes.fromhex(hex_bytes)
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == insn_type
    assert insn.mnemonic == mnemonic


def test_cern_verified_jmpa_target():
    dec = EcuC166Decoder(_make_rom(bytes.fromhex('EA 00 64 09'), 0x8000), base_pa=0x20000)
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'JMPA'
    assert insn.target == 0x20964
    assert insn.is_branch is True


def test_dpp_address_translation_and_reference_scan():
    assert EcuC166Decoder.dpp_pa(0x45E9, 7) == 0x1C5E9
    assert EcuC166Decoder.dpp_offset(0x1C5E9, 7, 1) == 0x45E9
    with pytest.raises(ValueError, match='outside DPP page'):
        EcuC166Decoder.dpp_offset(0x1C5E9, 3, 1)

    dec = EcuC166Decoder(_make_rom(_mov_imm(9, 0x45E9)))
    hits = dec.scan_dpp_loads(0x1C5E9, 7, 1)
    assert len(hits) == 1
    assert hits[0].imm == 0x45E9


def test_ivt_can_start_at_boot_application_base():
    image = bytearray(0x401)
    for index in range(64):
        image[0x200 + index * 4:0x204 + index * 4] = _jmps(2, 0x0104)
    dec = EcuC166Decoder(bytes(image))
    entries = dec.parse_ivt(start_pa=0x200)
    assert len(entries) == 64
    assert entries[0].pa == 0x200
    assert entries[0].target_pa == 0x20104
    assert dec.is_c166_rom(start_pa=0x200) is True
    assert dec.is_c166_rom() is False


def test_negative_instruction_offsets_are_rejected():
    dec = EcuC166Decoder(_make_rom(b''))
    assert dec.insn_length(-1) == 0
    assert dec.decode_one(-1) is None


@pytest.mark.parametrize('raw, expected_reg, expected_imm', [
    (bytes.fromhex('29 81'), 8, 1),
    (bytes.fromhex('29 82'), 8, 2),
    (bytes.fromhex('29 07'), 0, 7),
    (bytes.fromhex('29 f0'), 15, 0),
])
def test_decode_subb_immediate(raw, expected_reg, expected_imm):
    dec = EcuC166Decoder(_make_rom(raw))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'SUBB_IMM'
    assert insn.reg == expected_reg
    assert insn.imm == expected_imm
    assert insn.raw == raw


def test_subb_other_addressing_modes_remain_explicitly_unknown():
    dec = EcuC166Decoder(_make_rom(bytes.fromhex('29 88')))
    insn = dec.decode_one(0)
    assert insn is not None
    assert insn.insn_type == 'UNKNOWN_2B'
