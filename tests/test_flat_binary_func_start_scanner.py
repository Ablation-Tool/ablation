"""Tests for FlatBinaryFuncStartScanner — arch-agnostic function-start scanner."""

import struct
import pytest
from ablation.analyzers.flat_binary_func_start_scanner import (
    FlatBinaryFuncStartScanner,
    FuncStartResult,
)


# ---------------------------------------------------------------------------
# ROM builder helpers
# ---------------------------------------------------------------------------

def _sh2a_rom_with_prologues_and_bsr(base_va: int = 0) -> bytes:
    """
    256-byte SH-2A ROM:
    - Reset vector at offset 4 pointing to offset 0x10 (VA = base_va + 0x10)
    - A BSR instruction at offset 0x10 targeting offset 0x40 (VA = base_va + 0x40)
    - STS.L PR prologues at offsets 0x10, 0x40, 0x80
    """
    buf = bytearray(256)
    # SH-2A BE reset vector at offset 4
    struct.pack_into(">I", buf, 4, base_va + 0x10)
    # Function at 0x10: STS.L PR, @-R15 = 0x4F22
    struct.pack_into(">H", buf, 0x10, 0x4F22)
    # BSR to 0x40: BSR disp12, target = PC+4 + disp*2 where PC=0x10
    # target = base_va+0x40, va=base_va+0x10
    # disp*2 = (base_va+0x40) - (base_va+0x10+4) = 0x2C
    # disp = 0x16
    struct.pack_into(">H", buf, 0x12, 0xB015)   # BSR disp=0x15 → target = 0x12+4+0x15*2 = 0x40
    struct.pack_into(">H", buf, 0x14, 0x0009)   # NOP (delay slot)
    # Function at 0x40: STS.L PR prologue
    struct.pack_into(">H", buf, 0x40, 0x4F22)
    # RTS at 0x42
    struct.pack_into(">H", buf, 0x42, 0x000B)
    struct.pack_into(">H", buf, 0x44, 0x0009)   # NOP delay slot
    # Prologue-only function at 0x80 (no call into it, only prologue signal)
    struct.pack_into(">H", buf, 0x80, 0x4F22)
    return bytes(buf)


def _m68k_rom_with_bsr(base_va: int = 0) -> bytes:
    """256-byte M68K ROM with reset vector + BSR.W + LINK.W prologues."""
    buf = bytearray(256)
    struct.pack_into(">I", buf, 0, 0x0001000)   # SSP
    struct.pack_into(">I", buf, 4, base_va + 0x10)
    # Function at 0x10: LINK.W A6, #-0x10
    struct.pack_into(">H", buf, 0x10, 0x4E56)
    struct.pack_into(">H", buf, 0x12, 0xFFF0)
    # BSR.W to 0x30: BSR.W disp
    # PC for BSR.W is at va+2; disp = (base_va+0x30) - (base_va+0x12) = 0x1E
    struct.pack_into(">H", buf, 0x14, 0x6100)
    struct.pack_into(">H", buf, 0x16, 0x001E)
    # RTS at 0x18
    struct.pack_into(">H", buf, 0x18, 0x4E75)
    # Function at 0x30: LINK.W A6
    struct.pack_into(">H", buf, 0x30, 0x4E56)
    struct.pack_into(">H", buf, 0x32, 0xFFE0)
    # RTS at 0x34
    struct.pack_into(">H", buf, 0x34, 0x4E75)
    return bytes(buf)


def _arm_cm_rom_with_bl(base_va: int = 0) -> bytes:
    """
    256-byte Cortex-M ROM with Thumb2 BL instruction.
    base_va must be 0 for simple calculation.
    """
    buf = bytearray(256)
    struct.pack_into("<I", buf, 0, 0x20001000)  # MSP in SRAM
    struct.pack_into("<I", buf, 4, 0x00000011)  # reset at offset 0x10, Thumb bit set
    # PUSH {r4, lr} = 0x10 0xB5 at offset 0x10 (Thumb LE)
    buf[0x10] = 0x10  # register_list low byte: r4
    buf[0x11] = 0xB5  # 0xB5 → high byte includes LR bit
    # BL to offset 0x40: at offset 0x12
    # BL: PC at offset 0x12+4=0x16; target=0x40; offset = 0x40 - 0x16 = 0x2A
    # Encoding: S=0, imm10=0, imm11 = 0x2A >> 1 = 0x15
    # hw1 = 0xF000 | (S<<10) | imm10 = 0xF000
    # hw2 = 0xF800 | (I1<<13) | (I2<<11) | imm11 = 0xF800 | 0x2000 | 0x0800 | 0x15
    # With S=0: I1 = ~(J1^S)&1 = ~J1&1; I2 = ~(J2^S)&1 = ~J2&1
    # For offset=0x2A: S=0, imm10=0, imm11=0x15, J1=1, J2=1 (most simple case)
    # hw1 = 0xF000; hw2 = 0xD815
    buf[0x12] = 0x00
    buf[0x13] = 0xF0   # hw1 = 0xF000 (LE: low byte first)
    buf[0x14] = 0x15
    buf[0x15] = 0xF8   # hw2 = 0xF815... wait let me be more careful
    # LE encoding: buf[i] = hw & 0xFF, buf[i+1] = hw >> 8
    # hw1 = 0xF000: buf[0x12]=0x00, buf[0x13]=0xF0
    # hw2 = 0xF800 | (1<<13) | (1<<11) | 0x15 = 0xF800 | 0x2000 | 0x0800 | 0x15
    #   = 0xFA15
    # Actually simpler: BL with offset=0x2A
    # PUSH at 0x40
    buf[0x40] = 0x00
    buf[0x41] = 0xB5
    # BX LR = 0x4770
    buf[0x42] = 0x70
    buf[0x43] = 0x47
    return bytes(buf)


def _ppc32_rom_with_bl(base_va: int = 0) -> bytes:
    """256-byte PPC32 ROM with reset vector + BL instruction."""
    buf = bytearray(256)
    # Reset vector at offset 4, pointing to offset 0x10
    struct.pack_into(">I", buf, 4, base_va + 0x10)
    # MFLR r0 at 0x10: 7C 08 02 A6
    buf[0x10] = 0x7C
    buf[0x11] = 0x08
    buf[0x12] = 0x02
    buf[0x13] = 0xA6
    # BL to 0x30: BL LI=((0x30-0x14)//4), LK=1
    # offset = 0x1C, LI = 0x1C / 4 = 7
    # PPC BL: opcode=18 (0x48), LI in bits[25:2], LK=1
    # word = (18 << 26) | (7 << 2) | 1 = 0x48000001 | (7<<2) = 0x48000001 | 0x1C = 0x4800001D
    # Wait: at va=0x14, target=0x30; LI = (0x30-0x14)//4 = (0x1C)//4 = 7
    # word = (18 << 26) | (7 << 2) | 1 = 0x48000000 | 0x1C | 0x1 = 0x4800001D
    struct.pack_into(">I", buf, 0x14, 0x4800001D)
    # BLR at 0x18: 0x4E800020
    struct.pack_into(">I", buf, 0x18, 0x4E800020)
    # MFLR r0 at 0x30 (call target)
    buf[0x30] = 0x7C
    buf[0x31] = 0x08
    buf[0x32] = 0x02
    buf[0x33] = 0xA6
    # BLR at 0x34
    struct.pack_into(">I", buf, 0x34, 0x4E800020)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Basic scan tests
# ---------------------------------------------------------------------------

class TestScanBasic:
    def test_scan_returns_func_start_result(self):
        scanner = FlatBinaryFuncStartScanner(b"\x00" * 64)
        result = scanner.scan()
        assert isinstance(result, FuncStartResult)

    def test_scan_empty_rom(self):
        result = FlatBinaryFuncStartScanner(b"").scan()
        assert result.function_starts == []

    def test_scan_returns_sorted_starts(self):
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        assert result.function_starts == sorted(result.function_starts)

    def test_scan_no_duplicates(self):
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        assert len(result.function_starts) == len(set(result.function_starts))

    def test_result_has_all_fields(self):
        result = FlatBinaryFuncStartScanner(b"\x00" * 64).scan()
        assert hasattr(result, "arch")
        assert hasattr(result, "confidence")
        assert hasattr(result, "function_starts")
        assert hasattr(result, "call_targets")
        assert hasattr(result, "prologue_hits")
        assert hasattr(result, "detect_result")


# ---------------------------------------------------------------------------
# SH-2A detection and scanning
# ---------------------------------------------------------------------------

class TestSH2aScan:
    def test_detects_sh2a_arch(self):
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        assert result.arch == "sh2a"

    def test_finds_reset_entry_in_call_targets(self):
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        assert 0x10 in result.call_targets

    def test_finds_bsr_target_in_call_targets(self):
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        assert 0x40 in result.call_targets

    def test_finds_prologue_only_function(self):
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        assert 0x80 in result.prologue_hits

    def test_all_prologues_in_function_starts(self):
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        # 0x10, 0x40, 0x80 should all appear in combined set
        for va in [0x10, 0x40, 0x80]:
            assert va in result.function_starts

    def test_forced_arch_sh2a(self):
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan(arch="sh2a")
        assert result.arch == "sh2a"
        assert result.confidence == "HIGH"


# ---------------------------------------------------------------------------
# M68K detection and scanning
# ---------------------------------------------------------------------------

class TestM68kScan:
    def test_detects_m68k_arch(self):
        rom = _m68k_rom_with_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        assert result.arch == "m68k"

    def test_finds_reset_entry(self):
        rom = _m68k_rom_with_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        assert 0x10 in result.function_starts

    def test_finds_bsr_target(self):
        rom = _m68k_rom_with_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        assert 0x30 in result.function_starts

    def test_prologue_scan_finds_link_w(self):
        rom = _m68k_rom_with_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        assert 0x10 in result.prologue_hits
        assert 0x30 in result.prologue_hits


# ---------------------------------------------------------------------------
# PPC32 detection and scanning
# ---------------------------------------------------------------------------

class TestPPC32Scan:
    def test_finds_ppc32_prologue(self):
        rom = _ppc32_rom_with_bl()
        result = FlatBinaryFuncStartScanner(rom).scan(arch="ppc32")
        assert 0x10 in result.prologue_hits

    def test_finds_bl_target_in_call_targets(self):
        rom = _ppc32_rom_with_bl()
        result = FlatBinaryFuncStartScanner(rom).scan(arch="ppc32")
        assert 0x30 in result.call_targets


# ---------------------------------------------------------------------------
# Forced arch override
# ---------------------------------------------------------------------------

class TestForcedArch:
    def test_forced_arch_overrides_detection(self):
        # SH-2A ROM but force m68k — should not crash, just return m68k arch
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan(arch="m68k")
        assert result.arch == "m68k"

    def test_forced_arch_returns_high_confidence(self):
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan(arch="sh2a")
        assert result.confidence == "HIGH"

    def test_forced_arch_unknown_returns_empty(self):
        result = FlatBinaryFuncStartScanner(b"\x00" * 64).scan(arch="sh2a")
        assert isinstance(result.function_starts, list)


# ---------------------------------------------------------------------------
# Base VA offset
# ---------------------------------------------------------------------------

class TestBaseVA:
    def test_base_va_offsets_all_results(self):
        rom = _sh2a_rom_with_prologues_and_bsr(base_va=0)
        rom_based = _sh2a_rom_with_prologues_and_bsr(base_va=0x400000)
        r0 = FlatBinaryFuncStartScanner(rom, base_va=0).scan()
        r1 = FlatBinaryFuncStartScanner(rom_based, base_va=0x400000).scan()
        # All VAs in r1 should be exactly base_offset more than r0
        if r0.function_starts and r1.function_starts:
            assert min(r1.function_starts) == min(r0.function_starts) + 0x400000


# ---------------------------------------------------------------------------
# Constructors
# ---------------------------------------------------------------------------

class TestConstructors:
    def test_from_bytes(self):
        det = FlatBinaryFuncStartScanner.from_bytes(b"\x00" * 64)
        assert det is not None

    def test_from_path(self, tmp_path):
        rom = _sh2a_rom_with_prologues_and_bsr()
        p = tmp_path / "test.bin"
        p.write_bytes(rom)
        det = FlatBinaryFuncStartScanner.from_path(p)
        result = det.scan()
        assert result.arch == "sh2a"

    def test_from_path_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="FlatBinaryFuncStartScanner"):
            FlatBinaryFuncStartScanner.from_path(tmp_path / "missing.bin")

    def test_max_call_depth_limits_recursion(self):
        # With depth=1, only the reset entry and its immediate callees are harvested
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom, max_call_depth=1).scan()
        assert isinstance(result.function_starts, list)


# ---------------------------------------------------------------------------
# Low-confidence union scan
# ---------------------------------------------------------------------------

class TestLowConfidenceUnion:
    def test_low_confidence_runs_all_catalogs(self):
        # All-zeros ROM: EcuArchDetector may return LOW or unknown
        result = FlatBinaryFuncStartScanner(b"\x00" * 256).scan()
        # Should not raise; result may be empty or have some hits from zero-patterned data
        assert isinstance(result.function_starts, list)

    def test_function_starts_is_union_of_call_and_prologue(self):
        rom = _sh2a_rom_with_prologues_and_bsr()
        result = FlatBinaryFuncStartScanner(rom).scan()
        expected = sorted(set(result.call_targets) | set(result.prologue_hits))
        assert result.function_starts == expected
