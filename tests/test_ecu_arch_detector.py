"""Tests for EcuArchDetector — ISA fingerprinter for flat ECU ROMs."""

import struct
import pytest
from ablation.analyzers.ecu_arch_detector import EcuArchDetector, ArchCandidate


# ---------------------------------------------------------------------------
# Helpers — build synthetic ROM blobs
# ---------------------------------------------------------------------------

def _arm_cm_rom(size: int = 256) -> bytes:
    """Cortex-M: MSP in SRAM, reset vector Thumb-flagged in flash."""
    buf = bytearray(size)
    struct.pack_into("<I", buf, 0, 0x20001000)  # MSP in SRAM
    struct.pack_into("<I", buf, 4, 0x00000101)  # reset handler: flash + Thumb bit
    # fill with thumb2-ish NOPs (0x0000)
    return bytes(buf)


def _m68k_rom(size: int = 256, link_count: int = 5) -> bytes:
    """M68K: big-endian reset vector in range + LINK.W A6 prologues."""
    buf = bytearray(size)
    struct.pack_into(">I", buf, 0, 0x00001000)  # SSP
    struct.pack_into(">I", buf, 4, 0x00000080)  # PC in range (0x80 < 256)
    # Inject LINK.W A6, #-0x20 prologues
    off = 8
    for _ in range(link_count):
        if off + 4 <= size:
            struct.pack_into(">H", buf, off, 0x4E56)      # LINK.W A6 opcode
            struct.pack_into(">H", buf, off + 2, 0xFFE0)  # #-0x20 (negative)
            off += 4
    return bytes(buf)


def _sh2a_rom(size: int = 256, rts_count: int = 10) -> bytes:
    """SH-2A: reset vector at offset 4 + RTS instructions."""
    buf = bytearray(size)
    struct.pack_into(">I", buf, 4, 0x00000080)  # reset vector in range (0x80 < 256)
    # Inject RTS and STS.L PR instructions
    off = 8
    for i in range(rts_count):
        if off + 2 <= size:
            struct.pack_into(">H", buf, off, 0x000B)  # RTS
            off += 2
    return bytes(buf)


def _sh2a_rom_with_prologue(size: int = 256) -> bytes:
    """SH-2A: reset vector + STS.L PR prologues."""
    buf = bytearray(size)
    struct.pack_into(">I", buf, 4, 0x00000080)  # reset vector in range (0x80 < 256)
    off = 8
    for _ in range(10):
        if off + 2 <= size:
            struct.pack_into(">H", buf, off, 0x4F22)  # STS.L PR, @-R15
            off += 2
    return bytes(buf)


def _ppc_vle_rom(size: int = 256) -> bytes:
    """PPC VLE: high density of halfwords with (byte0 & 0x90) == 0x10."""
    buf = bytearray(size)
    struct.pack_into(">I", buf, 0, 0xFFFFFFFF)  # PPC reset area
    # Fill with e_stwu pattern (0x1C21, first byte 0x1C: 0x1C & 0x90 = 0x10)
    off = 8
    while off + 4 <= size:
        struct.pack_into(">I", buf, off, 0x1C210000)  # e_stwu r1, offset
        off += 4
    return bytes(buf)


def _ppc32_rom(size: int = 256) -> bytes:
    """PPC32: fill with stw (opcode 0x90) instructions."""
    buf = bytearray(size)
    off = 0
    while off + 4 <= size:
        # stw r0, 0(r1) = 0x90010000 (opcode 0x24 >> ... wait, stw = opcode 36)
        # opcode field (bits[31:26]) = 36 = 0x24 in 6-bit = 0x90000000 >> 2
        # Actually: stw = 0x90000000: (0x90 >> 2) = 0x24 which is NOT in range
        # Use lwz opcode = 32 = 0x20 in 6-bit
        # lwz r3, 0(r4): 0x8064_0000 → first byte 0x80, primary op = 0x80>>2 = 0x20 = 32
        struct.pack_into(">I", buf, off, 0x80640000)  # lwz r3, 0(r4)
        off += 4
    return bytes(buf)


def _unknown_rom(size: int = 256) -> bytes:
    """Random-looking data that shouldn't match any ISA."""
    # Use a PRNG-like pattern without any real ISA signatures
    buf = bytearray(size)
    v = 0xDEADBEEF
    for i in range(size):
        v = (v * 1664525 + 1013904223) & 0xFFFFFFFF
        buf[i] = v & 0xFF
    return bytes(buf)


# ---------------------------------------------------------------------------
# ARM Cortex-M detection
# ---------------------------------------------------------------------------

class TestArmCortexM:
    def test_detects_arm_cm_high_confidence(self):
        rom = _arm_cm_rom()
        result = EcuArchDetector(rom).detect()
        assert result.arch == "arm_cm"
        assert result.confidence in ("HIGH",)

    def test_arm_cm_msp_in_sram(self):
        # MSP at 0x20000800 (valid SRAM), reset at 0x00000201 (Thumb)
        buf = bytearray(256)
        struct.pack_into("<I", buf, 0, 0x20000800)
        struct.pack_into("<I", buf, 4, 0x00000201)
        result = EcuArchDetector(bytes(buf)).detect()
        assert result.arch == "arm_cm"

    def test_arm_cm_score_from_candidates(self):
        cands = EcuArchDetector(_arm_cm_rom()).candidates()
        arm_cands = [c for c in cands if c.arch == "arm_cm"]
        assert len(arm_cands) == 1
        assert arm_cands[0].score >= 0.85

    def test_arm_cm_msp_only_medium(self):
        # MSP in SRAM but reset vector without Thumb bit
        buf = bytearray(256)
        struct.pack_into("<I", buf, 0, 0x20001000)
        struct.pack_into("<I", buf, 4, 0x00000100)  # no Thumb bit
        cands = EcuArchDetector(bytes(buf)).candidates()
        arm_cands = [c for c in cands if c.arch == "arm_cm"]
        assert arm_cands[0].score == 0.55

    def test_no_arm_cm_for_m68k_rom(self):
        cands = EcuArchDetector(_m68k_rom()).candidates()
        arm_cands = [c for c in cands if c.arch == "arm_cm"]
        assert len(arm_cands) == 0 or arm_cands[0].score < 0.80


# ---------------------------------------------------------------------------
# M68K / CPU32 detection
# ---------------------------------------------------------------------------

class TestM68kDetection:
    def test_detects_m68k_high_confidence(self):
        rom = _m68k_rom(size=512, link_count=10)
        result = EcuArchDetector(rom).detect()
        assert result.arch == "m68k"
        assert result.confidence in ("HIGH", "MEDIUM")

    def test_m68k_score_increases_with_link_density(self):
        low_link = EcuArchDetector(_m68k_rom(size=512, link_count=2))
        high_link = EcuArchDetector(_m68k_rom(size=512, link_count=20))
        low_cands = [c for c in low_link.candidates() if c.arch == "m68k"]
        high_cands = [c for c in high_link.candidates() if c.arch == "m68k"]
        assert high_cands[0].score >= low_cands[0].score

    def test_m68k_reset_vector_in_range(self):
        buf = bytearray(256)
        struct.pack_into(">I", buf, 4, 0x00000080)  # valid PC in-range (0x80 < 256)
        for i in range(3):
            struct.pack_into(">H", buf, 8 + i * 4, 0x4E56)
            struct.pack_into(">H", buf, 10 + i * 4, 0xFFE0)
        cands = EcuArchDetector(bytes(buf)).candidates()
        m68k = [c for c in cands if c.arch == "m68k"]
        assert m68k[0].score >= 0.70

    def test_m68k_not_top_for_arm_rom(self):
        result = EcuArchDetector(_arm_cm_rom()).detect()
        assert result.arch != "m68k"


# ---------------------------------------------------------------------------
# PPC VLE detection
# ---------------------------------------------------------------------------

class TestPPCVLEDetection:
    def test_detects_ppc_vle(self):
        rom = _ppc_vle_rom(size=512)
        cands = EcuArchDetector(rom).candidates()
        vle_cands = [c for c in cands if c.arch == "ppc_vle"]
        assert len(vle_cands) == 1
        assert vle_cands[0].score >= 0.40

    def test_vle_density_scales_with_content(self):
        # Fill more with VLE patterns
        buf = bytearray(512)
        for i in range(0, 512, 4):
            struct.pack_into(">I", buf, i, 0x1C210000)
        result = EcuArchDetector(bytes(buf)).detect()
        assert result.arch == "ppc_vle"

    def test_plain_ppc32_does_not_trigger_vle(self):
        # PPC32 opcode 0x80 (lwz): byte0 = 0x80, 0x80 & 0x90 = 0x80 != 0x10
        buf = bytearray(256)
        for i in range(0, 256, 4):
            struct.pack_into(">I", buf, i, 0x80640000)
        cands = EcuArchDetector(bytes(buf)).candidates()
        vle_cands = [c for c in cands if c.arch == "ppc_vle"]
        assert len(vle_cands) == 0 or vle_cands[0].score < 0.30


# ---------------------------------------------------------------------------
# SH-2A detection
# ---------------------------------------------------------------------------

class TestSH2aDetection:
    def test_detects_sh2a_with_rts(self):
        rom = _sh2a_rom(size=256, rts_count=20)
        result = EcuArchDetector(rom).detect()
        assert result.arch == "sh2a"

    def test_detects_sh2a_with_prologue(self):
        rom = _sh2a_rom_with_prologue(size=256)
        result = EcuArchDetector(rom).detect()
        assert result.arch == "sh2a"
        assert result.confidence in ("HIGH", "MEDIUM")

    def test_sh2a_score_from_candidates(self):
        cands = EcuArchDetector(_sh2a_rom_with_prologue()).candidates()
        sh2a_cands = [c for c in cands if c.arch == "sh2a"]
        assert len(sh2a_cands) == 1
        assert sh2a_cands[0].score >= 0.75

    def test_sh2a_reset_vector_check(self):
        # Reset vector pointing outside image — should reduce score
        buf = bytearray(256)
        struct.pack_into(">I", buf, 4, 0xFFFFFFFF)  # out of range
        for i in range(10):
            struct.pack_into(">H", buf, 8 + i * 2, 0x4F22)  # high prologue density
        cands = EcuArchDetector(bytes(buf)).candidates()
        sh2a_cands = [c for c in cands if c.arch == "sh2a"]
        if sh2a_cands:
            assert sh2a_cands[0].score < 0.80  # lower without valid reset vector

    def test_sh2a_not_top_for_arm_rom(self):
        result = EcuArchDetector(_arm_cm_rom()).detect()
        assert result.arch != "sh2a"


# ---------------------------------------------------------------------------
# Unknown / ambiguous ROMs
# ---------------------------------------------------------------------------

class TestUnknownROM:
    def test_empty_rom(self):
        result = EcuArchDetector(b"").detect()
        assert result.arch == "unknown"

    def test_all_zeros(self):
        result = EcuArchDetector(b"\x00" * 256).detect()
        # All zeros: reset vector = 0 (in range for most), but no instruction density
        # Result depends on implementation; must not crash
        assert isinstance(result.arch, str)

    def test_candidates_returns_list(self):
        result = EcuArchDetector(b"\xFF" * 256).candidates()
        assert isinstance(result, list)

    def test_result_has_all_fields(self):
        result = EcuArchDetector(_arm_cm_rom()).detect()
        assert hasattr(result, "arch")
        assert hasattr(result, "confidence")
        assert hasattr(result, "score")
        assert hasattr(result, "reason")
        assert hasattr(result, "candidates")

    def test_is_confident_true_for_high(self):
        result = EcuArchDetector(_arm_cm_rom()).detect()
        assert result.is_confident is True


# ---------------------------------------------------------------------------
# Constructors
# ---------------------------------------------------------------------------

class TestConstructors:
    def test_from_bytes(self):
        det = EcuArchDetector.from_bytes(_arm_cm_rom())
        assert det is not None

    def test_from_path(self, tmp_path):
        p = tmp_path / "test.bin"
        p.write_bytes(_arm_cm_rom())
        det = EcuArchDetector.from_path(p)
        assert det.detect().arch == "arm_cm"

    def test_from_path_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="EcuArchDetector"):
            EcuArchDetector.from_path(tmp_path / "missing.bin")

    def test_sample_size_zero_uses_full_data(self):
        data = _sh2a_rom_with_prologue(size=512)
        det = EcuArchDetector(data, sample_size=0)
        result = det.detect()
        assert result.arch == "sh2a"

    def test_sample_size_larger_than_data_clips(self):
        data = _arm_cm_rom(size=64)
        det = EcuArchDetector(data, sample_size=9999)
        # Should not raise; uses full 64 bytes
        assert det.detect().arch == "arm_cm"


# ---------------------------------------------------------------------------
# Candidate sorting and scoring
# ---------------------------------------------------------------------------

class TestCandidateSorting:
    def test_candidates_sorted_by_score_desc(self):
        cands = EcuArchDetector(_arm_cm_rom()).candidates()
        scores = [c.score for c in cands]
        assert scores == sorted(scores, reverse=True)

    def test_candidate_has_reason_string(self):
        cands = EcuArchDetector(_arm_cm_rom()).candidates()
        for c in cands:
            assert isinstance(c.reason, str)
            assert len(c.reason) > 0

    def test_confidence_high_for_score_above_0_75(self):
        rom = _arm_cm_rom()
        result = EcuArchDetector(rom).detect()
        if result.score >= 0.75:
            assert result.confidence == "HIGH"

    def test_confidence_medium_for_score_above_0_40(self):
        # MSP-only Cortex-M has score 0.55 → MEDIUM
        buf = bytearray(256)
        struct.pack_into("<I", buf, 0, 0x20001000)
        struct.pack_into("<I", buf, 4, 0x00000100)  # no Thumb bit
        result = EcuArchDetector(bytes(buf)).detect()
        if result.arch == "arm_cm" and 0.40 <= result.score < 0.75:
            assert result.confidence == "MEDIUM"
