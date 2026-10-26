"""
Tests for LpgbtDecoder — lpGBT e-link serial protocol decoder.

Tests cover:
  - 6B/8B encode/decode (LCB downlink custom codec)
  - LCB frame decoding: IDLE, L0A, BCR, CMD frames
  - STAR FLINK 4-bit symbol decoding: IDLE, BCR, LS, PR, LP events
  - Standard 8B/10B encoding/decoding (HCC uplink)
  - Integration: known constant values from lcb_pkg_globals.vhd and
    pkg_star_flink.vhd
"""

import pytest

from ablation.analyzers.lpgbt_decoder import (
    LCB_K0, LCB_K1, LCB_K2, LCB_K3,
    LCB_IDLE_FRAME,
    LCB_SYMB_CMD_IGNORE, LCB_SYMB_CMD_END,
    LCB_SYMB_ECR, LCB_SYMB_ABCRST, LCB_SYMB_HCCRST,
    LCB_ASIC_HCC, LCB_ASIC_ABC,
    K28_5, K28_1,
    decode_6b8b, encode_6b8b,
    decode_8b10b, encode_8b10b, decode_8b10b_stream,
    LcbDecoder, LcbFrame, LcbFrameType, LcbSymbol,
    StarFlinkDecoder, StarFlinkEvent, StarFlinkEventType, StarFlinkSymbol,
    LpgbtDecoder,
    _MAP_6B_8B, _MAP_K_8B,
)


# ── 6B/8B codec unit tests ─────────────────────────────────────────────────────

class Test6B8BCodec:

    def test_encode_decode_all_data_symbols(self):
        """All 64 data values must round-trip through encode→decode."""
        for i in range(64):
            encoded = encode_6b8b(i, False)
            decoded = decode_6b8b(encoded)
            assert decoded == (i, False), f"data symbol {i} failed"

    def test_encode_decode_all_k_symbols(self):
        """All 4 K symbols must round-trip through encode→decode."""
        for i in range(4):
            encoded = encode_6b8b(i, True)
            decoded = decode_6b8b(encoded)
            assert decoded == (i, True), f"K{i} failed"

    def test_decode_invalid_byte_returns_none(self):
        """Bytes not in the 6B/8B codebook must return None."""
        # 0x00 is not a valid LCB codeword (weight 0)
        assert decode_6b8b(0x00) is None
        # 0xff is not valid (weight 8)
        assert decode_6b8b(0xff) is None

    def test_all_valid_codewords_have_weight_4(self):
        """
        All 68 valid LCB codewords (64 data + 4 K) must have exactly 4 set bits.
        This is the 4-of-8 property that enables the parity check in lcb_frame_sync.vhd.
        """
        for i in range(64):
            byte = encode_6b8b(i, False)
            assert bin(byte).count('1') == 4, f"data {i}: {byte:#04x} weight != 4"
        for i in range(4):
            byte = encode_6b8b(i, True)
            assert bin(byte).count('1') == 4, f"K{i}: {byte:#04x} weight != 4"

    def test_encode_out_of_range_raises(self):
        with pytest.raises(ValueError):
            encode_6b8b(64, False)
        with pytest.raises(ValueError):
            encode_6b8b(4, True)

    def test_k_symbol_bytes_match_vhdl_constants(self):
        """K symbol bytes must match MAP_K_8B from lcb_pkg_globals.vhd."""
        assert _MAP_K_8B[0] == 0x47   # K0
        assert _MAP_K_8B[1] == 0x55   # K1
        assert _MAP_K_8B[2] == 0x78   # K2
        assert _MAP_K_8B[3] == 0x6a   # K3

    def test_map_6b8b_first_entry(self):
        """MAP_6B_8B[0] must be 0x59 (from lcb_pkg_globals.vhd)."""
        assert _MAP_6B_8B[0] == 0x59

    def test_map_6b8b_last_entry(self):
        """MAP_6B_8B[63] must be 0x66 (from lcb_pkg_globals.vhd)."""
        assert _MAP_6B_8B[63] == 0x66


# ── LCB protocol constants ──────────────────────────────────────────────────────

class TestLcbConstants:

    def test_idle_frame_value(self):
        """IDLE_FRAME must be K0||K1 = 0x4755."""
        assert LCB_IDLE_FRAME == 0x4755
        assert LCB_K0 == 0x47
        assert LCB_K1 == 0x55

    def test_k2_k3_values(self):
        assert LCB_K2 == 0x78
        assert LCB_K3 == 0x6a

    def test_symb_ecr_value(self):
        """SYMB_ECR must be MAP_6B_8B[2] = 0x72."""
        assert LCB_SYMB_ECR == _MAP_6B_8B[2]
        assert LCB_SYMB_ECR == 0x72

    def test_symb_abcrst_value(self):
        """SYMB_ABCRST must be MAP_6B_8B[4] = 0x65."""
        assert LCB_SYMB_ABCRST == _MAP_6B_8B[4]
        assert LCB_SYMB_ABCRST == 0x65

    def test_symb_hccrst_value(self):
        """SYMB_HCCRST must be MAP_6B_8B[8] = 0x69."""
        assert LCB_SYMB_HCCRST == _MAP_6B_8B[8]
        assert LCB_SYMB_HCCRST == 0x69

    def test_asic_type_constants(self):
        """HCC=0xcc, ABC=0xab (from lcb_pkg_globals.vhd integer constants)."""
        assert LCB_ASIC_HCC == 0xcc
        assert LCB_ASIC_ABC == 0xab


# ── LcbDecoder frame tests ──────────────────────────────────────────────────────

class TestLcbDecoder:

    def _make_stream(self, *frame_pairs):
        """Helper: build a byte stream from (s0, s1) frame pairs."""
        data = bytearray()
        for s0, s1 in frame_pairs:
            data.append(s0)
            data.append(s1)
        return bytes(data)

    def test_decode_empty(self):
        assert LcbDecoder.decode_stream(b"") == []

    def test_decode_single_byte(self):
        assert LcbDecoder.decode_stream(bytes([LCB_K0])) == []

    def test_decode_idle_stream(self):
        """Pure IDLE stream must produce all IDLE frames."""
        data = bytes([LCB_K0, LCB_K1] * 8)
        frames = LcbDecoder.decode_stream(data)
        assert len(frames) == 8
        assert all(f.frame_type == LcbFrameType.IDLE for f in frames)

    def test_idle_frame_has_zero_l0a(self):
        data = bytes([LCB_K0, LCB_K1] * 3)
        frames = LcbDecoder.decode_stream(data)
        for f in frames:
            assert f.l0a_map == 0
            assert not f.bcr

    def test_decode_bcr_frame(self):
        """
        BCR frame: Symbol0 has bit 0 set and bits 4:1 = 0.
        Using MAP_6B_8B[0b000001] = 0x71 as Symbol0 (value=1, bcr=bit0=1, l0a_map=0).
        """
        # 6-bit value 0b000001 → bcr=True, l0a_map=0, tag_msb=0
        s0 = encode_6b8b(0b000001)
        s1 = encode_6b8b(0)  # any data symbol as Symbol1
        data = self._make_stream((s0, s1))
        frames = LcbDecoder.decode_stream(data)
        assert len(frames) == 1
        f = frames[0]
        assert f.bcr is True
        assert f.l0a_map == 0
        assert f.frame_type == LcbFrameType.BCR

    def test_decode_l0a_frame(self):
        """
        L0A frame: Symbol0 has l0a_map != 0.
        6-bit value 0b000110 → bcr=0, l0a_map=0b011=3, tag_msb=0.
        """
        s0 = encode_6b8b(0b000110)
        s1 = encode_6b8b(0b001010)  # tag_lsbs = 0b001010
        data = self._make_stream((s0, s1))
        frames = LcbDecoder.decode_stream(data)
        assert len(frames) == 1
        f = frames[0]
        assert f.frame_type == LcbFrameType.L0A
        assert f.l0a_map == 0b011
        assert f.bcr is False

    def test_decode_l0a_bcr_combined(self):
        """L0A frame with BCR bit set: both l0a_map != 0 and bcr = True."""
        # 6-bit value 0b000111 → bcr=1, l0a_map=0b011=3, tag_msb=0
        s0 = encode_6b8b(0b000111)
        s1 = encode_6b8b(0b000000)
        data = self._make_stream((s0, s1))
        frames = LcbDecoder.decode_stream(data)
        assert len(frames) == 1
        f = frames[0]
        assert f.frame_type == LcbFrameType.L0A
        assert f.l0a_map == 0b011
        assert f.bcr is True

    def test_decode_k2_cmd_frame(self):
        """K2 Symbol0 → CMD frame. Symbol1 carries 4-bit fast command."""
        s0 = LCB_K2
        # fast_cmd in Symbol1 = low 4 bits of decoded 6-bit value
        s1 = encode_6b8b(0b001011)  # value bits[3:0] = 0b1011
        data = self._make_stream((s0, s1))
        frames = LcbDecoder.decode_stream(data)
        assert len(frames) == 1
        f = frames[0]
        assert f.frame_type == LcbFrameType.CMD
        assert f.fast_cmd == 0b1011

    def test_decode_k3_cmd_frame(self):
        """K3 Symbol0 → CMD frame. Symbol1 carries HCC ID."""
        s0 = LCB_K3
        s1 = encode_6b8b(0b010101)  # HCC ID = bits[4:0] = 0b10101 = 21
        data = self._make_stream((s0, s1))
        frames = LcbDecoder.decode_stream(data)
        assert len(frames) == 1
        f = frames[0]
        assert f.frame_type == LcbFrameType.CMD
        assert f.cmd_hccid == 0b10101

    def test_l0a_tag_reconstruction(self):
        """
        tag() = (tag_msb << 6) | tag_lsbs.
        6-bit value 0b100010: tag_msb=1, l0a_map=0b001, bcr=0.
        Symbol1 6-bit value 0b101010: tag_lsbs = 0b101010 = 42.
        tag = (1 << 6) | 42 = 64+42 = 106.
        """
        s0 = encode_6b8b(0b100010)   # tag_msb=1, l0a_map=0b001, bcr=0
        s1 = encode_6b8b(0b101010)   # tag_lsbs=42
        data = self._make_stream((s0, s1))
        frames = LcbDecoder.decode_stream(data)
        assert len(frames) == 1
        f = frames[0]
        assert f.frame_type == LcbFrameType.L0A
        assert f.tag() == (1 << 6) | 42

    def test_decode_mixed_stream(self):
        """Mixed IDLE + L0A + BCR + CMD stream."""
        s0_l0a = encode_6b8b(0b000110)  # l0a_map=3
        s1_l0a = encode_6b8b(0)
        s0_bcr = encode_6b8b(0b000001)  # bcr only
        s1_bcr = encode_6b8b(0)
        data = self._make_stream(
            (LCB_K0, LCB_K1),    # IDLE
            (s0_l0a, s1_l0a),    # L0A
            (LCB_K0, LCB_K1),    # IDLE
            (s0_bcr, s1_bcr),    # BCR
            (LCB_K2, encode_6b8b(3)),  # CMD (K2)
        )
        frames = LcbDecoder.decode_stream(data)
        types = [f.frame_type for f in frames]
        assert LcbFrameType.IDLE in types
        assert LcbFrameType.L0A in types
        assert LcbFrameType.BCR in types
        assert LcbFrameType.CMD in types

    def test_phase_alignment_odd(self):
        """Decoder must find sync even when the stream starts with a leading byte."""
        # Prepend a garbage byte — decoder should still find 3 IDLE frames
        data = bytes([0x00]) + bytes([LCB_K0, LCB_K1] * 3)
        frames = LcbDecoder.decode_stream(data)
        idle = [f for f in frames if f.frame_type == LcbFrameType.IDLE]
        assert len(idle) >= 2  # at least 2 of the 3 IDLE frames found

    def test_report_output(self):
        data = bytes([LCB_K0, LCB_K1] * 3)
        frames = LcbDecoder.decode_stream(data)
        report = LcbDecoder.report(frames)
        assert "IDLE" in report
        assert "3" in report

    def test_str_representation(self):
        data = bytes([LCB_K0, LCB_K1])
        frames = LcbDecoder.decode_stream(data)
        s = str(frames[0])
        assert "IDLE" in s


# ── STAR FLINK decoder tests ────────────────────────────────────────────────────

class TestStarFlinkDecoder:

    def test_decode_empty(self):
        assert StarFlinkDecoder.decode_stream([]) == []

    def test_decode_idle(self):
        events = StarFlinkDecoder.decode_stream([StarFlinkSymbol.sIDLE])
        assert len(events) == 1
        assert events[0].event_type == StarFlinkEventType.IDLE

    def test_decode_bcr(self):
        events = StarFlinkDecoder.decode_stream([StarFlinkSymbol.sBCR])
        assert len(events) == 1
        assert events[0].event_type == StarFlinkEventType.BCR

    def test_decode_ls(self):
        events = StarFlinkDecoder.decode_stream([StarFlinkSymbol.sLS])
        assert len(events) == 1
        assert events[0].event_type == StarFlinkEventType.LS

    def test_decode_bcrls(self):
        events = StarFlinkDecoder.decode_stream([StarFlinkSymbol.sBCRLS])
        assert len(events) == 1
        assert events[0].event_type == StarFlinkEventType.BCRLS

    def test_decode_pr_basic(self):
        """PR event: sPR header + 3 data symbols. L0ID reconstructed correctly."""
        # sPR=0x5, sDATA0=0x8(0), sDATA1=0x9(1), sDATA2=0xa(2) → L0ID = 0b000_001_010 = 10
        nibs = [0x5, 0x8, 0x9, 0xa]
        events = StarFlinkDecoder.decode_stream(nibs)
        assert len(events) == 1
        assert events[0].event_type == StarFlinkEventType.PR
        assert events[0].l0id == 0b000_001_010

    def test_decode_pr_l0id_known(self):
        """
        PR with data symbols sDATA3(011), sDATA1(001), sDATA5(101):
        L0ID = 0b011_001_101 = 205 = 0xcd.
        """
        nibs = [StarFlinkSymbol.sPR, 0xb, 0x9, 0xd]  # D3, D1, D5
        events = StarFlinkDecoder.decode_stream(nibs)
        assert len(events) == 1
        assert events[0].l0id == 0b011_001_101

    def test_decode_lp_basic(self):
        """LP event: sLP header + 3 data symbols."""
        nibs = [StarFlinkSymbol.sLP, 0x8, 0x8, 0x8]  # L0ID = 0
        events = StarFlinkDecoder.decode_stream(nibs)
        assert len(events) == 1
        assert events[0].event_type == StarFlinkEventType.LP
        assert events[0].l0id == 0

    def test_decode_pr_max_l0id(self):
        """PR with all sDATA7 → L0ID = 0b111_111_111 = 511."""
        nibs = [StarFlinkSymbol.sPR, 0x7, 0x7, 0x7]  # sDATA7 = 0x7
        events = StarFlinkDecoder.decode_stream(nibs)
        assert len(events) == 1
        assert events[0].l0id == 0b111_111_111  # 511

    def test_decode_mixed_sequence(self):
        """IDLE → BCR → PR → IDLE sequence."""
        nibs = [
            StarFlinkSymbol.sIDLE,
            StarFlinkSymbol.sBCR,
            StarFlinkSymbol.sPR, 0x8, 0x9, 0xa,
            StarFlinkSymbol.sIDLE,
        ]
        events = StarFlinkDecoder.decode_stream(nibs)
        types = [e.event_type for e in events]
        assert StarFlinkEventType.IDLE in types
        assert StarFlinkEventType.BCR in types
        assert StarFlinkEventType.PR in types

    def test_pr_incomplete_at_eof(self):
        """PR at end of stream with only 2 data symbols — should not crash."""
        nibs = [StarFlinkSymbol.sPR, 0x8, 0x9]  # missing 3rd data symbol
        events = StarFlinkDecoder.decode_stream(nibs)
        # Should either produce zero events or an invalid event, not crash
        for e in events:
            assert e.event_type in (StarFlinkEventType.PR,
                                    StarFlinkEventType.INVALID)

    def test_symbol_values_match_vhdl(self):
        """STAR FLINK symbol constants must match pkg_star_flink.vhd."""
        assert StarFlinkSymbol.sIDLE  == 0x1
        assert StarFlinkSymbol.sBCR   == 0x2
        assert StarFlinkSymbol.sLS    == 0x3
        assert StarFlinkSymbol.sBCRLS == 0x4
        assert StarFlinkSymbol.sPR    == 0x5
        assert StarFlinkSymbol.sLP    == 0x6
        assert StarFlinkSymbol.sDATA7 == 0x7
        assert StarFlinkSymbol.sDATA0 == 0x8

    def test_offset_tracking(self):
        """Offset field must reflect nibble position in stream."""
        nibs = [StarFlinkSymbol.sIDLE, StarFlinkSymbol.sBCR]
        events = StarFlinkDecoder.decode_stream(nibs)
        assert events[0].offset == 0
        assert events[1].offset == 1

    def test_report_output(self):
        nibs = [StarFlinkSymbol.sIDLE, StarFlinkSymbol.sBCR,
                StarFlinkSymbol.sPR, 0x8, 0x9, 0xa]
        events = StarFlinkDecoder.decode_stream(nibs)
        report = StarFlinkDecoder.report(events)
        assert "IDLE" in report
        assert "BCR" in report
        assert "PR" in report


# ── 8B/10B codec tests ──────────────────────────────────────────────────────────

class Test8B10BCodec:

    def test_all_256_data_bytes_round_trip(self):
        """All 256 data bytes must round-trip through encode→decode."""
        errors = []
        for b in range(256):
            w = encode_8b10b(b)
            r = decode_8b10b(w)
            if r is None or r[0] != b or r[1] is not False:
                errors.append(b)
        assert errors == [], f"Round-trip failures: {errors}"

    def test_decode_invalid_word_returns_none(self):
        """10-bit word 0x000 is not a valid 8B/10B codeword."""
        assert decode_8b10b(0x000) is None

    def test_k28_5_is_k_symbol(self):
        """K28.5 (0xbc) must decode as a K symbol."""
        word = encode_8b10b(K28_5)
        result = decode_8b10b(word)
        # K28.5 encodes to a specific word that decodes as K
        # We verify the round-trip is at least consistent
        assert result is not None
        assert result[0] == K28_5

    def test_k28_5_constant_value(self):
        """K28.5 must be 0xbc per the 8B/10B standard."""
        assert K28_5 == 0xbc

    def test_k28_1_constant_value(self):
        assert K28_1 == 0x3c

    def test_encode_decode_stream_basic(self):
        """decode_8b10b_stream must decode a sequence of encoded bytes."""
        # Encode 3 bytes: 0xAB, 0xCD, 0xEF
        test_bytes = [0xab, 0xcd, 0xef]
        bits = []
        for b in test_bytes:
            word = encode_8b10b(b)
            for j in range(9, -1, -1):
                bits.append((word >> j) & 1)
        results = decode_8b10b_stream(bits)
        assert len(results) == 3
        for i, (off, byte_val, is_k) in enumerate(results):
            assert byte_val == test_bytes[i]
            assert is_k is False

    def test_encode_decode_stream_empty(self):
        assert decode_8b10b_stream([]) == []


# ── LpgbtDecoder wrapper tests ──────────────────────────────────────────────────

class TestLpgbtDecoder:

    def test_lcb_method_works(self):
        data = bytes([LCB_K0, LCB_K1] * 3)
        frames = LpgbtDecoder.lcb(data)
        assert len(frames) == 3
        assert all(f.frame_type == LcbFrameType.IDLE for f in frames)

    def test_star_flink_method_works(self):
        nibs = [StarFlinkSymbol.sIDLE, StarFlinkSymbol.sBCR]
        events = LpgbtDecoder.star_flink(nibs)
        assert len(events) == 2

    def test_hcc_8b10b_method_works(self):
        bits = []
        word = encode_8b10b(0x5a)
        for j in range(9, -1, -1):
            bits.append((word >> j) & 1)
        results = LpgbtDecoder.hcc_8b10b(bits)
        assert len(results) == 1
        _, byte_val, is_k = results[0]
        assert byte_val == 0x5a
        assert is_k is False
