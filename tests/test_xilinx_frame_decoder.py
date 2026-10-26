"""Tests for xilinx_frame_decoder.py — family detection and FAR decode."""

import struct
import pytest

from ablation.analyzers.xilinx_frame_decoder import (
    XilinxFrameDecoder,
    _detect_family,
    _REGS_V4,
    _REGS_S2E,
    _REGS_7S,
    _REGS_S6,
    _FRAME_WORDS,
)


# ── _detect_family ─────────────────────────────────────────────────────────────

class TestDetectFamily:
    def test_v4_fx100(self):
        family, regs, fw = _detect_family("xc4vfx100ff1152-11")
        assert family == "v4"
        assert regs is _REGS_V4
        assert fw == 41

    def test_v4_fx60(self):
        family, regs, fw = _detect_family("xc4vfx60ff1152-11")
        assert family == "v4"
        assert fw == 41

    def test_v4_lx160(self):
        family, regs, fw = _detect_family("xc4vlx160ff1148-11")
        assert family == "v4"

    def test_v4_sx35(self):
        family, regs, fw = _detect_family("xc4vsx35ff668-10")
        assert family == "v4"

    def test_7s_default(self):
        family, regs, fw = _detect_family("xc7k325tffg900-2")
        assert family == "7s"
        assert regs is _REGS_7S
        assert fw == 101

    def test_s2e(self):
        family, regs, fw = _detect_family("2s600efg456-7")
        assert family == "s2e"
        assert fw == 30

    def test_s6(self):
        family, regs, fw = _detect_family("6slx45csg324-3")
        assert family == "s6"
        assert fw == 65

    def test_ku(self):
        family, regs, fw = _detect_family("xcku115flva1517-2")
        assert family == "ku"

    def test_v4_not_confused_with_7s(self):
        # xc4v* must not fall through to the 7s default
        family, _, _ = _detect_family("xc4vfx100")
        assert family == "v4"
        family7, _, _ = _detect_family("xc7vx690t")
        assert family7 == "7s"

    def test_frame_words_dict_has_v4(self):
        assert "v4" in _FRAME_WORDS
        assert _FRAME_WORDS["v4"] == 41


# ── decode_far ─────────────────────────────────────────────────────────────────

def _make_decoder(family_tag: str) -> XilinxFrameDecoder:
    """Construct a minimal decoder with no packets for FAR-decode tests."""
    regs_map = {"v4": _REGS_V4, "7s": _REGS_7S, "s2e": _REGS_S2E, "s6": _REGS_S6}
    fw_map   = {"v4": 41, "7s": 101, "s2e": 30, "s6": 65}
    return XilinxFrameDecoder(
        part=f"test_{family_tag}",
        family=family_tag,
        reg_map=regs_map.get(family_tag, _REGS_7S),
        frame_words=fw_map.get(family_tag, 101),
        pkt_list=[],
        sync_offset=-1,
        raw_bitstream=b"",
    )


class TestDecodeFarV4:
    """Virtex-4 FAR: [25:24]=block(2b), [23:17]=row(7b), [16:8]=col(9b), [7:0]=minor(8b)"""

    def test_all_zero(self):
        dec = _make_decoder("v4")
        f = dec.decode_far(0x00000000)
        assert f["block"] == 0
        assert f["block_name"] == "CLB/IO/GCLK"
        assert f["row"] == 0
        assert f["col"] == 0
        assert f["minor"] == 0

    def test_block_clb(self):
        dec = _make_decoder("v4")
        # block=0 at bits[25:24]: FAR with block=0, row=0, col=0, minor=1
        far = 0x00000001
        f = dec.decode_far(far)
        assert f["block"] == 0
        assert f["minor"] == 1

    def test_block_bram_content(self):
        dec = _make_decoder("v4")
        # block=1 → bits[25:24]=0b01 → 0x01000000
        f = dec.decode_far(0x01000000)
        assert f["block"] == 1
        assert f["block_name"] == "BRAM_content"

    def test_block_cfg_clk_dcm(self):
        dec = _make_decoder("v4")
        # block=2 → bits[25:24]=0b10 → 0x02000000
        f = dec.decode_far(0x02000000)
        assert f["block"] == 2
        assert f["block_name"] == "CFG_CLK_DCM"

    def test_block_bram_cfg(self):
        dec = _make_decoder("v4")
        # block=3 → bits[25:24]=0b11 → 0x03000000
        f = dec.decode_far(0x03000000)
        assert f["block"] == 3
        assert f["block_name"] == "BRAM_cfg"

    def test_row_extraction(self):
        dec = _make_decoder("v4")
        # row=5 → bits[23:17]=0b0000101 → 5 << 17 = 0x000A0000
        f = dec.decode_far(0x000A0000)
        assert f["row"] == 5
        assert f["block"] == 0
        assert f["col"] == 0

    def test_col_extraction(self):
        dec = _make_decoder("v4")
        # col=7 → bits[16:8]=0b000000111 → 7 << 8 = 0x00000700
        f = dec.decode_far(0x00000700)
        assert f["col"] == 7
        assert f["row"] == 0

    def test_minor_extraction(self):
        dec = _make_decoder("v4")
        # minor=255 → bits[7:0]=0xFF
        f = dec.decode_far(0x000000FF)
        assert f["minor"] == 255
        assert f["col"] == 0

    def test_compound_far(self):
        dec = _make_decoder("v4")
        # block=2, row=1, col=1, minor=0
        # = 0x02000000 | (1<<17) | (1<<8) = 0x02020100
        f = dec.decode_far(0x02020100)
        assert f["block"] == 2
        assert f["row"] == 1
        assert f["col"] == 1
        assert f["minor"] == 0

    def test_max_fields(self):
        dec = _make_decoder("v4")
        # block=3 (2b max), row=127 (7b max), col=511 (9b max), minor=255 (8b max)
        far = (3 << 24) | (127 << 17) | (511 << 8) | 255
        f = dec.decode_far(far)
        assert f["block"] == 3
        assert f["row"] == 127
        assert f["col"] == 511
        assert f["minor"] == 255


class TestDecodeFar7S:
    """7-series FAR: [25:23]=block(3b), [22:17]=row(6b), [16:7]=col(10b), [6:0]=minor(7b)"""

    def test_basic(self):
        dec = _make_decoder("7s")
        # block=0, row=0, col=0, minor=1 → FAR=0x00000001
        f = dec.decode_far(0x00000001)
        assert f["block"] == 0
        assert f["block_name"] == "CLB/IO/CLK"
        assert f["minor"] == 1

    def test_bram_block(self):
        dec = _make_decoder("7s")
        # block=1 → bits[25:23]=0b001 → 1<<23 = 0x00800000
        f = dec.decode_far(0x00800000)
        assert f["block"] == 1
        assert f["block_name"] == "BRAM_content"

    def test_compound(self):
        dec = _make_decoder("7s")
        # block=0, row=3, col=5, minor=2
        # = (3<<17)|(5<<7)|(2) = 0x00060282
        far = (3 << 17) | (5 << 7) | 2
        f = dec.decode_far(far)
        assert f["block"] == 0
        assert f["row"] == 3
        assert f["col"] == 5
        assert f["minor"] == 2


class TestDecodeFarS6:
    def test_returns_raw(self):
        dec = _make_decoder("s6")
        f = dec.decode_far(0xABCD1234)
        assert "raw" in f
        assert f["raw"] == 0xABCD1234


# ── V4 register map completeness ───────────────────────────────────────────────

class TestV4RegisterMap:
    def test_required_regs_present(self):
        for reg in ("CRC", "FAR", "FDRI", "FDRO", "CMD", "CTL",
                    "MASK", "STAT", "COR", "MFWR", "CBC", "IDCODE", "AXSS"):
            assert reg in _REGS_V4.values(), f"V4 missing register {reg}"

    def test_fdri_addr_0x02(self):
        # FDRI must be at 0x02 — packet decoder uses the reg_map to name it "FDRI"
        assert _REGS_V4[0x02] == "FDRI"

    def test_cor_is_single(self):
        # V4 uses COR (not COR0/COR1 as in 7-series)
        v4_vals = list(_REGS_V4.values())
        assert "COR" in v4_vals
        assert "COR0" not in v4_vals
        assert "COR1" not in v4_vals

    def test_7s_uses_cor0(self):
        # 7-series has COR0 at 0x09; V4 has COR at 0x09
        assert _REGS_7S.get(0x09) == "COR0"
        assert _REGS_V4.get(0x09) == "COR"


# ── Synthetic V4 bitstream decode ─────────────────────────────────────────────

def _build_v4_stream() -> bytes:
    """
    Build a minimal valid Virtex-4 config stream:
      sync word + NOP + IDCODE write (0x0191C093 = XC4VFX100 IDCODE) +
      CMD=WCFG + FAR write (block=0, row=1, col=2, minor=0) +
      Type1(FDRI,wc=0) + Type2(FDRI, 41 words) + CMD=DESYNC
    """
    SYNC   = b"\xaa\x99\x55\x66"
    NOP    = struct.pack(">I", 0x20000000)

    def t1(reg: int, wc: int, payload: bytes = b"") -> bytes:
        hdr = (0b001 << 29) | (0b10 << 27) | (reg << 13) | (wc & 0x7FF)
        return struct.pack(">I", hdr) + payload

    def t2(wc: int, payload: bytes) -> bytes:
        hdr = (0b010 << 29) | (0b10 << 27) | (wc & 0x07FFFFFF)
        return struct.pack(">I", hdr) + payload

    IDCODE_REG = 0x0C
    CMD_REG    = 0x04
    FAR_REG    = 0x01
    FDRI_REG   = 0x02

    WCFG_CMD   = struct.pack(">I", 0x00000001)
    DESYNC_CMD = struct.pack(">I", 0x0000000D)

    # FAR: block=0, row=1, col=2, minor=0
    far_val = (0 << 24) | (1 << 17) | (2 << 8) | 0
    FAR_PAYLOAD = struct.pack(">I", far_val)

    IDCODE_PAYLOAD = struct.pack(">I", 0x0191C093)

    frame_data = bytes(41 * 4)  # 41 words of zeros

    return (
        SYNC
        + NOP
        + t1(IDCODE_REG, 1, IDCODE_PAYLOAD)
        + t1(CMD_REG, 1, WCFG_CMD)
        + t1(FAR_REG, 1, FAR_PAYLOAD)
        + t1(FDRI_REG, 0)          # Type1 wc=0 → signals Type2 follows
        + t2(41, frame_data)        # Type2 FDRI: 41 words
        + t1(CMD_REG, 1, DESYNC_CMD)
    )


class _FakeBitfile:
    def __init__(self, part: str, data: bytes):
        self._part = part
        self._data = data

    def part_name(self) -> str:
        return self._part

    def bitstream_bytes(self) -> bytes:
        return self._data

    def is_compressed(self) -> bool:
        return False


class TestSyntheticV4Decode:
    def setup_method(self):
        data = _build_v4_stream()
        bf = _FakeBitfile("xc4vfx100ff1152-11", data)
        self.dec = XilinxFrameDecoder.from_bitfile(bf)

    def test_family_detected(self):
        assert self.dec.family() == "v4"

    def test_frame_words(self):
        assert self.dec.frame_words() == 41

    def test_idcode_extracted(self):
        assert self.dec.idcode() == 0x0191C093

    def test_fdri_frame_data_length(self):
        fd = self.dec.frame_data()
        assert len(fd) == 1
        assert len(fd[0]) == 41 * 4

    def test_far_fdri_pair(self):
        pairs = self.dec.far_fdri_pairs()
        assert len(pairs) == 1
        far_val, data = pairs[0]
        f = self.dec.decode_far(far_val)
        assert f["block"] == 0
        assert f["row"] == 1
        assert f["col"] == 2
        assert f["minor"] == 0

    def test_summary_mentions_v4(self):
        s = self.dec.summary()
        assert "v4" in s

    def test_config_registers(self):
        regs = self.dec.config_registers()
        assert "IDCODE" in regs
        assert regs["IDCODE"] == 0x0191C093
