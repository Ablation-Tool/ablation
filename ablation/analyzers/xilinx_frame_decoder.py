"""
xilinx_frame_decoder.py — Xilinx Type1/Type2 config packet decoder.

Decodes configuration packets from UNCOMPRESSED Xilinx bitstreams.
Compressed bitstreams (COMPRESS=TRUE, e.g. FELIX FLX712) return an empty
decoder — use XilinxBitfile.part_name() for device identification only.

Supported families:
  - 7-series (Kintex-7, Artix-7, Zynq): full packet decode, FAR+FDRI via T1(wc=0)→T2
  - Spartan-6 (XC6SLX45 Atlys): setup packets decoded, frame data via streaming FDRI
      (Spartan-6 uses CMD=WCFG + streaming mode: frame words flow without Type2
       wrappers; use heuristic_frame_bytes() / frame_diff() for version comparison)
  - Spartan-3AN (XC3S50AN ABC130): sync word absent, metadata-only fallback
  - Spartan-2E (XC2S200E/XC2S600E TIM-3C firmware): full packet decode; frame_words=30
      (FLR register at 0x0B encodes frame_words-1; FAR/FDRI/CMD/CRC same addresses as 7s)

Packet format (same encoding across ALL Xilinx families from Spartan-2 through 7-series):
    Type1: [31:29]=001  [28:27]=op  [26:18]=rsvd  [17:13]=reg(5b)  [12:11]=rsvd  [10:0]=wcount
    Type2: [31:29]=010  [28:27]=op  [26:0]=wcount(27b)
    NOP:   [31:29]=001  [28:27]=00  any lower bits  (wcount must be 0 for valid NOP)
    DESYNC: 0x0000000D written to CMD register triggers desynchronisation

Usage:
    bf  = XilinxBitfile.from_path('/path/to/design.bit')
    dec = XilinxFrameDecoder.from_bitfile(bf)
    print(dec.summary())
    for pkt in dec.packets():
        if pkt.reg_name == 'FDRI':
            print(f'FDRI {pkt.word_count} words at FAR=0x{pkt.context_far:08X}')
    diff = dec.frame_diff(dec_v2)
    print(f'{len(diff)} differing frame positions')
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Register maps ─────────────────────────────────────────────────────────────

# 7-series register map (5-bit addresses, from UG470)
_REGS_7S: Dict[int, str] = {
    0x00: "CRC",    0x01: "FAR",    0x02: "FDRI",   0x03: "FDRO",
    0x04: "CMD",    0x05: "CTL0",   0x06: "MASK",   0x07: "STAT",
    0x08: "LOUT",   0x09: "COR0",   0x0A: "MFWR",   0x0B: "CBC",
    0x0C: "IDCODE", 0x0D: "AXSS",   0x0E: "COR1",   0x10: "WBSTAR",
    0x11: "TIMER",  0x13: "BOOTSTS",0x15: "CTL1",
}

# Spartan-2/2E register map (5-bit addresses, from XAPP138 / Spartan-2E Config Guide)
# Addresses 0x00-0x04 identical to 7-series. Key differences:
#   0x09 = COR  (not COR0)
#   0x0B = FLR  (Frame Length Register, value = frame_words-1; 7s has CBC here)
#   0x0E = IDCODE (in Spartan-2E; 7s has IDCODE at 0x0C)
_REGS_S2E: Dict[int, str] = {
    0x00: "CRC",   0x01: "FAR",   0x02: "FDRI",  0x03: "FDRO",
    0x04: "CMD",   0x05: "CTL",   0x06: "MASK",  0x07: "STAT",
    0x08: "LOUT",  0x09: "COR",   0x0A: "MFWR",  0x0B: "FLR",
    0x0C: "KEY",   0x0D: "AXSS",  0x0E: "IDCODE",
}

# Virtex-4 register map (5-bit addresses, from UG071 Table 6-2)
# Nearly identical to 7-series but: single COR (not COR0/COR1), CTL (not CTL0),
# no WBSTAR/TIMER/BOOTSTS/CTL1 (those are 7-series-only).
_REGS_V4: Dict[int, str] = {
    0x00: "CRC",   0x01: "FAR",   0x02: "FDRI",  0x03: "FDRO",
    0x04: "CMD",   0x05: "CTL",   0x06: "MASK",  0x07: "STAT",
    0x08: "LOUT",  0x09: "COR",   0x0A: "MFWR",  0x0B: "CBC",
    0x0C: "IDCODE",0x0D: "AXSS",
}

# Virtex-4 FAR block type field [25:24] (UG071 Table 6-1)
# FAR layout: [31:26]=rsvd, [25:24]=block(2b), [23:17]=row(7b), [16:8]=col(9b), [7:0]=minor(8b)
_V4_FAR_BLOCK_TYPES: Dict[int, str] = {
    0: "CLB/IO/GCLK",
    1: "BRAM_content",
    2: "CFG_CLK_DCM",
    3: "BRAM_cfg",
}

# 7-series / UltraScale FAR block type field [25:23] (UG470 Table 5-31)
# FAR layout: [31:26]=rsvd, [25:23]=block(3b), [22:17]=row(6b), [16:7]=col(10b), [6:0]=minor(7b)
_7S_FAR_BLOCK_TYPES: Dict[int, str] = {
    0: "CLB/IO/CLK",
    1: "BRAM_content",
    2: "CFG_CLK",
}

# Spartan-6 register map (5-bit addresses, from UG380)
_REGS_S6: Dict[int, str] = {
    0x00: "CRC",    0x01: "FAR_MAJ",0x02: "FAR_MIN",0x03: "FDRI",
    0x04: "FDRO",   0x05: "CMD",    0x06: "CTL",    0x07: "MASK",
    0x08: "STAT",   0x09: "LOUT",   0x0A: "COR1",   0x0B: "COR2",
    0x0C: "PWRDN",  0x0D: "FLR",    0x0E: "IDCODE", 0x0F: "CWDT",
    0x10: "HC_OPT", 0x12: "CSBO",   0x14: "GENERAL1",0x15: "GENERAL2",
    0x16: "GENERAL3",0x17: "GENERAL4",0x18: "GENERAL5",
    0x1A: "MODE",   0x1C: "PU_GWE", 0x1D: "PU_GTS",
    0x1E: "MFWR",   0x1F: "SEU_OPT",
}

# CMD register values (same across families)
_CMD_NAMES: Dict[int, str] = {
    0x00: "NULL",   0x01: "WCFG",   0x02: "MFW",    0x03: "LFRM",
    0x04: "RCFG",   0x05: "START",  0x07: "RCRC",   0x08: "AGHIGH",
    0x09: "SWITCH", 0x0A: "GRESTORE",0x0B: "SHUTDOWN",0x0C: "DESYNC",
    0x0D: "IPROG",  0x0E: "CRCC",
}

# Sync word in all Xilinx bitstreams
_SYNC_WORD = b"\xaa\x99\x55\x66"

# Packet type identifiers
_PT_TYPE1 = 0b001
_PT_TYPE2 = 0b010
_OP_NOP   = 0b00
_OP_READ  = 0b01
_OP_WRITE = 0b10

# Frame sizes in 32-bit words per device family
_FRAME_WORDS: Dict[str, int] = {
    "7s":  101,   # 7-series: 101 words per frame
    "s6":   65,   # Spartan-6: 65 words per frame
    "s3":  208,   # Spartan-3: varies; 208 for XC3S50AN
    "ku":  123,   # Kintex UltraScale+
    "s2e":  30,   # Spartan-2E: FLR=0x1D (29) → frame_words=30 (XC2S200E/XC2S600E)
    "v4":   41,   # Virtex-4 (all variants LX/FX/SX): UG071 Table 9-1
}

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class ConfigPacket:
    """One decoded configuration packet."""
    offset: int          # byte offset within the bitstream
    pkt_type: int        # 1 or 2
    opcode: int          # 0=NOP, 1=Read, 2=Write, 3=Reserved
    reg_addr: int        # 5-bit register address
    reg_name: str        # human-readable name from register map
    word_count: int      # number of 32-bit words of payload
    payload: bytes       # raw payload bytes (empty if word_count==0)
    context_far: int     # FAR address last written before this packet (0 if none)

    def value(self) -> Optional[int]:
        """Return the single 32-bit value, or None if word_count != 1."""
        if self.word_count == 1 and len(self.payload) >= 4:
            return struct.unpack_from(">I", self.payload, 0)[0]
        return None

    def cmd_name(self) -> str:
        """If reg=CMD and wc=1, return the command name."""
        if self.reg_name == "CMD" and self.word_count == 1:
            val = self.value()
            if val is not None:
                return _CMD_NAMES.get(val, f"0x{val:04X}")
        return ""


# ── Main class ────────────────────────────────────────────────────────────────

class XilinxFrameDecoder:
    """
    Configuration packet decoder for uncompressed Xilinx bitstreams.

    Requires an XilinxBitfile instance. Compressed bitstreams return a decoder
    whose packets() and config_registers() return empty results.

    Family detection is from the part_name() field:
      '6sl'  → Spartan-6 (two sync words, FAR_MAJ/FAR_MIN/FDRI)
      '3s'   → Spartan-3 (heuristic only, no packet decode)
      'xc7'  → 7-series
      'xcku' / 'xcvu' / 'xcvm' → UltraScale/Versal
    """

    def __init__(
        self,
        part: str,
        family: str,
        reg_map: Dict[int, str],
        frame_words: int,
        pkt_list: List[ConfigPacket],
        sync_offset: int,
        raw_bitstream: bytes,
    ) -> None:
        self._part        = part
        self._family      = family
        self._reg_map     = reg_map
        self._frame_words = frame_words
        self._pkts        = pkt_list
        self._sync_offset = sync_offset
        self._raw         = raw_bitstream

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_bitfile(cls, bf: object) -> "XilinxFrameDecoder":
        """
        Decode configuration packets from an XilinxBitfile instance.

        For compressed bitstreams or devices where the sync word is absent
        (Spartan-3AN in SPI-flash mode), returns a decoder with no packets.
        """
        part = bf.part_name().lower()
        bs   = bf.bitstream_bytes()

        family, reg_map, frame_words = _detect_family(part)

        # For compressed bitstreams, skip packet decode
        if bf.is_compressed():
            return cls(part, family, reg_map, frame_words, [], -1, bs)

        # Spartan-6 has two sync words: use the SECOND one
        sw = _find_config_sync(bs, family)
        if sw < 0:
            return cls(part, family, reg_map, frame_words, [], -1, bs)

        pkts = _decode_packets(bs, sw, reg_map)
        return cls(part, family, reg_map, frame_words, pkts, sw, bs)

    # ── Public API ────────────────────────────────────────────────────────────

    def summary(self) -> str:
        lines = [
            f"XilinxFrameDecoder: {self._part}",
            f"  family      : {self._family}",
            f"  sync_offset : {self._sync_offset}",
            f"  packets     : {len(self._pkts)}",
        ]
        regs = self.config_registers()
        if regs:
            lines.append("  final reg values:")
            for rname, val in sorted(regs.items()):
                lines.append(f"    {rname:12s} = 0x{val:08X}")
        fdri = self.frame_data()
        if fdri:
            total = sum(len(f) for f in fdri)
            lines.append(
                f"  frame data  : {len(fdri)} FDRI write(s), "
                f"{total // 4} words total"
            )
        else:
            hbytes = self.heuristic_frame_bytes()
            if hbytes:
                lines.append(
                    f"  frame data  : {len(hbytes)} bytes heuristic "
                    f"(streaming FDRI / use heuristic_frame_bytes())"
                )
        return "\n".join(lines)

    def packets(self) -> List[ConfigPacket]:
        """Return the decoded packet list in order."""
        return list(self._pkts)

    def config_registers(self) -> Dict[str, int]:
        """
        Return the final value written to each register (last write wins).
        Only includes single-word writes (word_count == 1).
        """
        result: Dict[str, int] = {}
        for pkt in self._pkts:
            if pkt.opcode == _OP_WRITE and pkt.word_count == 1:
                val = pkt.value()
                if val is not None:
                    result[pkt.reg_name] = val
        return result

    def frame_data(self) -> List[bytes]:
        """
        Return the raw payload bytes for every FDRI write packet.
        For Spartan-6, FDRI is register 0x03; for 7-series, register 0x02.
        """
        fdri_name = "FDRI"
        return [
            pkt.payload
            for pkt in self._pkts
            if pkt.reg_name == fdri_name and pkt.word_count > 0
        ]

    def far_fdri_pairs(self) -> List[Tuple[int, bytes]]:
        """
        Return (far_address, frame_data_bytes) for each FDRI write.
        The FAR address is the last FAR (or FAR_MAJ) value written before the FDRI.
        """
        return [
            (pkt.context_far, pkt.payload)
            for pkt in self._pkts
            if pkt.reg_name == "FDRI" and pkt.word_count > 0
        ]

    def frame_diff(
        self, other: "XilinxFrameDecoder"
    ) -> Dict[int, Tuple[bytes, bytes]]:
        """
        Compare frame data between this decoder and *other* at the word level.

        Returns a dict of {word_offset: (word_self, word_other)} for every
        32-bit word that differs.

        For 7-series targets, compares concatenated FDRI payloads.
        For Spartan-6 (streaming FDRI), automatically falls back to
        heuristic_frame_bytes() so version comparison always works.
        """
        fdri_a = b"".join(self.frame_data())
        fdri_b = b"".join(other.frame_data())
        if fdri_a and fdri_b:
            a, b_ = fdri_a, fdri_b
        else:
            a  = self.heuristic_frame_bytes()
            b_ = other.heuristic_frame_bytes()
        n = min(len(a), len(b_)) // 4
        diffs: Dict[int, Tuple[bytes, bytes]] = {}
        for i in range(n):
            wa = a[i * 4 : i * 4 + 4]
            wb = b_[i * 4 : i * 4 + 4]
            if wa != wb:
                diffs[i] = (wa, wb)
        return diffs

    def idcode(self) -> int:
        """
        Return the IDCODE value written to the IDCODE register, or 0 if not found.
        """
        for pkt in self._pkts:
            if pkt.reg_name == "IDCODE" and pkt.word_count == 1:
                val = pkt.value()
                if val:
                    return val
        return 0

    def family(self) -> str:
        """Return the detected family string ('7s', 's6', 's3', 'ku', etc.)."""
        return self._family

    def frame_words(self) -> int:
        """Return the number of 32-bit words per configuration frame."""
        return self._frame_words

    def decode_far(self, far_val: int) -> Dict[str, object]:
        """
        Decode a FAR register value into component fields for the detected family.

        Returns a dict with 'block', 'row', 'col', 'minor' keys (all int), plus
        'block_name' (str) where the block type has a known name.

        Virtex-4 FAR:  [25:24]=block(2b), [23:17]=row(7b), [16:8]=col(9b), [7:0]=minor(8b)
        7s/ku FAR:     [25:23]=block(3b), [22:17]=row(6b), [16:7]=col(10b), [6:0]=minor(7b)
        S6 uses FAR_MAJ/FAR_MIN separately; this returns {'raw': far_val}.
        """
        if self._family == "v4":
            block = (far_val >> 24) & 0x3
            return {
                "block":      block,
                "block_name": _V4_FAR_BLOCK_TYPES.get(block, f"RSVD({block})"),
                "row":        (far_val >> 17) & 0x7F,
                "col":        (far_val >>  8) & 0x1FF,
                "minor":       far_val        & 0xFF,
            }
        if self._family in ("7s", "ku"):
            block = (far_val >> 23) & 0x7
            return {
                "block":      block,
                "block_name": _7S_FAR_BLOCK_TYPES.get(block, f"RSVD({block})"),
                "row":        (far_val >> 17) & 0x3F,
                "col":        (far_val >>  7) & 0x3FF,
                "minor":       far_val        & 0x7F,
            }
        if self._family == "s2e":
            return {
                "block": (far_val >> 25) & 0x1,
                "row":   (far_val >> 17) & 0xFF,
                "col":   (far_val >>  9) & 0xFF,
                "minor":  far_val        & 0x1FF,
            }
        # S6 (FAR_MAJ/FAR_MIN) and others: return raw
        return {"raw": far_val}

    def heuristic_frame_bytes(self) -> bytes:
        """
        Return a raw byte slice spanning the configuration frame region.

        For bitstreams where full packet decode is unavailable (Spartan-3AN),
        or as a fast alternative: skip the setup header (first 512 bytes after
        the sync word) and return the remainder minus the last 1024 bytes of
        epilogue. Use for version-to-version byte comparison.
        """
        if self._sync_offset < 0:
            # No sync word: return full bitstream minus preamble (first 16 bytes)
            return self._raw[16:]
        start = self._sync_offset + 4 + 512
        end   = len(self._raw) - 1024
        if end <= start:
            return b""
        return self._raw[start:end]


# ── Family detection ──────────────────────────────────────────────────────────

def _detect_family(
    part: str,
) -> Tuple[str, Dict[int, str], int]:
    """Return (family_tag, reg_map, frame_words) from the lowercase part name."""
    if part.startswith("2s"):
        return "s2e", _REGS_S2E, _FRAME_WORDS["s2e"]
    if part.startswith("6s"):
        return "s6", _REGS_S6, _FRAME_WORDS["s6"]
    if part.startswith("3s"):
        return "s3", _REGS_S6, _FRAME_WORDS["s3"]  # Spartan-3 regs ~ S6
    if part.startswith("xc4v"):
        return "v4", _REGS_V4, _FRAME_WORDS["v4"]
    if part.startswith(("xcku", "xcvu", "xcvm", "xcvp")):
        return "ku", _REGS_7S, _FRAME_WORDS["ku"]
    # Default: 7-series (xc7a, xc7k, xc7v, xc7z, xcartix, xckintex, ...)
    return "7s", _REGS_7S, _FRAME_WORDS["7s"]


# ── Sync word location ────────────────────────────────────────────────────────

def _find_config_sync(bs: bytes, family: str) -> int:
    """
    Return the byte offset of the configuration sync word in *bs*.

    Spartan-6 bitstreams contain TWO sync words: the first is a bus-width
    detection marker and the second is the real configuration stream start.
    All other families use a single sync word.
    """
    first = bs.find(_SYNC_WORD)
    if first < 0:
        return -1
    if family == "s6":
        # Look for a second occurrence after the first
        second = bs.find(_SYNC_WORD, first + 4)
        if second >= 0:
            return second
    return first


# ── Packet decoder ────────────────────────────────────────────────────────────

def _decode_packets(
    bs: bytes,
    sync_offset: int,
    reg_map: Dict[int, str],
) -> List[ConfigPacket]:
    """
    Walk the bitstream from *sync_offset* + 4 and decode all packets.

    Stops at the first DESYNC command or when the bitstream is exhausted.
    Limits payload capture to 4 MB per packet (guards against corrupt wc).
    """
    pkts: List[ConfigPacket] = []
    pos = sync_offset + 4  # skip sync word itself
    current_far = 0
    _MAX_PAYLOAD = 4 * 1024 * 1024  # 4 MB guard

    # Track which register is "active" for Type2 writes
    last_reg_addr = 0
    last_reg_name = "FDRI"

    while pos + 4 <= len(bs):
        w = struct.unpack_from(">I", bs, pos)[0]
        pt = (w >> 29) & 0x7
        op = (w >> 27) & 0x3

        if pt == _PT_TYPE1:
            reg_addr = (w >> 13) & 0x1F
            wc       = w & 0x7FF
            reg_name = reg_map.get(reg_addr, f"REG{reg_addr:02X}")

            if op == _OP_NOP and wc == 0:
                # Standard NOP — skip without recording
                pos += 4
                continue

            # Capture payload (capped)
            payload_bytes = wc * 4
            if payload_bytes > _MAX_PAYLOAD:
                pos += 4
                continue
            if pos + 4 + payload_bytes > len(bs):
                break

            payload = bs[pos + 4 : pos + 4 + payload_bytes]
            pkt = ConfigPacket(
                offset=pos, pkt_type=1, opcode=op,
                reg_addr=reg_addr, reg_name=reg_name,
                word_count=wc, payload=payload,
                context_far=current_far,
            )
            pkts.append(pkt)

            # Update FAR tracker
            if reg_name in ("FAR", "FAR_MAJ") and wc == 1 and len(payload) >= 4:
                current_far = struct.unpack_from(">I", payload, 0)[0]

            # Track active register for following Type2
            if op == _OP_WRITE:
                last_reg_addr = reg_addr
                last_reg_name = reg_name

            # Stop on DESYNC
            if reg_name == "CMD" and wc == 1 and len(payload) >= 4:
                cmd_val = struct.unpack_from(">I", payload, 0)[0]
                if cmd_val == 0x0000000D:  # DESYNC
                    pos += 4 + payload_bytes
                    break

            pos += 4 + payload_bytes

        elif pt == _PT_TYPE2:
            wc27 = w & 0x07FFFFFF

            payload_bytes = wc27 * 4
            if payload_bytes > _MAX_PAYLOAD:
                pos += 4
                continue
            if pos + 4 + payload_bytes > len(bs):
                # Partial Type2 — capture what we have
                payload = bs[pos + 4 :]
            else:
                payload = bs[pos + 4 : pos + 4 + payload_bytes]

            # Type2 uses the last register address from the preceding Type1
            pkt = ConfigPacket(
                offset=pos, pkt_type=2, opcode=op,
                reg_addr=last_reg_addr, reg_name=last_reg_name,
                word_count=wc27, payload=payload,
                context_far=current_far,
            )
            pkts.append(pkt)
            pos += 4 + payload_bytes

        else:
            # Unknown / null packet — advance one word
            pos += 4

    return pkts


# ── CLI ───────────────────────────────────────────────────────────────────────

def _main() -> None:
    import sys
    if len(sys.argv) < 2:
        print("Usage: xilinx_frame_decoder.py <file.bit> [file.bit ...]")
        sys.exit(1)
    # Import lazily to avoid circular dep if run standalone
    import importlib.util as _iu
    _spec = _iu.spec_from_file_location(
        "xilinx_bitfile",
        Path(__file__).parent / "xilinx_bitfile.py",
    )
    _mod = _iu.module_from_spec(_spec)  # type: ignore[arg-type]
    _spec.loader.exec_module(_mod)      # type: ignore[union-attr]
    XilinxBitfile = _mod.XilinxBitfile

    for arg in sys.argv[1:]:
        try:
            bf  = XilinxBitfile.from_path(arg)
            dec = XilinxFrameDecoder.from_bitfile(bf)
            print(dec.summary())
            pairs = dec.far_fdri_pairs()
            for far_addr, fdata in pairs[:5]:
                print(f"  FAR=0x{far_addr:08X}  {len(fdata)//4} words")
        except Exception as exc:
            print(f"ERROR {arg}: {exc}")
        print()


if __name__ == "__main__":
    _main()
