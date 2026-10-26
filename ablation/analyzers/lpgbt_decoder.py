"""
lpgbt_decoder.py: Software decoder for lpGBT e-link serial protocols.

Covers all three physical link types used in ATLAS ITk Strip detector e-links:

  LCB downlink (lpGBT → HCC, 640 Mb/s):
    Custom 6B/8B encoding. 64 data symbols + 4 K symbols (K0–K3).
    16-bit frames: Symbol0 carries L0A map + BCR bit, Symbol1 carries
    command payload or tag data. Frame sync via repeated IDLE_FRAME (K0||K1).
    Source: sims/lcb/downlink/ (lcb_pkg_globals.vhd, lcb_decoder.vhd)
    Author of codec: Matt Warren, UCL HEP, Aug 2016.

  STAR FLINK uplink (ABC130 → lpGBT, 160 Mb/s, 4-bit symbols):
    Parallel/BCR/LinSync/Pipeline-reset/Linpulse packet types.
    PR and LP packets carry 9-bit L0ID in 3 consecutive 3-bit data symbols.
    Source: sims/star_flink/readout130/ (pkg_star_flink.vhd)
    Author: Matt Warren, UCL HEP, July 2015.

  HCC uplink (HCC → lpGBT, 640 Mb/s, standard 8B/10B):
    Industry-standard 8B/10B encoding (ANSI/IEEE 802.3).
    HCC encodes variable-length packets (≤ 50 bytes, avg 15–30).
    Packet types: event data, register readback, calibration, DCS, warnings.

Usage:
    # Decode a buffer of LCB downlink bytes
    frames = LcbDecoder.decode_stream(data_bytes)
    for frame in frames:
        print(frame)

    # Decode STAR FLINK nibble stream
    events = StarFlinkDecoder.decode_stream(nibble_list)

    # Decode a single 10-bit 8B/10B word
    byte, is_k = decode_8b10b(0b1001110100)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, Iterator, List, Optional, Sequence, Tuple


# ── 6B/8B encode/decode tables (from lcb_pkg_globals.vhd) ───────────────────
#
# MAP_6B_8B: 6-bit index → 8-bit encoded byte.
# Every valid codeword has exactly 4 set bits (Hamming weight 4).
# The 4-of-8 property enables a single-bit parity check in lcb_frame_sync.vhd.
#
# Attribution: "From Paul" (Paul Sherwood, CERN) per VHDL comment.

_MAP_6B_8B: Tuple[int, ...] = (
    0x59, 0x71, 0x72, 0xc3, 0x65, 0xc5, 0xc6, 0x87,  #  0– 7
    0x69, 0xc9, 0xca, 0x8b, 0xcc, 0x8d, 0x8e, 0x4b,  #  8–15
    0x53, 0xd1, 0xd2, 0x93, 0xd4, 0x95, 0x96, 0x17,  # 16–23
    0xd8, 0x99, 0x9a, 0x1b, 0x9c, 0x1d, 0x1e, 0x5c,  # 24–31
    0x63, 0xe1, 0xe2, 0xa3, 0xe4, 0xa5, 0xa6, 0x27,  # 32–39
    0xe8, 0xa9, 0xaa, 0x2b, 0xac, 0x2d, 0x2e, 0x6c,  # 40–47
    0x74, 0xb1, 0xb2, 0x33, 0xb4, 0x35, 0x36, 0x56,  # 48–55
    0xb8, 0x39, 0x3a, 0x5a, 0x3c, 0x4d, 0x4e, 0x66,  # 56–63
)

# MAP_K_8B: K-symbol index (0–3) → 8-bit encoded byte
_MAP_K_8B: Tuple[int, ...] = (0x47, 0x55, 0x78, 0x6a)

# Reverse table: encoded byte → (6-bit value, is_k_symbol)
_DECODE_6B8B: Dict[int, Tuple[int, bool]] = {}
for _i, _b in enumerate(_MAP_6B_8B):
    _DECODE_6B8B[_b] = (_i, False)
for _i, _b in enumerate(_MAP_K_8B):
    _DECODE_6B8B[_b] = (_i, True)

# LCB protocol constants (from lcb_pkg_globals.vhd + lcb_decoder.vhd)
LCB_K0: int = _MAP_K_8B[0]           # 0x47 — IDLE MSB
LCB_K1: int = _MAP_K_8B[1]           # 0x55 — IDLE LSB
LCB_K2: int = _MAP_K_8B[2]           # 0x78 — CMD header (fast cmd / K2 packet)
LCB_K3: int = _MAP_K_8B[3]           # 0x6a — extended CMD stream header
LCB_IDLE_FRAME: int = (LCB_K0 << 8) | LCB_K1   # 0x4755 — repeated during idle

# Command symbols extracted from VHDL named constants
LCB_SYMB_CMD_IGNORE: int = _MAP_6B_8B[0b100000]  # 0x63 — broadcast ignore
LCB_SYMB_CMD_END:    int = _MAP_6B_8B[0b000001]  # 0x71 — end-of-command
LCB_SYMB_ECR:        int = _MAP_6B_8B[0b000010]  # 0x72 — Event Count Reset
LCB_SYMB_ABCRST:     int = _MAP_6B_8B[0b000100]  # 0x65 — ABC reset
LCB_SYMB_HCCRST:     int = _MAP_6B_8B[0b001000]  # 0x69 — HCC reset

# ASIC type bytes (from lcb_pkg_globals.vhd: constant HCC / ABC)
LCB_ASIC_HCC: int = 0xcc
LCB_ASIC_ABC: int = 0xab


def decode_6b8b(byte: int) -> Optional[Tuple[int, bool]]:
    """
    Decode one 8-bit LCB byte → (6-bit_value, is_k_symbol).

    Returns None for invalid (non-codeword) bytes.
    """
    return _DECODE_6B8B.get(byte)


def encode_6b8b(value: int, is_k: bool = False) -> int:
    """
    Encode a 6-bit value (0–63) or K-symbol index (0–3) to an 8-bit LCB byte.

    Raises ValueError for out-of-range inputs.
    """
    if is_k:
        if not (0 <= value <= 3):
            raise ValueError(f"K symbol index must be 0–3, got {value}")
        return _MAP_K_8B[value]
    if not (0 <= value <= 63):
        raise ValueError(f"6-bit value must be 0–63, got {value}")
    return _MAP_6B_8B[value]


# ── LCB frame structures ──────────────────────────────────────────────────────

class LcbFrameType(IntEnum):
    IDLE    = 0   # K0||K1 — no payload
    L0A     = 1   # Level-0 Accept trigger (+ optional BCR)
    BCR     = 2   # Bunch Counter Reset only
    CMD     = 3   # Command packet (K2 or K3 header)
    UNKNOWN = 99


@dataclass
class LcbSymbol:
    """One decoded LCB 8-bit symbol."""
    raw: int           # raw encoded byte
    value: int         # 6-bit decoded value (or K index 0–3)
    is_k: bool         # True = K symbol, False = data symbol
    valid: bool        # False = unrecognised codeword


@dataclass
class LcbFrame:
    """
    One decoded LCB 16-bit frame (two symbols).

    The LCB downlink is framed in 16-bit units: Symbol0 is transmitted first,
    Symbol1 second. Frame sync is established when IDLE_FRAME (K0||K1 = 0x4755)
    appears in consecutive 16-bit windows.

    Symbol0 structure (at FSYNC_SYMB0, decoded from 6-bit value):
        bit 5:      dec_tag_msb — MSB of the L0A tag counter
        bits 4–1:   dec_l0a_map[3:0] — 4-bit L0A trigger map
        bit 0:      dec_bcr — Bunch Counter Reset flag

    Symbol1 structure (at FSYNC_FRAME):
        K2 in Symbol0 → Symbol1 is fast-command or K3 intro
        K3 in Symbol0 → Symbol1..+N carry command bus data (cbus)
        data in Symbol0 → Symbol1 carries tag LSBs [5:0]
    """
    offset: int              # byte offset in the source stream
    symbol0: LcbSymbol
    symbol1: LcbSymbol
    frame_type: LcbFrameType = LcbFrameType.UNKNOWN

    # Decoded fields populated after construction
    l0a_map: int = 0         # 4-bit trigger map from Symbol0[4:1]
    bcr: bool = False        # Bunch Counter Reset from Symbol0[0]
    tag_msb: int = 0         # tag counter MSB from Symbol0[5]
    tag_lsbs: int = 0        # tag LSBs [5:0] from Symbol1 (when applicable)
    fast_cmd: int = 0        # fast command nibble when K2 header
    cmd_hccid: int = 0       # HCC ID from command symbol when K3 header

    def tag(self) -> int:
        """Reconstruct 7-bit L0A tag from MSB and LSBs."""
        return (self.tag_msb << 6) | (self.tag_lsbs & 0x3f)

    def __str__(self) -> str:
        parts = [f"@{self.offset:04x} {self.frame_type.name}"]
        if self.bcr:
            parts.append("BCR")
        if self.l0a_map:
            parts.append(f"L0A={self.l0a_map:#06b}")
        if self.frame_type == LcbFrameType.L0A:
            parts.append(f"tag={self.tag():#04x}")
        if self.frame_type == LcbFrameType.CMD:
            parts.append(f"fast_cmd={self.fast_cmd:#06b}")
        s0 = f"{self.symbol0.raw:#04x}"
        s1 = f"{self.symbol1.raw:#04x}"
        parts.append(f"[{s0}|{s1}]")
        return " ".join(parts)


class LcbDecoder:
    """
    Software decoder for the LCB (Low-latency Command Broadcast) downlink.

    Scans a byte buffer for LCB frame sync, then decodes 16-bit frames.

    Frame sync: look for consecutive occurrences of IDLE_FRAME (0x4755)
    at the same byte alignment (either even or odd). Once sync is acquired
    at a given phase, all subsequent frames are decoded at that phase.
    """

    IDLE_SYNC_COUNT: int = 3   # consecutive IDLE frames needed to lock

    @staticmethod
    def _decode_symbol(byte: int) -> LcbSymbol:
        result = decode_6b8b(byte)
        if result is None:
            return LcbSymbol(raw=byte, value=0, is_k=False, valid=False)
        value, is_k = result
        return LcbSymbol(raw=byte, value=value, is_k=is_k, valid=True)

    @staticmethod
    def _decode_frame(offset: int, s0_byte: int, s1_byte: int) -> LcbFrame:
        s0 = LcbDecoder._decode_symbol(s0_byte)
        s1 = LcbDecoder._decode_symbol(s1_byte)

        frame = LcbFrame(offset=offset, symbol0=s0, symbol1=s1)

        # IDLE: both K symbols in IDLE pattern
        if s0_byte == LCB_K0 and s1_byte == LCB_K1:
            frame.frame_type = LcbFrameType.IDLE
            return frame

        # Decode Symbol0 fields (valid for all non-IDLE frames)
        if s0.valid and not s0.is_k:
            v = s0.value
            frame.tag_msb  = (v >> 5) & 0x1
            frame.l0a_map  = (v >> 1) & 0xf
            frame.bcr      = bool(v & 0x1)

        # Symbol0 K2 → CMD frame (fast command in Symbol1)
        if s0.is_k and s0.value == 2:  # K2
            frame.frame_type = LcbFrameType.CMD
            if s1.valid and not s1.is_k:
                frame.fast_cmd = s1.value & 0xf
            return frame

        # Symbol0 K3 → extended CMD frame
        if s0.is_k and s0.value == 3:  # K3
            frame.frame_type = LcbFrameType.CMD
            if s1.valid and not s1.is_k:
                frame.cmd_hccid = s1.value & 0x1f
            return frame

        # Data symbol: L0A or BCR
        if s0.valid and not s0.is_k:
            if frame.bcr and not frame.l0a_map:
                frame.frame_type = LcbFrameType.BCR
            elif frame.l0a_map or frame.bcr:
                frame.frame_type = LcbFrameType.L0A
                # Symbol1 carries tag LSBs when it's a data symbol
                if s1.valid and not s1.is_k:
                    frame.tag_lsbs = s1.value & 0x3f
            return frame

        return frame

    @classmethod
    def decode_stream(cls, data: bytes) -> List[LcbFrame]:
        """
        Decode all LCB frames in a byte buffer.

        Phase-aligns automatically: tries both even (phase=0) and odd (phase=1)
        byte offsets and picks the phase that achieves sync fastest.
        """
        if len(data) < 2:
            return []

        # Find the phase (0 or 1) that gives the most consecutive IDLE frames
        phase = cls._find_phase(data)
        return list(cls._iter_frames(data, phase))

    @classmethod
    def _find_phase(cls, data: bytes) -> int:
        """Return the phase (0 or 1) with the highest IDLE frame count."""
        best_phase = 0
        best_count = 0
        for phase in (0, 1):
            count = 0
            for i in range(phase, len(data) - 1, 2):
                if data[i] == LCB_K0 and data[i + 1] == LCB_K1:
                    count += 1
            if count > best_count:
                best_count, best_phase = count, phase
        return best_phase

    @classmethod
    def _iter_frames(cls, data: bytes, phase: int) -> Iterator[LcbFrame]:
        for i in range(phase, len(data) - 1, 2):
            yield cls._decode_frame(i, data[i], data[i + 1])

    @classmethod
    def report(cls, frames: List[LcbFrame]) -> str:
        """Summary statistics for a decoded frame list."""
        total   = len(frames)
        idle    = sum(1 for f in frames if f.frame_type == LcbFrameType.IDLE)
        l0a     = sum(1 for f in frames if f.frame_type == LcbFrameType.L0A)
        bcr     = sum(1 for f in frames if f.frame_type == LcbFrameType.BCR)
        cmd     = sum(1 for f in frames if f.frame_type == LcbFrameType.CMD)
        unknown = sum(1 for f in frames if f.frame_type == LcbFrameType.UNKNOWN)
        invalid = sum(1 for f in frames
                      if not f.symbol0.valid or not f.symbol1.valid)
        lines = [
            f"LcbDecoder: {total} frames",
            f"  IDLE    : {idle}",
            f"  L0A     : {l0a}",
            f"  BCR     : {bcr}",
            f"  CMD     : {cmd}",
            f"  UNKNOWN : {unknown}",
            f"  invalid : {invalid} (bad codewords)",
        ]
        sample = [f for f in frames if f.frame_type != LcbFrameType.IDLE][:5]
        if sample:
            lines.append("  Non-idle frames (first 5):")
            for f in sample:
                lines.append(f"    {f}")
        return "\n".join(lines)


# ── STAR FLINK uplink decoder ────────────────────────────────────────────────
#
# Source: sims/star_flink/readout130/pkg_star_flink.vhd
# 4-bit symbol encoding at 160 Mb/s. Each BC clock produces one 4-bit symbol.
# Serial output is 160 Mb/s (4 bits per 40 MHz BCO clock).

class StarFlinkSymbol(IntEnum):
    """4-bit STAR FLINK symbol constants (from pkg_star_flink.vhd)."""
    sIDLE  = 0x1   # Idle
    sBCR   = 0x2   # Bunch Counter Reset
    sLS    = 0x3   # Line Sync
    sBCRLS = 0x4   # BCR + Line Sync
    sPR    = 0x5   # Pipeline Reset (header; L0ID follows in 3 symbols)
    sLP    = 0x6   # Linpulse      (header; L0ID follows in 3 symbols)
    sDATA7 = 0x7   # data[2:0] = 111
    sDATA0 = 0x8   # data[2:0] = 000
    sDATA1 = 0x9   # data[2:0] = 001
    sDATA2 = 0xa   # data[2:0] = 010
    sDATA3 = 0xb   # data[2:0] = 011
    sDATA4 = 0xc   # data[2:0] = 100
    sDATA5 = 0xd   # data[2:0] = 101
    sDATA6 = 0xe   # data[2:0] = 110
    # 0x0 and 0xf are not defined in the package (invalid)


# Decode a 4-bit STAR FLINK symbol to its 3-bit data value.
# sDATA0–7 map to 0–7 in a non-contiguous pattern:
_STAR_SYMB_TO_DATA = {
    0x8: 0, 0x9: 1, 0xa: 2, 0xb: 3,
    0xc: 4, 0xd: 5, 0xe: 6, 0x7: 7,
}
_STAR_DATA_TO_SYMB = {v: k for k, v in _STAR_SYMB_TO_DATA.items()}


class StarFlinkEventType(IntEnum):
    IDLE    = 0
    BCR     = 1
    LS      = 2
    BCRLS   = 3
    PR      = 4   # Pipeline Reset — carries L0ID
    LP      = 5   # Linpulse — carries L0ID
    INVALID = 99


@dataclass
class StarFlinkEvent:
    """One decoded STAR FLINK uplink event."""
    offset: int                    # nibble offset in source stream
    event_type: StarFlinkEventType
    l0id: int = 0                  # 9-bit L0ID for PR/LP events (0 otherwise)

    def __str__(self) -> str:
        s = f"@{self.offset:04x} {self.event_type.name}"
        if self.event_type in (StarFlinkEventType.PR, StarFlinkEventType.LP):
            s += f" L0ID={self.l0id:#05x}"
        return s


class StarFlinkDecoder:
    """
    Software decoder for the STAR FLINK 4-bit uplink symbol stream.

    Input is a sequence of 4-bit nibbles (integers 0–15).
    PR and LP events consume 4 nibbles total: header + 3 data symbols
    (each data symbol carries 3 bits, reconstructing a 9-bit L0ID).
    """

    @classmethod
    def decode_stream(cls, nibbles: Sequence[int]) -> List[StarFlinkEvent]:
        """Decode all events in a 4-bit nibble sequence."""
        events: List[StarFlinkEvent] = []
        i = 0
        while i < len(nibbles):
            sym = nibbles[i]
            if sym == StarFlinkSymbol.sPR or sym == StarFlinkSymbol.sLP:
                # PR or LP: next 3 nibbles are DATA symbols carrying L0ID[8:0]
                if i + 3 >= len(nibbles):
                    break  # incomplete packet at end of buffer
                l0id = 0
                valid = True
                for j in range(3):
                    d = _STAR_SYMB_TO_DATA.get(nibbles[i + 1 + j])
                    if d is None:
                        valid = False
                        break
                    l0id = (l0id << 3) | d
                etype = (StarFlinkEventType.PR
                         if sym == StarFlinkSymbol.sPR
                         else StarFlinkEventType.LP)
                if valid:
                    events.append(StarFlinkEvent(offset=i, event_type=etype,
                                                 l0id=l0id))
                else:
                    events.append(StarFlinkEvent(offset=i,
                                                 event_type=StarFlinkEventType.INVALID))
                i += 4
            elif sym == StarFlinkSymbol.sIDLE:
                events.append(StarFlinkEvent(offset=i,
                                             event_type=StarFlinkEventType.IDLE))
                i += 1
            elif sym == StarFlinkSymbol.sBCR:
                events.append(StarFlinkEvent(offset=i,
                                             event_type=StarFlinkEventType.BCR))
                i += 1
            elif sym == StarFlinkSymbol.sLS:
                events.append(StarFlinkEvent(offset=i,
                                             event_type=StarFlinkEventType.LS))
                i += 1
            elif sym == StarFlinkSymbol.sBCRLS:
                events.append(StarFlinkEvent(offset=i,
                                             event_type=StarFlinkEventType.BCRLS))
                i += 1
            else:
                events.append(StarFlinkEvent(offset=i,
                                             event_type=StarFlinkEventType.INVALID))
                i += 1
        return events

    @classmethod
    def report(cls, events: List[StarFlinkEvent]) -> str:
        """Summary statistics for a decoded event list."""
        from collections import Counter
        counts = Counter(e.event_type for e in events)
        lines = [
            f"StarFlinkDecoder: {len(events)} events",
            f"  IDLE    : {counts[StarFlinkEventType.IDLE]}",
            f"  BCR     : {counts[StarFlinkEventType.BCR]}",
            f"  LS      : {counts[StarFlinkEventType.LS]}",
            f"  BCRLS   : {counts[StarFlinkEventType.BCRLS]}",
            f"  PR      : {counts[StarFlinkEventType.PR]}",
            f"  LP      : {counts[StarFlinkEventType.LP]}",
            f"  INVALID : {counts[StarFlinkEventType.INVALID]}",
        ]
        prs = [e for e in events if e.event_type == StarFlinkEventType.PR][:5]
        if prs:
            lines.append("  PR events (first 5):")
            for e in prs:
                lines.append(f"    {e}")
        return "\n".join(lines)


# ── Standard 8B/10B decoder (HCC uplink, 640 Mb/s) ──────────────────────────
#
# Standard ANSI/IEEE 8B/10B encoding (IBM, 1983). The 10-bit codeword encodes
# 8 bits of data or a K (control) symbol. Each 10-bit word is split into
# a 6-bit abcdeif group and a 4-bit fghj group.
#
# Canonical decode: the disparity-independent primary coding table.
# Only the RD− (negative running disparity) codewords are listed;
# if a codeword matches neither polarity it is invalid.
#
# For RE purposes only data bytes and K28.x (comma) characters matter.
# Full table covers all 256 data bytes + 12 standard K-symbols.

def _build_8b10b_table() -> Tuple[
    Dict[int, Tuple[int, bool]],   # 10-bit word → (byte, is_k)
    Dict[int, int],                 # 8-bit data  → 10-bit word (RD−)
]:
    """
    Build the 8B/10B decode/encode tables from first principles.

    Implements the ANSI X3.230-1994 (Fibre Channel) 8B/10B code, which is
    identical to the GBT/lpGBT uplink encoding used by HCC ASICs.
    """
    # --- 5B/6B sub-table (RD−): 5-bit Dx[4:0] → 6-bit abcdei ---
    # Source: IEEE 802.3, Table 36-3
    _5b6b_rdm = {
        0:  0b100111, 1:  0b011101, 2:  0b101101, 3:  0b110001,
        4:  0b110101, 5:  0b101001, 6:  0b011001, 7:  0b111000,
        8:  0b111001, 9:  0b100101, 10: 0b010101, 11: 0b110100,
        12: 0b001101, 13: 0b101100, 14: 0b011100, 15: 0b010111,
        16: 0b011011, 17: 0b100011, 18: 0b010011, 19: 0b110010,
        20: 0b001011, 21: 0b101010, 22: 0b011010, 23: 0b111010,
        24: 0b110011, 25: 0b100110, 26: 0b010110, 27: 0b110110,
        28: 0b001110, 29: 0b101110, 30: 0b011110, 31: 0b101011,
    }
    # RD+ is the bitwise complement for symbols where weight ≠ 3;
    # for weight-3 symbols (balanced) RD+ = RD−.
    def _complement6(v: int) -> int:
        return (~v) & 0x3f

    def _weight(v: int, bits: int) -> int:
        return bin(v & ((1 << bits) - 1)).count('1')

    _5b6b_rdp = {k: (_complement6(v) if _weight(v, 6) != 3 else v)
                 for k, v in _5b6b_rdm.items()}

    # --- 3B/4B sub-table (RD−): 3-bit Dx[7:5] → 4-bit fghj ---
    # Source: IEEE 802.3, Table 36-2
    _3b4b_rdm = {
        0: 0b1011, 1: 0b1001, 2: 0b0101, 3: 0b1100,
        4: 0b1101, 5: 0b1010, 6: 0b0110, 7: 0b1110,
    }
    _3b4b_rdp = {k: ((~v) & 0xf) if _weight(v, 4) != 2 else v
                 for k, v in _3b4b_rdm.items()}

    # Special-case: D.x.7 uses alternate 4B code when Dx[4:0] gives
    # running-disparity mismatch (Table 36-2 footnote).
    _3b4b_rdm_alt7 = 0b0111   # alternate for D.x.7 with RD−
    _3b4b_rdp_alt7 = 0b1000   # alternate for D.x.7 with RD+

    # --- K-symbol sub-tables ---
    # K28.x uses special 6B code 0b001111 (RD−) / 0b110000 (RD+)
    _k28_6b_rdm = 0b001111
    _k28_6b_rdp = 0b110000
    # K.x.7 uses 3B/4B code 0b0111 (RD−) / 0b1000 (RD+)
    _kx7_4b_rdm = 0b0111
    _kx7_4b_rdp = 0b1000
    # Standard K symbols: K28.1,2,3,4,5,6,7; K23.7, K27.7, K29.7, K30.7, K31.7
    _k_syms = {
        # K(Dx, Dy): byte value
        (28, 0): 0xbc, (28, 1): 0x3c, (28, 2): 0x5c, (28, 3): 0x7c,
        (28, 4): 0x9c, (28, 5): 0xbc,  # note: K28.5 = 0xbc = comma
        (28, 6): 0xdc, (28, 7): 0xfc,
        (23, 7): 0xf7, (27, 7): 0xfb,
        (29, 7): 0xfd, (30, 7): 0xfe, (31, 7): 0xff,
    }
    # Fix K28.5 — it's 0xbc per the standard
    _k_syms[(28, 5)] = 0xbc

    decode: Dict[int, Tuple[int, bool]] = {}
    encode: Dict[int, int] = {}

    # Build data symbol table
    for d5 in range(32):
        for d3 in range(8):
            byte_val = (d3 << 5) | d5

            # 6B part
            ab6_rdm = _5b6b_rdm[d5]
            ab6_rdp = _5b6b_rdp[d5]

            # 4B part — handle D.x.7 alternate
            if d3 == 7:
                # Use alternate when 6B is not balanced (wt≠3)
                if _weight(ab6_rdm, 6) != 3:
                    fg4_rdm = _3b4b_rdm_alt7
                else:
                    fg4_rdm = _3b4b_rdm[7]
                if _weight(ab6_rdp, 6) != 3:
                    fg4_rdp = _3b4b_rdp_alt7
                else:
                    fg4_rdp = _3b4b_rdp[7]
            else:
                fg4_rdm = _3b4b_rdm[d3]
                fg4_rdp = _3b4b_rdp[d3]

            # 10-bit words: abcdei|fghj, RD− and RD+
            word_rdm = (ab6_rdm << 4) | fg4_rdm
            word_rdp = (ab6_rdp << 4) | fg4_rdp

            decode[word_rdm] = (byte_val, False)
            if word_rdp != word_rdm:
                decode[word_rdp] = (byte_val, False)

            encode[byte_val] = word_rdm  # encode uses RD− as canonical

    # Build K-symbol table (simplified — just K28.5 comma + K28.1 for sync)
    # Full K28.x: 6B = 0b001111/0b110000, 4B from 3B/4B table
    for (d5, d3), byte_val in _k_syms.items():
        fg4_rdm = _3b4b_rdm.get(d3, 0b1110)
        fg4_rdp = _3b4b_rdp.get(d3, 0b0001)
        if d5 == 28:
            ab6_rdm = _k28_6b_rdm
            ab6_rdp = _k28_6b_rdp
        else:
            ab6_rdm = _5b6b_rdm.get(d5 & 0x1f, 0)
            ab6_rdp = _5b6b_rdp.get(d5 & 0x1f, 0)

        word_rdm = (ab6_rdm << 4) | fg4_rdm
        word_rdp = (ab6_rdp << 4) | fg4_rdp

        decode[word_rdm] = (byte_val, True)
        if word_rdp != word_rdm:
            decode[word_rdp] = (byte_val, True)

    return decode, encode


_8B10B_DECODE, _8B10B_ENCODE = _build_8b10b_table()

# Standard 8B/10B K-symbol byte values
K28_5: int = 0xbc   # comma character — frame sync
K28_1: int = 0x3c   # GBT idle / align
K28_7: int = 0xfc   # extended idle


def decode_8b10b(word10: int) -> Optional[Tuple[int, bool]]:
    """
    Decode a 10-bit 8B/10B codeword → (8-bit_byte, is_k_symbol).

    Returns None for invalid codewords.

    The HCC ASIC transmits on its 640 Mb/s uplink e-links using this encoding.
    FELIX's lpgbt-fpga IP core decodes this before routing to the host DMA.
    """
    return _8B10B_DECODE.get(word10 & 0x3ff)


def encode_8b10b(byte: int) -> int:
    """
    Encode an 8-bit data byte → 10-bit 8B/10B codeword (RD− canonical form).

    Raises KeyError for bytes not in the table.
    """
    return _8B10B_ENCODE[byte & 0xff]


def decode_8b10b_stream(bits: Sequence[int],
                        start_bit: int = 0) -> List[Tuple[int, int, bool]]:
    """
    Decode a bit sequence as consecutive 10-bit 8B/10B codewords.

    *bits* is a flat list/tuple of 0/1 integers (MSB first per codeword).
    Returns [(bit_offset, byte_value, is_k)] for each valid codeword.
    """
    results: List[Tuple[int, int, bool]] = []
    for i in range(start_bit, len(bits) - 9, 10):
        word = 0
        for j in range(10):
            word = (word << 1) | (bits[i + j] & 1)
        result = decode_8b10b(word)
        if result is not None:
            byte_val, is_k = result
            results.append((i, byte_val, is_k))
    return results


# ── Convenience wrapper ───────────────────────────────────────────────────────

class LpgbtDecoder:
    """
    Top-level convenience wrapper for all three lpGBT e-link protocols.

    Selects the right decoder based on the protocol argument.

      LpgbtDecoder.lcb(data)        → List[LcbFrame]
      LpgbtDecoder.star_flink(nibs) → List[StarFlinkEvent]
      LpgbtDecoder.hcc_8b10b(bits)  → List[(offset, byte, is_k)]
    """

    @staticmethod
    def lcb(data: bytes) -> List[LcbFrame]:
        """Decode an LCB downlink byte buffer."""
        return LcbDecoder.decode_stream(data)

    @staticmethod
    def star_flink(nibbles: Sequence[int]) -> List[StarFlinkEvent]:
        """Decode a STAR FLINK uplink nibble sequence."""
        return StarFlinkDecoder.decode_stream(nibbles)

    @staticmethod
    def hcc_8b10b(bits: Sequence[int],
                  start_bit: int = 0) -> List[Tuple[int, int, bool]]:
        """Decode an HCC uplink bit stream using standard 8B/10B."""
        return decode_8b10b_stream(bits, start_bit)
