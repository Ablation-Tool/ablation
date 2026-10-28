"""ISA and binary-format model for the Intel MCS-51 / Enhanced 8051 family.

Covers the standard MCS-51 instruction set as implemented in the Texas Instruments
CC254x (CC2540/CC2541) Enhanced 8051 cores used in BLE 4.0 SoCs.

MCS-51 ISA facts relevant to security analysis:
* Dual data spaces: IRAM (direct/indirect, 0x00–0xFF) vs XDATA (MOVX, 64KB).
  Direct address 0x80–0xFF accesses SFR; indirect @Ri on the same range accesses
  upper IRAM.  Taint analysis must track which access mode was used.
* All SFRs are memory-mapped at fixed 8-bit addresses (0x80–0xFF direct).
  Hardware crypto (AES co-processor on CC254x) is at SFR 0xB1 (ENCDI/ENCDO)
  and 0xB3 (ENCCS).  A MOV 0xB3,A write triggers the AES engine.
* Code and XDATA are separate 64KB address spaces; MOVC reads from CODE,
  MOVX reads/writes XDATA.
* Banking (CC254x): code above 0x7FFF is in a banked 32KB window at 0x8000–0xFFFF.
  The active bank is selected via FMAP (0xF1) or MEMCTR (0xC7) SFR writes.
  Cross-bank calls require runtime bank-select awareness.
* Variable instruction length: 1, 2, or 3 bytes.  The high 3 bits of AJMP/ACALL
  encode an 11-bit page-relative offset.
* Computed-call idiom: LCALL <stub>; <addr_hi>; <addr_lo>; <param> is used in
  TI BLE stacks as a function-pointer call.  The 3 bytes after the LCALL are
  NOT instructions; they are inline data consumed by the stub.

Gap origin: surfaced during TI BLE-Stack 1.5.2.0 RE (2026-10-11).
Module reference: ablation/docs/module-reference/isa-8051.md
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Iterator, List, Optional, Tuple

from ablation.parsers.intel_hex import IntelHexImage

_MAX_HEX_FILE_BYTES  = 4 * 1024 * 1024    # 4 MB source text limit
_MAX_ADDRESS_RANGE   = 512 * 1024           # 512 KB dense buffer limit (CC254x max)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class MemSpace(str, Enum):
    CODE  = "CODE"    # read via MOVC A,@A+DPTR / MOVC A,@A+PC
    IRAM  = "IRAM"    # read/write via direct addressing or @Ri indirect
    XDATA = "XDATA"   # read/write via MOVX A,@DPTR / MOVX A,@Ri
    SFR   = "SFR"     # direct addresses 0x80–0xFF (strict SFR access mode)
    BIT   = "BIT"     # bit-addressable space (overlaps IRAM 0x20–0x2F + SFRs)


class InsnType(str, Enum):
    NORMAL    = "NORMAL"     # no control-flow change
    CALL      = "CALL"       # LCALL or ACALL (pushes return addr, jumps)
    JUMP      = "JUMP"       # LJMP, AJMP, SJMP, JMP@A+DPTR
    BRANCH    = "BRANCH"     # conditional: JC, JNC, JZ, JNZ, DJNZ, CJNE, JB, JNB, JBC
    RET       = "RET"        # RET or RETI
    COMPUTED  = "COMPUTED"   # JMP @A+DPTR (fully indirect)
    COMP_CALL = "COMP_CALL"  # LCALL <stub>; <addr_hi>; <addr_lo>; <param> idiom


# ---------------------------------------------------------------------------
# CC254x SFR map (Enhanced 8051; security-relevant subset)
# ---------------------------------------------------------------------------

CC254X_SFR: Dict[int, str] = {
    0x81: "SP",       # Stack Pointer
    0x82: "DPL",      # Data Pointer low
    0x83: "DPH",      # Data Pointer high
    0x87: "PCON",     # Power Control
    0x88: "TCON",     # Timer Control
    0x89: "TMOD",     # Timer Mode
    0x8A: "TL0",      # Timer 0 low
    0x8B: "TL1",      # Timer 1 low
    0x8C: "TH0",      # Timer 0 high
    0x8D: "TH1",      # Timer 1 high
    0x90: "P1",       # Port 1
    0x92: "ADCCFG",   # ADC config
    0x98: "S0CON",    # UART0 control
    0x99: "U0DBUF",   # UART0 data buffer
    0xA0: "P2",       # Port 2
    0xA8: "IEN0",     # Interrupt Enable 0
    0xB0: "P3",       # Port 3
    0xB1: "ENCDI",    # AES data in/out  ← SECURITY
    0xB3: "ENCCS",    # AES control/status  ← SECURITY
    0xB8: "IP0",      # Interrupt Priority 0
    0xC0: "S1CON",    # UART1 control
    0xC1: "U1DBUF",   # UART1 data buffer
    0xC7: "MEMCTR",   # Memory Control (bank select)  ← SECURITY
    0xC8: "T2CTL",    # Timer 2 control
    0xD0: "PSW",      # Program Status Word
    0xD1: "DPSEL",    # DPTR select
    0xE0: "ACC",      # Accumulator
    0xF0: "B",        # B register
    0xF1: "FMAP",     # Flash map register (bank select)  ← SECURITY
}

# AES co-processor SFRs — writes to these trigger hardware crypto
AES_SFRS = frozenset({0xB1, 0xB3})

# Bank-select SFRs — writes here change the banked code window
BANK_SELECT_SFRS = frozenset({0xC7, 0xF1})


def sfr_name(addr: int) -> str:
    return CC254X_SFR.get(addr, f"0x{addr:02X}")


# ---------------------------------------------------------------------------
# Instruction dataclass
# ---------------------------------------------------------------------------

@dataclass
class Mcs51Insn:
    offset: int            # flat binary offset (NOT code address)
    raw: bytes             # raw bytes (1–3)
    mnemonic: str
    operands: str          # human-readable operand string
    insn_type: InsnType = InsnType.NORMAL
    target: Optional[int] = None    # absolute target for calls/jumps/branches
    size: int = field(init=False)

    def __post_init__(self) -> None:
        self.size = len(self.raw)

    @property
    def is_call(self) -> bool:
        return self.insn_type in (InsnType.CALL, InsnType.COMP_CALL)

    @property
    def is_jump(self) -> bool:
        return self.insn_type in (InsnType.JUMP, InsnType.COMPUTED)

    @property
    def is_branch(self) -> bool:
        return self.insn_type == InsnType.BRANCH

    @property
    def is_ret(self) -> bool:
        return self.insn_type == InsnType.RET

    @property
    def reads_aes_sfr(self) -> bool:
        """True if this instruction reads from the AES co-processor SFR."""
        # MOV A,direct (0xE5 <direct>) — direct in AES_SFRS
        return (len(self.raw) >= 2 and self.raw[0] == 0xE5
                and self.raw[1] in AES_SFRS)

    @property
    def writes_aes_sfr(self) -> bool:
        """True if this instruction writes to the AES co-processor SFR."""
        # MOV direct,A (0xF5 <direct>)
        return (len(self.raw) >= 2 and self.raw[0] == 0xF5
                and self.raw[1] in AES_SFRS)

    @property
    def changes_bank(self) -> bool:
        """True if this instruction may change the active flash bank."""
        # MOV direct,A (0xF5 <direct>) where direct is MEMCTR or FMAP
        # MOV direct,#imm (0x75 <direct> <imm>)
        if len(self.raw) >= 2 and self.raw[0] in (0xF5, 0x75):
            return self.raw[1] in BANK_SELECT_SFRS
        return False

    def __str__(self) -> str:
        return (f"0x{self.offset:05X}: "
                + " ".join(f"{b:02X}" for b in self.raw).ljust(9)
                + f"  {self.mnemonic} {self.operands}".rstrip())


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class Mcs51Decoder:
    """Decode MCS-51 / Enhanced 8051 instructions from a flat binary buffer.

    Call decode_one(data, offset) for a single instruction, or
    decode_range(data, start, end) to decode a linear range.

    Banking note: flat binary offsets are used throughout.  Use
    Cc254xBankResolver to convert flat offsets to logical code addresses.

    Computed-call detection: if computed_call_stub is set, any LCALL to
    that address is decoded as InsnType.COMP_CALL with size=6 (the LCALL
    plus 3 bytes of inline data), and the inline target address is decoded
    from the 3 bytes that follow.
    """

    def __init__(self, computed_call_stub: Optional[int] = None) -> None:
        self.computed_call_stub = computed_call_stub

    def decode_one(self, data: bytes | bytearray, offset: int) -> Mcs51Insn:
        if offset < 0 or offset >= len(data):
            raise IndexError(f"offset 0x{offset:x} out of range")

        b0 = data[offset]
        n = len(data)

        def b1() -> int:
            return data[offset + 1] if offset + 1 < n else 0

        def b2() -> int:
            return data[offset + 2] if offset + 2 < n else 0

        def rel8(off: int) -> int:
            r = data[off] if off < n else 0
            return offset + 2 + (r if r < 128 else r - 256)

        def rel8_at(base_off: int) -> int:
            r = data[base_off] if base_off < n else 0
            return base_off + 1 + (r if r < 128 else r - 256)

        def addr16() -> int:
            return (b1() << 8) | b2()

        def ajmp_acall_target() -> int:
            # 11-bit page: high 3 bits from opcode[7:5], low 8 bits from b1
            page_bits = (b0 & 0xE0) >> 5
            return (offset & 0xF800) | (page_bits << 8) | b1()

        def _raw(sz: int) -> bytes:
            return bytes(data[offset:offset + sz])

        s = sfr_name

        # ── 1-byte instructions ──
        if b0 == 0x00: return Mcs51Insn(offset, _raw(1), "NOP", "")
        if b0 == 0x22: return Mcs51Insn(offset, _raw(1), "RET", "", InsnType.RET)
        if b0 == 0x32: return Mcs51Insn(offset, _raw(1), "RETI", "", InsnType.RET)
        if b0 == 0xA3: return Mcs51Insn(offset, _raw(1), "INC", "DPTR")
        if b0 == 0x73:
            return Mcs51Insn(offset, _raw(1), "JMP", "@A+DPTR",
                             InsnType.COMPUTED, None)
        if b0 == 0x83: return Mcs51Insn(offset, _raw(1), "MOVC", "A,@A+PC")
        if b0 == 0x93: return Mcs51Insn(offset, _raw(1), "MOVC", "A,@A+DPTR")
        if b0 == 0xE0: return Mcs51Insn(offset, _raw(1), "MOVX", "A,@DPTR")
        if b0 == 0xF0: return Mcs51Insn(offset, _raw(1), "MOVX", "@DPTR,A")
        if b0 == 0xE2: return Mcs51Insn(offset, _raw(1), "MOVX", "A,@R0")
        if b0 == 0xE3: return Mcs51Insn(offset, _raw(1), "MOVX", "A,@R1")
        if b0 == 0xF2: return Mcs51Insn(offset, _raw(1), "MOVX", "@R0,A")
        if b0 == 0xF3: return Mcs51Insn(offset, _raw(1), "MOVX", "@R1,A")
        if b0 == 0xC3: return Mcs51Insn(offset, _raw(1), "CLR", "C")
        if b0 == 0xD3: return Mcs51Insn(offset, _raw(1), "SETB", "C")
        if b0 == 0xE4: return Mcs51Insn(offset, _raw(1), "CLR", "A")
        if b0 == 0xF4: return Mcs51Insn(offset, _raw(1), "CPL", "A")
        if b0 == 0x04: return Mcs51Insn(offset, _raw(1), "INC", "A")
        if b0 == 0x14: return Mcs51Insn(offset, _raw(1), "DEC", "A")
        if b0 == 0x84: return Mcs51Insn(offset, _raw(1), "DIV", "AB")
        if b0 == 0xA4: return Mcs51Insn(offset, _raw(1), "MUL", "AB")
        if b0 == 0xC4: return Mcs51Insn(offset, _raw(1), "SWAP", "A")
        if b0 == 0x03: return Mcs51Insn(offset, _raw(1), "RR", "A")
        if b0 == 0x13: return Mcs51Insn(offset, _raw(1), "RRC", "A")
        if b0 == 0x23: return Mcs51Insn(offset, _raw(1), "RL", "A")
        if b0 == 0x33: return Mcs51Insn(offset, _raw(1), "RLC", "A")
        if b0 == 0xA5: return Mcs51Insn(offset, _raw(1), "???", "reserved-0xA5")

        # Rn operations (1-byte)
        if 0xE8 <= b0 <= 0xEF:
            return Mcs51Insn(offset, _raw(1), "MOV", f"A,R{b0-0xE8}")
        if 0xF8 <= b0 <= 0xFF:
            return Mcs51Insn(offset, _raw(1), "MOV", f"R{b0-0xF8},A")
        if 0x08 <= b0 <= 0x0F:
            return Mcs51Insn(offset, _raw(1), "INC", f"R{b0-0x08}")
        if 0x18 <= b0 <= 0x1F:
            return Mcs51Insn(offset, _raw(1), "DEC", f"R{b0-0x18}")
        if 0x28 <= b0 <= 0x2F:
            return Mcs51Insn(offset, _raw(1), "ADD", f"A,R{b0-0x28}")
        if 0x38 <= b0 <= 0x3F:
            return Mcs51Insn(offset, _raw(1), "ADDC", f"A,R{b0-0x38}")
        if 0x98 <= b0 <= 0x9F:
            return Mcs51Insn(offset, _raw(1), "SUBB", f"A,R{b0-0x98}")
        if 0x48 <= b0 <= 0x4F:
            return Mcs51Insn(offset, _raw(1), "ORL", f"A,R{b0-0x48}")
        if 0x58 <= b0 <= 0x5F:
            return Mcs51Insn(offset, _raw(1), "ANL", f"A,R{b0-0x58}")
        if 0x68 <= b0 <= 0x6F:
            return Mcs51Insn(offset, _raw(1), "XRL", f"A,R{b0-0x68}")
        if 0xC8 <= b0 <= 0xCF:
            return Mcs51Insn(offset, _raw(1), "XCH", f"A,R{b0-0xC8}")
        if 0xD8 <= b0 <= 0xDF:
            r = b1(); t = offset + 2 + (r if r < 128 else r - 256)
            return Mcs51Insn(offset, _raw(2), "DJNZ",
                             f"R{b0-0xD8},0x{t:04X}", InsnType.BRANCH, t)
        if 0x88 <= b0 <= 0x8F:
            return Mcs51Insn(offset, _raw(2), "MOV", f"R{b0-0x88},{s(b1())}")
        if 0xA8 <= b0 <= 0xAF:
            return Mcs51Insn(offset, _raw(2), "MOV", f"R{b0-0xA8},{s(b1())}")
        if 0x78 <= b0 <= 0x7F:
            return Mcs51Insn(offset, _raw(2), "MOV", f"R{b0-0x78},#0x{b1():02X}")
        if 0xB8 <= b0 <= 0xBF:
            r = b2(); t = offset + 3 + (r if r < 128 else r - 256)
            return Mcs51Insn(offset, _raw(3), "CJNE",
                             f"R{b0-0xB8},#0x{b1():02X},0x{t:04X}",
                             InsnType.BRANCH, t)

        # @Ri operations (1-byte)
        if b0 in (0x06, 0x07): return Mcs51Insn(offset, _raw(1), "INC", f"@R{b0-6}")
        if b0 in (0x16, 0x17): return Mcs51Insn(offset, _raw(1), "DEC", f"@R{b0-0x16}")
        if b0 in (0x26, 0x27): return Mcs51Insn(offset, _raw(1), "ADD", f"A,@R{b0-0x26}")
        if b0 in (0x36, 0x37): return Mcs51Insn(offset, _raw(1), "ADDC", f"A,@R{b0-0x36}")
        if b0 in (0x96, 0x97): return Mcs51Insn(offset, _raw(1), "SUBB", f"A,@R{b0-0x96}")
        if b0 in (0x46, 0x47): return Mcs51Insn(offset, _raw(1), "ORL", f"A,@R{b0-0x46}")
        if b0 in (0x56, 0x57): return Mcs51Insn(offset, _raw(1), "ANL", f"A,@R{b0-0x56}")
        if b0 in (0x66, 0x67): return Mcs51Insn(offset, _raw(1), "XRL", f"A,@R{b0-0x66}")
        if b0 in (0xC6, 0xC7): return Mcs51Insn(offset, _raw(1), "XCH", f"A,@R{b0-0xC6}")
        if b0 in (0xD6, 0xD7): return Mcs51Insn(offset, _raw(1), "XCHD", f"A,@R{b0-0xD6}")
        if b0 in (0xE6, 0xE7): return Mcs51Insn(offset, _raw(1), "MOV", f"A,@R{b0-0xE6}")
        if b0 in (0xF6, 0xF7): return Mcs51Insn(offset, _raw(1), "MOV", f"@R{b0-0xF6},A")
        if b0 in (0x86, 0x87): return Mcs51Insn(offset, _raw(2), "MOV", f"{s(b1())},@R{b0-0x86}")
        if b0 in (0xA6, 0xA7): return Mcs51Insn(offset, _raw(2), "MOV", f"@R{b0-0xA6},{s(b1())}")
        if b0 in (0x76, 0x77): return Mcs51Insn(offset, _raw(2), "MOV", f"@R{b0-0x76},#0x{b1():02X}")
        if b0 in (0xB6, 0xB7):
            r = b2(); t = offset + 3 + (r if r < 128 else r - 256)
            return Mcs51Insn(offset, _raw(3), "CJNE",
                             f"@R{b0-0xB6},#0x{b1():02X},0x{t:04X}",
                             InsnType.BRANCH, t)

        # ── 2-byte instructions ──
        if b0 == 0x74: return Mcs51Insn(offset, _raw(2), "MOV", f"A,#0x{b1():02X}")
        if b0 == 0xE5: return Mcs51Insn(offset, _raw(2), "MOV", f"A,{s(b1())}")
        if b0 == 0xF5: return Mcs51Insn(offset, _raw(2), "MOV", f"{s(b1())},A")
        if b0 == 0x24: return Mcs51Insn(offset, _raw(2), "ADD", f"A,#0x{b1():02X}")
        if b0 == 0x25: return Mcs51Insn(offset, _raw(2), "ADD", f"A,{s(b1())}")
        if b0 == 0x34: return Mcs51Insn(offset, _raw(2), "ADDC", f"A,#0x{b1():02X}")
        if b0 == 0x35: return Mcs51Insn(offset, _raw(2), "ADDC", f"A,{s(b1())}")
        if b0 == 0x94: return Mcs51Insn(offset, _raw(2), "SUBB", f"A,#0x{b1():02X}")
        if b0 == 0x95: return Mcs51Insn(offset, _raw(2), "SUBB", f"A,{s(b1())}")
        if b0 == 0x44: return Mcs51Insn(offset, _raw(2), "ORL", f"A,#0x{b1():02X}")
        if b0 == 0x45: return Mcs51Insn(offset, _raw(2), "ORL", f"A,{s(b1())}")
        if b0 == 0x54: return Mcs51Insn(offset, _raw(2), "ANL", f"A,#0x{b1():02X}")
        if b0 == 0x55: return Mcs51Insn(offset, _raw(2), "ANL", f"A,{s(b1())}")
        if b0 == 0x64: return Mcs51Insn(offset, _raw(2), "XRL", f"A,#0x{b1():02X}")
        if b0 == 0x65: return Mcs51Insn(offset, _raw(2), "XRL", f"A,{s(b1())}")
        if b0 == 0xC5: return Mcs51Insn(offset, _raw(2), "XCH", f"A,{s(b1())}")
        if b0 == 0xC2: return Mcs51Insn(offset, _raw(2), "CLR", f"bit 0x{b1():02X}")
        if b0 == 0xD2: return Mcs51Insn(offset, _raw(2), "SETB", f"bit 0x{b1():02X}")
        if b0 == 0xB2: return Mcs51Insn(offset, _raw(2), "CPL", f"bit 0x{b1():02X}")
        if b0 == 0xA2: return Mcs51Insn(offset, _raw(2), "MOV", f"C,bit 0x{b1():02X}")
        if b0 == 0x92: return Mcs51Insn(offset, _raw(2), "MOV", f"bit 0x{b1():02X},C")
        if b0 == 0xC0: return Mcs51Insn(offset, _raw(2), "PUSH", f"{s(b1())}")
        if b0 == 0xD0: return Mcs51Insn(offset, _raw(2), "POP", f"{s(b1())}")
        if b0 == 0x05: return Mcs51Insn(offset, _raw(2), "INC", f"{s(b1())}")
        if b0 == 0x15: return Mcs51Insn(offset, _raw(2), "DEC", f"{s(b1())}")
        if b0 == 0xB4:
            r = b2(); t = offset + 3 + (r if r < 128 else r - 256)
            return Mcs51Insn(offset, _raw(3), "CJNE",
                             f"A,#0x{b1():02X},0x{t:04X}", InsnType.BRANCH, t)
        if b0 == 0xB5:
            r = b2(); t = offset + 3 + (r if r < 128 else r - 256)
            return Mcs51Insn(offset, _raw(3), "CJNE",
                             f"A,{s(b1())},0x{t:04X}", InsnType.BRANCH, t)

        if b0 == 0x80:
            t = rel8(offset + 1)
            return Mcs51Insn(offset, _raw(2), "SJMP", f"0x{t:04X}",
                             InsnType.JUMP, t)
        if b0 == 0x40:
            t = rel8(offset + 1)
            return Mcs51Insn(offset, _raw(2), "JC", f"0x{t:04X}",
                             InsnType.BRANCH, t)
        if b0 == 0x50:
            t = rel8(offset + 1)
            return Mcs51Insn(offset, _raw(2), "JNC", f"0x{t:04X}",
                             InsnType.BRANCH, t)
        if b0 == 0x60:
            t = rel8(offset + 1)
            return Mcs51Insn(offset, _raw(2), "JZ", f"0x{t:04X}",
                             InsnType.BRANCH, t)
        if b0 == 0x70:
            t = rel8(offset + 1)
            return Mcs51Insn(offset, _raw(2), "JNZ", f"0x{t:04X}",
                             InsnType.BRANCH, t)

        # Bit branches (3-byte: opcode, bit-addr, rel)
        if b0 == 0x20:
            r = b2(); t = offset + 3 + (r if r < 128 else r - 256)
            return Mcs51Insn(offset, _raw(3), "JB",
                             f"bit 0x{b1():02X},0x{t:04X}", InsnType.BRANCH, t)
        if b0 == 0x30:
            r = b2(); t = offset + 3 + (r if r < 128 else r - 256)
            return Mcs51Insn(offset, _raw(3), "JNB",
                             f"bit 0x{b1():02X},0x{t:04X}", InsnType.BRANCH, t)
        if b0 == 0x10:
            r = b2(); t = offset + 3 + (r if r < 128 else r - 256)
            return Mcs51Insn(offset, _raw(3), "JBC",
                             f"bit 0x{b1():02X},0x{t:04X}", InsnType.BRANCH, t)

        # DJNZ direct (3-byte)
        if b0 == 0xD5:
            r = b2(); t = offset + 3 + (r if r < 128 else r - 256)
            return Mcs51Insn(offset, _raw(3), "DJNZ",
                             f"{s(b1())},0x{t:04X}", InsnType.BRANCH, t)

        # ── 3-byte instructions ──
        if b0 == 0x02:
            t = addr16()
            return Mcs51Insn(offset, _raw(3), "LJMP", f"0x{t:04X}",
                             InsnType.JUMP, t)
        if b0 == 0x12:
            t = addr16()
            # Computed-call idiom detection
            if (self.computed_call_stub is not None and t == self.computed_call_stub
                    and offset + 6 <= len(data)):
                inline_hi = data[offset + 3]
                inline_lo = data[offset + 4]
                inline_param = data[offset + 5]
                real_target = (inline_hi << 8) | inline_lo
                return Mcs51Insn(
                    offset,
                    bytes(data[offset:offset + 6]),
                    "CALL*",
                    f"0x{real_target:04X} param=0x{inline_param:02X}",
                    InsnType.COMP_CALL,
                    real_target,
                )
            return Mcs51Insn(offset, _raw(3), "LCALL", f"0x{t:04X}",
                             InsnType.CALL, t)

        if b0 == 0x75:
            return Mcs51Insn(offset, _raw(3), "MOV",
                             f"{s(b1())},#0x{b2():02X}")
        if b0 == 0x85:
            return Mcs51Insn(offset, _raw(3), "MOV",
                             f"{s(b2())},{s(b1())}")
        if b0 == 0x43:
            return Mcs51Insn(offset, _raw(3), "ORL",
                             f"{s(b1())},#0x{b2():02X}")
        if b0 == 0x53:
            return Mcs51Insn(offset, _raw(3), "ANL",
                             f"{s(b1())},#0x{b2():02X}")
        if b0 == 0x63:
            return Mcs51Insn(offset, _raw(3), "XRL",
                             f"{s(b1())},#0x{b2():02X}")

        if b0 == 0x90:
            t = addr16()
            return Mcs51Insn(offset, _raw(3), "MOV", f"DPTR,#0x{t:04X}")

        # ACALL (11-bit, 2-byte): opcode bits [7:5] encode page[2:0]
        if (b0 & 0x1F) == 0x11:
            t = ajmp_acall_target()
            return Mcs51Insn(offset, _raw(2), "ACALL", f"0x{t:04X}",
                             InsnType.CALL, t)

        # AJMP (11-bit, 2-byte): opcode bits [7:5] encode page[2:0]
        if (b0 & 0x1F) == 0x01:
            t = ajmp_acall_target()
            return Mcs51Insn(offset, _raw(2), "AJMP", f"0x{t:04X}",
                             InsnType.JUMP, t)

        # LCALL-like extended (some Enhanced 8051 variants add opcodes — treat as ???)
        return Mcs51Insn(offset, _raw(1), "???", f"0x{b0:02X}")

    def decode_range(
        self, data: bytes | bytearray, start: int, end: int
    ) -> List[Mcs51Insn]:
        """Decode all instructions in [start, end)."""
        insns: List[Mcs51Insn] = []
        i = start
        while i < end and i < len(data):
            insn = self.decode_one(data, i)
            insns.append(insn)
            if insn.insn_type == InsnType.COMP_CALL:
                i += 6  # LCALL(3) + inline data(3)
            else:
                i += insn.size
        return insns


# ---------------------------------------------------------------------------
# Intel HEX loader
# ---------------------------------------------------------------------------

class IntelHexLoader:
    """Compatibility wrapper around the strict shared Intel HEX parser."""

    def __init__(self, image: IntelHexImage | None = None) -> None:
        self._image = image
        self._data: Dict[int, int] = {} if image is None else image.to_sparse()

    @classmethod
    def from_file(cls, path: str) -> "IntelHexLoader":
        file_size = os.path.getsize(path)
        if file_size > _MAX_HEX_FILE_BYTES:
            raise ValueError(
                f'{path}: HEX file size {file_size} exceeds {_MAX_HEX_FILE_BYTES} byte limit')
        return cls(IntelHexImage.from_path(path, max_input_bytes=_MAX_HEX_FILE_BYTES))

    @classmethod
    def from_bytes(cls, hexdata: str) -> "IntelHexLoader":
        """Parse from an in-memory HEX string."""
        return cls(IntelHexImage.from_bytes(hexdata, max_input_bytes=_MAX_HEX_FILE_BYTES))

    def address_range(self) -> Tuple[int, int]:
        if not self._data:
            return (0, 0)
        lo = min(self._data)
        hi = max(self._data)
        return (lo, hi + 1)

    def to_bytes(self, fill: int = 0xFF) -> bytes:
        """Return a dense flat byte array; gaps filled with `fill`."""
        if self._image is None:
            return b""
        return self._image.to_bytes(fill=fill, max_dense_bytes=_MAX_ADDRESS_RANGE)

    def to_sparse(self) -> Dict[int, int]:
        return dict(self._data)


# ---------------------------------------------------------------------------
# CC254x bank-aware address resolver
# ---------------------------------------------------------------------------

class Cc254xBankResolver:
    """Resolve flat binary offsets (from IntelHexLoader.to_bytes()) to
    CC254x logical code addresses, accounting for the banked flash window.

    CC254x flash layout:
        0x0000–0x7FFF  common area (bank 0, always visible)
        0x8000–0xFFFF  banked window (one bank at a time, selected by FMAP/MEMCTR)

    For a flat binary produced by to_bytes() with base address 0x00000:
        flat offset 0x00000–0x07FFF  →  code address 0x0000–0x7FFF  (common)
        flat offset 0x08000–0x0FFFF  →  bank 0: code address 0x8000–0xFFFF
        flat offset 0x10000–0x17FFF  →  bank 1: code address 0x8000–0xFFFF
        flat offset 0x18000–0x1FFFF  →  bank 2: code address 0x8000–0xFFFF
        flat offset 0x20000–0x27FFF  →  bank 3: code address 0x8000–0xFFFF
        (CC2541 adds banks 4–7 for 256KB total)

    flat_to_logical(flat_offset) → (bank, code_address)
    logical_to_flat(bank, code_address) → flat_offset
    """

    COMMON_SIZE  = 0x8000    # 32KB common area
    BANK_SIZE    = 0x8000    # 32KB per bank
    BANK_BASE    = 0x8000    # bank window base address in code space

    def __init__(self, num_banks: int = 4) -> None:
        self.num_banks = num_banks  # CC2540=4, CC2541=8

    def flat_to_logical(self, flat: int) -> Tuple[int, int]:
        """(bank, code_address).  Bank 0xFF means common area (no bank switch)."""
        if flat < self.COMMON_SIZE:
            return (0xFF, flat)                   # common area
        rel = flat - self.COMMON_SIZE
        bank = rel // self.BANK_SIZE
        code_addr = self.BANK_BASE + (rel % self.BANK_SIZE)
        return (bank, code_addr)

    def logical_to_flat(self, bank: int, code_addr: int) -> int:
        if code_addr < self.BANK_BASE:
            return code_addr                      # common area
        return self.COMMON_SIZE + bank * self.BANK_SIZE + (code_addr - self.BANK_BASE)

    def is_cross_bank_call(self, caller_flat: int, callee_code_addr: int) -> bool:
        """True when a LCALL target address is in the banked window and the
        caller is in the common area (cross-bank — requires runtime bank selection)."""
        caller_bank, _ = self.flat_to_logical(caller_flat)
        return caller_bank == 0xFF and callee_code_addr >= self.BANK_BASE

    def cross_bank_candidates(
        self, insns: List[Mcs51Insn]
    ) -> List[Tuple[Mcs51Insn, int, int]]:
        """Return (insn, caller_flat, callee_code_addr) for all cross-bank calls."""
        results = []
        for insn in insns:
            if insn.is_call and insn.target is not None:
                if self.is_cross_bank_call(insn.offset, insn.target):
                    results.append((insn, insn.offset, insn.target))
        return results


# ---------------------------------------------------------------------------
# AES access scanner (convenience wrapper)
# ---------------------------------------------------------------------------

def scan_aes_accesses(
    data: bytes | bytearray,
    decoder: Optional[Mcs51Decoder] = None,
) -> Dict[str, List[Mcs51Insn]]:
    """Return {reads: [...], writes: [...]} for all AES co-processor SFR accesses."""
    if decoder is None:
        decoder = Mcs51Decoder()
    reads: List[Mcs51Insn] = []
    writes: List[Mcs51Insn] = []
    # Fast byte scan for F5 B1, F5 B3, E5 B1, E5 B3 patterns
    for i in range(len(data) - 1):
        b0, b1 = data[i], data[i + 1]
        if b0 == 0xF5 and b1 in AES_SFRS:
            writes.append(decoder.decode_one(data, i))
        elif b0 == 0xE5 and b1 in AES_SFRS:
            reads.append(decoder.decode_one(data, i))
    return {"reads": reads, "writes": writes}


def scan_bank_switches(
    data: bytes | bytearray,
    decoder: Optional[Mcs51Decoder] = None,
) -> List[Mcs51Insn]:
    """Return all instructions that write to a bank-select SFR."""
    if decoder is None:
        decoder = Mcs51Decoder()
    results: List[Mcs51Insn] = []
    for i in range(len(data) - 1):
        b0, b1 = data[i], data[i + 1]
        if b0 in (0xF5, 0x75) and b1 in BANK_SELECT_SFRS:
            results.append(decoder.decode_one(data, i))
    return results
