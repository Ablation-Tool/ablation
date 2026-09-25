"""
v850_decoder.py: Renesas V850 variable-length instruction frame decoder.

V850 (NEC/Renesas V850E, V850E2, V850E2M, V850E3V5) is a RISC architecture
used in automotive ECUs, industrial controllers, and embedded systems.

Instruction width discriminant (bits[10:5] of first halfword = 6-bit opcode):
  op6 >= 32 (bit[10] of word set): 32-bit instruction
  op6 in (28, 29) -- PREPARE/DISPOSE: 32-bit (may extend to 48-bit)
  all other op6: 16-bit instruction

Key control-flow instructions:
  JARL disp22, reg2  [32-bit, op6=0x3E=62]
    reg2=r31 (lp): direct function call
    reg2=r0:       JR = unconditional relative branch
  JMP  [reg1]        [16-bit, op6=0x06=6]
    reg1=r31 (lp): return from function
    reg1=other:    indirect branch
  Bcond disp9        [16-bit, Format III: (hw0>>1)&7==3]
    conditional branch (bc, bnc, bz, bnz, bgt, blt, bge, ble, br, ...)

capstone 5.x and next branch have NO CS_ARCH_V850 support.
This module provides a pure-Python control-flow decoder.

ABI: V850 EABI (GCC default):
  r6-r9:  argument registers (a0-a3), caller-saved
  r10:    return value (also used as temp), caller-saved
  r11-r19: caller-saved temporaries
  r20-r29: callee-saved
  r30:    ep (element pointer), callee-saved
  r31:    lp (link pointer = return address)

Targets: Renesas RH850/G3M, RH850/G3MH (automotive ECU), V850E2R (industrial),
         V850E3V5 (dual-core ASIL-D), NEC V850E2 (embedded control).

Usage:
    from ablation.analyzers.v850_decoder import V850Decoder, V850Disasm

    dec = V850Decoder()
    frames = dec.decode_frames(data, base_addr=0)
    for f in frames:
        if f.is_call:
            print(f'call @ 0x{f.va:x} -> 0x{f.target:x}')
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# V850 opcode constants (bits[10:5] of first halfword)
# ---------------------------------------------------------------------------

_OP_JMP    = 0x06   # JMP [reg1] -- 16-bit indirect jump
_OP_JARL   = 0x3E   # JARL disp22, reg2 -- 32-bit call/branch
_OP_CALLT  = 0x11   # CALLT imm6 -- 16-bit table call (ignore for taint)
_OP_PREPARE = 0x1C  # PREPARE {list}, imm5 -- function prologue, treat as 32-bit
_OP_DISPOSE = 0x1D  # DISPOSE imm5, {list} -- function epilogue, treat as 32-bit

# r31 = lp (link pointer = return address register)
_LP = 31


# ---------------------------------------------------------------------------
# Frame record
# ---------------------------------------------------------------------------

@dataclass
class V850Frame:
    """Single V850 instruction frame."""
    va:        int
    width:     int    # bytes: 2 or 4
    hw0:       int    # first halfword
    hw1:       int    # second halfword (0 for 16-bit insns)
    mnemonic:  str
    op_str:    str
    is_branch: bool = False
    is_call:   bool = False
    is_ret:    bool = False
    target:    int  = 0   # resolved call/branch target VA (0 = not computed)

    def __str__(self) -> str:
        raw = f'{self.hw0:04x}{self.hw1:04x}' if self.width == 4 else f'{self.hw0:04x}'
        tgt = f' -> 0x{self.target:x}' if self.target else ''
        tag = ' CALL' if self.is_call else (' RET' if self.is_ret else '')
        return (f'0x{self.va:08x}  [{self.width * 8:2d}-bit]  {raw:<8}  '
                f'{self.mnemonic} {self.op_str}{tgt}{tag}')


# ---------------------------------------------------------------------------
# Width discriminant
# ---------------------------------------------------------------------------

def _v850_width(hw0: int) -> int:
    """Return instruction width in bytes (2 or 4) from first halfword."""
    op6 = (hw0 >> 5) & 0x3F
    # 32-bit: op6 >= 32 (bit[10] of instruction set)
    # Also PREPARE (28) and DISPOSE (29) are at least 32-bit
    if op6 >= 0x20 or op6 in (_OP_PREPARE, _OP_DISPOSE):
        return 4
    return 2


# ---------------------------------------------------------------------------
# JARL target offset extraction (22-bit signed, halfword-aligned)
# ---------------------------------------------------------------------------

def _jarl_target(hw0: int, hw1: int, pc: int) -> int:
    """
    Compute JARL/JR target VA.

    Format V (32-bit) displacement layout:
      hw0[15:11] = disp[5:1]   (5 lower displacement bits, excluding bit0)
      hw1[15:0]  = disp[21:6]  (16 upper displacement bits)
    Target = PC + sign_extend_22({disp[21:6], disp[5:1], 1'b0})
    """
    disp_low5  = (hw0 >> 11) & 0x1F        # disp[5:1]
    raw = (hw1 << 6) | (disp_low5 << 1)    # 22-bit, bit[0]=0
    if raw & (1 << 21):                     # sign bit at position 21
        raw -= (1 << 22)
    return pc + raw


# ---------------------------------------------------------------------------
# Classify instruction
# ---------------------------------------------------------------------------

def _classify(hw0: int, hw1: int, va: int) -> Tuple[str, str, bool, bool, bool, int]:
    """Return (mnemonic, op_str, is_branch, is_call, is_ret, target)."""
    op6  = (hw0 >> 5) & 0x3F
    reg2 = hw0 & 0x1F
    reg1 = (hw0 >> 11) & 0x1F

    # JARL/JR (32-bit, op6 == 0x3E)
    if op6 == _OP_JARL:
        target = _jarl_target(hw0, hw1, va)
        if reg2 == _LP:
            return 'jarl', f'0x{target:x}, lp', False, True, False, target
        if reg2 == 0:
            return 'jr', f'0x{target:x}', True, False, False, target
        return 'jarl', f'0x{target:x}, r{reg2}', False, True, False, target

    # JMP [reg1] (16-bit, op6 == 0x06)
    if op6 == _OP_JMP:
        if reg1 == _LP:
            return 'jmp', '[lp]', False, False, True, 0
        return 'jmp', f'[r{reg1}]', True, False, False, 0

    # PREPARE / DISPOSE (function frame management)
    if op6 == _OP_PREPARE:
        return 'prepare', '', False, False, False, 0
    if op6 == _OP_DISPOSE:
        return 'dispose', '', False, False, False, 0

    # Format III conditional branch: (hw0>>1)&7 == 3 (bits[3:1] = 011)
    if ((hw0 >> 1) & 7) == 3:
        # Reconstruct 9-bit signed displacement from Format III
        disp_hi = (hw0 >> 11) & 0x1F  # disp[8:4]
        disp_lo = (hw0 >> 4) & 0x7    # disp[3:1]
        raw9 = (disp_hi << 4) | (disp_lo << 1)  # 9-bit, bit0=0
        if raw9 & (1 << 8):
            raw9 -= (1 << 9)
        cond = (hw0 >> 7) & 0xF
        _COND = {0:'bv', 1:'bl', 2:'be', 3:'bnh', 4:'bn', 5:'br',
                 6:'blt', 7:'ble', 8:'bnv', 9:'bnl', 10:'bne', 11:'bh',
                 12:'bp', 13:'bsa', 14:'bge', 15:'bgt'}
        mnem = _COND.get(cond, 'bc')
        tgt = va + raw9
        return mnem, f'0x{tgt:x}', True, False, False, tgt

    return '???', '', False, False, False, 0


# ---------------------------------------------------------------------------
# Core decoder
# ---------------------------------------------------------------------------

class V850Decoder:
    """
    V850 variable-length instruction frame decoder (no capstone required).

    Handles 16-bit and 32-bit V850 instruction formats.
    PREPARE/DISPOSE treated as 32-bit (may be 48-bit in V850E2; conservative).

    Args:
        endian: 'little' (default, all known V850 Linux/GCC targets) or 'big'.
    """

    def __init__(self, endian: str = 'little'):
        self.endian = endian
        self._bo = 'little' if endian == 'little' else 'big'

    def _hw(self, data: bytes, off: int) -> int:
        if off + 2 > len(data):
            return 0
        return int.from_bytes(data[off:off+2], self._bo)

    def decode_frames(self, data: bytes, base_addr: int = 0) -> List[V850Frame]:
        return list(self._iter_frames(data, base_addr))

    def _iter_frames(self, data: bytes, base_addr: int) -> Iterator[V850Frame]:
        off = 0
        while off < len(data) - 1:
            hw0 = self._hw(data, off)
            width = _v850_width(hw0)
            va = base_addr + off

            if off + width > len(data):
                break

            hw1 = self._hw(data, off + 2) if width == 4 else 0
            mnem, ops, is_br, is_call, is_ret, tgt = _classify(hw0, hw1, va)
            yield V850Frame(va=va, width=width, hw0=hw0, hw1=hw1,
                            mnemonic=mnem, op_str=ops,
                            is_branch=is_br, is_call=is_call,
                            is_ret=is_ret, target=tgt)
            off += width


# ---------------------------------------------------------------------------
# DisasmEngine-compatible streaming interface
# ---------------------------------------------------------------------------

class V850Disasm:
    """
    Streaming V850 disassembler matching the DisasmEngine.stream() contract.

    Yields dicts: address, mnemonic, op_str, size, hw0, hw1,
                  is_branch, is_call, is_ret, target.

    is_call/is_ret classification is accurate for JARL lp/JMP [lp] patterns.
    Mnemonic is '???' for instructions that are not control-flow.
    """

    def __init__(self, endian: str = 'little'):
        self._dec = V850Decoder(endian=endian)
        self.endian = endian

    def stream(self, data: bytes, base_addr: int = 0) -> Iterator[dict]:
        for frame in self._dec.decode_frames(data, base_addr):
            yield {
                'address':   frame.va,
                'mnemonic':  frame.mnemonic,
                'op_str':    frame.op_str,
                'size':      frame.width,
                'hw0':       frame.hw0,
                'hw1':       frame.hw1,
                'is_branch': frame.is_branch,
                'is_call':   frame.is_call,
                'is_ret':    frame.is_ret,
                'target':    frame.target,
            }

    def find_function_starts(self, data: bytes, base_addr: int = 0) -> List[int]:
        """
        Function-start heuristic for V850 ELF binaries.

        Detects PREPARE instructions (standard GCC function prologue) and
        positions following JMP [lp] (return) that start with a PREPARE.
        """
        starts: List[int] = []
        prev_ret = True
        for frame in self._dec.decode_frames(data, base_addr):
            if prev_ret and frame.mnemonic == 'prepare':
                starts.append(frame.va)
            if frame.is_ret:
                prev_ret = True
            elif frame.mnemonic != '???':
                prev_ret = False
        return sorted(set(starts))

    def report_frames(self, data: bytes, base_addr: int = 0, limit: int = 0) -> str:
        lines = []
        for i, f in enumerate(self._dec.decode_frames(data, base_addr)):
            if limit and i >= limit:
                break
            lines.append(str(f))
        return '\n'.join(lines)
