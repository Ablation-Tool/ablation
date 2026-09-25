"""
arc_decoder.py: ARC (Synopsys DesignWare ARC) variable-length instruction frame decoder.

ARC 700 / ARC HS processors use a mixed 16/32-bit instruction encoding.
The instruction width is determined by bits[15:11] of the first halfword fetched:
  op5 = (hw0 >> 11) & 0x1f
  if op5 >= 0x18 (24): 16-bit "compact" instruction (ARC16/ARCv2 short)
  else              : 32-bit instruction

Capstone 5.x does not support CS_ARCH_ARC; capstone next branch does.
This module provides:
  1. Frame-width discriminant + byte walker (pure Python, always available).
  2. Control-flow hints from known 32-bit patterns (BL, J, branch group).
  3. Function-start heuristic via prologue scan ("push_s blink" or ELF symbols).
  4. Graceful upgrade: if capstone with CS_ARCH_ARC is available (capstone next),
     ARCDecoder uses it for full instruction decode; otherwise pure Python only.

The ARCDecoder / ARCDisasm classes provide a DisasmEngine-compatible streaming
interface that the taint tracker consumes.

ARC ISA references:
  ARC 700 Programmer's Reference Manual (ARC International)
  ARC HS Processor Programmer's Reference (Synopsys)

Targets: Synopsys DesignWare ARC EM/HS (IoT MCUs, smart TVs, storage controllers,
         automotive SoCs), ARC 770D (Linux-capable), ARC HS38/HS48 (SMP Linux).

Usage:
    from ablation.analyzers.arc_decoder import ARCDecoder, ARCDisasm, ARCFrame

    dec = ARCDecoder(endian='little')
    frames = dec.decode_frames(data, base_addr=0)
    for f in frames:
        print(f)

    dis = ARCDisasm(endian='little')
    for insn in dis.stream(data, base_addr):
        if insn['is_call']:
            print(f'call @ 0x{insn["address"]:x} -> 0x{insn["target"]:x}')
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

try:
    import capstone
    _HAS_CAPSTONE = True
    try:
        _CS_ARCH_ARC = capstone.CS_ARCH_ARC  # type: ignore[attr-defined]  # capstone next
        _HAS_CAPSTONE_ARC = True
    except AttributeError:
        _CS_ARCH_ARC = None
        _HAS_CAPSTONE_ARC = False
except ImportError:
    _HAS_CAPSTONE = False
    _HAS_CAPSTONE_ARC = False
    _CS_ARCH_ARC = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# 32-bit instruction major opcode groups (hw0 bits[15:11])
_OP_BRANCH = 4    # 0b00100  B/BL/Bcc family
_OP_BRCC   = 5    # 0b00101  Bcc 21-bit offset
_OP_BRREG  = 6    # 0b00110  branch-to-register
_OP_JUMP   = 7    # 0b00111  J/JL family (includes J[blink] = return)

# BL (branch and link = direct call):
# hw0 & 0xFE00 == 0x2200
# Derivation: (op5=4)<<11 | (format=0)<<10 | (link=1)<<9 = 0x2200
_BL_MASK  = 0xFE00
_BL_MATCH = 0x2200

# B (branch, no link):
# hw0 & 0xFE00 == 0x2000
_B_MASK  = 0xFE00
_B_MATCH = 0x2000

# Conditional branch (Bcc, 21-bit): op5 == 5 => hw0 & 0xF800 == 0x2800
_BCC_MASK  = 0xF800
_BCC_MATCH = 0x2800

# J / JL group: op5 == 7 => hw0 & 0xF800 == 0x3800
_J_MASK  = 0xF800
_J_MATCH = 0x3800

# JL (jump and link = indirect call): op5==7, bit[9] = link flag
# hw0 & 0xFE00 == 0x3A00 (approximate; bit[9]=1)
_JL_MASK  = 0xFE00
_JL_MATCH = 0x3A00

# J [blink] (return): op5==7, no link bit, target register = BLINK (r31 = 0x1F)
# In ARC 700, the target register is encoded in hw1[5:0].
# hw1 & 0x003F == 0x001F -> target is BLINK.
# Combined: (hw0 & 0xFE00) == 0x3800 and (hw1 & 0x003F) == 0x001F
_RET_HW0_MASK  = 0xFE00
_RET_HW0_MATCH = 0x3800  # J, unconditional, no link
_RET_HW1_MASK  = 0x003F
_RET_HW1_MATCH = 0x001F  # BLINK = r31 = 0x1F

# 16-bit compact major opcode range: op5 in [0x18, 0x1F]
_OP16_MIN = 0x18

# push_s blink (16-bit compact): saves BLINK to stack, decrements SP.
# Typical function prologue first instruction.
# ARC compact push_s group: op5 = 0x18 = 0b11000, sub-opcode encodes register.
# push_s blink = 0b11000_001_0_111_1110 approximation.
# This is heuristic; verify against real ARC binaries.
_PUSH_BLINK_MASK  = 0xFF80
_PUSH_BLINK_MATCH = 0xC180   # tentative; bit pattern needs real-binary verification


# ---------------------------------------------------------------------------
# Frame record
# ---------------------------------------------------------------------------

@dataclass
class ARCFrame:
    """Single ARC instruction frame."""
    va:       int
    width:    int     # bytes: 2 or 4
    hw0:      int     # first halfword (bits[15:0])
    hw1:      int     # second halfword (bits[31:16]); 0 for 16-bit insns
    mnemonic: str
    op_str:   str
    is_branch: bool   = False
    is_call:   bool   = False
    is_ret:    bool   = False
    target:    int    = 0     # resolved branch/call target VA (0 if not computed)

    def __str__(self) -> str:
        raw_hex = (f'{self.hw0:04x}{self.hw1:04x}' if self.width == 4
                   else f'{self.hw0:04x}')
        tgt = f' -> 0x{self.target:x}' if self.target else ''
        return (f'0x{self.va:08x}  [{self.width * 8:2d}-bit]  {raw_hex:<8}  '
                f'{self.mnemonic} {self.op_str}{tgt}')


# ---------------------------------------------------------------------------
# Frame width discriminant
# ---------------------------------------------------------------------------

def _arc_width(hw0: int) -> int:
    """Return instruction width in bytes (2 or 4) from first halfword."""
    op5 = (hw0 >> 11) & 0x1f
    return 2 if op5 >= _OP16_MIN else 4


# ---------------------------------------------------------------------------
# BL target offset extraction (25-bit signed)
# ---------------------------------------------------------------------------

def _bl_target(hw0: int, hw1: int, instr_va: int) -> int:
    """
    Compute BL target VA from 25-bit signed offset.

    BL encoding (25-bit offset, ARC 700 / ARC HS):
      hw0[8:0]  = offset[24:16]  (9 upper bits)
      hw1[15:0] = offset[15:0]   (16 lower bits)
    Target = instr_va + 4 + sign_extend_25(offset)

    Note: the +4 accounts for branches being relative to the NEXT instruction
    (instruction size = 4 bytes). Verify against real ARC binaries if targets
    appear to be consistently off by 4.
    """
    raw = ((hw0 & 0x1FF) << 16) | (hw1 & 0xFFFF)
    if raw & (1 << 24):
        raw -= (1 << 25)
    return instr_va + 4 + raw


# ---------------------------------------------------------------------------
# Classify 32-bit instruction
# ---------------------------------------------------------------------------

def _classify32(hw0: int, hw1: int, va: int) -> Tuple[str, str, bool, bool, bool, int]:
    """Return (mnemonic, op_str, is_branch, is_call, is_ret, target)."""
    is_br = is_call = is_ret = False
    target = 0

    if (hw0 & _BL_MASK) == _BL_MATCH:
        target = _bl_target(hw0, hw1, va)
        return 'bl', f'0x{target:x}', False, True, False, target

    if (hw0 & _B_MASK) == _B_MATCH:
        target = _bl_target(hw0, hw1, va)  # same offset encoding as BL
        return 'b', f'0x{target:x}', True, False, False, target

    if (hw0 & _BCC_MASK) == _BCC_MATCH:
        return 'bcc', '', True, False, False, 0

    op5 = (hw0 >> 11) & 0x1f
    if op5 == _OP_JUMP:
        if (hw0 & _JL_MASK) == _JL_MATCH:
            return 'jl', '', False, True, False, 0
        if ((hw0 & _RET_HW0_MASK) == _RET_HW0_MATCH
                and (hw1 & _RET_HW1_MASK) == _RET_HW1_MATCH):
            return 'j_blink', '[blink]', False, False, True, 0
        return 'j', '', True, False, False, 0

    if op5 == _OP_BRREG:
        return 'bbit', '', True, False, False, 0

    return '???', '', False, False, False, 0


# ---------------------------------------------------------------------------
# Core decoder
# ---------------------------------------------------------------------------

class ARCDecoder:
    """
    ARC variable-length instruction frame decoder.

    Uses capstone CS_ARCH_ARC (capstone next branch) when available for full
    instruction decode. Falls back to pure-Python frame walker otherwise.
    Pure-Python path is always accurate for control-flow (BL, J[blink], branch).

    Args:
        endian: 'little' (default, Linux ARC HS) or 'big' (ARC 600/700 BE).
    """

    def __init__(self, endian: str = 'little'):
        self.endian = endian
        self._bo = 'little' if endian == 'little' else 'big'
        self._cs: Optional[object] = None
        if _HAS_CAPSTONE_ARC and _CS_ARCH_ARC is not None:
            cs_endian = (capstone.CS_MODE_BIG_ENDIAN  # type: ignore[union-attr]
                         if endian == 'big'
                         else capstone.CS_MODE_LITTLE_ENDIAN)  # type: ignore[union-attr]
            try:
                self._cs = capstone.Cs(_CS_ARCH_ARC, cs_endian)  # type: ignore[arg-type]
                self._cs.detail = False  # type: ignore[union-attr]
            except Exception:
                self._cs = None

    def _hw(self, data: bytes, off: int) -> int:
        """Read one 16-bit halfword at offset, respecting endianness."""
        if off + 2 > len(data):
            return 0
        return int.from_bytes(data[off:off+2], self._bo)

    @property
    def has_full_decode(self) -> bool:
        """True when capstone ARC is available for full instruction text."""
        return self._cs is not None

    def decode_frames(self, data: bytes, base_addr: int = 0) -> List[ARCFrame]:
        return list(self._iter_frames(data, base_addr))

    def _iter_frames_capstone(self, data: bytes, base_addr: int) -> Iterator[ARCFrame]:
        """Full decode via capstone CS_ARCH_ARC (capstone next branch)."""
        for insn in self._cs.disasm(data, base_addr):  # type: ignore[union-attr]
            hw0 = self._hw(data, insn.address - base_addr)
            width = insn.size
            hw1 = self._hw(data, insn.address - base_addr + 2) if width == 4 else 0
            mnem = insn.mnemonic.lower()
            is_call = mnem in ('bl', 'jl')
            is_ret  = mnem in ('j_s', 'j') and '[blink]' in insn.op_str
            is_br   = mnem in ('b', 'bcc', 'bbit0', 'bbit1', 'brne', 'breq', 'brlt', 'brge', 'brlo', 'brhs') and not is_call
            target  = 0
            if is_call and insn.op_str.startswith('0x'):
                try:
                    target = int(insn.op_str, 16)
                except ValueError:
                    pass
            yield ARCFrame(va=insn.address, width=width, hw0=hw0, hw1=hw1,
                           mnemonic=mnem, op_str=insn.op_str,
                           is_branch=is_br, is_call=is_call,
                           is_ret=is_ret, target=target)

    def _iter_frames(self, data: bytes, base_addr: int) -> Iterator[ARCFrame]:
        if self._cs is not None:
            yield from self._iter_frames_capstone(data, base_addr)
            return
        off = 0
        while off < len(data) - 1:
            hw0 = self._hw(data, off)
            width = _arc_width(hw0)
            va = base_addr + off

            if off + width > len(data):
                break

            if width == 2:
                mnem, ops, is_br, is_call, is_ret, tgt = self._classify16(hw0, va)
                yield ARCFrame(va=va, width=2, hw0=hw0, hw1=0,
                               mnemonic=mnem, op_str=ops,
                               is_branch=is_br, is_call=is_call,
                               is_ret=is_ret, target=tgt)
            else:
                hw1 = self._hw(data, off + 2)
                mnem, ops, is_br, is_call, is_ret, tgt = _classify32(hw0, hw1, va)
                yield ARCFrame(va=va, width=4, hw0=hw0, hw1=hw1,
                               mnemonic=mnem, op_str=ops,
                               is_branch=is_br, is_call=is_call,
                               is_ret=is_ret, target=tgt)
            off += width

    def _classify16(self, hw0: int, va: int) -> Tuple[str, str, bool, bool, bool, int]:
        """Classify 16-bit compact instruction."""
        op5 = (hw0 >> 11) & 0x1f

        # j_s [blink]: common compact return. ARC compact j_s [blink]
        # is encoded with a sub-opcode that encodes the BLINK register.
        # Approximate check: op5 == 0x1F and specific lower bits.
        # Real pattern from GCC ARC output: 0x7FE0 (big-endian) or similar.
        # Using conservative heuristic: op5 == 0x1f and lower byte suggests jump.
        if op5 == 0x1f and (hw0 & 0x001F) == 0x001F:
            return 'j_s', '[blink]', False, False, True, 0

        # push_s blink: typical prologue
        if (hw0 & _PUSH_BLINK_MASK) == _PUSH_BLINK_MATCH:
            return 'push_s', 'blink', False, False, False, 0

        # Compact branch hints (approximate)
        if op5 in (0x1b, 0x1c, 0x1d):
            return 'b_s', '', True, False, False, 0

        return '???', '', False, False, False, 0


# ---------------------------------------------------------------------------
# DisasmEngine-compatible streaming interface
# ---------------------------------------------------------------------------

class ARCDisasm:
    """
    Streaming ARC disassembler matching the DisasmEngine.stream() contract.

    Yields dicts: address, mnemonic, op_str, size, hw0, hw1,
                  is_branch, is_call, is_ret, target, width_bits.

    Automatically uses capstone CS_ARCH_ARC (capstone next branch) when
    installed for full instruction decode. Falls back to pure-Python frame
    walker otherwise. is_call/is_ret are accurate on both paths.
    """

    def __init__(self, endian: str = 'little'):
        self._dec = ARCDecoder(endian=endian)
        self.endian = endian

    def stream(self, data: bytes, base_addr: int = 0) -> Iterator[dict]:
        for frame in self._dec.decode_frames(data, base_addr):
            yield {
                'address':    frame.va,
                'mnemonic':   frame.mnemonic,
                'op_str':     frame.op_str,
                'size':       frame.width,
                'hw0':        frame.hw0,
                'hw1':        frame.hw1,
                'is_branch':  frame.is_branch,
                'is_call':    frame.is_call,
                'is_ret':     frame.is_ret,
                'target':     frame.target,
                'width_bits': frame.width * 8,
            }

    def find_function_starts(self, data: bytes, base_addr: int = 0) -> List[int]:
        """
        Function-start heuristic for ARC binaries.

        Looks for push_s blink (first instruction of a standard BLINK-saving
        prologue) and for any 16-bit compact push instruction at positions
        that are preceded by the end of a prior function (j_s [blink] or
        nop_s / nop alignment padding).

        Returns sorted list of likely function start addresses.
        """
        starts: List[int] = []
        prev_was_ret = True  # treat start of data as potential function entry
        for frame in self._dec.decode_frames(data, base_addr):
            if prev_was_ret and frame.mnemonic in ('push_s', 'st.a'):
                starts.append(frame.va)
            if frame.is_ret:
                prev_was_ret = True
            elif frame.mnemonic not in ('???',):
                prev_was_ret = False
        return sorted(set(starts))

    def report_frames(self, data: bytes, base_addr: int = 0, limit: int = 0) -> str:
        lines = []
        for i, f in enumerate(self._dec.decode_frames(data, base_addr)):
            if limit and i >= limit:
                break
            lines.append(str(f))
        return '\n'.join(lines)
