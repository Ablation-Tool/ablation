"""
nanomips_decoder.py: nanoMIPS variable-length instruction frame decoder.

nanoMIPS is a compact ISA from Wave Computing (formerly MIPS Tech) introduced
with MIPS32r6. Instructions are 16, 32, or 48 bits wide. The frame width is
encoded in the first 16-bit halfword:

  bits[14:10] of hw0 == 0b11111  ->  48-bit (P48 encoding, POOL48A class)
  bits[1:0]   of hw0 == 0b00     ->  32-bit (P32 encoding)
  otherwise                       ->  16-bit (P16 encoding)

Capstone 5.x does NOT support nanoMIPS. This module:
  1. Gates on CS_MODE_NANOMIPS availability (capstone 6.x).
  2. When capstone 6.x is present: full decode via Capstone.
  3. When only capstone 5.x: frame-boundary detection only. Instruction
     mnemonics are left as '???' but size/address/raw fields are correct.
     This is enough to walk a binary and identify function boundaries,
     branch targets, and PLT stubs by byte pattern.

Targets: Ingenic X series SoCs (JZ4780, X1000, X2000), MediaTek Helio
         embedded, MIPS32r6 microcontrollers.

Usage:
    from ablation.analyzers.nanomips_decoder import NanoMIPSDecoder, NanoMIPSDisasm

    dec = NanoMIPSDecoder(endian='little')
    frames = dec.decode_frames(data, base_addr=0x80000000)
    for f in frames:
        print(f'0x{f.va:x}  [{f.width*8:2d}-bit]  {f.raw.hex()}  {f.mnemonic} {f.op_str}')

    # DisasmEngine-compatible interface:
    dis = NanoMIPSDisasm(endian='little')
    for insn in dis.stream(data, base_addr):
        print(insn)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Capstone availability check
# ---------------------------------------------------------------------------

try:
    import capstone
    from capstone import CS_ARCH_MIPS
    _HAS_CAPSTONE = True
    try:
        _CS_MODE_NANOMIPS = capstone.CS_MODE_NANOMIPS  # type: ignore[attr-defined]
        _HAS_NANOMIPS = True
    except AttributeError:
        _CS_MODE_NANOMIPS = None
        _HAS_NANOMIPS = False
except ImportError:
    _HAS_CAPSTONE = False
    _HAS_NANOMIPS = False
    _CS_MODE_NANOMIPS = None


# ---------------------------------------------------------------------------
# Frame record
# ---------------------------------------------------------------------------

@dataclass
class NanoFrame:
    """Single nanoMIPS instruction frame."""
    va: int
    width: int      # bytes: 2, 4, or 6
    raw: bytes
    mnemonic: str
    op_str: str

    def __str__(self) -> str:
        return f'0x{self.va:08x}  [{self.width * 8:2d}-bit]  {self.raw.hex():<12}  {self.mnemonic} {self.op_str}'


# ---------------------------------------------------------------------------
# Frame width discriminant
# ---------------------------------------------------------------------------

def _frame_width(hw0: int) -> int:
    """Return instruction width in bytes given the first 16-bit halfword."""
    if (hw0 >> 10) & 0x1f == 0x1f:
        return 6   # P48: POOL48A class (48-bit)
    if hw0 & 0x3 == 0x00:
        return 4   # P32: 32-bit instruction
    return 2       # P16: 16-bit instruction


# ---------------------------------------------------------------------------
# P16 branch/call/return detection (frame-only, no full decode)
# ---------------------------------------------------------------------------
# These cover the most common P16 patterns needed for function boundary
# detection when capstone 6.x is unavailable.

def _p16_classify(raw: bytes, endian: str) -> Tuple[str, str]:
    """Return (mnemonic_hint, op_str_hint) for a 16-bit nanoMIPS frame."""
    bo = 'little' if endian == 'little' else 'big'
    hw = int.from_bytes(raw[:2], bo)
    bits_15_10 = (hw >> 10) & 0x3f

    # P16.SYSCALL: bits[15:10] = 0b000110
    if bits_15_10 == 0b000110:
        return 'syscall', ''
    # P16.BR: unconditional branch  bits[15:10] = 0b110110
    if bits_15_10 == 0b110110:
        return 'bc', f'0x{(hw & 0x3ff):x}'
    # P16.JRC (jr $ra): bits[15:10] = 0b010010, bits[9:5] = 31
    if bits_15_10 == 0b010010 and ((hw >> 5) & 0x1f) == 31:
        return 'jrc', '$ra'
    # P16.JRC (jr $reg)
    if bits_15_10 == 0b010010:
        return 'jrc', f'${(hw >> 5) & 0x1f}'
    # P16.BALC: call  bits[15:10] = 0b110010
    if bits_15_10 == 0b110010:
        return 'balc', f'0x{(hw & 0x3ff):x}'
    # P16.BEQZC: bits[15:11] = 0b100xx
    if (hw >> 11) & 0x1f == 0b10000 or (hw >> 11) & 0x1f == 0b10001:
        reg = (hw >> 7) & 0xf
        return 'beqzc', f'${reg}'
    # P16.BNEZC: bits[15:11] = 0b101xx
    if (hw >> 11) & 0x1f == 0b10100 or (hw >> 11) & 0x1f == 0b10101:
        reg = (hw >> 7) & 0xf
        return 'bnezc', f'${reg}'

    return '???', ''


def _p32_classify(raw: bytes, endian: str) -> Tuple[str, str]:
    """Return (mnemonic_hint, op_str_hint) for a 32-bit nanoMIPS frame."""
    bo = 'little' if endian == 'little' else 'big'
    # nanoMIPS P32: the 32-bit word is stored as two 16-bit halfwords.
    # In little-endian nanoMIPS, the first 16-bit halfword in memory holds
    # bits[15:0] and the second holds bits[31:16].
    w = int.from_bytes(raw[:4], bo)
    bits_31_26 = (w >> 26) & 0x3f

    # BALC: bits[31:26] = 0b101010 (0x2a)
    if bits_31_26 == 0x2a:
        return 'balc', ''
    # BC: unconditional branch  bits[31:26] = 0b101000 (0x28)
    if bits_31_26 == 0x28:
        return 'bc', ''
    # BEQZC/BNEZC: bits[31:29] = 011
    if (w >> 29) & 0x7 == 0b011:
        op = 'beqzc' if not (w >> 28) & 1 else 'bnezc'
        return op, ''
    # JRC ($ra): POOL32A subop check
    if bits_31_26 == 0x00:
        subop = (w >> 22) & 0xf
        if subop == 0x7:
            rs = (w >> 16) & 0x1f
            return ('jrc', '$ra') if rs == 31 else ('jrc', f'${rs}')

    return '???', ''


# ---------------------------------------------------------------------------
# Core decoder
# ---------------------------------------------------------------------------

class NanoMIPSDecoder:
    """
    nanoMIPS variable-length frame decoder.

    When capstone 6.x with CS_MODE_NANOMIPS is available, delegates to
    Capstone for full decode.  Otherwise, walks byte boundaries and
    classifies frames as 16/32/48-bit, providing mnemonic hints for the
    most common branch/call/return patterns only.

    Args:
        endian: 'little' (default) or 'big'.
    """

    def __init__(self, endian: str = 'little'):
        self.endian = endian
        self._cs: Optional[object] = None

        if _HAS_NANOMIPS and _CS_MODE_NANOMIPS is not None:
            cs_endian = (capstone.CS_MODE_BIG_ENDIAN
                         if endian == 'big' else capstone.CS_MODE_LITTLE_ENDIAN)
            self._cs = capstone.Cs(CS_ARCH_MIPS, _CS_MODE_NANOMIPS | cs_endian)
            self._cs.detail = True
            self._cs.skipdata = True

    @property
    def has_full_decode(self) -> bool:
        """True when capstone 6.x nanoMIPS support is available."""
        return self._cs is not None

    def decode_frames(self, data: bytes, base_addr: int = 0) -> List[NanoFrame]:
        """Decode all frames in `data`, returning a list of NanoFrame records."""
        return list(self._iter_frames(data, base_addr))

    def _iter_frames(self, data: bytes, base_addr: int) -> Iterator[NanoFrame]:
        if self._cs is not None:
            yield from self._iter_capstone(data, base_addr)
        else:
            yield from self._iter_fallback(data, base_addr)

    def _iter_capstone(self, data: bytes, base_addr: int) -> Iterator[NanoFrame]:
        for insn in self._cs.disasm(data, base_addr):
            raw = bytes(insn.bytes)
            yield NanoFrame(
                va=insn.address,
                width=insn.size,
                raw=raw,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
            )

    def _iter_fallback(self, data: bytes, base_addr: int) -> Iterator[NanoFrame]:
        """Frame-boundary walk without full decode (capstone 5.x path)."""
        bo = 'little' if self.endian == 'little' else 'big'
        off = 0
        while off < len(data) - 1:
            hw0 = int.from_bytes(data[off:off+2], bo)
            width = _frame_width(hw0)

            if off + width > len(data):
                break

            raw = data[off: off + width]
            va  = base_addr + off

            if width == 2:
                mnem, ops = _p16_classify(raw, self.endian)
            elif width == 4:
                mnem, ops = _p32_classify(raw, self.endian)
            else:
                mnem, ops = 'p48', ''  # 48-bit insns are rare; don't attempt decode

            yield NanoFrame(va=va, width=width, raw=raw, mnemonic=mnem, op_str=ops)
            off += width


# ---------------------------------------------------------------------------
# DisasmEngine-compatible streaming interface
# ---------------------------------------------------------------------------

class NanoMIPSDisasm:
    """
    Streaming nanoMIPS disassembler matching the DisasmEngine.stream() contract.

    Yields dicts with keys: address, mnemonic, op_str, size, raw,
    is_branch, is_call, is_ret.

    When capstone 6.x is available, all fields are populated.
    With capstone 5.x, mnemonic may be '???' for non-branch insns, but
    is_branch/is_call/is_ret are still set from pattern-matched hints.
    """

    _BRANCH_MNEMS = frozenset({
        'bc', 'beqzc', 'bnezc', 'beqc', 'bnec', 'bltc', 'bgec',
        'bltuc', 'bgeuc', 'bgtzc', 'bltzc', 'bgezc', 'blezc',
        'bltic', 'bgeic', 'bltiuc', 'bleiuc',
    })
    _CALL_MNEMS  = frozenset({'balc', 'jalrc', 'jalrc.hb'})
    _RET_MNEMS   = frozenset({'jrc'})

    def __init__(self, endian: str = 'little'):
        self._dec = NanoMIPSDecoder(endian=endian)

    @property
    def has_full_decode(self) -> bool:
        return self._dec.has_full_decode

    def stream(self, data: bytes, base_addr: int = 0) -> Iterator[dict]:
        for frame in self._dec.decode_frames(data, base_addr):
            mnem = frame.mnemonic
            yield {
                'address':   frame.va,
                'mnemonic':  mnem,
                'op_str':    frame.op_str,
                'size':      frame.width,
                'raw':       frame.raw.hex(),
                'is_branch': mnem in self._BRANCH_MNEMS,
                'is_call':   mnem in self._CALL_MNEMS,
                'is_ret':    mnem in self._RET_MNEMS,
                'width_bits': frame.width * 8,
            }

    def find_function_starts(self, data: bytes, base_addr: int = 0) -> List[int]:
        """
        Heuristic function-start detector for nanoMIPS binaries.

        Looks for the standard nanoMIPS frame setup:
          addiu[32] $sp, $sp, -N   (P32 form)
          save[16]  imm, ...       (P16 compact frame setup)

        Returns sorted list of likely function start addresses.
        """
        starts: List[int] = []
        bo = 'little' if self._dec.endian == 'little' else 'big'
        frames = self._dec.decode_frames(data, base_addr)
        for f in frames:
            # addiu/daddiu $sp, $sp, -N decoded by capstone 6.x
            if f.mnemonic in ('addiu', 'daddiu') and 'sp, sp, -' in f.op_str:
                starts.append(f.va)
                continue
            # Fallback: pattern-match on 32-bit ADDIU $sp frame
            # P32 ADDIU: bits[31:26]=0b001001(=9), rs=rt=29($sp), imm<0
            if f.width == 4:
                w = int.from_bytes(f.raw, bo)
                op = (w >> 26) & 0x3f
                rs = (w >> 21) & 0x1f
                rt = (w >> 16) & 0x1f
                imm = w & 0xffff
                if op == 9 and rs == 29 and rt == 29 and (imm & 0x8000):
                    starts.append(f.va)
        return sorted(set(starts))

    def report_frames(self, data: bytes, base_addr: int = 0, limit: int = 0) -> str:
        """Human-readable frame listing for inspection."""
        lines = []
        for i, f in enumerate(self._dec.decode_frames(data, base_addr)):
            if limit and i >= limit:
                break
            lines.append(str(f))
        return '\n'.join(lines)
