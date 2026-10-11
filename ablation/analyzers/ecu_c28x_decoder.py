"""
TMS320C28x ISA decoder for ECU/embedded firmware.

The TMS320C28x (C28x) is a 32-bit fixed-point DSP/MCU core produced by Texas
Instruments, used in F28x-series MCUs (F28P55x, F28335, F2837x, F2838x). It
appears in EV/HEV traction inverter control units and motor-drive ECUs compiled
with cl2000 or c29clang. Capstone 5.x has no C28x support; this module
implements the decoder in pure Python from SPRU430F (TMS320C28x CPU and
Instruction Set Reference Guide, April 2015).

Instruction width
-----------------
C28x uses 16-bit program words stored in little-endian byte order. Program
memory is word-addressed (each address refers to one 16-bit word). Instructions
are either one word (16 bits) or two words (32 bits).

Within a raw byte buffer the word layout is:

    byte offset 0-1  -> instruction word 0 (w1)
    byte offset 2-3  -> instruction word 1 (w2), present only for 32-bit insns

Two-word instructions are identified by the pattern of w1 alone (see _is_32bit).
All encodings in this module are sourced verbatim from SPRU430F per-instruction
encoding pages and Table B-1.

Program counter and branch targets
-----------------------------------
The PC holds a word address. After a 16-bit (1-word) instruction the PC
advances by 1; after a 32-bit (2-word) instruction it advances by 2.
PC-relative branch offsets (B, BF, BANZ, BAR) are signed 16-bit word counts
added to the PC after the branch instruction has been fetched. For a 32-bit
instruction at word VA ``wva``, the next word VA is ``wva + 2``; the branch
target is ``wva + 2 + offset``.

Long-branch / call instructions (LB 22bit, LC 22bit, LCR #22bit, FFC) carry an
absolute 22-bit word address, not a PC-relative offset.

Usage::

    from ablation.analyzers.ecu_c28x_decoder import EcuC28xDecoder

    dec = EcuC28xDecoder(data, base_va=0)          # base_va is a word address
    insns = dec.disassemble(start=0, end=0x2000)   # byte offsets
    starts = dec.function_starts()                 # word VAs of call targets
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


_COND_NAMES: dict[int, str] = {
    0x0: 'NEQ', 0x1: 'EQ',  0x2: 'GT',   0x3: 'GEQ',
    0x4: 'LT',  0x5: 'LEQ', 0x6: 'HI',   0x7: 'HIS',
    0x8: 'LO',  0x9: 'LOS', 0xA: 'NOV',  0xB: 'OV',
    0xC: 'NTC', 0xD: 'TC',  0xE: 'NBIO', 0xF: 'UNC',
}


@dataclass
class C28xInsn:
    """A decoded TMS320C28x instruction."""

    word_va: int          # word-address VA of this instruction
    is_32bit: bool        # True when this is a 2-word (32-bit) instruction
    mnemonic: str
    insn_type: str        # 'BRANCH' | 'CALL' | 'RETURN' | 'LOOP' | 'MISC'
    raw: bytes            # 2 or 4 raw bytes (little-endian)
    target: Optional[int] = None   # word-address target VA (branches/calls)
    cond: Optional[str] = None     # condition name for B/BF, None = UNC
    imm: Optional[int] = None

    def __str__(self) -> str:
        width = 'C28/32' if self.is_32bit else 'C28/16'
        cond_str = f'/{self.cond}' if self.cond and self.cond != 'UNC' else ''
        target_str = f'  -> 0x{self.target:06X}' if self.target is not None else ''
        return (
            f'0x{self.word_va:06X}  [{width}]  '
            f'{self.mnemonic + cond_str:<22}{target_str}'
        )


class EcuC28xDecoder:
    """
    Decode TMS320C28x instructions from a raw binary buffer.

    Parameters
    ----------
    data
        Raw bytes. Accepts ``bytes``, ``str`` path, or ``Path``.
    base_va
        Word address of the first instruction word in ``data``.

    Notes
    -----
    ``from_path`` and ``from_bytes`` are convenience constructors; all three
    forms are equivalent.

    All ``word_va`` values and ``target`` addresses are word-addresses.
    Byte offsets (used in ``disassemble``/``insn_length``/``decode_one``) refer
    to positions within the raw ``data`` buffer, not to program-memory addresses.
    """

    # ---- 16-bit fixed-value instructions ----
    _LRET    = 0x7614   # Long Return (software-stack form, pairs with LC)
    _LRETE   = 0x7610   # Long Return and Enable Interrupts
    _LRETR   = 0x0006   # Long Return using RPC register (pairs with LCR)
    _IRET    = 0x7602   # Interrupt Return
    _LB_XAR7 = 0x7620  # LB *XAR7 (indirect long branch via XAR7)
    _LC_XAR7 = 0x7604  # LC *XAR7 (indirect long call via XAR7)
    _IDLE    = 0x7621
    _NMI     = 0x7616   # INTR NMI (16-bit form; no second word)
    _EMUINT  = 0x761C   # INTR EMUINT (16-bit form)

    # 32-bit instruction whose first word is a fixed value (not a mask range)
    _IACK_W1 = 0x763F   # IACK #16bit: w1=0x763F, w2=imm16

    def __init__(self, data: 'str | Path | bytes', base_va: int = 0):
        if isinstance(data, (str, Path)):
            try:
                with open(data, 'rb') as f:
                    self._data = f.read()
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f'EcuC28xDecoder: {data!r} not found'
                ) from exc
        else:
            self._data = bytes(data)
        self._base_va = base_va

    @classmethod
    def from_path(cls, path: 'str | Path', base_va: int = 0) -> 'EcuC28xDecoder':
        """Convenience constructor; equivalent to EcuC28xDecoder(path, base_va)."""
        return cls(path, base_va)

    @classmethod
    def from_bytes(cls, data: bytes, base_va: int = 0) -> 'EcuC28xDecoder':
        """Convenience constructor; equivalent to EcuC28xDecoder(data, base_va)."""
        return cls(data, base_va)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def insn_length(self, byte_off: int) -> int:
        """Return 2 or 4 — byte length of the instruction starting at ``byte_off``."""
        data = self._data
        if byte_off + 2 > len(data):
            return 0
        w1 = struct.unpack_from('<H', data, byte_off)[0]
        return 4 if self._is_32bit(w1) else 2

    def decode_one(self, byte_off: int) -> Optional[C28xInsn]:
        """Decode a single instruction at byte offset ``byte_off``.

        Returns ``None`` when fewer than 2 bytes remain or a 32-bit instruction
        would exceed the buffer.
        """
        data = self._data
        if byte_off + 2 > len(data):
            return None
        w1 = struct.unpack_from('<H', data, byte_off)[0]
        word_va = self._base_va + byte_off // 2
        if self._is_32bit(w1):
            if byte_off + 4 > len(data):
                return None
            w2 = struct.unpack_from('<H', data, byte_off + 2)[0]
            return self._decode_32(word_va, w1, w2)
        return self._decode_16(word_va, w1)

    def disassemble(
        self, start: int = 0, end: Optional[int] = None
    ) -> list[C28xInsn]:
        """Decode all instructions in byte range ``[start, end)``.

        Both bounds are byte offsets within the data buffer.
        """
        if end is None:
            end = len(self._data)
        end = min(end, len(self._data))
        results: list[C28xInsn] = []
        off = start
        while off < end:
            insn = self.decode_one(off)
            if insn is None:
                break
            results.append(insn)
            off += len(insn.raw)
        return results

    def function_starts(self) -> list[int]:
        """Return probable function-start word-VAs by collecting direct call targets.

        Scans for direct-address call instructions (LC 22bit, LCR #22bit, FFC) and
        returns their 22-bit absolute word-address targets as candidate function
        entry points. Sorted ascending.

        Indirect calls (LC *XAR7, LCR *XARn) cannot be resolved statically and are
        not included.
        """
        data = self._data
        n = len(data)
        starts: set[int] = set()
        off = 0
        while off + 2 <= n:
            w1 = struct.unpack_from('<H', data, off)[0]
            if self._is_32bit(w1) and off + 4 <= n:
                w2 = struct.unpack_from('<H', data, off + 2)[0]
                mask_hi = w1 & 0xFFC0
                if mask_hi in (0x0080, 0x7640, 0x00C0):
                    # LC 22bit, LCR #22bit, FFC XAR7 — all carry a 22-bit target
                    addr22 = ((w1 & 0x3F) << 16) | w2
                    starts.add(addr22)
                off += 4
            else:
                off += 2
        return sorted(starts)

    # ------------------------------------------------------------------
    # 32-bit instruction decoder
    # ------------------------------------------------------------------

    def _decode_32(self, word_va: int, w1: int, w2: int) -> C28xInsn:
        raw = struct.pack('<HH', w1, w2)

        # B COND, #16bit  —  1111 1111 1110 COND / signed offset16
        # SPRU430F p.163: PC advances past the 2-word instruction (word_va+2), then
        # adds the signed 16-bit word offset.
        if (w1 & 0xFFF0) == 0xFFE0:
            cond = w1 & 0xF
            cond_name = _COND_NAMES.get(cond, f'C{cond:X}')
            off16 = w2 if w2 < 0x8000 else w2 - 0x10000
            target = word_va + 2 + off16
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='B', insn_type='BRANCH',
                raw=raw, target=target,
                cond=cond_name if cond_name != 'UNC' else None,
            )

        # BF COND, #16bit  —  0101 0110 1100 COND / signed offset16
        # SPRU430F p.167: "Branch Fast" — same offset semantics as B.
        if (w1 & 0xFFF0) == 0x56C0:
            cond = w1 & 0xF
            cond_name = _COND_NAMES.get(cond, f'C{cond:X}')
            off16 = w2 if w2 < 0x8000 else w2 - 0x10000
            target = word_va + 2 + off16
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='BF', insn_type='BRANCH',
                raw=raw, target=target,
                cond=cond_name if cond_name != 'UNC' else None,
            )

        # BANZ #16bit, ARn--  —  0000 0000 0000 1nnn / signed offset16
        if (w1 & 0xFFF8) == 0x0008:
            ar_n = w1 & 0x7
            off16 = w2 if w2 < 0x8000 else w2 - 0x10000
            target = word_va + 2 + off16
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic=f'BANZ AR{ar_n}--', insn_type='BRANCH',
                raw=raw, target=target,
            )

        # BAR #16bit, ARn, ARm, EQ  —  1000 1111 10nn nmmm / signed offset16
        if (w1 & 0xFFC0) == 0x8F80:
            ar_n = (w1 >> 3) & 0x7
            ar_m = w1 & 0x7
            off16 = w2 if w2 < 0x8000 else w2 - 0x10000
            target = word_va + 2 + off16
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic=f'BAR AR{ar_n},AR{ar_m},EQ', insn_type='BRANCH',
                raw=raw, target=target, cond='EQ',
            )

        # BAR #16bit, ARn, ARm, NEQ  —  1000 1111 11nn nmmm / signed offset16
        if (w1 & 0xFFC0) == 0x8FC0:
            ar_n = (w1 >> 3) & 0x7
            ar_m = w1 & 0x7
            off16 = w2 if w2 < 0x8000 else w2 - 0x10000
            target = word_va + 2 + off16
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic=f'BAR AR{ar_n},AR{ar_m},NEQ', insn_type='BRANCH',
                raw=raw, target=target, cond='NEQ',
            )

        # LB 22bit  —  0000 0000 01CC CCCC / addr16
        if (w1 & 0xFFC0) == 0x0040:
            addr22 = ((w1 & 0x3F) << 16) | w2
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='LB', insn_type='BRANCH',
                raw=raw, target=addr22,
            )

        # LC 22bit  —  0000 0000 10CC CCCC / addr16
        if (w1 & 0xFFC0) == 0x0080:
            addr22 = ((w1 & 0x3F) << 16) | w2
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='LC', insn_type='CALL',
                raw=raw, target=addr22,
            )

        # FFC XAR7, 22bit  —  0000 0000 11CC CCCC / addr16
        # Fast function call; stores return address in XAR7 (not the stack or RPC).
        if (w1 & 0xFFC0) == 0x00C0:
            addr22 = ((w1 & 0x3F) << 16) | w2
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='FFC', insn_type='CALL',
                raw=raw, target=addr22,
            )

        # LCR #22bit  —  0111 0110 01CC CCCC / addr16
        if (w1 & 0xFFC0) == 0x7640:
            addr22 = ((w1 & 0x3F) << 16) | w2
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='LCR', insn_type='CALL',
                raw=raw, target=addr22,
            )

        # INTR INTx  —  0000 0000 0001 CCCC / imm16
        if (w1 & 0xFFF0) == 0x0010:
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='INTR', insn_type='MISC',
                raw=raw, imm=w1 & 0xF,
            )

        # IACK #16bit  —  0111 0110 0011 1111 / imm16
        if w1 == self._IACK_W1:
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='IACK', insn_type='MISC',
                raw=raw, imm=w2,
            )

        # LOOPNZ loc16, #16bit  —  0010 1110 LLLL LLLL / mask16
        if (w1 & 0xFF00) == 0x2E00:
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='LOOPNZ', insn_type='LOOP',
                raw=raw, imm=w2,
            )

        # LOOPZ loc16, #16bit  —  0010 1100 LLLL LLLL / mask16
        if (w1 & 0xFF00) == 0x2C00:
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='LOOPZ', insn_type='LOOP',
                raw=raw, imm=w2,
            )

        # IN loc16, *(PA)  —  1011 0100 LLLL LLLL / port_addr16
        if (w1 & 0xFF00) == 0xB400:
            return C28xInsn(
                word_va=word_va, is_32bit=True,
                mnemonic='IN', insn_type='MISC',
                raw=raw, imm=w2,
            )

        # Generic 32-bit fallback
        return C28xInsn(
            word_va=word_va, is_32bit=True,
            mnemonic=f'c28_32_{w1:04x}', insn_type='MISC',
            raw=raw,
        )

    # ------------------------------------------------------------------
    # 16-bit instruction decoder
    # ------------------------------------------------------------------

    def _decode_16(self, word_va: int, w1: int) -> C28xInsn:
        raw = struct.pack('<H', w1)

        # --- Return instructions ---
        if w1 == self._LRET:
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic='LRET', insn_type='RETURN', raw=raw,
            )
        if w1 == self._LRETE:
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic='LRETE', insn_type='RETURN', raw=raw,
            )
        if w1 == self._LRETR:
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic='LRETR', insn_type='RETURN', raw=raw,
            )
        if w1 == self._IRET:
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic='IRET', insn_type='RETURN', raw=raw,
            )

        # --- Indirect branches ---
        if w1 == self._LB_XAR7:
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic='LB *XAR7', insn_type='BRANCH', raw=raw,
            )

        # --- Indirect calls ---
        if w1 == self._LC_XAR7:
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic='LC *XAR7', insn_type='CALL', raw=raw,
            )

        # LCR *XARn  —  0011 1110 0110 0RRR  (indirect RPC call via XARn)
        if (w1 & 0xFFF8) == 0x3E60:
            n = w1 & 0x7
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic=f'LCR *XAR{n}', insn_type='CALL', raw=raw,
            )

        # --- Interrupt / system ---
        if w1 == self._NMI:
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic='NMI', insn_type='MISC', raw=raw,
            )
        if w1 == self._EMUINT:
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic='EMUINT', insn_type='MISC', raw=raw,
            )
        if w1 == self._IDLE:
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic='IDLE', insn_type='MISC', raw=raw,
            )

        # INC loc16  —  0000 1010 LLLL LLLL
        if (w1 & 0xFF00) == 0x0A00:
            return C28xInsn(
                word_va=word_va, is_32bit=False,
                mnemonic='INC', insn_type='MISC',
                raw=raw, imm=w1 & 0xFF,
            )

        # Generic 16-bit fallback
        return C28xInsn(
            word_va=word_va, is_32bit=False,
            mnemonic=f'c28_{w1:04x}', insn_type='MISC',
            raw=raw,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_32bit(w1: int) -> bool:
        """Return True when this first word is the first word of a 32-bit instruction.

        All patterns are sourced from SPRU430F per-instruction encoding pages.
        The 16-bit specials in the 0x76xx range (LRET=0x7614, LRETE=0x7610,
        LRETR=0x0006, IRET=0x7602, LB *XAR7=0x7620, LC *XAR7=0x7604,
        IDLE=0x7621, NMI=0x7616, EMUINT=0x761C) all fall below 0x7640 and are
        correctly excluded by the LCR #22bit test (mask 0xFFC0 == 0x7640).
        IACK (0x763F) is listed separately because its upper bits (0x7600) do
        not match the LCR pattern either.
        """
        return (
            (w1 & 0xFFF0) == 0xFFE0    # B COND
            or (w1 & 0xFFF0) == 0x56C0 # BF COND
            or (w1 & 0xFFF8) == 0x0008 # BANZ ARn--
            or (w1 & 0xFFC0) == 0x8F80 # BAR ARn,ARm,EQ
            or (w1 & 0xFFC0) == 0x8FC0 # BAR ARn,ARm,NEQ
            or (w1 & 0xFFC0) == 0x0040 # LB 22bit
            or (w1 & 0xFFC0) == 0x0080 # LC 22bit
            or (w1 & 0xFFC0) == 0x00C0 # FFC XAR7,22bit
            or (w1 & 0xFFC0) == 0x7640 # LCR #22bit
            or (w1 & 0xFFF0) == 0x0010 # INTR INTx
            or w1 == 0x763F             # IACK #16bit (first word)
            or (w1 & 0xFF00) == 0x2E00 # LOOPNZ loc16,#16bit
            or (w1 & 0xFF00) == 0x2C00 # LOOPZ  loc16,#16bit
            or (w1 & 0xFF00) == 0xB400 # IN loc16,*(PA)
        )
