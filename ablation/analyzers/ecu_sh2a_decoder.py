"""
Renesas SH-2A decoder for ECU firmware.

SH-2A is the core used in Renesas SH7058 / SH7059 MCUs found in Honda (CBR250RR,
ECU type 38770-K87-J01 and similar), Subaru (SH7058S, EcuFlash corpus), and other
Japanese OEM ECUs.  Capstone 5.0.7 does not support SH-2A; this module implements
the decoder in pure Python.

Instruction width
-----------------
The base SH-2 ISA uses 16-bit fixed-width instructions (all 2-byte aligned, big-endian).
SH-2A extends SH-2 with a set of 32-bit instructions identified by specific first-halfword
patterns.  The length discrimination rule (from Renesas SH2A Hardware Manual Rev.2.00):

    32-bit SH-2A instructions start with these first-halfword patterns:
      (hw & 0xF00F) == 0x3001    MOV.B @(disp12,Rm), R0  family
      (hw & 0xF00F) == 0x3009    BIT operation family
      (hw & 0xF0FF) == 0x00E5    MOVI20
      (hw & 0xF0FF) == 0x00E7    MOVI20S
    All other first halfwords → 16-bit SH-2 instruction.

Function prologue detection
---------------------------
SH-2A firmware uses the same prologue conventions as SH-2:

    STS.L PR, @-R15    =  0x4F22   (save procedure register to stack)

R15 is the stack pointer.  PR is the procedure register (equivalent of LR in ARM,
return address holder).  ``STS.L PR, @-R15`` at any even offset is the primary
function-start signal.

For leaf functions (no stack frame, no callee-save):

    STS PR, Rn    =  (hw & 0xF0FF) == 0x002A   (move PR to any register)

This appears as the first instruction of a leaf function that saves PR to a
register before making calls.

Return instruction:
    RTS    =  0x000B

Usage::

    from ablation.analyzers.ecu_sh2a_decoder import EcuSH2aDecoder

    dec = EcuSH2aDecoder(rom_bytes, base_va=0)
    insns = dec.disassemble(start=0x400, end=0x1000)
    starts = dec.function_starts()

All encodings sourced from Renesas SH2A / SH2 Hardware Manual Rev.2.00.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class SH2aInsn:
    """A decoded SH-2A instruction."""

    offset: int
    is_32bit: bool
    mnemonic: str
    insn_type: str
    raw: bytes
    target: Optional[int] = None
    rd: Optional[int] = None
    rs: Optional[int] = None
    imm: Optional[int] = None

    def __str__(self) -> str:
        width = "SH32" if self.is_32bit else "SH16"
        ops = []
        if self.rd is not None:
            ops.append(f"R{self.rd}")
        if self.rs is not None and self.rs != self.rd:
            ops.append(f"R{self.rs}")
        if self.imm is not None:
            ops.append(f"0x{self.imm:x}" if self.imm >= 0 else f"-0x{-self.imm:x}")
        op_str = ", ".join(ops) if ops else ""
        target_str = f"  -> 0x{self.target:08X}" if self.target is not None else ""
        return (
            f"0x{self.offset:08X}  [{width}]  "
            f"{self.mnemonic:<16} {op_str}{target_str}"
        )


class EcuSH2aDecoder:
    """
    Decode Renesas SH-2A instructions from a raw ROM buffer.

    Parameters
    ----------
    data
        Raw ROM bytes.  Accepts ``bytes``, ``str`` path, or ``Path``.
    base_va
        Virtual address of the first byte in ``data``.

    Notes
    -----
    ``from_path`` and ``from_bytes`` are convenience wrappers; all three
    constructors are equivalent.

    This decoder targets the SH-2A ISA (Renesas SH7058/SH7059).  The
    SH-2 and SH-2A base instruction sets are fully backward-compatible;
    SH-2A adds 32-bit instruction variants.
    """

    # Core prologue / return instruction halfwords
    _STS_L_PR_AT_MINUS_R15 = 0x4F22   # STS.L PR, @-R15 (push LR to stack)
    _LDS_L_AT_R15_PLUS_PR  = 0x4F26   # LDS.L @R15+, PR (pop LR from stack)
    _RTS                   = 0x000B   # RTS
    _NOP                   = 0x0009   # NOP (fills branch delay slot)
    _RTS_N                 = 0x0063   # RTS/N (SH2A: return + NOP delay slot)

    def __init__(self, data: "str | Path | bytes", base_va: int = 0):
        if isinstance(data, (str, Path)):
            try:
                self._data = open(data, "rb").read()
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"EcuSH2aDecoder: {data!r} not found"
                ) from exc
        else:
            self._data = bytes(data)
        self._base_va = base_va

    @classmethod
    def from_path(cls, path: "str | Path", base_va: int = 0) -> "EcuSH2aDecoder":
        """Convenience wrapper; equivalent to EcuSH2aDecoder(path, base_va)."""
        return cls(path, base_va)

    @classmethod
    def from_bytes(cls, data: bytes, base_va: int = 0) -> "EcuSH2aDecoder":
        """Convenience wrapper; equivalent to EcuSH2aDecoder(data, base_va)."""
        return cls(data, base_va)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def insn_length(self, offset: int) -> int:
        """Return 2 or 4 — the length of the instruction at ``offset``."""
        data = self._data
        n = len(data)
        if offset + 2 > n:
            return 0
        hw = struct.unpack_from(">H", data, offset)[0]
        return 4 if self._is_32bit(hw) else 2

    def decode_one(self, offset: int) -> Optional[SH2aInsn]:
        """Decode a single instruction at ``offset``.  Returns None at EOF."""
        data = self._data
        n = len(data)
        if offset + 2 > n:
            return None
        hw = struct.unpack_from(">H", data, offset)[0]
        if self._is_32bit(hw):
            if offset + 4 > n:
                return None
            lo = struct.unpack_from(">H", data, offset + 2)[0]
            return self._decode_32(offset, hw, lo)
        return self._decode_16(offset, hw)

    def disassemble(
        self, start: int = 0, end: Optional[int] = None
    ) -> list[SH2aInsn]:
        """
        Decode all instructions in the byte range ``[start, end)``.

        ``start`` and ``end`` are byte offsets within the data buffer.
        """
        if end is None:
            end = len(self._data)
        end = min(end, len(self._data))
        results: list[SH2aInsn] = []
        off = start
        while off < end:
            insn = self.decode_one(off)
            if insn is None:
                break
            results.append(insn)
            off += len(insn.raw)
        return results

    def function_starts(self) -> list[int]:
        """
        Return probable function-start VAs by scanning for SH-2A prologues.

        Two prologue forms are detected:

        *Stack-saving functions* — ``STS.L PR, @-R15`` (``0x4F22``): push the
        procedure register (return address) to the stack.  This is the primary
        prologue signal for any non-leaf function.

        *Register-saving leaf functions* — ``STS PR, Rn`` (``(hw & 0xF0FF) == 0x002A``):
        move PR to any general-purpose register.  Only accepted when the
        immediately preceding 2-byte instruction is not itself an ``STS.L PR``
        (which would mean this STS PR is the second instruction of a non-leaf
        function, not the start of a leaf).

        Returns virtual addresses (``base_va + offset``), sorted.
        """
        data = self._data
        n = len(data)
        starts: set[int] = set()

        for i in range(0, n - 1, 2):
            hw = struct.unpack_from(">H", data, i)[0]

            if hw == self._STS_L_PR_AT_MINUS_R15:
                starts.add(self._base_va + i)

            elif (hw & 0xF0FF) == 0x002A:
                # STS PR, Rn — leaf function start signal
                va = self._base_va + i
                if va not in starts:
                    if i >= 2:
                        prev_hw = struct.unpack_from(">H", data, i - 2)[0]
                        if prev_hw == self._STS_L_PR_AT_MINUS_R15:
                            continue
                    starts.add(va)

        return sorted(starts)

    # ------------------------------------------------------------------
    # 32-bit SH-2A instruction decoder
    # ------------------------------------------------------------------

    def _decode_32(self, offset: int, hw: int, lo: int) -> SH2aInsn:
        raw = struct.pack(">HH", hw, lo)
        va = self._base_va + offset

        # MOVI20: 0000 nnnn iiii 0101 + lo = imm20[15:0]
        # bits[11:8]=Rn, bits[7:4]=imm20[19:16] (varies), bits[3:0]=0101 fixed
        # Correct mask: (hw & 0xF00F) == 0x0005  — NOT 0xF0FF because imm_hi varies
        if (hw & 0xF00F) == 0x0005:
            rd = (hw >> 8) & 0xF
            imm_hi = (hw >> 4) & 0xF
            imm20_val = (imm_hi << 16) | lo
            imm_s = imm20_val if imm20_val < 0x80000 else imm20_val - 0x100000
            return SH2aInsn(
                offset=va, is_32bit=True, mnemonic="movi20", insn_type="MISC",
                raw=raw, rd=rd, imm=imm_s,
            )

        # MOVI20S: 0000 nnnn iiii 0111 + lo = imm20[15:0]  (shift-left-8 form)
        # bits[3:0]=0111 fixed; (hw & 0xF00F) == 0x0007
        if (hw & 0xF00F) == 0x0007:
            rd = (hw >> 8) & 0xF
            imm_hi = (hw >> 4) & 0xF
            imm20_val = (imm_hi << 16) | lo
            imm_s = imm20_val if imm20_val < 0x80000 else imm20_val - 0x100000
            return SH2aInsn(
                offset=va, is_32bit=True, mnemonic="movi20s", insn_type="MISC",
                raw=raw, rd=rd, imm=imm_s << 8,
            )

        # MOV family with 12-bit displacement: (hw & 0xF00F) == 0x3001
        # Format: 0011 nnnn/mmmm dddd | dddd dddd xxxx x???
        if (hw & 0xF00F) == 0x3001:
            rn_rm = (hw >> 8) & 0xF
            disp12_hi = (hw >> 4) & 0xF
            disp12_lo = (lo >> 8) & 0xFF
            disp12 = (disp12_hi << 8) | disp12_lo
            sub_op = lo & 0xFF
            _MOV12_OPS = {
                0x00: ("mov.b @(d12,Rm),R0", "LOAD"),
                0x10: ("mov.w @(d12,Rm),R0", "LOAD"),
                0x20: ("mov.l @(d12,Rm),R0", "LOAD"),
                0x30: ("mov.b R0,@(d12,Rn)", "STORE"),
                0x40: ("mov.w R0,@(d12,Rn)", "STORE"),
                0x50: ("mov.l R0,@(d12,Rn)", "STORE"),
            }
            mnem, itype = _MOV12_OPS.get(sub_op & 0xF0, (f"sh2a_32_{hw:04x}", "MISC"))
            return SH2aInsn(
                offset=va, is_32bit=True, mnemonic=mnem, insn_type=itype,
                raw=raw, imm=disp12,
            )

        # BIT operations: (hw & 0xF00F) == 0x3009
        if (hw & 0xF00F) == 0x3009:
            _BIT_OPS = {0x10: "bclr.b", 0x30: "bset.b", 0x50: "bstz.b",
                        0x70: "bst.b",  0x90: "bldz.b", 0xB0: "bld.b"}
            sub = (lo >> 4) & 0xF0
            mnem = _BIT_OPS.get(sub, f"sh2a_bit_{hw:04x}")
            return SH2aInsn(
                offset=va, is_32bit=True, mnemonic=mnem, insn_type="MISC",
                raw=raw,
            )

        # Generic 32-bit fallback
        return SH2aInsn(
            offset=va, is_32bit=True,
            mnemonic=f"sh2a32_{hw:04x}", insn_type="MISC",
            raw=raw,
        )

    # ------------------------------------------------------------------
    # 16-bit SH-2 instruction decoder
    # ------------------------------------------------------------------

    def _decode_16(self, offset: int, hw: int) -> SH2aInsn:
        raw = struct.pack(">H", hw)
        va = self._base_va + offset

        # Return instructions
        if hw == self._RTS:
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="rts", insn_type="RETURN", raw=raw,
            )
        if hw == self._RTS_N:
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="rts/n", insn_type="RETURN", raw=raw,
            )

        # STS.L PR, @-R15  (push LR to stack — primary prologue)
        if hw == self._STS_L_PR_AT_MINUS_R15:
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="sts.l", insn_type="LR_SAVE",
                raw=raw, rs=15,
            )

        # LDS.L @R15+, PR  (pop LR from stack — epilogue)
        if hw == self._LDS_L_AT_R15_PLUS_PR:
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="lds.l", insn_type="LR_RESTORE",
                raw=raw, rs=15,
            )

        # STS PR, Rn  —  0000 nnnn 0010 1010  (leaf prologue)
        if (hw & 0xF0FF) == 0x002A:
            rd = (hw >> 8) & 0xF
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="sts", insn_type="LR_SAVE",
                raw=raw, rd=rd,
            )

        # LDS Rn, PR  —  0100 nnnn 0010 1010  (restore PR from register)
        if (hw & 0xF0FF) == 0x402A:
            rs = (hw >> 8) & 0xF
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="lds", insn_type="LR_RESTORE",
                raw=raw, rs=rs,
            )

        # BSR disp12  —  1011 xxxx xxxx xxxx  (branch-and-link, short)
        if (hw & 0xF000) == 0xB000:
            disp12 = hw & 0xFFF
            disp_s = disp12 if disp12 < 0x800 else disp12 - 0x1000
            target = va + 4 + disp_s * 2
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="bsr", insn_type="CALL",
                raw=raw, target=target, imm=disp_s,
            )

        # JSR @Rn  —  0100 nnnn 0000 1011  (call through register)
        if (hw & 0xF0FF) == 0x400B:
            rs = (hw >> 8) & 0xF
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="jsr", insn_type="CALL",
                raw=raw, rs=rs,
            )

        # BRA disp12  —  1010 xxxx xxxx xxxx
        if (hw & 0xF000) == 0xA000:
            disp12 = hw & 0xFFF
            disp_s = disp12 if disp12 < 0x800 else disp12 - 0x1000
            target = va + 4 + disp_s * 2
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="bra", insn_type="BRANCH",
                raw=raw, target=target, imm=disp_s,
            )

        # Conditional branches Bcc  —  1000 xxxx xxxx xxxx  and  0000 xxxx (BRAF/BSRF)
        if (hw & 0xFF00) in (
            0x8900, 0x8B00,  # BT, BF
            0x8D00, 0x8F00,  # BT/S, BF/S
        ):
            disp8 = hw & 0xFF
            disp_s = disp8 if disp8 < 0x80 else disp8 - 0x100
            target = va + 4 + disp_s * 2
            _COND = {0x89: "bt", 0x8B: "bf", 0x8D: "bt/s", 0x8F: "bf/s"}
            mnem = _COND.get((hw >> 8) & 0xFF, "b?")
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic=mnem, insn_type="BRANCH",
                raw=raw, target=target, imm=disp_s,
            )

        # MOV.L @(disp4*4, PC), Rn  —  1101 nnnn dddd dddd  (PC-relative load)
        if (hw & 0xF000) == 0xD000:
            rd = (hw >> 8) & 0xF
            disp = hw & 0xFF
            pc_target = (va + 4 & ~3) + disp * 4
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="mov.l", insn_type="LOAD",
                raw=raw, rd=rd, imm=pc_target,
            )

        # MOV.W @(disp4*2, PC), Rn  —  1001 nnnn dddd dddd
        if (hw & 0xF000) == 0x9000:
            rd = (hw >> 8) & 0xF
            disp = hw & 0xFF
            pc_target = va + 4 + disp * 2
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="mov.w", insn_type="LOAD",
                raw=raw, rd=rd, imm=pc_target,
            )

        # MOVT Rn (move T flag)  —  0000 nnnn 0010 1001
        if (hw & 0xF0FF) == 0x0029:
            rd = (hw >> 8) & 0xF
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="movt", insn_type="MISC",
                raw=raw, rd=rd,
            )

        # PUSH: MOV.L Rm, @-R15  —  0010 1111 mmmm 0110  (push Rm to stack)
        # Encoding: nibble3=2, nibble2=F(R15), nibble1=Rm, nibble0=6
        # Mask 0xFF0F keeps nibble3+nibble2+nibble0; masks nibble1 (Rm)
        if (hw & 0xFF0F) == 0x2F06:  # MOV.L Rm, @-R15
            rs = (hw >> 4) & 0xF   # Rm is nibble1 (bits 7:4)
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="mov.l", insn_type="STORE",
                raw=raw, rs=rs,
            )

        # POP: MOV.L @R15+, Rn  —  0110 nnnn 1111 0110  (pop R15 to Rn)
        # Encoding: nibble3=6, nibble2=Rn, nibble1=F(R15), nibble0=6
        # Mask 0xF0FF keeps nibble3+nibble1+nibble0; masks nibble2 (Rn)
        # Expected after masking: 0x60F6 (nibble2=0, nibble1=F)
        if (hw & 0xF0FF) == 0x60F6:
            rd = (hw >> 8) & 0xF   # Rn is nibble2 (bits 11:8)
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="mov.l", insn_type="LOAD",
                raw=raw, rd=rd,
            )

        # NOP
        if hw == self._NOP:
            return SH2aInsn(
                offset=va, is_32bit=False, mnemonic="nop", insn_type="MISC", raw=raw,
            )

        # Generic 16-bit fallback
        nibble0 = (hw >> 12) & 0xF
        _GENERIC = {
            0x0: "misc0", 0x1: "mov_disp", 0x2: "mov_rm", 0x3: "arith",
            0x4: "shift", 0x5: "mov_disp_r",0x6: "mov_rn", 0x7: "add_imm",
            0x8: "cmp_mov", 0xC: "mov_r0gbr",0xE: "mov_imm", 0xF: "fpu",
        }
        tag = _GENERIC.get(nibble0, f"sh16_{hw:04x}")
        return SH2aInsn(
            offset=va, is_32bit=False, mnemonic=tag, insn_type="MISC", raw=raw,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_32bit(hw: int) -> bool:
        """Return True if this first halfword indicates a 32-bit SH-2A instruction.

        From Renesas SH2A Hardware Manual Rev.2.00:
          - MOV/BCLR/BSET etc. with 12-bit displacement: (hw & 0xF00F) == 0x3001
          - BIT manipulation with disp: (hw & 0xF00F) == 0x3009
          - MOVI20:  first halfword = 0000 nnnn iiii 0101 → bits[15:12]=0, bits[3:0]=5
            Mask: (hw & 0xF00F) == 0x0005
          - MOVI20S: first halfword = 0000 nnnn iiii 0111 → bits[15:12]=0, bits[3:0]=7
            Mask: (hw & 0xF00F) == 0x0007
          Note: bits[11:8]=Rn and bits[7:4]=imm[19:16] both vary, so 0xF0FF would
          incorrectly exclude instructions where Rn != 0 or imm_hi != 0xE.
        """
        return (
            (hw & 0xF00F) == 0x3001
            or (hw & 0xF00F) == 0x3009
            or (hw & 0xF00F) == 0x0005
            or (hw & 0xF00F) == 0x0007
        )
