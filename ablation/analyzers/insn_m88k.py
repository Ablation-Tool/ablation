"""Motorola MC88100 (M88000) instruction decoder.

All instructions are 32-bit big-endian fixed-width.  Decoding uses the
empirically validated opcode table from isa_m88k.py, derived from analysis
of the Lotus 1-2-3 moto_gen BCS COFF binary (1993).

Why this exists
---------------
1. Capstone 5.x has no M88K backend.
2. GNU binutils 88K support was removed circa 2020.
3. Radare2 has no m88k plugin.
4. The MC88100 was discontinued in 1997; no maintained disassembler survives.

This decoder provides:
  - ``M88kInsn`` dataclass (address, mnemonic, operands, branch_target)
  - ``M88kDecoder`` for decoding raw big-endian bytes
  - ``function_starts()`` — BSR-scan to locate all callable functions
  - ``string_refs()`` — ORU+OR pair scan to locate all data pointer loads

Usage::

    from ablation.core.coff_m88k_parser import parse
    from ablation.analyzers.insn_m88k import M88kDecoder

    binary = parse('/path/to/m88k.coff')
    dec = M88kDecoder(binary)

    for insn in dec.disassemble_va(binary.entry, max_insns=40):
        print(insn)

    funcs = dec.function_starts()
    for va in sorted(funcs):
        print(f'  func_{va:08x}')
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .isa_m88k import (
    BCND_CONDS,
    BCND_OPS,
    BRANCH_OPS,
    CTL_OP,
    CTL_SUB,
    IMM_OPS,
    LDST_OPS,
    TRIADIC_OPS,
    reg_name,
)

try:
    from ablation.core.coff_m88k_parser import M88kCoffBinary, Section
except ImportError:
    M88kCoffBinary = None  # type: ignore
    Section = None  # type: ignore


@dataclass
class M88kInsn:
    """A single decoded M88100 instruction."""

    address:       int
    mnemonic:      str
    op_str:        str
    raw:           int             # 32-bit big-endian word
    is_branch:     bool = False
    is_call:       bool = False
    is_return:     bool = False
    branch_target: Optional[int] = None

    def __str__(self) -> str:
        tgt = f"  -> {self.branch_target:#010x}" if self.branch_target else ""
        return f"{self.address:#010x}:  {self.raw:08x}  {self.mnemonic:<10} {self.op_str}{tgt}"


class M88kDecoder:
    """Decode MC88100 instructions from an M88kCoffBinary.

    All methods that walk the .text section assume big-endian byte order.
    The decoder does NOT perform CFG analysis; it provides linear sweeps
    and targeted disassembly windows.  Use analysis_m88k.py for CFG work.
    """

    def __init__(self, binary: "M88kCoffBinary") -> None:
        self._bin = binary
        text = binary.text
        if text is None:
            raise ValueError("binary has no .text section")
        self._text: "Section" = text

    # ------------------------------------------------------------------
    # Single instruction decode
    # ------------------------------------------------------------------

    def decode_word(self, word: int, va: int) -> M88kInsn:
        """Decode a single 32-bit instruction word at virtual address va."""
        op    = word >> 26
        rd    = (word >> 21) & 0x1F
        rs1   = (word >> 16) & 0x1F
        imm16 = word & 0xFFFF
        simm16 = imm16 if imm16 < 0x8000 else imm16 - 0x10000

        # ---- Immediate-form ops ----------------------------------------
        if op in IMM_OPS:
            mn = IMM_OPS[op]
            if op in (0x10, 0x1a, 0x1b):   # signed immediate
                op_s = f"r{rd}, r{rs1}, {simm16}"
            elif op in (0x1e, 0x1f):        # lda.h / lda.w
                op_s = f"r{rd}, r{rs1}[{imm16}]"
            else:
                op_s = f"r{rd}, r{rs1}, {imm16:#06x}"
            return M88kInsn(va, mn, op_s, word)

        # ---- Load / store ops -----------------------------------------
        if op in LDST_OPS:
            mn   = LDST_OPS[op]
            op_s = f"r{rd}, r{rs1}[{simm16}]"
            return M88kInsn(va, mn, op_s, word)

        # ---- Branch (26-bit PC-relative) --------------------------------
        if op in BRANCH_OPS:
            mn    = BRANCH_OPS[op]
            off26 = word & 0x3FFFFFF
            if off26 & (1 << 25):
                off26 -= (1 << 26)
            tgt = va + 4 + off26 * 4
            is_call   = mn in ("bsr", "bsr.n")
            is_branch = not is_call
            return M88kInsn(va, mn, f"{tgt:#010x}", word,
                            is_branch=is_branch, is_call=is_call,
                            branch_target=tgt)

        # ---- Conditional branch -----------------------------------------
        if op in BCND_OPS:
            mn      = BCND_OPS[op]
            cond5   = (word >> 21) & 0x1F
            rs      = (word >> 16) & 0x1F
            off16   = word & 0xFFFF
            if off16 & 0x8000:
                off16 -= 0x10000
            tgt     = va + 4 + off16 * 4
            cond_nm = BCND_CONDS.get(cond5, f"c{cond5:#04x}")
            op_s    = f"{cond_nm}, r{rs}, {tgt:#010x}"
            return M88kInsn(va, mn, op_s, word,
                            is_branch=True, branch_target=tgt)

        # ---- JMP / JSR / MOV (opcode 0x3D) ------------------------------
        if op == CTL_OP:
            bits15_14 = (word >> 14) & 3
            rs2 = word & 0x1F
            sub = CTL_SUB.get(bits15_14)
            if sub == "jmp":
                is_ret = (rs2 == 1)    # jmp r1 = return
                return M88kInsn(va, "jmp", f"r{rs2}", word,
                                is_branch=True, is_return=is_ret,
                                branch_target=None)
            if sub == "jsr":
                return M88kInsn(va, "jsr", f"r{rs2}", word,
                                is_call=True)
            # MOV rd, rs (or rd, r0, rs2)
            rs_top = (word >> 21) & 0x1F
            return M88kInsn(va, "mov", f"r{rs_top}, r{rs2}", word)

        # ---- Triadic integer unit ops (0x3A, 0x3B, 0x3C) ---------------
        if op in TRIADIC_OPS:
            rs2  = word & 0x1F
            func = (word >> 5) & 0x7F
            tag  = {0x3A: "cmp?", 0x3B: "arith", 0x3C: "tri"}[op]
            op_s = f"r{rd}, r{rs1}, r{rs2}  ; f={func:#04x}"
            return M88kInsn(va, tag, op_s, word)

        # ---- Unknown / unimplemented ------------------------------------
        return M88kInsn(va, f"???{op:02x}", f"[{word:#010x}]", word)

    # ------------------------------------------------------------------
    # Linear sweep disassembly
    # ------------------------------------------------------------------

    def disassemble_va(self, start_va: int, max_insns: int = 512) -> Iterator[M88kInsn]:
        """Linearly disassemble instructions starting at start_va."""
        sec = self._text
        if not sec.contains_va(start_va):
            return
        va = start_va
        count = 0
        while count < max_insns and sec.contains_va(va):
            word = sec.read_word(va)
            insn = self.decode_word(word, va)
            yield insn
            va += 4
            count += 1
            if insn.is_return:
                # M88K has no delay slots for JMP; stop the linear sweep here
                break

    def disassemble_bytes(self, data: bytes, base_va: int) -> Iterator[M88kInsn]:
        """Decode from raw bytes (big-endian) with given base VA."""
        n = len(data) // 4
        for i in range(n):
            word = struct.unpack_from(">I", data, i * 4)[0]
            yield self.decode_word(word, base_va + i * 4)

    # ------------------------------------------------------------------
    # Function and reference discovery
    # ------------------------------------------------------------------

    def function_starts(self) -> Set[int]:
        """Return the set of all BSR targets in .text (function entry VAs)."""
        targets: Set[int] = set()
        sec = self._text
        va  = sec.vaddr
        while sec.contains_va(va):
            word = sec.read_word(va)
            op   = word >> 26
            if op in (0x32, 0x33):   # BSR / BSR.N
                off26 = word & 0x3FFFFFF
                if off26 & (1 << 25):
                    off26 -= (1 << 26)
                tgt = va + 4 + off26 * 4
                if sec.contains_va(tgt):
                    targets.add(tgt)
            va += 4
        return targets

    def string_refs(self) -> Dict[int, int]:
        """Scan for ORU+OR pairs that load a 32-bit data pointer.

        Returns {code_va: data_va} for each ORU rd,r0,hi / OR rd,rd,lo pair.
        Only pairs where data_va falls in the .data section are included.
        """
        refs: Dict[int, int] = {}
        sec  = self._text
        dsec = self._bin.data
        if dsec is None:
            return refs
        va = sec.vaddr
        prev_word = 0
        prev_va   = 0
        while sec.contains_va(va):
            word = sec.read_word(va)
            op1  = prev_word >> 26
            op2  = word >> 26
            if op1 == 0x17 and op2 == 0x16:     # ORU then OR
                rd1 = (prev_word >> 21) & 0x1F
                s1  = (prev_word >> 16) & 0x1F
                rd2 = (word >> 21) & 0x1F
                rs2 = (word >> 16) & 0x1F
                if s1 == 0 and rd1 == rd2 and rd1 == rs2:
                    hi16 = prev_word & 0xFFFF
                    lo16 = word & 0xFFFF
                    data_va = (hi16 << 16) | lo16
                    if dsec.contains_va(data_va):
                        refs[prev_va] = data_va
            prev_word = word
            prev_va   = va
            va += 4
        return refs
