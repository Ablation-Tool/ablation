"""ISA and ABI model for the Motorola MC88100 (M88000) architecture.

The MC88100 was the first member of the M88000 RISC family (1988–1997).
All instructions are 32 bits, big-endian.  The BCS (Binary Compatibility
Standard) ABI governs Unix System V / Motorola 88Open systems.

Sources: MC88100 Programmer's Reference Manual (M88000PRM/AD); Motorola
88Open Binary Compatibility Standard (BCS) Rev. 1.1; empirical analysis
of Lotus 1-2-3 moto_gen binary (1993, 88K BCS COFF).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------

# r0  = zero (hardwired to 0)
# r1  = link register (return address on BSR/BSR.N)
# r2–r9  = argument / return value registers (caller-saved)
# r10–r13 = additional return / scratch (caller-saved)
# r14–r25 = callee-saved (must be restored before RET)
# r26–r29 = caller-saved temporaries
# r30 = frame pointer (callee-saved; used as FP by compilers)
# r31 = stack pointer (call decrements, return increments)

ZERO_REG  = "r0"
LINK_REG  = "r1"
SP_REG    = "r31"
FP_REG    = "r30"

ARG_REGS:  Tuple[str, ...] = tuple(f"r{i}" for i in range(2, 10))
RET_REGS:  Tuple[str, ...] = tuple(f"r{i}" for i in range(10, 14))
CALLEE_SAVED: FrozenSet[str] = frozenset(f"r{i}" for i in range(14, 31))

# All 32 general-purpose register names.
REG_NAMES: Tuple[str, ...] = tuple(f"r{i}" for i in range(32))


def reg_name(n: int) -> str:
    """Return canonical name for register number 0–31."""
    if not 0 <= n <= 31:
        raise ValueError(f"invalid M88k register number: {n}")
    return f"r{n}"


def is_callee_saved(reg: str) -> bool:
    return reg in CALLEE_SAVED or reg in (FP_REG, SP_REG)


# ---------------------------------------------------------------------------
# Opcode tables — empirically validated from moto_gen disassembly
# ---------------------------------------------------------------------------

# Immediate-form opcodes (bits 31:26): rd, rs1, imm16
IMM_OPS: Dict[int, str] = {
    0x10: "addu",    # rd = rs1 + sign_ext(imm16), unsigned (no overflow trap)
    0x11: "subu",    # rd = rs1 - imm16, unsigned
    0x12: "divu",    # rd = rs1 / imm16, unsigned
    0x13: "mulu",    # rd = rs1 * imm16, unsigned
    0x14: "and",     # rd = rs1 & imm16  (zero-extends imm16)
    0x15: "and.u",   # rd = rs1 & (imm16 << 16)
    0x16: "or",      # rd = rs1 | imm16  (zero-extends imm16)
    0x17: "or.u",    # rd = rs1 | (imm16 << 16)   ← canonical "load upper"
    0x18: "xor",     # rd = rs1 ^ imm16
    0x19: "xor.u",   # rd = rs1 ^ (imm16 << 16)
    0x1a: "add",     # rd = rs1 + sign_ext(imm16), signed (trap on overflow)
    0x1b: "sub",     # rd = rs1 - sign_ext(imm16), signed
    0x1c: "add",     # signed add alias (varies by compiler)
    0x1e: "lda.h",   # rd = rs1 + imm16*2  (half-word scaled address)
    0x1f: "lda.w",   # rd = rs1 + imm16*4  (word scaled address)
}

# Load/store opcodes (bits 31:26): rd/src, base, imm16_offset
LDST_OPS: Dict[int, str] = {
    0x00: "xmem",    # exchange memory word
    0x01: "xmem.bu", # exchange memory byte unsigned
    0x02: "ld.hu",   # load halfword unsigned (signed-displacement form)
    0x03: "ld.hu",
    0x04: "ld.b",    # load byte signed
    0x05: "ld.bu",   # load byte unsigned
    0x06: "ld.h",    # load halfword signed
    0x07: "ld.hu",   # load halfword unsigned
    0x08: "ld",      # load word
    0x09: "ld.d",    # load doubleword (rd:rd+1)
    0x0a: "st.d",    # store doubleword
    0x0b: "st",      # store word
    0x0c: "ld",
    0x0d: "ld.b",
    0x0e: "st.b",    # store byte
    0x0f: "st.h",    # store halfword
    # Scaled/indexed variants (base + rs2*scale)
    0x20: "ld",
    0x21: "ld.b",
    0x22: "ld.h",
    0x23: "ld.hu",
    0x24: "st",
    0x26: "st.b",
    0x27: "st.h",
    0x28: "ld",
    0x2a: "ld.b",
    0x2b: "ld.bu",
    0x2c: "st",
    0x2e: "st.b",
    0x2f: "st.h",
    # Immediate-displacement stores (confirmed from moto_gen analysis)
    0x34: "st.b",    # store byte, imm16 offset
    0x36: "st.h",    # store halfword, imm16 offset (confirmed: used for output key)
    0x38: "ld",
}

# Branch opcodes (bits 31:26): use 26-bit PC-relative offset × 4
BRANCH_OPS: Dict[int, str] = {
    0x30: "br",      # unconditional branch (absolute)
    0x31: "br.n",    # branch with nullify (delay-slot-like: next insn executes)
    0x32: "bsr",     # branch subroutine (saves PC+4 in r1)
    0x33: "bsr.n",   # branch subroutine with nullify
}

# Conditional branch (bits 31:26 = 0x25/0x29/0x2d):
#   bits 25:21 = condition code (5-bit mask matching MC88100 condition bits)
#   bits 20:16 = rs (register compared)
#   bits 15:0  = 16-bit signed PC-relative offset (in words, × 4)
BCND_OPS: Dict[int, str] = {
    0x25: "bcnd",
    0x29: "bcnd",
    0x2d: "bcnd.n",
}

# Condition code meanings for BCND (bits 25:21)
BCND_CONDS: Dict[int, str] = {
    0x01: "eq0",   # rs == 0
    0x02: "ne0",   # rs != 0
    0x04: "gt0",   # rs > 0
    0x05: "ge0",   # rs >= 0  (eq0 OR gt0)
    0x06: "lt0",   # rs < 0   (or signed bit set)
    0x09: "ne0",   # alias
    0x0a: "ne0",   # alias
    0x0b: "ne0",   # alias
    0x0d: "ne0",   # alias
    0x0e: "ne0",   # alias
    0x0f: "ne0",   # alias
}

# ---------------------------------------------------------------------------
# Triadic register-to-register unit (opcode 0x3D = JMP/JSR/MOV class)
#   bits 25:21 = rd (destination)
#   bits 20:16 = rs1 (source 1, r0 for MOV)
#   bits 15:14 sub-class:
#     11 = JMP rs2    (register indirect jump)
#     10 = JSR rs2    (register indirect call, saves r1)
#     01/00 = MOV rd, rs2  (via "or rd, r0, rs2")
#   bits 4:0 = rs2
# ---------------------------------------------------------------------------
CTL_OP = 0x3D

CTL_SUB: Dict[int, str] = {
    3: "jmp",   # bits 15:14 = 11
    2: "jsr",   # bits 15:14 = 10
}

# ---------------------------------------------------------------------------
# Triadic integer unit ops (opcode 0x3A, 0x3B, 0x3C)
#   bits 10:5 = function code
#   bits 4:0  = rs2
# Partially decoded; key mnemonics from moto_gen analysis.
# ---------------------------------------------------------------------------

# opcode 0x3C with f=0x48 observed as identity-like op (possibly OR rd,rs1,r0)
TRIADIC_OPS = {0x3A, 0x3B, 0x3C}
