"""ISA and ABI model for LoongArch64 (LA64) — lp64 calling convention.

LoongArch is a 64-bit RISC ISA designed by Loongson Technology, first shipped
in the Loongson 3A5000 (2021). TencentOS 4.6 targets Loongson 3A5000/3C5000
(server-class) and 3C6000 (HPC). All instructions are fixed 32-bit LE.

lp64 ABI register roles (from Loongson ABI spec v2.01 and GCC loongarch.h):

  $zero ($r0)   hardwired zero
  $ra   ($r1)   return address; caller saves, callee restores
  $tp   ($r2)   thread pointer; OS-managed, never touched by normal code
  $sp   ($r3)   stack pointer; 16-byte aligned at call boundaries
  $a0   ($r4)   argument 0 / return value 0
  $a1   ($r5)   argument 1 / return value 1
  $a2–$a7 ($r6–$r11)   arguments 2–7
  $t0–$t8 ($r12–$r20)  caller-saved temporaries
  $r21          platform-reserved (must not be touched by application code)
  $fp   ($r22)  frame pointer (callee-saved, optional)
  $s0–$s8 ($r23–$r31) callee-saved

Float lp64:
  $fa0–$fa7   float argument/return registers
  $ft0–$ft15  float caller-saved
  $fs0–$fs7   float callee-saved

Stack discipline:
  - Stack grows downward.
  - Prologue: addi.d $sp,$sp,-N  [st.d $ra,$sp,off]  [st.d $fp,$sp,off]
  - Epilogue: [ld.d $ra,$sp,off] [ld.d $fp,$sp,off]  addi.d $sp,$sp,N
              jirl $zero,$ra,0   ; ret

Sources: Loongson ABI spec v2.01, binutils LoongArch port, GCC loongarch-protos.h,
         TencentOS 4.6 corpus at /media/cowboy/research/TencentOS/
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple

XLEN    = 64
MASK64  = (1 << 64) - 1
ABS_BASE = "abs"

# ---------------------------------------------------------------------------
# Register model
# ---------------------------------------------------------------------------

# Canonical lp64 names indexed by register number
_CANON: Tuple[str, ...] = (
    "$zero", "$ra",  "$tp",  "$sp",  "$a0",  "$a1",  "$a2",  "$a3",
    "$a4",   "$a5",  "$a6",  "$a7",  "$t0",  "$t1",  "$t2",  "$t3",
    "$t4",   "$t5",  "$t6",  "$t7",  "$t8",  "$r21", "$fp",  "$s0",
    "$s1",   "$s2",  "$s3",  "$s4",  "$s5",  "$s6",  "$s7",  "$s8",
)

# Alternate spellings the assembler / objdump may emit
_ALIASES = {
    "$r0":  "$zero", "$r1": "$ra",  "$r2": "$tp",  "$r3": "$sp",
    "$r4":  "$a0",   "$r5": "$a1",  "$r6": "$a2",  "$r7": "$a3",
    "$r8":  "$a4",   "$r9": "$a5",  "$r10":"$a6",  "$r11":"$a7",
    "$r12": "$t0",   "$r13":"$t1",  "$r14":"$t2",  "$r15":"$t3",
    "$r16": "$t4",   "$r17":"$t5",  "$r18":"$t6",  "$r19":"$t7",
    "$r20": "$t8",   "$r22":"$fp",  "$r23":"$s0",  "$r24":"$s1",
    "$r25": "$s2",   "$r26":"$s3",  "$r27":"$s4",  "$r28":"$s5",
    "$r29": "$s6",   "$r30":"$s7",  "$r31":"$s8",
}

ALL_REGS: FrozenSet[str] = frozenset(_CANON) | frozenset(_ALIASES)
GPR_NAMES: FrozenSet[str] = frozenset(_CANON)


def canon_reg(name: str) -> Optional[str]:
    """Return the canonical lp64 name for any LoongArch GPR spelling."""
    n = name.strip()
    if n in _ALIASES:
        return _ALIASES[n]
    if n in GPR_NAMES:
        return n
    return None


def reg_num(canon: str) -> int:
    return _CANON.index(canon)


def reg_by_num(n: int) -> str:
    return _CANON[n & 0x1f]


# ---------------------------------------------------------------------------
# ABI register classes
# ---------------------------------------------------------------------------

ZERO_REG  = "$zero"
RA_REG    = "$ra"
SP_REG    = "$sp"
FP_REG    = "$fp"
TP_REG    = "$tp"

ARG_REGS: Tuple[str, ...] = (
    "$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7",
)
RET_REGS: Tuple[str, ...] = ("$a0", "$a1")
FLOAT_ARG_REGS: Tuple[str, ...] = (
    "$fa0", "$fa1", "$fa2", "$fa3", "$fa4", "$fa5", "$fa6", "$fa7",
)

# Caller-saved (volatile across a call): $ra, $t0-$t8, $a0-$a7
CALLER_SAVED: FrozenSet[str] = frozenset([
    "$ra",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8",
    "$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7",
])

# Callee-saved (must be preserved by the callee): $fp, $s0-$s8
CALLEE_SAVED: FrozenSet[str] = frozenset([
    "$fp",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$s8",
])

# Never meaningful as a taint source or destination
NEVER_TOUCHED: FrozenSet[str] = frozenset(["$zero", "$tp", "$r21"])


# ---------------------------------------------------------------------------
# Instruction classification sets
# (Used by the taint engine; CF flags come from LoongArchFrame directly)
# ---------------------------------------------------------------------------

# Direct call — bl only (jirl is classified at runtime in the decoder)
CALL_MNEMS: FrozenSet[str] = frozenset({"bl"})

# Unconditional direct branch
JUMP_MNEMS: FrozenSet[str] = frozenset({"b"})

# Conditional branches (rj [,rd], offset)
COND_BRANCH_MNEMS: FrozenSet[str] = frozenset({
    "beqz", "bnez",
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "bceqz", "bcnez",
})

# Integer load instructions: (rd, rj, simm) or (rd, rj, rk) — rd is the dest
LOAD_MNEMS: FrozenSet[str] = frozenset({
    "ld.b",  "ld.h",  "ld.w",  "ld.d",
    "ld.bu", "ld.hu", "ld.wu",
    "ldx.b", "ldx.h", "ldx.w", "ldx.d",
    "ldx.bu","ldx.hu","ldx.wu",
    "ldptr.w","ldptr.d",
    "ll.w",  "ll.d",
    "ldgt.b","ldgt.h","ldgt.w","ldgt.d",
    "ldle.b","ldle.h","ldle.w","ldle.d",
})

# Integer store instructions: (rd, rj, simm) or (rd, rj, rk) — rd is the src
STORE_MNEMS: FrozenSet[str] = frozenset({
    "st.b",  "st.h",  "st.w",  "st.d",
    "stx.b", "stx.h", "stx.w", "stx.d",
    "stptr.w","stptr.d",
    "sc.w",  "sc.d",
    "stgt.b","stgt.h","stgt.w","stgt.d",
    "stle.b","stle.h","stle.w","stle.d",
})

# Atomic RMW: rd=old_value, rj=address, rk=new_value
ATOMIC_MNEMS: FrozenSet[str] = frozenset({
    "amswap.w",  "amswap.d",
    "amadd.w",   "amadd.d",
    "amand.w",   "amand.d",
    "amor.w",    "amor.d",
    "amxor.w",   "amxor.d",
    "ammax.w",   "ammax.d",   "ammax.wu",  "ammax.du",
    "ammin.w",   "ammin.d",   "ammin.wu",  "ammin.du",
    "amswap_db.w","amswap_db.d",
    "amadd_db.w","amadd_db.d",
    "amand_db.w","amand_db.d",
    "amor_db.w", "amor_db.d",
    "amxor_db.w","amxor_db.d",
    "ammax_db.w","ammax_db.d","ammax_db.wu","ammax_db.du",
    "ammin_db.w","ammin_db.d","ammin_db.wu","ammin_db.du",
})

# ALU 3-register: rd = rj op rk
ALU3_MNEMS: FrozenSet[str] = frozenset({
    "add.w",  "add.d",  "sub.w",  "sub.d",
    "slt",    "sltu",
    "maskeqz","masknez",
    "nor",    "and",    "or",     "xor",    "orn",    "andn",
    "sll.w",  "srl.w",  "sra.w",
    "sll.d",  "srl.d",  "sra.d",
    "rotr.w", "rotr.d",
    "mul.w",  "mulh.w", "mulh.wu","mul.d",  "mulh.d", "mulh.du",
    "mulw.d.w","mulw.d.wu",
    "div.w",  "mod.w",  "div.wu", "mod.wu",
    "div.d",  "mod.d",  "div.du", "mod.du",
    "alsl.w", "alsl.wu","alsl.d",
    "bytepick.w","bytepick.d",
    "crc.w.b.w","crc.w.h.w","crc.w.w.w","crc.w.d.w",
    "crcc.w.b.w","crcc.w.h.w","crcc.w.w.w","crcc.w.d.w",
})

# ALU register-immediate: rd = rj op imm
ALUI_MNEMS: FrozenSet[str] = frozenset({
    "addi.w",  "addi.d",
    "slti",    "sltui",
    "andi",    "ori",    "xori",
    "slli.w",  "srli.w", "srai.w",
    "slli.d",  "srli.d", "srai.d",
    "rotri.w", "rotri.d",
    "lu52i.d", "addu16i.d",
    "bstrins.w","bstrpick.w","bstrins.d","bstrpick.d",
})

# Load large immediate into rd (no rj input)
IMM_MNEMS: FrozenSet[str] = frozenset({
    "lu12i.w", "lu32i.d",
    "pcaddi",  "pcalau12i","pcaddu12i","pcaddu18i",
})

# 1-register ops: rd = f(rj)
UNARY_MNEMS: FrozenSet[str] = frozenset({
    "clo.w",  "clz.w",  "cto.w",  "ctz.w",
    "clo.d",  "clz.d",  "cto.d",  "ctz.d",
    "revb.2h","revb.4h","revb.2w","revb.d",
    "revh.2w","revh.d",
    "bitrev.4b","bitrev.8b","bitrev.w","bitrev.d",
    "ext.w.h","ext.w.b",
})

# System / barrier / no-taint-propagation
BARRIER_MNEMS: FrozenSet[str] = frozenset({
    "dbar", "ibar", "syscall", "break", "dbcl",
    "ertn", "idle",
    "tlbclr","tlbflush","tlbsrch","tlbrd","tlbwr","tlbfill","invtlb",
    "cacop", "preld", "preldx",
})

# Bound produced by andi when imm is a mask (e.g. 0xff, 0xffff)
def andi_bound(imm: int) -> Optional[int]:
    """Return the value bound implied by ``andi rd, rj, imm``, or None."""
    if imm > 0 and (imm & (imm + 1)) == 0:
        return imm
    return None
