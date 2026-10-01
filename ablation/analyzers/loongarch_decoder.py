"""
loongarch_decoder.py: LoongArch64 fixed-width instruction frame decoder.

LoongArch (LA64) is a 64-bit RISC ISA developed by Loongson Technology.
All instructions are fixed 32-bit little-endian words — no variable-length
decode path. The ISA uses a clean match/mask table model derived from binutils
opcodes/loongarch-opc.c (binutils 2.41, the version shipped in TencentOS 4.6).

Register file (lp64 ABI names):
  $zero ($r0)   zero register
  $ra   ($r1)   return address (link register)
  $tp   ($r2)   thread pointer
  $sp   ($r3)   stack pointer
  $a0–$a7       argument/return registers ($r4–$r11)
  $t0–$t8       caller-saved temporaries ($r12–$r20)
  $r21          reserved (platform-specific, not named in lp64)
  $fp   ($r22)  frame pointer (callee-saved)
  $s0–$s8       callee-saved ($r23–$r31)

ABI function call convention (lp64):
  Arguments:    $a0–$a7 (int/ptr), $fa0–$fa7 (float/double)
  Return:       $a0/$a1 (int), $fa0/$fa1 (float)
  Caller-saved: $ra, $t0–$t8, $a0–$a7, $fa0–$fa15
  Callee-saved: $fp, $s0–$s8, $fs0–$fs7

Prologue pattern (GCC/Clang lp64):
  addi.d   $sp, $sp, -N          ; allocate stack frame
  st.d     $ra, $sp, N-8         ; save return address
  st.d     $fp, $sp, N-16        ; save frame pointer (if used)
  addi.d   $fp, $sp, N           ; set up frame pointer (if used)

Return pattern:
  ld.d     $ra, $sp, N-8         ; restore return address
  addi.d   $sp, $sp, N           ; restore stack pointer
  jirl     $zero, $ra, 0         ; return (also written "ret" by assembler)

Control-flow instruction encoding:
  b    offs26  : 0x50000000 / 0xfc000000   unconditional direct branch
  bl   offs26  : 0x54000000 / 0xfc000000   direct call (branch-and-link to $ra)
  jirl rd,rj,si16<<2 : 0x4c000000/0xfc000000
       rd=$zero, rj=$ra, imm=0  →  ret
       rd=$ra,   rj=any, imm=0  →  indirect call
       rd=$zero, rj=any         →  indirect branch
  beqz rj, offs21    : 0x40000000 / 0xfc000000
  bnez rj, offs21    : 0x44000000 / 0xfc000000
  beq  rj,rd, offs16 : 0x58000000 / 0xfc000000
  bne  rj,rd, offs16 : 0x5c000000 / 0xfc000000
  blt  rj,rd, offs16 : 0x60000000 / 0xfc000000
  bge  rj,rd, offs16 : 0x64000000 / 0xfc000000
  bltu rj,rd, offs16 : 0x68000000 / 0xfc000000
  bgeu rj,rd, offs16 : 0x6c000000 / 0xfc000000
  bceqz cc, offs21   : 0x48000000 / 0xfc000300
  bcnez cc, offs21   : 0x48000100 / 0xfc000300

Instruction encoding source:
  binutils 2.41 opcodes/loongarch-opc.c (TencentOS 4.6 corpus)
  /media/cowboy/research/TencentOS/LoongArch-RE/Source/binutils-2.41-24.tl4.src.rpm

Capstone note:
  Capstone 5.x has no CS_ARCH_LOONGARCH64. This module provides a pure-Python
  decoder following the same pattern as arc_decoder.py and v850_decoder.py.

Usage:
    from ablation.analyzers.loongarch_decoder import LoongArchDecoder

    dec = LoongArchDecoder()
    for frame in dec.decode_frames(elf_section_bytes, base_addr=0x400000):
        if frame.is_call:
            print(f'call @ {frame.va:#x} -> {frame.target:#x}')
        if frame.is_ret:
            print(f'ret  @ {frame.va:#x}')
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Register name tables  (source: loongarch-opc.c loongarch_r_lp64_name)
# ---------------------------------------------------------------------------

_R_LP64: Tuple[str, ...] = (
    "$zero", "$ra",  "$tp",  "$sp",  "$a0",  "$a1",  "$a2",  "$a3",
    "$a4",   "$a5",  "$a6",  "$a7",  "$t0",  "$t1",  "$t2",  "$t3",
    "$t4",   "$t5",  "$t6",  "$t7",  "$t8",  "$r21", "$fp",  "$s0",
    "$s1",   "$s2",  "$s3",  "$s4",  "$s5",  "$s6",  "$s7",  "$s8",
)

_F_LP64: Tuple[str, ...] = (
    "$fa0",  "$fa1",  "$fa2",  "$fa3",  "$fa4",  "$fa5",  "$fa6",  "$fa7",
    "$ft0",  "$ft1",  "$ft2",  "$ft3",  "$ft4",  "$ft5",  "$ft6",  "$ft7",
    "$ft8",  "$ft9",  "$ft10", "$ft11", "$ft12", "$ft13", "$ft14", "$ft15",
    "$fs0",  "$fs1",  "$fs2",  "$fs3",  "$fs4",  "$fs5",  "$fs6",  "$fs7",
)

# Condition flag registers $fcc0–$fcc7
_C_NAMES: Tuple[str, ...] = (
    "$fcc0", "$fcc1", "$fcc2", "$fcc3", "$fcc4", "$fcc5", "$fcc6", "$fcc7",
)

# Float CSR ($fcsr0–$fcsr3)
_FC_NAMES: Tuple[str, ...] = ("$fcsr0", "$fcsr1", "$fcsr2", "$fcsr3")

# Scratch/control register aliases ($scr0–$scr3)
_CR_NAMES: Tuple[str, ...] = ("$scr0", "$scr1", "$scr2", "$scr3")

# LSX vector registers $vr0–$vr31
_V_NAMES: Tuple[str, ...] = tuple(f"$vr{i}" for i in range(32))

# LASX vector registers $xr0–$xr31
_X_NAMES: Tuple[str, ...] = tuple(f"$xr{i}" for i in range(32))

# Frequently-referenced register indices
_REG_ZERO = 0   # $zero
_REG_RA   = 1   # $ra  (return address / link register)
_REG_SP   = 3   # $sp


# ---------------------------------------------------------------------------
# Frame record
# ---------------------------------------------------------------------------

@dataclass
class LoongArchFrame:
    """Single decoded LoongArch64 instruction."""
    va:        int
    width:     int = 4        # always 4 bytes (fixed-width ISA)
    insn:      int = 0        # raw 32-bit word (little-endian)
    mnemonic:  str = ""
    op_str:    str = ""
    is_branch: bool = False
    is_call:   bool = False
    is_ret:    bool = False
    target:    int  = 0       # resolved PC-relative target VA (0 = indirect/unknown)

    def __str__(self) -> str:
        tgt = f" -> {self.target:#x}" if self.target else ""
        tag = " CALL" if self.is_call else (" RET" if self.is_ret else
              (" BRANCH" if self.is_branch else ""))
        return (f"{self.va:#010x}  {self.insn:08x}  "
                f"{self.mnemonic:<12} {self.op_str}{tgt}{tag}")


# ---------------------------------------------------------------------------
# Opcode table
# Derived from binutils 2.41 opcodes/loongarch-opc.c.
# Format: (match, mask, name, format)
# Entries with mask==0 are assembler macros and are excluded.
# LSX (loongarch_lsx_opcodes) and LASX (loongarch_lasx_opcodes) are
# deferred to a future step; unknown encodings in those ranges decode
# as .word directives.
# ---------------------------------------------------------------------------

_OPCODES: List[Tuple[int, int, str, str]] = [

    # -----------------------------------------------------------------------
    # fix_opcodes: integer ALU (2R, 3R, 2RI5, 2RI6, 2RI12, 2RI20, 4R)
    # -----------------------------------------------------------------------
    (0x00001000, 0xfffffc00, "clo.w",       "r0:5,r5:5"),
    (0x00001400, 0xfffffc00, "clz.w",       "r0:5,r5:5"),
    (0x00001800, 0xfffffc00, "cto.w",       "r0:5,r5:5"),
    (0x00001c00, 0xfffffc00, "ctz.w",       "r0:5,r5:5"),
    (0x00002000, 0xfffffc00, "clo.d",       "r0:5,r5:5"),
    (0x00002400, 0xfffffc00, "clz.d",       "r0:5,r5:5"),
    (0x00002800, 0xfffffc00, "cto.d",       "r0:5,r5:5"),
    (0x00002c00, 0xfffffc00, "ctz.d",       "r0:5,r5:5"),
    (0x00003000, 0xfffffc00, "revb.2h",     "r0:5,r5:5"),
    (0x00003400, 0xfffffc00, "revb.4h",     "r0:5,r5:5"),
    (0x00003800, 0xfffffc00, "revb.2w",     "r0:5,r5:5"),
    (0x00003c00, 0xfffffc00, "revb.d",      "r0:5,r5:5"),
    (0x00004000, 0xfffffc00, "revh.2w",     "r0:5,r5:5"),
    (0x00004400, 0xfffffc00, "revh.d",      "r0:5,r5:5"),
    (0x00004800, 0xfffffc00, "bitrev.4b",   "r0:5,r5:5"),
    (0x00004c00, 0xfffffc00, "bitrev.8b",   "r0:5,r5:5"),
    (0x00005000, 0xfffffc00, "bitrev.w",    "r0:5,r5:5"),
    (0x00005400, 0xfffffc00, "bitrev.d",    "r0:5,r5:5"),
    (0x00005800, 0xfffffc00, "ext.w.h",     "r0:5,r5:5"),
    (0x00005c00, 0xfffffc00, "ext.w.b",     "r0:5,r5:5"),
    (0x00006000, 0xfffffc00, "rdtimel.w",   "r0:5,r5:5"),
    (0x00006400, 0xfffffc00, "rdtimeh.w",   "r0:5,r5:5"),
    (0x00006800, 0xfffffc00, "rdtime.d",    "r0:5,r5:5"),
    (0x00006c00, 0xfffffc00, "cpucfg",      "r0:5,r5:5"),
    (0x00010000, 0xffff801f, "asrtle.d",    "r5:5,r10:5"),
    (0x00018000, 0xffff801f, "asrtgt.d",    "r5:5,r10:5"),
    (0x00040000, 0xfffe0000, "alsl.w",      "r0:5,r5:5,r10:5,u15:2+1"),
    (0x00060000, 0xfffe0000, "alsl.wu",     "r0:5,r5:5,r10:5,u15:2+1"),
    (0x00080000, 0xfffe0000, "bytepick.w",  "r0:5,r5:5,r10:5,u15:2"),
    (0x000c0000, 0xfffc0000, "bytepick.d",  "r0:5,r5:5,r10:5,u15:3"),
    (0x00100000, 0xffff8000, "add.w",       "r0:5,r5:5,r10:5"),
    (0x00108000, 0xffff8000, "add.d",       "r0:5,r5:5,r10:5"),
    (0x00110000, 0xffff8000, "sub.w",       "r0:5,r5:5,r10:5"),
    (0x00118000, 0xffff8000, "sub.d",       "r0:5,r5:5,r10:5"),
    (0x00120000, 0xffff8000, "slt",         "r0:5,r5:5,r10:5"),
    (0x00128000, 0xffff8000, "sltu",        "r0:5,r5:5,r10:5"),
    (0x00130000, 0xffff8000, "maskeqz",     "r0:5,r5:5,r10:5"),
    (0x00138000, 0xffff8000, "masknez",     "r0:5,r5:5,r10:5"),
    (0x00140000, 0xffff8000, "nor",         "r0:5,r5:5,r10:5"),
    (0x00148000, 0xffff8000, "and",         "r0:5,r5:5,r10:5"),
    (0x00150000, 0xffff8000, "or",          "r0:5,r5:5,r10:5"),
    (0x00158000, 0xffff8000, "xor",         "r0:5,r5:5,r10:5"),
    (0x00160000, 0xffff8000, "orn",         "r0:5,r5:5,r10:5"),
    (0x00168000, 0xffff8000, "andn",        "r0:5,r5:5,r10:5"),
    (0x00170000, 0xffff8000, "sll.w",       "r0:5,r5:5,r10:5"),
    (0x00178000, 0xffff8000, "srl.w",       "r0:5,r5:5,r10:5"),
    (0x00180000, 0xffff8000, "sra.w",       "r0:5,r5:5,r10:5"),
    (0x00188000, 0xffff8000, "sll.d",       "r0:5,r5:5,r10:5"),
    (0x00190000, 0xffff8000, "srl.d",       "r0:5,r5:5,r10:5"),
    (0x00198000, 0xffff8000, "sra.d",       "r0:5,r5:5,r10:5"),
    (0x001b0000, 0xffff8000, "rotr.w",      "r0:5,r5:5,r10:5"),
    (0x001b8000, 0xffff8000, "rotr.d",      "r0:5,r5:5,r10:5"),
    (0x001c0000, 0xffff8000, "mul.w",       "r0:5,r5:5,r10:5"),
    (0x001c8000, 0xffff8000, "mulh.w",      "r0:5,r5:5,r10:5"),
    (0x001d0000, 0xffff8000, "mulh.wu",     "r0:5,r5:5,r10:5"),
    (0x001d8000, 0xffff8000, "mul.d",       "r0:5,r5:5,r10:5"),
    (0x001e0000, 0xffff8000, "mulh.d",      "r0:5,r5:5,r10:5"),
    (0x001e8000, 0xffff8000, "mulh.du",     "r0:5,r5:5,r10:5"),
    (0x001f0000, 0xffff8000, "mulw.d.w",    "r0:5,r5:5,r10:5"),
    (0x001f8000, 0xffff8000, "mulw.d.wu",   "r0:5,r5:5,r10:5"),
    (0x00200000, 0xffff8000, "div.w",       "r0:5,r5:5,r10:5"),
    (0x00208000, 0xffff8000, "mod.w",       "r0:5,r5:5,r10:5"),
    (0x00210000, 0xffff8000, "div.wu",      "r0:5,r5:5,r10:5"),
    (0x00218000, 0xffff8000, "mod.wu",      "r0:5,r5:5,r10:5"),
    (0x00220000, 0xffff8000, "div.d",       "r0:5,r5:5,r10:5"),
    (0x00228000, 0xffff8000, "mod.d",       "r0:5,r5:5,r10:5"),
    (0x00230000, 0xffff8000, "div.du",      "r0:5,r5:5,r10:5"),
    (0x00238000, 0xffff8000, "mod.du",      "r0:5,r5:5,r10:5"),
    (0x00240000, 0xffff8000, "crc.w.b.w",   "r0:5,r5:5,r10:5"),
    (0x00248000, 0xffff8000, "crc.w.h.w",   "r0:5,r5:5,r10:5"),
    (0x00250000, 0xffff8000, "crc.w.w.w",   "r0:5,r5:5,r10:5"),
    (0x00258000, 0xffff8000, "crc.w.d.w",   "r0:5,r5:5,r10:5"),
    (0x00260000, 0xffff8000, "crcc.w.b.w",  "r0:5,r5:5,r10:5"),
    (0x00268000, 0xffff8000, "crcc.w.h.w",  "r0:5,r5:5,r10:5"),
    (0x00270000, 0xffff8000, "crcc.w.w.w",  "r0:5,r5:5,r10:5"),
    (0x00278000, 0xffff8000, "crcc.w.d.w",  "r0:5,r5:5,r10:5"),
    (0x002a0000, 0xffff8000, "break",       "u0:15"),
    (0x002a8000, 0xffff8000, "dbcl",        "u0:15"),
    (0x002b0000, 0xffff8000, "syscall",     "u0:15"),
    (0x002c0000, 0xfffe0000, "alsl.d",      "r0:5,r5:5,r10:5,u15:2+1"),
    (0x00408000, 0xffff8000, "slli.w",      "r0:5,r5:5,u10:5"),
    (0x00410000, 0xffff0000, "slli.d",      "r0:5,r5:5,u10:6"),
    (0x00448000, 0xffff8000, "srli.w",      "r0:5,r5:5,u10:5"),
    (0x00450000, 0xffff0000, "srli.d",      "r0:5,r5:5,u10:6"),
    (0x00488000, 0xffff8000, "srai.w",      "r0:5,r5:5,u10:5"),
    (0x00490000, 0xffff0000, "srai.d",      "r0:5,r5:5,u10:6"),
    (0x004c8000, 0xffff8000, "rotri.w",     "r0:5,r5:5,u10:5"),
    (0x004d0000, 0xffff0000, "rotri.d",     "r0:5,r5:5,u10:6"),
    (0x00600000, 0xffe08000, "bstrins.w",   "r0:5,r5:5,u16:5,u10:5"),
    (0x00608000, 0xffe08000, "bstrpick.w",  "r0:5,r5:5,u16:5,u10:5"),
    (0x00800000, 0xffc00000, "bstrins.d",   "r0:5,r5:5,u16:6,u10:6"),
    (0x00c00000, 0xffc00000, "bstrpick.d",  "r0:5,r5:5,u16:6,u10:6"),

    # -----------------------------------------------------------------------
    # imm_opcodes: 2RI12 / 2RI16 / 1RI20
    # -----------------------------------------------------------------------
    (0x02000000, 0xffc00000, "slti",        "r0:5,r5:5,s10:12"),
    (0x02400000, 0xffc00000, "sltui",       "r0:5,r5:5,s10:12"),
    (0x02800000, 0xffc00000, "addi.w",      "r0:5,r5:5,s10:12"),
    (0x02c00000, 0xffc00000, "addi.d",      "r0:5,r5:5,s10:12"),
    (0x03000000, 0xffc00000, "lu52i.d",     "r0:5,r5:5,s10:12"),
    (0x03400000, 0xffc00000, "andi",        "r0:5,r5:5,u10:12"),
    (0x03800000, 0xffc00000, "ori",         "r0:5,r5:5,u10:12"),
    (0x03c00000, 0xffc00000, "xori",        "r0:5,r5:5,u10:12"),
    (0x10000000, 0xfc000000, "addu16i.d",   "r0:5,r5:5,s10:16"),
    (0x14000000, 0xfe000000, "lu12i.w",     "r0:5,s5:20"),
    (0x16000000, 0xfe000000, "lu32i.d",     "r0:5,s5:20"),
    (0x18000000, 0xfe000000, "pcaddi",      "r0:5,s5:20"),
    (0x1a000000, 0xfe000000, "pcalau12i",   "r0:5,s5:20"),
    (0x1c000000, 0xfe000000, "pcaddu12i",   "r0:5,s5:20"),
    (0x1e000000, 0xfe000000, "pcaddu18i",   "r0:5,s5:20"),

    # -----------------------------------------------------------------------
    # privilege_opcodes: CSR, TLB, IOCSR, barrier
    # -----------------------------------------------------------------------
    (0x04000000, 0xff0003e0, "csrrd",       "r0:5,u10:14"),
    (0x04000020, 0xff0003e0, "csrwr",       "r0:5,u10:14"),
    (0x04000000, 0xff000000, "csrxchg",     "r0:5,r5:5,u10:14"),
    (0x06000000, 0xffc00000, "cacop",       "u0:5,r5:5,s10:12"),
    (0x06400000, 0xfffc0000, "lddir",       "r0:5,r5:5,u10:8"),
    (0x06440000, 0xfffc001f, "ldpte",       "r5:5,u10:8"),
    (0x06480000, 0xfffffc00, "iocsrrd.b",   "r0:5,r5:5"),
    (0x06480400, 0xfffffc00, "iocsrrd.h",   "r0:5,r5:5"),
    (0x06480800, 0xfffffc00, "iocsrrd.w",   "r0:5,r5:5"),
    (0x06480c00, 0xfffffc00, "iocsrrd.d",   "r0:5,r5:5"),
    (0x06481000, 0xfffffc00, "iocsrwr.b",   "r0:5,r5:5"),
    (0x06481400, 0xfffffc00, "iocsrwr.h",   "r0:5,r5:5"),
    (0x06481800, 0xfffffc00, "iocsrwr.w",   "r0:5,r5:5"),
    (0x06481c00, 0xfffffc00, "iocsrwr.d",   "r0:5,r5:5"),
    (0x06482000, 0xffffffff, "tlbclr",      ""),
    (0x06482400, 0xffffffff, "tlbflush",    ""),
    (0x06482800, 0xffffffff, "tlbsrch",     ""),
    (0x06482c00, 0xffffffff, "tlbrd",       ""),
    (0x06483000, 0xffffffff, "tlbwr",       ""),
    (0x06483400, 0xffffffff, "tlbfill",     ""),
    (0x06483800, 0xffffffff, "ertn",        ""),
    (0x06488000, 0xffff8000, "idle",        "u0:15"),
    (0x06498000, 0xffff8000, "invtlb",      "u0:5,r5:5,r10:5"),

    # -----------------------------------------------------------------------
    # single_float_opcodes
    # -----------------------------------------------------------------------
    (0x01008000, 0xffff8000, "fadd.s",      "f0:5,f5:5,f10:5"),
    (0x01028000, 0xffff8000, "fsub.s",      "f0:5,f5:5,f10:5"),
    (0x01048000, 0xffff8000, "fmul.s",      "f0:5,f5:5,f10:5"),
    (0x01068000, 0xffff8000, "fdiv.s",      "f0:5,f5:5,f10:5"),
    (0x01088000, 0xffff8000, "fmax.s",      "f0:5,f5:5,f10:5"),
    (0x010a8000, 0xffff8000, "fmin.s",      "f0:5,f5:5,f10:5"),
    (0x010c8000, 0xffff8000, "fmaxa.s",     "f0:5,f5:5,f10:5"),
    (0x010e8000, 0xffff8000, "fmina.s",     "f0:5,f5:5,f10:5"),
    (0x01108000, 0xffff8000, "fscaleb.s",   "f0:5,f5:5,f10:5"),
    (0x01128000, 0xffff8000, "fcopysign.s", "f0:5,f5:5,f10:5"),
    (0x01140400, 0xfffffc00, "fabs.s",      "f0:5,f5:5"),
    (0x01141400, 0xfffffc00, "fneg.s",      "f0:5,f5:5"),
    (0x01142400, 0xfffffc00, "flogb.s",     "f0:5,f5:5"),
    (0x01143400, 0xfffffc00, "fclass.s",    "f0:5,f5:5"),
    (0x01144400, 0xfffffc00, "fsqrt.s",     "f0:5,f5:5"),
    (0x01145400, 0xfffffc00, "frecip.s",    "f0:5,f5:5"),
    (0x01146400, 0xfffffc00, "frsqrt.s",    "f0:5,f5:5"),
    (0x01149400, 0xfffffc00, "fmov.s",      "f0:5,f5:5"),
    (0x0114a400, 0xfffffc00, "movgr2fr.w",  "f0:5,r5:5"),
    (0x0114ac00, 0xfffffc00, "movgr2frh.w", "f0:5,r5:5"),
    (0x0114b400, 0xfffffc00, "movfr2gr.s",  "r0:5,f5:5"),
    (0x0114bc00, 0xfffffc00, "movfrh2gr.s", "r0:5,f5:5"),
    (0x0114c000, 0xfffffc1c, "movgr2fcsr",  "fc0:2,r5:5"),
    (0x0114c800, 0xffffff80, "movfcsr2gr",  "r0:5,fc5:2"),
    (0x0114d000, 0xfffffc18, "movfr2cf",    "c0:3,f5:5"),
    (0x0114d400, 0xffffff00, "movcf2fr",    "f0:5,c5:3"),
    (0x0114d800, 0xfffffc18, "movgr2cf",    "c0:3,r5:5"),
    (0x0114dc00, 0xffffff00, "movcf2gr",    "r0:5,c5:3"),
    (0x011a0400, 0xfffffc00, "ftintrm.w.s", "f0:5,f5:5"),
    (0x011a2400, 0xfffffc00, "ftintrm.l.s", "f0:5,f5:5"),
    (0x011a4400, 0xfffffc00, "ftintrp.w.s", "f0:5,f5:5"),
    (0x011a6400, 0xfffffc00, "ftintrp.l.s", "f0:5,f5:5"),
    (0x011a8400, 0xfffffc00, "ftintrz.w.s", "f0:5,f5:5"),
    (0x011aa400, 0xfffffc00, "ftintrz.l.s", "f0:5,f5:5"),
    (0x011ac400, 0xfffffc00, "ftintrne.w.s","f0:5,f5:5"),
    (0x011ae400, 0xfffffc00, "ftintrne.l.s","f0:5,f5:5"),
    (0x011b0400, 0xfffffc00, "ftint.w.s",   "f0:5,f5:5"),
    (0x011b2400, 0xfffffc00, "ftint.l.s",   "f0:5,f5:5"),
    (0x011d1000, 0xfffffc00, "ffint.s.w",   "f0:5,f5:5"),
    (0x011d1800, 0xfffffc00, "ffint.s.l",   "f0:5,f5:5"),
    (0x011e4400, 0xfffffc00, "frint.s",     "f0:5,f5:5"),

    # -----------------------------------------------------------------------
    # double_float_opcodes
    # -----------------------------------------------------------------------
    (0x01010000, 0xffff8000, "fadd.d",      "f0:5,f5:5,f10:5"),
    (0x01030000, 0xffff8000, "fsub.d",      "f0:5,f5:5,f10:5"),
    (0x01050000, 0xffff8000, "fmul.d",      "f0:5,f5:5,f10:5"),
    (0x01070000, 0xffff8000, "fdiv.d",      "f0:5,f5:5,f10:5"),
    (0x01090000, 0xffff8000, "fmax.d",      "f0:5,f5:5,f10:5"),
    (0x010b0000, 0xffff8000, "fmin.d",      "f0:5,f5:5,f10:5"),
    (0x010d0000, 0xffff8000, "fmaxa.d",     "f0:5,f5:5,f10:5"),
    (0x010f0000, 0xffff8000, "fmina.d",     "f0:5,f5:5,f10:5"),
    (0x01110000, 0xffff8000, "fscaleb.d",   "f0:5,f5:5,f10:5"),
    (0x01130000, 0xffff8000, "fcopysign.d", "f0:5,f5:5,f10:5"),
    (0x01140800, 0xfffffc00, "fabs.d",      "f0:5,f5:5"),
    (0x01141800, 0xfffffc00, "fneg.d",      "f0:5,f5:5"),
    (0x01142800, 0xfffffc00, "flogb.d",     "f0:5,f5:5"),
    (0x01143800, 0xfffffc00, "fclass.d",    "f0:5,f5:5"),
    (0x01144800, 0xfffffc00, "fsqrt.d",     "f0:5,f5:5"),
    (0x01145800, 0xfffffc00, "frecip.d",    "f0:5,f5:5"),
    (0x01146800, 0xfffffc00, "frsqrt.d",    "f0:5,f5:5"),
    (0x01149800, 0xfffffc00, "fmov.d",      "f0:5,f5:5"),
    (0x0114a800, 0xfffffc00, "movgr2fr.d",  "f0:5,r5:5"),
    (0x0114b800, 0xfffffc00, "movfr2gr.d",  "r0:5,f5:5"),
    (0x01191800, 0xfffffc00, "fcvt.s.d",    "f0:5,f5:5"),
    (0x01192400, 0xfffffc00, "fcvt.d.s",    "f0:5,f5:5"),
    (0x011a0800, 0xfffffc00, "ftintrm.w.d", "f0:5,f5:5"),
    (0x011a2800, 0xfffffc00, "ftintrm.l.d", "f0:5,f5:5"),
    (0x011a4800, 0xfffffc00, "ftintrp.w.d", "f0:5,f5:5"),
    (0x011a6800, 0xfffffc00, "ftintrp.l.d", "f0:5,f5:5"),
    (0x011a8800, 0xfffffc00, "ftintrz.w.d", "f0:5,f5:5"),
    (0x011aa800, 0xfffffc00, "ftintrz.l.d", "f0:5,f5:5"),
    (0x011ac800, 0xfffffc00, "ftintrne.w.d","f0:5,f5:5"),
    (0x011ae800, 0xfffffc00, "ftintrne.l.d","f0:5,f5:5"),
    (0x011b0800, 0xfffffc00, "ftint.w.d",   "f0:5,f5:5"),
    (0x011b2800, 0xfffffc00, "ftint.l.d",   "f0:5,f5:5"),
    (0x011d2000, 0xfffffc00, "ffint.d.w",   "f0:5,f5:5"),
    (0x011d2800, 0xfffffc00, "ffint.d.l",   "f0:5,f5:5"),
    (0x011e4800, 0xfffffc00, "frint.d",     "f0:5,f5:5"),

    # -----------------------------------------------------------------------
    # 4opt_single_float_opcodes: fmadd/fmsub/fnmadd/fnmsub, fcmp.*
    # -----------------------------------------------------------------------
    (0x08100000, 0xfff00000, "fmadd.s",     "f0:5,f5:5,f10:5,f15:5"),
    (0x08500000, 0xfff00000, "fmsub.s",     "f0:5,f5:5,f10:5,f15:5"),
    (0x08900000, 0xfff00000, "fnmadd.s",    "f0:5,f5:5,f10:5,f15:5"),
    (0x08d00000, 0xfff00000, "fnmsub.s",    "f0:5,f5:5,f10:5,f15:5"),
    (0x0c100000, 0xffff8018, "fcmp.caf.s",  "c0:3,f5:5,f10:5"),
    (0x0c108000, 0xffff8018, "fcmp.saf.s",  "c0:3,f5:5,f10:5"),
    (0x0c110000, 0xffff8018, "fcmp.clt.s",  "c0:3,f5:5,f10:5"),
    (0x0c118000, 0xffff8018, "fcmp.slt.s",  "c0:3,f5:5,f10:5"),
    (0x0c120000, 0xffff8018, "fcmp.ceq.s",  "c0:3,f5:5,f10:5"),
    (0x0c128000, 0xffff8018, "fcmp.seq.s",  "c0:3,f5:5,f10:5"),
    (0x0c130000, 0xffff8018, "fcmp.cle.s",  "c0:3,f5:5,f10:5"),
    (0x0c138000, 0xffff8018, "fcmp.sle.s",  "c0:3,f5:5,f10:5"),
    (0x0c140000, 0xffff8018, "fcmp.cun.s",  "c0:3,f5:5,f10:5"),
    (0x0c148000, 0xffff8018, "fcmp.sun.s",  "c0:3,f5:5,f10:5"),
    (0x0c150000, 0xffff8018, "fcmp.cult.s", "c0:3,f5:5,f10:5"),
    (0x0c158000, 0xffff8018, "fcmp.sult.s", "c0:3,f5:5,f10:5"),
    (0x0c160000, 0xffff8018, "fcmp.cueq.s", "c0:3,f5:5,f10:5"),
    (0x0c168000, 0xffff8018, "fcmp.sueq.s", "c0:3,f5:5,f10:5"),
    (0x0c170000, 0xffff8018, "fcmp.cule.s", "c0:3,f5:5,f10:5"),
    (0x0c178000, 0xffff8018, "fcmp.sule.s", "c0:3,f5:5,f10:5"),
    (0x0c180000, 0xffff8018, "fcmp.cne.s",  "c0:3,f5:5,f10:5"),
    (0x0c188000, 0xffff8018, "fcmp.sne.s",  "c0:3,f5:5,f10:5"),
    (0x0c1a0000, 0xffff8018, "fcmp.cor.s",  "c0:3,f5:5,f10:5"),
    (0x0c1a8000, 0xffff8018, "fcmp.sor.s",  "c0:3,f5:5,f10:5"),
    (0x0c1c0000, 0xffff8018, "fcmp.cune.s", "c0:3,f5:5,f10:5"),
    (0x0c1c8000, 0xffff8018, "fcmp.sune.s", "c0:3,f5:5,f10:5"),
    (0x0d000000, 0xfffc0000, "fsel",        "f0:5,f5:5,f10:5,c15:3"),

    # -----------------------------------------------------------------------
    # 4opt_double_float_opcodes: fmadd/fmsub/fnmadd/fnmsub, fcmp.*.d
    # -----------------------------------------------------------------------
    (0x08200000, 0xfff00000, "fmadd.d",     "f0:5,f5:5,f10:5,f15:5"),
    (0x08600000, 0xfff00000, "fmsub.d",     "f0:5,f5:5,f10:5,f15:5"),
    (0x08a00000, 0xfff00000, "fnmadd.d",    "f0:5,f5:5,f10:5,f15:5"),
    (0x08e00000, 0xfff00000, "fnmsub.d",    "f0:5,f5:5,f10:5,f15:5"),
    (0x0c200000, 0xffff8018, "fcmp.caf.d",  "c0:3,f5:5,f10:5"),
    (0x0c208000, 0xffff8018, "fcmp.saf.d",  "c0:3,f5:5,f10:5"),
    (0x0c210000, 0xffff8018, "fcmp.clt.d",  "c0:3,f5:5,f10:5"),
    (0x0c218000, 0xffff8018, "fcmp.slt.d",  "c0:3,f5:5,f10:5"),
    (0x0c220000, 0xffff8018, "fcmp.ceq.d",  "c0:3,f5:5,f10:5"),
    (0x0c228000, 0xffff8018, "fcmp.seq.d",  "c0:3,f5:5,f10:5"),
    (0x0c230000, 0xffff8018, "fcmp.cle.d",  "c0:3,f5:5,f10:5"),
    (0x0c238000, 0xffff8018, "fcmp.sle.d",  "c0:3,f5:5,f10:5"),
    (0x0c240000, 0xffff8018, "fcmp.cun.d",  "c0:3,f5:5,f10:5"),
    (0x0c248000, 0xffff8018, "fcmp.sun.d",  "c0:3,f5:5,f10:5"),
    (0x0c250000, 0xffff8018, "fcmp.cult.d", "c0:3,f5:5,f10:5"),
    (0x0c258000, 0xffff8018, "fcmp.sult.d", "c0:3,f5:5,f10:5"),
    (0x0c260000, 0xffff8018, "fcmp.cueq.d", "c0:3,f5:5,f10:5"),
    (0x0c268000, 0xffff8018, "fcmp.sueq.d", "c0:3,f5:5,f10:5"),
    (0x0c270000, 0xffff8018, "fcmp.cule.d", "c0:3,f5:5,f10:5"),
    (0x0c278000, 0xffff8018, "fcmp.sule.d", "c0:3,f5:5,f10:5"),
    (0x0c280000, 0xffff8018, "fcmp.cne.d",  "c0:3,f5:5,f10:5"),
    (0x0c288000, 0xffff8018, "fcmp.sne.d",  "c0:3,f5:5,f10:5"),
    (0x0c2a0000, 0xffff8018, "fcmp.cor.d",  "c0:3,f5:5,f10:5"),
    (0x0c2a8000, 0xffff8018, "fcmp.sor.d",  "c0:3,f5:5,f10:5"),
    (0x0c2c0000, 0xffff8018, "fcmp.cune.d", "c0:3,f5:5,f10:5"),
    (0x0c2c8000, 0xffff8018, "fcmp.sune.d", "c0:3,f5:5,f10:5"),

    # -----------------------------------------------------------------------
    # load_store_opcodes: ld/st (imm offset), ll/sc, ldptr/stptr,
    #                     ldx/stx (register offset), atomics, barriers
    # -----------------------------------------------------------------------
    (0x20000000, 0xff000000, "ll.w",        "r0:5,r5:5,so10:14<<2"),
    (0x21000000, 0xff000000, "sc.w",        "r0:5,r5:5,so10:14<<2"),
    (0x22000000, 0xff000000, "ll.d",        "r0:5,r5:5,so10:14<<2"),
    (0x23000000, 0xff000000, "sc.d",        "r0:5,r5:5,so10:14<<2"),
    (0x24000000, 0xff000000, "ldptr.w",     "r0:5,r5:5,so10:14<<2"),
    (0x25000000, 0xff000000, "stptr.w",     "r0:5,r5:5,so10:14<<2"),
    (0x26000000, 0xff000000, "ldptr.d",     "r0:5,r5:5,so10:14<<2"),
    (0x27000000, 0xff000000, "stptr.d",     "r0:5,r5:5,so10:14<<2"),
    (0x28000000, 0xffc00000, "ld.b",        "r0:5,r5:5,so10:12"),
    (0x28400000, 0xffc00000, "ld.h",        "r0:5,r5:5,so10:12"),
    (0x28800000, 0xffc00000, "ld.w",        "r0:5,r5:5,so10:12"),
    (0x28c00000, 0xffc00000, "ld.d",        "r0:5,r5:5,so10:12"),
    (0x29000000, 0xffc00000, "st.b",        "r0:5,r5:5,so10:12"),
    (0x29400000, 0xffc00000, "st.h",        "r0:5,r5:5,so10:12"),
    (0x29800000, 0xffc00000, "st.w",        "r0:5,r5:5,so10:12"),
    (0x29c00000, 0xffc00000, "st.d",        "r0:5,r5:5,so10:12"),
    (0x2a000000, 0xffc00000, "ld.bu",       "r0:5,r5:5,so10:12"),
    (0x2a400000, 0xffc00000, "ld.hu",       "r0:5,r5:5,so10:12"),
    (0x2a800000, 0xffc00000, "ld.wu",       "r0:5,r5:5,so10:12"),
    (0x2ac00000, 0xffc00000, "preld",       "u0:5,r5:5,so10:12"),
    (0x38000000, 0xffff8000, "ldx.b",       "r0:5,r5:5,r10:5"),
    (0x38040000, 0xffff8000, "ldx.h",       "r0:5,r5:5,r10:5"),
    (0x38080000, 0xffff8000, "ldx.w",       "r0:5,r5:5,r10:5"),
    (0x380c0000, 0xffff8000, "ldx.d",       "r0:5,r5:5,r10:5"),
    (0x38100000, 0xffff8000, "stx.b",       "r0:5,r5:5,r10:5"),
    (0x38140000, 0xffff8000, "stx.h",       "r0:5,r5:5,r10:5"),
    (0x38180000, 0xffff8000, "stx.w",       "r0:5,r5:5,r10:5"),
    (0x381c0000, 0xffff8000, "stx.d",       "r0:5,r5:5,r10:5"),
    (0x38200000, 0xffff8000, "ldx.bu",      "r0:5,r5:5,r10:5"),
    (0x38240000, 0xffff8000, "ldx.hu",      "r0:5,r5:5,r10:5"),
    (0x38280000, 0xffff8000, "ldx.wu",      "r0:5,r5:5,r10:5"),
    (0x382c0000, 0xffff8000, "preldx",      "u0:5,r5:5,r10:5"),
    (0x38600000, 0xffff8000, "amswap.w",    "r0:5,r10:5,r5:5"),
    (0x38608000, 0xffff8000, "amswap.d",    "r0:5,r10:5,r5:5"),
    (0x38610000, 0xffff8000, "amadd.w",     "r0:5,r10:5,r5:5"),
    (0x38618000, 0xffff8000, "amadd.d",     "r0:5,r10:5,r5:5"),
    (0x38620000, 0xffff8000, "amand.w",     "r0:5,r10:5,r5:5"),
    (0x38628000, 0xffff8000, "amand.d",     "r0:5,r10:5,r5:5"),
    (0x38630000, 0xffff8000, "amor.w",      "r0:5,r10:5,r5:5"),
    (0x38638000, 0xffff8000, "amor.d",      "r0:5,r10:5,r5:5"),
    (0x38640000, 0xffff8000, "amxor.w",     "r0:5,r10:5,r5:5"),
    (0x38648000, 0xffff8000, "amxor.d",     "r0:5,r10:5,r5:5"),
    (0x38650000, 0xffff8000, "ammax.w",     "r0:5,r10:5,r5:5"),
    (0x38658000, 0xffff8000, "ammax.d",     "r0:5,r10:5,r5:5"),
    (0x38660000, 0xffff8000, "ammin.w",     "r0:5,r10:5,r5:5"),
    (0x38668000, 0xffff8000, "ammin.d",     "r0:5,r10:5,r5:5"),
    (0x38670000, 0xffff8000, "ammax.wu",    "r0:5,r10:5,r5:5"),
    (0x38678000, 0xffff8000, "ammax.du",    "r0:5,r10:5,r5:5"),
    (0x38680000, 0xffff8000, "ammin.wu",    "r0:5,r10:5,r5:5"),
    (0x38688000, 0xffff8000, "ammin.du",    "r0:5,r10:5,r5:5"),
    (0x38690000, 0xffff8000, "amswap_db.w", "r0:5,r10:5,r5:5"),
    (0x38698000, 0xffff8000, "amswap_db.d", "r0:5,r10:5,r5:5"),
    (0x386a0000, 0xffff8000, "amadd_db.w",  "r0:5,r10:5,r5:5"),
    (0x386a8000, 0xffff8000, "amadd_db.d",  "r0:5,r10:5,r5:5"),
    (0x386b0000, 0xffff8000, "amand_db.w",  "r0:5,r10:5,r5:5"),
    (0x386b8000, 0xffff8000, "amand_db.d",  "r0:5,r10:5,r5:5"),
    (0x386c0000, 0xffff8000, "amor_db.w",   "r0:5,r10:5,r5:5"),
    (0x386c8000, 0xffff8000, "amor_db.d",   "r0:5,r10:5,r5:5"),
    (0x386d0000, 0xffff8000, "amxor_db.w",  "r0:5,r10:5,r5:5"),
    (0x386d8000, 0xffff8000, "amxor_db.d",  "r0:5,r10:5,r5:5"),
    (0x386e0000, 0xffff8000, "ammax_db.w",  "r0:5,r10:5,r5:5"),
    (0x386e8000, 0xffff8000, "ammax_db.d",  "r0:5,r10:5,r5:5"),
    (0x386f0000, 0xffff8000, "ammin_db.w",  "r0:5,r10:5,r5:5"),
    (0x386f8000, 0xffff8000, "ammin_db.d",  "r0:5,r10:5,r5:5"),
    (0x38700000, 0xffff8000, "ammax_db.wu", "r0:5,r10:5,r5:5"),
    (0x38708000, 0xffff8000, "ammax_db.du", "r0:5,r10:5,r5:5"),
    (0x38710000, 0xffff8000, "ammin_db.wu", "r0:5,r10:5,r5:5"),
    (0x38718000, 0xffff8000, "ammin_db.du", "r0:5,r10:5,r5:5"),
    (0x38720000, 0xffff8000, "dbar",        "u0:15"),
    (0x38728000, 0xffff8000, "ibar",        "u0:15"),
    (0x38780000, 0xffff8000, "ldgt.b",      "r0:5,r5:5,r10:5"),
    (0x38788000, 0xffff8000, "ldgt.h",      "r0:5,r5:5,r10:5"),
    (0x38790000, 0xffff8000, "ldgt.w",      "r0:5,r5:5,r10:5"),
    (0x38798000, 0xffff8000, "ldgt.d",      "r0:5,r5:5,r10:5"),
    (0x387a0000, 0xffff8000, "ldle.b",      "r0:5,r5:5,r10:5"),
    (0x387a8000, 0xffff8000, "ldle.h",      "r0:5,r5:5,r10:5"),
    (0x387b0000, 0xffff8000, "ldle.w",      "r0:5,r5:5,r10:5"),
    (0x387b8000, 0xffff8000, "ldle.d",      "r0:5,r5:5,r10:5"),
    (0x387c0000, 0xffff8000, "stgt.b",      "r0:5,r5:5,r10:5"),
    (0x387c8000, 0xffff8000, "stgt.h",      "r0:5,r5:5,r10:5"),
    (0x387d0000, 0xffff8000, "stgt.w",      "r0:5,r5:5,r10:5"),
    (0x387d8000, 0xffff8000, "stgt.d",      "r0:5,r5:5,r10:5"),
    (0x387e0000, 0xffff8000, "stle.b",      "r0:5,r5:5,r10:5"),
    (0x387e8000, 0xffff8000, "stle.h",      "r0:5,r5:5,r10:5"),
    (0x387f0000, 0xffff8000, "stle.w",      "r0:5,r5:5,r10:5"),
    (0x387f8000, 0xffff8000, "stle.d",      "r0:5,r5:5,r10:5"),

    # -----------------------------------------------------------------------
    # float_load_store_opcodes
    # -----------------------------------------------------------------------
    (0x2b000000, 0xffc00000, "fld.s",       "f0:5,r5:5,so10:12"),
    (0x2b400000, 0xffc00000, "fst.s",       "f0:5,r5:5,so10:12"),
    (0x2b800000, 0xffc00000, "fld.d",       "f0:5,r5:5,so10:12"),
    (0x2bc00000, 0xffc00000, "fst.d",       "f0:5,r5:5,so10:12"),
    (0x38300000, 0xffff8000, "fldx.s",      "f0:5,r5:5,r10:5"),
    (0x38340000, 0xffff8000, "fldx.d",      "f0:5,r5:5,r10:5"),
    (0x38380000, 0xffff8000, "fstx.s",      "f0:5,r5:5,r10:5"),
    (0x383c0000, 0xffff8000, "fstx.d",      "f0:5,r5:5,r10:5"),
    (0x38740000, 0xffff8000, "fldgt.s",     "f0:5,r5:5,r10:5"),
    (0x38748000, 0xffff8000, "fldgt.d",     "f0:5,r5:5,r10:5"),
    (0x38750000, 0xffff8000, "fldle.s",     "f0:5,r5:5,r10:5"),
    (0x38758000, 0xffff8000, "fldle.d",     "f0:5,r5:5,r10:5"),
    (0x38760000, 0xffff8000, "fstgt.s",     "f0:5,r5:5,r10:5"),
    (0x38768000, 0xffff8000, "fstgt.d",     "f0:5,r5:5,r10:5"),
    (0x38770000, 0xffff8000, "fstle.s",     "f0:5,r5:5,r10:5"),
    (0x38778000, 0xffff8000, "fstle.d",     "f0:5,r5:5,r10:5"),

    # -----------------------------------------------------------------------
    # float_jmp_opcodes: bceqz, bcnez (branch on condition flag)
    # -----------------------------------------------------------------------
    (0x48000000, 0xfc000300, "bceqz",       "c5:3,sb0:5|10:16<<2"),
    (0x48000100, 0xfc000300, "bcnez",       "c5:3,sb0:5|10:16<<2"),

    # -----------------------------------------------------------------------
    # jmp_opcodes: beqz, bnez, jirl, b, bl, beq, bne, blt, bge, bltu, bgeu
    # CRITICAL PATH: these drive all CF classification.
    # -----------------------------------------------------------------------
    (0x40000000, 0xfc000000, "beqz",        "r5:5,sb0:5|10:16<<2"),
    (0x44000000, 0xfc000000, "bnez",        "r5:5,sb0:5|10:16<<2"),
    (0x4c000000, 0xfc000000, "jirl",        "r0:5,r5:5,so10:16<<2"),
    (0x50000000, 0xfc000000, "b",           "sb0:10|10:16<<2"),
    (0x54000000, 0xfc000000, "bl",          "sb0:10|10:16<<2"),
    (0x58000000, 0xfc000000, "beq",         "r5:5,r0:5,sb10:16<<2"),
    (0x5c000000, 0xfc000000, "bne",         "r5:5,r0:5,sb10:16<<2"),
    (0x60000000, 0xfc000000, "blt",         "r5:5,r0:5,sb10:16<<2"),
    (0x64000000, 0xfc000000, "bge",         "r5:5,r0:5,sb10:16<<2"),
    (0x68000000, 0xfc000000, "bltu",        "r5:5,r0:5,sb10:16<<2"),
    (0x6c000000, 0xfc000000, "bgeu",        "r5:5,r0:5,sb10:16<<2"),
]

# Sort by popcount(mask) descending so more-specific patterns match first.
# This is necessary because some entries share match bits at different mask
# granularities (e.g. csrrd/csrwr vs csrxchg, or bceqz vs beqz).
_OPCODES.sort(key=lambda t: bin(t[1]).count('1'), reverse=True)


# ---------------------------------------------------------------------------
# Bit-field decoder
# Python port of loongarch_decode_imm() from binutils loongarch-coder.c.
#
# The format grammar for a bit_field string:
#   <start>:<width> [ '|' <start>:<width> ]* [ '<<' <shift> | '+' <addend> ]
#
# Segments are processed left to right; each segment's bits are extracted
# from the instruction and appended to the right of the accumulator.  So
# the first segment in the string occupies the most-significant bits of the
# decoded value, and later segments fill downward.
# ---------------------------------------------------------------------------

def _decode_imm(bit_field: str, insn: int, signed: bool) -> int:
    """Decode a bit-field operand from a 32-bit LoongArch instruction word."""
    ret    = 0
    length = 0
    rest   = bit_field

    while rest:
        # Parse <start>
        colon = rest.index(':')
        b_start = int(rest[:colon])
        rest = rest[colon + 1:]

        # Parse <width>
        w_end = 0
        while w_end < len(rest) and rest[w_end].isdigit():
            w_end += 1
        width = int(rest[:w_end])
        rest = rest[w_end:]
        length += width

        # Extract `width` bits starting at bit `b_start`
        t = (insn >> b_start) & ((1 << width) - 1)
        ret = (ret << width) | t

        if not rest or rest[0] != '|':
            break
        rest = rest[1:]

    # Post-modifiers
    if rest.startswith('<<'):
        shift = int(rest[2:])
        ret    <<= shift
        length  += shift
    elif rest.startswith('+'):
        ret += int(rest[1:])

    # Sign extension
    if signed and length > 0:
        sign = 1 << (length - 1)
        if ret & sign:
            ret -= (1 << length)

    return ret


# ---------------------------------------------------------------------------
# Format string tokeniser
# Splits a format string like "r5:5,sb0:5|10:16<<2" into a list of
# (esc1, esc2, bit_field) tuples, mirroring loongarch_parse_format() in C.
# ---------------------------------------------------------------------------

def _parse_format(fmt: str) -> List[Tuple[str, str, str]]:
    """Parse a format string into a list of (esc1, esc2, bit_field) tuples."""
    if not fmt:
        return []
    tokens: List[Tuple[str, str, str]] = []
    pos = 0
    n   = len(fmt)
    while pos < n:
        if not fmt[pos].isalpha():
            break
        esc1 = fmt[pos]; pos += 1
        esc2 = ''
        if pos < n and fmt[pos].isalpha():
            esc2 = fmt[pos]; pos += 1
        # Read bit_field until comma or end
        start = pos
        while pos < n and fmt[pos] != ',':
            pos += 1
        bit_field = fmt[start:pos]
        tokens.append((esc1, esc2, bit_field))
        if pos < n and fmt[pos] == ',':
            pos += 1
    return tokens


# ---------------------------------------------------------------------------
# Operand renderer
# ---------------------------------------------------------------------------

def _render_operands(fmt: str, insn: int, va: int) -> Tuple[str, int]:
    """
    Render the operand string for an instruction.

    Returns (op_str, branch_target) where branch_target is the resolved
    PC-relative target VA for 'sb' operands, or 0 for non-branch / indirect.
    """
    tokens = _parse_format(fmt)
    if not tokens:
        return "", 0

    parts:  List[str] = []
    target: int       = 0

    for esc1, esc2, bf in tokens:
        imm_u = _decode_imm(bf, insn, signed=False)
        imm_s = _decode_imm(bf, insn, signed=True)

        if esc1 == 'r':
            parts.append(_R_LP64[imm_u & 0x1f])

        elif esc1 == 'f':
            if esc2 == 'c':
                parts.append(_FC_NAMES[imm_u & 0x3])
            else:
                parts.append(_F_LP64[imm_u & 0x1f])

        elif esc1 == 'c':
            if esc2 == 'r':
                parts.append(_CR_NAMES[imm_u & 0x3])
            else:
                parts.append(_C_NAMES[imm_u & 0x7])

        elif esc1 == 'v':
            parts.append(_V_NAMES[imm_u & 0x1f])

        elif esc1 == 'x':
            parts.append(_X_NAMES[imm_u & 0x1f])

        elif esc1 == 'u':
            parts.append(f"0x{imm_u:x}")

        elif esc1 == 's':
            if esc2 == 'b':
                # PC-relative branch offset; target = instruction VA + signed offset
                target = (va + imm_s) & 0xffffffffffffffff
                parts.append(f"{imm_s}")
            else:
                # 'so' (memory offset) or plain 's' immediate — signed decimal
                parts.append(f"{imm_s}")

    return ", ".join(parts), target


# ---------------------------------------------------------------------------
# Control-flow classification
# ---------------------------------------------------------------------------

_JIRL_MATCH = 0x4c000000
_JIRL_MASK  = 0xfc000000
_B_MATCH    = 0x50000000
_BL_MATCH   = 0x54000000
_CF_MASK    = 0xfc000000   # top-6-bit opcode mask for all CF instructions

# Conditional branch top-6-bit match values (insn & 0xfc000000)
_COND_BRANCH_TOP6 = frozenset({
    0x40000000,  # beqz
    0x44000000,  # bnez
    0x48000000,  # bceqz / bcnez  (bits[9:8] distinguish; both share this top6)
    0x58000000,  # beq
    0x5c000000,  # bne
    0x60000000,  # blt
    0x64000000,  # bge
    0x68000000,  # bltu
    0x6c000000,  # bgeu
})


def _classify_cf(insn: int, va: int, branch_target: int) -> Tuple[bool, bool, bool, int]:
    """
    Classify LoongArch control-flow and return (is_branch, is_call, is_ret, target).

    branch_target: already-computed PC-relative target from _render_operands,
                   or 0 if the format had no 'sb' operand.
    """
    opc6 = insn & _CF_MASK

    # jirl: the unified indirect-branch / call / return instruction.
    if opc6 == _JIRL_MATCH:
        rd     = insn & 0x1f
        rj     = (insn >> 5) & 0x1f
        # offset field so10:16<<2
        raw16  = (insn >> 10) & 0xffff
        offset = (raw16 - 0x10000 if raw16 & 0x8000 else raw16) << 2

        if rd == _REG_ZERO and rj == _REG_RA and offset == 0:
            return False, False, True, 0    # ret
        elif rd == _REG_RA:
            return False, True, False, 0    # indirect call  (target unknown statically)
        else:
            return True, False, False, 0    # indirect branch (target unknown)

    # bl: direct call
    if opc6 == _BL_MATCH:
        return False, True, False, branch_target

    # b: unconditional direct branch
    if opc6 == _B_MATCH:
        return True, False, False, branch_target

    # conditional branches (beqz/bnez/beq/bne/blt/bge/bltu/bgeu/bceqz/bcnez)
    if insn & _CF_MASK in _COND_BRANCH_TOP6:
        return True, False, False, branch_target

    return False, False, False, 0


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class LoongArchDecoder:
    """
    Pure-Python LoongArch64 fixed-width instruction decoder.

    All instructions are 32 bits / 4 bytes, little-endian. The decoder
    performs a linear match/mask scan through the opcode table (sorted by
    mask popcount descending for correct priority). Unknown encodings
    produce a .word frame with mnemonic=".word".

    Targets: TencentOS 4.6 LoongArch64 binaries (glibc, OpenSSL, GCC,
             QEMU, kernel modules, EDK2, GRUB2, crypto libraries).

    Usage:
        dec = LoongArchDecoder()
        for frame in dec.decode_frames(section_bytes, base_addr=0x400000):
            print(frame)
    """

    def decode_one(self, data: bytes, va: int) -> Optional[LoongArchFrame]:
        """Decode a single instruction at the start of `data` at address `va`."""
        if len(data) < 4:
            return None
        insn = struct.unpack_from("<I", data, 0)[0]

        for match, mask, name, fmt in _OPCODES:
            if (insn & mask) == match:
                op_str, br_target = _render_operands(fmt, insn, va)
                is_br, is_call, is_ret, target = _classify_cf(insn, va, br_target)
                return LoongArchFrame(
                    va        = va,
                    width     = 4,
                    insn      = insn,
                    mnemonic  = name,
                    op_str    = op_str,
                    is_branch = is_br,
                    is_call   = is_call,
                    is_ret    = is_ret,
                    target    = target,
                )

        # Unknown encoding (likely LSX/LASX or future extension)
        return LoongArchFrame(
            va       = va,
            width    = 4,
            insn     = insn,
            mnemonic = ".word",
            op_str   = f"0x{insn:08x}",
        )

    def decode_frames(self, data: bytes, base_addr: int = 0) -> Iterator[LoongArchFrame]:
        """
        Yield LoongArchFrame objects for every 4-byte word in `data`.

        Unlike variable-width ISAs, LoongArch never needs re-synchronisation:
        every 4-byte aligned offset is a valid instruction boundary candidate.
        """
        offset = 0
        length = len(data)
        while offset + 4 <= length:
            frame = self.decode_one(data[offset:], base_addr + offset)
            if frame is None:
                break
            yield frame
            offset += 4


# ---------------------------------------------------------------------------
# Convenience: LoongArchDisasm — thin wrapper used by DisasmEngine
# ---------------------------------------------------------------------------

class LoongArchDisasm:
    """Thin wrapper so DisasmEngine can call decode_frames uniformly."""

    def __init__(self) -> None:
        self._dec = LoongArchDecoder()

    def decode_frames(self, data: bytes, base_addr: int = 0) -> Iterator[LoongArchFrame]:
        return self._dec.decode_frames(data, base_addr)
