"""
arch_configs_raw.py — ArchConfig implementations for arches without Capstone support,
plus Capstone-backed configs for x86-64 and PPC64 BE that were missing from
dataflow_engine.py.

Concrete configs exported here:
  AlphaAXPConfig   — DEC Alpha AXP (21064/21164/21264), no Capstone
  X86_64Config     — x86-64 SysV AMD64, Capstone CS_ARCH_X86 MODE_64
  PPC64BEConfig    — IBM POWER64 big-endian ELFv1/ELFv2, Capstone CS_ARCH_PPC

Usage:
    from ablation.analyzers.arch_configs_raw import AlphaAXPConfig
    from ablation.analyzers.dataflow_engine import CFGBuilder, DomTree

    cfg   = CFGBuilder(AlphaAXPConfig(), data, base).build(func_va)
    dom   = DomTree(cfg)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import capstone
from capstone import x86 as C_X86

from ablation.analyzers.dataflow_engine import ArchConfig, RawArchConfig, RawInsn


# ══════════════════════════════════════════════════════════════════════════════
# Alpha AXP — 32-bit fixed-width, no Capstone
# ══════════════════════════════════════════════════════════════════════════════

# Opcode constants
_A_OP_LDA   = 0x08   # Load Address      Ra = Rb + disp16       (load)
_A_OP_LDAH  = 0x09   # Load Address High Ra = Rb + (disp16<<16) (load)
_A_OP_LDBU  = 0x0A   # Load Byte Unsgnd  Ra = M(Rb+disp)        (load)
_A_OP_LDQ_U = 0x0B   # Load Qword Unalgn Ra = M(Rb+disp)        (load)
_A_OP_LDWU  = 0x0C   # Load Word Unsgnd  Ra = M(Rb+disp)        (load)
_A_OP_STW   = 0x0D   # Store Word        (store — Ra is source)
_A_OP_STB   = 0x0E   # Store Byte        (store)
_A_OP_STQ_U = 0x0F   # Store Qword Unaln (store)
# Integer Operate: 0x10–0x17 — dest = Rc [4:0]
# Floating-Point: 0x15–0x17 (Fa/Fb sources, Fc dest)
_A_OP_LDS   = 0x22   # Load FP S (load)
_A_OP_LDT   = 0x23   # Load FP T (load)
_A_OP_STS   = 0x26   # Store FP S (store)
_A_OP_STT   = 0x27   # Store FP T (store)
_A_OP_LDL   = 0x28   # Load Long    Ra = M[Rb+disp] sign-ext    (load)
_A_OP_LDQ   = 0x29   # Load Qword                               (load)
_A_OP_LDL_L = 0x2A   # Load Long Locked                         (load)
_A_OP_LDQ_L = 0x2B   # Load Qword Locked                        (load)
_A_OP_STL   = 0x2C   # Store Long   (store)
_A_OP_STQ   = 0x2D   # Store Qword  (store)
_A_OP_STL_C = 0x2E   # Store Long Conditional (store)
_A_OP_STQ_C = 0x2F   # Store Qword Conditional (store)
_A_OP_BR    = 0x30   # Branch Unconditional   Ra = PC+4 (written)
_A_OP_JMP   = 0x1A   # JMP/JSR/RET/JSR_CO    Ra = PC+4 (written)
_A_OP_BSR   = 0x34   # Branch Subroutine      Ra = PC+4 (written)

# Conditional branches — Ra is READ (the tested register), NOT written
_A_COND_BRANCH_OPS = frozenset([
    0x38,  # BLBS
    0x39,  # BEQ
    0x3A,  # BLT
    0x3B,  # BLE
    0x3C,  # BLBC
    0x3D,  # BNE
    0x3E,  # BGE
    0x3F,  # BGT
    0x31,  # FBEQ
    0x32,  # FBLT
    0x33,  # FBLE
    0x35,  # FBNE
    0x36,  # FBGE
    0x37,  # FBGT
])

# Load opcodes: Ra is the destination register
_A_LOAD_OPS = frozenset([
    _A_OP_LDA, _A_OP_LDAH, _A_OP_LDBU, _A_OP_LDQ_U, _A_OP_LDWU,
    _A_OP_LDS, _A_OP_LDT,
    _A_OP_LDL, _A_OP_LDQ, _A_OP_LDL_L, _A_OP_LDQ_L,
])

# Store opcodes: Ra is a source (nothing written to a GPR)
_A_STORE_OPS = frozenset([
    _A_OP_STW, _A_OP_STB, _A_OP_STQ_U,
    _A_OP_STS, _A_OP_STT,
    _A_OP_STL, _A_OP_STQ, _A_OP_STL_C, _A_OP_STQ_C,
])

# Integer operate opcodes: dest = Rc [4:0]
_A_IOPS = frozenset(range(0x10, 0x18))  # 0x10–0x17

# Callee-saved registers per Alpha calling convention (not clobbered by call)
_ALPHA_CALLEE_SAVED = frozenset(range(9, 16))  # r9–r15 ($s0–$s6)

# All caller-save (volatile) registers (clobbered across a BSR/JSR)
_ALPHA_CALLER_SAVE = (
    [f'r{i}' for i in range(9)]          # r0–r8
    + [f'r{i}' for i in range(16, 29)]   # r16–r28  (r25–r28 are temporaries)
    + ['r29']                             # gp (may be clobbered)
)

# Alpha opcodes → mnemonic (abbreviated; covers the common subset)
_A_MNEM: Dict[int, str] = {
    0x08: 'lda',   0x09: 'ldah',  0x0A: 'ldbu',  0x0B: 'ldq_u',
    0x0C: 'ldwu',  0x0D: 'stw',   0x0E: 'stb',   0x0F: 'stq_u',
    0x18: 'misc',  0x19: 'pal19', 0x1A: 'jmp',   0x1C: 'sext',
    0x22: 'lds',   0x23: 'ldt',   0x24: 'stf',   0x25: 'stg',
    0x26: 'sts',   0x27: 'stt',   0x28: 'ldl',   0x29: 'ldq',
    0x2A: 'ldl_l', 0x2B: 'ldq_l', 0x2C: 'stl',   0x2D: 'stq',
    0x2E: 'stl_c', 0x2F: 'stq_c', 0x30: 'br',    0x31: 'fbeq',
    0x32: 'fblt',  0x33: 'fble',  0x34: 'bsr',   0x35: 'fbne',
    0x36: 'fbge',  0x37: 'fbgt',  0x38: 'blbs',  0x39: 'beq',
    0x3A: 'blt',   0x3B: 'ble',   0x3C: 'blbc',  0x3D: 'bne',
    0x3E: 'bge',   0x3F: 'bgt',
}
_A_IOPS_MNEM: Dict[int, str] = {
    0x10: 'inta',  0x11: 'intl',  0x12: 'ints',  0x13: 'intm',
    0x14: 'itfp',  0x15: 'fltv',  0x16: 'flti',  0x17: 'fltl',
}


def _alpha_decode(word: int, addr: int) -> RawInsn:
    op = (word >> 26) & 0x3F
    ra = (word >> 21) & 0x1F
    rb = (word >> 16) & 0x1F
    if op in _A_IOPS:
        rc = word & 0x1F
        fn = (word >> 5) & 0x7F
        mnem = f'{_A_IOPS_MNEM.get(op,"iop")}.{fn:02x} r{ra},r{rb},r{rc}'
    elif op in (_A_OP_BR, _A_OP_BSR, *_A_COND_BRANCH_OPS):
        disp = word & 0x1FFFFF
        if disp >= (1 << 20):
            disp -= (1 << 21)
        target = (addr + 4) + disp * 4
        mnem = f'{_A_MNEM.get(op,"b?")} r{ra},0x{target:x}'
    elif op == _A_OP_JMP:
        hint = (word >> 14) & 0x3
        hint_nm = ['jmp', 'jsr', 'ret', 'jsr_co'][hint]
        mnem = f'{hint_nm} r{ra},(r{rb})'
    else:
        disp = word & 0xFFFF
        if disp >= 0x8000:
            disp -= 0x10000
        mnem = f'{_A_MNEM.get(op,"?")} r{ra},{disp}(r{rb})'
    return RawInsn(address=addr, word=word, mnemonic=mnem)


class AlphaAXPConfig(RawArchConfig):
    """
    ArchConfig for DEC Alpha AXP (21064/21164/21264).
    All instructions are 32-bit fixed-width, little-endian.
    No Capstone backend exists for Alpha — uses custom decode.
    """

    def decode_range(self, data: bytes, base: int, addr: int, n_bytes: int) -> List[RawInsn]:
        off = addr - base
        if off < 0 or off + 4 > len(data):
            return []
        result: List[RawInsn] = []
        end = min(off + n_bytes, len(data))
        cur = off
        while cur + 4 <= end:
            word = struct.unpack_from('<I', data, cur)[0]
            va   = base + cur
            result.append(_alpha_decode(word, va))
            cur += 4
        return result

    def is_return(self, insn: RawInsn) -> bool:
        op   = (insn.word >> 26) & 0x3F
        hint = (insn.word >> 14) & 0x3
        return op == _A_OP_JMP and hint == 2   # RET

    def is_unconditional_branch(self, insn: RawInsn) -> bool:
        op = (insn.word >> 26) & 0x3F
        return op == _A_OP_BR

    def is_conditional_branch(self, insn: RawInsn) -> bool:
        return ((insn.word >> 26) & 0x3F) in _A_COND_BRANCH_OPS

    def branch_target(self, insn: RawInsn) -> Optional[int]:
        op = (insn.word >> 26) & 0x3F
        if op in (_A_OP_BR, _A_OP_BSR, *_A_COND_BRANCH_OPS):
            disp = insn.word & 0x1FFFFF
            if disp >= (1 << 20):
                disp -= (1 << 21)
            return (insn.address + 4) + disp * 4
        return None

    def is_call(self, insn: RawInsn) -> bool:
        op   = (insn.word >> 26) & 0x3F
        hint = (insn.word >> 14) & 0x3
        # BSR is the standard call instruction; JSR (op=0x1A hint=1) is indirect call
        return op == _A_OP_BSR or (op == _A_OP_JMP and hint == 1)

    def call_clobbers(self) -> List[str]:
        return list(_ALPHA_CALLER_SAVE)

    def dest_reg(self, insn: RawInsn) -> Optional[str]:
        """
        Return the name of the register written by this instruction, or None.

        Alpha has two destination positions:
          - Ra [25:21]: written by loads (LDA/LDQ/etc.) and BSR/BR/JMP
          - Rc [4:0]:   written by integer/FP operate instructions (0x10-0x17)
        """
        op = (insn.word >> 26) & 0x3F
        ra = (insn.word >> 21) & 0x1F
        rc = insn.word & 0x1F

        # Integer/FP operate: dest = Rc
        if op in _A_IOPS:
            return f'r{rc}' if rc != 31 else None

        # Loads: dest = Ra
        if op in _A_LOAD_OPS:
            return f'r{ra}' if ra != 31 else None

        # Stores: no GPR written
        if op in _A_STORE_OPS:
            return None

        # BSR / BR: Ra is written with the return address
        if op in (_A_OP_BSR, _A_OP_BR):
            return f'r{ra}' if ra != 31 else None

        # JMP/JSR/RET/JSR_CO: Ra is written with PC+4 (return address)
        if op == _A_OP_JMP:
            return f'r{ra}' if ra != 31 else None

        # Conditional branches: Ra is READ (tested), not written
        if op in _A_COND_BRANCH_OPS:
            return None

        # PAL, MISC, SEXT and other catch-alls — conservatively no GPR dest
        return None

    def pc_relative_load(self, insn: RawInsn) -> Optional[Tuple[str, int]]:
        # Alpha uses GP-relative addressing (LDA/LDQ with $gp=r29),
        # not PC-relative pools. The existing trace_arg() handles GP reads.
        return None

    def all_regs(self) -> List[str]:
        return [f'r{i}' for i in range(32)]


# ══════════════════════════════════════════════════════════════════════════════
# x86-64 — System V AMD64 ABI, Capstone
# ══════════════════════════════════════════════════════════════════════════════

class X86_64Config(ArchConfig):
    """ArchConfig for x86-64 (System V AMD64)."""

    _CALL_MN = frozenset(['call', 'callq'])
    _RET_MN  = frozenset(['ret', 'retq', 'retn'])

    def __init__(self) -> None:
        self._cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._cs.detail = True
        self._cs.skipdata = True

    def cs(self):
        return self._cs

    def _mn(self, insn) -> str:
        return insn.mnemonic.lower()

    def is_return(self, insn) -> bool:
        return self._mn(insn) in self._RET_MN

    def is_unconditional_branch(self, insn) -> bool:
        return self._mn(insn) == 'jmp'

    def is_conditional_branch(self, insn) -> bool:
        mn = self._mn(insn)
        return mn.startswith('j') and mn != 'jmp' and mn not in self._CALL_MN

    def branch_target(self, insn) -> Optional[int]:
        try:
            for op in insn.operands:
                if op.type == C_X86.X86_OP_IMM:
                    return op.imm
        except Exception:
            pass
        return None

    def is_call(self, insn) -> bool:
        return self._mn(insn) in self._CALL_MN

    def call_clobbers(self) -> List[str]:
        # SysV AMD64: caller-save = rax, rcx, rdx, rsi, rdi, r8-r11
        return ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']

    def dest_reg(self, insn) -> Optional[str]:
        mn = self._mn(insn)
        if mn.startswith(('mov', 'lea', 'add', 'sub', 'and', 'or', 'xor',
                           'shl', 'shr', 'sar', 'imul', 'neg', 'not',
                           'pop', 'xchg', 'movsx', 'movzx', 'cdqe', 'cbw')):
            try:
                if insn.operands:
                    op0 = insn.operands[0]
                    if op0.type == C_X86.X86_OP_REG:
                        name = insn.reg_name(op0.reg).lower()
                        return _x86_canon(name)
            except Exception:
                pass
        return None

    def pc_relative_load(self, insn) -> Optional[Tuple[str, int]]:
        # RIP-relative loads: MOV rax, [rip + disp]
        mn = self._mn(insn)
        if not mn.startswith(('mov', 'lea')):
            return None
        try:
            if len(insn.operands) < 2:
                return None
            op1 = insn.operands[1]
            if op1.type == C_X86.X86_OP_MEM:
                if op1.mem.base == C_X86.X86_REG_RIP:
                    rd = _x86_canon(insn.reg_name(insn.operands[0].reg).lower())
                    pool_addr = insn.address + insn.size + op1.mem.disp
                    return (rd, pool_addr)
        except Exception:
            pass
        return None

    def all_regs(self) -> List[str]:
        return (
            ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp']
            + [f'r{i}' for i in range(8, 16)]
        )


def _x86_canon(name: str) -> str:
    """Canonicalise x86 register to 64-bit name (eax → rax, r8d → r8, etc.)."""
    _32to64 = {
        'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
        'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
    }
    if name in _32to64:
        return _32to64[name]
    if name.endswith('d') and name[:-1] in ('r8','r9','r10','r11','r12','r13','r14','r15'):
        return name[:-1]
    if name.endswith(('b', 'w')) and len(name) >= 3:
        # ah/al/bh/bl etc. — just return as-is for now
        pass
    return name


# ══════════════════════════════════════════════════════════════════════════════
# PPC64 BE — IBM POWER64 big-endian (ELFv1/ELFv2), Capstone
# ══════════════════════════════════════════════════════════════════════════════

class PPC64BEConfig(ArchConfig):
    """
    ArchConfig for IBM POWER64 big-endian (AIX, Linux ELFv1/ELFv2).
    Uses Capstone CS_ARCH_PPC, CS_MODE_64 + CS_MODE_BIG_ENDIAN.
    """

    def __init__(self) -> None:
        self._cs = capstone.Cs(
            capstone.CS_ARCH_PPC,
            capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN,
        )
        self._cs.detail = True
        self._cs.skipdata = True

    def cs(self):
        return self._cs

    def _mn(self, insn) -> str:
        return insn.mnemonic.lower()

    def is_return(self, insn) -> bool:
        # BLR = branch to LR (return). Also BLRL (branch to LR + link, rare).
        return self._mn(insn) in ('blr', 'blrl', 'bctr')

    def is_unconditional_branch(self, insn) -> bool:
        mn = self._mn(insn)
        return mn == 'b' or (mn.startswith('b') and mn.endswith('a') and len(mn) == 2)

    def is_conditional_branch(self, insn) -> bool:
        mn = self._mn(insn)
        # BC, BCLR, BCT variants — anything starting with 'b' that isn't a call
        # and isn't unconditional
        if mn in ('b', 'ba', 'bl', 'bla', 'blr', 'blrl', 'bctr', 'bctrl'):
            return False
        return mn.startswith('b') and 'l' not in mn[1:]  # no 'l' (link) means not a call

    def branch_target(self, insn) -> Optional[int]:
        try:
            for op in insn.operands:
                import capstone.ppc as C_PPC
                if op.type == C_PPC.PPC_OP_IMM:
                    return op.imm
        except Exception:
            pass
        return None

    def is_call(self, insn) -> bool:
        mn = self._mn(insn)
        # BL / BLA (branch+link); BCTRL (branch to CTR + link)
        return mn in ('bl', 'bla', 'bctrl') or (mn.startswith('bl') and len(mn) <= 4)

    def call_clobbers(self) -> List[str]:
        # POWER64 ABI: r0–r12 are volatile (caller-save)
        return [f'r{i}' for i in range(13)] + ['lr', 'ctr', 'xer']

    def dest_reg(self, insn) -> Optional[str]:
        mn = self._mn(insn)
        if mn.startswith(('st', 'cmp', 'b', 'mtl', 'mtc')):
            return None
        try:
            if insn.operands:
                import capstone.ppc as C_PPC
                op0 = insn.operands[0]
                if op0.type == C_PPC.PPC_OP_REG:
                    return insn.reg_name(op0.reg).lower()
        except Exception:
            pass
        return None

    def pc_relative_load(self, insn) -> Optional[Tuple[str, int]]:
        # POWER64 uses TOC-relative loads, not PC pools. Not handled here.
        return None

    def all_regs(self) -> List[str]:
        return [f'r{i}' for i in range(32)] + ['lr', 'ctr', 'xer', 'cr']
