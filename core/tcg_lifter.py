#!/usr/bin/env python3
"""
TCG IR Lifter and QEMU Emulation Bridge
Synthesized from: QEMU TCG backend-ops specification, QEMU source (tcg/README),
                  ARM 64-Bit Assembly Language (9780128192221),
                  Foundations of ARM64 Linux Debugging (9781484290828)

QEMU TCG (Tiny Code Generator) is QEMU's JIT compiler backend.
Architecture:
  Guest (ARM64) -> TCG frontend -> TCG IR -> TCG backend -> Host (x86-64)

TCG IR is architecture-neutral SSA-like intermediate representation.
This module provides:
  1. QEMU user-mode emulation bridge (run ARM64 code on x86 via qemu-aarch64)
  2. A lightweight ARM64→TCG-IR lifter built on capstone output
  3. TCG IR analysis: memory access patterns, branch conditions, call graphs

Key TCG IR concepts:
  - Temporaries: typed SSA values (TCGv_i32, TCGv_i64, TCGv_ptr)
  - Ops: add_i64, sub_i64, ld_i64, st_i64, brcond_i64, call, exit_tb
  - Labels: branch targets within translation blocks
  - Translation Blocks (TBs): sequences of instructions ending at branch/call

QEMU flags for analysis:
  qemu-aarch64 -d in_asm          # guest disassembly
  qemu-aarch64 -d op              # TCG IR ops (one TB at a time)
  qemu-aarch64 -d op_opt          # optimized TCG IR
  qemu-aarch64 -d out_asm         # host code generated
  qemu-aarch64 -d exec            # execution trace (slow)
  qemu-aarch64 -d cpu             # CPU state after each TB
"""

import re
import subprocess
import shutil
import json
from pathlib import Path
from typing import Optional

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
    from capstone.arm64_const import (
        ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM,
        ARM64_REG_X29, ARM64_REG_X30, ARM64_REG_SP,
    )
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


# ── TCG IR op definitions ─────────────────────────────────────────────────────
# From QEMU Documentation/TCG/backend-ops and tcg/README

TCG_OPS = {
    # ── Host memory load ops (CPU register state, CPUState struct) ───────────
    # These access host memory — used for saving/restoring CPU registers.
    # NOT for guest process memory (use QEMU_LD* for that).
    'ld8s_i32':  {'desc': 'LD8S: Load 8-bit signed from host mem, sign-extend to i32',   'mem': 'host_load', 'width': 8},
    'ld8u_i32':  {'desc': 'LD8U: Load 8-bit unsigned from host mem, zero-extend to i32', 'mem': 'host_load', 'width': 8},
    'ld16s_i32': {'desc': 'LD16S: Load 16-bit signed, sign-extend to i32',               'mem': 'host_load', 'width': 16},
    'ld16u_i32': {'desc': 'LD16U: Load 16-bit unsigned, zero-extend to i32',             'mem': 'host_load', 'width': 16},
    'ld_i32':    {'desc': 'LD: Load native-sized (32-bit target) from host mem',         'mem': 'host_load', 'width': 32},
    'ld8s_i64':  {'desc': 'LD8S: Load 8-bit signed from host mem, sign-extend to i64',   'mem': 'host_load', 'width': 8},
    'ld8u_i64':  {'desc': 'LD8U: Load 8-bit unsigned from host mem, zero-extend to i64', 'mem': 'host_load', 'width': 8},
    'ld16s_i64': {'desc': 'LD16S: Load 16-bit signed, sign-extend to i64',               'mem': 'host_load', 'width': 16},
    'ld16u_i64': {'desc': 'LD16U: Load 16-bit unsigned, zero-extend to i64',             'mem': 'host_load', 'width': 16},
    'ld32s_i64': {'desc': 'LD32S: Load 32-bit signed, sign-extend to i64',               'mem': 'host_load', 'width': 32},
    'ld32u_i64': {'desc': 'LD32U: Load 32-bit unsigned, zero-extend to i64',             'mem': 'host_load', 'width': 32},
    'ld_i64':    {'desc': 'LD64: Load 64-bit from host memory',                          'mem': 'host_load', 'width': 64},
    # Host memory store ops
    'st8_i32':  {'desc': 'ST8: Store 8-bit to host mem (from i32)',  'mem': 'host_store', 'width': 8},
    'st16_i32': {'desc': 'ST16: Store 16-bit to host mem (from i32)', 'mem': 'host_store', 'width': 16},
    'st_i32':   {'desc': 'ST: Store 32-bit to host mem',              'mem': 'host_store', 'width': 32},
    'st8_i64':  {'desc': 'ST8: Store 8-bit to host mem (from i64)',  'mem': 'host_store', 'width': 8},
    'st16_i64': {'desc': 'ST16: Store 16-bit to host mem (from i64)', 'mem': 'host_store', 'width': 16},
    'st32_i64': {'desc': 'ST32: Store 32-bit to host mem (from i64)', 'mem': 'host_store', 'width': 32},
    'st_i64':   {'desc': 'ST: Store 64-bit to host mem',              'mem': 'host_store', 'width': 64},
    # ── Target (guest process) memory ops — QEMU_LD/QEMU_ST ──────────────
    # These go through QEMU's TLB/MMU. Address is arg1; memidx=0 for user mode.
    # ARM64 LDR/STR instructions lift to these, NOT to the LD/ST family above.
    'qemu_ld8s':  {'desc': 'QEMU_LD8S: Guest mem load 8-bit signed',       'mem': 'guest_load', 'width': 8},
    'qemu_ld8u':  {'desc': 'QEMU_LD8U: Guest mem load 8-bit unsigned',     'mem': 'guest_load', 'width': 8},
    'qemu_ld16s': {'desc': 'QEMU_LD16S: Guest mem load 16-bit signed',     'mem': 'guest_load', 'width': 16},
    'qemu_ld16u': {'desc': 'QEMU_LD16U: Guest mem load 16-bit unsigned',   'mem': 'guest_load', 'width': 16},
    'qemu_ld32s': {'desc': 'QEMU_LD32S: Guest mem load 32-bit signed',     'mem': 'guest_load', 'width': 32},
    'qemu_ld32u': {'desc': 'QEMU_LD32U: Guest mem load 32-bit unsigned',   'mem': 'guest_load', 'width': 32},
    'qemu_ld64':  {'desc': 'QEMU_LD64: Guest mem load 64-bit',             'mem': 'guest_load', 'width': 64},
    'qemu_st8':   {'desc': 'QEMU_ST8: Guest mem store 8-bit',              'mem': 'guest_store', 'width': 8},
    'qemu_st16':  {'desc': 'QEMU_ST16: Guest mem store 16-bit',            'mem': 'guest_store', 'width': 16},
    'qemu_st32':  {'desc': 'QEMU_ST32: Guest mem store 32-bit',            'mem': 'guest_store', 'width': 32},
    'qemu_st64':  {'desc': 'QEMU_ST64: Guest mem store 64-bit',            'mem': 'guest_store', 'width': 64},
    # Arithmetic ops
    'add_i32': {'desc': 'a = b + c (i32)',  'arith': True},
    'add_i64': {'desc': 'a = b + c (i64)',  'arith': True},
    'sub_i32': {'desc': 'a = b - c (i32)',  'arith': True},
    'sub_i64': {'desc': 'a = b - c (i64)',  'arith': True},
    'mul_i32': {'desc': 'a = b * c (i32)',  'arith': True},
    'mul_i64': {'desc': 'a = b * c (i64)',  'arith': True},
    'div_i32': {'desc': 'a = b / c signed (i32)',  'arith': True},
    'div_i64': {'desc': 'a = b / c signed (i64)',  'arith': True},
    'divu_i32': {'desc': 'a = b / c unsigned (i32)', 'arith': True},
    'divu_i64': {'desc': 'a = b / c unsigned (i64)', 'arith': True},
    'rem_i32': {'desc': 'a = b %% c signed (i32)', 'arith': True},
    'rem_i64': {'desc': 'a = b %% c signed (i64)', 'arith': True},
    # Bitwise ops
    'and_i32': {'desc': 'a = b & c (i32)',  'bitwise': True},
    'and_i64': {'desc': 'a = b & c (i64)',  'bitwise': True},
    'or_i32':  {'desc': 'a = b | c (i32)',  'bitwise': True},
    'or_i64':  {'desc': 'a = b | c (i64)',  'bitwise': True},
    'xor_i32': {'desc': 'a = b ^ c (i32)',  'bitwise': True},
    'xor_i64': {'desc': 'a = b ^ c (i64)',  'bitwise': True},
    'not_i32': {'desc': 'a = ~b (i32)',     'bitwise': True},
    'not_i64': {'desc': 'a = ~b (i64)',     'bitwise': True},
    'neg_i32': {'desc': 'a = -b (i32)',     'bitwise': True},
    'neg_i64': {'desc': 'a = -b (i64)',     'bitwise': True},
    # Shift ops
    'shl_i32': {'desc': 'a = b << c (i32, logical)', 'shift': True},
    'shl_i64': {'desc': 'a = b << c (i64, logical)', 'shift': True},
    'shr_i32': {'desc': 'a = b >> c (i32, logical)', 'shift': True},
    'shr_i64': {'desc': 'a = b >> c (i64, logical)', 'shift': True},
    'sar_i32': {'desc': 'a = b >> c (i32, arithmetic)', 'shift': True},
    'sar_i64': {'desc': 'a = b >> c (i64, arithmetic)', 'shift': True},
    'rotl_i32': {'desc': 'a = rotate_left(b, c) i32', 'shift': True},
    'rotl_i64': {'desc': 'a = rotate_left(b, c) i64', 'shift': True},
    'rotr_i32': {'desc': 'a = rotate_right(b, c) i32', 'shift': True},
    'rotr_i64': {'desc': 'a = rotate_right(b, c) i64', 'shift': True},
    # Branch ops
    'br':        {'desc': 'Unconditional branch to label',   'branch': True},
    'brcond_i32': {'desc': 'Branch if cond(a, b) i32',       'branch': True, 'conditional': True},
    'brcond_i64': {'desc': 'Branch if cond(a, b) i64',       'branch': True, 'conditional': True},
    'exit_tb':   {'desc': 'Exit current translation block',  'branch': True},
    'goto_tb':   {'desc': 'Chained TB transition',           'branch': True},
    # Compare/select ops
    'setcond_i32':  {'desc': 'a = (cond(b,c)) ? 1 : 0 (i32)', 'compare': True},
    'setcond_i64':  {'desc': 'a = (cond(b,c)) ? 1 : 0 (i64)', 'compare': True},
    'movcond_i32':  {'desc': 'a = cond(b,c) ? d : e (i32)',    'compare': True},
    'movcond_i64':  {'desc': 'a = cond(b,c) ? d : e (i64)',    'compare': True},
    # Type conversion ops
    'ext8s_i32':   {'desc': 'Sign-extend 8-bit to i32',  'convert': True},
    'ext8s_i64':   {'desc': 'Sign-extend 8-bit to i64',  'convert': True},
    'ext16s_i32':  {'desc': 'Sign-extend 16-bit to i32', 'convert': True},
    'ext16s_i64':  {'desc': 'Sign-extend 16-bit to i64', 'convert': True},
    'ext32s_i64':  {'desc': 'Sign-extend 32-bit to i64', 'convert': True},
    'ext8u_i32':   {'desc': 'Zero-extend 8-bit to i32',  'convert': True},
    'ext8u_i64':   {'desc': 'Zero-extend 8-bit to i64',  'convert': True},
    'ext16u_i32':  {'desc': 'Zero-extend 16-bit to i32', 'convert': True},
    'ext16u_i64':  {'desc': 'Zero-extend 16-bit to i64', 'convert': True},
    'ext32u_i64':  {'desc': 'Zero-extend 32-bit to i64', 'convert': True},
    'trunc_shr_i32_i64': {'desc': 'Truncate i64 to i32 with shift', 'convert': True},
    # Move ops
    'mov_i32': {'desc': 'a = b (i32)', 'move': True},
    'mov_i64': {'desc': 'a = b (i64)', 'move': True},
    'movi_i32': {'desc': 'a = immediate (i32)', 'move': True},
    'movi_i64': {'desc': 'a = immediate (i64)', 'move': True},
    # Call op
    'call': {'desc': 'Call helper function (C ABI)', 'call': True},
    # Misc
    'nop':    {'desc': 'No operation'},
    'discard': {'desc': 'Value is dead — optimizer hint'},
}

# TCG condition codes (used in brcond/setcond/movcond)
TCG_CONDS = {
    0:  'NEVER', 1:  'ALWAYS',
    2:  'EQ',    3:  'NE',
    4:  'LT',    5:  'GE',    # signed
    6:  'LE',    7:  'GT',    # signed
    8:  'LTU',   9:  'GEU',   # unsigned
    10: 'LEU',   11: 'GTU',   # unsigned
    12: 'TSTEQ', 13: 'TSTNE', # test bits
}


# ── ARM64 → TCG IR lifter ─────────────────────────────────────────────────────

class TCGTemp:
    """Represents a TCG temporary value (SSA node)."""
    _counter = 0

    def __init__(self, width=64, name=None):
        TCGTemp._counter += 1
        self.id    = TCGTemp._counter
        self.width = width
        self.name  = name or f't{self.id}'

    def __repr__(self):
        return f'tmp_{self.name}_i{self.width}'


class TCGOp:
    """A single TCG IR operation."""

    def __init__(self, op, args=None, comment=None):
        self.op      = op
        self.args    = args or []
        self.comment = comment

    def __repr__(self):
        args_str = ', '.join(str(a) for a in self.args)
        comment  = f'  ; {self.comment}' if self.comment else ''
        return f'{self.op}({args_str}){comment}'


class ARM64TCGLifter:
    """Lift ARM64 instructions to TCG IR using capstone for decoding.

    This is a semantic lifter — it produces TCG-like IR that describes
    what each instruction DOES (reads/writes memory, computes values)
    rather than just what it is syntactically.

    Useful for:
    - Taint tracking: which values flow from user-controlled inputs
    - Memory access pattern analysis: which addresses are read/written
    - Symbolic execution: propagate symbolic values through IR
    - Side-channel analysis: identify secret-dependent branches
    """

    # ARM64 register name → TCG variable name
    REG_NAMES = {
        'x0': 'r0',   'x1': 'r1',   'x2': 'r2',   'x3': 'r3',
        'x4': 'r4',   'x5': 'r5',   'x6': 'r6',   'x7': 'r7',
        'x8': 'r8',   'x9': 'r9',   'x10': 'r10', 'x11': 'r11',
        'x12': 'r12', 'x13': 'r13', 'x14': 'r14', 'x15': 'r15',
        'x16': 'r16', 'x17': 'r17', 'x18': 'r18', 'x19': 'r19',
        'x20': 'r20', 'x21': 'r21', 'x22': 'r22', 'x23': 'r23',
        'x24': 'r24', 'x25': 'r25', 'x26': 'r26', 'x27': 'r27',
        'x28': 'r28', 'x29': 'fp',  'x30': 'lr',
        'sp':  'sp',  'xzr': 'zero',
        # 32-bit aliases (W regs) — same storage, width=32
        'w0': 'r0',   'w1': 'r1',   'w2': 'r2',   'w3': 'r3',
        'w4': 'r4',   'w5': 'r5',   'w6': 'r6',   'w7': 'r7',
        'w8': 'r8',   'w9': 'r9',   'w10': 'r10', 'w11': 'r11',
        'w12': 'r12', 'w13': 'r13', 'w14': 'r14', 'w15': 'r15',
        'w16': 'r16', 'w17': 'r17', 'w18': 'r18', 'w19': 'r19',
        'w20': 'r20', 'w21': 'r21', 'w22': 'r22', 'w23': 'r23',
        'w24': 'r24', 'w25': 'r25', 'w26': 'r26', 'w27': 'r27',
        'w28': 'r28', 'w29': 'fp',  'w30': 'lr',  'wzr': 'zero',
    }

    def __init__(self):
        self.ops: list[TCGOp] = []
        self.md = None
        if HAS_CAPSTONE:
            self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.md.detail = True

    def _reg(self, name: str) -> str:
        return self.REG_NAMES.get(name.lower(), name)

    def _width(self, reg: str) -> int:
        return 32 if reg.lower().startswith('w') else 64

    def _emit(self, op: str, *args, comment=None):
        self.ops.append(TCGOp(op, list(args), comment))

    def lift_instruction(self, insn) -> list:
        """Lift a single capstone ARM64 instruction to TCG ops."""
        start_idx = len(self.ops)
        mnem = insn.mnemonic.lower()
        ops  = insn.operands if insn.detail else []

        comment = f'{hex(insn.address)}: {insn.mnemonic} {insn.op_str}'

        # ── MOV / MOVZ / MOVK ─────────────────────────────────────────────
        if mnem in ('mov', 'movz'):
            if len(ops) >= 2:
                dst = self._reg(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else '?'
                w   = self._width(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else 64
                if ops[1].type == ARM64_OP_IMM:
                    self._emit(f'movi_i{w}', dst, ops[1].imm, comment=comment)
                elif ops[1].type == ARM64_OP_REG:
                    src = self._reg(insn.reg_name(ops[1].reg))
                    self._emit(f'mov_i{w}', dst, src, comment=comment)

        # ── ADD / SUB ──────────────────────────────────────────────────────
        elif mnem in ('add', 'sub', 'adds', 'subs'):
            if len(ops) >= 3:
                dst  = self._reg(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else '?'
                src1 = self._reg(insn.reg_name(ops[1].reg)) if ops[1].type == ARM64_OP_REG else '?'
                w    = self._width(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else 64
                op_name = 'sub' if mnem.startswith('sub') else 'add'
                if ops[2].type == ARM64_OP_IMM:
                    t = TCGTemp(w)
                    self._emit(f'movi_i{w}', t, ops[2].imm)
                    self._emit(f'{op_name}_i{w}', dst, src1, t, comment=comment)
                elif ops[2].type == ARM64_OP_REG:
                    src2 = self._reg(insn.reg_name(ops[2].reg))
                    self._emit(f'{op_name}_i{w}', dst, src1, src2, comment=comment)

        # ── AND / ORR / EOR (XOR) ─────────────────────────────────────────
        elif mnem in ('and', 'orr', 'eor', 'ands', 'eors'):
            op_map = {'and': 'and', 'ands': 'and', 'orr': 'or', 'eor': 'xor', 'eors': 'xor'}
            if len(ops) >= 3:
                dst  = self._reg(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else '?'
                src1 = self._reg(insn.reg_name(ops[1].reg)) if ops[1].type == ARM64_OP_REG else '?'
                w    = self._width(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else 64
                tcg_op = op_map.get(mnem, 'and')
                if ops[2].type == ARM64_OP_IMM:
                    t = TCGTemp(w)
                    self._emit(f'movi_i{w}', t, ops[2].imm)
                    self._emit(f'{tcg_op}_i{w}', dst, src1, t, comment=comment)
                elif ops[2].type == ARM64_OP_REG:
                    src2 = self._reg(insn.reg_name(ops[2].reg))
                    self._emit(f'{tcg_op}_i{w}', dst, src1, src2, comment=comment)

        # ── LSL / LSR / ASR ────────────────────────────────────────────────
        elif mnem in ('lsl', 'lsr', 'asr'):
            op_map = {'lsl': 'shl', 'lsr': 'shr', 'asr': 'sar'}
            if len(ops) >= 3:
                dst  = self._reg(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else '?'
                src  = self._reg(insn.reg_name(ops[1].reg)) if ops[1].type == ARM64_OP_REG else '?'
                w    = self._width(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else 64
                if ops[2].type == ARM64_OP_IMM:
                    t = TCGTemp(w)
                    self._emit(f'movi_i{w}', t, ops[2].imm)
                    self._emit(f'{op_map[mnem]}_i{w}', dst, src, t, comment=comment)

        # ── LDR / LDRB / LDRH / LDRSB / LDRSH / LDRSW ────────────────────
        elif mnem.startswith('ldr') or mnem in ('ldar', 'ldaxr', 'ldxr', 'ldp'):
            if len(ops) >= 2:
                dst = self._reg(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else '?'
                if ops[-1].type == ARM64_OP_MEM:
                    mem = ops[-1].mem
                    base = self._reg(insn.reg_name(mem.base)) if mem.base else 'sp'
                    disp = mem.disp
                    width_map = {'ldrb': 8, 'ldrh': 16, 'ldrsb': 8, 'ldrsh': 16, 'ldrsw': 32}
                    w = width_map.get(mnem, 64)
                    sign = 's' if mnem.startswith('ldrs') else 'u'
                    signed_suffix = '' if w == 64 else f'{sign}'
                    op_name = f'ld{w if w < 64 else ""}{signed_suffix}_i64'
                    if w == 64:
                        op_name = 'ld_i64'
                    t = TCGTemp(64)
                    self._emit(f'movi_i64', t, disp)
                    self._emit(f'add_i64', 'addr_tmp', base, t)
                    self._emit(op_name, dst, 'addr_tmp', 0, comment=comment)

        # ── STR / STRB / STRH / STP ────────────────────────────────────────
        elif mnem.startswith('str') or mnem in ('stlr', 'stlxr', 'stxr', 'stp'):
            if len(ops) >= 2:
                src = self._reg(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else '?'
                if ops[-1].type == ARM64_OP_MEM:
                    mem = ops[-1].mem
                    base = self._reg(insn.reg_name(mem.base)) if mem.base else 'sp'
                    disp = mem.disp
                    width_map = {'strb': 8, 'strh': 16}
                    w = width_map.get(mnem, 64)
                    op_name = f'st{w if w < 64 else ""}_i64' if w < 64 else 'st_i64'
                    t = TCGTemp(64)
                    self._emit(f'movi_i64', t, disp)
                    self._emit(f'add_i64', 'addr_tmp', base, t)
                    self._emit(op_name, src, 'addr_tmp', 0, comment=comment)

        # ── Branch instructions ─────────────────────────────────────────────
        elif mnem == 'bl':
            if ops and ops[0].type == ARM64_OP_IMM:
                self._emit('call', hex(ops[0].imm), comment=comment)

        elif mnem == 'blr':
            if ops and ops[0].type == ARM64_OP_REG:
                reg = self._reg(insn.reg_name(ops[0].reg))
                self._emit('call', reg, comment=comment)  # indirect call

        elif mnem == 'ret':
            self._emit('exit_tb', 'lr', comment=comment)

        elif mnem == 'b':
            if ops and ops[0].type == ARM64_OP_IMM:
                self._emit('br', hex(ops[0].imm), comment=comment)

        elif mnem.startswith('b.') or mnem in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            cond_map = {
                'b.eq': 'EQ', 'b.ne': 'NE', 'b.lt': 'LT', 'b.gt': 'GT',
                'b.le': 'LE', 'b.ge': 'GE', 'b.lo': 'LTU', 'b.hi': 'GTU',
                'b.ls': 'LEU', 'b.hs': 'GEU', 'b.mi': 'LT', 'b.pl': 'GE',
                'cbz': 'EQ', 'cbnz': 'NE', 'tbz': 'TSTEQ', 'tbnz': 'TSTNE',
            }
            cond = cond_map.get(mnem, 'NE')
            target = hex(ops[-1].imm) if ops and ops[-1].type == ARM64_OP_IMM else '?'
            reg = self._reg(insn.reg_name(ops[0].reg)) if ops and ops[0].type == ARM64_OP_REG else '?'
            self._emit('brcond_i64', reg, 0, cond, target, comment=comment)

        # ── Comparisons ────────────────────────────────────────────────────
        elif mnem in ('cmp', 'cmn', 'tst'):
            if len(ops) >= 2:
                src1 = self._reg(insn.reg_name(ops[0].reg)) if ops[0].type == ARM64_OP_REG else '?'
                if ops[1].type == ARM64_OP_IMM:
                    t = TCGTemp(64)
                    self._emit('movi_i64', t, ops[1].imm)
                    self._emit('setcond_i64', 'flags', src1, t, 'EQ', comment=comment)
                elif ops[1].type == ARM64_OP_REG:
                    src2 = self._reg(insn.reg_name(ops[1].reg))
                    self._emit('setcond_i64', 'flags', src1, src2, 'EQ', comment=comment)

        else:
            # Unlifted — emit a placeholder
            self._emit('nop', comment=comment)

        return self.ops[start_idx:]

    def lift_basic_block(self, code: bytes, base_addr: int = 0) -> list:
        """Lift a sequence of ARM64 bytes to TCG IR ops."""
        if not HAS_CAPSTONE or not self.md:
            return []

        self.ops = []
        for insn in self.md.disasm(code, base_addr):
            self.lift_instruction(insn)

        return self.ops

    def analyze_memory_access(self) -> dict:
        """Summarize memory read/write patterns from lifted IR."""
        loads  = [op for op in self.ops if op.op.startswith('ld')]
        stores = [op for op in self.ops if op.op.startswith('st')]
        calls  = [op for op in self.ops if op.op == 'call']
        branches = [op for op in self.ops if op.op in ('br', 'brcond_i64', 'brcond_i32', 'exit_tb')]

        return {
            'load_count':    len(loads),
            'store_count':   len(stores),
            'call_count':    len(calls),
            'branch_count':  len(branches),
            'call_targets':  [op.args[0] for op in calls if op.args],
            'branch_targets': [op.args[3] for op in branches if len(op.args) > 3],
        }


# ── QEMU user-mode emulation bridge ──────────────────────────────────────────

class QEMUBridge:
    """Interface to qemu-aarch64 user-mode emulation for ARM64 binary analysis."""

    QEMU_BIN = shutil.which('qemu-aarch64') or '/usr/bin/qemu-aarch64'

    def __init__(self, binary_path: str, library_path: str = None):
        self.binary   = binary_path
        self.lib_path = library_path or '/lib/aarch64-linux-gnu'
        self.available = bool(shutil.which('qemu-aarch64') or Path('/usr/bin/qemu-aarch64').exists())

    def is_available(self) -> bool:
        return self.available

    def get_tcg_ir(self, args: list = None, timeout: int = 10) -> dict:
        """Run binary under QEMU with -d op_opt to capture TCG IR output.

        Returns dict with raw TCG IR text and parsed translation blocks.
        """
        if not self.available:
            return {'error': 'qemu-aarch64 not found'}

        cmd = [
            self.QEMU_BIN,
            '-L', self.lib_path,
            '-d', 'op_opt',     # optimized TCG IR output
            '-D', '/tmp/ablation-qemu-tcg.log',
        ]
        if args:
            cmd += [self.binary] + args
        else:
            cmd += [self.binary, '--help']

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            log_path = Path('/tmp/ablation-qemu-tcg.log')
            raw_tcg = log_path.read_text() if log_path.exists() else ''
            return {
                'raw_tcg': raw_tcg[:50000],  # cap at 50KB
                'returncode': result.returncode,
                'stderr': result.stderr[:2000],
                'tb_count': raw_tcg.count('Translation block'),
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Timeout running QEMU'}
        except Exception as e:
            return {'error': str(e)}

    def get_execution_trace(self, args: list = None, timeout: int = 10) -> list:
        """Capture instruction-level execution trace via QEMU -d in_asm."""
        if not self.available:
            return []

        cmd = [
            self.QEMU_BIN,
            '-L', self.lib_path,
            '-d', 'in_asm',
            '-D', '/tmp/ablation-qemu-trace.log',
            self.binary,
        ]
        if args:
            cmd += args

        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout)
            log_path = Path('/tmp/ablation-qemu-trace.log')
            if not log_path.exists():
                return []

            trace = []
            for line in log_path.read_text().splitlines():
                m = re.match(r'^0x([0-9a-f]+):\s+(.+)$', line)
                if m:
                    trace.append({'addr': int(m.group(1), 16), 'insn': m.group(2).strip()})
            return trace

        except Exception:
            return []

    def parse_tcg_ops(self, raw_tcg: str) -> list:
        """Parse raw QEMU TCG IR output into structured translation blocks."""
        blocks = []
        current_block = None
        current_ops = []

        for line in raw_tcg.splitlines():
            line = line.strip()

            # Translation block header: "-------\nIN:\nTranslation block 0x..."
            if line.startswith('IN:') or 'Translation block' in line:
                if current_block is not None and current_ops:
                    current_block['ops'] = current_ops
                    blocks.append(current_block)

                addr_m = re.search(r'0x([0-9a-f]+)', line)
                addr = int(addr_m.group(1), 16) if addr_m else 0
                current_block = {'addr': hex(addr), 'ops': []}
                current_ops = []

            elif current_block is not None and line:
                # TCG op line: " add_i64 tmp0,tmp1,tmp2"
                parts = line.split(None, 1)
                if parts and parts[0] in TCG_OPS:
                    args = parts[1].split(',') if len(parts) > 1 else []
                    current_ops.append({'op': parts[0], 'args': args})
                elif line.startswith('0x'):
                    # Assembly annotation
                    current_ops.append({'op': 'asm', 'args': [line]})

        if current_block is not None and current_ops:
            current_block['ops'] = current_ops
            blocks.append(current_block)

        return blocks


def analyze_with_tcg(binary_path: str, args: list = None) -> dict:
    """Full pipeline: QEMU emulation + TCG IR capture + analysis."""
    bridge = QEMUBridge(binary_path)
    result = {'binary': binary_path, 'qemu_available': bridge.is_available()}

    if bridge.is_available():
        tcg_result = bridge.get_tcg_ir(args)
        result['tcg'] = tcg_result
        if tcg_result.get('raw_tcg'):
            result['translation_blocks'] = bridge.parse_tcg_ops(tcg_result['raw_tcg'])
    else:
        result['note'] = 'Install qemu-aarch64: apt install qemu-user'

    return result


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: tcg_lifter.py <arm64_binary>")
        print("       tcg_lifter.py --lift <hex_bytes> [base_addr_hex]")
        sys.exit(1)

    if sys.argv[1] == '--lift':
        # Lift raw bytes to TCG IR
        hex_bytes = sys.argv[2]
        base = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0
        code = bytes.fromhex(hex_bytes)

        lifter = ARM64TCGLifter()
        ops = lifter.lift_basic_block(code, base)

        print(f'TCG IR for {len(code)} bytes at {hex(base)}:')
        for op in ops:
            print(f'  {op}')

        summary = lifter.analyze_memory_access()
        print(f'\nSummary: {summary}')

    else:
        binary = sys.argv[1]
        result = analyze_with_tcg(binary, sys.argv[2:])
        print(json.dumps(result, indent=2))
