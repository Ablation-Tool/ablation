"""
arm32_reg_annotator.py -- AAPCS-aware forward register annotator for ARM32/Thumb.

Tracks r0-r3 at call sites: immediate constants, string pointer loads via
LDR [PC, #off] literal pool, and register copies. Produces the same
CallSite/AnnotationResult types as reg_annotator.py so FuncProfiler
can use it transparently for ARM32 binaries.

AAPCS register roles:
  r0-r3   -- argument registers + r0 = return value (all caller-saved)
  r4-r11  -- callee-saved (preserved across calls)
  r12/ip  -- call-clobbered scratch
  r13/sp, r14/lr, r15/pc -- special purpose
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone
from capstone import arm as C_ARM

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False

from .reg_annotator import RegVal, CallSite, AnnotationResult

_ARM32_ARG_REGS = ['r0', 'r1', 'r2', 'r3']
_ARM32_CALLER_SAVED = {'r0', 'r1', 'r2', 'r3', 'r12'}


class ARM32RegAnnotator:
    """
    Forward symbolic register pass for ARM32/Thumb.

    Tracks r0-r3 arg values at BL/BLX call sites within a single function.
    Handles:
      MOV Rd, #imm          -- const
      MOVW Rd, #imm16        -- const (Thumb MOVW)
      LDR Rd, [PC, #off]    -- pool literal; if pool word is a string VA, string
      MOV Rd, Rn             -- register copy
      BL/BLX #target         -- call site recorded; r0-r3, r12 clobbered after
    Does not track branches or loops (linear pass only).
    """

    def __init__(self, data: bytes, base: int, strings: Dict[int, str],
                 plt: Dict[int, str], thumb_funcs: Optional[Set[int]] = None):
        self._data = data
        self._base = base
        self._strings = strings
        self._plt = plt
        self._thumb_funcs: Set[int] = set(thumb_funcs) if thumb_funcs else set()

        # Build section map for pool dereference
        self._sec_map: List[Tuple[int, int, bytes]] = []
        if _LIEF_OK:
            try:
                binary = lief.parse(data)
                if isinstance(binary, lief.ELF.Binary):
                    for sn in ('.text', '.rodata', '.data', '.data.rel.ro'):
                        try:
                            sec = binary.get_section(sn)
                            if sec and sec.size > 0:
                                sc = bytes(sec.content)
                                sv = int(sec.virtual_address)
                                self._sec_map.append((sv, sv + len(sc), sc))
                        except Exception:
                            pass
            except Exception:
                pass

    @classmethod
    def from_path(cls, path: str, thumb_funcs: Optional[Set[int]] = None) -> 'ARM32RegAnnotator':
        data = Path(path).read_bytes()
        strings: Dict[int, str] = {}
        plt: Dict[int, str] = {}
        if _LIEF_OK:
            try:
                binary = lief.parse(data)
                if isinstance(binary, lief.ELF.Binary):
                    for sn in ('.rodata', '.data.rel.ro'):
                        try:
                            sec = binary.get_section(sn)
                            if sec:
                                sc = bytes(sec.content)
                                sv = int(sec.virtual_address)
                                i = 0
                                while i < len(sc):
                                    s = i
                                    while i < len(sc) and 0x20 <= sc[i] < 0x7f:
                                        i += 1
                                    if i - s >= 4:
                                        strings[sv + s] = sc[s:i].decode('ascii', errors='replace')
                                    else:
                                        i = s + 1
                        except Exception:
                            pass
                    # PLT
                    sym_names: List[str] = []
                    try:
                        rel_plt = binary.get_section('.rel.plt')
                        if rel_plt:
                            rd = bytes(rel_plt.content)
                            for off in range(0, len(rd) - 7, 8):
                                r_offset, r_info = struct.unpack_from('<II', rd, off)
                                sym_idx = r_info >> 8
                                try:
                                    sym = binary.dynamic_symbols[sym_idx]
                                    sym_names.append(sym.name or '')
                                except Exception:
                                    sym_names.append('')
                    except Exception:
                        pass
                    if sym_names:
                        ps = binary.get_section('.plt')
                        if ps:
                            pv = int(ps.virtual_address)
                            for i, name in enumerate(sym_names):
                                if name:
                                    plt[pv + 20 + i * 12] = name
            except Exception:
                pass
        base = 0
        if _LIEF_OK:
            try:
                binary = lief.parse(data)
                if isinstance(binary, lief.ELF.Binary):
                    base = binary.imagebase
            except Exception:
                pass
        return cls(data, base, strings, plt, thumb_funcs)

    @classmethod
    def from_context(cls, ctx) -> 'ARM32RegAnnotator':
        data = Path(ctx.path).read_bytes()
        return cls(data, ctx.base_va, ctx.strings, ctx.plt,
                   thumb_funcs=getattr(ctx, 'thumb_funcs', None))

    def annotate_calls(
        self,
        va: int,
        end_va: int,
        window: int = 2048,
        seed_args: bool = True,
    ) -> AnnotationResult:
        """
        Forward pass from va to end_va, tracking r0-r3 and recording call sites.

        seed_args: pre-seed r0=arg0, r1=arg1, r2=arg2, r3=arg3 at entry.
        """
        is_thumb = va in self._thumb_funcs
        mode = capstone.CS_MODE_THUMB if is_thumb else capstone.CS_MODE_ARM
        cs = capstone.Cs(capstone.CS_ARCH_ARM, mode)
        cs.detail = True
        cs.skipdata = True

        off = va - self._base
        size = min(end_va - va, window) if end_va > va else window
        if off < 0 or off + size > len(self._data):
            return AnnotationResult(func_va=va, func_end_va=end_va, calls=[], reg_trace=[])
        chunk = self._data[off: off + size]

        # Register state: reg_name -> RegVal
        state: Dict[str, RegVal] = {}
        if seed_args:
            for i, r in enumerate(_ARM32_ARG_REGS):
                state[r] = RegVal.arg(i)

        calls: List[CallSite] = []
        reg_trace: List[Tuple[int, str, RegVal]] = []

        for insn in cs.disasm(chunk, va):
            if insn.address >= end_va:
                break
            mn = insn.mnemonic.lower()
            try:
                ops = insn.operands
            except Exception:
                ops = []

            # MOV Rd, #imm or MOVW Rd, #imm
            if mn in ('mov', 'movw') and len(ops) == 2:
                if ops[0].type == C_ARM.ARM_OP_REG and ops[1].type == C_ARM.ARM_OP_IMM:
                    rd = insn.reg_name(ops[0].reg).lower()
                    v = RegVal.const(ops[1].imm)
                    state[rd] = v
                    reg_trace.append((insn.address, rd, v))
                    continue

            # MOV Rd, Rn (register copy)
            if mn == 'mov' and len(ops) == 2:
                if ops[0].type == C_ARM.ARM_OP_REG and ops[1].type == C_ARM.ARM_OP_REG:
                    rd = insn.reg_name(ops[0].reg).lower()
                    rn = insn.reg_name(ops[1].reg).lower()
                    v = RegVal.copy(rn, state.get(rn))
                    state[rd] = v
                    reg_trace.append((insn.address, rd, v))
                    continue

            # LDR Rd, [PC, #off] -- literal pool load
            if mn == 'ldr' and len(ops) >= 2:
                if (ops[0].type == C_ARM.ARM_OP_REG and
                        ops[1].type == C_ARM.ARM_OP_MEM and
                        insn.reg_name(ops[1].mem.base).lower() == 'pc'):
                    rd = insn.reg_name(ops[0].reg).lower()
                    disp = ops[1].mem.disp
                    if is_thumb and insn.size == 2:
                        pool_va = ((insn.address + 4) & ~3) + disp
                    elif is_thumb:
                        pool_va = insn.address + 4 + disp
                    else:
                        pool_va = insn.address + 8 + disp
                    ptr = self._read_word(pool_va)
                    if ptr is not None:
                        s = self._strings.get(ptr)
                        if s:
                            v = RegVal.string(s)
                        else:
                            v = RegVal.mem(f'[pool@0x{pool_va:x}]->0x{ptr:x}')
                        state[rd] = v
                        reg_trace.append((insn.address, rd, v))
                    continue

            # ADD Rd, Rn, #imm or ADD Rd, Rn, Rm
            if mn.startswith('add') and len(ops) >= 3:
                if ops[0].type == C_ARM.ARM_OP_REG:
                    rd = insn.reg_name(ops[0].reg).lower()
                    if ops[1].type == C_ARM.ARM_OP_REG and ops[2].type == C_ARM.ARM_OP_IMM:
                        rn = insn.reg_name(ops[1].reg).lower()
                        src = state.get(rn)
                        if src and src.kind == 'const':
                            v = RegVal.const(src.int_val + ops[2].imm)
                        else:
                            v = RegVal.unknown()
                        state[rd] = v
                        reg_trace.append((insn.address, rd, v))
                    else:
                        state[rd] = RegVal.unknown()
                    continue

            # BL/BLX -- call site
            if mn in ('bl', 'blx') and len(ops) >= 1 and ops[0].type == C_ARM.ARM_OP_IMM:
                target = ops[0].imm
                target_name = self._plt.get(target, f'0x{target:x}')
                call_args: Dict[str, RegVal] = {
                    r: state.get(r, RegVal.unknown()) for r in _ARM32_ARG_REGS
                }
                calls.append(CallSite(va=insn.address, target_va=target,
                                      target_name=target_name, args=call_args))
                # Clobber caller-saved regs after call
                for r in _ARM32_CALLER_SAVED:
                    state[r] = RegVal.ret(target_name) if r == 'r0' else RegVal.unknown()
                continue

            # Any write to a tracked register from unhandled insn: mark unknown
            try:
                for op in ops:
                    if op.type == C_ARM.ARM_OP_REG and op.access == capstone.CS_AC_WRITE:
                        rd = insn.reg_name(op.reg).lower()
                        if rd in state:
                            state[rd] = RegVal.unknown()
            except Exception:
                pass

        return AnnotationResult(func_va=va, func_end_va=end_va,
                                calls=calls, reg_trace=reg_trace)

    def _read_word(self, va: int) -> Optional[int]:
        for sv, ev, sc in self._sec_map:
            off = va - sv
            if 0 <= off <= len(sc) - 4:
                return struct.unpack_from('<I', sc, off)[0]
        return None
