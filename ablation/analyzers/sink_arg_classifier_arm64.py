"""
sink_arg_classifier_arm64.py: classify exec-class sink argument provenance on AArch64 ELFs.

Gap this fills vs SinkArgClassifier (ARM64-SAC-GAP-001):
  SinkArgClassifier hardcodes x86-64 registers (rdi, rsi, rdx, rcx, r8, r9).
  AArch64 AAPCS64 passes the first eight arguments in x0-x7.
  For aarch64 targets, SinkArgClassifier returns only UNKNOWN because the
  x86-64 register IDs never match any ARM64 instruction operand.
  This module fills that gap.

Four verdicts (same as SinkArgClassifier and SinkArgClassifierARM32):
  RODATA_CONST     — argument is a constant from .rodata or a literal immediate.
  SNPRINTF_RODATA  — argument is a stack buffer written by snprintf/vsnprintf
                     whose format string is RODATA_CONST.
  ARG_PROPAGATED   — argument traces back to an entry-point x0-x7 register.
  UNKNOWN          — provenance not resolved within the look-back window.

AArch64 AAPCS64 calling convention:
  Argument position 0 → x0  (Capstone ARM64_REG_X0 = 218)
  Argument position 1 → x1  (Capstone ARM64_REG_X1 = 219)
  Argument position 2 → x2  (Capstone ARM64_REG_X2 = 220)
  Argument position 3 → x3  (Capstone ARM64_REG_X3 = 221)
  ...through x7 for arguments 4-7.

AArch64 string address load patterns handled:
  1. ADRP xR, page; ADD xR, xR, #off   — most common PIC string ref in AArch64.
     string_va = adrp.imm + add.imm; if .rodata → RODATA_CONST.
  2. ADRP xR, page; LDR xR, [xR, #off] — GOT-indirect string pointer load.
     ptr_va = adrp.imm + off; string_va = read_u64(ptr_va); if .rodata → RODATA_CONST.
  3. ADR xR, target                      — short-range PC-relative direct address.
     if .rodata → RODATA_CONST.
  4. LDR xR, #pool_va                   — literal pool (IMM operand = absolute VA).
     string_va = read_u64(pool_va); if .rodata → RODATA_CONST.
  5. MOV/ORR xR, xzr, xY               — register copy; recurse on xY.
  6. MOV xR, #imm / MOVZ xR, #imm      — immediate constant (NULL, flag, small int).
  7. LDR xR, [sp, #N] / [x29, #N]      — stack slot: snprintf buf or entry arg save.
  8. LDR xR, [xY, #N] where xY ≠ sp    — struct field / heap dereference.
     if xY is entry reg → ARG_PROPAGATED; else UNKNOWN.

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier_arm64 import SinkArgClassifierARM64

    ctx = BinaryContext.load_or_build('/path/to/target_arm64_binary')
    clf = SinkArgClassifierARM64.from_context(ctx)
    clf.add_sink('custom_exec', arg_pos=0)
    results = clf.classify_all()
    print(clf.report(results))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64_const import (
        ARM64_OP_REG, ARM64_OP_MEM, ARM64_OP_IMM,
        ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_X3,
        ARM64_REG_X4, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_X7,
        ARM64_REG_SP, ARM64_REG_XZR, ARM64_REG_LR,
        ARM64_REG_X29,  # frame pointer (fp)
    )
    _CS_OK = True
except ImportError:
    pass

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

from ablation.analyzers.sink_arg_classifier import (
    SinkClassification,
    RODATA_CONST,
    SNPRINTF_RODATA,
    ARG_PROPAGATED,
    UNKNOWN,
)

# ── AArch64 AAPCS64 argument registers (x0-x7) ───────────────────────────────
_ARM64_ARG_REGS: List[int] = [
    ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_X3,
    ARM64_REG_X4, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_X7,
]
_ARM64_ENTRY_ARG_SET = frozenset(_ARM64_ARG_REGS)

_ARM64_REG_NAMES: Dict[int, str] = {
    ARM64_REG_X0: 'x0', ARM64_REG_X1: 'x1', ARM64_REG_X2: 'x2', ARM64_REG_X3: 'x3',
    ARM64_REG_X4: 'x4', ARM64_REG_X5: 'x5', ARM64_REG_X6: 'x6', ARM64_REG_X7: 'x7',
    ARM64_REG_SP: 'sp', ARM64_REG_XZR: 'xzr', ARM64_REG_LR: 'lr', ARM64_REG_X29: 'x29',
}

# Store mnemonics: first operand is the VALUE being stored, not the destination.
_STORE_MNEMS = frozenset([
    'str', 'stur', 'strb', 'strh', 'sturb', 'sturh', 'stlr', 'stlrb', 'stlrh',
    'stp', 'stxr', 'stlxr', 'stxrb', 'stxrh',
])

# ── Default sinks (AAPCS64 exec-class, arg_pos 0 = x0) ───────────────────────
_DEFAULT_SINKS_ARM64: Dict[str, int] = {
    'system':   0,
    'popen':    0,
    'execve':   0,
    'execvp':   0,
    'execl':    0,
    'execlp':   0,
}

# snprintf-family format arg positions (AAPCS64: a0=x0, a1=x1, a2=x2, a3=x3).
_SNPRINTF_FMT_POS_ARM64: Dict[str, int] = {
    'snprintf':       2,   # x2 = fmt
    'vsnprintf':      2,
    'sprintf':        1,   # x1 = fmt
    '__sprintf_chk':  3,
    '__snprintf_chk': 3,
}

# ── Scan constants ────────────────────────────────────────────────────────────
_LOOKBACK        = 80
_SNPRINTF_WINDOW = 140
_MAX_FUNC_BYTES  = 65536


if not _CS_OK:
    ARM64_REG_SP  = 5
    ARM64_REG_X29 = 2


def _rname(reg_id: int) -> str:
    return _ARM64_REG_NAMES.get(reg_id, f'x?{reg_id}')


class SinkArgClassifierARM64:
    """
    Classify exec-class sink call site argument provenance on AArch64 ELFs.

    AArch64 has a single execution state (no Thumb/Thumb2). Uses Capstone
    CS_ARCH_ARM64 with CS_MODE_ARM.

    This module fills ARM64-SAC-GAP-001: SinkArgClassifier (x86-64) produces
    all UNKNOWN verdicts on AArch64 binaries because x86-64 register IDs
    (rdi=7, rsi=6) never appear in AArch64 instruction operands.
    """

    def __init__(self, ctx):
        self._ctx           = ctx
        self._data: bytes   = Path(ctx.path).read_bytes()
        self._plt_rev: Dict[str, int] = {v: k for k, v in ctx.plt.items()}
        self._sinks: Dict[str, int]   = dict(_DEFAULT_SINKS_ARM64)
        self._snprintf_plts: Dict[int, int] = {}
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._dead_sinks: List[str] = []
        self._bin = None
        self._cs: Optional[Cs] = None
        if _CS_OK:
            self._cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self._cs.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(ctx.path)
        self._init()

    @classmethod
    def from_path(cls, path: str) -> 'SinkArgClassifierARM64':
        """Build directly from an ELF path — constructs BinaryContext internally."""
        from ablation.analyzers.binary_context import BinaryContext
        return cls(BinaryContext.load_or_build(path))

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierARM64':
        return cls(ctx)

    def add_sink(self, name: str, arg_pos: int) -> None:
        """Register a vendor-specific exec-class sink."""
        self._sinks[name] = arg_pos

    # ── initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        for sec in self._bin.sections:
            if sec.name in ('.rodata', '.rodata1', '__const', '__cstring', '.rdata'):
                self._rodata_ranges.append(
                    (int(sec.virtual_address), int(sec.virtual_address) + int(sec.size))
                )
        for name, fmt_pos in _SNPRINTF_FMT_POS_ARM64.items():
            va = self._plt_rev.get(name)
            if va:
                self._snprintf_plts[va] = fmt_pos

    # ── helpers ───────────────────────────────────────────────────────────────

    def _is_rodata(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._rodata_ranges)

    def _va_to_file_offset(self, va: int) -> int:
        if self._bin is None:
            return va
        try:
            return int(self._bin.virtual_address_to_offset(va))
        except Exception:
            return -1

    def _read_va(self, va: int, size: int) -> bytes:
        off = self._va_to_file_offset(va)
        if off < 0 or off + size > len(self._data):
            return b''
        return self._data[off:off + size]

    def _read_u64_le(self, va: int) -> Optional[int]:
        raw = self._read_va(va, 8)
        if len(raw) < 8:
            return None
        return struct.unpack_from('<Q', raw)[0]

    def _writes_reg(self, insn, reg_id: int) -> bool:
        """True if insn writes to reg_id as its first destination operand.

        Explicitly excludes store instructions (STR, STP, etc.) whose first
        operand is the value being stored, not the destination.
        """
        if insn.mnemonic in _STORE_MNEMS:
            return False
        if not insn.operands:
            return False
        op = insn.operands[0]
        return op.type == ARM64_OP_REG and op.reg == reg_id

    def _next_func_va(self, func_va: int) -> Optional[int]:
        fs = self._ctx.func_starts
        if not fs:
            return None
        import bisect
        idx = bisect.bisect_right(fs, func_va)
        return fs[idx] if idx < len(fs) else None

    def _find_sink_plts(self) -> Dict[int, Tuple[str, int]]:
        result: Dict[int, Tuple[str, int]] = {}
        self._dead_sinks = []
        for name, arg_pos in self._sinks.items():
            va = self._plt_rev.get(name) or self._ctx.exports.get(name)
            if not va:
                continue
            callers = self._ctx.callers_of(name)
            if not callers:
                self._dead_sinks.append(name)
            else:
                result[va] = (name, arg_pos)
        return result

    # ── per-function disassembly ──────────────────────────────────────────────

    def _get_insns(self, func_va: int) -> list:
        if self._cs is None:
            return []
        nxt = self._next_func_va(func_va)
        size = min(nxt - func_va if nxt else _MAX_FUNC_BYTES, _MAX_FUNC_BYTES)
        raw = self._read_va(func_va, size)
        if not raw:
            return []
        return list(self._cs.disasm(raw, func_va))

    def _find_call_sites(self, insns: list, sink_va: int) -> List[int]:
        """Return indices in insns where a BL calls sink_va directly."""
        sites: List[int] = []
        for i, insn in enumerate(insns):
            if insn.mnemonic != 'bl':
                continue
            if not insn.operands:
                continue
            op = insn.operands[0]
            if op.type == ARM64_OP_IMM and op.imm == sink_va:
                sites.append(i)
        return sites

    # ── backward argument trace ───────────────────────────────────────────────

    def _trace_arg(
        self,
        insns: list,
        from_idx: int,
        arg_reg: int,
        depth: int = 0,
    ) -> Tuple[str, str]:
        """Trace the source of arg_reg backward from from_idx."""
        if depth > 1:
            return (UNKNOWN, 'max recursion depth')

        limit = max(from_idx - _LOOKBACK, -1)

        for j in range(from_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, arg_reg):
                continue

            mnem = insn.mnemonic

            # ── ADRP xR, page — first check for ADRP alone ───────────────────
            # ADRP is always part of an ADRP+ADD or ADRP+LDR pair. When we
            # encounter ADRP as the write, it means the ADD/LDR consuming the
            # result is in the gap between from_idx and the ADRP. Handle the
            # combined pattern at the ADD/LDR step below.
            if mnem == 'adrp':
                if not insn.operands or len(insn.operands) < 2:
                    return (UNKNOWN, f'adrp {_rname(arg_reg)}: no operands')
                page_va = insn.operands[1].imm
                # The string VA is page_va (ADD/LDR was not found between
                # from_idx and here). The page itself may BE in .rodata
                # (unlikely but possible for small constants). Treat as UNKNOWN
                # unless .rodata.
                if self._is_rodata(page_va):
                    return (RODATA_CONST, f'adrp {_rname(arg_reg)}, 0x{page_va:x} in .rodata')
                return (UNKNOWN, f'adrp {_rname(arg_reg)}, 0x{page_va:x}: no ADD/LDR found')

            # ── ADD xR, xR, #off — ADRP+ADD pair ─────────────────────────────
            # This is the primary PIC string load pattern in AArch64.
            # ADD xd, xn, #off where xd == xn == arg_reg → look for preceding ADRP.
            if mnem == 'add' and len(insn.operands) >= 3:
                op0 = insn.operands[0]
                op1 = insn.operands[1]
                op2 = insn.operands[2]
                if (op0.type == ARM64_OP_REG and op0.reg == arg_reg
                        and op1.type == ARM64_OP_REG and op1.reg == arg_reg
                        and op2.type == ARM64_OP_IMM):
                    page_offset = op2.imm
                    # Look backward for ADRP xR, page_va
                    for k in range(j - 1, max(j - 6, -1), -1):
                        prev = insns[k]
                        if prev.mnemonic != 'adrp':
                            continue
                        if not prev.operands or len(prev.operands) < 2:
                            continue
                        if prev.operands[0].reg != arg_reg:
                            continue
                        page_va = prev.operands[1].imm
                        string_va = page_va + page_offset
                        if self._is_rodata(string_va):
                            return (RODATA_CONST,
                                    f'adrp+add 0x{prev.address:x}/0x{insn.address:x}'
                                    f' page=0x{page_va:x}+0x{page_offset:x}'
                                    f' → 0x{string_va:x} in .rodata')
                        return (UNKNOWN,
                                f'adrp+add → 0x{string_va:x} not .rodata')
                    return (UNKNOWN,
                            f'add {_rname(arg_reg)}, {_rname(arg_reg)}, #0x{page_offset:x}'
                            f': no preceding adrp found')
                # ADD with different source register — register copy or arithmetic
                if (op0.type == ARM64_OP_REG and op0.reg == arg_reg
                        and op1.type == ARM64_OP_REG
                        and op2.type == ARM64_OP_IMM):
                    src_reg = op1.reg
                    if src_reg in _ARM64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'add {_rname(arg_reg)}, {_rname(src_reg)}, #imm (entry arg)')
                    return (UNKNOWN,
                            f'add {_rname(arg_reg)}: non-entry-arg source {_rname(src_reg)}')

            # ── ADR xR, target ────────────────────────────────────────────────
            elif mnem == 'adr' and len(insn.operands) >= 2:
                op = insn.operands[1]
                if op.type == ARM64_OP_IMM:
                    target_va = op.imm
                    if self._is_rodata(target_va):
                        return (RODATA_CONST,
                                f'adr {_rname(arg_reg)}, 0x{target_va:x} in .rodata')
                    return (RODATA_CONST,
                            f'adr {_rname(arg_reg)}, 0x{target_va:x} (inline literal)')

            # ── LDR xR, ... ───────────────────────────────────────────────────
            elif mnem in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldur', 'ldursw') and len(insn.operands) >= 2:
                src = insn.operands[1]

                # Literal pool load: LDR xR, #pool_va (IMM operand = absolute VA)
                if src.type == ARM64_OP_IMM:
                    pool_va = src.imm
                    string_va = self._read_u64_le(pool_va)
                    if string_va is None:
                        return (UNKNOWN,
                                f'ldr {_rname(arg_reg)}, #0x{pool_va:x}: pool unreadable')
                    if self._is_rodata(string_va):
                        return (RODATA_CONST,
                                f'ldr {_rname(arg_reg)}, #0x{pool_va:x}'
                                f' → 0x{string_va:x} in .rodata')
                    return (UNKNOWN,
                            f'ldr {_rname(arg_reg)}, #0x{pool_va:x}'
                            f' → 0x{string_va:x} not .rodata')

                if src.type == ARM64_OP_MEM:
                    base = src.mem.base
                    disp = src.mem.disp

                    # Stack slot: LDR xR, [sp, #N] or [x29, #N]
                    if base in (ARM64_REG_SP, ARM64_REG_X29):
                        snp = self._trace_snprintf_buf(insns, from_idx,
                                                       base, disp, depth)
                        if snp is not None:
                            return snp
                        if self._is_entry_arg_save(insns, base, disp):
                            return (ARG_PROPAGATED,
                                    f'entry arg at {_rname(base)}+0x{disp:x}')
                        return (UNKNOWN,
                                f'ldr {_rname(arg_reg)}, [{_rname(base)}, #0x{disp:x}]')

                    # ADRP+LDR pair: LDR xR, [xR, #off] following ADRP xR, page
                    # This is a GOT-indirect load: ptr_va = page + off → read pointer → string
                    if base == arg_reg:
                        for k in range(j - 1, max(j - 6, -1), -1):
                            prev = insns[k]
                            if prev.mnemonic != 'adrp':
                                continue
                            if not prev.operands or len(prev.operands) < 2:
                                continue
                            if prev.operands[0].reg != arg_reg:
                                continue
                            page_va = prev.operands[1].imm
                            ptr_va  = page_va + disp
                            string_va = self._read_u64_le(ptr_va)
                            if string_va is None:
                                return (UNKNOWN,
                                        f'adrp+ldr ptr@0x{ptr_va:x}: unreadable')
                            if self._is_rodata(string_va):
                                return (RODATA_CONST,
                                        f'adrp+ldr 0x{prev.address:x}/0x{insn.address:x}'
                                        f' ptr=0x{ptr_va:x} → 0x{string_va:x} in .rodata')
                            return (UNKNOWN,
                                    f'adrp+ldr → 0x{string_va:x} not .rodata')

                    # Struct/heap field load
                    if base in _ARM64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'ldr {_rname(arg_reg)}, [{_rname(base)}, #0x{disp:x}]'
                                f' struct/entry')
                    return (UNKNOWN,
                            f'ldr {_rname(arg_reg)}, [{_rname(base)}, #0x{disp:x}]')

            # ── MOV / ORR xR, xzr, xY — register copy ────────────────────────
            elif mnem in ('mov', 'orr') and len(insn.operands) >= 2:
                # MOV xd, xn  (AAPCS64 mov alias, disassembles as orr xd, xzr, xn)
                # Check last operand for the source register
                src_op = insn.operands[-1]
                if src_op.type == ARM64_OP_IMM:
                    return (RODATA_CONST,
                            f'{mnem} {_rname(arg_reg)}, #0x{src_op.imm:x}')
                if src_op.type == ARM64_OP_REG:
                    src_reg = src_op.reg
                    if src_reg == ARM64_REG_XZR:
                        return (RODATA_CONST,
                                f'{mnem} {_rname(arg_reg)}, xzr (NULL)')
                    if src_reg in _ARM64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'{mnem} from entry {_rname(src_reg)}')
                    return self._trace_arg(insns, j, src_reg, depth + 1)

            # ── MOVZ xR, #imm — immediate load ───────────────────────────────
            elif mnem in ('movz', 'movn') and len(insn.operands) >= 2:
                op = insn.operands[1]
                if op.type == ARM64_OP_IMM:
                    return (RODATA_CONST,
                            f'{mnem} {_rname(arg_reg)}, #0x{op.imm:x}')
                return (UNKNOWN, f'{mnem} {_rname(arg_reg)}: non-IMM source')

            # ── MOVK xR, #imm, lsl #shift — upper bits of address pair ───────
            elif mnem == 'movk' and len(insn.operands) >= 2:
                # MOVK is the upper half of a MOVZ+MOVK pair building a 64-bit constant.
                # The lower half (MOVZ) is a separate write; treat this as RODATA_CONST
                # since the full value is a compile-time constant.
                return (RODATA_CONST,
                        f'movz+movk {_rname(arg_reg)} literal pair')

            else:
                return (UNKNOWN,
                        f'{mnem} writes {_rname(arg_reg)} @ 0x{insn.address:x}')

        return (UNKNOWN,
                f'{_rname(arg_reg)} write not found in {_LOOKBACK}-insn window')

    # ── snprintf buffer backtrack ─────────────────────────────────────────────

    def _trace_snprintf_buf(
        self,
        insns: list,
        sink_idx: int,
        base_reg: int,
        disp: int,
        depth: int,
    ) -> Optional[Tuple[str, str]]:
        """Search backward for a snprintf/vsnprintf that wrote to (base_reg, disp)."""
        limit = max(sink_idx - _SNPRINTF_WINDOW, -1)
        for i in range(sink_idx - 1, limit, -1):
            insn = insns[i]
            if insn.mnemonic != 'bl':
                continue
            if not insn.operands:
                continue
            op = insn.operands[0]
            if op.type != ARM64_OP_IMM:
                continue
            snp_plt_va = op.imm
            if snp_plt_va not in self._snprintf_plts:
                continue
            if not self._x0_is_slot(insns, i, base_reg, disp):
                continue
            fmt_pos = self._snprintf_plts[snp_plt_va]
            if fmt_pos >= len(_ARM64_ARG_REGS):
                continue
            fmt_reg = _ARM64_ARG_REGS[fmt_pos]
            snp_name = self._ctx.plt.get(snp_plt_va, 'snprintf')
            verdict, detail = self._trace_arg(insns, i, fmt_reg, depth + 1)
            if verdict == RODATA_CONST:
                return (SNPRINTF_RODATA,
                        f'{snp_name}({_rname(base_reg)}+0x{disp:x}) fmt={detail}')
            return (verdict,
                    f'{snp_name}({_rname(base_reg)}+0x{disp:x}) fmt={detail}')
        return None

    def _x0_is_slot(
        self,
        insns: list,
        bl_idx: int,
        base_reg: int,
        disp: int,
    ) -> bool:
        """True if, before bl_idx, x0 is set to the address of (base_reg, disp)."""
        limit = max(bl_idx - _LOOKBACK, -1)
        for j in range(bl_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, ARM64_REG_X0):
                continue
            if insn.mnemonic != 'add':
                return False
            if len(insn.operands) < 3:
                return False
            # ADD x0, base_reg, #disp
            src = insn.operands[1]
            imm = insn.operands[2]
            if src.type == ARM64_OP_REG and imm.type == ARM64_OP_IMM:
                return src.reg == base_reg and imm.imm == disp
            return False
        return False

    def _is_entry_arg_save(
        self,
        insns: list,
        base_reg: int,
        disp: int,
    ) -> bool:
        """True if the function prologue stores an entry x0-x7 to (base_reg, disp)."""
        limit = min(len(insns), 24)
        for j in range(0, limit):
            insn = insns[j]
            if insn.mnemonic not in ('str', 'stur'):
                continue
            if len(insn.operands) < 2:
                continue
            src = insn.operands[0]
            dst = insn.operands[1]
            if src.type != ARM64_OP_REG or dst.type != ARM64_OP_MEM:
                continue
            if src.reg not in _ARM64_ENTRY_ARG_SET:
                continue
            if dst.mem.base == base_reg and dst.mem.disp == disp:
                return True
        return False

    # ── per-function classification ───────────────────────────────────────────

    def _classify_function(
        self,
        func_va: int,
        sink_plts: Dict[int, Tuple[str, int]],
    ) -> List[SinkClassification]:
        insns = self._get_insns(func_va)
        if not insns:
            return []
        results: List[SinkClassification] = []
        for sink_va, (sink_name, arg_pos) in sink_plts.items():
            if arg_pos >= len(_ARM64_ARG_REGS):
                continue
            call_indices = self._find_call_sites(insns, sink_va)
            for ci in call_indices:
                arg_reg = _ARM64_ARG_REGS[arg_pos]
                verdict, detail = self._trace_arg(insns, ci, arg_reg, depth=0)
                results.append(SinkClassification(
                    sink_name=sink_name,
                    arg_pos=arg_pos,
                    func_va=func_va,
                    call_va=insns[ci].address,
                    verdict=verdict,
                    detail=detail,
                ))
        return results

    # ── public interface ──────────────────────────────────────────────────────

    def classify_all(self) -> List[SinkClassification]:
        if not _CS_OK:
            return []
        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []
        results: List[SinkClassification] = []
        for func_va in self._ctx.func_starts:
            results.extend(self._classify_function(func_va, sink_plts))
        return results

    def classify_sink(
        self,
        sink_name: str,
        arg_pos: Optional[int] = None,
    ) -> List[SinkClassification]:
        if arg_pos is None:
            arg_pos = self._sinks.get(sink_name, 0)
        self._sinks[sink_name] = arg_pos
        sink_plts = self._find_sink_plts()
        results: List[SinkClassification] = []
        for func_va in self._ctx.func_starts:
            results.extend(self._classify_function(func_va, sink_plts))
        return [r for r in results if r.sink_name == sink_name]

    def report(self, results: List[SinkClassification]) -> str:
        if not results and not self._dead_sinks:
            return '[sink_arg_classifier_arm64] no results\n'
        by_verdict: Dict[str, int] = {}
        for r in results:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        hdr = (
            f'[sink_arg_classifier_arm64] {len(results)} call site(s)  '
            + '  '.join(f'{k}={v}' for k, v in sorted(by_verdict.items()))
            + '\n'
        )
        lines = [hdr]
        for r in sorted(results, key=lambda x: (x.verdict, x.func_va)):
            lines.append(r.fmt())
        if self._dead_sinks:
            lines.append(
                f'\n  DEAD IMPORTS (0 callers — ELIMINATED): '
                + ', '.join(sorted(self._dead_sinks))
            )
        investigate = by_verdict.get(ARG_PROPAGATED, 0) + by_verdict.get(UNKNOWN, 0)
        if investigate:
            lines.append(
                f'\n  {investigate} site(s) need manual review '
                f'(ARG_PROPAGATED or UNKNOWN).\n'
            )
        return '\n'.join(lines) + '\n'
