"""
sink_arg_classifier_arm32.py: classify exec-class sink argument provenance on ARM32 ELFs.

Gap this fills vs SinkArgClassifier:
  SinkArgClassifier hardcodes x86-64 registers (rdi, rsi, rdx).
  ARM32 AAPCS passes the first four arguments in r0-r3.
  That gap is ARM-SNMP-GAP-001. This module resolves it.

Four verdicts (same as SinkArgClassifier and SinkArgClassifierMIPS):
  RODATA_CONST     — argument is a constant from .rodata or a literal immediate.
  SNPRINTF_RODATA  — argument is a stack buffer written by snprintf/vsnprintf
                     whose format string is RODATA_CONST.
  ARG_PROPAGATED   — argument traces back to an entry-point r0-r3 register.
  UNKNOWN          — provenance not resolved within the look-back window.

ARM32 AAPCS calling convention:
  Argument position 0 → r0 (Capstone ARM_REG_R0 = 66)
  Argument position 1 → r1 (Capstone ARM_REG_R1 = 67)
  Argument position 2 → r2 (Capstone ARM_REG_R2 = 68)
  Argument position 3 → r3 (Capstone ARM_REG_R3 = 69)

ARM32 string address load patterns:
  1. LDR rX, [pc, #N] (literal pool)   — most common: pool entry holds string VA.
     target_pool_va = insn_addr + 8 + disp; string_va = read_u32(target_pool_va).
     If string_va in .rodata → RODATA_CONST.
  2. ADR rX, label                      — PC-relative add, imm encodes address.
     target_va = (insn_addr + 8) + imm (or - imm for negative). RODATA_CONST if .rodata.
  3. MOV rX, rY / PUSH+POP copy        — register copy. Recurse on rY.
  4. MOV rX, #imm (small constant)     — RODATA_CONST (NULL, flag, integer literal).
  5. LDR rX, [sp, #N]                  — stack slot. Run snprintf buffer backtrack.
  6. LDR rX, [rY, #N] where rY ≠ pc   — struct field / heap. ARG_PROPAGATED or UNKNOWN.
  7. STR rX, [sp, #N] in prologue      — entry-arg save detection.

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier_arm32 import SinkArgClassifierARM32

    ctx = BinaryContext.load_or_build('/path/to/libcapwap.so')
    clf = SinkArgClassifierARM32.from_context(ctx)

    # Add Fortinet-specific sinks
    clf.add_sink('cwSysCmdRun', arg_pos=0)

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
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    from capstone.arm_const import (
        ARM_OP_REG, ARM_OP_MEM, ARM_OP_IMM,
        ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
        ARM_REG_SP, ARM_REG_PC, ARM_REG_LR,
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

# Re-export shared verdict constants from the x86 module.
from ablation.analyzers.sink_arg_classifier import (
    SinkClassification,
    RODATA_CONST,
    SNPRINTF_RODATA,
    ARG_PROPAGATED,
    UNKNOWN,
)

# ── Capstone ARM32 register IDs ───────────────────────────────────────────────
_ARM32_ARG_REGS: List[int] = [ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3]
_ARM32_ENTRY_ARG_SET = frozenset([ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3])

_ARM32_REG_NAMES: Dict[int, str] = {
    ARM_REG_R0: 'r0', ARM_REG_R1: 'r1', ARM_REG_R2: 'r2', ARM_REG_R3: 'r3',
    ARM_REG_SP: 'sp', ARM_REG_PC: 'pc', ARM_REG_LR: 'lr',
}

# ── Default sinks ─────────────────────────────────────────────────────────────
_DEFAULT_SINKS_ARM32: Dict[str, int] = {
    'system':    0,
    'popen':     0,
    'execve':    0,
    'execvp':    0,
    'execl':     0,
    'execlp':    0,
}

# snprintf-family and their format-arg positions (AAPCS: a0=r0, a1=r1, a2=r2, a3=r3).
_SNPRINTF_FMT_POS_ARM32: Dict[str, int] = {
    'snprintf':       2,   # r2 = fmt
    'vsnprintf':      2,
    'sprintf':        1,   # r1 = fmt
    '__sprintf_chk':  3,
    '__snprintf_chk': 3,
}

# ── Scan constants ────────────────────────────────────────────────────────────
_LOOKBACK       = 80
_SNPRINTF_WINDOW = 140
_MAX_FUNC_BYTES = 65536


if not _CS_OK:
    ARM_REG_PC = 11  # fallback so module can be imported without Capstone


def _rname(reg_id: int) -> str:
    return _ARM32_REG_NAMES.get(reg_id, f'r{reg_id}')


class SinkArgClassifierARM32:
    """
    Classify exec-class sink call site argument provenance on ARM32 ELFs.

    Supports both ARM (32-bit instructions) and Thumb/Thumb2 (16/32-bit instructions).
    Mode is detected per-function from BinaryContext.thumb_funcs; defaults to ARM.

    This module fills ARM-SNMP-GAP-001.
    """

    def __init__(self, ctx, thumb: bool = False):
        self._ctx           = ctx
        self._default_thumb = thumb
        self._data: bytes   = Path(ctx.path).read_bytes()
        self._plt_rev: Dict[str, int] = {v: k for k, v in ctx.plt.items()}
        self._sinks: Dict[str, int]   = dict(_DEFAULT_SINKS_ARM32)
        self._snprintf_plts: Dict[int, int] = {}  # PLT VA → fmt arg position
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._dead_sinks: List[str] = []
        self._bin = None
        self._cs_arm: Optional[Cs]   = None
        self._cs_thumb: Optional[Cs] = None
        if _CS_OK:
            self._cs_arm   = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            self._cs_arm.detail   = True
            self._cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            self._cs_thumb.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(ctx.path)
        self._init()

    # ── construction ──────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str) -> 'SinkArgClassifierARM32':
        """Build directly from an ELF path — constructs BinaryContext internally."""
        from ablation.analyzers.binary_context import BinaryContext
        return cls.from_context(BinaryContext.load_or_build(path))

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierARM32':
        """Build from a BinaryContext. Detects Thumb mode from ctx.arch."""
        thumb = getattr(ctx, 'arch', 'arm32') in ('arm32', 'arm') and bool(
            getattr(ctx, 'thumb_funcs', None)
        )
        return cls(ctx, thumb=thumb)

    def add_sink(self, name: str, arg_pos: int) -> None:
        """Register a vendor-specific exec-class sink (e.g., cwSysCmdRun)."""
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

        for name, fmt_pos in _SNPRINTF_FMT_POS_ARM32.items():
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

    def _read_u32_le(self, va: int) -> Optional[int]:
        raw = self._read_va(va, 4)
        if len(raw) < 4:
            return None
        return struct.unpack_from('<I', raw)[0]

    def _cs_for_func(self, func_va: int) -> Optional[Cs]:
        if not _CS_OK:
            return None
        thumb_funcs = getattr(self._ctx, 'thumb_funcs', set())
        if func_va in thumb_funcs or self._default_thumb:
            return self._cs_thumb
        return self._cs_arm

    def _writes_reg(self, insn, reg_id: int) -> bool:
        """True if the first destination operand of insn writes to reg_id."""
        if not insn.operands:
            return False
        op = insn.operands[0]
        return op.type == ARM_OP_REG and op.reg == reg_id

    def _next_func_va(self, func_va: int) -> Optional[int]:
        fs = self._ctx.func_starts
        if not fs:
            return None
        import bisect
        idx = bisect.bisect_right(fs, func_va)
        return fs[idx] if idx < len(fs) else None

    def _find_sink_plts(self) -> Dict[int, Tuple[str, int]]:
        """Return {sink_va: (sink_name, arg_pos)} for sinks with ≥1 caller."""
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
        cs = self._cs_for_func(func_va)
        if cs is None:
            return []
        nxt = self._next_func_va(func_va)
        size = min(nxt - func_va if nxt else _MAX_FUNC_BYTES, _MAX_FUNC_BYTES)
        raw = self._read_va(func_va, size)
        if not raw:
            return []
        return list(cs.disasm(raw, func_va))

    def _find_call_sites(self, insns: list, sink_va: int) -> List[int]:
        """Return indices in insns where a BL/BLX calls sink_va."""
        sites: List[int] = []
        for i, insn in enumerate(insns):
            if insn.mnemonic not in ('bl', 'blx'):
                continue
            if not insn.operands:
                continue
            op = insn.operands[0]
            if op.type == ARM_OP_IMM and op.imm == sink_va:
                sites.append(i)
        return sites

    # ── backward argument trace ───────────────────────────────────────────────

    def _trace_arg(
        self,
        insns: list,
        from_idx: int,
        arg_reg: int,
        depth: int = 0,
        is_thumb: bool = False,
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

            # ── LDR rX, [pc, #N] (literal pool) ──────────────────────────────
            if mnem in ('ldr', 'ldr.w') and len(insn.operands) >= 2:
                src = insn.operands[1]
                if src.type == ARM_OP_MEM:
                    base = src.mem.base
                    disp = src.mem.disp

                    if base == ARM_REG_PC:
                        # ARM32 pipeline adds 8; Thumb aligns to 4-byte boundary first.
                        # Capstone reports the raw encoded offset in mem.disp; the caller
                        # must apply the correct pipeline offset for each encoding.
                        if is_thumb:
                            pool_va = (insn.address & ~3) + 4 + disp
                        else:
                            pool_va = insn.address + 8 + disp
                        str_va = self._read_u32_le(pool_va)
                        if str_va is None:
                            return (UNKNOWN, f'LDR {_rname(arg_reg)}, [pc, #{disp}]: pool unreadable')
                        if self._is_rodata(str_va):
                            return (RODATA_CONST,
                                    f'LDR {_rname(arg_reg)}, [pc, #{disp}] → pool 0x{pool_va:x}'
                                    f' → 0x{str_va:x} in .rodata')
                        return (UNKNOWN,
                                f'LDR {_rname(arg_reg)}, [pc, #{disp}] → 0x{str_va:x} not .rodata')

                    if base == ARM_REG_SP:
                        snp = self._trace_snprintf_buf(insns, from_idx, ARM_REG_SP, disp,
                                                       depth, is_thumb)
                        if snp is not None:
                            return snp
                        if self._is_entry_arg_save(insns, ARM_REG_SP, disp):
                            return (ARG_PROPAGATED, f'entry arg at sp+{disp:#x}')
                        return (UNKNOWN, f'LDR {_rname(arg_reg)}, [sp, #{disp:#x}]')

                    # LDR from a non-PC, non-SP register → struct field
                    if base in _ARM32_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'LDR {_rname(arg_reg)}, [{_rname(base)}, #{disp:#x}] struct/entry')
                    return (UNKNOWN,
                            f'LDR {_rname(arg_reg)}, [{_rname(base)}, #{disp:#x}]')

            # ── ADD rX, pc, rX (ARM32 PIC shared-library string load) ───────
            # Two-instruction PIC pair:
            #   LDR rX, [pc, #N]  → loads a delta from the literal pool
            #   ADD rX, pc, rX    → rX = (add_addr + 8) + delta = string VA
            # libcapwap.so and other ARM32 shared objects use this form exclusively
            # for .rodata string references (absolute VAs would need runtime relocs).
            elif mnem in ('add', 'add.w') and len(insn.operands) >= 3:
                op0 = insn.operands[0]
                op1 = insn.operands[1]
                op2 = insn.operands[2]
                if (op0.type == ARM_OP_REG and op0.reg == arg_reg
                        and op1.type == ARM_OP_REG and op1.reg == ARM_REG_PC
                        and op2.type == ARM_OP_REG and op2.reg == arg_reg):
                    # Look backward for LDR arg_reg, [pc, #M] that loaded the delta.
                    for k in range(j - 1, max(j - 10, -1), -1):
                        prev = insns[k]
                        if not self._writes_reg(prev, arg_reg):
                            continue
                        if prev.mnemonic not in ('ldr', 'ldr.w'):
                            break
                        if len(prev.operands) < 2:
                            break
                        psrc = prev.operands[1]
                        if psrc.type != ARM_OP_MEM or psrc.mem.base != ARM_REG_PC:
                            break
                        if is_thumb:
                            pool_va = (prev.address & ~3) + 4 + psrc.mem.disp
                        else:
                            pool_va = prev.address + 8 + psrc.mem.disp
                        delta = self._read_u32_le(pool_va)
                        if delta is None:
                            return (UNKNOWN,
                                    f'PIC ADD [pc+r0]: pool 0x{pool_va:x} unreadable')
                        add_pc = ((insn.address & ~3) + 4) if is_thumb else (insn.address + 8)
                        string_va = add_pc + delta
                        if self._is_rodata(string_va):
                            return (RODATA_CONST,
                                    f'PIC LDR+ADD 0x{prev.address:x}/0x{insn.address:x}'
                                    f' delta=0x{delta:x} → 0x{string_va:x} in .rodata')
                        return (UNKNOWN,
                                f'PIC LDR+ADD → 0x{string_va:x} not .rodata')
                    # ADD r0, pc, r0 without a preceding LDR — treat as UNKNOWN
                    return (UNKNOWN, f'ADD {_rname(arg_reg)}, pc, {_rname(arg_reg)}: no LDR found')

            # ── ADR rX, #N ────────────────────────────────────────────────────
            elif mnem in ('adr', 'adr.w') and len(insn.operands) >= 2:
                op = insn.operands[1]
                if op.type == ARM_OP_IMM:
                    target_va = op.imm
                    if self._is_rodata(target_va):
                        return (RODATA_CONST, f'ADR {_rname(arg_reg)}, 0x{target_va:x} in .rodata')
                    # ADR addresses nearby constants — treat as inline data (RODATA_CONST)
                    return (RODATA_CONST, f'ADR {_rname(arg_reg)}, 0x{target_va:x} (inline)')

            # ── MOV rX, #imm ──────────────────────────────────────────────────
            elif mnem in ('mov', 'mov.w', 'movw') and len(insn.operands) >= 2:
                src_op = insn.operands[1]
                if src_op.type == ARM_OP_IMM:
                    return (RODATA_CONST, f'MOV {_rname(arg_reg)}, #{src_op.imm:#x}')
                if src_op.type == ARM_OP_REG:
                    src_reg = src_op.reg
                    if src_reg in _ARM32_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED, f'MOV from entry {_rname(src_reg)}')
                    return self._trace_arg(insns, j, src_reg, depth, is_thumb)

            # ── MOVT rX, #hi — upper half of 32-bit address load ──────────────
            elif mnem == 'movt' and len(insn.operands) >= 2:
                # MOVT writes to upper 16 bits but does not overwrite the full reg.
                # The lower 16 bits were set by a preceding MOVW. Treat as RODATA_CONST
                # because the full 32-bit address is known only from both insns.
                # A conservative classifier reports RODATA_CONST for MOVW/MOVT pairs.
                op = insn.operands[1]
                if op.type == ARM_OP_IMM:
                    return (RODATA_CONST, f'MOVT/MOVW {_rname(arg_reg)} literal pair')
                return (UNKNOWN, f'MOVT {_rname(arg_reg)}: non-IMM source')

            # ── STR rY, [sp, #N] prologue save → already handled via LDR ─────
            else:
                return (UNKNOWN, f'{mnem} writes {_rname(arg_reg)} @ 0x{insn.address:x}')

        return (UNKNOWN, f'{_rname(arg_reg)} write not found in {_LOOKBACK}-insn window')

    # ── snprintf buffer backtrack ─────────────────────────────────────────────

    def _trace_snprintf_buf(
        self,
        insns: list,
        sink_idx: int,
        base_reg: int,
        disp: int,
        depth: int,
        is_thumb: bool = False,
    ) -> Optional[Tuple[str, str]]:
        """Search backward for a snprintf/vsnprintf that wrote to (base_reg, disp)."""
        limit = max(sink_idx - _SNPRINTF_WINDOW, -1)
        for i in range(sink_idx - 1, limit, -1):
            insn = insns[i]
            if insn.mnemonic not in ('bl', 'blx'):
                continue
            if not insn.operands:
                continue
            op = insn.operands[0]
            if op.type != ARM_OP_IMM:
                continue
            snp_plt_va = op.imm
            if snp_plt_va not in self._snprintf_plts:
                continue

            if not self._r0_is_slot(insns, i, base_reg, disp):
                continue

            fmt_pos = self._snprintf_plts[snp_plt_va]
            if fmt_pos >= len(_ARM32_ARG_REGS):
                continue
            fmt_reg = _ARM32_ARG_REGS[fmt_pos]
            snp_name = self._ctx.plt.get(snp_plt_va, 'snprintf')

            verdict, detail = self._trace_arg(insns, i, fmt_reg, depth + 1, is_thumb)
            if verdict == RODATA_CONST:
                return (SNPRINTF_RODATA,
                        f'{snp_name}({_rname(base_reg)}+{disp:#x}) fmt={detail}')
            return (verdict,
                    f'{snp_name}({_rname(base_reg)}+{disp:#x}) fmt={detail}')
        return None

    def _r0_is_slot(
        self,
        insns: list,
        bl_idx: int,
        base_reg: int,
        disp: int,
    ) -> bool:
        """True if, before bl_idx, r0 is set to the address of (base_reg, disp)."""
        limit = max(bl_idx - _LOOKBACK, -1)
        for j in range(bl_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, ARM_REG_R0):
                continue
            if insn.mnemonic not in ('add', 'add.w') and insn.mnemonic not in ('mov', 'mov.w'):
                return False
            if len(insn.operands) < 3:
                return False
            # ADD r0, base_reg, #disp  or  ADD r0, sp, #disp
            src = insn.operands[1]
            imm = insn.operands[2]
            if src.type == ARM_OP_REG and imm.type == ARM_OP_IMM:
                return src.reg == base_reg and imm.imm == disp
            return False
        return False

    def _is_entry_arg_save(
        self,
        insns: list,
        base_reg: int,
        disp: int,
    ) -> bool:
        """True if the function prologue stores an entry r0-r3 to (base_reg, disp)."""
        limit = min(len(insns), 20)
        for j in range(0, limit):
            insn = insns[j]
            if insn.mnemonic not in ('str', 'str.w'):
                continue
            if len(insn.operands) < 2:
                continue
            src = insn.operands[0]
            dst = insn.operands[1]
            if src.type != ARM_OP_REG or dst.type != ARM_OP_MEM:
                continue
            if src.reg not in _ARM32_ENTRY_ARG_SET:
                continue
            if dst.mem.base == base_reg and dst.mem.disp == disp:
                return True
        return False

    def _classify_function(
        self,
        func_va: int,
        sink_plts: Dict[int, Tuple[str, int]],
    ) -> List[SinkClassification]:
        insns = self._get_insns(func_va)
        if not insns:
            return []
        thumb_funcs = getattr(self._ctx, 'thumb_funcs', set())
        is_thumb = func_va in thumb_funcs or self._default_thumb
        results: List[SinkClassification] = []
        for sink_va, (sink_name, arg_pos) in sink_plts.items():
            if arg_pos >= len(_ARM32_ARG_REGS):
                continue
            call_indices = self._find_call_sites(insns, sink_va)
            for ci in call_indices:
                arg_reg = _ARM32_ARG_REGS[arg_pos]
                verdict, detail = self._trace_arg(insns, ci, arg_reg, depth=0,
                                                  is_thumb=is_thumb)
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
        """Classify all sink call sites across all known function starts."""
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
        """Classify call sites for a single named sink."""
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
            return '[sink_arg_classifier_arm32] no results\n'
        by_verdict: Dict[str, int] = {}
        for r in results:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        hdr = (
            f'[sink_arg_classifier_arm32] {len(results)} call site(s)  '
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
