"""
sink_arg_classifier_mips.py: classify exec-class sink argument provenance on MIPS32 ELFs.

Gap this fills vs SinkArgClassifier:
  SinkArgClassifier hardcodes x86-64 registers (rdi, rsi, rdx).
  MIPS O32 ABI passes the first four arguments in $a0-$a3.
  That gap is MIPS-GAP-002. This module resolves it.

Four verdicts (same as SinkArgClassifier):
  RODATA_CONST     — argument is a constant from .rodata or a literal immediate.
  SNPRINTF_RODATA  — argument is a stack buffer written by snprintf/vsnprintf
                     whose format string is RODATA_CONST.
  ARG_PROPAGATED   — argument traces back to an entry-point $a0-$a3 register.
  UNKNOWN          — provenance not resolved within the look-back window.

MIPS32 O32 ABI calling convention:
  Argument position 0 → $a0 (Capstone reg 6)
  Argument position 1 → $a1 (Capstone reg 7)
  Argument position 2 → $a2 (Capstone reg 8)
  Argument position 3 → $a3 (Capstone reg 9)

MIPS string address load patterns:
  1. LW $aX, N($gp)                      — direct GOT entry pointing to rodata.
  2. LW $vY, N($gp); ADDIU $aX, $vY, M  — section base + offset. Dominant pattern
     in ET_EXEC firmware. GOT[N] holds a section base; M is the intra-section offset.
  3. ADDIU $aX, $zero, imm               — small immediate (NULL, flag). RODATA_CONST.
  4. LW $aX, N($fp/$sp)                  — stack slot. Triggers snprintf backtrack
     or entry-arg-save detection.
  5. MOVE/OR $aX, $rY, $zero             — register copy. Recurse on $rY.

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier_mips import SinkArgClassifierMIPS

    ctx = BinaryContext.load_or_build('/path/to/firmware.elf')
    clf = SinkArgClassifierMIPS.from_context(ctx)

    # Add Fortinet-specific sinks beyond the defaults
    clf.add_sink('cwSysCmdRun', arg_pos=0)

    results = clf.classify_all()
    print(clf.report(results))

    # Filter to non-safe findings only
    flagged = [r for r in results if r.verdict not in ('RODATA_CONST', 'SNPRINTF_RODATA')]
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN
    from capstone.mips_const import MIPS_OP_REG, MIPS_OP_MEM, MIPS_OP_IMM
    _CS_OK = True
except ImportError:
    pass

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

# Re-export shared verdict constants and SinkClassification from the x86 module.
from ablation.analyzers.sink_arg_classifier import (
    SinkClassification,
    RODATA_CONST,
    SNPRINTF_RODATA,
    ARG_PROPAGATED,
    UNKNOWN,
)

# ── Capstone MIPS register IDs ────────────────────────────────────────────────
# These are the integer IDs Capstone uses for MIPS registers.
# They differ from the MIPS ABI register numbers (e.g., $a0 = ABI reg 4, Capstone reg 6).
_R_ZERO = 2
_R_V0   = 4
_R_V1   = 5
_R_A0   = 6
_R_A1   = 7
_R_A2   = 8
_R_A3   = 9
_R_T9   = 27
_R_GP   = 30
_R_SP   = 31
_R_FP   = 32
_R_RA   = 33

# Argument registers in position order.
_MIPS_ARG_REGS: List[int] = [_R_A0, _R_A1, _R_A2, _R_A3]

# Entry-point argument registers. A trace that ends here is ARG_PROPAGATED.
_MIPS_ENTRY_ARG_SET = frozenset([_R_A0, _R_A1, _R_A2, _R_A3])

_MIPS_REG_NAMES: Dict[int, str] = {
    _R_ZERO: 'zero', _R_V0: 'v0', _R_V1: 'v1',
    _R_A0: 'a0', _R_A1: 'a1', _R_A2: 'a2', _R_A3: 'a3',
    _R_T9: 't9', _R_GP: 'gp', _R_SP: 'sp', _R_FP: 'fp', _R_RA: 'ra',
}

# ── Default sinks ─────────────────────────────────────────────────────────────
_DEFAULT_SINKS_MIPS: Dict[str, int] = {
    'system':    0,   # a0 = cmd
    'popen':     0,   # a0 = cmd
    'execve':    0,   # a0 = pathname
    'execvp':    0,
    'execl':     0,
    'execlp':    0,
}

# Snprintf-family sinks and their format-argument positions.
_SNPRINTF_FMT_POS_MIPS: Dict[str, int] = {
    'snprintf':        2,   # a2 = fmt
    'vsnprintf':       2,   # a2 = fmt
    'sprintf':         1,   # a1 = fmt
    '__sprintf_chk':   3,   # a3 = fmt (glibc fortified)
    '__snprintf_chk':  3,   # a3 = fmt (glibc fortified)
}

# ── Scan constants ────────────────────────────────────────────────────────────
_LOOKBACK = 80        # backward scan window in instructions
_SNPRINTF_WINDOW = 140
_MAX_FUNC_BYTES = 65536


def _rname(reg_id: int) -> str:
    return _MIPS_REG_NAMES.get(reg_id, f'r{reg_id}')


class SinkArgClassifierMIPS:
    """
    Classify exec-class sink call site argument provenance on MIPS32 ELFs.

    Uses BinaryContext for the call graph and PLT map. Both big-endian (BE) and
    little-endian (LE) MIPS32 binaries are supported; endianness is detected from
    the ELF header via lief.

    This module fills MIPS-GAP-002.
    """

    def __init__(self, ctx, big_endian: bool = True):
        self._ctx         = ctx
        self._big_endian  = big_endian
        self._data: bytes = Path(ctx.path).read_bytes()
        self._plt_rev: Dict[str, int] = {v: k for k, v in ctx.plt.items()}
        self._sinks: Dict[str, int]   = dict(_DEFAULT_SINKS_MIPS)
        self._snprintf_plts: Dict[int, int] = {}  # PLT VA → fmt arg position
        self._gp: int  = 0
        self._got: Dict[int, int] = {}  # GOT entry VA → value
        self._got_va: int = 0
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._dead_sinks: List[str] = []
        self._bin = None
        self._cs: Optional[Cs] = None
        if _CS_OK:
            mode = CS_MODE_MIPS32 + (CS_MODE_BIG_ENDIAN if big_endian else CS_MODE_LITTLE_ENDIAN)
            self._cs = Cs(CS_ARCH_MIPS, mode)
            self._cs.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(ctx.path)
        self._init()

    # ── construction ──────────────────────────────────────────────────────────

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierMIPS':
        big_endian = True
        if _LIEF_OK:
            try:
                b = _lief.parse(ctx.path)
                if b and hasattr(b.header, 'endianness'):
                    big_endian = 'BIG' in str(b.header.endianness).upper()
            except Exception:
                pass
        return cls(ctx, big_endian=big_endian)

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
                    (sec.virtual_address, sec.virtual_address + sec.size)
                )

        # .reginfo → $gp
        reginfo = self._bin.get_section('.reginfo')
        if reginfo:
            ri = bytes(reginfo.content)
            if len(ri) >= 24:
                endian = '>' if self._big_endian else '<'
                self._gp = int(struct.unpack_from(f'{endian}I', ri, 20)[0])

        # .got → VA → value map
        got_sec = self._bin.get_section('.got')
        if got_sec and self._gp:
            gd = bytes(got_sec.content)
            gva = int(got_sec.virtual_address)
            self._got_va = gva
            endian = '>' if self._big_endian else '<'
            count = len(gd) // 4
            vals = struct.unpack(endian + 'I' * count, gd[:count * 4])
            for i, v in enumerate(vals):
                self._got[gva + i * 4] = int(v)

        # Build snprintf PLT map
        for name, fmt_pos in _SNPRINTF_FMT_POS_MIPS.items():
            va = self._plt_rev.get(name)
            if va:
                self._snprintf_plts[va] = fmt_pos

    # ── helpers ───────────────────────────────────────────────────────────────

    def _is_rodata(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._rodata_ranges)

    def _resolve_got(self, gp_offset: int) -> Optional[int]:
        """Return the value stored in GOT at $gp + gp_offset. None if out of range."""
        if not self._gp:
            return None
        e_va = self._gp + gp_offset
        return self._got.get(e_va)

    def _va_to_file_offset(self, va: int) -> int:
        if self._bin is None:
            return va
        try:
            return self._bin.virtual_address_to_offset(va)
        except Exception:
            return -1

    def _read_va(self, va: int, size: int) -> bytes:
        off = self._va_to_file_offset(va)
        if off < 0 or off + size > len(self._data):
            return b''
        return self._data[off:off + size]

    def _writes_reg(self, insn, reg_id: int) -> bool:
        """True if insn's first operand writes to reg_id."""
        if not insn.operands:
            return False
        op = insn.operands[0]
        return op.type == MIPS_OP_REG and op.reg == reg_id

    def _next_func_va(self, func_va: int) -> Optional[int]:
        """Return the next function start after func_va, or None."""
        fs = self._ctx.func_starts
        if not fs:
            return None
        import bisect
        idx = bisect.bisect_right(fs, func_va)
        return fs[idx] if idx < len(fs) else None

    def _find_sink_plts(self) -> Dict[int, Tuple[str, int]]:
        """
        Return {sink_va: (sink_name, arg_pos)} for sinks with ≥1 known caller.
        Checks PLT stubs first, then ctx.exports for internal functions.
        callers_of is called by name (string) so that the call-graph index
        key resolves correctly for both PLT stubs and exported internals.
        """
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

    # ── per-function scan ─────────────────────────────────────────────────────

    def _get_insns(self, func_va: int) -> list:
        """Disassemble func_va up to MAX_FUNC_BYTES or next function start."""
        nxt = self._next_func_va(func_va)
        size = min(nxt - func_va if nxt else _MAX_FUNC_BYTES, _MAX_FUNC_BYTES)
        raw = self._read_va(func_va, size)
        if not raw or self._cs is None:
            return []
        return list(self._cs.disasm(raw, func_va))

    def _find_call_sites(self, insns: list, sink_va: int) -> List[int]:
        """Return indices in insns where a JALR $t9 calls sink_va."""
        sites: List[int] = []
        for i, insn in enumerate(insns):
            if insn.mnemonic != 'jalr':
                continue
            if not insn.operands or insn.operands[0].reg != _R_T9:
                continue
            # Look back up to 4 instructions for LW $t9, N($gp)
            for j in range(max(0, i - 4), i):
                prev = insns[j]
                if prev.mnemonic != 'lw':
                    continue
                if len(prev.operands) < 2:
                    continue
                if prev.operands[0].reg != _R_T9:
                    continue
                if prev.operands[1].type != MIPS_OP_MEM:
                    continue
                if prev.operands[1].mem.base != _R_GP:
                    continue
                tgt = self._resolve_got(prev.operands[1].mem.disp)
                if tgt == sink_va:
                    sites.append(i)
                    break
        return sites

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
            if arg_pos >= len(_MIPS_ARG_REGS):
                continue
            call_indices = self._find_call_sites(insns, sink_va)
            for ci in call_indices:
                arg_reg = _MIPS_ARG_REGS[arg_pos]
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

            # ── LW $aX, N($...) ───────────────────────────────────────────────
            if mnem == 'lw' and len(insn.operands) >= 2:
                src = insn.operands[1]
                if src.type == MIPS_OP_MEM:
                    base = src.mem.base
                    disp = src.mem.disp

                    # LW from $gp → GOT-relative load
                    if base == _R_GP:
                        tgt_va = self._resolve_got(disp)
                        if tgt_va is not None:
                            if self._is_rodata(tgt_va):
                                return (RODATA_CONST,
                                        f'LW ${_rname(arg_reg)},{disp}($gp) → 0x{tgt_va:x} in .rodata')
                            return (UNKNOWN,
                                    f'LW ${_rname(arg_reg)},{disp}($gp) → 0x{tgt_va:x} not .rodata')
                        return (UNKNOWN, f'LW ${_rname(arg_reg)},{disp}($gp): GOT unresolved')

                    # LW from $fp/$sp → stack slot
                    if base in (_R_FP, _R_SP):
                        # Snprintf buffer backtrack
                        snp = self._trace_snprintf_buf(insns, from_idx, base, disp, depth)
                        if snp is not None:
                            return snp
                        # Entry arg saved to stack
                        if self._is_entry_arg_save(insns, base, disp):
                            return (ARG_PROPAGATED,
                                    f'entry arg at ${_rname(base)}+{disp:#x}')
                        return (UNKNOWN, f'LW from stack ${_rname(base)}+{disp:#x}')

                    return (UNKNOWN, f'LW from [{_rname(base)}+{disp:#x}]')

            # ── ADDIU $aX, $src, imm ─────────────────────────────────────────
            elif mnem == 'addiu' and len(insn.operands) >= 3:
                src_op = insn.operands[1]
                imm_op = insn.operands[2]
                if src_op.type != MIPS_OP_REG or imm_op.type != MIPS_OP_IMM:
                    return (UNKNOWN, f'addiu operand mismatch @ 0x{insn.address:x}')

                src_reg = src_op.reg
                imm     = imm_op.imm
                # imm is already sign-extended by Capstone for 16-bit immediates

                if src_reg == _R_ZERO:
                    # ADDIU $aX, $zero, N — small constant (NULL, flag, etc.)
                    return (RODATA_CONST, f'ADDIU constant 0x{imm & 0xFFFFFFFF:x}')

                # ADDIU $aX, $vY/... , M — base + offset
                return self._trace_arg_addiu(insns, j, src_reg, imm, arg_reg, depth)

            # ── MOVE / OR / ADDU (register copy) ─────────────────────────────
            elif mnem == 'move' and len(insn.operands) >= 2:
                src_reg = insn.operands[1].reg if insn.operands[1].type == MIPS_OP_REG else None
                if src_reg is None:
                    return (UNKNOWN, f'MOVE src not reg @ 0x{insn.address:x}')
                if src_reg in _MIPS_ENTRY_ARG_SET:
                    return (ARG_PROPAGATED, f'MOVE from entry ${_rname(src_reg)}')
                return self._trace_arg(insns, j, src_reg, depth)

            elif mnem in ('or', 'addu') and len(insn.operands) == 3:
                # GCC move pattern: OR/ADDU $aX, $rY, $zero  or  OR $aX, $zero, $rZ
                r1 = insn.operands[1].reg if insn.operands[1].type == MIPS_OP_REG else None
                r2 = insn.operands[2].reg if insn.operands[2].type == MIPS_OP_REG else None
                src_reg = None
                if r2 == _R_ZERO and r1 is not None:
                    src_reg = r1
                elif r1 == _R_ZERO and r2 is not None:
                    src_reg = r2
                if src_reg is not None:
                    if src_reg in _MIPS_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED, f'OR/ADDU from entry ${_rname(src_reg)}')
                    return self._trace_arg(insns, j, src_reg, depth)
                return (UNKNOWN, f'{mnem} from non-zero pair @ 0x{insn.address:x}')

            else:
                return (UNKNOWN, f'{mnem} writes ${_rname(arg_reg)} @ 0x{insn.address:x}')

        return (UNKNOWN, f'${_rname(arg_reg)} write not found in {_LOOKBACK}-insn window')

    def _trace_arg_addiu(
        self,
        insns: list,
        addiu_idx: int,
        src_reg: int,
        imm: int,
        arg_reg: int,
        depth: int,
    ) -> Tuple[str, str]:
        """
        Trace ADDIU $aX, $src_reg, imm backward.
        Find what loaded $src_reg and compute the final string VA.

        Special case: ADDIU $aX, $fp/$sp, N computes the address of a local
        variable (frame pointer + offset). The frame pointer is not "set" by a
        prior instruction — it is the frame pointer by ABI invariant. Treat this
        immediately as a stack slot and run the snprintf buffer backtrack.
        """
        # $fp and $sp are ABI-invariant frame/stack pointers. ADDIU $aX, $fp/$sp, N
        # takes the address of a local variable. Skip the backward search and go
        # directly to snprintf buffer detection for that slot.
        if src_reg in (_R_FP, _R_SP):
            snp = self._trace_snprintf_buf(insns, addiu_idx, src_reg, imm, depth)
            if snp is not None:
                return snp
            if self._is_entry_arg_save(insns, src_reg, imm):
                return (ARG_PROPAGATED,
                        f'ADDIU ${_rname(arg_reg)}, ${_rname(src_reg)}, {imm:#x} → entry arg slot')
            return (UNKNOWN,
                    f'ADDIU ${_rname(arg_reg)}, ${_rname(src_reg)}, {imm:#x}: stack buf, no snprintf writer')

        limit = max(addiu_idx - _LOOKBACK, -1)
        for k in range(addiu_idx - 1, limit, -1):
            insn = insns[k]
            if not self._writes_reg(insn, src_reg):
                continue
            mnem = insn.mnemonic

            if mnem == 'lw' and len(insn.operands) >= 2:
                src = insn.operands[1]
                if src.type == MIPS_OP_MEM and src.mem.base == _R_GP:
                    base_va = self._resolve_got(src.mem.disp)
                    if base_va is not None:
                        str_va = base_va + imm
                        if self._is_rodata(str_va):
                            return (RODATA_CONST,
                                    f'LW ${_rname(src_reg)},{src.mem.disp}($gp)'
                                    f'+{imm} → 0x{str_va:x} in .rodata')
                        return (UNKNOWN,
                                f'LW ${_rname(src_reg)},{src.mem.disp}($gp)'
                                f'+{imm} → 0x{str_va:x} not .rodata')
                    return (UNKNOWN, f'LW ${_rname(src_reg)},{src.mem.disp}($gp): unresolved')

                if src.type == MIPS_OP_MEM and src.mem.base in (_R_FP, _R_SP):
                    # base from stack — UNKNOWN (too indirect for v1)
                    return (UNKNOWN,
                            f'ADDIU base ${_rname(src_reg)} from stack'
                            f' ${_rname(src.mem.base)}+{src.mem.disp:#x}')

            return (UNKNOWN,
                    f'ADDIU base ${_rname(src_reg)} set by {mnem} @ 0x{insn.address:x}')

        return (UNKNOWN, f'ADDIU base ${_rname(src_reg)} not found')

    # ── snprintf buffer backtrack ─────────────────────────────────────────────

    def _trace_snprintf_buf(
        self,
        insns: list,
        sink_idx: int,
        base_reg: int,
        disp: int,
        depth: int,
    ) -> Optional[Tuple[str, str]]:
        """
        Search backward from sink_idx for a snprintf/vsnprintf that wrote to
        the stack slot (base_reg, disp). If found and its format string is
        RODATA_CONST, return SNPRINTF_RODATA; else return the snprintf's verdict.
        Returns None if no snprintf writer is found.
        """
        limit = max(sink_idx - _SNPRINTF_WINDOW, -1)
        for i in range(sink_idx - 1, limit, -1):
            insn = insns[i]
            if insn.mnemonic != 'jalr':
                continue
            if not insn.operands or insn.operands[0].reg != _R_T9:
                continue

            # Find the LW $t9, N($gp) that precedes this JALR
            snp_plt_va: Optional[int] = None
            for j in range(max(0, i - 4), i):
                prev = insns[j]
                if prev.mnemonic != 'lw':
                    continue
                if len(prev.operands) < 2:
                    continue
                if prev.operands[0].reg != _R_T9:
                    continue
                if prev.operands[1].type != MIPS_OP_MEM:
                    continue
                if prev.operands[1].mem.base != _R_GP:
                    continue
                tgt = self._resolve_got(prev.operands[1].mem.disp)
                if tgt is not None and tgt in self._snprintf_plts:
                    snp_plt_va = tgt
                    break

            if snp_plt_va is None:
                continue

            # Check that $a0 (dest arg) is set to (base_reg + disp)
            if not self._a0_is_slot(insns, i, base_reg, disp):
                continue

            # Trace format arg: $a2 for snprintf/vsnprintf, $a1 for sprintf, etc.
            fmt_pos = self._snprintf_plts[snp_plt_va]
            if fmt_pos >= len(_MIPS_ARG_REGS):
                continue
            fmt_reg = _MIPS_ARG_REGS[fmt_pos]
            snp_name = self._ctx.plt.get(snp_plt_va, 'snprintf')

            verdict, detail = self._trace_arg(insns, i, fmt_reg, depth + 1)
            if verdict == RODATA_CONST:
                return (SNPRINTF_RODATA,
                        f'{snp_name}(${_rname(base_reg)}+{disp:#x}) fmt={detail}')
            return (verdict,
                    f'{snp_name}(${_rname(base_reg)}+{disp:#x}) fmt={detail}')

        return None

    def _a0_is_slot(
        self,
        insns: list,
        jalr_idx: int,
        base_reg: int,
        disp: int,
    ) -> bool:
        """
        True if, before the JALR at jalr_idx, $a0 is set to the address of
        (base_reg, disp) via ADDIU $a0, base_reg, disp.
        """
        limit = max(jalr_idx - _LOOKBACK, -1)
        for j in range(jalr_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, _R_A0):
                continue
            if insn.mnemonic != 'addiu':
                return False
            if len(insn.operands) < 3:
                return False
            src_op = insn.operands[1]
            imm_op = insn.operands[2]
            if src_op.type != MIPS_OP_REG or imm_op.type != MIPS_OP_IMM:
                return False
            return src_op.reg == base_reg and imm_op.imm == disp
        return False

    def _is_entry_arg_save(
        self,
        insns: list,
        base_reg: int,
        disp: int,
    ) -> bool:
        """
        True if the function prologue stores an entry $aX register to
        (base_reg, disp). Detects the O32 pattern:  SW $aX, disp($fp).
        """
        limit = min(len(insns), 20)
        for j in range(0, limit):
            insn = insns[j]
            if insn.mnemonic != 'sw':
                continue
            if len(insn.operands) < 2:
                continue
            src = insn.operands[0]
            dst = insn.operands[1]
            if src.type != MIPS_OP_REG or dst.type != MIPS_OP_MEM:
                continue
            if src.reg not in _MIPS_ENTRY_ARG_SET:
                continue
            if dst.mem.base == base_reg and dst.mem.disp == disp:
                return True
        return False

    # ── public interface ──────────────────────────────────────────────────────

    def classify_all(self) -> List[SinkClassification]:
        """Classify all sink call sites across all known function starts."""
        if self._cs is None:
            return []
        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []
        results: List[SinkClassification] = []
        for func_va in self._ctx.func_starts:
            results.extend(self._classify_function(func_va, sink_plts))
        return results

    def classify_sink(self, sink_name: str, arg_pos: Optional[int] = None) -> List[SinkClassification]:
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
            return '[sink_arg_classifier_mips] no results\n'
        by_verdict: Dict[str, int] = {}
        for r in results:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        hdr = (
            f'[sink_arg_classifier_mips] {len(results)} call site(s)  '
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
