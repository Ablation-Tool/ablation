"""
sink_arg_classifier_ppc32.py: classify exec-class sink argument provenance on PPC32 BE ELFs.

Gap this fills vs SinkArgClassifier:
  SinkArgClassifier hardcodes x86-64 registers (rdi, rsi, rdx).
  PPC32 System V ELF ABI passes the first eight arguments in r3-r10.
  That gap is CLSTRMGR-GAP-001 (HACMP clstrmgr).

Four verdicts (same as all other SinkArgClassifier variants):
  RODATA_CONST     — argument is a constant from .rodata or a literal immediate.
  SNPRINTF_RODATA  — argument is a stack buffer written by snprintf/vsnprintf
                     whose format string is RODATA_CONST.
  ARG_PROPAGATED   — argument traces back to an entry-point r3-r10 register.
  UNKNOWN          — provenance not resolved within the look-back window.

PPC32 System V ABI calling convention:
  Argument position 0 → r3  (Capstone PPC_REG_R3  = 90)
  Argument position 1 → r4  (Capstone PPC_REG_R4  = 91)
  Argument position 2 → r5  (Capstone PPC_REG_R5  = 92)
  Argument position 3 → r6  (Capstone PPC_REG_R6  = 93)
  Argument position 4 → r7  (Capstone PPC_REG_R7  = 94)
  Argument position 5 → r8  (Capstone PPC_REG_R8  = 95)
  Argument position 6 → r9  (Capstone PPC_REG_R9  = 96)
  Argument position 7 → r10 (Capstone PPC_REG_R10 = 97)

PPC32 string address load patterns:
  1. lis rX, HI; addi rX, rX, LO         — 32-bit address; HI+LO sign-extend.
     string_va = (HI << 16) + sign_extend_16(LO).
     If string_va in .rodata → RODATA_CONST.
  2. lis rX, HI; lwz rX, LO(rX)          — indirect: load pointer from (HI<<16)+LO.
     Dereference to get the actual string VA.  If target in .rodata → RODATA_CONST.
  3. li rX, imm                           — small immediate (NULL=0, flag).
     RODATA_CONST (literal constant).
  4. mr rX, rY  (decoded by Capstone as: or rD, rA, rA)
                                          — register copy.  Recurse on rA.
  5. addi rX, r1, N                       — address of stack slot.
     Trigger snprintf backtrack then entry-arg-save detection.
  6. lwz rX, N(r1)                        — stack slot load.
     Same backtrack path as addi r1.
  7. lwz rX, N(rY)  rY not r1            — struct field / heap offset.
     If rY is an entry-point argument register (r3–r10) → ARG_PROPAGATED.
     Otherwise → UNKNOWN.
  8. lbz/lhz rX, N(rY)                   — byte/halfword load — UNKNOWN.

Note: GOT-relative loads (lwz rX, N(r30)) are treated as UNKNOWN because resolving
them requires knowing the GOT base at runtime.  Only the lis+addi/lis+lwz forms
(absolute addressing) are fully resolved.

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier_ppc32 import SinkArgClassifierPPC32BE

    ctx = BinaryContext.load_or_build('/path/to/clstrmgr')
    clf = SinkArgClassifierPPC32BE.from_context(ctx)

    # Optionally add vendor-specific sinks beyond the defaults
    clf.add_sink('my_exec_wrapper', arg_pos=0)

    results = clf.classify_all()
    print(clf.report(results))

    flagged = [r for r in results if r.verdict not in ('RODATA_CONST', 'SNPRINTF_RODATA')]
"""

from __future__ import annotations

import bisect
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_CS_OK = False
try:
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
    from capstone.ppc_const import (
        PPC_OP_REG, PPC_OP_MEM, PPC_OP_IMM,
        PPC_REG_R0, PPC_REG_R1, PPC_REG_R2,
        PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
        PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10,
        PPC_REG_R30,
        PPC_INS_LIS, PPC_INS_ADDI, PPC_INS_LI,
        PPC_INS_LWZ, PPC_INS_STW, PPC_INS_BL,
        PPC_INS_OR,   # mr rD, rA  may be decoded as  or rD, rA, rA (older Capstone)
        PPC_INS_MR,   # or as explicit mr rD, rA (newer Capstone, id=759, 2 ops)
        PPC_INS_ORI,
        PPC_INS_LBZ, PPC_INS_LHZ,
    )
    _CS_OK = True
except ImportError:
    # Stubs so the module can be imported without Capstone
    (PPC_OP_REG, PPC_OP_MEM, PPC_OP_IMM) = (1, 3, 2)
    (PPC_REG_R0, PPC_REG_R1, PPC_REG_R2) = (87, 88, 89)
    (PPC_REG_R3, PPC_REG_R4, PPC_REG_R5,  PPC_REG_R6,
     PPC_REG_R7, PPC_REG_R8, PPC_REG_R9,  PPC_REG_R10) = range(90, 98)
    PPC_REG_R30 = 117
    (PPC_INS_LIS, PPC_INS_ADDI, PPC_INS_LI, PPC_INS_LWZ,
     PPC_INS_STW, PPC_INS_BL, PPC_INS_OR, PPC_INS_ORI,
     PPC_INS_LBZ, PPC_INS_LHZ, PPC_INS_MR) = (632, 4, 631, 651, 1066, 108, 843, 845, 594, 626, 759)

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

# Re-use shared verdict constants
from ablation.analyzers.sink_arg_classifier import (
    SinkClassification,
    RODATA_CONST,
    SNPRINTF_RODATA,
    ARG_PROPAGATED,
    UNKNOWN,
)

# ── PPC32 argument registers (r3 = arg0, r10 = arg7) ─────────────────────────
_PPC32_ARG_REGS: List[int] = [
    PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
    PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10,
]
_PPC32_ENTRY_ARG_SET = frozenset(_PPC32_ARG_REGS)

_PPC32_REG_NAMES: Dict[int, str] = {
    PPC_REG_R0:  'r0',  PPC_REG_R1:  'r1',  PPC_REG_R2:  'r2',
    PPC_REG_R3:  'r3',  PPC_REG_R4:  'r4',  PPC_REG_R5:  'r5',
    PPC_REG_R6:  'r6',  PPC_REG_R7:  'r7',  PPC_REG_R8:  'r8',
    PPC_REG_R9:  'r9',  PPC_REG_R10: 'r10', PPC_REG_R30: 'r30',
}

# ── Default exec-class sinks ──────────────────────────────────────────────────
_DEFAULT_SINKS_PPC32: Dict[str, int] = {
    'system':   0,
    'popen':    0,
    'execve':   0,
    'execvp':   0,
    'execl':    0,
    'execlp':   0,
    'strcpy':   0,   # dest
    'strcat':   0,   # dest
    'sprintf':  0,   # dest (format string check uses separate entry below)
}

# snprintf-family: fmt arg position (0-indexed, r3=pos0)
_SNPRINTF_FMT_POS_PPC32: Dict[str, int] = {
    'snprintf':       2,   # r3=buf, r4=size, r5=fmt
    'vsnprintf':      2,
    'sprintf':        1,   # r3=buf, r4=fmt
    '__sprintf_chk':  3,
    '__snprintf_chk': 3,
}

_LOOKBACK        = 80
_SNPRINTF_WINDOW = 140
_MAX_FUNC_BYTES  = 65536


def _rname(reg_id: int) -> str:
    return _PPC32_REG_NAMES.get(reg_id, f'r{reg_id}')


def _sign16(v: int) -> int:
    """Sign-extend a 16-bit value."""
    return v if v < 0x8000 else v - 0x10000


class SinkArgClassifierPPC32BE:
    """
    Classify exec-class sink call-site argument provenance on PPC32 BE ELFs.

    Fills CLSTRMGR-GAP-001 (HACMP clstrmgr) and any other ppc32 BE analysis gap.
    """

    def __init__(self, ctx) -> None:
        self._ctx                             = ctx
        self._data: bytes                     = Path(ctx.path).read_bytes()
        self._plt_rev: Dict[str, int]         = {v: k for k, v in ctx.plt.items()}
        self._sinks: Dict[str, int]           = dict(_DEFAULT_SINKS_PPC32)
        self._snprintf_plts: Dict[int, int]   = {}   # PLT VA → fmt arg position
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._dead_sinks: List[str]           = []
        self._bin                             = None
        self._cs: Optional[Cs]               = None
        if _CS_OK:
            self._cs = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
            self._cs.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(ctx.path)
        self._init()

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierPPC32BE':
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> 'SinkArgClassifierPPC32BE':
        """Build directly from an ELF path — constructs BinaryContext internally."""
        from ablation.analyzers.binary_context import BinaryContext
        ctx = BinaryContext.load_or_build(path)
        return cls(ctx)

    def add_sink(self, name: str, arg_pos: int) -> None:
        """Register a vendor-specific exec-class sink."""
        self._sinks[name] = arg_pos

    # ── initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        for sec in self._bin.sections:
            if sec.name in ('.rodata', '.rodata1', '__const', '__cstring',
                            '.rdata', '.got2', '.data.rel.ro'):
                self._rodata_ranges.append(
                    (int(sec.virtual_address),
                     int(sec.virtual_address) + int(sec.size))
                )
        for name, fmt_pos in _SNPRINTF_FMT_POS_PPC32.items():
            va = self._plt_rev.get(name)
            if va:
                self._snprintf_plts[va] = fmt_pos

    # ── helpers ───────────────────────────────────────────────────────────────

    def _is_rodata(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._rodata_ranges)

    def _va_to_file_offset(self, va: int) -> int:
        if self._bin is None:
            return va - self._ctx.base_va
        try:
            return int(self._bin.virtual_address_to_offset(va))
        except Exception:
            return -1

    def _read_va(self, va: int, size: int) -> bytes:
        off = self._va_to_file_offset(va)
        if off < 0 or off >= len(self._data):
            return b''
        return self._data[off:off + size]

    def _read_u32_be(self, va: int) -> Optional[int]:
        raw = self._read_va(va, 4)
        if len(raw) < 4:
            return None
        return struct.unpack_from('>I', raw)[0]

    def _writes_reg(self, insn, reg_id: int) -> bool:
        """True if insn's first operand writes to reg_id."""
        if not insn.operands:
            return False
        op = insn.operands[0]
        return op.type == PPC_OP_REG and op.reg == reg_id

    def _next_func_va(self, func_va: int) -> Optional[int]:
        fs = self._ctx.func_starts
        if not fs:
            return None
        idx = bisect.bisect_right(fs, func_va)
        return fs[idx] if idx < len(fs) else None

    def _find_sink_plts(self) -> Dict[int, Tuple[str, int]]:
        result: Dict[int, Tuple[str, int]] = {}
        self._dead_sinks = []
        for name, arg_pos in self._sinks.items():
            va = self._plt_rev.get(name) or self._ctx.exports.get(name)
            if not va:
                # Also try versioned names (e.g. "strcpy@@GLIBC_2.0")
                for key in self._plt_rev:
                    if isinstance(key, str) and key.startswith(name + '@@'):
                        va = self._plt_rev[key]
                        break
            if not va:
                continue
            callers = list(self._ctx.callers_of(va))
            if not callers:
                self._dead_sinks.append(name)
            else:
                result[va] = (name, arg_pos)
        return result

    # ── per-function disassembly ──────────────────────────────────────────────

    def _get_insns(self, func_va: int) -> list:
        if self._cs is None:
            return []
        nxt  = self._next_func_va(func_va)
        size = min(nxt - func_va if nxt else _MAX_FUNC_BYTES, _MAX_FUNC_BYTES)
        raw  = self._read_va(func_va, size)
        if not raw:
            return []
        return list(self._cs.disasm(raw, func_va))

    def _find_call_sites(self, insns: list, sink_va: int) -> List[int]:
        sites: List[int] = []
        for i, insn in enumerate(insns):
            if insn.id != PPC_INS_BL:
                continue
            if not insn.operands:
                continue
            op = insn.operands[0]
            if op.type == PPC_OP_IMM and op.imm == sink_va:
                sites.append(i)
        return sites

    # ── backward argument trace ───────────────────────────────────────────────

    def _find_preceding_lis(
        self,
        insns: list,
        from_j: int,
        reg_id: int,
    ) -> Optional[int]:
        """
        Scan backward from from_j - 1 for a 'lis reg_id, HI' instruction.
        Returns the HI value (0..0xFFFF) if found, else None.
        Stops if any other instruction writes reg_id (the lis would have been overwritten).
        """
        for k in range(from_j - 1, max(from_j - 6, -1), -1):
            insn = insns[k]
            if insn.id == PPC_INS_LIS and self._writes_reg(insn, reg_id):
                return insn.operands[1].imm & 0xFFFF
            if self._writes_reg(insn, reg_id):
                return None  # something else set reg_id; lis not the source
        return None

    def _resolve_lis_pair(
        self,
        insns: list,
        addi_or_lwz_j: int,
        arg_reg: int,
        lo: int,
    ) -> Optional[Tuple[str, str]]:
        """
        Try to resolve a lis+addi or lis+lwz pair whose second half is at addi_or_lwz_j.
        lo is the signed offset/immediate from the second instruction.
        Returns a (verdict, detail) pair, or None if no preceding lis was found.
        """
        hi = self._find_preceding_lis(insns, addi_or_lwz_j, arg_reg)
        if hi is None:
            return None
        string_va = ((hi << 16) + _sign16(lo & 0xFFFF)) & 0xFFFFFFFF
        if self._is_rodata(string_va):
            return (RODATA_CONST,
                    f'lis+addi/lwz {_rname(arg_reg)} → {string_va:#010x} in .rodata')
        # Could be a pointer stored in .data pointing into .rodata
        val = self._read_u32_be(string_va)
        if val is not None and self._is_rodata(val):
            return (RODATA_CONST,
                    f'lis+addi/lwz → ptr {string_va:#010x} → {val:#010x} in .rodata')
        return (UNKNOWN, f'lis+addi/lwz → {string_va:#010x} not .rodata')

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

            # ── li rX, imm (small immediate — id PPC_INS_LI = 631) ───────────
            if insn.id == PPC_INS_LI:
                return (RODATA_CONST,
                        f'li {_rname(arg_reg)}, #{insn.operands[1].imm:#x}')

            # ── lis rX, HI — no paired addi/lwz found before we got here ──────
            # (This branch is reached only when the forward scan from lis lands here,
            # which can happen when addi/lwz are outside the lookback window or absent.)
            if insn.id == PPC_INS_LIS:
                hi = insn.operands[1].imm & 0xFFFF
                # Scan forward for paired addi/lwz
                for k in range(j + 1, min(j + 6, len(insns))):
                    nxt = insns[k]
                    if nxt.id == PPC_INS_ADDI and self._writes_reg(nxt, arg_reg):
                        ops = nxt.operands
                        if len(ops) >= 3 and ops[1].reg == arg_reg:
                            lo   = _sign16(ops[2].imm & 0xFFFF)
                            addr = ((hi << 16) + lo) & 0xFFFFFFFF
                            if self._is_rodata(addr):
                                return (RODATA_CONST,
                                        f'lis+addi {_rname(arg_reg)} → {addr:#010x} in .rodata')
                            val = self._read_u32_be(addr)
                            if val is not None and self._is_rodata(val):
                                return (RODATA_CONST,
                                        f'lis+addi → ptr {addr:#010x} → {val:#010x} in .rodata')
                            return (UNKNOWN, f'lis+addi → {addr:#010x} not .rodata')
                    if nxt.id == PPC_INS_LWZ and self._writes_reg(nxt, arg_reg):
                        ops = nxt.operands
                        if (len(ops) >= 2 and ops[1].type == PPC_OP_MEM
                                and ops[1].mem.base == arg_reg):
                            lo    = _sign16(ops[1].mem.disp & 0xFFFF)
                            ptr_v = ((hi << 16) + lo) & 0xFFFFFFFF
                            val   = self._read_u32_be(ptr_v)
                            if val is not None and self._is_rodata(val):
                                return (RODATA_CONST,
                                        f'lis+lwz → {ptr_v:#010x} → {val:#010x} in .rodata')
                            return (UNKNOWN, f'lis+lwz → {ptr_v:#010x}: not .rodata or unreadable')
                    if self._writes_reg(nxt, arg_reg) and nxt.id not in (
                            PPC_INS_LIS, PPC_INS_ADDI, PPC_INS_LWZ):
                        break
                return (UNKNOWN, f'lis {_rname(arg_reg)}: no paired addi/lwz within 5 insns')

            # ── mr rD, rA — Capstone may emit either PPC_INS_MR (2 ops) or ─────
            # ── PPC_INS_OR (3 ops, rA==rB) depending on version.            ─────
            if insn.id == PPC_INS_MR:
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == PPC_OP_REG:
                    src_reg = ops[1].reg
                    if src_reg in _PPC32_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'mr {_rname(arg_reg)}, {_rname(src_reg)} (entry arg)')
                    return self._trace_arg(insns, j, src_reg, depth)
                return (UNKNOWN, f'mr {_rname(arg_reg)}: unknown src')

            if insn.id == PPC_INS_OR:
                ops = insn.operands
                if len(ops) == 3 and ops[1].type == PPC_OP_REG and ops[2].type == PPC_OP_REG:
                    if ops[1].reg == ops[2].reg:  # mr pattern (or rD, rA, rA)
                        src_reg = ops[1].reg
                        if src_reg in _PPC32_ENTRY_ARG_SET:
                            return (ARG_PROPAGATED,
                                    f'mr {_rname(arg_reg)}, {_rname(src_reg)} (entry arg)')
                        return self._trace_arg(insns, j, src_reg, depth)
                return (UNKNOWN, f'or {_rname(arg_reg)}: non-mr pattern')

            # ── addi rX, r1, N — address of stack slot ────────────────────────
            if insn.id == PPC_INS_ADDI:
                ops = insn.operands
                if len(ops) >= 3 and ops[1].type == PPC_OP_REG:
                    base_r = ops[1].reg
                    lo_val = ops[2].imm

                    if base_r == PPC_REG_R1:
                        disp = lo_val
                        snp = self._trace_snprintf_buf(insns, from_idx, PPC_REG_R1, disp, depth)
                        if snp is not None:
                            return snp
                        if self._is_entry_arg_save(insns, PPC_REG_R1, disp):
                            return (ARG_PROPAGATED, f'entry arg at r1+{disp:#x}')
                        return (UNKNOWN, f'addi {_rname(arg_reg)}, r1, {disp:#x}')

                    if base_r == arg_reg:
                        # Possible second half of lis+addi pair
                        pair = self._resolve_lis_pair(insns, j, arg_reg, lo_val)
                        if pair is not None:
                            return pair

                    # addi rD, rBase, imm where rBase is an entry arg
                    if base_r in _PPC32_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'addi {_rname(arg_reg)}, {_rname(base_r)}: entry+imm')

                return (UNKNOWN,
                        f'addi {_rname(arg_reg)}: unknown base @ {insn.address:#010x}')

            # ── lwz rX, N(rY) — memory load ──────────────────────────────────
            if insn.id == PPC_INS_LWZ:
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == PPC_OP_MEM:
                    base_reg = ops[1].mem.base
                    disp     = ops[1].mem.disp

                    if base_reg == PPC_REG_R1:
                        snp = self._trace_snprintf_buf(insns, from_idx, PPC_REG_R1, disp, depth)
                        if snp is not None:
                            return snp
                        if self._is_entry_arg_save(insns, PPC_REG_R1, disp):
                            return (ARG_PROPAGATED, f'entry arg saved at r1+{disp:#x}')
                        return (UNKNOWN, f'lwz {_rname(arg_reg)}, {disp:#x}(r1)')

                    if base_reg == arg_reg:
                        # Possible second half of lis+lwz pair (indirect load)
                        pair = self._resolve_lis_pair(insns, j, arg_reg, disp)
                        if pair is not None:
                            return pair

                    if base_reg in _PPC32_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'lwz {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)})'
                                f' struct field of entry arg')
                    return (UNKNOWN,
                            f'lwz {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)})')

            # ── lbz/lhz — byte/halfword load → UNKNOWN ───────────────────────
            if insn.id in (PPC_INS_LBZ, PPC_INS_LHZ):
                return (UNKNOWN, f'{insn.mnemonic} {_rname(arg_reg)} @ {insn.address:#010x}')

            # ── any other writer ──────────────────────────────────────────────
            ops = insn.operands
            if (len(ops) >= 2 and ops[1].type == PPC_OP_REG
                    and ops[1].reg in _PPC32_ENTRY_ARG_SET):
                return (ARG_PROPAGATED,
                        f'{insn.mnemonic}: src {_rname(ops[1].reg)} is entry arg')
            return (UNKNOWN,
                    f'{insn.mnemonic} writes {_rname(arg_reg)} @ {insn.address:#010x}')

        # No writer found — unmodified entry registers are entry args
        if arg_reg in _PPC32_ENTRY_ARG_SET:
            return (ARG_PROPAGATED,
                    f'{_rname(arg_reg)} unmodified in {_LOOKBACK}-insn window: entry arg')
        return (UNKNOWN, f'{_rname(arg_reg)} write not found in {_LOOKBACK}-insn window')

    # ── snprintf buffer backtrack ─────────────────────────────────────────────

    def _trace_snprintf_buf(
        self,
        insns: list,
        sink_idx: int,
        base_reg: int,
        disp: int,
        depth: int,
    ) -> Optional[Tuple[str, str]]:
        """Search backward for snprintf/vsnprintf that wrote to stack at (base_reg, disp)."""
        limit = max(sink_idx - _SNPRINTF_WINDOW, -1)
        for i in range(sink_idx - 1, limit, -1):
            insn = insns[i]
            if insn.id != PPC_INS_BL:
                continue
            if not insn.operands:
                continue
            op = insn.operands[0]
            if op.type != PPC_OP_IMM:
                continue
            snp_plt_va = op.imm
            if snp_plt_va not in self._snprintf_plts:
                continue
            if not self._r3_is_slot(insns, i, base_reg, disp):
                continue

            fmt_pos  = self._snprintf_plts[snp_plt_va]
            if fmt_pos >= len(_PPC32_ARG_REGS):
                continue
            fmt_reg  = _PPC32_ARG_REGS[fmt_pos]
            snp_name = self._ctx.plt.get(snp_plt_va, 'snprintf')

            verdict, detail = self._trace_arg(insns, i, fmt_reg, depth + 1)
            if verdict == RODATA_CONST:
                return (SNPRINTF_RODATA,
                        f'{snp_name}(r1+{disp:#x}) fmt={detail}')
            return (verdict, f'{snp_name}(r1+{disp:#x}) fmt={detail}')
        return None

    def _r3_is_slot(
        self,
        insns: list,
        bl_idx: int,
        base_reg: int,
        disp: int,
    ) -> bool:
        """True if r3 (dest of snprintf) is set to address of stack slot (base_reg, disp)."""
        limit = max(bl_idx - _LOOKBACK, -1)
        for j in range(bl_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, PPC_REG_R3):
                continue
            # addi r3, r1, N
            if insn.id == PPC_INS_ADDI:
                ops = insn.operands
                if (len(ops) >= 3
                        and ops[1].type == PPC_OP_REG
                        and ops[1].reg == base_reg
                        and ops[2].type == PPC_OP_IMM
                        and ops[2].imm == disp):
                    return True
            return False
        return False

    def _is_entry_arg_save(
        self,
        insns: list,
        base_reg: int,
        disp: int,
    ) -> bool:
        """
        True if there is a stw rX, disp(base_reg) in the function prologue where
        rX is in r3..r10 (i.e., an entry argument was saved to the stack at this slot).
        """
        for insn in insns:
            if insn.id != PPC_INS_STW:
                continue
            ops = insn.operands
            if len(ops) < 2:
                continue
            if ops[0].type == PPC_OP_REG and ops[0].reg in _PPC32_ENTRY_ARG_SET:
                if (ops[1].type == PPC_OP_MEM
                        and ops[1].mem.base == base_reg
                        and ops[1].mem.disp == disp):
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
            for call_idx in self._find_call_sites(insns, sink_va):
                if arg_pos >= len(_PPC32_ARG_REGS):
                    continue
                arg_reg = _PPC32_ARG_REGS[arg_pos]
                verdict, detail = self._trace_arg(insns, call_idx, arg_reg)
                severity = '' if verdict in (RODATA_CONST, SNPRINTF_RODATA) else 'HIGH'
                results.append(SinkClassification(
                    sink_name, arg_pos, func_va,
                    insns[call_idx].address,
                    verdict, detail, severity,
                ))
        return results

    # ── public API ────────────────────────────────────────────────────────────

    def classify_all(self) -> List[SinkClassification]:
        """Run classification across all callers of registered sinks."""
        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []
        results: List[SinkClassification] = []
        seen_funcs: set = set()
        for sink_va, (sink_name, arg_pos) in sink_plts.items():
            for entry in self._ctx.callers_of(sink_va):
                # callers_of may return (va, name) tuples or plain ints
                caller_va = entry[0] if isinstance(entry, tuple) else entry
                if caller_va in seen_funcs:
                    continue
                seen_funcs.add(caller_va)
                results.extend(self._classify_function(caller_va, sink_plts))
        return results

    def classify_sink(self, sink_name: str) -> List[SinkClassification]:
        """Run classification for a single named sink only."""
        arg_pos = self._sinks.get(sink_name)
        if arg_pos is None:
            return []
        va = self._plt_rev.get(sink_name) or self._ctx.exports.get(sink_name)
        if not va:
            return []
        sink_plts = {va: (sink_name, arg_pos)}
        results: List[SinkClassification] = []
        for entry in self._ctx.callers_of(va):
            caller_va = entry[0] if isinstance(entry, tuple) else entry
            results.extend(self._classify_function(caller_va, sink_plts))
        return results

    def report(self, results: List[SinkClassification]) -> str:
        if not results:
            return 'SinkArgClassifierPPC32BE: no results\n'
        lines = [f'SinkArgClassifierPPC32BE: {len(results)} results']
        for r in results:
            lines.append(
                f'  {r.verdict:16s} {r.sink_name}(arg{r.arg_pos})'
                f' func={r.func_va:#010x} call={r.call_va:#010x}'
                f' detail={r.detail}'
            )
        by_verdict: Dict[str, int] = {}
        for r in results:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        lines.append('Summary: ' + ' | '.join(f'{k}={v}' for k, v in sorted(by_verdict.items())))
        if self._dead_sinks:
            lines.append(f'Dead sinks (no callers): {", ".join(self._dead_sinks)}')
        return '\n'.join(lines) + '\n'


# Backward-compat alias: the class was previously named SinkArgClassifierPPC32.
# sac_for_path() and callers should use SinkArgClassifierPPC32BE (the canonical name).
SinkArgClassifierPPC32 = SinkArgClassifierPPC32BE
