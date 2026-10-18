"""
sink_arg_classifier_ppc64.py: classify exec-class sink argument provenance on PPC64 ELFs.

Gap this fills vs SinkArgClassifier:
  SinkArgClassifier hardcodes x86-64 registers (rdi, rsi, rdx).
  PPC64 ABIv2 passes the first eight arguments in r3-r10.
  That gap is ARCH-GAP-PPC64LE (AdvanceToolchain ppc64le Linux).

Four verdicts (same as all other SinkArgClassifier variants):
  RODATA_CONST     — argument is a constant from .rodata or a literal immediate.
  SNPRINTF_RODATA  — argument is a stack buffer written by snprintf/vsnprintf
                     whose format string is RODATA_CONST.
  ARG_PROPAGATED   — argument traces back to an entry-point r3-r10 register.
  UNKNOWN          — provenance not resolved within the look-back window.

PPC64 ABIv2 calling convention:
  Argument position 0 → r3  (Capstone PPC_REG_R3  = 90)
  Argument position 1 → r4  (Capstone PPC_REG_R4  = 91)
  Argument position 2 → r5  (Capstone PPC_REG_R5  = 92)
  Argument position 3 → r6  (Capstone PPC_REG_R6  = 93)
  Argument position 4 → r7  (Capstone PPC_REG_R7  = 94)
  Argument position 5 → r8  (Capstone PPC_REG_R8  = 95)
  Argument position 6 → r9  (Capstone PPC_REG_R9  = 96)
  Argument position 7 → r10 (Capstone PPC_REG_R10 = 97)
  TOC base → r2 (initialized to .TOC. symbol value at function entry)

PPC64le string address load patterns:
  1. addis rX, r2, HI; addi rX, rX, LO  — TOC-relative addr (most common in ABIv2).
     string_va = toc_base + sign16(HI)<<16 + sign16(LO).
     If string_va in .rodata → RODATA_CONST.
  2. addis rX, r2, HI; ld rX, LO(rX)   — TOC-indirect pointer load.
     ptr_va = toc_base + sign16(HI)<<16 + sign16(LO); val = *ptr_va.
     If val in .rodata → RODATA_CONST.
  3. li rX, imm                          — small immediate (NULL=0, flag).
     RODATA_CONST (literal constant).
  4. mr rX, rY  (or: or rD, rA, rA)     — register copy.  Recurse on rA.
  5. addi rX, r1, N                      — address of stack slot.
     Trigger snprintf backtrack then entry-arg-save detection.
  6. ld rX, N(r1)                        — stack slot load.
     Same backtrack path as addi r1.
  7. ld rX, N(rY)  rY not r1/r2         — struct field / heap offset.
     If rY is an entry-point argument register (r3–r10) → ARG_PROPAGATED.
     Otherwise → UNKNOWN.
  8. Also handles ppc64 BE (EI_DATA=2) via CS_MODE_BIG_ENDIAN.

Note: GOT-relative loads through unknown base registers are UNKNOWN.
Only addis-r2 patterns (absolute TOC-relative) are fully resolved.

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier_ppc64 import SinkArgClassifierPPC64

    ctx = BinaryContext.load_or_build('/path/to/gcc')
    clf = SinkArgClassifierPPC64.from_context(ctx)
    results = clf.classify_all()
    print(clf.report(results))
"""

from __future__ import annotations

import bisect
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_CS_OK = False
try:
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_64, CS_MODE_BIG_ENDIAN
    from capstone.ppc_const import (
        PPC_OP_REG, PPC_OP_MEM, PPC_OP_IMM,
        PPC_REG_R0, PPC_REG_R1, PPC_REG_R2,
        PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
        PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10,
        PPC_INS_ADDI, PPC_INS_ADDIS, PPC_INS_LI, PPC_INS_LIS,
        PPC_INS_LD, PPC_INS_STD, PPC_INS_LWZ, PPC_INS_STW,
        PPC_INS_BL,
        PPC_INS_OR, PPC_INS_MR,
        PPC_INS_LBZ, PPC_INS_LHZ,
    )
    _CS_OK = True
except ImportError:
    (PPC_OP_REG, PPC_OP_MEM, PPC_OP_IMM) = (1, 3, 2)
    (PPC_REG_R0, PPC_REG_R1, PPC_REG_R2) = (87, 88, 89)
    (PPC_REG_R3, PPC_REG_R4, PPC_REG_R5,  PPC_REG_R6,
     PPC_REG_R7, PPC_REG_R8, PPC_REG_R9,  PPC_REG_R10) = range(90, 98)
    (PPC_INS_ADDI, PPC_INS_ADDIS, PPC_INS_LI, PPC_INS_LIS) = (4, 6, 631, 632)
    (PPC_INS_LD, PPC_INS_STD, PPC_INS_LWZ, PPC_INS_STW) = (599, 1032, 651, 1066)
    PPC_INS_BL = 108
    (PPC_INS_OR, PPC_INS_MR) = (843, 759)
    (PPC_INS_LBZ, PPC_INS_LHZ) = (594, 626)
    CS_ARCH_PPC = 4
    CS_MODE_64 = 8
    CS_MODE_BIG_ENDIAN = 2147483648

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

_PPC64_ARG_REGS: List[int] = [
    PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
    PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10,
]
_PPC64_ENTRY_ARG_SET = frozenset(_PPC64_ARG_REGS)

_PPC64_REG_NAMES: Dict[int, str] = {
    PPC_REG_R0:  'r0',  PPC_REG_R1:  'r1',  PPC_REG_R2:  'r2',
    PPC_REG_R3:  'r3',  PPC_REG_R4:  'r4',  PPC_REG_R5:  'r5',
    PPC_REG_R6:  'r6',  PPC_REG_R7:  'r7',  PPC_REG_R8:  'r8',
    PPC_REG_R9:  'r9',  PPC_REG_R10: 'r10',
}

_DEFAULT_SINKS_PPC64: Dict[str, int] = {
    'system':   0,
    'popen':    0,
    'execve':   0,
    'execvp':   0,
    'execl':    0,
    'execlp':   0,
    'execle':   0,
    'execvpe':  0,
}

_SNPRINTF_FMT_POS_PPC64: Dict[str, int] = {
    'snprintf':       2,
    'vsnprintf':      2,
    'sprintf':        1,
    '__sprintf_chk':  3,
    '__snprintf_chk': 3,
}

_LOOKBACK        = 80
_SNPRINTF_WINDOW = 140
_MAX_FUNC_BYTES  = 65536


def _rname(reg_id: int) -> str:
    return _PPC64_REG_NAMES.get(reg_id, f'r?{reg_id}')


def _sign16(v: int) -> int:
    return v if v < 0x8000 else v - 0x10000


def _is_ppc64le(path: str) -> bool:
    with open(path, 'rb') as f:
        h = f.read(6)
    return h[:4] == b'\x7fELF' and h[4] == 2 and h[5] == 1


class SinkArgClassifierPPC64:
    """
    Classify exec-class sink call-site argument provenance on PPC64 ELFs.

    Fills ARCH-GAP-PPC64LE (AdvanceToolchain at17.0 ppc64le Linux) and any
    other ppc64 LE/BE binary analysis gap.
    """

    def __init__(self, ctx) -> None:
        self._ctx                              = ctx
        self._data: bytes                      = Path(ctx.path).read_bytes()
        self._plt_rev: Dict[str, int]          = {v: k for k, v in ctx.plt.items()}
        self._sinks: Dict[str, int]            = dict(_DEFAULT_SINKS_PPC64)
        self._snprintf_plts: Dict[int, int]    = {}
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._toc_base: int                    = 0
        self._dead_sinks: List[str]            = []
        self._bin                              = None
        self._cs: Optional[Cs]                = None
        if _CS_OK:
            is_le = _is_ppc64le(ctx.path)
            mode = CS_MODE_64 if is_le else (CS_MODE_64 | CS_MODE_BIG_ENDIAN)
            self._cs = Cs(CS_ARCH_PPC, mode)
            self._cs.detail = True
        if _LIEF_OK:
            self._bin = _lief.ELF.parse(ctx.path)
        self._init()

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierPPC64':
        return cls(ctx)

    def add_sink(self, name: str, arg_pos: int) -> None:
        self._sinks[name] = arg_pos

    # ── initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        for sec in self._bin.sections:
            if sec.name in ('.rodata', '.rodata1', '__const', '__cstring',
                            '.rdata', '.data.rel.ro', '.got2'):
                self._rodata_ranges.append(
                    (int(sec.virtual_address),
                     int(sec.virtual_address) + int(sec.size))
                )
        # Resolve TOC base: the .TOC. symbol value (r2 at function entry in ABIv2)
        for sym in self._bin.symbols:
            if sym.name == '.TOC.':
                self._toc_base = int(sym.value)
                break
        if not self._toc_base:
            for sec in self._bin.sections:
                if sec.name in ('.toc', '.got'):
                    self._toc_base = int(sec.virtual_address)
                    break
        # snprintf PLT entries
        for name, fmt_pos in _SNPRINTF_FMT_POS_PPC64.items():
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

    def _read_u64(self, va: int, little_endian: bool = True) -> Optional[int]:
        raw = self._read_va(va, 8)
        if len(raw) < 8:
            return None
        fmt = '<Q' if little_endian else '>Q'
        return struct.unpack_from(fmt, raw)[0]

    def _read_u32(self, va: int, little_endian: bool = True) -> Optional[int]:
        raw = self._read_va(va, 4)
        if len(raw) < 4:
            return None
        fmt = '<I' if little_endian else '>I'
        return struct.unpack_from(fmt, raw)[0]

    def _writes_reg(self, insn, reg_id: int) -> bool:
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

    # ── TOC-relative address resolution ──────────────────────────────────────

    def _resolve_addis_r2(
        self,
        insns: list,
        from_j: int,
        arg_reg: int,
    ) -> Optional[int]:
        """
        Scan backward from from_j - 1 for 'addis arg_reg, r2, HI'.
        Returns HI (0..0xFFFF) if found, None otherwise.
        Stops if anything else writes arg_reg.
        """
        for k in range(from_j - 1, max(from_j - 8, -1), -1):
            insn = insns[k]
            if insn.id == PPC_INS_ADDIS and self._writes_reg(insn, arg_reg):
                ops = insn.operands
                if (len(ops) >= 3 and ops[1].type == PPC_OP_REG
                        and ops[1].reg == PPC_REG_R2):
                    return ops[2].imm & 0xFFFF
                return None  # addis from non-r2 base
            if self._writes_reg(insn, arg_reg):
                return None
        return None

    def _resolve_toc_pair(
        self,
        insns: list,
        second_j: int,
        arg_reg: int,
        lo: int,
        is_ld: bool,
    ) -> Optional[Tuple[str, str]]:
        """
        Try to resolve addis-r2+addi or addis-r2+ld pair.
        lo is the signed displacement/immediate from the second instruction.
        is_ld: True for ld (pointer load); False for addi (direct address).
        """
        hi = self._resolve_addis_r2(insns, second_j, arg_reg)
        if hi is None:
            return None
        is_le = _is_ppc64le(self._ctx.path)
        offset = (_sign16(hi) << 16) + _sign16(lo & 0xFFFF)
        string_va = (self._toc_base + offset) & 0xFFFFFFFFFFFFFFFF
        if is_ld:
            val = self._read_u64(string_va, is_le)
            if val is not None and self._is_rodata(val):
                return (RODATA_CONST,
                        f'addis-r2+ld → ptr {string_va:#018x} → {val:#018x} in .rodata')
            return (UNKNOWN, f'addis-r2+ld → {string_va:#018x}: target not .rodata')
        else:
            if self._is_rodata(string_va):
                return (RODATA_CONST,
                        f'addis-r2+addi → {string_va:#018x} in .rodata')
            val = self._read_u64(string_va, is_le)
            if val is not None and self._is_rodata(val):
                return (RODATA_CONST,
                        f'addis-r2+addi → ptr {string_va:#018x} → {val:#018x} in .rodata')
            return (UNKNOWN, f'addis-r2+addi → {string_va:#018x} not .rodata')

    # ── backward argument trace ───────────────────────────────────────────────

    def _trace_arg(
        self,
        insns: list,
        from_idx: int,
        arg_reg: int,
        depth: int = 0,
    ) -> Tuple[str, str]:
        if depth > 1:
            return (UNKNOWN, 'max recursion depth')

        limit = max(from_idx - _LOOKBACK, -1)

        for j in range(from_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, arg_reg):
                continue

            # ── li rX, imm ────────────────────────────────────────────────────
            if insn.id == PPC_INS_LI:
                return (RODATA_CONST,
                        f'li {_rname(arg_reg)}, #{insn.operands[1].imm:#x}')

            # ── addis rX, r2, HI — TOC-relative high half ────────────────────
            if insn.id == PPC_INS_ADDIS:
                ops = insn.operands
                if len(ops) >= 3 and ops[1].type == PPC_OP_REG:
                    base_r = ops[1].reg
                    hi_val = ops[2].imm & 0xFFFF
                    if base_r == PPC_REG_R2 and self._toc_base:
                        # Standalone addis r2+HI with no following addi/ld yet seen
                        addr = (self._toc_base + (_sign16(hi_val) << 16)) & 0xFFFFFFFFFFFFFFFF
                        if self._is_rodata(addr):
                            return (RODATA_CONST, f'addis-r2 {_rname(arg_reg)} → {addr:#018x} in .rodata')
                        return (UNKNOWN, f'addis-r2 {_rname(arg_reg)} hi only → {addr:#018x}')
                    if base_r in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'addis {_rname(arg_reg)}, {_rname(base_r)}: entry+hi')
                return (UNKNOWN, f'addis {_rname(arg_reg)} unknown base')

            # ── addi rX, rY, LO ──────────────────────────────────────────────
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
                        pair = self._resolve_toc_pair(insns, j, arg_reg, lo_val, is_ld=False)
                        if pair is not None:
                            return pair

                    if base_r in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'addi {_rname(arg_reg)}, {_rname(base_r)}: entry+imm')

                return (UNKNOWN, f'addi {_rname(arg_reg)}: unknown base @ {insn.address:#018x}')

            # ── ld rX, N(rY) — 64-bit memory load ────────────────────────────
            if insn.id == PPC_INS_LD:
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == PPC_OP_MEM:
                    base_reg = ops[1].mem.base
                    disp     = ops[1].mem.disp

                    if base_reg == PPC_REG_R1:
                        snp = self._trace_snprintf_buf(insns, from_idx, PPC_REG_R1, disp, depth)
                        if snp is not None:
                            return snp
                        if self._is_entry_arg_save_64(insns, PPC_REG_R1, disp):
                            return (ARG_PROPAGATED, f'entry arg saved at r1+{disp:#x}')
                        return (UNKNOWN, f'ld {_rname(arg_reg)}, {disp:#x}(r1)')

                    if base_reg == arg_reg:
                        pair = self._resolve_toc_pair(insns, j, arg_reg, disp, is_ld=True)
                        if pair is not None:
                            return pair

                    if base_reg in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'ld {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)}): struct of entry arg')
                    return (UNKNOWN, f'ld {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)})')

            # ── lwz rX, N(rY) — 32-bit load (still present in ppc64) ─────────
            if insn.id == PPC_INS_LWZ:
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == PPC_OP_MEM:
                    base_reg = ops[1].mem.base
                    disp     = ops[1].mem.disp
                    if base_reg == PPC_REG_R1:
                        if self._is_entry_arg_save(insns, PPC_REG_R1, disp):
                            return (ARG_PROPAGATED, f'entry arg at r1+{disp:#x} (lwz)')
                        return (UNKNOWN, f'lwz {_rname(arg_reg)}, {disp:#x}(r1)')
                    if base_reg in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'lwz {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)}): entry struct')
                    return (UNKNOWN, f'lwz {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)})')

            # ── mr rD, rA ─────────────────────────────────────────────────────
            if insn.id == PPC_INS_MR:
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == PPC_OP_REG:
                    src_reg = ops[1].reg
                    if src_reg in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED, f'mr {_rname(arg_reg)}, {_rname(src_reg)} (entry arg)')
                    return self._trace_arg(insns, j, src_reg, depth)
                return (UNKNOWN, f'mr {_rname(arg_reg)}: unknown src')

            # ── or rD, rA, rA (mr alias) ──────────────────────────────────────
            if insn.id == PPC_INS_OR:
                ops = insn.operands
                if (len(ops) == 3 and ops[1].type == PPC_OP_REG
                        and ops[2].type == PPC_OP_REG
                        and ops[1].reg == ops[2].reg):
                    src_reg = ops[1].reg
                    if src_reg in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED, f'mr(or) {_rname(arg_reg)}, {_rname(src_reg)} (entry arg)')
                    return self._trace_arg(insns, j, src_reg, depth)
                return (UNKNOWN, f'or {_rname(arg_reg)}: non-mr @ {insn.address:#018x}')

            # ── lbz/lhz → UNKNOWN ─────────────────────────────────────────────
            if insn.id in (PPC_INS_LBZ, PPC_INS_LHZ):
                return (UNKNOWN, f'{insn.mnemonic} {_rname(arg_reg)} @ {insn.address:#018x}')

            # ── fallback ──────────────────────────────────────────────────────
            ops = insn.operands
            if (len(ops) >= 2 and ops[1].type == PPC_OP_REG
                    and ops[1].reg in _PPC64_ENTRY_ARG_SET):
                return (ARG_PROPAGATED, f'{insn.mnemonic}: src {_rname(ops[1].reg)} is entry arg')
            return (UNKNOWN, f'{insn.mnemonic} writes {_rname(arg_reg)} @ {insn.address:#018x}')

        if arg_reg in _PPC64_ENTRY_ARG_SET:
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
            if fmt_pos >= len(_PPC64_ARG_REGS):
                continue
            fmt_reg  = _PPC64_ARG_REGS[fmt_pos]
            snp_name = self._ctx.plt.get(snp_plt_va, 'snprintf')
            verdict, detail = self._trace_arg(insns, i, fmt_reg, depth + 1)
            if verdict == RODATA_CONST:
                return (SNPRINTF_RODATA, f'{snp_name}(r1+{disp:#x}) fmt={detail}')
            return (verdict, f'{snp_name}(r1+{disp:#x}) fmt={detail}')
        return None

    def _r3_is_slot(self, insns: list, bl_idx: int, base_reg: int, disp: int) -> bool:
        limit = max(bl_idx - _LOOKBACK, -1)
        for j in range(bl_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, PPC_REG_R3):
                continue
            if insn.id == PPC_INS_ADDI:
                ops = insn.operands
                if (len(ops) >= 3 and ops[1].type == PPC_OP_REG
                        and ops[1].reg == base_reg and ops[2].type == PPC_OP_IMM
                        and ops[2].imm == disp):
                    return True
            return False
        return False

    def _is_entry_arg_save(self, insns: list, base_reg: int, disp: int) -> bool:
        for insn in insns:
            if insn.id != PPC_INS_STW:
                continue
            ops = insn.operands
            if len(ops) < 2:
                continue
            if (ops[0].type == PPC_OP_REG and ops[0].reg in _PPC64_ENTRY_ARG_SET
                    and ops[1].type == PPC_OP_MEM
                    and ops[1].mem.base == base_reg and ops[1].mem.disp == disp):
                return True
        return False

    def _is_entry_arg_save_64(self, insns: list, base_reg: int, disp: int) -> bool:
        for insn in insns:
            if insn.id != PPC_INS_STD:
                continue
            ops = insn.operands
            if len(ops) < 2:
                continue
            if (ops[0].type == PPC_OP_REG and ops[0].reg in _PPC64_ENTRY_ARG_SET
                    and ops[1].type == PPC_OP_MEM
                    and ops[1].mem.base == base_reg and ops[1].mem.disp == disp):
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
                if arg_pos >= len(_PPC64_ARG_REGS):
                    continue
                arg_reg = _PPC64_ARG_REGS[arg_pos]
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
        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []
        results: List[SinkClassification] = []
        seen_funcs: set = set()
        for sink_va, (sink_name, arg_pos) in sink_plts.items():
            for entry in self._ctx.callers_of(sink_va):
                caller_va = entry[0] if isinstance(entry, tuple) else entry
                if caller_va in seen_funcs:
                    continue
                seen_funcs.add(caller_va)
                results.extend(self._classify_function(caller_va, sink_plts))
        return results

    def classify_sink(self, sink_name: str) -> List[SinkClassification]:
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
            return 'SinkArgClassifierPPC64: no results\n'
        lines = [f'SinkArgClassifierPPC64: {len(results)} results']
        for r in results:
            lines.append(
                f'  {r.verdict:16s} {r.sink_name}(arg{r.arg_pos})'
                f' func={r.func_va:#018x} call={r.call_va:#018x}'
                f' detail={r.detail}'
            )
        by_verdict: Dict[str, int] = {}
        for r in results:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        lines.append('Summary: ' + ' | '.join(f'{k}={v}' for k, v in sorted(by_verdict.items())))
        if self._dead_sinks:
            lines.append(f'Dead sinks (no callers): {", ".join(self._dead_sinks)}')
        return '\n'.join(lines) + '\n'
