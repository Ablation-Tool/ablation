"""
sink_arg_classifier_ppc64_elfv1.py: classify exec-class sink argument provenance
on PPC64 BE ELFv1 ELFs (POWER Linux, e.g. IBM LoadLeveler, iAccess, PE bundle).

Gap this fills vs SinkArgClassifier:
  SinkArgClassifier hardcodes x86-64 CALL scanning (E8 opcode) and register names.
  PPC64 BE ELFv1 dispatches via 7-instruction TOC-relative inline stubs; callers
  reach sinks with ``bl <stub_va>`` where stub_va is mapped by BinaryContext's
  _extract_plt_ppc64be().  That stub scan is LOADL-GAP-002.

PPC64 BE ELFv1 ABI calling convention (same registers as PPC32):
  Argument position 0 → r3  (Capstone PPC_REG_R3  = 90)
  Argument position 1 → r4  (Capstone PPC_REG_R4  = 91)
  Argument position 2 → r5  (Capstone PPC_REG_R5  = 92)
  …
  Argument position 7 → r10 (Capstone PPC_REG_R10 = 97)

PPC64 BE string-address load patterns (superset of PPC32):
  1. lis rX, HI; addi rX, rX, LO   — 32-bit signed address (same as PPC32).
  2. lis rX, HI; ori  rX, rX, LO   — 32-bit unsigned address; LO zero-extended.
     string_va = ((HI & 0xFFFF) << 16) | (LO & 0xFFFF).
  3. lis rX, HI; lwz  rX, LO(rX)   — indirect 32-bit pointer (same as PPC32).
  4. lis rX, HI; ld   rX, LO(rX)   — indirect 64-bit pointer.
  5. li  rX, imm                    — small immediate (NULL=0, flag).
  6. mr  rX, rY  (or rD, rA, rA)   — register copy; recurse on rA.
  7. addi rX, r1, N                 — address of stack slot.
  8. ld   rX, N(r1)                 — 64-bit stack slot load.
  9. lwz  rX, N(r1)                 — 32-bit stack slot load (struct with 32-bit fields).
  10. addis rX, r2, HI; addi rX, rX, LO   — TOC-relative address.
      toc_addr = r2 + sign_ext16(HI)<<16 + sign_ext16(LO); RODATA_CONST if in .rodata.
  11. addis rX, r2, HI; ld rX, LO(rX)     — TOC-relative pointer dereference.
      ptr_va = r2 + sign_ext16(HI)<<16 + sign_ext16(LO); RODATA_CONST if *ptr in .rodata.

Usage:
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier_ppc64_elfv1 import SinkArgClassifierPPC64ELFv1

    ctx = BinaryContext.load_or_build('/path/to/LoadL_master')
    clf = SinkArgClassifierPPC64ELFv1.from_context(ctx)
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
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_64, CS_MODE_BIG_ENDIAN
    from capstone.ppc_const import (
        PPC_OP_REG, PPC_OP_MEM, PPC_OP_IMM,
        PPC_REG_R0, PPC_REG_R1, PPC_REG_R2,
        PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
        PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10,
        PPC_INS_LIS, PPC_INS_ADDI, PPC_INS_ADDIS, PPC_INS_LI,
        PPC_INS_LWZ, PPC_INS_STW,
        PPC_INS_LD, PPC_INS_LDU, PPC_INS_LWA,
        PPC_INS_STD, PPC_INS_STDU,
        PPC_INS_BL,
        PPC_INS_OR, PPC_INS_ORI,
        PPC_INS_MR,
        PPC_INS_LBZ, PPC_INS_LHZ,
    )
    _CS_OK = True
except ImportError:
    # Stubs so the module can be imported without Capstone
    (PPC_OP_REG, PPC_OP_MEM, PPC_OP_IMM) = (1, 3, 2)
    (PPC_REG_R0, PPC_REG_R1, PPC_REG_R2) = (87, 88, 89)
    (PPC_REG_R3, PPC_REG_R4, PPC_REG_R5,  PPC_REG_R6,
     PPC_REG_R7, PPC_REG_R8, PPC_REG_R9,  PPC_REG_R10) = range(90, 98)
    (PPC_INS_LIS, PPC_INS_ADDI, PPC_INS_ADDIS, PPC_INS_LI) = (632, 4, 6, 631)
    (PPC_INS_LWZ, PPC_INS_STW) = (651, 1066)
    (PPC_INS_LD, PPC_INS_LDU, PPC_INS_LWA) = (599, 605, 643)
    (PPC_INS_STD, PPC_INS_STDU) = (1032, 1037)
    PPC_INS_BL = 108
    (PPC_INS_OR, PPC_INS_ORI) = (843, 845)
    PPC_INS_MR = 759
    (PPC_INS_LBZ, PPC_INS_LHZ) = (594, 626)

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

# ── PPC64 ELFv1 argument registers (r3 = arg0, r10 = arg7) ───────────────────
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

# ── Default exec-class sinks ──────────────────────────────────────────────────
_DEFAULT_SINKS_PPC64: Dict[str, int] = {
    'system':   0,
    'popen':    0,
    'execve':   0,
    'execvp':   0,
    'execl':    0,
    'execlp':   0,
    'execv':    0,
    'strcpy':   0,
    'strcat':   0,
    'sprintf':  0,
}

# snprintf-family: fmt arg position (0-indexed, r3=pos0)
_SNPRINTF_FMT_POS_PPC64: Dict[str, int] = {
    'snprintf':       2,   # r3=buf, r4=size, r5=fmt
    'vsnprintf':      2,
    'sprintf':        1,   # r3=buf, r4=fmt
    '__sprintf_chk':  3,
    '__snprintf_chk': 3,
}

_LOOKBACK        = 80
_SNPRINTF_WINDOW = 140
_MAX_FUNC_BYTES  = 65536

_PPC64_LOAD_INSNS = frozenset({PPC_INS_LD, PPC_INS_LDU, PPC_INS_LWA, PPC_INS_LWZ})
_PPC64_STORE_INSNS = frozenset({PPC_INS_STD, PPC_INS_STDU, PPC_INS_STW})


def _rname(reg_id: int) -> str:
    return _PPC64_REG_NAMES.get(reg_id, f'r{reg_id}')


def _sign16(v: int) -> int:
    """Sign-extend a 16-bit value."""
    return v if v < 0x8000 else v - 0x10000


class SinkArgClassifierPPC64ELFv1:
    """
    Classify exec-class sink call-site argument provenance on PPC64 BE ELFv1 ELFs.

    Fills LOADL-GAP-002 (LoadLeveler ppc64 BE) and similar ELFv1 analysis gaps.
    Shares the same four-verdict model as all other SinkArgClassifier variants.
    """

    def __init__(self, ctx) -> None:
        self._ctx                             = ctx
        self._data: bytes                     = Path(ctx.path).read_bytes()
        self._plt_rev: Dict[str, int]         = {v: k for k, v in ctx.plt.items()}
        self._sinks: Dict[str, int]           = dict(_DEFAULT_SINKS_PPC64)
        self._snprintf_plts: Dict[int, int]   = {}   # PLT stub VA → fmt arg position
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._dead_sinks: List[str]           = []
        self._bin                             = None
        self._cs: Optional[Cs]               = None
        self._r2: Optional[int]              = None  # TOC base pointer
        if _CS_OK:
            self._cs = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN)
            self._cs.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(ctx.path)
        self._init()

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierPPC64ELFv1':
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> 'SinkArgClassifierPPC64ELFv1':
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
                            '.rdata', '.got2', '.data.rel.ro', '.toc'):
                self._rodata_ranges.append(
                    (int(sec.virtual_address),
                     int(sec.virtual_address) + int(sec.size))
                )
        # BinaryContext._extract_plt_ppc64be() populates ctx.plt with stub VAs for
        # ELFv1.  If it returned empty (e.g. no .rela.plt / .opd found), fall back
        # to LIEF pltgot_relocations.  NOTE: LIEF returns GOT-slot VAs for ELFv1,
        # not stub VAs — callers won't match bl targets, so classify_all() will
        # return 0 results.  This is a known limitation; the primary path is
        # BinaryContext's stub scan.
        if not self._plt_rev:
            for rel in self._bin.pltgot_relocations:
                if rel.has_symbol and rel.symbol.name:
                    bare = rel.symbol.name.split('@')[0]
                    self._plt_rev[bare] = rel.address
        for name, fmt_pos in _SNPRINTF_FMT_POS_PPC64.items():
            va = self._plt_rev.get(name)
            if va:
                self._snprintf_plts[va] = fmt_pos
        # Read TOC (r2) from .opd[0] — second 8-byte word of the first function
        # descriptor.  Used to resolve TOC-relative address patterns.
        try:
            opd = self._bin.get_section('.opd')
            if opd and len(bytes(opd.content)) >= 16:
                self._r2 = struct.unpack_from('>Q', bytes(opd.content), 8)[0]
        except Exception:
            pass

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

    def _read_u64_be(self, va: int) -> Optional[int]:
        raw = self._read_va(va, 8)
        if len(raw) < 8:
            return None
        return struct.unpack_from('>Q', raw)[0]

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
                for key in self._plt_rev:
                    if isinstance(key, str) and key.startswith(name + '@@'):
                        va = self._plt_rev[key]
                        break
            if not va:
                self._dead_sinks.append(name)
                continue
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
        """Scan backward for 'lis reg_id, HI'; return HI or None."""
        for k in range(from_j - 1, max(from_j - 6, -1), -1):
            insn = insns[k]
            if insn.id == PPC_INS_LIS and self._writes_reg(insn, reg_id):
                return insn.operands[1].imm & 0xFFFF
            if self._writes_reg(insn, reg_id):
                return None
        return None

    def _find_preceding_addis_r2(
        self,
        insns: list,
        from_j: int,
        reg_id: int,
    ) -> Optional[int]:
        """Scan backward for 'addis reg_id, r2, HI'; return HI or None."""
        for k in range(from_j - 1, max(from_j - 6, -1), -1):
            insn = insns[k]
            if insn.id == PPC_INS_ADDIS and self._writes_reg(insn, reg_id):
                ops = insn.operands
                # addis rD, r2, HI: ops = [rD, r2, HI]
                if (len(ops) >= 3
                        and ops[1].type == PPC_OP_REG
                        and ops[1].reg == PPC_REG_R2
                        and ops[2].type == PPC_OP_IMM):
                    return ops[2].imm & 0xFFFF
            if self._writes_reg(insn, reg_id):
                return None
        return None

    def _resolve_lis_pair(
        self,
        insns: list,
        second_j: int,
        arg_reg: int,
        lo: int,
        unsigned_lo: bool = False,
    ) -> Optional[Tuple[str, str]]:
        """
        Resolve lis+addi, lis+ori, or lis+lwz/ld pair whose second instruction is at
        second_j.  lo is the offset/immediate from the second instruction.
        unsigned_lo=True for ori (zero-extends LO); False for addi/ld (sign-extends).
        Returns (verdict, detail) or None if no preceding lis found.
        """
        hi = self._find_preceding_lis(insns, second_j, arg_reg)
        if hi is None:
            return None
        if unsigned_lo:
            string_va = ((hi << 16) | (lo & 0xFFFF)) & 0xFFFFFFFF
        else:
            string_va = ((hi << 16) + _sign16(lo & 0xFFFF)) & 0xFFFFFFFF
        if self._is_rodata(string_va):
            return (RODATA_CONST,
                    f'lis+addi/ori/ld {_rname(arg_reg)} → {string_va:#010x} in .rodata')
        # Indirect: pointer at string_va pointing into rodata (64-bit or 32-bit)
        val64 = self._read_u64_be(string_va)
        if val64 is not None and self._is_rodata(val64):
            return (RODATA_CONST,
                    f'lis+ld → ptr {string_va:#010x} → {val64:#018x} in .rodata')
        val32 = self._read_u32_be(string_va)
        if val32 is not None and self._is_rodata(val32):
            return (RODATA_CONST,
                    f'lis+lwz → ptr {string_va:#010x} → {val32:#010x} in .rodata')
        return (UNKNOWN, f'lis+pair → {string_va:#010x} not .rodata')

    def _resolve_toc_relative(
        self,
        insns: list,
        second_j: int,
        arg_reg: int,
        lo: int,
        indirect: bool = False,
    ) -> Optional[Tuple[str, str]]:
        """
        Resolve addis rX, r2, HI followed by addi rX, rX, LO (direct address) or
        ld rX, LO(rX) (indirect pointer).  Requires self._r2 to be known.
        Returns (verdict, detail) or None if no preceding addis r2 or r2 unknown.
        """
        if self._r2 is None:
            return None
        hi = self._find_preceding_addis_r2(insns, second_j, arg_reg)
        if hi is None:
            return None
        toc_addr = (self._r2 + (_sign16(hi) << 16) + _sign16(lo & 0xFFFF)) & 0xFFFFFFFFFFFFFFFF
        if indirect:
            ptr = self._read_u64_be(toc_addr)
            if ptr is None:
                ptr_32 = self._read_u32_be(toc_addr)
                if ptr_32 is not None:
                    ptr = ptr_32
            if ptr is not None and self._is_rodata(ptr):
                return (RODATA_CONST,
                        f'addis+ld(r2) → ptr {toc_addr:#018x} → {ptr:#018x} in .rodata')
            return (UNKNOWN, f'addis+ld(r2) → {toc_addr:#018x}: ptr not in .rodata')
        if self._is_rodata(toc_addr):
            return (RODATA_CONST,
                    f'addis+addi(r2) → {toc_addr:#018x} in .rodata')
        return (UNKNOWN, f'addis+addi(r2) → {toc_addr:#018x}: not .rodata')

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

            # ── li rX, imm ────────────────────────────────────────────────────
            if insn.id == PPC_INS_LI:
                return (RODATA_CONST,
                        f'li {_rname(arg_reg)}, #{insn.operands[1].imm:#x}')

            # ── lis rX, HI — scan forward for paired addi/ori/lwz/ld ──────────
            if insn.id == PPC_INS_LIS:
                hi = insn.operands[1].imm & 0xFFFF
                for k in range(j + 1, min(j + 6, len(insns))):
                    nxt = insns[k]
                    # lis+addi
                    if nxt.id == PPC_INS_ADDI and self._writes_reg(nxt, arg_reg):
                        ops = nxt.operands
                        if len(ops) >= 3 and ops[1].reg == arg_reg:
                            lo   = _sign16(ops[2].imm & 0xFFFF)
                            addr = ((hi << 16) + lo) & 0xFFFFFFFF
                            if self._is_rodata(addr):
                                return (RODATA_CONST,
                                        f'lis+addi {_rname(arg_reg)} → {addr:#010x} in .rodata')
                            val64 = self._read_u64_be(addr)
                            if val64 is not None and self._is_rodata(val64):
                                return (RODATA_CONST,
                                        f'lis+addi → ptr {addr:#010x} → {val64:#018x} in .rodata')
                            return (UNKNOWN, f'lis+addi → {addr:#010x} not .rodata')
                    # lis+ori (unsigned LO, 32-bit address)
                    if nxt.id == PPC_INS_ORI and self._writes_reg(nxt, arg_reg):
                        ops = nxt.operands
                        if (len(ops) >= 3
                                and ops[1].type == PPC_OP_REG and ops[1].reg == arg_reg
                                and ops[2].type == PPC_OP_IMM):
                            lo   = ops[2].imm & 0xFFFF
                            addr = ((hi << 16) | lo) & 0xFFFFFFFF
                            if self._is_rodata(addr):
                                return (RODATA_CONST,
                                        f'lis+ori {_rname(arg_reg)} → {addr:#010x} in .rodata')
                            return (UNKNOWN, f'lis+ori → {addr:#010x} not .rodata')
                    # lis+lwz (indirect 32-bit pointer)
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
                            return (UNKNOWN, f'lis+lwz → {ptr_v:#010x}: not .rodata')
                    # lis+ld (indirect 64-bit pointer)
                    if nxt.id == PPC_INS_LD and self._writes_reg(nxt, arg_reg):
                        ops = nxt.operands
                        if (len(ops) >= 2 and ops[1].type == PPC_OP_MEM
                                and ops[1].mem.base == arg_reg):
                            lo    = _sign16(ops[1].mem.disp & 0xFFFF)
                            ptr_v = ((hi << 16) + lo) & 0xFFFFFFFF
                            val   = self._read_u64_be(ptr_v)
                            if val is not None and self._is_rodata(val):
                                return (RODATA_CONST,
                                        f'lis+ld → {ptr_v:#010x} → {val:#018x} in .rodata')
                            return (UNKNOWN, f'lis+ld → {ptr_v:#010x}: not .rodata')
                    if (self._writes_reg(nxt, arg_reg)
                            and nxt.id not in (PPC_INS_LIS, PPC_INS_ADDI,
                                               PPC_INS_ORI, PPC_INS_LWZ, PPC_INS_LD)):
                        break
                return (UNKNOWN, f'lis {_rname(arg_reg)}: no paired second insn within 5')

            # ── mr rD, rA (PPC_INS_MR: 2 ops) ───────────────────────────────
            if insn.id == PPC_INS_MR:
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == PPC_OP_REG:
                    src_reg = ops[1].reg
                    if src_reg in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'mr {_rname(arg_reg)}, {_rname(src_reg)} (entry arg)')
                    return self._trace_arg(insns, j, src_reg, depth)
                return (UNKNOWN, f'mr {_rname(arg_reg)}: unknown src')

            # ── or rD, rA, rA — mr alias in older Capstone ───────────────────
            if insn.id == PPC_INS_OR:
                ops = insn.operands
                if len(ops) == 3 and ops[1].type == PPC_OP_REG and ops[2].type == PPC_OP_REG:
                    if ops[1].reg == ops[2].reg:
                        src_reg = ops[1].reg
                        if src_reg in _PPC64_ENTRY_ARG_SET:
                            return (ARG_PROPAGATED,
                                    f'mr {_rname(arg_reg)}, {_rname(src_reg)} (entry arg)')
                        return self._trace_arg(insns, j, src_reg, depth)
                return (UNKNOWN, f'or {_rname(arg_reg)}: non-mr pattern')

            # ── addi rX, rBase, N ─────────────────────────────────────────────
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
                        # Second half of lis+addi
                        pair = self._resolve_lis_pair(insns, j, arg_reg, lo_val)
                        if pair is not None:
                            return pair
                        # Second half of addis r2 + addi (TOC-relative address)
                        toc = self._resolve_toc_relative(insns, j, arg_reg, lo_val, indirect=False)
                        if toc is not None:
                            return toc

                    if base_r in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'addi {_rname(arg_reg)}, {_rname(base_r)}: entry+imm')

                return (UNKNOWN,
                        f'addi {_rname(arg_reg)}: unknown base @ {insn.address:#010x}')

            # ── ld rX, N(rY) / lwz rX, N(rY) — memory loads ──────────────────
            if insn.id in _PPC64_LOAD_INSNS:
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
                        return (UNKNOWN, f'{insn.mnemonic} {_rname(arg_reg)}, {disp:#x}(r1)')

                    if base_reg == arg_reg:
                        # Second half of lis+ld (indirect)
                        pair = self._resolve_lis_pair(insns, j, arg_reg, disp)
                        if pair is not None:
                            return pair
                        # Second half of addis r2 + ld (TOC-relative pointer)
                        toc = self._resolve_toc_relative(insns, j, arg_reg, disp, indirect=True)
                        if toc is not None:
                            return toc

                    if base_reg == PPC_REG_R2 and self._r2 is not None:
                        # ld rX, N(r2) — direct TOC slot dereference
                        toc_addr = (self._r2 + _sign16(disp & 0xFFFF)) & 0xFFFFFFFFFFFFFFFF
                        ptr = self._read_u64_be(toc_addr)
                        if ptr is not None and self._is_rodata(ptr):
                            return (RODATA_CONST,
                                    f'ld(r2) → ptr {toc_addr:#018x} → {ptr:#018x} in .rodata')

                    if base_reg in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'{insn.mnemonic} {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)})'
                                f' struct field of entry arg')
                    return (UNKNOWN,
                            f'{insn.mnemonic} {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)})')

            # ── lbz/lhz — byte/halfword loads → UNKNOWN ──────────────────────
            if insn.id in (PPC_INS_LBZ, PPC_INS_LHZ):
                return (UNKNOWN, f'{insn.mnemonic} {_rname(arg_reg)} @ {insn.address:#010x}')

            # ── generic writer: check if source is an entry arg ───────────────
            ops = insn.operands
            if (len(ops) >= 2 and ops[1].type == PPC_OP_REG
                    and ops[1].reg in _PPC64_ENTRY_ARG_SET):
                return (ARG_PROPAGATED,
                        f'{insn.mnemonic}: src {_rname(ops[1].reg)} is entry arg')
            return (UNKNOWN,
                    f'{insn.mnemonic} writes {_rname(arg_reg)} @ {insn.address:#010x}')

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
            if fmt_pos >= len(_PPC64_ARG_REGS):
                continue
            fmt_reg  = _PPC64_ARG_REGS[fmt_pos]
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
        """True if r3 (snprintf dest) is set to address of stack slot (base_reg, disp)."""
        limit = max(bl_idx - _LOOKBACK, -1)
        for j in range(bl_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, PPC_REG_R3):
                continue
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
        True if there is a std/stdu/stw rX, disp(base_reg) in the function prologue
        where rX is in r3..r10 (entry argument saved to stack at this slot).
        """
        for insn in insns:
            if insn.id not in _PPC64_STORE_INSNS:
                continue
            ops = insn.operands
            if len(ops) < 2:
                continue
            if ops[0].type == PPC_OP_REG and ops[0].reg in _PPC64_ENTRY_ARG_SET:
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
        """Run classification across all func_starts for registered sink call sites.

        Iterates over func_starts rather than callers_of() for robustness: the
        ppc64 BE call graph may not be fully populated in all BinaryContext builds.
        """
        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []
        results: List[SinkClassification] = []
        for func_va in self._ctx.func_starts:
            results.extend(self._classify_function(func_va, sink_plts))
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
            return 'SinkArgClassifierPPC64ELFv1: no results\n'
        lines = [f'SinkArgClassifierPPC64ELFv1: {len(results)} results']
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
            lines.append(f'Dead sinks (no stubs): {", ".join(self._dead_sinks)}')
        return '\n'.join(lines) + '\n'
