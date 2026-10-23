"""
sink_arg_classifier_ppc64_elfv2.py: classify exec-class sink argument provenance
on PPC64 LE ELFv2 ELFs (RHEL/RHCOS ppc64le, HMC management binaries, etc.).

Why this exists
---------------
SinkArgClassifierPPC64ELFv1 handles big-endian ELFv1 (AIX/LoadLeveler TOC stubs).
ppc64le ELFv2 (RHEL-built HMC binaries, IBM PowerSC, RSCT) uses little-endian
encoding and ELFv2 ABIs: standard GOT-indirect PLT stubs and r2 = .got + 0x8000.
The generic SinkArgClassifier falls back to x86_64 Capstone, which produces garbage
on ppc64le code and returns 0 results.  This module closes that gap.

Gap this fills
--------------
All ppc64le (EI_DATA=1) ELFs with exec-class PLT entries returned SAC=0 because
sac_for_context() dispatched to the x86_64 SinkArgClassifier.  HMC management
binaries (hmc.mgmt, hmc.common, hmc.svrmgmt) contain 35+ such binaries.

ELFv2 vs ELFv1 differences handled here
-----------------------------------------
1. Capstone mode: CS_MODE_LITTLE_ENDIAN (EI_DATA=1) vs CS_MODE_BIG_ENDIAN.
2. TOC (r2) discovery: r2 = .got.virtual_address + 0x8000 (GNU ld ELFv2 convention)
   instead of reading from .opd[8].
3. Pointer reads: little-endian (<Q, <I) instead of big-endian (>Q, >I).
4. Rodata ranges: same LIEF section scan, LE binary.

Calling convention (identical to ELFv1 — same Power ABI)
----------------------------------------------------------
  Argument position 0 → r3  (Capstone PPC_REG_R3  = 90)
  Argument position 1 → r4  (PPC_REG_R4  = 91)
  ...
  Argument position 7 → r10 (PPC_REG_R10 = 97)

String-address load patterns (same instructions as ELFv1, LE-encoded)
----------------------------------------------------------------------
  1. lis rX, HI; addi rX, rX, LO         — 32-bit signed address
  2. lis rX, HI; ori  rX, rX, LO         — 32-bit unsigned address
  3. lis rX, HI; lwz  rX, LO(rX)         — indirect 32-bit pointer
  4. lis rX, HI; ld   rX, LO(rX)         — indirect 64-bit pointer
  5. li  rX, imm                          — small immediate / NULL
  6. mr  rX, rY                           — register copy; recurse on rY
  7. addi rX, r1, N                       — address of stack slot
  8. ld   rX, N(r1)                       — 64-bit stack slot load
  9. lwz  rX, N(r1)                       — 32-bit stack slot load
 10. addis rX, r2, HI; addi rX, rX, LO   — TOC-relative address
 11. addis rX, r2, HI; ld rX, LO(rX)     — TOC-relative pointer dereference
 12. ld   rX, N(r2)                       — direct TOC slot dereference
 13. addis rX, r2, HI; [addi rX, rX, LO]; addi r3, rX, OFF — callee-saved base
     register loaded at function entry beyond the 80-instruction backward window.
     (PPC64-SAC-CALLEE-001: full-function forward scan via _eval_callee_saved_reg)

Usage
-----
    from ablation.analyzers.binary_context import BinaryContext
    from ablation.analyzers.sink_arg_classifier_ppc64_elfv2 import SinkArgClassifierPPC64ELFv2

    ctx = BinaryContext.load_or_build('/path/to/hmc_mgmt_binary')
    clf = SinkArgClassifierPPC64ELFv2.from_context(ctx)
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
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_64, CS_MODE_LITTLE_ENDIAN
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
        PPC_INS_B,
        PPC_INS_OR, PPC_INS_ORI,
        PPC_INS_MR,
        PPC_INS_LBZ, PPC_INS_LHZ,
    )
    _CS_OK = True
except ImportError:
    (PPC_OP_REG, PPC_OP_MEM, PPC_OP_IMM) = (1, 3, 2)
    (PPC_REG_R0, PPC_REG_R1, PPC_REG_R2) = (87, 88, 89)
    (PPC_REG_R3, PPC_REG_R4, PPC_REG_R5,  PPC_REG_R6,
     PPC_REG_R7, PPC_REG_R8, PPC_REG_R9,  PPC_REG_R10) = range(90, 98)
    (PPC_INS_LIS, PPC_INS_ADDI, PPC_INS_ADDIS, PPC_INS_LI) = (632, 4, 6, 631)
    (PPC_INS_LWZ, PPC_INS_STW) = (651, 1066)
    (PPC_INS_LD, PPC_INS_LDU, PPC_INS_LWA) = (599, 605, 643)
    (PPC_INS_STD, PPC_INS_STDU) = (1032, 1037)
    PPC_INS_BL = 108
    PPC_INS_B  = 88
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

_PPC64_ARG_REGS: List[int] = [
    PPC_REG_R3, PPC_REG_R4, PPC_REG_R5, PPC_REG_R6,
    PPC_REG_R7, PPC_REG_R8, PPC_REG_R9, PPC_REG_R10,
]
_PPC64_ENTRY_ARG_SET = frozenset(_PPC64_ARG_REGS)

_PPC64_REG_NAMES: Dict[int, str] = {
    PPC_REG_R0 + i: f'r{i}' for i in range(32)
}
_PPC64_REG_NAMES.update({
    PPC_REG_R0:  'r0',  PPC_REG_R1:  'r1',  PPC_REG_R2:  'r2',
    PPC_REG_R3:  'r3',  PPC_REG_R4:  'r4',  PPC_REG_R5:  'r5',
    PPC_REG_R6:  'r6',  PPC_REG_R7:  'r7',  PPC_REG_R8:  'r8',
    PPC_REG_R9:  'r9',  PPC_REG_R10: 'r10',
})

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

_PPC64_LOAD_INSNS  = frozenset({PPC_INS_LD, PPC_INS_LDU, PPC_INS_LWA, PPC_INS_LWZ})
_PPC64_STORE_INSNS = frozenset({PPC_INS_STD, PPC_INS_STDU, PPC_INS_STW})


def _rname(reg_id: int) -> str:
    return _PPC64_REG_NAMES.get(reg_id, f'r{reg_id}')


def _sign16(v: int) -> int:
    return v if v < 0x8000 else v - 0x10000


class SinkArgClassifierPPC64ELFv2:
    """
    Classify exec-class sink call-site argument provenance on PPC64 LE ELFv2 ELFs.

    Fills the ppc64le analysis gap: sac_for_context() previously dispatched to the
    x86_64 SinkArgClassifier for EI_DATA=1 ppc64 binaries, returning 0 results.
    """

    def __init__(self, ctx) -> None:
        self._ctx                             = ctx
        self._data: bytes                     = Path(ctx.path).read_bytes()
        self._plt_rev: Dict[str, int]         = {v: k for k, v in ctx.plt.items()}
        self._sinks: Dict[str, int]           = dict(_DEFAULT_SINKS_PPC64)
        self._snprintf_plts: Dict[int, int]   = {}
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._dead_sinks: List[str]           = []
        self._bin                             = None
        self._cs: Optional[Cs]               = None
        self._r2: Optional[int]              = None
        if _CS_OK:
            self._cs = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN)
            self._cs.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(ctx.path)
        self._init()

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifierPPC64ELFv2':
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> 'SinkArgClassifierPPC64ELFv2':
        from ablation.analyzers.binary_context import BinaryContext
        ctx = BinaryContext.load_or_build(path)
        return cls(ctx)

    def add_sink(self, name: str, arg_pos: int) -> None:
        self._sinks[name] = arg_pos

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
        # PLT: prefer BinaryContext-populated plt dict; fall back to LIEF relocations.
        if not self._plt_rev:
            for rel in self._bin.pltgot_relocations:
                if rel.has_symbol and rel.symbol.name:
                    bare = rel.symbol.name.split('@')[0]
                    self._plt_rev[bare] = rel.address
        for name, fmt_pos in _SNPRINTF_FMT_POS_PPC64.items():
            va = self._plt_rev.get(name)
            if va:
                self._snprintf_plts[va] = fmt_pos
        # ELFv2 TOC: r2 = .got.virtual_address + 0x8000 (GNU ld convention).
        # This differs from ELFv1 which reads TOC from .opd[8].
        try:
            got = self._bin.get_section('.got')
            if got is not None:
                self._r2 = int(got.virtual_address) + 0x8000
        except Exception:
            pass
        # Remap GOT entry VAs in _plt_rev to the actual PLT call stub VAs.
        # GNU gold places ppc64le ELFv2 PLT call stubs in .fini (sometimes
        # other non-.text executable sections) rather than adjacent to .text.
        # Code branches with BL <stub_va>; the stub does:
        #   std r2, 0x18(r1)           [save TOC]
        #   addis r12, r2, ha          [GOT_VA = r2 + ha<<16 + lo]
        #   ld    r12, lo(r12)
        #   mtctr r12
        #   bctr
        # _find_call_sites() matches BL <va> against sink_va from _plt_rev.
        # Without remapping, sink_va is the GOT slot address — never a BL target.
        if self._r2 and self._plt_rev:
            self._remap_plt_rev_to_stubs()

    def _remap_plt_rev_to_stubs(self) -> None:
        """Scan non-.text executable sections for ppc64le ELFv2 PLT call stubs
        and remap _plt_rev entries from GOT VAs to the callable stub VAs."""
        import struct as _s
        STD_R2 = _s.pack('<I', 0xF8410018)   # std r2, 0x18(r1)
        MTCTR  = _s.pack('<I', 0x7D8903A6)   # mtctr r12
        BCTR   = _s.pack('<I', 0x4E800420)   # bctr
        r2 = self._r2
        # Build GOT_VA → stub_VA from all non-.text executable sections.
        got_to_stub: Dict[int, int] = {}
        exec_flag = 4  # SHF_EXECINSTR
        text_name = '.text'
        for sec in self._bin.sections:
            sec_va   = int(sec.virtual_address)
            sec_size = int(sec.size)
            if sec_size < 20 or sec.name == text_name:
                continue
            try:
                flags = int(sec.flags)
            except Exception:
                flags = 0
            if not (flags & exec_flag):
                continue
            try:
                sec_off = int(self._bin.virtual_address_to_offset(sec_va))
            except Exception:
                sec_off = sec_va
            if sec_off < 0 or sec_off >= len(self._data):
                continue
            sec_data = self._data[sec_off:sec_off + sec_size]
            for i in range(0, sec_size - 20, 4):
                if sec_data[i:i+4] != STD_R2:
                    continue
                w1 = _s.unpack_from('<I', sec_data, i + 4)[0]
                w2 = _s.unpack_from('<I', sec_data, i + 8)[0]
                if (w1 & 0xFFFF0000) != 0x3D820000:  # addis r12, r2, ha
                    continue
                if (w2 & 0xFFFF0000) != 0xE98C0000:  # ld r12, lo(r12)
                    continue
                if sec_data[i+12:i+16] != MTCTR:
                    continue
                if sec_data[i+16:i+20] != BCTR:
                    continue
                ha = w1 & 0xFFFF
                lo = w2 & 0xFFFF
                if ha & 0x8000: ha -= 0x10000
                if lo & 0x8000: lo -= 0x10000
                got_va   = r2 + ha * 0x10000 + lo
                stub_va  = sec_va + i
                got_to_stub[got_va] = stub_va
        # Power10 pass: add Form-A (compact ld r12,D(r2)) and Form-B (PLD pcrel)
        # stubs that the classic addis+ld scan misses (ELFv2-PLD-GAP-001).
        try:
            from ablation.analyzers.ppc64_power10_plt_stubs import scan_power10_stubs
            got_to_stub.update({v: k for k, v in
                                 scan_power10_stubs(self._data, self._bin, self._r2).items()})
        except Exception:
            pass

        if not got_to_stub:
            return
        for name in list(self._plt_rev):
            old_va = self._plt_rev[name]
            if old_va in got_to_stub:
                self._plt_rev[name] = got_to_stub[old_va]

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

    def _read_u64_le(self, va: int) -> Optional[int]:
        raw = self._read_va(va, 8)
        if len(raw) < 8:
            return None
        return struct.unpack_from('<Q', raw)[0]

    def _read_u32_le(self, va: int) -> Optional[int]:
        raw = self._read_va(va, 4)
        if len(raw) < 4:
            return None
        return struct.unpack_from('<I', raw)[0]

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
                self._dead_sinks.append(name)
                continue
            result[va] = (name, arg_pos)
        return result

    def _get_insns(self, func_va: int) -> list:
        if self._cs is None:
            return []
        nxt  = self._next_func_va(func_va)
        size = min(nxt - func_va if nxt else _MAX_FUNC_BYTES, _MAX_FUNC_BYTES)
        raw  = self._read_va(func_va, size)
        if not raw:
            return []
        insns = list(self._cs.disasm(raw, func_va))
        # ppc64le ELFv2 (GNU gold): the Global Entry Point (GEP) is a short stub
        # that sets up r2 then branches to the Local Entry Point (LEP) via an
        # unconditional B.  The GEP and LEP can be thousands of bytes apart with
        # null-byte alignment padding between them; capstone stops at the padding,
        # so the actual function body is never seen.  When we get ≤ 8 instructions
        # ending in B (not BL), follow that branch to disassemble the LEP.
        if insns and len(insns) <= 8:
            last = insns[-1]
            if last.id == PPC_INS_B and last.operands:
                lep_va = last.operands[0].imm
                if lep_va != func_va and self._read_va(lep_va, 4):
                    lep_size = _MAX_FUNC_BYTES
                    lep_raw  = self._read_va(lep_va, lep_size)
                    if lep_raw:
                        insns = list(self._cs.disasm(lep_raw, lep_va))
        return insns

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

    def _find_preceding_lis(self, insns: list, from_j: int, reg_id: int) -> Optional[int]:
        for k in range(from_j - 1, max(from_j - 6, -1), -1):
            insn = insns[k]
            if insn.id == PPC_INS_LIS and self._writes_reg(insn, reg_id):
                return insn.operands[1].imm & 0xFFFF
            if self._writes_reg(insn, reg_id):
                return None
        return None

    def _find_preceding_addis_r2(self, insns: list, from_j: int, reg_id: int) -> Optional[int]:
        for k in range(from_j - 1, max(from_j - 6, -1), -1):
            insn = insns[k]
            if insn.id == PPC_INS_ADDIS and self._writes_reg(insn, reg_id):
                ops = insn.operands
                if (len(ops) >= 3
                        and ops[1].type == PPC_OP_REG
                        and ops[1].reg == PPC_REG_R2
                        and ops[2].type == PPC_OP_IMM):
                    return ops[2].imm & 0xFFFF
            if self._writes_reg(insn, reg_id):
                return None
        return None

    def _eval_callee_saved_reg(self, insns: list, reg_id: int, use_idx: int) -> Optional[int]:
        """Forward-pass constant propagation for a callee-saved register.

        PPC64 ELFv2 callee-saved registers (r14-r31) are often loaded once at
        function entry with a TOC-relative address and then used as base registers
        throughout the function — far beyond the 80-instruction backward window.
        This scan tracks the deterministic value of reg_id from function start up
        to use_idx by following:
          addis rX, r2, HI          -> rX = r2 + sign16(HI)<<16
          addi  rX, rX, LO          -> rX += sign16(LO)  (only when base == rX)
          ld    rX, N(r2)           -> rX = mem[r2 + sign16(N)]  (direct GOT load)
        Any other write invalidates the known value (returns None).
        """
        # (PPC64-SAC-CALLEE-001)
        if self._r2 is None:
            return None
        val: Optional[int] = None
        for idx in range(min(use_idx, len(insns))):
            insn = insns[idx]
            # Store instructions have the source register as ops[0] — skip them so
            # 'std r14, N(r1)' (callee-save spill) does not falsely invalidate val.
            if insn.id in _PPC64_STORE_INSNS:
                continue
            if not self._writes_reg(insn, reg_id):
                continue
            if insn.id == PPC_INS_ADDIS:
                ops = insn.operands
                if (len(ops) >= 3
                        and ops[1].type == PPC_OP_REG
                        and ops[1].reg == PPC_REG_R2
                        and ops[2].type == PPC_OP_IMM):
                    val = (self._r2 + (_sign16(ops[2].imm & 0xFFFF) << 16)) & 0xFFFFFFFFFFFFFFFF
                else:
                    val = None
            elif insn.id == PPC_INS_ADDI:
                ops = insn.operands
                if (val is not None
                        and len(ops) >= 3
                        and ops[1].type == PPC_OP_REG
                        and ops[1].reg == reg_id
                        and ops[2].type == PPC_OP_IMM):
                    val = (val + _sign16(ops[2].imm & 0xFFFF)) & 0xFFFFFFFFFFFFFFFF
                else:
                    val = None
            elif insn.id in _PPC64_LOAD_INSNS:
                ops = insn.operands
                if (len(ops) >= 2
                        and ops[1].type == PPC_OP_MEM
                        and ops[1].mem.base == PPC_REG_R2):
                    toc_slot = (self._r2 + _sign16(ops[1].mem.disp)) & 0xFFFFFFFFFFFFFFFF
                    ptr = self._read_u64_le(toc_slot)
                    val = ptr  # None if unreadable
                else:
                    val = None
            else:
                val = None
        return val

    def _is_callee_saved_from_entry_arg(self, insns: list, reg_id: int, use_idx: int) -> bool:
        """Return True if the most recent write to reg_id before use_idx was
        'mr reg_id, rY' where rY is an entry-arg register (r3-r10).

        Handles 'ld r3, N(r26)' where r26 = mr r26, r3 (entry arg struct ptr).
        The backward scan is the same direction as _trace_arg to get the effective
        value at the call site (not the function-entry value).
        (PPC64-SAC-CALLEE-001)
        """
        limit = max(use_idx - _LOOKBACK * 2, -1)
        for k in range(use_idx - 1, limit, -1):
            insn = insns[k]
            if insn.id in _PPC64_STORE_INSNS:
                continue
            if not self._writes_reg(insn, reg_id):
                continue
            if insn.id in (PPC_INS_MR, PPC_INS_OR):
                ops = insn.operands
                if (len(ops) >= 2
                        and ops[1].type == PPC_OP_REG
                        and ops[1].reg in _PPC64_ENTRY_ARG_SET):
                    return True
            return False
        return False

    def _resolve_lis_pair(
        self,
        insns: list,
        second_j: int,
        arg_reg: int,
        lo: int,
        unsigned_lo: bool = False,
    ) -> Optional[Tuple[str, str]]:
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
        val64 = self._read_u64_le(string_va)
        if val64 is not None and self._is_rodata(val64):
            return (RODATA_CONST,
                    f'lis+ld → ptr {string_va:#010x} → {val64:#018x} in .rodata')
        val32 = self._read_u32_le(string_va)
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
        if self._r2 is None:
            return None
        hi = self._find_preceding_addis_r2(insns, second_j, arg_reg)
        if hi is None:
            return None
        toc_addr = (self._r2 + (_sign16(hi) << 16) + _sign16(lo & 0xFFFF)) & 0xFFFFFFFFFFFFFFFF
        if indirect:
            ptr = self._read_u64_le(toc_addr)
            if ptr is None:
                ptr_32 = self._read_u32_le(toc_addr)
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
        if depth > 1:
            return (UNKNOWN, 'max recursion depth')

        limit = max(from_idx - _LOOKBACK, -1)

        for j in range(from_idx - 1, limit, -1):
            insn = insns[j]
            if not self._writes_reg(insn, arg_reg):
                continue

            if insn.id == PPC_INS_LI:
                return (RODATA_CONST,
                        f'li {_rname(arg_reg)}, #{insn.operands[1].imm:#x}')

            if insn.id == PPC_INS_LIS:
                hi = insn.operands[1].imm & 0xFFFF
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
                            val64 = self._read_u64_le(addr)
                            if val64 is not None and self._is_rodata(val64):
                                return (RODATA_CONST,
                                        f'lis+addi → ptr {addr:#010x} → {val64:#018x} in .rodata')
                            return (UNKNOWN, f'lis+addi → {addr:#010x} not .rodata')
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
                    if nxt.id == PPC_INS_LWZ and self._writes_reg(nxt, arg_reg):
                        ops = nxt.operands
                        if (len(ops) >= 2 and ops[1].type == PPC_OP_MEM
                                and ops[1].mem.base == arg_reg):
                            lo    = _sign16(ops[1].mem.disp & 0xFFFF)
                            ptr_v = ((hi << 16) + lo) & 0xFFFFFFFF
                            val   = self._read_u32_le(ptr_v)
                            if val is not None and self._is_rodata(val):
                                return (RODATA_CONST,
                                        f'lis+lwz → {ptr_v:#010x} → {val:#010x} in .rodata')
                            return (UNKNOWN, f'lis+lwz → {ptr_v:#010x}: not .rodata')
                    if nxt.id == PPC_INS_LD and self._writes_reg(nxt, arg_reg):
                        ops = nxt.operands
                        if (len(ops) >= 2 and ops[1].type == PPC_OP_MEM
                                and ops[1].mem.base == arg_reg):
                            lo    = _sign16(ops[1].mem.disp & 0xFFFF)
                            ptr_v = ((hi << 16) + lo) & 0xFFFFFFFF
                            val   = self._read_u64_le(ptr_v)
                            if val is not None and self._is_rodata(val):
                                return (RODATA_CONST,
                                        f'lis+ld → {ptr_v:#010x} → {val:#018x} in .rodata')
                            return (UNKNOWN, f'lis+ld → {ptr_v:#010x}: not .rodata')
                    if (self._writes_reg(nxt, arg_reg)
                            and nxt.id not in (PPC_INS_LIS, PPC_INS_ADDI,
                                               PPC_INS_ORI, PPC_INS_LWZ, PPC_INS_LD)):
                        break
                return (UNKNOWN, f'lis {_rname(arg_reg)}: no paired second insn within 5')

            if insn.id == PPC_INS_MR:
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == PPC_OP_REG:
                    src_reg = ops[1].reg
                    if src_reg in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'mr {_rname(arg_reg)}, {_rname(src_reg)} (entry arg)')
                    return self._trace_arg(insns, j, src_reg, depth)
                return (UNKNOWN, f'mr {_rname(arg_reg)}: unknown src')

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
                        pair = self._resolve_lis_pair(insns, j, arg_reg, lo_val)
                        if pair is not None:
                            return pair
                        toc = self._resolve_toc_relative(insns, j, arg_reg, lo_val, indirect=False)
                        if toc is not None:
                            return toc

                    if base_r in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'addi {_rname(arg_reg)}, {_rname(base_r)}: entry+imm')

                    # Callee-saved base register (r14-r31) holding a TOC-derived address
                    # loaded at function entry — beyond the narrow backward window.
                    # Case A: base_r = addis rX, r2, HI [+ addi rX, rX, LO] → rodata constant.
                    # Case B: base_r = mr rX, rEntryArg → addi r3, rX, LO is ARG_PROPAGATED.
                    # (PPC64-SAC-CALLEE-001)
                    base_val = self._eval_callee_saved_reg(insns, base_r, j)
                    if base_val is not None:
                        final_va = (base_val + _sign16(lo_val)) & 0xFFFFFFFFFFFFFFFF
                        if self._is_rodata(final_va):
                            return (RODATA_CONST,
                                    f'addis+addi(r2→{_rname(base_r)}) → {final_va:#018x} in .rodata')
                        ptr = self._read_u64_le(final_va)
                        if ptr is not None and self._is_rodata(ptr):
                            return (RODATA_CONST,
                                    f'addis+addi(r2→{_rname(base_r)}) → ptr {final_va:#018x} → {ptr:#018x} in .rodata')
                    if self._is_callee_saved_from_entry_arg(insns, base_r, j):
                        return (ARG_PROPAGATED,
                                f'addi {_rname(arg_reg)}, {_rname(base_r)}: base is entry+imm')

                return (UNKNOWN,
                        f'addi {_rname(arg_reg)}: unknown base @ {insn.address:#010x}')

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
                        pair = self._resolve_lis_pair(insns, j, arg_reg, disp)
                        if pair is not None:
                            return pair
                        toc = self._resolve_toc_relative(insns, j, arg_reg, disp, indirect=True)
                        if toc is not None:
                            return toc

                    if base_reg == PPC_REG_R2 and self._r2 is not None:
                        # ld rX, N(r2) — direct TOC slot dereference
                        toc_addr = (self._r2 + _sign16(disp & 0xFFFF)) & 0xFFFFFFFFFFFFFFFF
                        ptr = self._read_u64_le(toc_addr)
                        if ptr is not None and self._is_rodata(ptr):
                            return (RODATA_CONST,
                                    f'ld(r2) → ptr {toc_addr:#018x} → {ptr:#018x} in .rodata')

                    if base_reg in _PPC64_ENTRY_ARG_SET:
                        return (ARG_PROPAGATED,
                                f'{insn.mnemonic} {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)})'
                                f' struct field of entry arg')

                    # Callee-saved base register (r14-r31) set via TOC or entry arg copy.
                    # Case A: base_reg = addis rX, r2, HI [+ addi rX, rX, LO] → rodata ptr.
                    # Case B: base_reg = mr rX, rEntryArg → ld r3, N(rX) is ARG_PROPAGATED.
                    # (PPC64-SAC-CALLEE-001)
                    base_val = self._eval_callee_saved_reg(insns, base_reg, j)
                    if base_val is not None:
                        load_va = (base_val + _sign16(disp)) & 0xFFFFFFFFFFFFFFFF
                        if self._is_rodata(load_va):
                            return (RODATA_CONST,
                                    f'{insn.mnemonic}(r2→{_rname(base_reg)}) → {load_va:#018x} in .rodata')
                        ptr = self._read_u64_le(load_va)
                        if ptr is not None and self._is_rodata(ptr):
                            return (RODATA_CONST,
                                    f'{insn.mnemonic}(r2→{_rname(base_reg)}) → ptr {load_va:#018x} → {ptr:#018x} in .rodata')
                    if self._is_callee_saved_from_entry_arg(insns, base_reg, j):
                        return (ARG_PROPAGATED,
                                f'ld {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)} ← entry arg)')

                    return (UNKNOWN,
                            f'{insn.mnemonic} {_rname(arg_reg)}, {disp:#x}({_rname(base_reg)})')

            if insn.id in (PPC_INS_LBZ, PPC_INS_LHZ):
                return (UNKNOWN, f'{insn.mnemonic} {_rname(arg_reg)} @ {insn.address:#010x}')

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

    def _scan_uncovered_bls(
        self,
        sink_plts: Dict[int, Tuple[str, int]],
        covered_call_vas: set,
    ) -> List['SinkClassification']:
        """Fallback: scan .text bytes directly for BL <stub_va> when func_starts
        misses the containing function (e.g. ppc64le ELFv2 large Go DSOs where
        BinaryContext doesn't register every GEP as a func_start).

        For each uncovered BL hit, disassemble a 256-instruction window ending
        at the call site and classify as if called from a pseudo func_start.
        """
        import struct as _s
        results: List[SinkClassification] = []
        text_sec = None
        if self._bin is not None:
            for sec in self._bin.sections:
                if sec.name == '.text':
                    text_sec = sec
                    break
        if text_sec is None or self._cs is None:
            return results
        text_va  = int(text_sec.virtual_address)
        text_off = self._va_to_file_offset(text_va)
        text_sz  = int(text_sec.size)
        if text_off < 0 or text_off >= len(self._data):
            return results
        text_raw = self._data[text_off:text_off + text_sz]
        for sink_va, (sink_name, arg_pos) in sink_plts.items():
            # Scan every 4-byte-aligned position for BL stub_va from that position.
            for i in range(0, text_sz - 4, 4):
                caller_va = text_va + i
                offset = sink_va - caller_va
                if offset % 4 != 0:
                    continue
                li = (offset >> 2) & 0xFFFFFF
                bl_word = 0x48000001 | ((li & 0xFFFFFF) << 2)
                if _s.unpack_from('<I', text_raw, i)[0] != bl_word:
                    continue
                if caller_va in covered_call_vas:
                    continue
                # Locate the function's Global Entry Point (GEP) by scanning
                # backward for "addis r2, r12, N" (opcode 15, rt=r2, ra=r12 =
                # 0x3C420000|N in LE ppc64).  .text may have null-byte gaps so a
                # fixed backward window can stop too early; starting from the GEP
                # and disassembling forward gives the complete function body.
                gep_va = caller_va  # fallback: start at call site
                scan_back_limit = max(text_va, caller_va - _MAX_FUNC_BYTES)
                j = caller_va - 4
                while j >= scan_back_limit:
                    w = _s.unpack_from('<I', text_raw, j - text_va)[0]
                    if (w & 0xFFFF0000) == 0x3C4C0000 and (w >> 26) == 15:
                        gep_va = j
                        break
                    j -= 4
                window_start = gep_va
                window_raw   = self._read_va(window_start, caller_va - window_start + 4)
                if not window_raw:
                    continue
                insns = list(self._cs.disasm(window_raw, window_start))
                # Find the BL index in this window.
                call_idx = next(
                    (j for j, ins in enumerate(insns)
                     if ins.id == PPC_INS_BL
                     and ins.operands
                     and ins.operands[0].imm == sink_va),
                    None,
                )
                if call_idx is None:
                    continue
                if arg_pos >= len(_PPC64_ARG_REGS):
                    continue
                arg_reg = _PPC64_ARG_REGS[arg_pos]
                verdict, detail = self._trace_arg(insns, call_idx, arg_reg)
                severity = '' if verdict in (RODATA_CONST, SNPRINTF_RODATA) else 'HIGH'
                results.append(SinkClassification(
                    sink_name, arg_pos, window_start,
                    caller_va, verdict, detail, severity,
                ))
        return results

    def classify_all(self) -> List[SinkClassification]:
        """Run classification across all func_starts for all registered sink call sites."""
        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []
        results: List[SinkClassification] = []
        for func_va in self._ctx.func_starts:
            results.extend(self._classify_function(func_va, sink_plts))
        # Fall back to direct BL scan for call sites not covered by func_starts.
        covered = {r.call_va for r in results}
        results.extend(self._scan_uncovered_bls(sink_plts, covered))
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
        for func_va in self._ctx.func_starts:
            results.extend(self._classify_function(func_va, sink_plts))
        return results

    def report(self, results: List[SinkClassification]) -> str:
        if not results:
            return 'SinkArgClassifierPPC64ELFv2: no results\n'
        lines = [f'SinkArgClassifierPPC64ELFv2: {len(results)} results']
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
