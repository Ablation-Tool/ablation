"""
taint_tracker_ppc64.py: PowerPC 64-bit network-to-sink taint analysis.

Architecture: PPC64 big-endian and little-endian.
ABI: ELFv2 (modern OpenPOWER Linux, POWER8+) and ELFv1 (AIX, old Linux PPC64).
     Both share the same integer register model:
     r3-r10 args (8 integer regs), r3 return value,
     r14-r31 callee-saved, r0/r3-r12/lr caller-saved.
     r2 = TOC pointer (callee must preserve in both ABIs).
     No branch delay slots.

Prologue (ELFv2): mflr r0   [save LR]
                  stdu r1, -N(r1)   [extend frame + save old SP]
                  std  r0, 16(r1)   [save LR in caller's ABI slot]
Prologue (ELFv1): same frame setup; function descriptor in .opd handles GOT.
Return:           blr               [branch to link register]
Call:             bl  <target>      [direct call]
                  bctrl             [indirect call via CTR, used for PLT]

Sources: recv/recvfrom/read/fgets/gets/fread -- return value in r3.
Sinks  : system/execve/execl/execvp/popen/strcpy/sprintf/memcpy/strcat/snprintf.

Targets: IBM POWER (AIX big-endian), OpenPOWER/POWER8+ Linux little-endian,
         old Linux PPC64 big-endian ELFv1, older Apple G5 macOS (big-endian),
         some network equipment (Juniper MX/PTX with POWER processors).

Usage:
    from ablation.analyzers.taint_tracker_ppc64 import PPC64TaintTracker
    tracker = PPC64TaintTracker.from_path('power_bin')          # big-endian default
    findings = tracker.run()
    chains   = tracker.run_interprocedural(depth=4)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    import capstone
    from capstone.ppc_const import (
        PPC_OP_REG, PPC_OP_IMM, PPC_OP_MEM,
        # 32-bit loads (still used in PPC64 for 32-bit values)
        PPC_INS_LWZ,  PPC_INS_LWZU,
        PPC_INS_LBZ,  PPC_INS_LBZU,
        PPC_INS_LHZ,  PPC_INS_LHZU,
        PPC_INS_LHA,  PPC_INS_LHAU,
        PPC_INS_LWAX, PPC_INS_LWA,
        # 64-bit loads
        PPC_INS_LD,   PPC_INS_LDU,  PPC_INS_LDX,
        # Stores (32-bit)
        PPC_INS_STW,  PPC_INS_STWU,
        PPC_INS_STB,  PPC_INS_STH,
        # Stores (64-bit)
        PPC_INS_STD,  PPC_INS_STDU,
        # Arithmetic (shared 32/64)
        PPC_INS_ADD,  PPC_INS_ADDI,  PPC_INS_ADDIS, PPC_INS_ADDIC,
        PPC_INS_ADDC, PPC_INS_ADDE,
        PPC_INS_SUBF, PPC_INS_SUBFIC, PPC_INS_NEG,
        PPC_INS_MULLW, PPC_INS_MULHW, PPC_INS_MULHWU,
        PPC_INS_DIVW,  PPC_INS_DIVWU,
        # Arithmetic (64-bit)
        PPC_INS_MULLD,  PPC_INS_MULHD,  PPC_INS_MULHDU,
        PPC_INS_DIVD,   PPC_INS_DIVDU,
        PPC_INS_EXTSW,
        # Logic
        PPC_INS_AND,  PPC_INS_ANDI,  PPC_INS_ANDC,
        PPC_INS_OR,   PPC_INS_ORI,   PPC_INS_NOR,
        PPC_INS_XOR,  PPC_INS_XORI,
        PPC_INS_SLW,  PPC_INS_SRW,   PPC_INS_SRAWI,
        PPC_INS_SLD,  PPC_INS_SRD,   PPC_INS_SRAD,  PPC_INS_SRADI,
        PPC_INS_RLWINM, PPC_INS_RLWIMI,
        PPC_INS_RLDICL, PPC_INS_RLDICR, PPC_INS_RLDIMI,
        # Pseudo / move
        PPC_INS_MR,   PPC_INS_LI,    PPC_INS_LIS,
        PPC_INS_NOP,
        # SPR
        PPC_INS_MFLR, PPC_INS_MTLR,  PPC_INS_MTCTR,
        # Branches / calls / returns
        PPC_INS_B,    PPC_INS_BC,
        PPC_INS_BL,   PPC_INS_BLA,
        PPC_INS_BLR,  PPC_INS_BLRL,
        PPC_INS_BCTR, PPC_INS_BCTRL,
        PPC_INS_BEQ,  PPC_INS_BNE,
        PPC_INS_BGT,  PPC_INS_BLT,
        PPC_INS_BGE,  PPC_INS_BLE,
    )
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False

try:
    import lief as _lief
    _HAS_LIEF = True
except ImportError:
    _HAS_LIEF = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    _HAS_PYELF = True
except ImportError:
    _HAS_PYELF = False


# ---------------------------------------------------------------------------
# PPC64 ELFv2 register model
# ---------------------------------------------------------------------------
#
# r0        : volatile (scratch; mflr r0 in prologue)
# r1        : stack pointer (never tainted)
# r2        : TOC pointer (callee-saved in ELFv2; skip taint)
# r3-r10    : integer arguments + return (r3)
# r11       : volatile (indirect call target, environment pointer)
# r12       : volatile (used in ELFv2 global entry; PLT indirect call target)
# r13       : small data pointer (TLS in Linux; callee-saved in EABI)
# r14-r31   : callee-saved
# lr        : link register
# ctr       : count register
# ---------------------------------------------------------------------------

_ARG_REGS: List[str] = ['r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10']

_CALLER_SAVED: frozenset = frozenset([
    'r0', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10',
    'r11', 'r12',
])

_CALLEE_SAVED: frozenset = frozenset([
    'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20',
    'r21', 'r22', 'r23', 'r24', 'r25', 'r26', 'r27', 'r28',
    'r29', 'r30', 'r31',
    'r1', 'r2',
])

_CALL_IDS: Set[int] = set()
_RET_IDS: Set[int] = set()

if _HAS_CAPSTONE:
    _CALL_IDS = {PPC_INS_BL, PPC_INS_BLA, PPC_INS_BCTRL}
    _RET_IDS  = {PPC_INS_BLR, PPC_INS_BLRL}

_SOURCES: Set[str] = {
    'recv', 'recvfrom', 'recvmsg', 'read', 'pread',
    'fread', 'fgets', 'gets', 'getenv',
    'recv@plt', 'read@plt', 'fgets@plt', 'recvfrom@plt',
}

_DEFAULT_SINKS: Dict[str, List[int]] = {
    'system':    [0],
    'execv':     [0],
    'execvp':    [0],
    'execve':    [0],
    'popen':     [0],
    'strcpy':    [1],
    'strcat':    [1],
    'sprintf':   [1],
    'snprintf':  [2],
    'memcpy':    [2],
    'memmove':   [2],
    'malloc':    [0],
    'calloc':    [0, 1],
    'realloc':   [1],
}

MAX_FUNC_BYTES = 0x8000


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TaintFindingPPC64:
    binary: str
    func_va: int
    func_name: str
    sink_va: int
    sink_name: str
    tainted_args: List[int]
    source_name: str

    def __str__(self) -> str:
        args_str = ', '.join(f'r{i + 3}' for i in self.tainted_args)
        return (f'[PPC64-TAINT] {self.func_name} (0x{self.func_va:x})'
                f' -> {self.sink_name}({args_str}) @ 0x{self.sink_va:x}'
                f'  [src: {self.source_name}]')


# ---------------------------------------------------------------------------
# PPC64TaintTracker
# ---------------------------------------------------------------------------

class PPC64TaintTracker:
    """
    Source-to-sink static taint tracker for PPC64 ELF binaries.

    ABI: ELFv2 (OpenPOWER Linux) and ELFv1 (AIX, old Linux PPC64).
    No branch delay slots.

    Usage:
        tracker = PPC64TaintTracker.from_path('power_bin')          # BE default
        findings = tracker.run()
        chains   = tracker.run_interprocedural(depth=4)

    Custom sinks:
        tracker = PPC64TaintTracker.from_path('fw', custom_sinks={'aix_exec': [0]})

    From BinaryContext:
        tracker = PPC64TaintTracker.from_context(ctx)
    """

    def __init__(
        self,
        binary_path: str,
        ctx=None,
        custom_sinks: Optional[Dict[str, List[int]]] = None,
        endian: str = 'big',
    ):
        if not _HAS_CAPSTONE:
            raise RuntimeError('capstone not installed')

        self.binary_path = binary_path
        self._ctx = ctx
        self._sinks = dict(_DEFAULT_SINKS)
        if custom_sinks:
            self._sinks.update(custom_sinks)

        self._data = Path(binary_path).read_bytes()
        self._endian = endian
        self._plt: Dict[int, str] = {}
        self._func_starts: List[int] = []
        self._text_va: int = 0
        self._text_off: int = 0
        self._text_size: int = 0

        cs_endian = (capstone.CS_MODE_BIG_ENDIAN if endian == 'big'
                     else capstone.CS_MODE_LITTLE_ENDIAN)
        self._md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_64 | cs_endian)
        self._md.detail = True
        self._md.skipdata = True

        self._load_elf()

    @classmethod
    def from_path(cls, path: str, endian: str = 'big', **kwargs) -> 'PPC64TaintTracker':
        return cls(path, endian=endian, **kwargs)

    @classmethod
    def from_context(cls, ctx, endian: str = 'big', **kwargs) -> 'PPC64TaintTracker':
        return cls(ctx.binary_path, ctx=ctx, endian=endian, **kwargs)

    # ------------------------------------------------------------------
    # ELF loading
    # ------------------------------------------------------------------

    def _load_elf(self) -> None:
        if _HAS_LIEF:
            self._load_lief()
        elif _HAS_PYELF:
            self._load_pyelf()

    def _load_lief(self) -> None:
        try:
            binary = _lief.parse(self.binary_path)
            if not binary:
                return
            for sym in binary.pltgot_relocations:
                if sym.symbol and sym.symbol.name:
                    self._plt[sym.address] = sym.symbol.name
            for sym in binary.plt_relocations:
                if sym.symbol and sym.symbol.name:
                    self._plt[sym.address] = sym.symbol.name
            starts: Set[int] = set()
            for sym in binary.static_symbols:
                if sym.type == _lief.ELF.SYMBOL_TYPES.FUNC and sym.value:
                    starts.add(sym.value)
            for sym in binary.dynamic_symbols:
                if sym.type == _lief.ELF.SYMBOL_TYPES.FUNC and sym.value:
                    starts.add(sym.value)
            self._func_starts = sorted(starts)
            for seg in binary.segments:
                if seg.type == _lief.ELF.SEGMENT_TYPES.LOAD and seg.flags & 0x1:
                    self._text_va   = seg.virtual_address
                    self._text_off  = seg.file_offset
                    self._text_size = seg.physical_size
                    break
        except Exception:
            pass

    def _load_pyelf(self) -> None:
        try:
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                text = elf.get_section_by_name('.text')
                if text:
                    self._text_va   = text['sh_addr']
                    self._text_off  = text['sh_offset']
                    self._text_size = text['sh_size']
                dynsym = elf.get_section_by_name('.dynsym')
                if dynsym:
                    plt_sec = elf.get_section_by_name('.plt')
                    plt_va  = plt_sec['sh_addr'] if plt_sec else 0
                    for relname in ('.rela.plt',):
                        rsec = elf.get_section_by_name(relname)
                        if not rsec:
                            continue
                        for idx, rel in enumerate(rsec.iter_relocations()):
                            sym = dynsym.get_symbol(rel['r_info_sym'])
                            if sym and plt_va:
                                # PPC64 ELFv2 PLT stubs are 16 bytes
                                self._plt[plt_va + 16 * (idx + 1)] = sym.name
                for sname in ('.symtab', '.dynsym'):
                    sec = elf.get_section_by_name(sname)
                    if not isinstance(sec, SymbolTableSection):
                        continue
                    for sym in sec.iter_symbols():
                        if (sym['st_info']['type'] == 'STT_FUNC'
                                and sym['st_value'] and sym['st_size'] > 0):
                            self._func_starts.append(sym['st_value'])
                self._func_starts = sorted(set(self._func_starts))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_func_starts(self) -> List[int]:
        if self._ctx is not None:
            return self._ctx.func_starts
        if self._func_starts:
            return self._func_starts
        # Prologue scan: stdu r1, -N(r1)
        # DS-form: opcode=62(0x3e), XO=1, rs=1, ra=1, ds=negative 14-bit
        # Word: [31:26]=62, [25:21]=1, [20:16]=1, [15:2]=ds, [1:0]=01
        starts: List[int] = []
        bo = 'big' if self._endian == 'big' else 'little'
        for off in range(0, len(self._data) - 3, 4):
            w = int.from_bytes(self._data[off:off+4], bo)
            opcode = (w >> 26) & 0x3f
            rs     = (w >> 21) & 0x1f
            ra     = (w >> 16) & 0x1f
            ds     = (w >> 2) & 0x3fff   # 14-bit field
            xo     = w & 0x3
            # STDU: opcode=62, XO=1, negative ds (bit 13 of ds set)
            if opcode == 62 and xo == 1 and rs == 1 and ra == 1 and (ds & 0x2000):
                if self._text_va and self._text_off:
                    va = self._text_va + (off - self._text_off)
                    if self._text_va <= va < self._text_va + self._text_size:
                        starts.append(va)
        return sorted(set(starts))

    def _va_to_slice(self, va: int, size: int) -> Optional[bytes]:
        if not self._text_va:
            return None
        off = self._text_off + (va - self._text_va)
        if off < 0 or off + size > len(self._data):
            return None
        return self._data[off: off + size]

    def _func_name(self, va: int) -> str:
        if self._ctx is not None:
            return self._ctx.name(va)
        return self._plt.get(va, f'0x{va:x}')

    # ------------------------------------------------------------------
    # Taint semantics
    # ------------------------------------------------------------------

    def _exec_insn(self, insn, tainted: Dict[str, bool]) -> None:
        """Apply one non-call instruction's taint semantics."""
        ops = insn.operands
        if not ops:
            return

        def get_t(reg: str) -> bool:
            return bool(tainted.get(reg.lower()))

        def set_t(reg: str, val: bool) -> None:
            r = reg.lower()
            if r not in ('r1', 'r2'):
                tainted[r] = val

        def rn(op) -> str:
            return insn.reg_name(op.reg).lower() if op.type == PPC_OP_REG else ''

        # LI/LIS: immediate load -- clears taint
        if insn.id in (PPC_INS_LI, PPC_INS_LIS) and ops:
            set_t(rn(ops[0]), False)

        # MR dst, src
        elif insn.id == PPC_INS_MR and len(ops) == 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # EXTSW: sign-extend word to doubleword; taint flows
        elif insn.id == PPC_INS_EXTSW and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # ADDI/ADDIS/ADDIC dst, src, imm -- taint from src
        elif insn.id in (PPC_INS_ADDI, PPC_INS_ADDIS, PPC_INS_ADDIC) and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # ADD/ADDC/ADDE dst, src1, src2
        elif insn.id in (PPC_INS_ADD, PPC_INS_ADDC, PPC_INS_ADDE) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])) or get_t(rn(ops[2])))

        # SUBF/NEG
        elif insn.id == PPC_INS_SUBF and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])) or get_t(rn(ops[2])))
        elif insn.id in (PPC_INS_SUBFIC,) and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id == PPC_INS_NEG and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # AND/ANDC, OR/NOR, XOR (3-reg)
        elif insn.id in (PPC_INS_AND, PPC_INS_ANDC,
                         PPC_INS_OR, PPC_INS_NOR,
                         PPC_INS_XOR) and len(ops) == 3:
            dst, s1, s2 = rn(ops[0]), rn(ops[1]), rn(ops[2])
            if insn.id == PPC_INS_XOR and s1 == s2:
                set_t(dst, False)
            else:
                set_t(dst, get_t(s1) or get_t(s2))

        # ANDI/ORI/XORI
        elif insn.id in (PPC_INS_ANDI, PPC_INS_ORI, PPC_INS_XORI) and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # 32-bit shifts/rotates
        elif insn.id in (PPC_INS_SLW, PPC_INS_SRW) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id == PPC_INS_SRAWI and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id == PPC_INS_RLWINM and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id == PPC_INS_RLWIMI and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[0])) or get_t(rn(ops[1])))

        # 64-bit shifts/rotates
        elif insn.id in (PPC_INS_SLD, PPC_INS_SRD, PPC_INS_SRAD) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id == PPC_INS_SRADI and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id in (PPC_INS_RLDICL, PPC_INS_RLDICR) and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))
        elif insn.id == PPC_INS_RLDIMI and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[0])) or get_t(rn(ops[1])))

        # 32-bit multiply/divide
        elif insn.id in (PPC_INS_MULLW, PPC_INS_MULHW, PPC_INS_MULHWU) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])) or get_t(rn(ops[2])))
        elif insn.id in (PPC_INS_DIVW, PPC_INS_DIVWU) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])) or get_t(rn(ops[2])))

        # 64-bit multiply/divide
        elif insn.id in (PPC_INS_MULLD, PPC_INS_MULHD, PPC_INS_MULHDU) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])) or get_t(rn(ops[2])))
        elif insn.id in (PPC_INS_DIVD, PPC_INS_DIVDU) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])) or get_t(rn(ops[2])))

        # 32-bit loads
        elif insn.id in (PPC_INS_LWZ, PPC_INS_LWZU,
                         PPC_INS_LWA, PPC_INS_LWAX,
                         PPC_INS_LBZ, PPC_INS_LBZU,
                         PPC_INS_LHZ, PPC_INS_LHZU,
                         PPC_INS_LHA, PPC_INS_LHAU) and len(ops) >= 2:
            dst = rn(ops[0])
            if ops[1].type == PPC_OP_MEM:
                base = insn.reg_name(ops[1].mem.base).lower()
                if tainted.get(base):
                    set_t(dst, True)

        # 64-bit loads: LD/LDU/LDX
        elif insn.id in (PPC_INS_LD, PPC_INS_LDU, PPC_INS_LDX) and len(ops) >= 2:
            dst = rn(ops[0])
            if ops[1].type == PPC_OP_MEM:
                base = insn.reg_name(ops[1].mem.base).lower()
                if tainted.get(base):
                    set_t(dst, True)

        # MFLR: not a taint source
        elif insn.id == PPC_INS_MFLR and ops:
            set_t(rn(ops[0]), False)

    def _analyze_function(
        self,
        func_va: int,
        func_end_va: int,
        func_bytes: bytes,
        seed_arg_indices: List[int],
    ) -> List[TaintFindingPPC64]:
        tainted: Dict[str, bool] = {}
        for i in seed_arg_indices:
            if i < len(_ARG_REGS):
                tainted[_ARG_REGS[i]] = True

        findings: List[TaintFindingPPC64] = []
        func_name = self._func_name(func_va)

        try:
            all_insns = list(self._md.disasm(func_bytes, func_va))
        except Exception:
            return findings

        for insn in all_insns:
            ops = insn.operands

            # -- Calls: bl/bla/bctrl --
            if insn.id in _CALL_IDS:
                target_name = ''
                if insn.id in (PPC_INS_BL, PPC_INS_BLA) and ops:
                    if ops[0].type == PPC_OP_IMM:
                        target_name = self._plt.get(ops[0].imm, '')

                if target_name in _SOURCES:
                    tainted['r3'] = True

                elif target_name in self._sinks:
                    hit_args = []
                    for ai, areg in enumerate(_ARG_REGS):
                        if ai in self._sinks.get(target_name, []) and tainted.get(areg):
                            hit_args.append(ai)
                    if hit_args:
                        findings.append(TaintFindingPPC64(
                            binary=self.binary_path,
                            func_va=func_va,
                            func_name=func_name,
                            sink_va=insn.address,
                            sink_name=target_name,
                            tainted_args=hit_args,
                            source_name='recv/arg',
                        ))

                # Clobber caller-saved after call
                for r in _CALLER_SAVED - {'r3'}:
                    tainted[r] = False
                if target_name not in _SOURCES:
                    tainted['r3'] = False

            # -- Return: blr/blrl --
            elif insn.id in _RET_IDS:
                break

            # -- Everything else: taint propagation --
            else:
                self._exec_insn(insn, tainted)

        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_on_function(self, func_va: int, func_end_va: int = 0) -> List[TaintFindingPPC64]:
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 8:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, [])

    def run_on_function_seeded(
        self, func_va: int, seed_arg_indices: List[int], func_end_va: int = 0
    ) -> List[TaintFindingPPC64]:
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 8:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, seed_arg_indices)

    def run(self) -> List[TaintFindingPPC64]:
        func_starts = self._get_func_starts()
        findings: List[TaintFindingPPC64] = []
        func_end_map = {
            fva: (func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES)
            for i, fva in enumerate(func_starts)
        }
        for fva, fend in func_end_map.items():
            size = min(fend - fva, MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(fva, size)
            if not func_bytes or len(func_bytes) < 8:
                continue
            try:
                findings.extend(self._analyze_function(fva, fend, func_bytes, []))
            except Exception:
                continue
        return findings

    def run_interprocedural(self, depth: int = 4) -> List[TaintFindingPPC64]:
        func_starts = self._get_func_starts()
        if not func_starts:
            return []

        func_start_set = set(func_starts)
        func_end_map: Dict[int, int] = {
            fva: (func_starts[i + 1] if i + 1 < len(func_starts) else fva + MAX_FUNC_BYTES)
            for i, fva in enumerate(func_starts)
        }

        # Seed: functions that directly call a network source
        seed_funcs: Dict[int, str] = {}
        for fva in func_starts:
            fend = func_end_map[fva]
            func_bytes = self._va_to_slice(fva, min(fend - fva, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 8:
                continue
            try:
                for insn in self._md.disasm(func_bytes, fva):
                    if insn.id == PPC_INS_BL and insn.operands:
                        op = insn.operands[0]
                        if op.type == PPC_OP_IMM:
                            name = self._plt.get(op.imm, '')
                            if name in _SOURCES:
                                seed_funcs[fva] = name
                                break
            except Exception:
                continue

        results: List[TaintFindingPPC64] = []
        queue: deque = deque()
        visited: Set[tuple] = set()

        for fva, src_name in seed_funcs.items():
            key = (fva, frozenset())
            if key not in visited:
                visited.add(key)
                queue.append((fva, [], 0, src_name))

        while queue:
            func_va, seed_arg_indices, depth_cur, source_name = queue.popleft()
            if depth_cur > depth:
                continue

            fend = func_end_map.get(func_va, func_va + MAX_FUNC_BYTES)
            func_bytes = self._va_to_slice(func_va, min(fend - func_va, MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 8:
                continue

            try:
                findings = self._analyze_function(func_va, fend, func_bytes, seed_arg_indices)
            except Exception:
                continue

            results.extend(findings)

            # Propagate tainted args into callees
            try:
                tainted: Dict[str, bool] = {_ARG_REGS[i]: True for i in seed_arg_indices
                                             if i < len(_ARG_REGS)}
                for insn in self._md.disasm(func_bytes, func_va):
                    if insn.id in _CALL_IDS:
                        if insn.id == PPC_INS_BL and insn.operands:
                            op = insn.operands[0]
                            if op.type == PPC_OP_IMM:
                                callee_va = op.imm
                                if callee_va in func_start_set:
                                    tainted_passed = [
                                        ai for ai, ar in enumerate(_ARG_REGS)
                                        if tainted.get(ar)
                                    ]
                                    if tainted_passed:
                                        key = (callee_va, frozenset(tainted_passed))
                                        if key not in visited:
                                            visited.add(key)
                                            queue.append((callee_va, tainted_passed,
                                                          depth_cur + 1, source_name))
                        for r in _CALLER_SAVED:
                            tainted[r] = False
                    elif insn.id in _RET_IDS:
                        break
                    else:
                        self._exec_insn(insn, tainted)
            except Exception:
                pass

        return results

    def report(self, findings: List[TaintFindingPPC64]) -> str:
        if not findings:
            return f'[ppc64_taint] No findings in {self.binary_path}'
        lines = [f'[ppc64_taint] {self.binary_path}: {len(findings)} finding(s)']
        for f in findings:
            lines.append(f'  {f}')
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='PPC64 taint tracker')
    ap.add_argument('binary')
    ap.add_argument('--le', action='store_true', help='little-endian (default: big-endian)')
    ap.add_argument('--interprocedural', action='store_true')
    ap.add_argument('--depth', type=int, default=4)
    args = ap.parse_args()

    tracker = PPC64TaintTracker.from_path(args.binary, endian='little' if args.le else 'big')
    if args.interprocedural:
        results = tracker.run_interprocedural(depth=args.depth)
    else:
        results = tracker.run()
    print(tracker.report(results))


if __name__ == '__main__':
    _cli()
