"""
taint_tracker_mips64.py: MIPS64 network-to-sink taint analysis.

Architecture: MIPS64 big-endian and little-endian.
ABI: N64: $a0-$a3 ($4-$7) + $a4-$a7 mapped to capstone t4-t7 ($12-$15);
     $v0/$v1 return; $t8/$t9 caller-saved; $s0-$s7 callee-saved.

Load-delay slot: pre-R6 MIPS64 retains branch delay slots. The tracker
consumes the delay-slot instruction before processing the branch outcome.

64-bit ops: LD/SD for 64-bit load/store; DADDU/DADDIU/DSUBU for 64-bit
arithmetic; DMULT/DMULTU/DDIV/DDIVU for wide multiply/divide; DSLL/DSRL/DSRA
and their 32-suffix variants for doubleword shifts.

Sources: recv/recvfrom/read/fgets/gets/fread and their PLT wrappers.
         Return value in $v0; taint propagates from there.
Sinks  : system/execve/execl/execvp/popen/strcpy/sprintf/memcpy/strcat/snprintf.

Targets: Cisco IOS/IOS-XE (big-endian, OCTEON), RouterOS 64 (little-endian).

Usage:
    from ablation.analyzers.taint_tracker_mips64 import MIPS64TaintTracker
    tracker = MIPS64TaintTracker.from_path('iosd', endian='big')
    findings = tracker.run()
    chains   = tracker.run_interprocedural(depth=4)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import capstone
    from capstone.mips_const import (
        MIPS_OP_REG, MIPS_OP_IMM, MIPS_OP_MEM,
        # 32-bit loads (still valid in MIPS64)
        MIPS_INS_LW,  MIPS_INS_LH,  MIPS_INS_LB,  MIPS_INS_LBU, MIPS_INS_LHU, MIPS_INS_LWU,
        MIPS_INS_SW,  MIPS_INS_SH,  MIPS_INS_SB,
        # 64-bit loads/stores
        MIPS_INS_LD,  MIPS_INS_LDL, MIPS_INS_LDR,
        MIPS_INS_SD,  MIPS_INS_SDL, MIPS_INS_SDR,
        # 32-bit arithmetic (still emitted for word-sized values)
        MIPS_INS_MOVE,
        MIPS_INS_ADD,  MIPS_INS_ADDU,  MIPS_INS_ADDI,  MIPS_INS_ADDIU,
        MIPS_INS_SUB,  MIPS_INS_SUBU,
        MIPS_INS_AND,  MIPS_INS_ANDI,
        MIPS_INS_OR,   MIPS_INS_ORI,
        MIPS_INS_XOR,  MIPS_INS_XORI,  MIPS_INS_NOR,
        MIPS_INS_SLL,  MIPS_INS_SRL,  MIPS_INS_SRA,
        MIPS_INS_SLLV, MIPS_INS_SRLV, MIPS_INS_SRAV,
        MIPS_INS_MUL,  MIPS_INS_MULT, MIPS_INS_MULTU,
        MIPS_INS_DIV,  MIPS_INS_DIVU,
        MIPS_INS_MFHI, MIPS_INS_MFLO,
        MIPS_INS_LUI,
        # 64-bit arithmetic
        MIPS_INS_DADD,   MIPS_INS_DADDU,  MIPS_INS_DADDI,  MIPS_INS_DADDIU,
        MIPS_INS_DSUB,   MIPS_INS_DSUBU,
        MIPS_INS_DMUL,   MIPS_INS_DMULT,  MIPS_INS_DMULTU, MIPS_INS_DMULU,
        MIPS_INS_DDIV,   MIPS_INS_DDIVU,
        MIPS_INS_DSLL,   MIPS_INS_DSRL,   MIPS_INS_DSRA,
        MIPS_INS_DSLL32, MIPS_INS_DSRL32, MIPS_INS_DSRA32,
        MIPS_INS_DSLLV,  MIPS_INS_DSRLV,  MIPS_INS_DSRAV,
        # Branches / jumps (have delay slots in pre-R6)
        MIPS_INS_JAL,  MIPS_INS_JALR, MIPS_INS_JR,  MIPS_INS_J,
        MIPS_INS_BEQ,  MIPS_INS_BNE,  MIPS_INS_BGTZ, MIPS_INS_BLTZ,
        MIPS_INS_BGEZ, MIPS_INS_BLEZ, MIPS_INS_BGEZAL, MIPS_INS_BLTZAL,
        MIPS_INS_BAL,
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
# N64 ABI register model
# ---------------------------------------------------------------------------
#
# In MIPS64 N64 ABI, registers $4-$11 are all argument registers (a0-a7).
# Capstone 5.x names them using the O32 convention:
#   $4-$7   -> a0-a3   (same as O32)
#   $8-$11  -> t0-t3   (O32 temp) but in N64 ABI these are a4-a7
#   $12-$15 -> t4-t7   (capstone name; N64 ABI treats these as callee-saved)
#   $24-$25 -> t8-t9   (caller-saved temp in both ABIs)
#
# We alias t0-t3 as extra arg registers for N64 taint tracking.
# ---------------------------------------------------------------------------

_REG_ALIASES: Dict[str, str] = {
    'zero': 'zero', 'at': 'at',
    'v0': 'v0', 'v1': 'v1',
    'a0': 'a0', 'a1': 'a1', 'a2': 'a2', 'a3': 'a3',
    # N64 extended arg regs: capstone calls these t0-t3 ($8-$11)
    't0': 't0', 't1': 't1', 't2': 't2', 't3': 't3',
    # N64 callee-saved (capstone t4-t7 = O32 t4-t7 = $12-$15)
    't4': 't4', 't5': 't5', 't6': 't6', 't7': 't7',
    's0': 's0', 's1': 's1', 's2': 's2', 's3': 's3',
    's4': 's4', 's5': 's5', 's6': 's6', 's7': 's7',
    't8': 't8', 't9': 't9', 'k0': 'k0', 'k1': 'k1',
    'gp': 'gp', 'sp': 'sp', 'fp': 'fp', 's8': 'fp',
    'ra': 'ra',
}

# N64 argument registers (all 8): a0-a3 plus t0-t3 (capstone names for $8-$11)
_ARG_REGS: List[str] = ['a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3']

# Caller-saved in N64: at, v0-v1, a0-a3 (args 0-3), t0-t3 (args 4-7), t8-t9
# t4-t7 ($12-$15) are callee-saved in N64 (differs from O32)
_CALLER_SAVED: frozenset = frozenset([
    'at', 'v0', 'v1',
    'a0', 'a1', 'a2', 'a3',
    't0', 't1', 't2', 't3',
    't8', 't9',
])

# Callee-saved in N64: t4-t7, s0-s7, gp, sp, fp
_CALLEE_SAVED: frozenset = frozenset([
    't4', 't5', 't6', 't7',
    's0', 's1', 's2', 's3',
    's4', 's5', 's6', 's7',
    'gp', 'sp', 'fp',
])

_BRANCH_IDS: Set[int] = set()
if _HAS_CAPSTONE:
    _BRANCH_IDS = {
        MIPS_INS_JAL, MIPS_INS_JALR, MIPS_INS_JR, MIPS_INS_J,
        MIPS_INS_BEQ, MIPS_INS_BNE, MIPS_INS_BGTZ, MIPS_INS_BLTZ,
        MIPS_INS_BGEZ, MIPS_INS_BLEZ, MIPS_INS_BGEZAL, MIPS_INS_BLTZAL,
        MIPS_INS_BAL,
    }

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
class TaintFinding64:
    binary: str
    func_va: int
    func_name: str
    sink_va: int
    sink_name: str
    tainted_args: List[int]
    source_name: str

    def __str__(self) -> str:
        args_str = ', '.join(f'$a{i}' if i < 4 else f'$t{i-4}' for i in self.tainted_args)
        return (f'[MIPS64-TAINT] {self.func_name} (0x{self.func_va:x})'
                f' -> {self.sink_name}({args_str}) @ 0x{self.sink_va:x}'
                f'  [src: {self.source_name}]')


@dataclass
class InterproceduralPath64:
    func_chain: List[int]
    sink_va: int
    sink_name: str
    tainted_args: List[int]
    source_name: str

    def __str__(self) -> str:
        chain = ' -> '.join(f'0x{va:x}' for va in self.func_chain)
        args_str = ', '.join(f'$a{i}' if i < 4 else f'$t{i-4}' for i in self.tainted_args)
        return (f'[MIPS64-CHAIN] {self.source_name} => {chain}'
                f' => {self.sink_name}({args_str}) @ 0x{self.sink_va:x}')


# ---------------------------------------------------------------------------
# Core taint analysis
# ---------------------------------------------------------------------------

def _canon(name: str) -> Optional[str]:
    return _REG_ALIASES.get(name.lower().lstrip('$'))


class MIPS64TaintTracker:
    """
    Source-to-sink static taint tracker for MIPS64 N64 ABI ELF binaries.

    Targets: Cisco IOS/IOS-XE (big-endian OCTEON), RouterOS 64 (little-endian).

    Usage:
        tracker = MIPS64TaintTracker.from_path('iosd', endian='big')
        findings = tracker.run()
        chains   = tracker.run_interprocedural(depth=4)

    Custom sinks:
        tracker = MIPS64TaintTracker.from_path('iosd', endian='big',
                      custom_sinks={'ios_exec_cmd': [0]})

    From BinaryContext:
        tracker = MIPS64TaintTracker.from_context(ctx, endian='big')
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

        cs_endian = capstone.CS_MODE_BIG_ENDIAN if endian == 'big' else capstone.CS_MODE_LITTLE_ENDIAN
        self._md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | cs_endian)
        self._md.detail = True
        self._md.skipdata = True

        self._load_elf()

    @classmethod
    def from_path(cls, path: str, endian: str = 'big', **kwargs) -> 'MIPS64TaintTracker':
        return cls(path, endian=endian, **kwargs)

    @classmethod
    def from_context(cls, ctx, endian: str = 'big', **kwargs) -> 'MIPS64TaintTracker':
        return cls(ctx.binary_path, ctx=ctx, endian=endian, **kwargs)

    # ------------------------------------------------------------------
    # ELF loading
    # ------------------------------------------------------------------

    def _load_elf(self) -> None:
        if _HAS_LIEF:
            self._load_elf_lief()
        elif _HAS_PYELF:
            self._load_elf_pyelf()

    def _load_elf_lief(self) -> None:
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
            # text bounds for va->offset
            for seg in binary.segments:
                if seg.type == _lief.ELF.SEGMENT_TYPES.LOAD and seg.flags & 0x1:
                    self._text_va   = seg.virtual_address
                    self._text_off  = seg.file_offset
                    self._text_size = seg.physical_size
                    break
        except Exception:
            pass

    def _load_elf_pyelf(self) -> None:
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
                    stub_sz = 16
                    for relname in ('.rel.plt', '.rela.plt'):
                        rsec = elf.get_section_by_name(relname)
                        if not rsec:
                            continue
                        for idx, rel in enumerate(rsec.iter_relocations()):
                            sym = dynsym.get_symbol(rel['r_info_sym'])
                            if sym and plt_va:
                                self._plt[plt_va + stub_sz * (idx + 1)] = sym.name
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
        # Prologue scan: daddiu $sp, $sp, -N
        # MIPS64 BE: opcode=DADDIU(25=0x19), rs=29(sp), rt=29(sp), imm<0
        # Word: bits[31:26]=0x19, [25:21]=29, [20:16]=29, [15:0]=negative
        starts: List[int] = []
        bo = 'big' if self._endian == 'big' else 'little'
        for off in range(0, len(self._data) - 3, 4):
            w = int.from_bytes(self._data[off:off+4], bo)
            opcode = (w >> 26) & 0x3f
            rs     = (w >> 21) & 0x1f
            rt     = (w >> 16) & 0x1f
            imm    = w & 0xffff
            # DADDIU=25, ADDIU=9 -- match either as frame setup
            if opcode in (25, 9) and rs == 29 and rt == 29 and (imm & 0x8000):
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

    def _exec_non_branch(self, insn, tainted: Dict[str, bool]) -> None:
        ops = insn.operands
        if not ops:
            return

        def get_t(reg: str) -> bool:
            c = _canon(reg)
            return bool(tainted.get(c)) if c else False

        def set_t(reg: str, val: bool) -> None:
            c = _canon(reg)
            if c and c not in ('zero', 'sp'):
                tainted[c] = val

        def rn(op) -> str:
            return insn.reg_name(op.reg).lower() if op.type == MIPS_OP_REG else ''

        # LUI: immediate load, clears taint
        if insn.id == MIPS_INS_LUI and ops:
            set_t(rn(ops[0]), False)

        # MOVE / pseudo-move
        elif insn.id == MIPS_INS_MOVE and len(ops) == 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # 32-bit add (ADDU/ADD): zero-register idiom = move
        elif insn.id in (MIPS_INS_ADDU, MIPS_INS_ADD) and len(ops) == 3:
            dst, s1, s2 = rn(ops[0]), rn(ops[1]), rn(ops[2])
            if s2 == 'zero':
                set_t(dst, get_t(s1))
            elif s1 == 'zero':
                set_t(dst, get_t(s2))
            else:
                set_t(dst, get_t(s1) or get_t(s2))

        # 64-bit add (DADDU/DADD): same semantics
        elif insn.id in (MIPS_INS_DADDU, MIPS_INS_DADD) and len(ops) == 3:
            dst, s1, s2 = rn(ops[0]), rn(ops[1]), rn(ops[2])
            if s2 == 'zero':
                set_t(dst, get_t(s1))
            elif s1 == 'zero':
                set_t(dst, get_t(s2))
            else:
                set_t(dst, get_t(s1) or get_t(s2))

        # ADDIU/ADDI/DADDIU/DADDI: reg + immediate, taint from src
        elif insn.id in (MIPS_INS_ADDIU, MIPS_INS_ADDI,
                         MIPS_INS_DADDIU, MIPS_INS_DADDI) and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # SUBU/SUB/DSUBU/DSUB
        elif insn.id in (MIPS_INS_SUBU, MIPS_INS_SUB,
                         MIPS_INS_DSUBU, MIPS_INS_DSUB) and len(ops) == 3:
            dst, s1, s2 = rn(ops[0]), rn(ops[1]), rn(ops[2])
            set_t(dst, get_t(s1) or get_t(s2))

        # OR / AND / XOR / NOR (3-reg)
        elif insn.id in (MIPS_INS_OR, MIPS_INS_AND,
                         MIPS_INS_XOR, MIPS_INS_NOR) and len(ops) == 3:
            dst, s1, s2 = rn(ops[0]), rn(ops[1]), rn(ops[2])
            if insn.id == MIPS_INS_XOR and s1 == s2:
                set_t(dst, False)
            else:
                set_t(dst, get_t(s1) or get_t(s2))

        # Immediate logic: ORI/ANDI/XORI
        elif insn.id in (MIPS_INS_ORI, MIPS_INS_ANDI, MIPS_INS_XORI) and len(ops) >= 2:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # Shifts (immediate): SLL/SRL/SRA/DSLL/DSRL/DSRA and *32 variants
        elif insn.id in (MIPS_INS_SLL,   MIPS_INS_SRL,   MIPS_INS_SRA,
                         MIPS_INS_DSLL,  MIPS_INS_DSRL,  MIPS_INS_DSRA,
                         MIPS_INS_DSLL32, MIPS_INS_DSRL32, MIPS_INS_DSRA32) and len(ops) >= 2:
            dst = rn(ops[0])
            src = rn(ops[1]) if ops[1].type == MIPS_OP_REG else rn(ops[0])
            set_t(dst, get_t(src))

        # Variable shifts: SLLV/SRLV/SRAV/DSLLV/DSRLV/DSRAV
        elif insn.id in (MIPS_INS_SLLV,  MIPS_INS_SRLV,  MIPS_INS_SRAV,
                         MIPS_INS_DSLLV, MIPS_INS_DSRLV, MIPS_INS_DSRAV) and len(ops) == 3:
            set_t(rn(ops[0]), get_t(rn(ops[1])))

        # MUL/DMUL (3-reg form): tainted if either operand tainted
        elif insn.id in (MIPS_INS_MUL, MIPS_INS_DMUL, MIPS_INS_DMULU) and len(ops) == 3:
            dst, s1, s2 = rn(ops[0]), rn(ops[1]), rn(ops[2])
            set_t(dst, get_t(s1) or get_t(s2))

        # MULT/MULTU/DMULT/DMULTU: result in HI/LO; no GPR dest here
        # MFHI/MFLO: treat as unknown (conservative: clear taint)
        elif insn.id in (MIPS_INS_MFHI, MIPS_INS_MFLO) and ops:
            set_t(rn(ops[0]), False)

        # 32-bit loads: LW/LH/LB/LBU/LHU/LWU
        elif insn.id in (MIPS_INS_LW, MIPS_INS_LH,  MIPS_INS_LB,
                         MIPS_INS_LBU, MIPS_INS_LHU, MIPS_INS_LWU) and len(ops) >= 2:
            dst = rn(ops[0])
            if ops[1].type == MIPS_OP_MEM:
                base = _canon(insn.reg_name(ops[1].mem.base).lower())
                if base and tainted.get(base):
                    set_t(dst, True)

        # 64-bit loads: LD/LDL/LDR
        elif insn.id in (MIPS_INS_LD, MIPS_INS_LDL, MIPS_INS_LDR) and len(ops) >= 2:
            dst = rn(ops[0])
            if ops[1].type == MIPS_OP_MEM:
                base = _canon(insn.reg_name(ops[1].mem.base).lower())
                if base and tainted.get(base):
                    set_t(dst, True)

        # Stores: no taint update to register file

    def _analyze_function(
        self,
        func_va: int,
        func_end_va: int,
        func_bytes: bytes,
        seed_arg_indices: List[int],
    ) -> List[TaintFinding64]:
        tainted: Dict[str, bool] = {}
        for i in seed_arg_indices:
            if i < len(_ARG_REGS):
                tainted[_ARG_REGS[i]] = True

        findings: List[TaintFinding64] = []
        func_name = self._func_name(func_va)

        try:
            all_insns = list(self._md.disasm(func_bytes, func_va))
        except Exception:
            return findings

        idx = 0
        while idx < len(all_insns):
            insn = all_insns[idx]
            ops = insn.operands

            if insn.id in _BRANCH_IDS:
                # Consume delay slot first (executes before branch takes effect)
                delay = all_insns[idx + 1] if idx + 1 < len(all_insns) else None
                if delay is not None:
                    self._exec_non_branch(delay, tainted)
                    idx += 1

                if insn.id in (MIPS_INS_JAL, MIPS_INS_JALR,
                               MIPS_INS_BAL, MIPS_INS_BGEZAL, MIPS_INS_BLTZAL):
                    target_name = ''
                    if ops and ops[0].type == MIPS_OP_IMM:
                        target_name = self._plt.get(ops[0].imm, '')

                    if target_name in _SOURCES:
                        tainted['v0'] = True
                        tainted['v1'] = False
                    elif target_name in self._sinks:
                        hit_args = []
                        for ai, areg in enumerate(_ARG_REGS):
                            if ai in self._sinks.get(target_name, []) and tainted.get(areg):
                                hit_args.append(ai)
                        if hit_args:
                            findings.append(TaintFinding64(
                                binary=self.binary_path,
                                func_va=func_va,
                                func_name=func_name,
                                sink_va=insn.address,
                                sink_name=target_name,
                                tainted_args=hit_args,
                                source_name='recv/arg',
                            ))

                    # Clobber caller-saved (preserve v0 if we just set it from source)
                    for r in _CALLER_SAVED - {'v0', 'v1'}:
                        tainted[r] = False
                    if target_name not in _SOURCES:
                        tainted['v0'] = False
                        tainted['v1'] = False

                elif insn.id == MIPS_INS_JR and ops:
                    reg = insn.reg_name(ops[0].reg).lower()
                    if reg == 'ra':
                        break

                idx += 1
                continue

            self._exec_non_branch(insn, tainted)
            idx += 1

        return findings

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_on_function(self, func_va: int, func_end_va: int = 0) -> List[TaintFinding64]:
        """Intraprocedural taint analysis on a single function."""
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 8:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, [])

    def run_on_function_seeded(
        self, func_va: int, seed_arg_indices: List[int], func_end_va: int = 0
    ) -> List[TaintFinding64]:
        """Analyze with pre-tainted argument registers."""
        if not func_end_va:
            func_end_va = func_va + MAX_FUNC_BYTES
        func_bytes = self._va_to_slice(func_va, min(func_end_va - func_va, MAX_FUNC_BYTES))
        if not func_bytes or len(func_bytes) < 8:
            return []
        return self._analyze_function(func_va, func_end_va, func_bytes, seed_arg_indices)

    def run(self) -> List[TaintFinding64]:
        """Intraprocedural taint analysis across all functions."""
        func_starts = self._get_func_starts()
        findings: List[TaintFinding64] = []
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

    def run_interprocedural(self, depth: int = 4) -> List[TaintFinding64]:
        """BFS from network source functions, following tainted args into callees."""
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
                    if insn.id == MIPS_INS_JAL and insn.operands:
                        op = insn.operands[0]
                        if op.type == MIPS_OP_IMM:
                            name = self._plt.get(op.imm, '')
                            if name in _SOURCES:
                                seed_funcs[fva] = name
                                break
            except Exception:
                continue

        results: List[TaintFinding64] = []
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

            # Propagate taint into callees
            try:
                tainted: Dict[str, bool] = {_ARG_REGS[i]: True for i in seed_arg_indices
                                             if i < len(_ARG_REGS)}
                all_insns = list(self._md.disasm(func_bytes, func_va))
                i2 = 0
                while i2 < len(all_insns):
                    insn = all_insns[i2]
                    ops = insn.operands
                    if insn.id in _BRANCH_IDS:
                        delay = all_insns[i2 + 1] if i2 + 1 < len(all_insns) else None
                        if delay:
                            self._exec_non_branch(delay, tainted)
                            i2 += 1
                        if insn.id == MIPS_INS_JAL and ops and ops[0].type == MIPS_OP_IMM:
                            callee_va = ops[0].imm
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
                    else:
                        self._exec_non_branch(insn, tainted)
                    i2 += 1
            except Exception:
                pass

        return results

    def report(self, findings: List[TaintFinding64]) -> str:
        if not findings:
            return f'[mips64_taint] No findings in {self.binary_path}'
        lines = [f'[mips64_taint] {self.binary_path}: {len(findings)} finding(s)']
        for f in findings:
            lines.append(f'  {f}')
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='MIPS64 N64 ABI taint tracker')
    ap.add_argument('binary')
    ap.add_argument('--endian', choices=['big', 'little'], default='big')
    ap.add_argument('--interprocedural', action='store_true')
    ap.add_argument('--depth', type=int, default=4)
    args = ap.parse_args()

    tracker = MIPS64TaintTracker.from_path(args.binary, endian=args.endian)
    if args.interprocedural:
        results = tracker.run_interprocedural(depth=args.depth)
    else:
        results = tracker.run()
    print(tracker.report(results))


if __name__ == '__main__':
    _cli()
