"""
taint_tracker_tricore.py: Infineon TriCore AURIX source-to-sink taint analysis.

Architecture: TriCore AURIX TC1.6x (little-endian).
ABI: Infineon TriCore EABI V2.9 / GHS EABI (GHS-RE-REFERENCE.md §1.2-1.3)
  Integer/scalar args: D[4]-D[7]  = d4, d5, d6, d7
  Pointer args:        A[4]-A[7]  = a4, a5, a6, a7
  Int return:          D[2]       = d2
  Ptr return:          A[2]       = a2
  Stack pointer:       A[10]      = sp
  Link register:       A[11]      = a11
  Caller-saved (lower context):   d0-d7, a2-a7, a11
  Callee-saved (upper context):   d8-d15, sp/a10, a12-a15, a0, a1

FCALL / FRET (GHS-RE-REFERENCE.md §1.7):
  Leaf functions use FCALL/FRET instead of CALL/RET.
  FCALL saves A[11] to stack only (no CSA). From taint perspective, same
  calling-convention effects as CALL: caller-saved regs are clobbered.

Sources: recv/recvfrom/read/fgets/gets/fread (return value in D[2] / A[2])
Sinks:   system/execve/execl/execvp/popen/strcpy/sprintf/snprintf/memcpy/strcat

Flat-binary usage (ECU ROM dumps):
    tracker = TriCoreTaintTracker.from_bytes(data, base_va=0x80000000)
    findings = tracker.scan_function(func_va, func_end_va, init_labels={'tainted'})

ELF usage:
    tracker = TriCoreTaintTracker.from_path('firmware.elf')
    findings = tracker.run()

Targets: Bosch ME17/MED17, Continental MG1, Waqas GEN3 ECU (AURIX TC1.6x).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, FrozenSet, List, Optional, Set, Tuple

try:
    import capstone
    from capstone import tricore_const as _tc
    _HAS_CAPSTONE = True
    _CS_ARCH_TRICORE = capstone.CS_ARCH_TRICORE
    _CS_MODE_TC162   = capstone.CS_MODE_TRICORE_162
    _OP_REG = _tc.CS_OP_REG
    _OP_IMM = _tc.CS_OP_IMM
    _OP_MEM = _tc.CS_OP_MEM
except ImportError:
    _HAS_CAPSTONE = False

try:
    import lief as _lief
    _HAS_LIEF = True
except ImportError:
    _HAS_LIEF = False

try:
    from elftools.elf.elffile import ELFFile
    _HAS_PYELF = True
except ImportError:
    _HAS_PYELF = False


# ---------------------------------------------------------------------------
# TriCore EABI register model (Capstone name strings)
# ---------------------------------------------------------------------------
#
# Integer argument registers (D[4]-D[7]):
_TC_INT_ARG  = ('d4', 'd5', 'd6', 'd7')
# Pointer argument registers (A[4]-A[7]):
_TC_PTR_ARG  = ('a4', 'a5', 'a6', 'a7')
# All argument registers:
_TC_ARG_REGS = _TC_INT_ARG + _TC_PTR_ARG
# Return value registers:
_TC_RET_REGS = ('d2', 'a2')
# Caller-saved (lower context) — clobbered by any call:
_TC_CALLER_SAVED: FrozenSet[str] = frozenset({
    'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7',
    'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a11',
    'd15', 'a15',  # implicit 16-bit operand regs; treat as caller-saved
})
# SP name as reported by Capstone:
_TC_SP = 'sp'

# Sources: functions whose return taints D[2] / A[2]
_SOURCE_NAMES: FrozenSet[str] = frozenset({
    'recv', 'recvfrom', 'recvmsg', 'read', 'fread',
    'fgets', 'gets', 'getchar', 'fgetc',
})
# Sinks: dangerous destination functions
_SINK_NAMES: FrozenSet[str] = frozenset({
    'system', 'execve', 'execl', 'execvp', 'execle', 'execvpe', 'popen',
    'strcpy', 'strcat', 'sprintf', 'vsprintf', 'snprintf', 'vsnprintf',
    'memcpy', 'memmove', 'gets',
})

# Call mnemonics (detect by mnemonic name — TriCore Capstone group IDs are unreliable)
_CALL_MNEMS: FrozenSet[str] = frozenset({'call', 'calla', 'calli', 'fcall'})
# Return mnemonics:
_RET_MNEMS:  FrozenSet[str] = frozenset({'ret', 'rfe', 'fret'})

# Bounds from zero-extending loads:
_LOAD_BOUNDS = {'ld.bu': 0xFF, 'ld.hu': 0xFFFF}

_PLT_TOL = 8  # bytes: PLT stub address tolerance for symbol lookup

# ALU mnemonic prefixes — kept at module level (not inside _is_alu) to avoid
# per-call tuple reconstruction on hot instruction-step paths.
_ALU_PREFIXES = (
    'add', 'sub', 'mul', 'madd', 'msub', 'div', 'mod',
    'and', 'or', 'xor', 'nor', 'andn',
    'sh', 'sha', 'shl', 'shr', 'sar',
    'extr', 'ins',
    'eq', 'ne', 'lt', 'ge', 'gt', 'le',
    'max', 'min', 'abs',
    'not', 'neg', 'nez', 'eqz',
    'cls', 'clz', 'clo', 'cnt',
    'cadd', 'csub', 'csel',
    'sat', 'round',
    'pack', 'unpack',
    'dv', 'dvadj', 'dvstep',
    'ixmax', 'ixmin',
    'sel',
)


# ---------------------------------------------------------------------------
# Taint type
# ---------------------------------------------------------------------------

Labels = FrozenSet[str]
EMPTY: Labels = frozenset()


@dataclass(frozen=True)
class Taint:
    labels: Labels = EMPTY
    bound: Optional[int] = None

    @property
    def tainted(self) -> bool:
        return bool(self.labels)

    def __str__(self) -> str:
        if not self.labels:
            return 'clean'
        s = '{' + ','.join(sorted(self.labels)) + '}'
        return s + (f'<={self.bound:#x}' if self.bound is not None else '')


CLEAN = Taint()


# ---------------------------------------------------------------------------
# Finding record
# ---------------------------------------------------------------------------

@dataclass
class TaintFindingTriCore:
    func_va:      int
    func_name:    str
    sink_va:      int
    sink_name:    str
    tainted_args: List[str]   # register names that were tainted at call site
    labels:       Labels
    severity:     str = 'HIGH'

    def __str__(self) -> str:
        args = ', '.join(self.tainted_args)
        lbl  = '{' + ','.join(sorted(self.labels)) + '}'
        return (
            f'[{self.severity}] 0x{self.func_va:x} ({self.func_name}): '
            f'tainted {{{args}}} {lbl} -> {self.sink_name} @ 0x{self.sink_va:x}'
        )


# ---------------------------------------------------------------------------
# Taint state
# ---------------------------------------------------------------------------

class _State:
    """Register and memory taint, plus a constant-value cache."""

    __slots__ = ('regs', 'mem', 'consts')

    def __init__(self) -> None:
        self.regs:   Dict[str, Taint]          = {}
        self.mem:    Dict[Tuple[str, int], Taint] = {}
        self.consts: Dict[str, int]             = {}

    # -- register access -----------------------------------------------------

    def get(self, name: Optional[str]) -> Taint:
        if not name:
            return CLEAN
        return self.regs.get(name, CLEAN)

    def set(self, name: Optional[str], t: Taint) -> None:
        if not name or name == _TC_SP:
            return
        if t.tainted or t.bound is not None:
            self.regs[name] = t
        else:
            self.regs.pop(name, None)
        self.consts.pop(name, None)

    def taint(self, name: str, label: str) -> None:
        cur = self.get(name)
        self.regs[name] = Taint(cur.labels | {label}, cur.bound)

    # -- memory access --------------------------------------------------------

    def mem_get(self, base: str, off: int) -> Taint:
        return self.mem.get((base, off), CLEAN)

    def mem_set(self, base: str, off: int, t: Taint) -> None:
        if t.tainted:
            self.mem[(base, off)] = t
        else:
            self.mem.pop((base, off), None)

    # -- call effects ---------------------------------------------------------

    def apply_call_effects(self, arg_regs=_TC_ARG_REGS, ret_regs=_TC_RET_REGS) -> None:
        """Clobber caller-saved registers; propagate arg taint to return regs."""
        arg_labels: Labels = EMPTY
        for r in arg_regs:
            arg_labels |= self.get(r).labels
        for r in _TC_CALLER_SAVED:
            self.regs.pop(r, None)
            self.consts.pop(r, None)
        if arg_labels:
            for r in ret_regs:
                self.regs[r] = Taint(arg_labels, None)

    # -- copy/join (for CFG merge) --------------------------------------------

    def copy(self) -> '_State':
        s = _State()
        s.regs   = dict(self.regs)
        s.mem    = dict(self.mem)
        s.consts = dict(self.consts)
        return s

    def join(self, other: '_State') -> '_State':
        out = _State()
        for r in set(self.regs) | set(other.regs):
            a, b = self.get(r), other.get(r)
            ab = None if (a.bound is None or b.bound is None) else max(a.bound, b.bound)
            t = Taint(a.labels | b.labels, ab)
            if t.tainted or t.bound is not None:
                out.regs[r] = t
        for k in set(self.mem) | set(other.mem):
            a, b = self.mem.get(k, CLEAN), other.mem.get(k, CLEAN)
            t = Taint(a.labels | b.labels, None)
            if t.tainted:
                out.mem[k] = t
        out.consts = {r: v for r, v in self.consts.items() if other.consts.get(r) == v}
        return out

    def same_as(self, other: '_State') -> bool:
        return (
            self.regs == other.regs
            and self.mem == other.mem
        )


# ---------------------------------------------------------------------------
# TriCore taint engine (single-function, Capstone-based)
# ---------------------------------------------------------------------------

class _Engine:
    """
    Intra-procedural taint engine for one TriCore function.

    Seed taint with ``seed(reg_name, label)`` before calling ``run()``.
    The ``findings`` list accumulates indirect-jump, tainted-store, and
    tainted-syscall findings.  Call-site effects are handled by the caller
    (TriCoreTaintTracker) so the engine can report on sink names.
    """

    def __init__(self, cs: 'capstone.Cs') -> None:
        self._cs = cs
        self.state    = _State()
        self.findings: List[TaintFindingTriCore] = []
        self._func_va:   int = 0
        self._func_name: str = 'unknown'

    def seed(self, reg: str, label: str) -> None:
        self.state.taint(reg, label)

    def init_func(self, va: int, name: str) -> None:
        self._func_va   = va
        self._func_name = name

    # -- step -----------------------------------------------------------------

    def step(self, insn: 'capstone.CsInsn') -> None:
        m = insn.mnemonic
        ops = insn.operands

        # Loads
        if m.startswith('ld.') or m in ('ld.w', 'ld.h', 'ld.b'):
            self._load(insn)
        # Stores
        elif m.startswith('st.'):
            self._store(insn)
        # Moves
        elif m in ('mov', 'mov.a', 'mov.d', 'mov.u'):
            self._mov(insn)
        elif m in ('movh', 'movh.a'):
            self._movh(insn)
        # Address arithmetic (LEA, ADD.A)
        elif m in ('lea', 'add.a', 'sub.a', 'addih.a'):
            self._addr_arith(insn)
        # ALU (generic)
        elif _is_alu(m):
            self._alu(insn)
        # Indirect jump (tainted jump-target detection)
        elif m == 'ji':
            self._indirect_jump(insn)
        # Calls / returns: handled by caller to access symbol table
        elif m in _CALL_MNEMS or m in _RET_MNEMS:
            pass  # caller handles these
        # NOP / branch (no state change for taken/not-taken; linear trace)
        else:
            # Conservative: propagate taint from any source regs to dest reg
            self._unknown(insn)

    # -- loads ----------------------------------------------------------------

    def _load(self, insn: 'capstone.CsInsn') -> None:
        ops = insn.operands
        if not ops:
            return
        if ops[0].type != _OP_REG:
            return
        dest = self._cs.reg_name(ops[0].reg)
        if len(ops) < 2:
            return

        src_op = ops[1]
        if src_op.type == _OP_MEM:
            base_id = src_op.mem.base
            base    = self._cs.reg_name(base_id) if base_id else None
            disp    = src_op.mem.disp
            # Tainted base register → load result is tainted (load from attacker address)
            bt = self.state.get(base)
            mem_t = self.state.mem_get(base or '__abs__', disp) if base else CLEAN
            labels = bt.labels | mem_t.labels
        elif src_op.type == _OP_REG:
            # Register-indexed load (rare — usually indirect through base)
            bt = self.state.get(self._cs.reg_name(src_op.reg))
            labels = bt.labels
        else:
            self.state.set(dest, CLEAN)
            return

        bound = _LOAD_BOUNDS.get(insn.mnemonic)
        self.state.set(dest, Taint(labels, bound))

    # -- stores ---------------------------------------------------------------

    def _store(self, insn: 'capstone.CsInsn') -> None:
        ops = insn.operands
        if len(ops) < 2:
            return
        mem_op  = ops[0] if ops[0].type == _OP_MEM else None
        reg_op  = next((o for o in ops if o.type == _OP_REG), None)
        if mem_op is None or reg_op is None:
            return

        base_id = mem_op.mem.base
        base    = self._cs.reg_name(base_id) if base_id else '__abs__'
        disp    = mem_op.mem.disp

        # Tainted address check
        bt = self.state.get(base)
        if bt.tainted and bt.bound is None:
            self.findings.append(TaintFindingTriCore(
                func_va=self._func_va, func_name=self._func_name,
                sink_va=insn.address, sink_name=f'{insn.mnemonic}[tainted-addr]',
                tainted_args=[base], labels=bt.labels, severity='HIGH',
            ))

        src = self._cs.reg_name(reg_op.reg)
        self.state.mem_set(base, disp, self.state.get(src))

    # -- moves ----------------------------------------------------------------

    def _mov(self, insn: 'capstone.CsInsn') -> None:
        ops = insn.operands
        if not ops or ops[0].type != _OP_REG:
            return
        dest = self._cs.reg_name(ops[0].reg)
        if len(ops) < 2:
            self.state.set(dest, CLEAN)
            return
        src_op = ops[1]
        if src_op.type == _OP_REG:
            src = self._cs.reg_name(src_op.reg)
            self.state.set(dest, self.state.get(src))
            if src in self.state.consts:
                self.state.consts[dest] = self.state.consts[src]
        else:
            self.state.set(dest, CLEAN)
            if src_op.type == _OP_IMM:
                self.state.consts[dest] = src_op.imm & 0xFFFFFFFF

    def _movh(self, insn: 'capstone.CsInsn') -> None:
        """MOVH/MOVH.A: load constant into high 16 bits (clears low 16)."""
        ops = insn.operands
        if not ops or ops[0].type != _OP_REG:
            return
        dest = self._cs.reg_name(ops[0].reg)
        # MOVH sets an immediate — always clean
        self.state.set(dest, CLEAN)
        if len(ops) >= 2 and ops[1].type == _OP_IMM:
            self.state.consts[dest] = (ops[1].imm & 0xFFFF) << 16

    # -- address arithmetic ---------------------------------------------------

    def _addr_arith(self, insn: 'capstone.CsInsn') -> None:
        """LEA, ADD.A, SUB.A, ADDIH.A: address register arithmetic."""
        ops = insn.operands
        if not ops or ops[0].type != _OP_REG:
            return
        dest = self._cs.reg_name(ops[0].reg)
        labels: Labels = EMPTY
        for op in ops[1:]:
            if op.type == _OP_REG:
                labels |= self.state.get(self._cs.reg_name(op.reg)).labels
            elif op.type == _OP_MEM and op.mem.base:
                # LEA Aa, [Ab]disp: base register Ab is the address source
                labels |= self.state.get(self._cs.reg_name(op.mem.base)).labels
        self.state.set(dest, Taint(labels, None))

    # -- ALU ------------------------------------------------------------------

    def _alu(self, insn: 'capstone.CsInsn') -> None:
        ops = insn.operands
        if not ops or ops[0].type != _OP_REG:
            return
        dest    = self._cs.reg_name(ops[0].reg)
        reg_ops = [o for o in ops if o.type == _OP_REG]
        imm_ops = [o for o in ops if o.type == _OP_IMM]

        # Determine source registers:
        # 2-reg: ops=[dest/src1, src2]  → dest is also a source (in-place)
        # 3-reg: ops=[dest, src1, src2] → dest is pure destination
        in_place = (len(reg_ops) == 2)
        if in_place:
            srcs = [self._cs.reg_name(o.reg) for o in reg_ops]  # both are sources
        else:
            srcs = [self._cs.reg_name(o.reg) for o in reg_ops[1:]]

        labels: Labels = EMPTY
        for s in srcs:
            labels |= self.state.get(s).labels

        bound: Optional[int] = None
        m = insn.mnemonic
        if m in ('and', 'andn') and len(reg_ops) >= 2:
            bs = [self.state.get(self._cs.reg_name(o.reg)).bound
                  for o in reg_ops[1:] if self.state.get(self._cs.reg_name(o.reg)).bound is not None]
            bound = min(bs) if bs else None
        elif m == 'and' and imm_ops:
            # ANDI-style: immediate mask → bounds
            bound = imm_ops[0].imm & 0xFFFF
            src0 = self.state.get(self._cs.reg_name(reg_ops[1].reg)) if len(reg_ops) > 1 else CLEAN
            if src0.bound is not None:
                bound = min(bound, src0.bound)
        elif m == 'extr.u' and imm_ops:
            # EXTR.U Da, Db, pos, width: zero-extends to width bits
            if len(imm_ops) >= 2:
                width = imm_ops[1].imm
                bound = (1 << width) - 1
            elif imm_ops:
                bound = (1 << imm_ops[0].imm) - 1

        self.state.set(dest, Taint(labels, bound))

    # -- indirect jump --------------------------------------------------------

    def _indirect_jump(self, insn: 'capstone.CsInsn') -> None:
        """JI Aa: indirect jump through address register."""
        ops = insn.operands
        if not ops or ops[0].type != _OP_REG:
            return
        reg  = self._cs.reg_name(ops[0].reg)
        t    = self.state.get(reg)
        if t.tainted:
            self.findings.append(TaintFindingTriCore(
                func_va=self._func_va, func_name=self._func_name,
                sink_va=insn.address, sink_name='ji[tainted-target]',
                tainted_args=[reg], labels=t.labels, severity='CRITICAL',
            ))

    # -- unknown fallback -----------------------------------------------------

    def _unknown(self, insn: 'capstone.CsInsn') -> None:
        """Conservative: propagate taint from any source regs to dest reg."""
        ops = insn.operands
        if not ops or ops[0].type != _OP_REG:
            return
        dest   = self._cs.reg_name(ops[0].reg)
        labels: Labels = EMPTY
        for op in ops[1:]:
            if op.type == _OP_REG:
                labels |= self.state.get(self._cs.reg_name(op.reg)).labels
        if labels:
            self.state.set(dest, Taint(labels, None))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_alu(m: str) -> bool:
    """True if mnemonic is an ALU operation (not load/store/branch/call/nop)."""
    for p in _ALU_PREFIXES:
        if m == p or m.startswith(p + '.') or m.startswith(p + 'i') or m.startswith(p + 's'):
            return True
    return False


def _sym_at(symbols: Dict[int, str], va: int, tol: int = _PLT_TOL) -> Optional[str]:
    for off in range(0, tol + 1, 2):
        if va + off in symbols: return symbols[va + off]
        if va - off in symbols: return symbols[va - off]
    return None


def _load_elf(path: str) -> Tuple:
    """Return (data, base_va, text_start, text_end, symbols)."""
    data = Path(path).read_bytes()

    if _HAS_LIEF:
        elf = _lief.parse(path)
        if elf is None:
            raise ValueError(f'lief: cannot parse {path}')
        text = elf.get_section('.text')
        if text:
            text_start = text.virtual_address
            text_end   = text_start + text.size
            base_va    = text.virtual_address - text.offset
        else:
            base_va = text_start = 0
            text_end = len(data)
        syms: Dict[int, str] = {}
        for sym in elf.symbols:
            if sym.name and sym.value:
                syms[sym.value] = sym.name
        return data, base_va, text_start, text_end, syms

    if _HAS_PYELF:
        with open(path, 'rb') as _f:
            ef = ELFFile(_f)
            text_sh = ef.get_section_by_name('.text')
            if text_sh:
                text_start = text_sh['sh_addr']
                text_end   = text_start + text_sh['sh_size']
                base_va    = text_sh['sh_addr'] - text_sh['sh_offset']
            else:
                base_va = text_start = text_end = 0
                text_end = len(data)
            syms: Dict[int, str] = {}
            for sec in ef.iter_sections():
                if sec.name in ('.symtab', '.dynsym'):
                    for sym in sec.iter_symbols():
                        if sym.name and sym['st_value']:
                            syms[sym['st_value']] = sym.name
        return data, base_va, text_start, text_end, syms

    raise ImportError('lief or pyelftools required for ELF parsing')


# ---------------------------------------------------------------------------
# Public tracker class
# ---------------------------------------------------------------------------

class TriCoreTaintTracker:
    """
    Source-to-sink taint tracker for TriCore AURIX binaries.

    Supports both ELF and flat ROM dumps.  Intra-procedural by default;
    ``run_interprocedural()`` follows tainted arguments into callees (depth-limited).

    Flat binary example (ECU ROM)::

        tracker = TriCoreTaintTracker.from_bytes(data, base_va=0x80000000)
        # scan_function: caller provides function boundaries
        findings = tracker.scan_function(0x80012000, 0x80012200,
                                         init_labels={'sa_seed'})

    ELF example::

        tracker = TriCoreTaintTracker.from_path('fw.elf')
        findings = tracker.run()        # intraprocedural
    """

    def __init__(
        self,
        data: bytes,
        base_va: int,
        text_start: int,
        text_end: int,
        symbols: Dict[int, str],
        tc_mode: int = 0,           # 0 = CS_MODE_TRICORE_162 (default for AURIX)
    ) -> None:
        if not _HAS_CAPSTONE:
            raise ImportError('capstone is required for TriCoreTaintTracker')
        self._data       = data
        self._base_va    = base_va
        self._text_start = text_start
        self._text_end   = text_end
        self._syms       = symbols
        self._tc_mode    = tc_mode if tc_mode else _CS_MODE_TC162
        self._cs         = capstone.Cs(_CS_ARCH_TRICORE, self._tc_mode)
        self._cs.detail  = True

    # -- constructors ---------------------------------------------------------

    @classmethod
    def from_path(cls, path: str, tc_mode: int = 0) -> 'TriCoreTaintTracker':
        """Create from ELF file; requires lief or pyelftools."""
        data, base_va, text_start, text_end, syms = _load_elf(path)
        return cls(data, base_va, text_start, text_end, syms, tc_mode)

    @classmethod
    def from_bytes(cls, data: bytes, base_va: int = 0x80000000,
                   tc_mode: int = 0) -> 'TriCoreTaintTracker':
        """Create from flat ROM bytes.  Caller must supply function boundaries."""
        return cls(data, base_va, base_va, base_va + len(data), {}, tc_mode)

    # -- public APIs ----------------------------------------------------------

    def scan_function(
        self,
        func_va:   int,
        func_end:  int,
        init_labels: Optional[Set[str]] = None,
        func_name:   Optional[str] = None,
    ) -> List[TaintFindingTriCore]:
        """
        Scan a single function for taint flow from seeded arg registers to sinks.

        ``init_labels`` seeds taint into D[4]-D[7] and A[4]-A[7] at function entry.
        Returns findings for this function only; does not follow calls.
        """
        name     = func_name or self._syms.get(func_va, f'fn_0x{func_va:x}')
        eng      = _Engine(self._cs)
        eng.init_func(func_va, name)

        if init_labels:
            for lbl in init_labels:
                for r in _TC_ARG_REGS:
                    eng.seed(r, lbl)

        self._run_engine(eng, func_va, func_end)
        return eng.findings

    def run(self) -> List[TaintFindingTriCore]:
        """Intra-procedural scan of all functions derived from symbols."""
        starts   = self._func_starts()
        findings: List[TaintFindingTriCore] = []
        for i, fva in enumerate(starts):
            fend = starts[i + 1] if i + 1 < len(starts) else self._text_end
            findings.extend(self._scan_func(fva, fend))
        return findings

    def run_interprocedural(self, depth: int = 3) -> List[TaintFindingTriCore]:
        """
        BFS interprocedural scan.  Follows tainted D[4]-D[7] / A[4]-A[7] into callees.
        ``depth`` controls maximum call-chain depth; default 3.
        """
        starts   = self._func_starts()
        func_end: Dict[int, int] = {
            fva: (starts[i + 1] if i + 1 < len(starts) else self._text_end)
            for i, fva in enumerate(starts)
        }
        findings: List[TaintFindingTriCore] = []
        # seed: every function independently, no initial labels
        queue: Deque[Tuple[int, int, Set[str]]] = deque(
            (fva, depth, set()) for fva in starts
        )
        visited: Dict[Tuple, int] = {}

        while queue:
            fva, d, lbs = queue.popleft()
            key = (fva,) + tuple(sorted(lbs))
            if visited.get(key, -1) >= d:
                continue
            visited[key] = d
            fend = func_end.get(fva, self._text_end)
            name = self._syms.get(fva, f'fn_0x{fva:x}')

            eng = _Engine(self._cs)
            eng.init_func(fva, name)
            for lbl in lbs:
                for r in _TC_ARG_REGS:
                    eng.seed(r, lbl)

            self._run_engine_ip(eng, fva, fend, func_end, queue, d)
            findings.extend(eng.findings)

        return _dedup(findings)

    def report(self, findings: List[TaintFindingTriCore]) -> str:
        if not findings:
            return 'TriCore taint: no findings.'
        lines = [f'TriCore taint: {len(findings)} finding(s)\n']
        for f in sorted(findings, key=lambda x: (x.func_va, x.sink_va)):
            lines.append(str(f))
        return '\n'.join(lines)

    # -- internal helpers -----------------------------------------------------

    def _func_starts(self) -> List[int]:
        starts: Set[int] = set()
        for va, name in self._syms.items():
            if self._text_start <= va < self._text_end:
                starts.add(va)
        if not starts:
            starts.add(self._text_start)
        return sorted(starts)

    def _offset(self, va: int) -> int:
        return va - self._base_va

    def _disasm(self, va: int, end_va: int):
        off = self._offset(va)
        end_off = self._offset(end_va)
        if off < 0 or end_off > len(self._data) or off >= end_off:
            return
        code = self._data[off:end_off]
        yield from self._cs.disasm(code, va)

    def _scan_func(self, func_va: int, func_end: int) -> List[TaintFindingTriCore]:
        """Intraprocedural scan seeded by source functions."""
        name = self._syms.get(func_va, f'fn_0x{func_va:x}')
        eng  = _Engine(self._cs)
        eng.init_func(func_va, name)
        self._run_engine(eng, func_va, func_end)
        return eng.findings

    def _run_engine(self, eng: _Engine, func_va: int, func_end: int) -> None:
        """Step the engine through all instructions in [func_va, func_end).
        Mirror changes to _run_engine_ip — call-site logic must stay in sync."""
        for insn in self._disasm(func_va, func_end):
            m = insn.mnemonic

            if m in _RET_MNEMS:
                break

            if m in _CALL_MNEMS:
                # Resolve call target
                target = _call_target(insn)
                callee = _sym_at(self._syms, target) if target else None
                st = eng.state

                if callee in _SOURCE_NAMES:
                    st.apply_call_effects()
                    for r in _TC_RET_REGS:
                        st.regs[r] = Taint(frozenset({callee}), None)

                elif callee in _SINK_NAMES:
                    tainted = [r for r in _TC_ARG_REGS if st.get(r).tainted]
                    if tainted:
                        labels = frozenset().union(*(st.get(r).labels for r in tainted))
                        sev = 'CRITICAL' if callee in (
                            'system', 'execve', 'execl', 'execvp', 'popen') else 'HIGH'
                        eng.findings.append(TaintFindingTriCore(
                            func_va=eng._func_va, func_name=eng._func_name,
                            sink_va=insn.address, sink_name=callee,
                            tainted_args=tainted, labels=labels, severity=sev,
                        ))
                    st.apply_call_effects()
                else:
                    st.apply_call_effects()
            else:
                eng.step(insn)

    def _run_engine_ip(
        self,
        eng: _Engine,
        func_va: int,
        func_end: int,
        func_end_map: Dict[int, int],
        queue: Deque,
        depth: int,
    ) -> None:
        """Interprocedural variant: also enqueues callees with tainted args.
        Mirror changes to _run_engine — call-site logic must stay in sync."""
        for insn in self._disasm(func_va, func_end):
            m = insn.mnemonic

            if m in _RET_MNEMS:
                break

            if m in _CALL_MNEMS:
                target = _call_target(insn)
                callee = _sym_at(self._syms, target) if target else None
                st = eng.state

                if callee in _SOURCE_NAMES:
                    st.apply_call_effects()
                    for r in _TC_RET_REGS:
                        st.regs[r] = Taint(frozenset({callee}), None)

                elif callee in _SINK_NAMES:
                    tainted = [r for r in _TC_ARG_REGS if st.get(r).tainted]
                    if tainted:
                        labels = frozenset().union(*(st.get(r).labels for r in tainted))
                        sev = 'CRITICAL' if callee in (
                            'system', 'execve', 'execl', 'execvp', 'popen') else 'HIGH'
                        eng.findings.append(TaintFindingTriCore(
                            func_va=eng._func_va, func_name=eng._func_name,
                            sink_va=insn.address, sink_name=callee,
                            tainted_args=tainted, labels=labels, severity=sev,
                        ))
                    st.apply_call_effects()

                else:
                    # Follow tainted args into callee
                    if depth > 0 and target is not None:
                        tainted_into = [r for r in _TC_ARG_REGS if st.get(r).tainted]
                        if tainted_into:
                            lbs = set().union(*(st.get(r).labels for r in tainted_into))
                            c_va = target
                            # Snap to nearest known function start
                            for off in range(0, _PLT_TOL + 1, 2):
                                if c_va + off in func_end_map:
                                    c_va += off; break
                                if c_va - off in func_end_map and c_va - off >= 0:
                                    c_va -= off; break
                            if c_va in func_end_map:
                                queue.append((c_va, depth - 1, lbs))
                    st.apply_call_effects()
            else:
                eng.step(insn)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call_target(insn: 'capstone.CsInsn') -> Optional[int]:
    """Extract absolute call target VA from a CALL/FCALL instruction."""
    for op in insn.operands:
        if op.type == _OP_IMM:
            return op.imm & 0xFFFFFFFF
    return None


def _dedup(findings: List[TaintFindingTriCore]) -> List[TaintFindingTriCore]:
    seen: Set[Tuple] = set()
    out: List[TaintFindingTriCore] = []
    for f in findings:
        k = (f.func_va, f.sink_va, f.sink_name)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
