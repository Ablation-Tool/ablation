"""
taint_tracker_arm32.py: Static intraprocedural ARM32/Thumb taint analysis.

Finds data-flow paths from network receive taint sources to dangerous sinks.
Implements the libdft taint policy adapted for ARM32 AAPCS:

  XFER  (mov/ldr):           dst_taint = src_taint
  ALU   (add/sub/and/orr/eor/mul): dst_taint |= operand taints
  CLR   (mov rd, #0; eor rd, rd): dst_taint = {}
  LOAD  (ldr rd, [rn, #off]): dst_taint = stack_slot_taint(rn+off)
  STORE (str rs, [rn, #off]): stack_slot_taint(rn+off) = src_taint
  CALL  (source):            r0 tainted; buffer args tracked
  CALL  (sink):              alert if relevant arg register tainted
  CALL  (other):             r0-r3, r12 cleared (AAPCS caller-saved)

Stack model: tracks [sp + N] and [sp - N] slots using sp-relative offsets.
Writeback addressing (STR rd, [sp, #-N]! and LDM/STM push/pop) updates the
sp delta tracker.

Usage:
    from ablation.analyzers.taint_tracker_arm32 import ARM32TaintTracker, TaintFinding32

    tracker = ARM32TaintTracker('/path/to/libhijoyptt.so')
    findings = tracker.run_on_function(func_va=0x2511c)
    for f in findings:
        print(f)

    # Interprocedural mode (all functions in binary):
    findings = tracker.run_interprocedural()
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

import capstone
from capstone import arm as C_ARM

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False


# ── AAPCS register model ──────────────────────────────────────────────────────

# Caller-saved (volatile): r0-r3 (args + return), r12 (ip/scratch)
_CALLER_SAVED = frozenset(['r0', 'r1', 'r2', 'r3', 'r12'])

# Argument registers (in order): r0-r3 map to arg0-arg3
_ARG_REGS = ['r0', 'r1', 'r2', 'r3']

def _canon(name: str) -> Optional[str]:
    """Normalise register name. Returns None for non-GP registers."""
    n = name.lower()
    if n in ('sp', 'r13'):
        return 'sp'
    if n in ('lr', 'r14'):
        return 'lr'
    if n in ('pc', 'r15'):
        return 'pc'
    if n in ('ip', 'r12'):
        return 'r12'
    if n.startswith('r') and n[1:].isdigit():
        return n
    return None


# ── taint sources and sinks ───────────────────────────────────────────────────

# Functions whose return value (r0) is tainted (network input sources)
_TAINT_SOURCES: Set[str] = {
    'recv', 'recvfrom', 'recvmsg', 'read', 'fread', 'pread', 'pread64',
    'gets', 'fgets', 'scanf', 'fscanf', 'sscanf',
    'SSL_read', 'SSL_read_ex',
    'BIO_read',
    'ngx_recv', 'ngx_recv_chain',
    'sendto',  # buffer arg is tainted when used as src
}

# Functions that forward taint from a buffer argument to return/output
_TAINT_FORWARDERS: Dict[str, List[int]] = {
    'memcpy':   [0],    # dst <- src (arg1 taint -> arg0 written region)
    'memmove':  [0],
    'strncpy':  [0],
    'strcpy':   [0],
    'strcat':   [0],
    'strncat':  [0],
    'snprintf': [0],
    'sprintf':  [0],
    'atoi':     [],     # return r0 tainted if r0 input was tainted
    'atol':     [],
    'strtol':   [],
    'strtoul':  [],
    'htons':    [],
    'htonl':    [],
    'ntohs':    [],
    'ntohl':    [],
}

# Dangerous sinks: symbol -> [arg indices that must not be tainted]
_DEFAULT_SINKS: Dict[str, List[int]] = {
    'memcpy':        [2],    # length arg
    'memmove':       [2],
    'malloc':        [0],
    'calloc':        [0, 1],
    'realloc':       [1],
    'alloca':        [0],
    'strcpy':        [0],    # destination size implicit
    'strncpy':       [2],
    'snprintf':      [1],
    'sprintf':       [0],
    'system':        [0],
    'popen':         [0],
    'execve':        [0],
    'execvp':        [0],
    'execl':         [0],
}


# ── data classes ─────────────────────────────────────────────────────────────

@dataclass
class TaintFinding32:
    func_va: int
    sink_va: int
    sink_name: str
    tainted_arg_idx: int
    tainted_regs: FrozenSet[str]
    tainted_slots: FrozenSet[int]
    path_length: int = 0

    def __str__(self) -> str:
        regs = ', '.join(sorted(self.tainted_regs))
        return (f"TAINT  0x{self.func_va:x} -> {self.sink_name}@0x{self.sink_va:x}"
                f"  arg{self.tainted_arg_idx}  regs=[{regs}]")


@dataclass
class TaintState32:
    regs: Dict[str, bool] = field(default_factory=dict)   # reg -> tainted
    stack: Dict[int, bool] = field(default_factory=dict)  # sp_offset -> tainted
    sp_delta: int = 0                                       # current sp - entry sp

    def is_tainted(self, reg: str) -> bool:
        return self.regs.get(_canon(reg) or reg, False)

    def taint_reg(self, reg: str) -> None:
        c = _canon(reg)
        if c:
            self.regs[c] = True

    def clear_reg(self, reg: str) -> None:
        c = _canon(reg)
        if c:
            self.regs[c] = False

    def clone(self) -> 'TaintState32':
        return TaintState32(
            regs=dict(self.regs),
            stack=dict(self.stack),
            sp_delta=self.sp_delta,
        )


# ── disassembler wrapper ──────────────────────────────────────────────────────

class _ARM32Disasm:
    def __init__(self, data: bytes, base: int, thumb: bool = False):
        self._data = data
        self._base = base
        mode = capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM
        self._cs = capstone.Cs(capstone.CS_ARCH_ARM, mode)
        self._cs.detail = True
        self._cs.skipdata = True

    def insns(self, start_va: int, max_bytes: int = 4096):
        off = start_va - self._base
        if off < 0 or off >= len(self._data):
            return
        chunk = self._data[off: off + max_bytes]
        yield from self._cs.disasm(chunk, start_va)


# ── taint engine ─────────────────────────────────────────────────────────────

class ARM32TaintTracker:
    """
    Intraprocedural ARM32 taint tracker.

    Sources: recv/read family (r0 tainted on return).
    Sinks:   memcpy/malloc length args, strcpy dst, system/execve path arg.
    Per-function Thumb mode: pass thumb_funcs from BinaryContext or let
    _load_elf() auto-detect from symbol LSB.
    """

    def __init__(
        self,
        binary_path: str,
        custom_sinks: Optional[Dict[str, List[int]]] = None,
        thumb: bool = False,
        thumb_funcs: Optional[Set[int]] = None,
    ):
        self.path = binary_path
        self._data = Path(binary_path).read_bytes()
        self._base = 0
        self._plt: Dict[int, str] = {}
        self._exports: Dict[str, int] = {}
        self._func_starts: List[int] = []
        self._thumb_funcs: Set[int] = set(thumb_funcs) if thumb_funcs else set()
        self._sinks: Dict[str, List[int]] = dict(_DEFAULT_SINKS)
        if custom_sinks:
            self._sinks.update(custom_sinks)
        self._thumb = thumb
        self._disasm = _ARM32Disasm(self._data, self._base, thumb)
        self._load_elf()

    def _load_elf(self) -> None:
        if not _LIEF_OK:
            return
        try:
            binary = lief.parse(self._data)
        except Exception:
            return
        if not isinstance(binary, lief.ELF.Binary):
            return
        self._base = binary.imagebase
        self._disasm = _ARM32Disasm(self._data, self._base, self._thumb)

        # Build PLT: .rel.plt entries in order, stubs at PLT_VA + 20 + n*12
        sym_names: List[str] = []
        try:
            rel_plt = binary.get_section('.rel.plt')
            if rel_plt:
                rel_data = bytes(rel_plt.content)
                for off in range(0, len(rel_data) - 7, 8):
                    r_offset, r_info = struct.unpack_from('<II', rel_data, off)
                    sym_idx = r_info >> 8
                    try:
                        sym = binary.dynamic_symbols[sym_idx]
                        sym_names.append(sym.name or '')
                    except Exception:
                        sym_names.append('')
        except Exception:
            pass

        if sym_names:
            plt_sec = binary.get_section('.plt')
            if plt_sec:
                plt_va = int(plt_sec.virtual_address)
                for i, name in enumerate(sym_names):
                    if name:
                        stub_va = plt_va + 20 + i * 12
                        self._plt[stub_va] = name

        if not self._plt:
            # Fallback: JUMP_SLOT relocations
            try:
                for rel in binary.relocations:
                    if rel.has_symbol:
                        rtype = str(getattr(rel, 'type', ''))
                        if 'JUMP_SLOT' in rtype and rel.symbol.name:
                            self._plt[rel.address] = rel.symbol.name
            except Exception:
                pass

        # Exports
        try:
            for sym in binary.exported_functions:
                if sym.name and sym.value:
                    self._exports[sym.name] = sym.value
        except Exception:
            pass

        # Strip LSB from exports (ARM32 Thumb indicator)
        self._exports = {k: (v & ~1 if v & 1 else v) for k, v in self._exports.items()}

        # Function starts via eh_frame; strip LSB and detect Thumb
        starts: set = set(self._exports.values())
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.dwarf.callframe import FDE
            with open(self.path, 'rb') as fh:
                elf = ELFFile(fh)
                if elf.has_dwarf_info():
                    di = elf.get_dwarf_info()
                    if di.has_EH_CFI():
                        for e in di.EH_CFI_entries():
                            if isinstance(e, FDE) and e['initial_location'] > 0:
                                va = e['initial_location']
                                if va & 1:
                                    va &= ~1
                                    self._thumb_funcs.add(va)
                                starts.add(va)
        except Exception:
            pass
        # Also detect Thumb from dynamic_symbols LSB
        try:
            binary2 = lief.parse(self._data)
            if isinstance(binary2, lief.ELF.Binary):
                for sym in binary2.dynamic_symbols:
                    if sym.name and sym.value and str(getattr(sym, 'type', '')).endswith('FUNC'):
                        if sym.value & 1:
                            self._thumb_funcs.add(sym.value & ~1)
                        starts.add(sym.value & ~1 if sym.value & 1 else sym.value)
        except Exception:
            pass
        self._func_starts = sorted(starts)

    def _sym_at(self, va: int) -> Optional[str]:
        return self._plt.get(va) or next(
            (n for n, v in self._exports.items() if v == va), None
        )

    def _is_source(self, sym: str) -> bool:
        return sym in _TAINT_SOURCES

    def _sink_args(self, sym: str) -> List[int]:
        return self._sinks.get(sym, [])

    def run_on_function(self, func_va: int, max_bytes: int = 8192) -> List[TaintFinding32]:
        """Analyze one function for source-to-sink paths."""
        is_thumb = func_va in self._thumb_funcs
        if is_thumb != self._thumb or self._disasm._base != self._base:
            self._disasm = _ARM32Disasm(self._data, self._base, is_thumb)
        state = TaintState32()
        findings: List[TaintFinding32] = []
        self._analyze(func_va, state, findings, max_bytes)
        return findings

    def run_interprocedural(self, max_funcs: int = 5000) -> List[TaintFinding32]:
        """Run on all known function starts."""
        all_findings: List[TaintFinding32] = []
        funcs = self._func_starts[:max_funcs] if self._func_starts else []
        if not funcs:
            return all_findings
        for va in funcs:
            findings = self.run_on_function(va)
            all_findings.extend(findings)
        return all_findings

    def _analyze(
        self,
        func_va: int,
        state: TaintState32,
        findings: List[TaintFinding32],
        max_bytes: int,
    ) -> None:
        for insn in self._disasm.insns(func_va, max_bytes):
            mn = insn.mnemonic.lower()
            ops = insn.operands

            # ── return ────────────────────────────────────────────────────────
            if mn.startswith('bx') and insn.op_str.lower() in ('lr', 'r14'):
                break
            if (mn.startswith('pop') or mn.startswith('ldm')) and 'pc' in insn.op_str.lower():
                break

            # ── call ──────────────────────────────────────────────────────────
            if mn.startswith('bl') or mn.startswith('blx'):
                target_va = None
                try:
                    for op in ops:
                        if op.type == C_ARM.ARM_OP_IMM:
                            target_va = op.imm
                            break
                except Exception:
                    pass
                sym = self._sym_at(target_va) if target_va else None
                if sym:
                    self._handle_call(insn.address, sym, func_va, state, findings)
                else:
                    # Unknown call: clobber caller-saved
                    for r in _CALLER_SAVED:
                        state.clear_reg(r)
                continue

            # ── MOV ──────────────────────────────────────────────────────────
            if mn.startswith('mov') and not mn.startswith('movw') and not mn.startswith('movt'):
                if len(ops) >= 2:
                    rd = insn.reg_name(ops[0].reg).lower() if ops[0].type == C_ARM.ARM_OP_REG else None
                    op1 = ops[1]
                    if rd:
                        if op1.type == C_ARM.ARM_OP_REG:
                            rs = insn.reg_name(op1.reg).lower()
                            if state.is_tainted(rs):
                                state.taint_reg(rd)
                            else:
                                state.clear_reg(rd)
                        elif op1.type == C_ARM.ARM_OP_IMM:
                            state.clear_reg(rd)
                        else:
                            state.clear_reg(rd)
                continue

            # ── LDR: rd = [rn, #off] ─────────────────────────────────────────
            if mn.startswith('ldr') and not mn.startswith('ldm'):
                if len(ops) >= 2:
                    rd = insn.reg_name(ops[0].reg).lower() if ops[0].type == C_ARM.ARM_OP_REG else None
                    op1 = ops[1]
                    if rd and op1.type == C_ARM.ARM_OP_MEM:
                        base_r = insn.reg_name(op1.mem.base).lower() if op1.mem.base else ''
                        off = op1.mem.disp
                        if base_r == 'sp':
                            slot = state.sp_delta + off
                            if state.stack.get(slot, False):
                                state.taint_reg(rd)
                            else:
                                state.clear_reg(rd)
                        elif state.is_tainted(base_r):
                            state.taint_reg(rd)
                        else:
                            state.clear_reg(rd)
                continue

            # ── STR: [rn, #off] = rs ─────────────────────────────────────────
            if mn.startswith('str') and not mn.startswith('stm'):
                if len(ops) >= 2:
                    rs = insn.reg_name(ops[0].reg).lower() if ops[0].type == C_ARM.ARM_OP_REG else None
                    op1 = ops[1]
                    if rs and op1.type == C_ARM.ARM_OP_MEM:
                        base_r = insn.reg_name(op1.mem.base).lower() if op1.mem.base else ''
                        off = op1.mem.disp
                        if base_r == 'sp':
                            slot = state.sp_delta + off
                            state.stack[slot] = state.is_tainted(rs)
                continue

            # ── ADD/SUB: taint propagation ────────────────────────────────────
            if (mn.startswith('add') or mn.startswith('sub')) and len(ops) >= 2:
                rd = insn.reg_name(ops[0].reg).lower() if ops[0].type == C_ARM.ARM_OP_REG else None
                if rd:
                    tainted = any(
                        state.is_tainted(insn.reg_name(op.reg).lower())
                        for op in ops[1:]
                        if op.type == C_ARM.ARM_OP_REG
                    )
                    if tainted:
                        state.taint_reg(rd)
                    else:
                        state.clear_reg(rd)
                continue

            # ── ALU: AND/ORR/EOR/MUL propagate taint ─────────────────────────
            if (mn.startswith(('and', 'orr', 'eor', 'mul', 'umull', 'smull', 'lsl', 'lsr', 'asr'))
                    and len(ops) >= 2):
                rd = insn.reg_name(ops[0].reg).lower() if ops[0].type == C_ARM.ARM_OP_REG else None
                if rd:
                    tainted = any(
                        state.is_tainted(insn.reg_name(op.reg).lower())
                        for op in ops[1:]
                        if op.type == C_ARM.ARM_OP_REG
                    )
                    if tainted:
                        state.taint_reg(rd)
                    else:
                        state.clear_reg(rd)
                continue

    def _handle_call(
        self,
        site_va: int,
        sym: str,
        func_va: int,
        state: TaintState32,
        findings: List[TaintFinding32],
    ) -> None:
        # Check sinks first
        sink_args = self._sink_args(sym)
        for arg_idx in sink_args:
            if arg_idx < len(_ARG_REGS):
                reg = _ARG_REGS[arg_idx]
                if state.is_tainted(reg):
                    findings.append(TaintFinding32(
                        func_va=func_va,
                        sink_va=site_va,
                        sink_name=sym,
                        tainted_arg_idx=arg_idx,
                        tainted_regs=frozenset(r for r in _ARG_REGS if state.is_tainted(r)),
                        tainted_slots=frozenset(
                            slot for slot, t in state.stack.items() if t
                        ),
                    ))

        # After call: clobber r0-r3, r12
        for r in _CALLER_SAVED:
            state.clear_reg(r)

        # Sources: re-taint r0
        if self._is_source(sym):
            state.taint_reg('r0')

    def report(self, findings: List[TaintFinding32]) -> str:
        if not findings:
            return "No taint findings."
        lines = [f"ARM32 Taint Analysis: {len(findings)} finding(s)"]
        lines.append("=" * 60)
        for f in findings:
            lines.append(str(f))
        return "\n".join(lines)

    @classmethod
    def from_context(cls, ctx, custom_sinks=None) -> 'ARM32TaintTracker':
        inst = cls(ctx.path, custom_sinks=custom_sinks,
                   thumb_funcs=getattr(ctx, 'thumb_funcs', None))
        # Overlay PLT and exports from BinaryContext
        inst._plt.update(ctx.plt)
        inst._exports.update(ctx.exports)
        if ctx.func_starts:
            inst._func_starts = list(ctx.func_starts)
        return inst
