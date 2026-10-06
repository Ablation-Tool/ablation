"""
sink_arg_classifier.py: classify the provenance of command-string arguments at
arbitrary exec-class sink call sites in x86-64 ELF binaries.

The question at every shell-invoking sink (system/popen/fadcsystem/execve) is:
  "Where did this command string come from?"

Four primary verdicts:
  RODATA_CONST       — LEA from .rodata: hardcoded literal. No injection possible.
  SNPRINTF_RODATA    — snprintf(buf, n, <rodata_fmt>, ...) → buf passed to sink.
                       Format is fixed. Injection requires control over a %s arg.
  ARG_PROPAGATED     — arrived from an entry-argument register. Caller controls it.
  UNKNOWN            — provenance not resolved within look-back window.

Gap this fills vs. FormatStringScanner:
  • Works on any PLT sink + argument position, not just printf-family.
  • Handles __snprintf_chk(dest, n, flag, objsize, fmt, ...) calling convention
    where fmt = r8 (not rdx as in plain snprintf).
  • One level of snprintf recursion: if the command arg is a stack buffer filled
    by a preceding snprintf, classifies *that* snprintf's format argument instead.
    This resolves the majority of MEDIUM findings that would otherwise require
    manual trace (e.g., fadcsystem(cmd) where cmd = snprintf-built buffer with
    '/var/log/%s' format → SNPRINTF_RODATA, not UNKNOWN).

Usage:
    from ablation.analyzers.sink_arg_classifier import SinkArgClassifier

    clf = SinkArgClassifier.from_path('/path/to/binary')

    # Built-in sinks (system/popen/execve/execvp/execl/execlp)
    results = clf.classify_all()

    # Add Fortinet-specific or vendor-specific sinks
    clf.add_sink('fadcsystem',     arg_pos=1)   # rsi = command string
    clf.add_sink('fadcsystem_envp', arg_pos=0)  # rdi = command string
    clf.add_sink('sys_vdom_exec',  arg_pos=1)   # rsi = command string

    for r in results:
        print(r.fmt())

    # Filter to non-safe findings only
    flagged = [r for r in results if r.verdict != 'RODATA_CONST']

CLI:
    python3 -m ablation.analyzers.sink_arg_classifier /path/to/binary
    python3 -m ablation.analyzers.sink_arg_classifier /path/to/binary --sink system
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import (
        X86_OP_REG, X86_OP_MEM, X86_OP_IMM,
        X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
        X86_REG_R8,  X86_REG_R9,  X86_REG_RAX,
        X86_REG_RBP, X86_REG_RSP, X86_REG_RIP,
        X86_REG_R10, X86_REG_R11, X86_REG_R12, X86_REG_R13,
        X86_REG_R14, X86_REG_R15,
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


# ── Shared PLT/func-start extraction helpers (x86-64) ────────────────────────
# Used by SinkArgClassifier, SanitizerDetector, and ForkExecClassifier.
# Mirrors BinaryContext._extract_plt: parses .rela.plt to get GOT→sym, then
# scans .plt/.plt.sec stubs for `ff 25` (jmp [rip+disp]) to get stub VAs.

_ENDBR64 = b'\xf3\x0f\x1e\xfa'

def _extract_plt_x86(binary, data: bytes) -> Dict[int, str]:
    """Return {plt_stub_va: symbol_name} for all PLT entries in binary."""
    if not _LIEF_OK or binary is None:
        return {}

    # Step 1: parse .rela.plt → {got_va: sym_name}
    got_to_sym: Dict[int, str] = {}
    try:
        rela_plt = binary.get_section('.rela.plt')
        if rela_plt:
            rela_data = bytes(rela_plt.content)
            for off in range(0, len(rela_data) - 23, 24):
                r_offset, r_info = struct.unpack_from('<QQ', rela_data, off)
                sym_idx = r_info >> 32
                try:
                    sym = binary.dynamic_symbols[sym_idx]
                    if sym.name:
                        got_to_sym[r_offset] = sym.name
                except Exception:
                    pass
    except Exception:
        pass

    if not got_to_sym:
        # Fallback: relocations with JUMP_SLOT type
        try:
            for rel in binary.relocations:
                if not rel.has_symbol:
                    continue
                if 'JUMP_SLOT' in str(getattr(rel, 'type', '')):
                    if rel.symbol.name:
                        got_to_sym[rel.address] = rel.symbol.name
        except Exception:
            pass

    plt: Dict[int, str] = {}

    if not _CS_OK:
        return plt

    import capstone as _cap
    cs = _cap.Cs(_cap.CS_ARCH_X86, _cap.CS_MODE_64)

    for sec_name in ('.plt.sec', '.plt', '.plt.got'):
        try:
            sec = binary.get_section(sec_name)
        except Exception:
            sec = None
        if not sec:
            continue
        sec_data = bytes(sec.content)
        sec_va = sec.virtual_address
        entry_size = 16

        for off in range(0, len(sec_data), entry_size):
            stub_va = sec_va + off
            chunk = sec_data[off:off + entry_size]
            if len(chunk) < 6:
                break
            start = 4 if chunk[:4] == _ENDBR64 else 0
            if len(chunk) < start + 6:
                continue
            if chunk[start:start + 2] == b'\xff\x25':
                disp = struct.unpack_from('<i', chunk, start + 2)[0]
                got_va = stub_va + start + 6 + disp
                if got_va in got_to_sym:
                    plt[stub_va] = got_to_sym[got_va]

    return plt


def _count_plt_callers(binary, data: bytes) -> Dict[int, int]:
    """
    Return {plt_va: caller_count} for all direct `call imm` targets in binary.

    Performs a single O(binary_size) scan over executable sections, counting
    every `e8 <rel32>` call target simultaneously.  Much faster than scanning
    once per PLT entry (which would be O(PLT_count × binary_size)).

    A PLT entry with count == 0 is dead code — the import is declared in the
    dynamic symbol table but never called from within this binary.
    """
    from collections import Counter
    call_targets: Counter = Counter()
    if binary is None or not data:
        return {}
    for sec in binary.sections:
        if not (int(getattr(sec, 'flags', 0)) & 0x4):  # SHF_EXECINSTR
            continue
        off    = sec.offset
        size   = sec.size
        sec_va = sec.virtual_address
        if off + size > len(data):
            continue
        for i in range(off, off + size - 5):
            if data[i] != 0xe8:
                continue
            rel     = struct.unpack_from('<i', data, i + 1)[0]
            call_va = sec_va + (i - off)
            tgt_va  = call_va + 5 + rel
            call_targets[tgt_va] += 1
    return dict(call_targets)


def _extract_func_starts(binary, data: bytes = b'') -> List[int]:
    """
    Extract function start VAs. Uses symbol table when available; falls back to
    prologue-pattern scanning for fully stripped x86-64 binaries.

    Args:
        binary: LIEF-parsed ELF binary.
        data:   Raw file bytes (required for prologue-scan fallback on stripped binaries).
                Pass Path(binary_path).read_bytes() or self._data from the classifier.

    Heuristic (stripped fallback):
      1. endbr64 (0xf3 0x0f 0x1e 0xfa) — IBT function entry marker; very high precision.
      2. push rbp (0x55) after ret (0xc3) or int3 (0xcc) — classic frame-pointer prologue.
      3. push r12-r15/rbx/rsi/rdi after ret/int3 — Fortinet-style omit-frame-pointer builds.
    """
    if not _LIEF_OK or binary is None:
        return []
    starts = sorted(
        s.value for s in binary.symbols
        if s.value and hasattr(s, 'type')
        and getattr(s.type, 'name', '') == 'FUNC'
    )
    if not starts:
        starts = sorted(
            s.value for s in binary.dynamic_symbols
            if s.value and getattr(s.type, 'name', '') == 'FUNC'
        )
    if starts:
        return starts

    # Stripped binary: heuristic prologue scan over executable sections.
    # Requires raw file bytes via data= parameter.
    if not data:
        return []
    raw = data

    found: List[int] = []
    _TERMINATORS = frozenset([0xc3, 0xcc])  # ret, int3
    # Additional Fortinet-style callee-save prologues (no frame pointer, push r12-r15/rbx/rsi)
    _PUSH_PAIRS = frozenset([
        (0x41, 0x57),  # push r15
        (0x41, 0x56),  # push r14
        (0x41, 0x55),  # push r13
        (0x41, 0x54),  # push r12
        (0x53,),       # push rbx (single byte — check separately)
        (0x56,),       # push rsi
        (0x57,),       # push rdi
    ])

    for sec in binary.sections:
        if not (int(getattr(sec, 'flags', 0)) & 0x4):  # SHF_EXECINSTR
            continue
        off    = sec.offset
        size   = sec.size
        sec_va = sec.virtual_address
        if off + size > len(raw):
            continue
        sec_data = raw[off:off + size]

        # endbr64: IBT function entry marker (modern PIE builds)
        for i in range(0, len(sec_data) - 4):
            if sec_data[i:i + 4] == _ENDBR64:
                found.append(sec_va + i)

        def _preceded_by_terminator(buf, idx, max_look=4):
            """True if buf[idx] is preceded by a ret/int3, optionally through NOPs."""
            for back in range(1, max_look + 1):
                if idx - back < 0:
                    return False
                prev = buf[idx - back]
                if prev in _TERMINATORS:
                    return True
                if prev != 0x90:   # non-NOP non-terminator: not a function boundary
                    return False
            return False

        # push rbp (0x55) after terminator (allow NOP padding between)
        for i in range(1, len(sec_data)):
            if sec_data[i] == 0x55 and _preceded_by_terminator(sec_data, i):
                found.append(sec_va + i)

        # push r12-r15 / push rbx / push rsi / push rdi after terminator (allow NOP padding)
        for i in range(1, len(sec_data) - 1):
            b0 = sec_data[i]
            b1 = sec_data[i + 1] if i + 1 < len(sec_data) else 0
            if b0 == 0x41 and (b1 in (0x54, 0x55, 0x56, 0x57)):
                if _preceded_by_terminator(sec_data, i):
                    found.append(sec_va + i)
            elif b0 in (0x53, 0x56, 0x57):
                if _preceded_by_terminator(sec_data, i):
                    found.append(sec_va + i)

    return sorted(set(found))

# ── ABI argument register positions ──────────────────────────────────────────
# arg_pos → capstone register constant (SysV AMD64)
_ARG_POS_TO_REG: List[int] = []
if _CS_OK:
    _ARG_POS_TO_REG = [
        X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
        X86_REG_R8,  X86_REG_R9,
    ]

# Entry argument registers (if fmt came from one of these → caller controls it)
_ENTRY_ARGS: Set[int] = set()
if _CS_OK:
    _ENTRY_ARGS = {
        X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
        X86_REG_R8, X86_REG_R9,
    }

# Caller-saved registers clobbered across calls
_CALLER_SAVED: Set[int] = set()
if _CS_OK:
    _CALLER_SAVED = {
        X86_REG_RAX, X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
        X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11,
    }

# Sub-register → canonical 64-bit register (capstone reg IDs vary; use names instead)
_SUBREG_CANON: Dict[str, str] = {
    'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
    'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx',
    'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx',
    'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx',
    'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
    'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
    'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
    'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
    'r8':  'r8',  'r8d': 'r8',  'r8w': 'r8',  'r8b': 'r8',
    'r9':  'r9',  'r9d': 'r9',  'r9w': 'r9',  'r9b': 'r9',
    'r10': 'r10', 'r10d': 'r10',
    'r11': 'r11', 'r11d': 'r11',
    'r12': 'r12', 'r12d': 'r12',
    'r13': 'r13', 'r13d': 'r13',
    'r14': 'r14', 'r14d': 'r14',
    'r15': 'r15', 'r15d': 'r15',
}

# __ canonical reg name from capstone reg ID ___________________________________
_ID_TO_NAME: Dict[int, str] = {}
if _CS_OK:
    _ID_TO_NAME = {
        X86_REG_RDI: 'rdi', X86_REG_RSI: 'rsi', X86_REG_RDX: 'rdx',
        X86_REG_RCX: 'rcx', X86_REG_R8:  'r8',  X86_REG_R9:  'r9',
        X86_REG_RAX: 'rax', X86_REG_RBP: 'rbp', X86_REG_RSP: 'rsp',
        X86_REG_RIP: 'rip', X86_REG_R10: 'r10', X86_REG_R11: 'r11',
        X86_REG_R12: 'r12', X86_REG_R13: 'r13', X86_REG_R14: 'r14',
        X86_REG_R15: 'r15',
    }

# Sink definitions: name → arg_pos (0-indexed, SysV AMD64)
_DEFAULT_SINKS: Dict[str, int] = {
    'system':     0,   # rdi = cmd
    'popen':      0,   # rdi = cmd
    'execve':     0,   # rdi = pathname
    'execvp':     0,
    'execvpe':    0,
    'execl':      0,
    'execlp':     0,
    'execle':     0,
    '__libc_system': 0,
}

# snprintf-family: maps PLT name → (arg_pos_dest=0, arg_pos_fmt)
# __snprintf_chk(dest, maxlen, flag, objsize, fmt, ...) → fmt at arg_pos 4 (r8)
_SNPRINTF_FMT_POS: Dict[str, int] = {
    'snprintf':       2,  # rdx
    'vsnprintf':      2,
    '__snprintf_chk': 4,  # r8
    'sprintf':        1,  # rsi
    'vsprintf':       1,
    '__sprintf_chk':  3,  # rcx
    'asprintf':       1,
}

_MAX_FUNC_BYTES = 6144
_LOOKBACK = 40
_SNPRINTF_SEARCH_WINDOW = 60   # how far back to look for the snprintf that built a stack buffer


# ── Verdict constants ─────────────────────────────────────────────────────────

RODATA_CONST    = 'RODATA_CONST'     # hardcoded literal in .rodata
SNPRINTF_RODATA = 'SNPRINTF_RODATA'  # built by snprintf with rodata format string
ARG_PROPAGATED  = 'ARG_PROPAGATED'   # came from a caller-supplied argument register
UNKNOWN         = 'UNKNOWN'          # provenance not resolved


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class SinkClassification:
    """Provenance classification for one call site argument."""
    sink_name:   str
    arg_pos:     int        # 0-indexed
    func_va:     int
    call_va:     int
    verdict:     str        # RODATA_CONST | SNPRINTF_RODATA | ARG_PROPAGATED | UNKNOWN
    detail:      str        # human-readable trace description
    severity:    str = ''   # HIGH | MEDIUM | LOW — set by caller

    def __post_init__(self):
        if not self.severity:
            self.severity = {
                RODATA_CONST:    'LOW',
                SNPRINTF_RODATA: 'MEDIUM',
                ARG_PROPAGATED:  'HIGH',
                UNKNOWN:         'MEDIUM',
            }.get(self.verdict, 'MEDIUM')

    def fmt(self) -> str:
        return (
            f"  {self.severity:6s}  {self.verdict:20s}  "
            f"0x{self.func_va:x}  call@0x{self.call_va:x}  "
            f"{self.sink_name}(arg{self.arg_pos})  {self.detail}"
        )

    def as_dict(self) -> dict:
        return {
            'sink':     self.sink_name,
            'arg_pos':  self.arg_pos,
            'func_va':  hex(self.func_va),
            'call_va':  hex(self.call_va),
            'verdict':  self.verdict,
            'detail':   self.detail,
            'severity': self.severity,
        }


# ── Classifier ────────────────────────────────────────────────────────────────

class SinkArgClassifier:
    """
    Classify the provenance of command-string arguments at exec-class sink call sites.

    Covers system/popen/execve family by default; add vendor-specific sinks
    (fadcsystem, sys_vdom_exec, etc.) via add_sink().

    Algorithm:
      1. For each sink call site, walk backwards _LOOKBACK instructions looking
         for the last write to the command argument register.
      2. LEA [rip+x] into .rodata → RODATA_CONST.
      3. MOV from an entry-argument register → ARG_PROPAGATED.
      4. LEA/MOV to a stack slot → search backwards for a snprintf call that
         wrote to that slot; if found, recurse into that snprintf's format arg.
         If the format arg is .rodata → SNPRINTF_RODATA.
      5. Otherwise → UNKNOWN.

    The snprintf recursion handles the dominant firmware pattern:
      snprintf(cmd, sizeof(cmd), '/bin/tool %s', validated_name)
      → fadcsystem(cmd)
    which appears hundreds of times in Fortinet/Aruba/similar firmware.
    """

    def __init__(self, binary_path: str):
        self._path = binary_path
        self._data: bytes = Path(binary_path).read_bytes()
        self._plt: Dict[int, str] = {}          # PLT VA → symbol name
        self._plt_rev: Dict[str, int] = {}      # symbol name → PLT VA
        self._rodata: List[Tuple[int, int]] = [] # (start_va, end_va) pairs
        self._func_starts: List[int] = []
        self._sinks: Dict[str, int] = dict(_DEFAULT_SINKS)  # name → arg_pos
        self._snprintf_plts: Dict[int, int] = {}  # PLT VA → fmt_arg_pos
        self._plt_caller_counts: Dict[int, int] = {}   # PLT VA → call site count
        self._dead_sinks: List[str] = []               # sink names with 0 callers
        self._md: Optional[Cs] = None
        self._bin = None
        if _CS_OK:
            self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._md.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(binary_path)
        self._init()

    # ── class methods ─────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str) -> 'SinkArgClassifier':
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'SinkArgClassifier':
        obj = cls(ctx.path)
        obj._plt = ctx.plt.copy()
        obj._plt_rev = {v: k for k, v in obj._plt.items()}
        obj._func_starts = list(ctx.func_starts)
        obj._init_snprintf_plts()
        return obj

    # ── configuration ─────────────────────────────────────────────────────────

    def add_sink(self, name: str, arg_pos: int) -> None:
        """Register a vendor-specific exec-class sink."""
        self._sinks[name] = arg_pos
        # Rebuild the sink PLT reverse map
        if name in self._plt_rev:
            pass  # already handled in classify_all

    # ── initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        # PLT: parse .rela.plt → build got_to_sym, then scan PLT stubs for ff25 pattern.
        # This mirrors BinaryContext._extract_plt and gives PLT *stub* VAs, not GOT VAs.
        self._plt = _extract_plt_x86(self._bin, self._data)
        for va, name in self._plt.items():
            self._plt_rev[name] = va

        # Function starts from symbols; data passed for prologue-scan fallback
        if not self._func_starts:
            self._func_starts = _extract_func_starts(self._bin, self._data)

        # .rodata ranges
        for sec in self._bin.sections:
            if sec.name in ('.rodata', '.rodata1', '__const', '__cstring', '.rdata'):
                self._rodata.append(
                    (sec.virtual_address, sec.virtual_address + sec.size)
                )

        # Single-pass caller count: O(binary_size) scan for all `call imm` targets.
        # Used to pre-filter dead PLT imports (0 callers = dead code, skip analysis).
        self._plt_caller_counts = _count_plt_callers(self._bin, self._data)

        self._init_snprintf_plts()

    def _init_snprintf_plts(self) -> None:
        for name, fmt_pos in _SNPRINTF_FMT_POS.items():
            va = self._plt_rev.get(name)
            if va:
                self._snprintf_plts[va] = fmt_pos

    # ── helpers ───────────────────────────────────────────────────────────────

    def _va_to_file_offset(self, va: int) -> int:
        if self._bin is None:
            return va  # assume va==offset
        try:
            return self._bin.virtual_address_to_offset(va)
        except Exception:
            return -1

    def _read_va(self, va: int, size: int) -> bytes:
        off = self._va_to_file_offset(va)
        if off < 0 or off + size > len(self._data):
            return b''
        return self._data[off:off + size]

    def _is_rodata(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._rodata)

    def _reg_id_to_canon(self, reg_id: int) -> str:
        """Return canonical 64-bit register name via Cs.reg_name() — correct for all reg IDs."""
        if self._md is None:
            return _ID_TO_NAME.get(reg_id, f'r?{reg_id}')
        name = self._md.reg_name(reg_id)
        return _SUBREG_CANON.get(name, name)

    def _is_entry_arg(self, reg_id: int) -> bool:
        return reg_id in _ENTRY_ARGS

    def _writes_canon(self, insn, canon_name: str) -> bool:
        """True if insn's first (destination) operand writes to canon_name register."""
        if not insn.operands:
            return False
        dst = insn.operands[0]
        if dst.type != X86_OP_REG:
            return False
        return self._reg_id_to_canon(dst.reg) == canon_name

    def _rip_relative_target(self, insn) -> int:
        """For a RIP-relative LEA/MOV, return the resolved VA. -1 if not RIP-rel."""
        if len(insn.operands) < 2:
            return -1
        src = insn.operands[1]
        if src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP:
            return insn.address + insn.size + src.mem.disp
        return -1

    def _find_sink_plts(self) -> Dict[int, Tuple[str, int]]:
        """
        Return {plt_va: (sink_name, arg_pos)} for sinks with ≥1 caller.

        Sinks present in the PLT but with 0 call sites anywhere in the binary
        are dead imports — recorded in self._dead_sinks and excluded from analysis.
        """
        result: Dict[int, Tuple[str, int]] = {}
        self._dead_sinks = []
        for name, arg_pos in self._sinks.items():
            va = self._plt_rev.get(name)
            if not va:
                continue
            if self._plt_caller_counts.get(va, 0) == 0:
                self._dead_sinks.append(name)
            else:
                result[va] = (name, arg_pos)
        return result

    # ── backward register trace ───────────────────────────────────────────────

    def _trace_reg(
        self,
        insns: list,
        from_idx: int,
        target_reg_canon: str,
        depth: int = 0,
    ) -> Tuple[str, str]:
        """
        Walk backwards from from_idx tracing the last write to target_reg_canon.

        Returns (verdict, detail).
        depth: recursion depth for snprintf unwinding (max 1).
        """
        if depth > 1:
            return (UNKNOWN, 'max recursion depth reached')

        limit = max(from_idx - _LOOKBACK, -1)

        for j in range(from_idx - 1, limit, -1):
            insn = insns[j]
            mnem = insn.mnemonic.lower()

            if not insn.operands:
                continue

            # Skip instructions that don't write the target register
            if not self._writes_canon(insn, target_reg_canon):
                continue

            # ── case 1: LEA rX, [rip + offset] ───────────────────────────────
            if mnem == 'lea':
                tgt = self._rip_relative_target(insn)
                if tgt > 0:
                    if self._is_rodata(tgt):
                        return (RODATA_CONST, f'LEA [rip+0x{tgt:x}] in .rodata')
                    return (UNKNOWN, f'LEA [rip+0x{tgt:x}] not in .rodata')
                # LEA from stack (rsp/rbp relative) — address of a stack buffer.
                # Use from_idx (the sink call position), not j (the LEA position):
                # the snprintf that fills this buffer may be BETWEEN the LEA and the sink.
                src = insn.operands[1]
                if src.type == X86_OP_MEM:
                    base_name = self._reg_id_to_canon(src.mem.base) if src.mem.base else ''
                    if base_name in ('rsp', 'rbp'):
                        slot = (base_name, src.mem.disp)
                        return self._trace_snprintf_buffer(insns, from_idx, slot, depth)

            # ── case 2: MOV rX, rY ────────────────────────────────────────────
            elif mnem in ('mov', 'movsx', 'movzx', 'movsxd'):
                src = insn.operands[1]
                if src.type == X86_OP_REG:
                    src_canon = self._reg_id_to_canon(src.reg)
                    if self._is_entry_arg(src.reg):
                        return (ARG_PROPAGATED,
                                f'{src_canon} (entry arg) → {target_reg_canon}')
                    # Recurse into source register
                    return self._trace_reg(insns, j, src_canon, depth)
                if src.type == X86_OP_MEM:
                    base_name = self._reg_id_to_canon(src.mem.base) if src.mem.base else ''
                    if base_name in ('rsp', 'rbp'):
                        slot = (base_name, src.mem.disp)
                        return self._trace_snprintf_buffer(insns, from_idx, slot, depth)
                    # Load from some other memory location
                    return (UNKNOWN, f'MOV from [{base_name}+{src.mem.disp:#x}]')
                if src.type == X86_OP_IMM:
                    return (RODATA_CONST, f'immediate 0x{src.imm:x} (likely NULL or constant)')

            # ── case 3: PUSH rX / stack manipulation ──────────────────────────
            elif mnem == 'pop':
                src_canon = target_reg_canon
                return (UNKNOWN, f'POP {src_canon} — stack value, provenance unclear')

        return (UNKNOWN, f'{target_reg_canon} write not found in {_LOOKBACK}-insn window')

    def _trace_snprintf_buffer(
        self,
        insns: list,
        load_idx: int,
        slot: Tuple[str, int],
        depth: int,
    ) -> Tuple[str, str]:
        """
        slot is (base_reg_canon, disp): a stack slot loaded as the sink argument.
        Search backwards for a snprintf call that wrote to this slot (rdi = slot address).
        If found, classify the snprintf's format argument.
        """
        base_reg, disp = slot
        search_limit = max(load_idx - _SNPRINTF_SEARCH_WINDOW, -1)

        for j in range(load_idx - 1, search_limit, -1):
            insn = insns[j]
            mnem = insn.mnemonic.lower()
            if mnem != 'call' or not insn.operands:
                continue
            call_tgt = insn.operands[0].imm if insn.operands[0].type == X86_OP_IMM else -1
            if call_tgt not in self._snprintf_plts:
                continue

            # Found a snprintf-family call. Verify its dest (rdi) points to our slot.
            dest_ok = self._verify_rdi_is_slot(insns, j, base_reg, disp)
            if not dest_ok:
                continue

            fmt_pos = self._snprintf_plts[call_tgt]
            if fmt_pos >= len(_ARG_POS_TO_REG):
                return (UNKNOWN, 'snprintf fmt arg pos out of range')

            fmt_reg_id = _ARG_POS_TO_REG[fmt_pos]
            fmt_reg_canon = self._reg_id_to_canon(fmt_reg_id)

            snprintf_name = self._plt.get(call_tgt, 'snprintf')
            verdict, detail = self._trace_reg(insns, j, fmt_reg_canon, depth + 1)
            if verdict == RODATA_CONST:
                return (SNPRINTF_RODATA,
                        f'{snprintf_name}({base_reg}+{disp:#x}) fmt={detail}')
            return (verdict,
                    f'{snprintf_name}({base_reg}+{disp:#x}) fmt={detail}')

        return (UNKNOWN, f'stack slot [{base_reg}+{disp:#x}]: no snprintf writer found')

    def _verify_rdi_is_slot(
        self,
        insns: list,
        call_idx: int,
        base_reg: str,
        disp: int,
    ) -> bool:
        """
        Check that rdi at call_idx is set to the address of (base_reg, disp).

        Handles two patterns:
          1. lea rdi, [rsp/rbp + disp]
          2. mov rdi, rX  where rX was loaded via  lea rX, [rsp/rbp + disp]
             (callee-saved register pattern: rbx holds the buffer pointer)
        """
        window = 30  # extended from 15; covers long movaps zeroing sequences
        for j in range(call_idx - 1, max(call_idx - window, -1), -1):
            insn = insns[j]
            mnem = insn.mnemonic.lower()
            if not self._writes_canon(insn, 'rdi'):
                continue

            if mnem == 'lea' and len(insn.operands) >= 2:
                src = insn.operands[1]
                if src.type == X86_OP_MEM:
                    src_base = self._reg_id_to_canon(src.mem.base) if src.mem.base else ''
                    if src_base == base_reg and src.mem.disp == disp:
                        return True

            elif mnem in ('mov', 'movq') and len(insn.operands) >= 2:
                src = insn.operands[1]
                if src.type == X86_OP_REG:
                    # Check if the source register was loaded from [base_reg+disp]
                    src_canon = self._reg_id_to_canon(src.reg)
                    if self._reg_holds_slot_addr(insns, j, src_canon, base_reg, disp):
                        return True

            return False  # rdi was set to something else
        return False

    def _reg_holds_slot_addr(
        self,
        insns: list,
        from_idx: int,
        reg_canon: str,
        base_reg: str,
        disp: int,
    ) -> bool:
        """Check if reg_canon was loaded with lea reg, [base_reg+disp] before from_idx."""
        for k in range(from_idx - 1, max(from_idx - 30, -1), -1):
            insn = insns[k]
            mnem = insn.mnemonic.lower()
            if not self._writes_canon(insn, reg_canon):
                continue
            if mnem == 'lea' and len(insn.operands) >= 2:
                src = insn.operands[1]
                if src.type == X86_OP_MEM:
                    src_base = self._reg_id_to_canon(src.mem.base) if src.mem.base else ''
                    if src_base == base_reg and src.mem.disp == disp:
                        return True
            return False  # reg was clobbered by something else
        return False

    # ── main scan ─────────────────────────────────────────────────────────────

    def classify_all(self) -> List[SinkClassification]:
        """Classify all sink call sites across all known function starts."""
        if not _CS_OK or not _LIEF_OK or self._md is None:
            return []
        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []
        results: List[SinkClassification] = []
        for func_va in self._func_starts:
            results.extend(self._classify_function(func_va, sink_plts))
        return results

    def classify_sink(self, sink_name: str, arg_pos: Optional[int] = None) -> List[SinkClassification]:
        """Classify call sites for a single named sink."""
        if arg_pos is None:
            arg_pos = self._sinks.get(sink_name, 0)
        self._sinks[sink_name] = arg_pos
        sink_plts = self._find_sink_plts()
        results: List[SinkClassification] = []
        for func_va in self._func_starts:
            results.extend(self._classify_function(func_va, sink_plts))
        return [r for r in results if r.sink_name == sink_name]

    def _classify_function(
        self,
        func_va: int,
        sink_plts: Dict[int, Tuple[str, int]],
    ) -> List[SinkClassification]:
        raw = self._read_va(func_va, _MAX_FUNC_BYTES)
        if not raw:
            return []
        insns = list(self._md.disasm(raw, func_va))
        results: List[SinkClassification] = []

        for i, insn in enumerate(insns):
            if insn.mnemonic.lower() != 'call' or not insn.operands:
                continue
            if insn.operands[0].type != X86_OP_IMM:
                continue
            tgt = insn.operands[0].imm
            if tgt not in sink_plts:
                continue

            sink_name, arg_pos = sink_plts[tgt]
            if arg_pos >= len(_ARG_POS_TO_REG):
                continue

            arg_reg_id = _ARG_POS_TO_REG[arg_pos]
            arg_canon = self._reg_id_to_canon(arg_reg_id)

            verdict, detail = self._trace_reg(insns, i, arg_canon, depth=0)
            results.append(SinkClassification(
                sink_name=sink_name,
                arg_pos=arg_pos,
                func_va=func_va,
                call_va=insn.address,
                verdict=verdict,
                detail=detail,
            ))
        return results

    # ── reporting ─────────────────────────────────────────────────────────────

    def report(self, results: List[SinkClassification]) -> str:
        if not results and not self._dead_sinks:
            return '[sink_arg_classifier] no results\n'
        by_verdict: Dict[str, int] = {}
        for r in results:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        hdr = (
            f'[sink_arg_classifier] {len(results)} call site(s)  '
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
                f'\n  !! SANITIZER CHECK REQUIRED: {investigate} ARG_PROPAGATED/UNKNOWN result(s) above.'
                f'\n     Run SanitizerDetector on this binary BEFORE filing any of these as PLAUSIBLE.'
                f'\n     An undetected allowlist validator (e.g. is_valid_host_name) may ELIMINATE the'
                f'\n     entire class. Skipping this step wasted 12 sessions on FortiADC (sessions 3→13).'
            )
        return '\n'.join(lines) + '\n'


# ── Batch stub-lib PLT intersection check ─────────────────────────────────────

def batch_plt_intersect(
    directory: str,
    sinks: Optional[List[str]] = None,
    recursive: bool = True,
) -> Dict[str, List[str]]:
    """
    Scan every ELF in `directory` and return only those whose PLT intersects
    with `sinks` (defaults to the built-in exec-class sink list).

    Returns {elf_path: [matching_sink_names]}. Files with zero matches are
    omitted — they are auto-CLEAN and need no individual audit.

    When recursive=True (default), traverses all subdirectories via os.walk.
    Use recursive=False for a flat single-directory scan (original behaviour).
    The recursive default is required for firmware rootfs trees where binaries
    live in deeply nested paths (e.g., VRP board squashfs 6 levels deep).
    Note: os.walk does not follow symlinks (followlinks=False). ELFs that live
    only under symlinked subdirectories will be skipped in recursive mode.

    Usage:
        from ablation.analyzers.sink_arg_classifier import batch_plt_intersect
        hits = batch_plt_intersect('/tmp/fad_root/lib/')
        for path, names in sorted(hits.items()):
            print(path, names)
    """
    import os
    target_sinks: List[str] = sinks if sinks is not None else list(_DEFAULT_SINKS.keys())
    sink_set = set(target_sinks)
    hits: Dict[str, List[str]] = {}

    def _iter_files(d: str):
        if recursive:
            for root, _dirs, files in os.walk(d):
                for fname in sorted(files):
                    yield os.path.join(root, fname)
        else:
            for fname in sorted(os.listdir(d)):
                yield os.path.join(d, fname)

    for fpath in _iter_files(directory):
        if not os.path.isfile(fpath):
            continue
        try:
            data = open(fpath, 'rb').read(4)
            if data[:4] != b'\x7fELF':
                continue
            data = open(fpath, 'rb').read()
        except OSError:
            continue
        try:
            import lief as _lief
            binary = _lief.parse(fpath)
            if binary is None:
                continue
            plt = _extract_plt_x86(binary, data)
        except Exception:
            continue
        matches = [name for _va, name in plt.items() if name in sink_set]
        if matches:
            hits[fpath] = sorted(matches)
    return hits


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='Classify exec-class sink command arguments')
    ap.add_argument('binary')
    ap.add_argument('--sink', help='Sink name to classify (default: all built-in sinks)')
    ap.add_argument('--arg-pos', type=int, default=None, help='Argument position (0=rdi)')
    ap.add_argument('--add-sink', nargs=2, metavar=('NAME', 'ARG_POS'), action='append',
                    help='Add extra sink NAME at argument position ARG_POS')
    ap.add_argument('--flagged-only', action='store_true',
                    help='Show only non-RODATA_CONST findings')
    args = ap.parse_args()

    clf = SinkArgClassifier.from_path(args.binary)
    if args.add_sink:
        for name, pos in args.add_sink:
            clf.add_sink(name, int(pos))

    if args.sink:
        results = clf.classify_sink(args.sink, args.arg_pos)
    else:
        results = clf.classify_all()

    if args.flagged_only:
        results = [r for r in results if r.verdict != RODATA_CONST]

    print(clf.report(results))


if __name__ == '__main__':
    _cli()
