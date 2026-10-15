"""
sscanf_sink_classifier.py: classify sscanf/scanf/fscanf/vsscanf call sites for
destination buffer overflow via unbounded %s format specifiers.

The question at every input-parsing sink is:
  "Does the format string contain unbounded %s — no explicit width specifier?"

Five verdicts:
  RODATA_SAFE    — format in .rodata, no unbounded %s. ELIMINATED.
  RODATA_UNSAFE  — format in .rodata, has unbounded %s (e.g., "%s %d"). HIGH risk.
  DYNAMIC_FMT    — format built at runtime via snprintf. Cannot verify statically.
                   The libwmshared.so tmplogin parser pattern:
                     snprintf(buf, 32, "%%%zus %%lu %%d", 46) → "%46s %lu %d"
                   would emit DYNAMIC_FMT, reducing manual trace work to:
                   confirm snprintf format template is constant (RODATA).
  ARG_PROPAGATED — format string came from a caller argument. Format injection risk.
  UNKNOWN        — provenance not resolved within look-back window.

Gap this fills vs. SinkArgClassifier:
  SinkArgClassifier covers exec-class sinks (system/popen/execve) and
  snprintf-built buffers passed to those sinks. It does NOT analyze sscanf-family
  format strings for unbounded %s — the class of bug where sscanf(input, "%s", buf)
  overflows buf when input is attacker-controlled.

  Four sscanf callers in libwmshared.so (session 18) required manual disassembly.
  This module would have auto-classified all four and surfaced only the UNKNOWN
  sites for manual follow-up.

Known limitation: %[...] character-class specifiers without a width limit are NOT
  flagged by this module. Only %s without a width specifier is detected as UNSAFE.

Usage:
    from ablation.analyzers.sscanf_sink_classifier import SscanfSinkClassifier

    clf = SscanfSinkClassifier.from_path('/path/to/binary')
    results = clf.classify_all()
    flagged = [r for r in results if r.needs_investigation]
    print(clf.report(results))

    # With existing BinaryContext (avoids redundant LIEF parse):
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build(path)
    clf = SscanfSinkClassifier.from_context(ctx)

CLI:
    python3 -m ablation.analyzers.sscanf_sink_classifier /path/to/binary
    python3 -m ablation.analyzers.sscanf_sink_classifier /path/to/binary --flagged-only
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import (
        X86_OP_REG, X86_OP_MEM, X86_OP_IMM,
        X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
        X86_REG_R8, X86_REG_R9, X86_REG_RAX,
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

# Import shared PLT + func-start infrastructure from SinkArgClassifier.
# These functions are non-trivial (200+ lines each); reuse avoids divergence.
try:
    from ablation.analyzers.sink_arg_classifier import (
        _extract_plt_x86,
        _extract_func_starts,
        _count_plt_callers,
    )
    _SAC_HELPERS = True
except ImportError:
    try:
        from sink_arg_classifier import (           # type: ignore
            _extract_plt_x86,
            _extract_func_starts,
            _count_plt_callers,
        )
        _SAC_HELPERS = True
    except ImportError:
        _extract_plt_x86 = None                     # type: ignore
        _extract_func_starts = None                 # type: ignore
        _count_plt_callers = None                   # type: ignore
        _SAC_HELPERS = False

# ── ABI register map (SysV AMD64) ─────────────────────────────────────────────

_ARG_POS_TO_REG: List[int] = []
if _CS_OK:
    _ARG_POS_TO_REG = [
        X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
        X86_REG_R8,  X86_REG_R9,
    ]

_ENTRY_ARGS: Set[int] = set()
if _CS_OK:
    _ENTRY_ARGS = {
        X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
        X86_REG_R8, X86_REG_R9,
    }

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

# snprintf-family PLT names and their format argument position
_SNPRINTF_FMT_POS: Dict[str, int] = {
    'snprintf':       2,
    'vsnprintf':      2,
    '__snprintf_chk': 4,
    'sprintf':        1,
    'vsprintf':       1,
    '__sprintf_chk':  3,
    'asprintf':       1,
}

# sscanf-family sinks: name → format_arg_pos (0-indexed, SysV AMD64)
_DEFAULT_SINKS: Dict[str, int] = {
    'sscanf':           1,   # sscanf(str, fmt, ...) → rsi
    'vsscanf':          1,
    '__isoc99_sscanf':  1,   # glibc C99 variant
    'scanf':            0,   # scanf(fmt, ...) → rdi; stdin = always user input
    '__isoc99_scanf':   0,
    'fscanf':           1,   # fscanf(file, fmt, ...) → rsi
    '__isoc99_fscanf':  1,
}

_MAX_FUNC_BYTES = 6144
_LOOKBACK = 40
_SNPRINTF_SEARCH_WINDOW = 60

# ── Verdict constants ──────────────────────────────────────────────────────────

RODATA_SAFE    = 'RODATA_SAFE'     # .rodata format, no unbounded %s → ELIMINATED
RODATA_UNSAFE  = 'RODATA_UNSAFE'   # .rodata format, has unbounded %s → HIGH
DYNAMIC_FMT    = 'DYNAMIC_FMT'     # runtime-built via snprintf → MEDIUM
ARG_PROPAGATED = 'ARG_PROPAGATED'  # format from caller arg → HIGH
UNKNOWN        = 'UNKNOWN'         # provenance unresolved → MEDIUM


# ── Data class ─────────────────────────────────────────────────────────────────

@dataclass
class SscanfClassification:
    """Format string classification for one sscanf-family call site."""
    sink_name:   str
    fmt_arg_pos: int    # 0-indexed position of the format argument
    func_va:     int
    call_va:     int
    verdict:     str    # RODATA_SAFE | RODATA_UNSAFE | DYNAMIC_FMT | ARG_PROPAGATED | UNKNOWN
    format_str:  str    # decoded format string if from .rodata, else ''
    detail:      str    # human-readable trace
    severity:    str = ''

    def __post_init__(self):
        if not self.severity:
            self.severity = {
                RODATA_SAFE:    'LOW',
                RODATA_UNSAFE:  'HIGH',
                DYNAMIC_FMT:    'MEDIUM',
                ARG_PROPAGATED: 'HIGH',
                UNKNOWN:        'MEDIUM',
            }.get(self.verdict, 'MEDIUM')

    @property
    def needs_investigation(self) -> bool:
        return self.verdict != RODATA_SAFE

    def fmt(self) -> str:
        fmtstr = f'  fmt={self.format_str!r}' if self.format_str else ''
        return (
            f"  {self.severity:6s}  {self.verdict:16s}  "
            f"0x{self.func_va:x}  call@0x{self.call_va:x}  "
            f"{self.sink_name}(fmtarg{self.fmt_arg_pos})"
            f"{fmtstr}  {self.detail}"
        )

    def as_dict(self) -> dict:
        return {
            'sink':       self.sink_name,
            'fmt_arg':    self.fmt_arg_pos,
            'func_va':    hex(self.func_va),
            'call_va':    hex(self.call_va),
            'verdict':    self.verdict,
            'format_str': self.format_str,
            'detail':     self.detail,
            'severity':   self.severity,
        }


# ── Format string scanner ──────────────────────────────────────────────────────

def _has_unbounded_s(fmt: bytes) -> bool:
    """
    Return True if fmt contains at least one unbounded %s (no explicit width).

    Handles:
      %s         → unbounded (True)
      %20s       → bounded (False)
      %05s       → bounded; '0' is a printf flag, '5' is the width (False)
      %-20s      → bounded; '-' is flag, '20' is width (False)
      %*s        → assignment-suppressed; no write to dest buffer (False)
      %%         → literal percent, not a specifier (False)

    NOT detected (known limitation):
      %[^:]      → character-class without width is also unbounded, but
                   this function only checks 's' conversions.
    """
    i = 0
    n = len(fmt)
    while i < n:
        if fmt[i] != ord('%'):
            i += 1
            continue
        i += 1
        if i >= n:
            break
        # %% → literal percent
        if fmt[i] == ord('%'):
            i += 1
            continue
        # * → assignment-suppressed: reads but discards, no buffer write
        if fmt[i] == ord('*'):
            i += 1
            while i < n and 48 <= fmt[i] <= 57:   # skip optional width digits
                i += 1
            while i < n and chr(fmt[i]) in 'hlLzjtq':  # skip length modifiers
                i += 1
            if i < n:
                i += 1   # skip conversion char
            continue
        # Skip printf/scanf flags: - + space # 0
        while i < n and chr(fmt[i]) in '-+ #0':
            i += 1
        # Check for width specifier (digits 1-9 leading, then any digit)
        has_width = False
        if i < n and fmt[i] == ord('*'):
            # Width from argument — could be zero or huge; treat conservatively
            i += 1
        elif i < n and 49 <= fmt[i] <= 57:  # '1'..'9': explicit nonzero width
            has_width = True
            while i < n and 48 <= fmt[i] <= 57:
                i += 1
        # Skip optional precision (e.g., %.10s)
        if i < n and fmt[i] == ord('.'):
            i += 1
            while i < n and 48 <= fmt[i] <= 57:
                i += 1
        # Skip length modifiers
        while i < n and chr(fmt[i]) in 'hlLzjtq':
            i += 1
        # Check conversion character
        if i < n and fmt[i] == ord('s') and not has_width:
            return True
        if i < n:
            i += 1
    return False


# ── Classifier ─────────────────────────────────────────────────────────────────

class SscanfSinkClassifier:
    """
    Classify sscanf/scanf/fscanf call sites for unbounded %s format specifiers.

    Algorithm:
      1. Locate sscanf-family PLT stubs with at least one caller.
      2. For each call site, trace the format argument register backwards.
      3. LEA [rip+x] → .rodata: read string bytes, scan for unbounded %s.
         → RODATA_SAFE or RODATA_UNSAFE.
      4. LEA/MOV → stack slot: search backwards for snprintf that filled it.
         → DYNAMIC_FMT (format was runtime-constructed; verify template manually).
      5. MOV from entry-argument register → ARG_PROPAGATED.
      6. Otherwise → UNKNOWN.
    """

    def __init__(self, binary_path: str):
        self._path = binary_path
        self._data: bytes = Path(binary_path).read_bytes()
        self._plt: Dict[int, str] = {}
        self._plt_rev: Dict[str, int] = {}
        self._rodata: List[Tuple[int, int]] = []
        self._func_starts: List[int] = []
        self._snprintf_plts: Dict[int, int] = {}
        self._plt_caller_counts: Dict[int, int] = {}
        self._dead_sinks: List[str] = []
        self._md = None
        self._bin = None
        if _CS_OK:
            self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._md.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(binary_path)
        self._init()

    @classmethod
    def from_path(cls, path: str) -> 'SscanfSinkClassifier':
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'SscanfSinkClassifier':
        """Build from existing BinaryContext to reuse pre-computed plt/func_starts."""
        obj = cls(ctx.path)
        obj._plt = ctx.plt.copy()
        obj._plt_rev = {v: k for k, v in obj._plt.items()}
        obj._func_starts = list(ctx.func_starts)
        obj._init_snprintf_plts()
        return obj

    # ── initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        if _extract_plt_x86 is not None:
            self._plt = _extract_plt_x86(self._bin, self._data)
        for va, name in self._plt.items():
            self._plt_rev[name] = va
        if not self._func_starts and _extract_func_starts is not None:
            self._func_starts = _extract_func_starts(self._bin, self._data)
        for sec in self._bin.sections:
            if sec.name in ('.rodata', '.rodata1', '__const', '__cstring', '.rdata'):
                self._rodata.append(
                    (sec.virtual_address, sec.virtual_address + sec.size)
                )
        if _count_plt_callers is not None:
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

    def _is_rodata(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._rodata)

    def _read_rodata_string(self, va: int, max_len: int = 512) -> Optional[bytes]:
        """Read null-terminated string from binary at va. Returns None on failure."""
        off = self._va_to_file_offset(va)
        if off < 0 or off >= len(self._data):
            return None
        limit = min(off + max_len, len(self._data))
        end = off
        while end < limit and self._data[end] != 0:
            end += 1
        if end >= limit:
            return None  # no null terminator within max_len: not a string
        return self._data[off:end]

    def _reg_id_to_canon(self, reg_id: int) -> str:
        if self._md is None:
            return _ID_TO_NAME.get(reg_id, f'r?{reg_id}')
        name = self._md.reg_name(reg_id)
        return _SUBREG_CANON.get(name, name)

    def _writes_canon(self, insn, canon_name: str) -> bool:
        if not insn.operands:
            return False
        dst = insn.operands[0]
        if dst.type != X86_OP_REG:
            return False
        return self._reg_id_to_canon(dst.reg) == canon_name

    def _rip_relative_target(self, insn) -> int:
        if len(insn.operands) < 2:
            return -1
        src = insn.operands[1]
        if src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP:
            return insn.address + insn.size + src.mem.disp
        return -1

    def _find_sink_plts(self) -> Dict[int, Tuple[str, int]]:
        result: Dict[int, Tuple[str, int]] = {}
        self._dead_sinks = []
        for name, fmt_pos in _DEFAULT_SINKS.items():
            va = self._plt_rev.get(name)
            if not va:
                continue
            # Guard: only apply dead-sink filter when caller count data exists.
            # An empty _plt_caller_counts means the scan was unavailable (all
            # SHF_EXECINSTR sections stripped), not that sinks have zero callers.
            if self._plt_caller_counts and self._plt_caller_counts.get(va, 0) == 0:
                self._dead_sinks.append(name)
            else:
                result[va] = (name, fmt_pos)
        return result

    # ── format register trace ─────────────────────────────────────────────────

    def _trace_fmt_reg(
        self,
        insns: list,
        from_idx: int,
        target_reg: str,
        depth: int = 0,
    ) -> Tuple[str, str, str]:
        """
        Trace the format string register backwards from from_idx.
        Returns (verdict, format_str_text, detail).
        format_str_text is the decoded format if from .rodata, else ''.
        """
        if depth > 1:
            return (UNKNOWN, '', 'max recursion depth')

        limit = max(from_idx - _LOOKBACK, -1)

        for j in range(from_idx - 1, limit, -1):
            insn = insns[j]
            mnem = insn.mnemonic.lower()

            if not insn.operands:
                continue
            if not self._writes_canon(insn, target_reg):
                continue

            # ── case 1: LEA rX, [rip + offset] ───────────────────────────────
            if mnem == 'lea':
                tgt = self._rip_relative_target(insn)
                if tgt > 0:
                    if self._is_rodata(tgt):
                        fmt_bytes = self._read_rodata_string(tgt)
                        if fmt_bytes is None:
                            return (UNKNOWN, '',
                                    f'LEA rodata@0x{tgt:x}: string read failed')
                        fmt_text = fmt_bytes.decode('ascii', errors='replace')
                        if _has_unbounded_s(fmt_bytes):
                            return (RODATA_UNSAFE, fmt_text,
                                    f'LEA [rip+0x{tgt:x}] has unbounded %s')
                        return (RODATA_SAFE, fmt_text,
                                f'LEA [rip+0x{tgt:x}] no unbounded %s')
                    return (UNKNOWN, '', f'LEA 0x{tgt:x} not in .rodata')
                # LEA to stack slot → check for snprintf writer
                src = insn.operands[1]
                if src.type == X86_OP_MEM:
                    base = self._reg_id_to_canon(src.mem.base) if src.mem.base else ''
                    if base in ('rsp', 'rbp'):
                        slot = (base, src.mem.disp)
                        return self._trace_snprintf_slot(insns, from_idx, slot, depth)

            # ── case 2: MOV rX, rY or MOV rX, [mem] ──────────────────────────
            elif mnem in ('mov', 'movsx', 'movzx', 'movsxd'):
                src = insn.operands[1]
                if src.type == X86_OP_REG:
                    if src.reg in _ENTRY_ARGS:
                        src_name = self._reg_id_to_canon(src.reg)
                        return (ARG_PROPAGATED, '',
                                f'{src_name} (entry arg) → {target_reg}')
                    src_name = self._reg_id_to_canon(src.reg)
                    return self._trace_fmt_reg(insns, j, src_name, depth)
                if src.type == X86_OP_MEM:
                    base = self._reg_id_to_canon(src.mem.base) if src.mem.base else ''
                    if base in ('rsp', 'rbp'):
                        slot = (base, src.mem.disp)
                        return self._trace_snprintf_slot(insns, from_idx, slot, depth)
                    return (UNKNOWN, '', f'MOV from [{base}+{src.mem.disp:#x}]')
                if src.type == X86_OP_IMM:
                    return (RODATA_SAFE, '',
                            f'immediate 0x{src.imm:x} (NULL or constant ptr)')

            # ── case 3: POP ───────────────────────────────────────────────────
            elif mnem == 'pop':
                return (UNKNOWN, '', f'POP {target_reg}: stack value, provenance unclear')

        return (UNKNOWN, '',
                f'{target_reg} write not found in {_LOOKBACK}-insn window')

    def _trace_snprintf_slot(
        self,
        insns: list,
        load_idx: int,
        slot: Tuple[str, int],
        depth: int,
    ) -> Tuple[str, str, str]:
        """
        Check if a stack slot was filled by snprintf.
        If yes → DYNAMIC_FMT: format was runtime-constructed; cannot verify statically.
        """
        base_reg, disp = slot
        search_limit = max(load_idx - _SNPRINTF_SEARCH_WINDOW, -1)

        for j in range(load_idx - 1, search_limit, -1):
            insn = insns[j]
            if insn.mnemonic.lower() != 'call' or not insn.operands:
                continue
            if insn.operands[0].type != X86_OP_IMM:
                continue
            call_tgt = insn.operands[0].imm
            if call_tgt not in self._snprintf_plts:
                continue
            if not self._verify_rdi_is_slot(insns, j, base_reg, disp):
                continue
            snprintf_name = self._plt.get(call_tgt, 'snprintf')
            return (DYNAMIC_FMT, '',
                    f'snprintf-built format at [{base_reg}+{disp:#x}] '
                    f'via {snprintf_name} — verify format template is constant')

        return (UNKNOWN, '',
                f'stack slot [{base_reg}+{disp:#x}]: no snprintf writer found')

    def _verify_rdi_is_slot(
        self,
        insns: list,
        call_idx: int,
        base_reg: str,
        disp: int,
    ) -> bool:
        """Return True if rdi at call_idx is set to address of stack slot (base_reg, disp)."""
        for j in range(call_idx - 1, max(call_idx - 30, -1), -1):
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
            return False  # rdi set to something else
        return False

    # ── main scan ─────────────────────────────────────────────────────────────

    def classify_all(self) -> List[SscanfClassification]:
        """Classify all sscanf-family call sites across all known function starts."""
        if not _CS_OK or not _LIEF_OK or self._md is None:
            return []
        sink_plts = self._find_sink_plts()
        if not sink_plts:
            return []
        results: List[SscanfClassification] = []
        for func_va in self._func_starts:
            results.extend(self._classify_function(func_va, sink_plts))
        return results

    def _classify_function(
        self,
        func_va: int,
        sink_plts: Dict[int, Tuple[str, int]],
    ) -> List[SscanfClassification]:
        raw = self._read_va(func_va, _MAX_FUNC_BYTES)
        if not raw:
            return []
        insns = list(self._md.disasm(raw, func_va))
        results: List[SscanfClassification] = []

        for i, insn in enumerate(insns):
            if insn.mnemonic.lower() != 'call' or not insn.operands:
                continue
            if insn.operands[0].type != X86_OP_IMM:
                continue
            tgt = insn.operands[0].imm
            if tgt not in sink_plts:
                continue

            sink_name, fmt_arg_pos = sink_plts[tgt]
            if fmt_arg_pos >= len(_ARG_POS_TO_REG):
                continue

            fmt_reg_id = _ARG_POS_TO_REG[fmt_arg_pos]
            fmt_reg = self._reg_id_to_canon(fmt_reg_id)

            verdict, fmt_text, detail = self._trace_fmt_reg(insns, i, fmt_reg)
            results.append(SscanfClassification(
                sink_name=sink_name,
                fmt_arg_pos=fmt_arg_pos,
                func_va=func_va,
                call_va=insn.address,
                verdict=verdict,
                format_str=fmt_text,
                detail=detail,
            ))
        return results

    # ── reporting ─────────────────────────────────────────────────────────────

    def report(self, results: List[SscanfClassification]) -> str:
        if not results and not self._dead_sinks:
            return '[sscanf_sink_classifier] no results\n'
        by_verdict: Dict[str, int] = {}
        for r in results:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        hdr = (
            f'[sscanf_sink_classifier] {len(results)} call site(s)  '
            + '  '.join(f'{k}={v}' for k, v in sorted(by_verdict.items()))
            + '\n'
        )
        lines = [hdr]
        # Print in severity order: HIGH → MEDIUM → LOW
        high = [r for r in results if r.verdict in (RODATA_UNSAFE, ARG_PROPAGATED)]
        medium = [r for r in results if r.verdict in (DYNAMIC_FMT, UNKNOWN)]
        safe = [r for r in results if r.verdict == RODATA_SAFE]
        for group in (high, medium, safe):
            for r in sorted(group, key=lambda x: x.func_va):
                lines.append(r.fmt())
        if self._dead_sinks:
            lines.append(
                '\n  DEAD IMPORTS (0 callers — ELIMINATED): '
                + ', '.join(sorted(self._dead_sinks))
            )
        hi_count = sum(1 for r in results if r.verdict in (RODATA_UNSAFE, ARG_PROPAGATED))
        if hi_count:
            lines.append(
                f'\n  !! {hi_count} HIGH finding(s):'
                f'\n     RODATA_UNSAFE: verify dest buffer >= max matched bytes.'
                f'\n     ARG_PROPAGATED: format injection risk — trace to network entry.'
            )
        return '\n'.join(lines) + '\n'


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli() -> None:
    import argparse
    ap = argparse.ArgumentParser(
        description='Classify sscanf-family format strings for unbounded %s'
    )
    ap.add_argument('binary')
    ap.add_argument('--flagged-only', action='store_true',
                    help='Show only non-RODATA_SAFE findings')
    args = ap.parse_args()

    clf = SscanfSinkClassifier.from_path(args.binary)
    results = clf.classify_all()

    if args.flagged_only:
        results = [r for r in results if r.needs_investigation]

    import sys
    print(clf.report(results))
    if any(r.verdict in (RODATA_UNSAFE, ARG_PROPAGATED) for r in results):
        sys.exit(1)


if __name__ == '__main__':
    _cli()
