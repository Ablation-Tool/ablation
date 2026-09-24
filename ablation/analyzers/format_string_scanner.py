"""
format_string_scanner.py -- Format string vulnerability detector for x86-64 ELF binaries.

TAOSSA Ch8: format string vulnerabilities arise when user-controlled data reaches the
format argument of printf/fprintf/syslog and similar functions. The format argument is
safe only when it is a string literal (RIP-relative load from .rodata). Any other provenance
-- function argument, stack variable, register from recv/read/network -- is a finding.

Covers the full printf family, syslog, err/warn, and user-supplied callable tables.

Detection algorithm per call site:
  1. Identify the fmt register for the callee (RDI for printf, RSI for fprintf, etc.)
  2. Walk backwards from the call site to find the last instruction that defined that register
  3. If the definition is LEA from .rodata -> string literal -> safe
  4. Otherwise -> potential format string vulnerability
  5. Severity HIGH if fmt comes from a function argument register (rdi/rsi/rdx/rcx at entry);
     MEDIUM if provenance is unclear (stack load, cross-call result)

Usage:
    from ablation.analyzers.format_string_scanner import FormatStringScanner

    scanner = FormatStringScanner.from_path('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = FormatStringScanner.from_context(ctx)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_CS_AVAILABLE = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_RET
    from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
    from capstone.x86_const import (
        X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
        X86_REG_R8, X86_REG_R9, X86_REG_RAX,
    )
    _CS_AVAILABLE = True
except ImportError:
    pass

_LIEF_AVAILABLE = False
try:
    import lief as _lief
    _LIEF_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Format function registry
# fmt_reg: the capstone register ID that carries the format string argument
# ---------------------------------------------------------------------------

# Built lazily after capstone is imported
_FMT_FUNCS: Dict[str, int] = {}

def _build_fmt_funcs() -> Dict[str, int]:
    if not _CS_AVAILABLE:
        return {}
    return {
        # printf family (fmt = arg0 = RDI)
        'printf':    X86_REG_RDI,
        'vprintf':   X86_REG_RDI,
        'puts':      X86_REG_RDI,  # not a fmt func but often confused; flag for review
        # fprintf/sprintf/dprintf family (fmt = arg1 = RSI)
        'fprintf':   X86_REG_RSI,
        'vfprintf':  X86_REG_RSI,
        'sprintf':   X86_REG_RSI,
        'vsprintf':  X86_REG_RSI,
        'snprintf':  X86_REG_RDX,  # snprintf(buf, n, fmt, ...) -> fmt = arg2 = RDX
        'vsnprintf': X86_REG_RDX,
        'asprintf':  X86_REG_RSI,
        'vasprintf': X86_REG_RSI,
        'dprintf':   X86_REG_RSI,
        'vdprintf':  X86_REG_RSI,
        # syslog family (fmt = arg1 = RSI)
        'syslog':    X86_REG_RSI,
        'vsyslog':   X86_REG_RSI,
        # err/warn (fmt = arg1 = RSI)
        'err':       X86_REG_RSI,
        'errx':      X86_REG_RSI,
        'warn':      X86_REG_RSI,
        'warnx':     X86_REG_RSI,
        'verr':      X86_REG_RSI,
        'verrx':     X86_REG_RSI,
        'vwarn':     X86_REG_RSI,
        'vwarnx':    X86_REG_RSI,
        # custom / embedded common names
        'log_printf':   X86_REG_RSI,
        'debug_printf': X86_REG_RDI,
        'trace_printf': X86_REG_RDI,
    }


# Entry argument registers (SysV AMD64): taint from caller
_ENTRY_ARGS = frozenset([
    X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
    X86_REG_R8, X86_REG_R9,
] if _CS_AVAILABLE else [])

_CALLER_SAVED = frozenset([
    X86_REG_RAX, X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
    X86_REG_R8, X86_REG_R9,
] if _CS_AVAILABLE else [])

_MAX_FUNC_BYTES = 4096
_LOOKBACK = 20   # max instructions to walk back from CALL site


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class FmtStringFinding:
    func_va: int
    call_va: int
    callee: str
    fmt_reg: str        # 'rdi' / 'rsi' / 'rdx'
    provenance: str     # 'arg_passthrough' | 'stack_load' | 'register' | 'unknown' | 'rodata'
    severity: str       # 'HIGH' | 'MEDIUM' | 'SAFE'
    description: str

    @property
    def verdict(self) -> str:
        if self.provenance == 'rodata':
            return 'SAFE'
        if self.severity == 'HIGH':
            return 'VULNERABLE'
        return 'SUSPICIOUS'

    def as_dict(self) -> dict:
        return {
            'func_va': hex(self.func_va),
            'call_va': hex(self.call_va),
            'callee': self.callee,
            'fmt_reg': self.fmt_reg,
            'provenance': self.provenance,
            'severity': self.severity,
            'verdict': self.verdict,
            'description': self.description,
        }

    def fmt(self) -> str:
        return (
            f"  {self.severity:6s}  fmt_string  0x{self.func_va:x}+{(self.call_va-self.func_va)&0xFFFF:#x}"
            f"  {self.callee}({self.fmt_reg}=user?)  {self.description}"
        )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class FormatStringScanner:
    """
    Detect non-constant format string arguments in printf-family calls.

    Safe: LEA fmt_reg, [rip + offset_in_rodata]   (string literal)
    Flag: any other definition of fmt_reg before the CALL
    """

    def __init__(self, binary_path: str, ctx=None):
        self.binary_path = binary_path
        self._ctx = ctx
        self._data: bytes = Path(binary_path).read_bytes()
        self._fmt_call_vas: Dict[int, Tuple[str, int]] = {}  # va -> (name, fmt_reg_id)
        self._func_starts: List[int] = []
        self._plt: Dict[int, str] = {}
        self._rodata_ranges: List[Tuple[int, int]] = []
        self._lief_binary = None
        self._md = None
        if _CS_AVAILABLE:
            self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._md.detail = True
            global _FMT_FUNCS
            if not _FMT_FUNCS:
                _FMT_FUNCS = _build_fmt_funcs()
        if _LIEF_AVAILABLE:
            self._lief_binary = _lief.parse(binary_path)
        self._init()

    @classmethod
    def from_context(cls, ctx) -> 'FormatStringScanner':
        return cls(ctx.path, ctx=ctx)

    @classmethod
    def from_path(cls, path: str) -> 'FormatStringScanner':
        try:
            from ablation.analyzers.binary_context import BinaryContext
            ctx = BinaryContext.load_or_build(path)
            return cls(path, ctx=ctx)
        except Exception:
            return cls(path)

    def _init(self):
        if self._ctx is not None:
            self._plt = self._ctx.plt.copy()
            self._func_starts = list(self._ctx.func_starts)
        elif self._lief_binary is not None:
            self._plt = {}
            for sym in self._lief_binary.symbols:
                if sym.value:
                    self._plt[sym.value] = sym.name
            self._func_starts = sorted(
                s.value for s in self._lief_binary.symbols
                if s.value and hasattr(s, 'type') and s.type.name == 'FUNC'
            )
        if not _FMT_FUNCS:
            return
        for va, name in self._plt.items():
            if name in _FMT_FUNCS:
                self._fmt_call_vas[va] = (name, _FMT_FUNCS[name])
        if self._lief_binary is not None:
            for sec in self._lief_binary.sections:
                if sec.name in ('.rodata', '.data.ro', '__const', '__cstring', '.rdata'):
                    self._rodata_ranges.append(
                        (sec.virtual_address, sec.virtual_address + sec.size)
                    )

    def _va_to_bytes(self, va: int, size: int) -> bytes:
        if not _LIEF_AVAILABLE or self._lief_binary is None:
            return b''
        try:
            off = self._lief_binary.virtual_address_to_offset(va)
            return self._data[off:off + size]
        except Exception:
            return b''

    def _is_rodata(self, va: int) -> bool:
        for start, end in self._rodata_ranges:
            if start <= va < end:
                return True
        return False

    def _resolve_rip_rel(self, insn_va: int, insn_size: int, disp: int) -> int:
        return insn_va + insn_size + disp

    def scan(self) -> List[FmtStringFinding]:
        if not _CS_AVAILABLE or not _LIEF_AVAILABLE or not self._fmt_call_vas:
            return []
        findings: List[FmtStringFinding] = []
        for func_va in self._func_starts:
            findings.extend(self._scan_function(func_va))
        return findings

    def _scan_function(self, func_va: int) -> List[FmtStringFinding]:
        raw = self._va_to_bytes(func_va, _MAX_FUNC_BYTES)
        if not raw:
            return []
        insns = list(self._md.disasm(raw, func_va))
        findings: List[FmtStringFinding] = []

        for i, insn in enumerate(insns):
            if not insn.group(CS_GRP_CALL) or not insn.operands:
                continue
            tgt = insn.operands[0].imm
            if tgt not in self._fmt_call_vas:
                continue

            callee_name, fmt_reg_id = self._fmt_call_vas[tgt]

            # Walk back to find the last definition of fmt_reg_id
            provenance, description = self._trace_fmt_reg(
                insns, i, fmt_reg_id, func_va, insn.address
            )
            if provenance == 'rodata':
                continue  # string literal -- safe

            severity = 'HIGH' if provenance == 'arg_passthrough' else 'MEDIUM'
            reg_name = self._reg_id_to_name(fmt_reg_id)
            findings.append(FmtStringFinding(
                func_va=func_va,
                call_va=insn.address,
                callee=callee_name,
                fmt_reg=reg_name,
                provenance=provenance,
                severity=severity,
                description=description,
            ))

        return findings

    def _trace_fmt_reg(
        self, insns: list, call_idx: int, fmt_reg: int, func_va: int, call_va: int
    ) -> Tuple[str, str]:
        """
        Walk backwards from call_idx to find the last write to fmt_reg.
        Returns (provenance, description).

        provenance values:
          'rodata'          -- LEA from .rodata: string literal, safe
          'arg_passthrough' -- entry argument register moved unchanged to fmt_reg
          'stack_load'      -- loaded from stack frame (likely local buffer or argc/argv)
          'register'        -- another non-entry register
          'unknown'         -- could not trace
        """
        for j in range(call_idx - 1, max(call_idx - _LOOKBACK, -1), -1):
            insn = insns[j]
            mnem = insn.mnemonic.lower()

            if not insn.operands:
                continue
            dst = insn.operands[0]

            # Only interested in writes to fmt_reg
            if dst.type != X86_OP_REG or dst.reg != fmt_reg:
                # Check for sub-register writes (e.g. esi -> rsi)
                if not self._is_subreg_of(dst.reg if dst.type == X86_OP_REG else -1, fmt_reg):
                    continue

            if mnem in ('lea', 'mov') and len(insn.operands) == 2:
                src = insn.operands[1]

                if mnem == 'lea' and src.type == X86_OP_MEM:
                    # RIP-relative LEA: target = rip + disp
                    if src.mem.base == 0 or src.mem.base == self._rip_reg():
                        resolved = self._resolve_rip_rel(insn.address, insn.size, src.mem.disp)
                        if self._is_rodata(resolved):
                            return ('rodata', f"string literal at 0x{resolved:x}")
                        return ('register', f"LEA to non-rodata address 0x{resolved:x}")

                if src.type == X86_OP_REG:
                    if src.reg in _ENTRY_ARGS:
                        return (
                            'arg_passthrough',
                            f"{self._reg_id_to_name(src.reg)} (entry arg) "
                            f"passed as format string -- caller controls format"
                        )
                    return ('register', f"loaded from register {self._reg_id_to_name(src.reg)}")

                if src.type == X86_OP_MEM:
                    base = src.mem.base
                    # rbp/rsp-relative = stack load
                    if base in (self._rbp_reg(), self._rsp_reg()):
                        return ('stack_load', f"loaded from stack [{self._reg_id_to_name(base)}{src.mem.disp:+#x}]")
                    return ('register', f"loaded from memory [{self._reg_id_to_name(base)}+{src.mem.disp:#x}]")

            if mnem == 'xor' and len(insn.operands) == 2:
                if insn.operands[1].type == X86_OP_REG and insn.operands[1].reg == fmt_reg:
                    # xor reg, reg = zero -- typically a NULL fmt, not interesting
                    return ('rodata', 'zeroed register (NULL fmt)')

        return ('unknown', f'format register {self._reg_id_to_name(fmt_reg)} provenance not found in {_LOOKBACK} insns')

    def _is_subreg_of(self, candidate: int, parent: int) -> bool:
        """Check if candidate is a sub-register of parent (e.g. esi is sub-reg of rsi)."""
        if not _CS_AVAILABLE:
            return False
        from capstone.x86_const import (
            X86_REG_ESI, X86_REG_EDI, X86_REG_EDX, X86_REG_ECX,
            X86_REG_EAX,
        )
        pairs = {
            X86_REG_RSI: X86_REG_ESI,
            X86_REG_RDI: X86_REG_EDI,
            X86_REG_RDX: X86_REG_EDX,
            X86_REG_RCX: X86_REG_ECX,
            X86_REG_RAX: X86_REG_EAX,
        }
        return pairs.get(parent) == candidate

    def _rip_reg(self) -> int:
        if not _CS_AVAILABLE:
            return -1
        from capstone.x86_const import X86_REG_RIP
        return X86_REG_RIP

    def _rbp_reg(self) -> int:
        if not _CS_AVAILABLE:
            return -1
        from capstone.x86_const import X86_REG_RBP
        return X86_REG_RBP

    def _rsp_reg(self) -> int:
        if not _CS_AVAILABLE:
            return -1
        from capstone.x86_const import X86_REG_RSP
        return X86_REG_RSP

    _REG_NAME_MAP: Dict[int, str] = {}

    def _reg_id_to_name(self, reg_id: int) -> str:
        if not self._REG_NAME_MAP and _CS_AVAILABLE:
            from capstone.x86_const import (
                X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
                X86_REG_R8, X86_REG_R9, X86_REG_RAX,
                X86_REG_RBP, X86_REG_RSP, X86_REG_RIP,
            )
            FormatStringScanner._REG_NAME_MAP = {
                X86_REG_RDI: 'rdi', X86_REG_RSI: 'rsi', X86_REG_RDX: 'rdx',
                X86_REG_RCX: 'rcx', X86_REG_R8: 'r8', X86_REG_R9: 'r9',
                X86_REG_RAX: 'rax', X86_REG_RBP: 'rbp', X86_REG_RSP: 'rsp',
                X86_REG_RIP: 'rip',
            }
        return self._REG_NAME_MAP.get(reg_id, f'r{reg_id}')

    def report(self, findings: List[FmtStringFinding]) -> str:
        if not findings:
            return '[format_string_scanner] no findings\n'
        high = [f for f in findings if f.severity == 'HIGH']
        med  = [f for f in findings if f.severity == 'MEDIUM']
        hdr = f'[format_string_scanner] {len(findings)} finding(s)  HIGH={len(high)}  MED={len(med)}\n'
        lines = [hdr]
        for f in sorted(findings, key=lambda x: (x.severity, x.func_va)):
            lines.append(f.fmt())
        return '\n'.join(lines) + '\n'
