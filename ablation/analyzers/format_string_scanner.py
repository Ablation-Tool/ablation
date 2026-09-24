"""
format_string_scanner.py -- Format string vulnerability scanner.

Detects calls to format string sink functions (printf, syslog, err, etc.) where
the format argument is not a string literal.

Static heuristic (TAOSSA ch.8): trace the format argument register backward from
the call site. If the last write is a LEA [rip+offset] into .rodata, the format
string is a literal and the call is safe. If the last write is a MOV from a stack
slot or argument register, the format string is user-controlled and the call is
vulnerable.

Verdict classification:
  VULNERABLE  -- format reg loaded from stack slot or propagated from argument
  SUSPICIOUS  -- format reg origin not determined (dynamic, global var, etc.)
  SAFE        -- format reg loaded via LEA into .rodata

Grounded in: The Art of Software Security Assessment (Dowd et al.), ch.8
"Strings and Metacharacters", format string section.

Usage:
    scanner = FormatStringScanner('/path/to/binary')
    findings = scanner.scan()
    for f in findings:
        if f.verdict != 'SAFE':
            print(f.fmt())

    # With existing BinaryContext (avoids ELF re-parse):
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = FormatStringScanner.from_context(ctx)
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone
from capstone.x86_const import (
    X86_OP_REG, X86_OP_IMM, X86_OP_MEM,
    X86_INS_LEA, X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVZX, X86_INS_MOVSXD,
    X86_INS_MOVSS, X86_INS_MOVSD, X86_INS_MOVAPS, X86_INS_MOVDQA,
    X86_INS_ADD, X86_INS_SUB, X86_INS_XOR, X86_INS_AND, X86_INS_OR,
    X86_INS_PUSH, X86_INS_POP, X86_INS_CALL, X86_INS_RET,
    X86_INS_RETF, X86_INS_RETFQ,
)
import lief

# ── register family normalization ─────────────────────────────────────────────

_REG_FAMILY: Dict[str, str] = {}

def _build_reg_family() -> Dict[str, str]:
    families = {
        'rax': ['eax', 'ax', 'al', 'ah'],
        'rbx': ['ebx', 'bx', 'bl', 'bh'],
        'rcx': ['ecx', 'cx', 'cl', 'ch'],
        'rdx': ['edx', 'dx', 'dl', 'dh'],
        'rsi': ['esi', 'si', 'sil'],
        'rdi': ['edi', 'di', 'dil'],
        'rsp': ['esp', 'sp', 'spl'],
        'rbp': ['ebp', 'bp', 'bpl'],
        'r8':  ['r8d', 'r8w', 'r8b'],
        'r9':  ['r9d', 'r9w', 'r9b'],
        'r10': ['r10d', 'r10w', 'r10b'],
        'r11': ['r11d', 'r11w', 'r11b'],
        'r12': ['r12d', 'r12w', 'r12b'],
        'r13': ['r13d', 'r13w', 'r13b'],
        'r14': ['r14d', 'r14w', 'r14b'],
        'r15': ['r15d', 'r15w', 'r15b'],
    }
    m: Dict[str, str] = {}
    for canon, aliases in families.items():
        m[canon] = canon
        for a in aliases:
            m[a] = canon
    return m

_REG_FAMILY = _build_reg_family()


def _canon(reg: str) -> str:
    return _REG_FAMILY.get(reg.lower(), reg.lower())


# ── format string sink table ──────────────────────────────────────────────────
# Maps PLT symbol name -> format argument index (0-based, SysV x86-64 ABI)
# arg0=RDI, arg1=RSI, arg2=RDX, arg3=RCX, arg4=R8, arg5=R9

_FORMAT_SINKS: Dict[str, int] = {
    # printf family
    'printf':    0,   # printf(fmt, ...)
    'fprintf':   1,   # fprintf(fp, fmt, ...)
    'sprintf':   1,   # sprintf(buf, fmt, ...)
    'snprintf':  2,   # snprintf(buf, n, fmt, ...)
    'vprintf':   0,   # vprintf(fmt, ap)
    'vfprintf':  1,   # vfprintf(fp, fmt, ap)
    'vsprintf':  1,   # vsprintf(buf, fmt, ap)
    'vsnprintf': 2,   # vsnprintf(buf, n, fmt, ap)
    # syslog
    'syslog':    1,   # syslog(priority, fmt, ...)
    'vsyslog':   1,   # vsyslog(priority, fmt, ap)
    # BSD err/warn family
    'err':       1,   # err(status, fmt, ...)
    'errx':      1,   # errx(status, fmt, ...)
    'warn':      0,   # warn(fmt, ...)
    'warnx':     0,   # warnx(fmt, ...)
    'verr':      1,
    'verrx':     1,
    'vwarn':     0,
    'vwarnx':    0,
    # wide-char variants
    'wprintf':   0,
    'fwprintf':  1,
    'swprintf':  1,
    'vwprintf':  0,
    'vfwprintf': 1,
    'vswprintf': 1,
    # Windows variants
    '_stprintf':  1,
    '_vstprintf': 1,
    '_vtprintf':  0,
    '_wsprintfA': 1,
    '_wsprintfW': 1,
    # glibc-specific / common embedded logging patterns
    'dprintf':   1,   # dprintf(fd, fmt, ...)
    'obstack_printf': 1,
    '__printf':  0,
}

# Argument register sequence (SysV x86-64)
_ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

# Instructions that unconditionally clobber their destination register.
# Used to detect when backward scan can stop (no earlier write matters).
_CLOBBER_MNEMS: Set[str] = {
    'mov', 'movabs', 'movsx', 'movzx', 'movsxd',
    'movss', 'movsd', 'movaps', 'movdqa', 'movq', 'movd',
    'lea',
    'xor',   # handles xor reg, reg (zero) and xor reg, other (clobber)
    'add', 'sub', 'and', 'or', 'not', 'neg', 'inc', 'dec',
    'imul', 'mul', 'shl', 'shr', 'sar', 'sal', 'rol', 'ror',
    'pop',
    # SET family: write boolean to 8-bit dest
    'sete', 'setne', 'setb', 'setbe', 'seta', 'setae',
    'setl', 'setle', 'setg', 'setge', 'sets', 'setns',
    'seto', 'setno', 'setp', 'setnp',
    'bsf', 'bsr', 'popcnt', 'tzcnt', 'lzcnt', 'bswap',
}

# Max instructions to scan backward per call site
_LOOKBACK_LIMIT = 80

# Max function size to analyze
_MAX_FUNC_BYTES = 4096


# ── finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class FormatStringFinding:
    func_va: int          # owning function start VA
    call_va: int          # VA of the CALL to the format sink
    sink_name: str        # PLT symbol (e.g., 'printf')
    fmt_arg_idx: int      # which argument index is the format string
    fmt_reg: str          # register carrying the format string (e.g., 'rsi')
    verdict: str          # 'VULNERABLE', 'SUSPICIOUS', 'SAFE'
    reason: str           # human-readable explanation of verdict
    write_va: int         # VA where fmt_reg was last written (0 if not found)
    write_insn: str       # disassembly of the write instruction (for context)
    two_hop: bool = False # True if this is a two-hop (buf from vsnprintf used as fmt)

    def fmt(self) -> str:
        tag = f'[{self.verdict}]'
        hop = '  [TWO-HOP]' if self.two_hop else ''
        write_line = ''
        if self.write_va:
            write_line = f'\n  write   : 0x{self.write_va:x}  {self.write_insn}'
        return (
            f'FormatStringFinding {tag}{hop}\n'
            f'  func    : 0x{self.func_va:x}\n'
            f'  call    : 0x{self.call_va:x}  {self.sink_name}({self.fmt_reg}=?)'
            f'  [arg{self.fmt_arg_idx}]{write_line}\n'
            f'  reason  : {self.reason}\n'
        )

    def as_dict(self) -> dict:
        return {
            'func_va': hex(self.func_va),
            'call_va': hex(self.call_va),
            'sink_name': self.sink_name,
            'fmt_arg_idx': self.fmt_arg_idx,
            'verdict': self.verdict,
            'reason': self.reason,
            'write_va': hex(self.write_va) if self.write_va else None,
            'two_hop': self.two_hop,
        }


# ── section boundary helpers ──────────────────────────────────────────────────

class _SectionMap:
    """Lightweight section boundary index for RIP-relative LEA checks."""

    def __init__(self) -> None:
        # List of (start_va, end_va, name)
        self._sections: List[Tuple[int, int, str]] = []

    @classmethod
    def from_binary(cls, binary: lief.ELF.Binary) -> '_SectionMap':
        sm = cls()
        for sec in binary.sections:
            if sec.virtual_size == 0:
                continue
            sm._sections.append((
                sec.virtual_address,
                sec.virtual_address + sec.virtual_size,
                sec.name,
            ))
        return sm

    def section_at(self, va: int) -> Optional[str]:
        for start, end, name in self._sections:
            if start <= va < end:
                return name
        return None

    def is_rodata(self, va: int) -> bool:
        name = self.section_at(va)
        if name is None:
            return False
        return name in ('.rodata', '.rodata.str1.4', '.rodata.str1.8',
                        '.rdata', '__TEXT.__cstring', '.text.rodata',
                        '.data.rel.ro', '.data.rel.ro.local')


# ── backward register origin tracker ─────────────────────────────────────────

def _origin_of_reg(
    insns: list,
    call_idx: int,
    target_reg: str,
    section_map: _SectionMap,
) -> Tuple[str, int, str]:
    """
    Scan backward from call_idx in the instruction list to find the last write
    to target_reg and classify its origin.

    Returns (verdict, write_va, write_insn):
      verdict: 'SAFE' | 'VULNERABLE' | 'SUSPICIOUS'
      write_va: VA of the write instruction (0 = not found)
      write_insn: disassembly string of the write instruction
    """
    target = _canon(target_reg)

    for i in range(call_idx - 1, max(-1, call_idx - _LOOKBACK_LIMIT - 1), -1):
        insn = insns[i]
        mnem = insn.mnemonic.lower()

        # Skip instructions that don't write a register in operands[0]
        if not insn.operands:
            continue
        dest_op = insn.operands[0]
        if dest_op.type != X86_OP_REG:
            continue

        dest_canon = _canon(insn.reg_name(dest_op.reg))
        if dest_canon != target:
            continue

        # This instruction writes to our target register.
        write_insn_str = f'{insn.mnemonic} {insn.op_str}'

        # -- LEA [rip + offset] check ----------------------------------------
        if insn.id == X86_INS_LEA and len(insn.operands) == 2:
            src_op = insn.operands[1]
            if src_op.type == X86_OP_MEM:
                base = insn.reg_name(src_op.mem.base) if src_op.mem.base else ''
                if _canon(base) in ('rip', 'eip'):
                    # RIP-relative: compute target VA
                    target_va = insn.address + insn.size + src_op.mem.disp
                    if section_map.is_rodata(target_va):
                        return ('SAFE', insn.address, write_insn_str)
                    # LEA into non-.rodata (global var, writable data) -> suspicious
                    return ('SUSPICIOUS', insn.address, write_insn_str
                            + '  [LEA into non-rodata section]')

        # -- XOR reg, reg (zero) ----------------------------------------------
        if insn.id == X86_INS_XOR and len(insn.operands) == 2:
            src_op = insn.operands[1]
            if src_op.type == X86_OP_REG:
                if _canon(insn.reg_name(src_op.reg)) == target:
                    # xor rsi, rsi -> NULL format string (safe but unusual)
                    return ('SAFE', insn.address, write_insn_str + '  [xor-zero]')

        # -- MOV reg, [mem] (stack slot read) ---------------------------------
        if insn.id in (X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVZX, X86_INS_MOVSXD):
            if len(insn.operands) == 2:
                src_op = insn.operands[1]
                if src_op.type == X86_OP_MEM:
                    base = insn.reg_name(src_op.mem.base) if src_op.mem.base else ''
                    base_canon = _canon(base)
                    # Stack-relative load: format string stored on stack = user data
                    if base_canon in ('rbp', 'rsp'):
                        return ('VULNERABLE', insn.address, write_insn_str
                                + '  [stack slot -> format string]')
                    # MOV from other memory (global, struct field) -> suspicious
                    return ('SUSPICIOUS', insn.address, write_insn_str
                            + '  [memory load, origin unknown]')

                if src_op.type == X86_OP_REG:
                    src_canon = _canon(insn.reg_name(src_op.reg))
                    # MOV from an argument register -> propagated caller-controlled input
                    if src_canon in _ARG_REGS:
                        return ('VULNERABLE', insn.address, write_insn_str
                                + '  [arg register propagation]')
                    # MOV from a callee-saved register -> could be anything; recurse
                    # (treat as suspicious; full interprocedural analysis is out of scope)
                    return ('SUSPICIOUS', insn.address, write_insn_str
                            + '  [register copy, origin unknown]')

        # Any other write to target_reg (add, sub, etc.) -> clobber, suspicious origin
        if mnem in _CLOBBER_MNEMS:
            return ('SUSPICIOUS', insn.address, write_insn_str
                    + '  [computed value]')

    # Reached function boundary without finding a write:
    # The register holds its entry value (function argument).
    # For argument registers, this means the caller controls it.
    if target in _ARG_REGS:
        return ('VULNERABLE', 0, f'{target_reg} = function argument (not written in body)')
    return ('SUSPICIOUS', 0, f'{target_reg} = origin not found in {_LOOKBACK_LIMIT} insns')


# ── main scanner class ────────────────────────────────────────────────────────

class FormatStringScanner:
    """
    Scan an x86-64 ELF for format string vulnerabilities.

    Finds every call to a format-string sink function where the format argument
    is not a string literal.
    """

    def __init__(
        self,
        binary_path: str,
        func_starts: Optional[List[int]] = None,
        plt: Optional[Dict[int, str]] = None,
        text_va: int = 0,
        text_data: Optional[bytes] = None,
    ) -> None:
        self._path = Path(binary_path)
        self._func_starts = func_starts or []
        self._plt = plt or {}
        self._text_va = text_va
        self._text_data = text_data
        self._binary: Optional[lief.ELF.Binary] = None
        self._section_map: Optional[_SectionMap] = None
        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._md.detail = True

    @classmethod
    def from_path(cls, binary_path: str) -> 'FormatStringScanner':
        scanner = cls(binary_path)
        scanner._load()
        return scanner

    @classmethod
    def from_context(cls, ctx) -> 'FormatStringScanner':
        """Build from a BinaryContext (avoids ELF re-parse)."""
        scanner = cls(
            ctx.path,
            func_starts=list(ctx.func_starts),
            plt=dict(ctx.plt),
        )
        scanner._load()
        return scanner

    def _load(self) -> None:
        binary = lief.parse(str(self._path))
        if binary is None:
            raise ValueError(f'lief could not parse {self._path}')
        self._binary = binary
        self._section_map = _SectionMap.from_binary(binary)

        # Build PLT if not supplied
        if not self._plt:
            self._plt = self._build_plt(binary)

        # Build func_starts if not supplied
        if not self._func_starts:
            self._func_starts = self._build_func_starts(binary)

        # Load .text section
        text_sec = binary.get_section('.text')
        if text_sec:
            self._text_va = text_sec.virtual_address
            self._text_data = bytes(text_sec.content)

    @staticmethod
    def _build_plt(binary: lief.ELF.Binary) -> Dict[int, str]:
        plt: Dict[int, str] = {}
        for sym in binary.symbols:
            if sym.value and sym.name:
                plt[sym.value] = sym.name
        try:
            for rel in binary.pltgot_relocations:
                if rel.symbol and rel.symbol.name:
                    plt[rel.address] = rel.symbol.name
        except Exception:
            pass
        try:
            for rel in binary.relocations:
                if rel.symbol and rel.symbol.name:
                    plt[rel.address] = rel.symbol.name
        except Exception:
            pass
        return plt

    @staticmethod
    def _build_func_starts(binary: lief.ELF.Binary) -> List[int]:
        starts = set()
        for sym in binary.symbols:
            if sym.value and sym.type == lief.ELF.Symbol.TYPE.FUNC:
                starts.add(sym.value)
        return sorted(starts)

    def _va_to_slice(self, va: int, size: int) -> Optional[bytes]:
        if not self._text_data or not self._text_va:
            return None
        offset = va - self._text_va
        if offset < 0 or offset >= len(self._text_data):
            return None
        end = min(offset + size, len(self._text_data))
        return self._text_data[offset:end]

    def _get_func_end(self, func_va: int, func_starts: List[int]) -> int:
        idx = func_starts.index(func_va) if func_va in func_starts else -1
        if idx >= 0 and idx + 1 < len(func_starts):
            return func_starts[idx + 1]
        return func_va + _MAX_FUNC_BYTES

    def _reverse_plt(self) -> Dict[str, int]:
        return {name: va for va, name in self._plt.items()}

    def _sink_vas(self) -> Dict[int, Tuple[str, int]]:
        """Return {plt_va: (sink_name, fmt_arg_idx)} for all format sinks."""
        result: Dict[int, Tuple[str, int]] = {}
        for va, name in self._plt.items():
            if name in _FORMAT_SINKS:
                result[va] = (name, _FORMAT_SINKS[name])
        return result

    def scan(self) -> List[FormatStringFinding]:
        """Scan the binary and return all format string findings."""
        if not self._text_data or not self._section_map:
            return []

        sink_map = self._sink_vas()
        if not sink_map:
            return []

        func_starts = sorted(self._func_starts)
        func_start_set = set(func_starts)

        findings: List[FormatStringFinding] = []
        seen: Set[int] = set()

        # Build function end map
        func_ends: Dict[int, int] = {}
        for i, fva in enumerate(func_starts):
            fend = func_starts[i + 1] if i + 1 < len(func_starts) else fva + _MAX_FUNC_BYTES
            func_ends[fva] = fend

        # Determine function boundaries for each instruction VA
        # by scanning per-function
        for func_va in func_starts:
            func_end = func_ends[func_va]
            func_bytes = self._va_to_slice(func_va, min(func_end - func_va, _MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 8:
                continue

            try:
                insns = list(self._md.disasm(func_bytes, func_va))
            except Exception:
                continue

            if not insns:
                continue

            # Find all CALL instructions to format sinks
            for call_idx, insn in enumerate(insns):
                if insn.id != X86_INS_CALL:
                    continue
                if not insn.operands or insn.operands[0].type != X86_OP_IMM:
                    continue
                target_va = insn.operands[0].imm
                if target_va not in sink_map:
                    continue
                if insn.address in seen:
                    continue
                seen.add(insn.address)

                sink_name, fmt_arg_idx = sink_map[target_va]
                fmt_reg = _ARG_REGS[fmt_arg_idx] if fmt_arg_idx < len(_ARG_REGS) else 'rdx'

                verdict, write_va, write_insn = _origin_of_reg(
                    insns, call_idx, fmt_reg, self._section_map,
                )

                findings.append(FormatStringFinding(
                    func_va=func_va,
                    call_va=insn.address,
                    sink_name=sink_name,
                    fmt_arg_idx=fmt_arg_idx,
                    fmt_reg=fmt_reg,
                    verdict=verdict,
                    reason=write_insn,
                    write_va=write_va,
                ))

        # Two-hop detection: vsnprintf(buf, ...) followed by syslog/printf(buf)
        # Detect local buf variable passed as format arg after being the output of vsnprintf
        findings.extend(self._scan_two_hop(func_starts, func_ends))

        return findings

    def _scan_two_hop(
        self,
        func_starts: List[int],
        func_ends: Dict[int, int],
    ) -> List[FormatStringFinding]:
        """
        Two-hop pattern (TAOSSA ch.8):
          vsnprintf(buf, n, fmt, ap)  -- buf on stack
          syslog(priority, buf)       -- buf used as format string

        Detects when a stack buffer that was the OUTPUT of vsnprintf is later
        passed as the format argument to another sink.
        """
        two_hop: List[FormatStringFinding] = []

        vsnprintf_vas = {va for va, name in self._plt.items()
                         if name in ('vsnprintf', 'snprintf')}
        if not vsnprintf_vas:
            return []

        sink_map = self._sink_vas()
        if not sink_map:
            return []

        for func_va in func_starts:
            func_end = func_ends[func_va]
            func_bytes = self._va_to_slice(func_va, min(func_end - func_va, _MAX_FUNC_BYTES))
            if not func_bytes or len(func_bytes) < 8:
                continue

            try:
                insns = list(self._md.disasm(func_bytes, func_va))
            except Exception:
                continue

            # Track stack slot writes from vsnprintf output (output buf = arg0 = RDI)
            # After vsnprintf call, rax = return value (bytes written).
            # The buf is whatever was in RDI before the call. Track the stack slot
            # where RDI was sourced just before the vsnprintf call.
            vsnprintf_output_slots: Set[int] = set()  # (base, disp) tuples as ints

            for call_idx, insn in enumerate(insns):
                if insn.id != X86_INS_CALL:
                    continue
                if not insn.operands or insn.operands[0].type != X86_OP_IMM:
                    continue
                target_va = insn.operands[0].imm

                # Is this a vsnprintf call? Record the stack slot holding buf (arg0=RDI)
                if target_va in vsnprintf_vas:
                    # Trace RDI backward to a stack slot
                    v, wva, _ = _origin_of_reg(insns, call_idx, 'rdi', self._section_map)
                    if v == 'VULNERABLE' and wva:
                        # Find the actual displacement from the write instruction
                        for j in range(call_idx - 1, max(-1, call_idx - _LOOKBACK_LIMIT), -1):
                            wi = insns[j]
                            if wi.address == wva and wi.id == X86_INS_LEA:
                                if len(wi.operands) == 2:
                                    src = wi.operands[1]
                                    if src.type == X86_OP_MEM:
                                        # Encode slot as (base_reg_id * 10000 + disp)
                                        slot_key = (src.mem.base << 24) | (src.mem.disp & 0xFFFFFF)
                                        vsnprintf_output_slots.add(slot_key)
                            elif wi.address < wva:
                                break

                # Is this a format sink call? Check if its format arg came from
                # a stack slot that was a vsnprintf output buffer
                if target_va in sink_map and vsnprintf_output_slots:
                    sink_name, fmt_arg_idx = sink_map[target_va]
                    fmt_reg = _ARG_REGS[fmt_arg_idx] if fmt_arg_idx < len(_ARG_REGS) else 'rdx'

                    # Trace fmt_reg backward - look for LEA rdi/rsi, [rbp-X]
                    for j in range(call_idx - 1, max(-1, call_idx - _LOOKBACK_LIMIT), -1):
                        wi = insns[j]
                        if not wi.operands:
                            continue
                        if wi.operands[0].type != X86_OP_REG:
                            continue
                        if _canon(wi.reg_name(wi.operands[0].reg)) != _canon(fmt_reg):
                            continue
                        if wi.id == X86_INS_LEA and len(wi.operands) == 2:
                            src = wi.operands[1]
                            if src.type == X86_OP_MEM:
                                slot_key = (src.mem.base << 24) | (src.mem.disp & 0xFFFFFF)
                                if slot_key in vsnprintf_output_slots:
                                    two_hop.append(FormatStringFinding(
                                        func_va=func_va,
                                        call_va=insn.address,
                                        sink_name=sink_name,
                                        fmt_arg_idx=fmt_arg_idx,
                                        fmt_reg=fmt_reg,
                                        verdict='VULNERABLE',
                                        reason=(
                                            f'two-hop: {fmt_reg} loaded from stack slot '
                                            f'that was vsnprintf output buffer; buf passed '
                                            f'as format string to {sink_name}'
                                        ),
                                        write_va=wi.address,
                                        write_insn=f'{wi.mnemonic} {wi.op_str}',
                                        two_hop=True,
                                    ))
                        break

        return two_hop

    def report(self, findings: List[FormatStringFinding]) -> str:
        """Format findings as a report string."""
        if not findings:
            return 'FormatStringScanner: no findings\n'

        vuln = [f for f in findings if f.verdict == 'VULNERABLE']
        susp = [f for f in findings if f.verdict == 'SUSPICIOUS']
        safe = [f for f in findings if f.verdict == 'SAFE']

        lines = [
            f'FormatStringScanner: {self._path.name}',
            f'  VULNERABLE: {len(vuln)}  SUSPICIOUS: {len(susp)}  SAFE: {len(safe)}',
            '',
        ]

        for f in vuln + susp:
            lines.append(f.fmt())

        return '\n'.join(lines)
