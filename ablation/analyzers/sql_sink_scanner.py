"""
sql_sink_scanner.py: detect raw SQL injection in C/C++ ELF binaries that call the
MySQL C API or SQLite3 directly, without a prepared-statement layer.

Classic pattern caught by this scanner:

    snprintf(buf, sizeof(buf), "SELECT ... WHERE login='%s'", username);
    mysql_query(conn, buf);   // SQL injection if username is user-controlled

FormatStringScanner misses this because snprintf is safe by itself.
SqlSinkScanner specifically chains: find SQL sink → trace SQL arg → find format
string builder → inspect format string for %s injection specifiers.

Verdicts:
  INJECTABLE          — format string has %s; argument is not RODATA; high-confidence
  INJECTABLE_LITERAL  — SQL literal in RODATA already contains %s
  RODATA_CONST        — SQL string is a RODATA literal with no %s; safe
  SAFE_NUMERIC        — format string has only %d/%u/%x/etc; no string interpolation
  ARG_PROPAGATED      — SQL string came from an entry-argument register; caller controls it
  UNKNOWN             — provenance not resolved within look-back window

Covered sinks:
  mysql_query(conn, sql)              → RSI (arg1)
  mysql_real_query(conn, sql, len)    → RSI (arg1)
  sqlite3_exec(db, sql, ...)          → RSI (arg1)
  sqlite3_prepare_v2(db, sql, ...)    → RSI (arg1)
  sqlite3_prepare(db, sql, ...)       → RSI (arg1)

Usage:
    from ablation.analyzers.sql_sink_scanner import SqlSinkScanner

    scanner = SqlSinkScanner.from_path('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    # Filter to injection candidates only
    injections = [f for f in findings if f.verdict == SqlSinkScanner.INJECTABLE]

CLI:
    python3 -m ablation.analyzers.sql_sink_scanner /path/to/binary
"""

from __future__ import annotations

import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Reuse PLT extraction and function-start helpers from sink_arg_classifier.
# These are stable internal helpers (prefixed _) but deliberately shared to
# avoid duplication across scanners in this module.
from ablation.analyzers.sink_arg_classifier import (
    _extract_plt_x86,
    _count_plt_callers,
    _extract_func_starts,
    _SUBREG_CANON,
    _SNPRINTF_FMT_POS,
)

_CS_OK = False
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import (
        X86_OP_REG, X86_OP_MEM, X86_OP_IMM,
        X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX,
        X86_REG_R8,  X86_REG_R9,  X86_REG_RAX, X86_REG_RIP,
        X86_REG_RBP, X86_REG_RSP,
        X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
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

# ── Constants ─────────────────────────────────────────────────────────────────

_LOOKBACK   = 40   # instructions to scan backward from sink call
_MAX_FN_SZ  = 8192  # max bytes to disassemble for a function

# SQL sink definitions: symbol name → SQL string arg position (0-indexed, SysV AMD64)
_SQL_SINKS: Dict[str, int] = {
    'mysql_query':        1,   # mysql_query(MYSQL *conn, const char *q)
    'mysql_real_query':   1,   # mysql_real_query(MYSQL *conn, const char *q, unsigned long length)
    'sqlite3_exec':       1,   # sqlite3_exec(sqlite3 *db, const char *sql, ...)
    'sqlite3_prepare_v2': 1,   # sqlite3_prepare_v2(sqlite3 *db, const char *zSql, ...)
    'sqlite3_prepare':    1,   # sqlite3_prepare(sqlite3 *db, const char *zSql, ...)
}

# Arg position → SysV AMD64 register constant
_ARG_REGS: List[int] = []
if _CS_OK:
    _ARG_REGS = [X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX, X86_REG_R8, X86_REG_R9]

# Entry-argument registers (function parameters on entry)
_ENTRY_ARGS: Set[int] = set()
if _CS_OK:
    _ENTRY_ARGS = {X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX, X86_REG_R8, X86_REG_R9}

# %s-style (string) specifiers that introduce SQL injection risk
_STRING_SPECIFIERS = re.compile(r'%[-+ #0]*\d*\.?\d*[hlLzjt]*s')
# Numeric-only specifier (safe — no string interpolation)
_NUMERIC_SPECIFIERS = re.compile(r'%[-+ #0]*\d*\.?\d*[hlLzjt]*[diouxXeEfgGpn]')


# ── Verdict constants ─────────────────────────────────────────────────────────

INJECTABLE          = 'INJECTABLE'
INJECTABLE_LITERAL  = 'INJECTABLE_LITERAL'
RODATA_CONST        = 'RODATA_CONST'
SAFE_NUMERIC        = 'SAFE_NUMERIC'
ARG_PROPAGATED      = 'ARG_PROPAGATED'
UNKNOWN             = 'UNKNOWN'


# ── Data class ────────────────────────────────────────────────────────────────

@dataclass
class SqlFinding:
    sink_name:   str
    call_va:     int
    func_va:     int
    verdict:     str
    fmt_string:  str   # format string literal, empty if not resolved
    fmt_va:      int   # VA of format string in RODATA, 0 if unknown
    description: str

    def __post_init__(self):
        pass

    @property
    def severity(self) -> str:
        return {
            INJECTABLE:         'HIGH',
            INJECTABLE_LITERAL: 'HIGH',
            ARG_PROPAGATED:     'HIGH',
            UNKNOWN:            'MEDIUM',
            SAFE_NUMERIC:       'LOW',
            RODATA_CONST:       'LOW',
        }.get(self.verdict, 'MEDIUM')

    def fmt(self) -> str:
        frag = f'  fmt={repr(self.fmt_string[:80])}' if self.fmt_string else ''
        return (
            f"  {self.severity:6s}  {self.verdict:22s}  "
            f"func@0x{self.func_va:x}  call@0x{self.call_va:x}  "
            f"{self.sink_name}{frag}"
        )

    def as_dict(self) -> dict:
        return {
            'sink':        self.sink_name,
            'call_va':     hex(self.call_va),
            'func_va':     hex(self.func_va),
            'verdict':     self.verdict,
            'severity':    self.severity,
            'fmt_string':  self.fmt_string,
            'fmt_va':      hex(self.fmt_va) if self.fmt_va else '',
            'description': self.description,
        }


# ── Scanner ───────────────────────────────────────────────────────────────────

class SqlSinkScanner:
    """
    Detect raw SQL injection candidates in x86-64 ELF binaries.

    Covers MySQL C API (mysql_query, mysql_real_query) and SQLite3
    (sqlite3_exec, sqlite3_prepare_v2, sqlite3_prepare).

    Algorithm:
      1. Find all SQL sink call sites via PLT resolution.
      2. For each call site, disassemble the enclosing function and walk
         backward from the call to trace the SQL string argument register.
      3. Classify based on provenance:
         - RODATA literal → RODATA_CONST (check for %s → INJECTABLE_LITERAL)
         - snprintf-built stack buffer → inspect format string for %s →
           INJECTABLE or SAFE_NUMERIC
         - Entry register → ARG_PROPAGATED
         - Unresolved → UNKNOWN
    """

    INJECTABLE          = INJECTABLE
    INJECTABLE_LITERAL  = INJECTABLE_LITERAL
    RODATA_CONST        = RODATA_CONST
    SAFE_NUMERIC        = SAFE_NUMERIC
    ARG_PROPAGATED      = ARG_PROPAGATED
    UNKNOWN             = UNKNOWN

    def __init__(self, binary_path: str):
        self._path  = binary_path
        self._data  = Path(binary_path).read_bytes()
        self._bin   = None
        self._plt:  Dict[int, str] = {}
        self._plt_rev: Dict[str, int] = {}
        self._rodata: List[Tuple[int, int]] = []
        self._func_starts: List[int] = []
        self._snprintf_plts: Dict[int, int] = {}   # plt_va → fmt_arg_pos
        self._plt_caller_counts: Dict[int, int] = {}
        self._dead_sinks: List[str] = []
        self._md: Optional[Cs] = None

        if _CS_OK:
            self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._md.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(binary_path)
        self._init()

    @classmethod
    def from_path(cls, path: str) -> 'SqlSinkScanner':
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'SqlSinkScanner':
        obj = cls.__new__(cls)
        obj._path  = ctx.path
        obj._data  = Path(ctx.path).read_bytes()
        obj._bin   = _lief.parse(ctx.path) if _LIEF_OK else None
        obj._plt   = dict(ctx.plt)
        obj._plt_rev = {v: k for k, v in ctx.plt.items()}
        obj._rodata = []
        obj._func_starts = list(ctx.func_starts)
        obj._snprintf_plts = {}
        obj._plt_caller_counts = {}
        obj._dead_sinks = []
        obj._md = Cs(CS_ARCH_X86, CS_MODE_64) if _CS_OK else None
        if obj._md:
            obj._md.detail = True
        if obj._bin:
            for sec in obj._bin.sections:
                if sec.name in ('.rodata', '.rodata1', '__const', '__cstring', '.rdata'):
                    obj._rodata.append((sec.virtual_address, sec.virtual_address + sec.size))
        obj._plt_caller_counts = _count_plt_callers(obj._bin, obj._data) if obj._bin else {}
        obj._init_snprintf_plts()
        return obj

    # ── initialisation ─────────────────────────────────────────────────────────

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        self._plt = _extract_plt_x86(self._bin, self._data)
        self._plt_rev = {v: k for k, v in self._plt.items()}
        if not self._func_starts:
            self._func_starts = _extract_func_starts(self._bin, self._data)
        for sec in self._bin.sections:
            if sec.name in ('.rodata', '.rodata1', '__const', '__cstring', '.rdata'):
                self._rodata.append((sec.virtual_address, sec.virtual_address + sec.size))
        self._plt_caller_counts = _count_plt_callers(self._bin, self._data)
        self._init_snprintf_plts()

    def _init_snprintf_plts(self) -> None:
        for name, fmt_pos in _SNPRINTF_FMT_POS.items():
            va = self._plt_rev.get(name)
            if va:
                self._snprintf_plts[va] = fmt_pos

    # ── helpers ────────────────────────────────────────────────────────────────

    def _va_to_file_offset(self, va: int) -> int:
        if self._bin is None:
            return va
        try:
            return self._bin.virtual_address_to_offset(va)
        except Exception:
            return -1

    def _read_cstring(self, va: int, maxlen: int = 256) -> str:
        off = self._va_to_file_offset(va)
        if off < 0 or off >= len(self._data):
            return ''
        raw = self._data[off:off + maxlen]
        nul = raw.find(b'\x00')
        s = raw[:nul if nul >= 0 else maxlen]
        try:
            return s.decode('utf-8', 'replace')
        except Exception:
            return ''

    def _is_rodata(self, va: int) -> bool:
        return any(s <= va < e for s, e in self._rodata)

    def _reg_canon(self, reg_id: int) -> str:
        if self._md is None:
            return f'r?{reg_id}'
        return _SUBREG_CANON.get(self._md.reg_name(reg_id), self._md.reg_name(reg_id))

    def _writes_reg(self, insn, canon: str) -> bool:
        if not insn.operands:
            return False
        dst = insn.operands[0]
        return dst.type == X86_OP_REG and self._reg_canon(dst.reg) == canon

    def _rip_target(self, insn) -> int:
        if len(insn.operands) < 2:
            return -1
        src = insn.operands[1]
        if src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP:
            return insn.address + insn.size + src.mem.disp
        return -1

    def _classify_sql_arg(self, insns: list, call_idx: int) -> Tuple[str, str, str, int]:
        """
        Walk backward from call_idx to trace the SQL arg register (rsi = arg1).
        Returns (verdict, description, fmt_string, fmt_va).
        """
        target = 'rsi'   # arg1 = SQL string

        limit = max(call_idx - _LOOKBACK, -1)
        for j in range(call_idx - 1, limit, -1):
            insn = insns[j]
            mnem = insn.mnemonic.lower()
            if not insn.operands or not self._writes_reg(insn, target):
                continue

            # case 1: LEA rsi, [rip+N] → direct RODATA reference
            if mnem == 'lea':
                tgt = self._rip_target(insn)
                if tgt > 0 and self._is_rodata(tgt):
                    sql_lit = self._read_cstring(tgt)
                    if _STRING_SPECIFIERS.search(sql_lit):
                        return (INJECTABLE_LITERAL, f'SQL literal @ 0x{tgt:x} contains %s', sql_lit, tgt)
                    return (RODATA_CONST, f'RODATA literal @ 0x{tgt:x}', sql_lit, tgt)
                if tgt > 0:
                    return (UNKNOWN, f'LEA [rip+0x{tgt:x}] not in .rodata', '', 0)

                # LEA rsi, [rbp/rsp+N] — address of a local stack buffer
                src = insn.operands[1]
                if src.type == X86_OP_MEM:
                    base = self._reg_canon(src.mem.base) if src.mem.base else ''
                    if base in ('rsp', 'rbp'):
                        slot = (base, src.mem.disp)
                        return self._find_snprintf_for_slot(insns, call_idx, slot)

            # case 2: MOV rsi, <reg>
            elif mnem in ('mov', 'movsx', 'movzx', 'movsxd'):
                src = insn.operands[1]
                if src.type == X86_OP_REG:
                    if src.reg in _ENTRY_ARGS:
                        return (ARG_PROPAGATED, f'from entry register {self._reg_canon(src.reg)}', '', 0)
                    # Follow the chain one level
                    new_target = self._reg_canon(src.reg)
                    target = new_target
                    continue
                if src.type == X86_OP_MEM:
                    # Stack load — look for snprintf filling this slot
                    base = self._reg_canon(src.mem.base) if src.mem.base else ''
                    if base in ('rsp', 'rbp'):
                        slot = (base, src.mem.disp)
                        return self._find_snprintf_for_slot(insns, call_idx, slot)

        return (UNKNOWN, 'provenance not resolved in look-back window', '', 0)

    def _find_snprintf_for_slot(
        self,
        insns: list,
        from_idx: int,
        slot: Tuple[str, int],
    ) -> Tuple[str, str, str, int]:
        """
        Search backward from from_idx for a snprintf call that writes to `slot`.
        Returns (verdict, description, fmt_string, fmt_va).
        """
        limit = max(from_idx - _LOOKBACK * 2, -1)
        for j in range(from_idx - 1, limit, -1):
            insn = insns[j]
            mnem = insn.mnemonic.lower()
            if mnem != 'call':
                continue
            if not insn.operands:
                continue
            op = insn.operands[0]
            if op.type != X86_OP_IMM:
                continue
            callee_va = op.imm
            if callee_va not in self._snprintf_plts:
                continue
            fmt_arg_pos = self._snprintf_plts[callee_va]
            # Find fmt register for this snprintf call
            fmt_reg_canon = _SUBREG_CANON.get(
                ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'][fmt_arg_pos]
                if fmt_arg_pos < 6 else 'rdx',
                'rdx',
            )
            # Walk backward from this call to find fmt arg
            fmt_limit = max(j - _LOOKBACK, -1)
            for k in range(j - 1, fmt_limit, -1):
                fi = insns[k]
                if not fi.operands or not self._writes_reg(fi, fmt_reg_canon):
                    continue
                fm = fi.mnemonic.lower()
                if fm == 'lea':
                    tgt = self._rip_target(fi)
                    if tgt > 0 and self._is_rodata(tgt):
                        fmt_str = self._read_cstring(tgt)
                        if _STRING_SPECIFIERS.search(fmt_str):
                            return (INJECTABLE, f'snprintf fmt @ 0x{tgt:x} has %s', fmt_str, tgt)
                        if _NUMERIC_SPECIFIERS.search(fmt_str):
                            return (SAFE_NUMERIC, f'snprintf fmt @ 0x{tgt:x} numeric only', fmt_str, tgt)
                        return (RODATA_CONST, f'snprintf fmt @ 0x{tgt:x} no injection specifiers', fmt_str, tgt)
                elif fm in ('mov', 'movabs'):
                    # movabs rX, imm64 — may embed a short format string address
                    src = fi.operands[1]
                    if src.type == X86_OP_IMM and self._is_rodata(src.imm):
                        fmt_str = self._read_cstring(src.imm)
                        if _STRING_SPECIFIERS.search(fmt_str):
                            return (INJECTABLE, f'snprintf fmt imm @ 0x{src.imm:x} has %s', fmt_str, src.imm)
                        if _NUMERIC_SPECIFIERS.search(fmt_str):
                            return (SAFE_NUMERIC, f'fmt imm @ 0x{src.imm:x} numeric only', fmt_str, src.imm)
                break
        return (UNKNOWN, 'snprintf not found for stack slot', '', 0)

    def _enclosing_func_va(self, call_va: int) -> int:
        """Return VA of the nearest function start <= call_va."""
        best = 0
        for fs in self._func_starts:
            if fs <= call_va:
                best = fs
            else:
                break
        return best

    # ── main scan ──────────────────────────────────────────────────────────────

    def scan(self) -> List[SqlFinding]:
        if not _CS_OK or not _LIEF_OK or self._md is None or self._bin is None:
            return []

        # Build {plt_va: (sink_name, arg_pos)} for live SQL sinks
        active_sinks: Dict[int, Tuple[str, int]] = {}
        self._dead_sinks = []
        for name, arg_pos in _SQL_SINKS.items():
            va = self._plt_rev.get(name)
            if not va:
                continue
            if self._plt_caller_counts.get(va, 0) == 0:
                self._dead_sinks.append(name)
            else:
                active_sinks[va] = (name, arg_pos)

        if not active_sinks:
            return []

        # Collect all call sites to active SQL sinks via single pass over executable sections
        call_sites: List[Tuple[int, int, str]] = []  # (call_va, sink_plt_va, sink_name)
        for sec in self._bin.sections:
            if not (int(getattr(sec, 'flags', 0)) & 0x4):   # SHF_EXECINSTR
                continue
            sec_data = self._data[sec.offset:sec.offset + sec.size]
            sec_va   = sec.virtual_address
            for i in range(len(sec_data) - 5):
                if sec_data[i] != 0xe8:
                    continue
                rel    = struct.unpack_from('<i', sec_data, i + 1)[0]
                cva    = sec_va + i
                target = cva + 5 + rel
                if target in active_sinks:
                    call_sites.append((cva, target, active_sinks[target][0]))

        findings: List[SqlFinding] = []

        for call_va, sink_plt_va, sink_name in call_sites:
            func_va = self._enclosing_func_va(call_va)

            # Disassemble the enclosing function
            fn_off  = self._va_to_file_offset(func_va)
            fn_data = self._data[fn_off:fn_off + _MAX_FN_SZ] if fn_off >= 0 else b''
            if not fn_data:
                findings.append(SqlFinding(
                    sink_name=sink_name, call_va=call_va, func_va=func_va,
                    verdict=UNKNOWN, fmt_string='', fmt_va=0,
                    description='could not read function bytes',
                ))
                continue

            insns = list(self._md.disasm(fn_data, func_va))

            # Find the index of our call within the disassembly
            call_idx = next(
                (i for i, ins in enumerate(insns) if ins.address == call_va), None
            )
            if call_idx is None:
                findings.append(SqlFinding(
                    sink_name=sink_name, call_va=call_va, func_va=func_va,
                    verdict=UNKNOWN, fmt_string='', fmt_va=0,
                    description='call site not found in disassembly',
                ))
                continue

            verdict, desc, fmt_str, fmt_va = self._classify_sql_arg(insns, call_idx)

            findings.append(SqlFinding(
                sink_name=sink_name,
                call_va=call_va,
                func_va=func_va,
                verdict=verdict,
                fmt_string=fmt_str,
                fmt_va=fmt_va,
                description=desc,
            ))

        return findings

    # ── reporting ──────────────────────────────────────────────────────────────

    def report(self, findings: List[SqlFinding]) -> str:
        lines = [f'SqlSinkScanner: {self._path}']
        if self._dead_sinks:
            lines.append(f'  Dead imports (0 callers): {", ".join(self._dead_sinks)}')
        if not findings:
            lines.append('  No SQL sink call sites found.')
            return '\n'.join(lines)
        by_verdict: Dict[str, List[SqlFinding]] = {}
        for f in findings:
            by_verdict.setdefault(f.verdict, []).append(f)
        for verdict in [INJECTABLE, INJECTABLE_LITERAL, ARG_PROPAGATED, UNKNOWN, SAFE_NUMERIC, RODATA_CONST]:
            group = by_verdict.get(verdict, [])
            if group:
                lines.append(f'\n  [{verdict}] ({len(group)} site(s))')
                for f in group:
                    lines.append(f.fmt())
        return '\n'.join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        print(f'Usage: python3 -m ablation.analyzers.sql_sink_scanner <binary>')
        sys.exit(1)
    scanner  = SqlSinkScanner.from_path(sys.argv[1])
    findings = scanner.scan()
    print(scanner.report(findings))
    highs = [f for f in findings if f.severity == 'HIGH']
    if highs:
        sys.exit(2)  # non-zero exit when HIGH findings found


if __name__ == '__main__':
    main()
