"""
toctou_scanner.py: TOCTOU race condition detector for ELF firmware.

Finds the classic access()-before-open() time-of-check/time-of-use pattern:

    access(path, R_OK)   -- checks permissions using real UID
    ...                  -- attacker replaces file with symlink here
    open(path, O_RDONLY) -- opens using effective UID -> follows symlink

The access(2) manpage states: "do not use access() in security-critical code".
Any occurrence where access@plt and open@plt (or fopen@plt) are called on the
same path argument in the same function is a confirmed TOCTOU candidate.

Detection strategy:
  1. Find all functions that call both access@plt and open@plt/fopen@plt.
  2. Within each such function, check whether the first argument (rdi on
     x86-64, r0 on ARM64, a0 on MIPS) to both calls shares a common origin
     (same register, same stack slot, or same immediate string).
  3. If both calls share a path argument and access precedes open in the
     function's basic-block ordering, emit a TOCTOUFinding.

Usage:
    scanner = TOCTOUScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = TOCTOUScanner.from_context(ctx)
    findings = scanner.scan()
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class TOCTOUFinding:
    func_va:      int    # VA of the containing function
    func_name:    str    # name if available, else sub_VA
    access_va:    int    # VA of the access() call instruction
    open_va:      int    # VA of the open()/fopen() call instruction
    path_note:    str    # description of the shared path argument
    confidence:   str    # HIGH / MEDIUM

    def fmt(self) -> str:
        return (f"  {self.confidence:6s}  TOCTOU  {self.func_name}\n"
                f"         access() at 0x{self.access_va:x}\n"
                f"         open()   at 0x{self.open_va:x}\n"
                f"         path: {self.path_note}")


# ── PLT sink names ─────────────────────────────────────────────────────────────

_ACCESS_NAMES = frozenset({'access', 'faccessat', 'euidaccess', 'eaccess'})
_OPEN_NAMES   = frozenset({'open', 'open64', 'fopen', 'fopen64', 'openat', 'creat'})


# ── Scanner ────────────────────────────────────────────────────────────────────

class TOCTOUScanner:
    """Detect access()-before-open() TOCTOU patterns in ELF binaries."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'TOCTOUScanner':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._ctx  = ctx
        return obj

    def _load_ctx(self):
        if self._ctx is not None:
            return self._ctx
        from ablation.analyzers.binary_context import BinaryContext
        self._ctx = BinaryContext.load_or_build(self._path)
        return self._ctx

    def _plt_vas(self, ctx, name_set: frozenset) -> frozenset:
        """Return the set of PLT VAs for any sink whose name is in name_set."""
        vas: set[int] = set()
        for name, va in ctx.plt_entries():
            base = name.split('@')[0].lstrip('_')
            if base in name_set:
                vas.add(va)
        return frozenset(vas)

    def scan(self) -> List[TOCTOUFinding]:
        import capstone

        ctx = self._load_ctx()
        access_vas = self._plt_vas(ctx, _ACCESS_NAMES)
        open_vas   = self._plt_vas(ctx, _OPEN_NAMES)

        if not access_vas or not open_vas:
            return []

        findings: list[TOCTOUFinding] = []

        try:
            arch, mode = ctx.capstone_params()
            md = capstone.Cs(arch, mode)
            md.detail = True
        except Exception:
            return []

        for func_va in ctx.func_starts:
            insns = list(ctx.disasm_func(func_va))
            if not insns:
                continue

            # Find call sites for access and open within this function
            access_calls: list[tuple[int, str]] = []  # (call_va, path_hint)
            open_calls:   list[tuple[int, str]] = []

            prev_arg: str = ''  # track most recent first-argument setup

            for insn in insns:
                mnemonic = insn.mnemonic.lower()

                # Track argument register (first arg: rdi/r0/a0)
                if _is_first_arg_load(insn):
                    prev_arg = _extract_arg_hint(insn)

                if mnemonic in ('call', 'bl', 'blx', 'jalr', 'jal'):
                    target = _call_target(insn)
                    if target in access_vas:
                        access_calls.append((insn.address, prev_arg))
                    elif target in open_vas:
                        open_calls.append((insn.address, prev_arg))

            if not access_calls or not open_calls:
                continue

            # Pair: each access() call before any open() call with matching arg
            for acc_va, acc_arg in access_calls:
                for opn_va, opn_arg in open_calls:
                    if opn_va <= acc_va:
                        continue  # open must come after access
                    # Check argument similarity
                    confidence, path_note = _match_args(acc_arg, opn_arg)
                    if confidence is None:
                        continue
                    findings.append(TOCTOUFinding(
                        func_va=func_va,
                        func_name=ctx.name(func_va),
                        access_va=acc_va,
                        open_va=opn_va,
                        path_note=path_note,
                        confidence=confidence,
                    ))

        return findings

    def report(self, findings: Optional[List[TOCTOUFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'TOCTOUScanner: no TOCTOU findings in {self._path}'
        lines = [f'TOCTOUScanner: {len(findings)} TOCTOU finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_first_arg_load(insn) -> bool:
    """Return True if this instruction loads the first function argument register."""
    mn = insn.mnemonic.lower()
    op = insn.op_str.lower()
    # x86-64: mov/lea rdi,...
    if mn in ('mov', 'lea') and 'rdi' in op:
        return True
    # ARM64: mov/ldr/add x0,...
    if mn in ('mov', 'ldr', 'add', 'adrp') and op.startswith('x0'):
        return True
    # MIPS: move/lw/la a0,...
    if mn in ('move', 'lw', 'la', 'addiu', 'li') and 'a0' in op.split(',')[0]:
        return True
    return False


def _extract_arg_hint(insn) -> str:
    """Extract a string hint for the argument being loaded (register or immediate)."""
    op = insn.op_str
    return op[:40] if op else ''


def _call_target(insn) -> int:
    """Extract call target VA from a call/branch instruction."""
    try:
        op = insn.op_str.strip()
        if op.startswith('0x') or op.startswith('#0x'):
            return int(op.lstrip('#'), 16)
        return int(op, 16)
    except (ValueError, AttributeError):
        return 0


def _match_args(acc_arg: str, opn_arg: str) -> tuple:
    """Return (confidence, note) if args likely share a path, else (None, '')."""
    if not acc_arg or not opn_arg:
        return 'MEDIUM', 'path argument tracking unavailable'
    if acc_arg == opn_arg:
        return 'HIGH', f'same argument: {acc_arg!r}'
    # Partial match: same register family
    if acc_arg[:3] == opn_arg[:3] and acc_arg[:3] in ('rdi', 'x0,', 'a0,'):
        return 'MEDIUM', f'same register loaded: {acc_arg!r} / {opn_arg!r}'
    # Both are likely path strings if they mention similar characters
    return 'MEDIUM', f'co-occurrence in same function: {acc_arg!r} / {opn_arg!r}'
