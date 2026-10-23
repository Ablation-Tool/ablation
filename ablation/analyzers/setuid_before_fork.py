"""
setuid_before_fork.py: SETUID privilege escalation via setuid(0)-before-fork pattern.

Why this exists
---------------
Gap discovered during HMC asmmenu analysis (session 52, 2026-10-23):
  asmmenu (SETUID root) calls setuid(0) *before* fork(), then execv()s a bash
  script in the child.  Because setuid(0) with EUID=0 sets RUID=EUID=0, the
  child process carries full root identity.  bash's SUID-dropping check
  (EUID≠RUID) never fires, so the child shell script runs as real root even
  though bash normally resets privileges when RUID≠EUID.

  SinkArgClassifier finds the execv sink and marks it RODATA_CONST (path is
  hardcoded), so the binary is silently classified as low risk.  The privilege
  escalation happens at the OS-level identity layer, not in the sink's argument,
  making it invisible to SAC/TaintTracker.

The pattern
-----------
  Within a single function:
    1. setuid(0) or seteuid(0)  — with explicit 0 argument
    2. fork()                    — in the same function, after (1)
    3. In child branch (fork()==0): execv/execve/execvp with any path

  Key constraint: (1) must come *before* (2) within the same function.  If
  setuid is called after fork, only one side of the fork gains the privilege.

Usage
-----
    from ablation.analyzers.setuid_before_fork import SetuidBeforeForkAnalyzer
    results = SetuidBeforeForkAnalyzer.from_path('/path/to/binary').scan()
    for r in results:
        print(r)

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    results = SetuidBeforeForkAnalyzer.from_context(ctx).scan()
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone

from ablation.analyzers.binary_context import BinaryContext


@dataclass
class SetuidForkFinding:
    func_va: int
    setuid_va: int
    setuid_name: str        # 'setuid' or 'seteuid'
    setuid_arg: int         # 0 = confirmed root promotion
    fork_va: int
    exec_va: int
    exec_name: str          # 'execv', 'execve', 'execvp', etc.
    exec_path: Optional[str]  # RODATA string if resolvable, else None
    arch: str
    verdict: str            # 'CONFIRMED' or 'PLAUSIBLE'
    note: str

    def __str__(self) -> str:
        path_s = repr(self.exec_path) if self.exec_path else '(unknown)'
        return (
            f"SetuidForkFinding({self.verdict}): "
            f"func@{hex(self.func_va)} | "
            f"{self.setuid_name}({self.setuid_arg})@{hex(self.setuid_va)} → "
            f"fork()@{hex(self.fork_va)} → "
            f"{self.exec_name}({path_s})@{hex(self.exec_va)}"
        )


_SETUID_FUNCS = {'setuid', 'seteuid', 'setreuid'}
_FORK_FUNCS   = {'fork', 'vfork'}
_EXEC_FUNCS   = {'execv', 'execve', 'execvp', 'execvpe', 'execl', 'execlp', 'execle'}


class SetuidBeforeForkAnalyzer:
    """
    Detects SETUID binaries where setuid(0) is called before fork()+exec in
    the same function, defeating bash SUID-dropping in the child process.
    """

    def __init__(self, ctx: BinaryContext) -> None:
        self._ctx = ctx
        self._data: bytes = open(ctx.path, 'rb').read()
        self._base_va: int = ctx.base_va

        # Map PLT names → VAs (ctx.plt is {va: name})
        self._plt: Dict[str, int] = {
            name: va for va, name in ctx.plt.items()
            if name in (*_SETUID_FUNCS, *_FORK_FUNCS, *_EXEC_FUNCS)
        }

    @classmethod
    def from_context(cls, ctx: BinaryContext) -> SetuidBeforeForkAnalyzer:
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> SetuidBeforeForkAnalyzer:
        return cls(BinaryContext.load_or_build(path))

    def _plt_name(self, va: int) -> Optional[str]:
        for name, plt_va in self._plt.items():
            if plt_va == va:
                return name
        return None

    def _read_rodata_str(self, va: int) -> Optional[str]:
        """Read null-terminated string at VA if in a readable section."""
        off = va - self._base_va
        if off < 0 or off >= len(self._data):
            return None
        null = self._data.find(b'\x00', off)
        if null < 0 or null - off > 512:
            return None
        raw = self._data[off:null]
        try:
            s = raw.decode('ascii')
            if all(32 <= ord(c) <= 126 for c in s):
                return s
        except UnicodeDecodeError:
            pass
        return None

    def _disasm_func(self, func_va: int, max_bytes: int = 1024) -> List:
        """Disassemble up to max_bytes from func_va using capstone."""
        arch = self._ctx.arch
        if arch == 'x86_64':
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
        elif arch == 'x86':
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
        else:
            return []

        off = func_va - self._base_va
        if off < 0 or off >= len(self._data):
            return []
        chunk = self._data[off:off + max_bytes]
        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = True
        return list(md.disasm(chunk, func_va))

    def _resolve_call_target(self, insn) -> Optional[int]:
        """Return target VA of a call instruction, if resolvable."""
        op_str = insn.op_str.strip()
        try:
            return int(op_str, 16)
        except ValueError:
            return None

    def _extract_edi_before(self, insns: List, call_idx: int) -> Optional[int]:
        """
        Scan backwards from call_idx to find the most recent write to
        edi/rdi (first arg in SysV x86_64 ABI).  Returns int value if it
        was a direct immediate assignment, else None.
        """
        for i in range(call_idx - 1, max(call_idx - 20, -1), -1):
            insn = insns[i]
            if insn.mnemonic in ('mov', 'xor') and insn.op_str.startswith(('edi', 'rdi')):
                parts = insn.op_str.split(',')
                if len(parts) == 2:
                    if insn.mnemonic == 'xor' and parts[0].strip() == parts[1].strip():
                        return 0
                    try:
                        return int(parts[1].strip(), 16)
                    except ValueError:
                        pass
        return None

    def _scan_func(self, func_va: int) -> List[SetuidForkFinding]:
        insns = self._disasm_func(func_va)
        if not insns:
            return []

        findings = []
        setuid_seen: List[Tuple[int, str, int]] = []  # (va, name, arg)
        fork_seen: List[int] = []

        for i, insn in enumerate(insns):
            if insn.mnemonic != 'call':
                continue
            target = self._resolve_call_target(insn)
            if target is None:
                continue
            name = self._plt_name(target)
            if name is None:
                continue

            if name in _SETUID_FUNCS:
                arg = self._extract_edi_before(insns, i)
                setuid_seen.append((insn.address, name, arg if arg is not None else -1))

            elif name in _FORK_FUNCS and setuid_seen:
                fork_seen.append(insn.address)

            elif name in _EXEC_FUNCS and setuid_seen and fork_seen:
                # setuid → fork → exec confirmed in sequence
                # Resolve exec path: scan backwards for any mov that loads a
                # RODATA path constant (contains '/').  Skip register-to-register
                # moves — only stop when we find an immediate VA that resolves.
                exec_path: Optional[str] = None
                for j in range(i - 1, max(i - 40, -1), -1):
                    pi = insns[j]
                    if pi.mnemonic != 'mov':
                        continue
                    parts = pi.op_str.split(',')
                    if len(parts) != 2:
                        continue
                    try:
                        path_va = int(parts[1].strip(), 16)
                    except ValueError:
                        continue
                    if path_va < 0x400000:
                        continue
                    s = self._read_rodata_str(path_va)
                    if s and '/' in s:
                        exec_path = s
                        break

                su = setuid_seen[0]
                confirmed = (su[2] == 0)  # setuid arg = 0

                findings.append(SetuidForkFinding(
                    func_va=func_va,
                    setuid_va=su[0],
                    setuid_name=su[1],
                    setuid_arg=su[2],
                    fork_va=fork_seen[0],
                    exec_va=insn.address,
                    exec_name=name,
                    exec_path=exec_path,
                    arch=self._ctx.arch,
                    verdict='CONFIRMED' if confirmed else 'PLAUSIBLE',
                    note='setuid(0) before fork+exec: child process runs as full root; '
                         'bash SUID-dropping defeated (RUID=EUID=0)' if confirmed else
                         f'setuid({su[2]}) before fork+exec',
                ))

        return findings

    def scan(self) -> List[SetuidForkFinding]:
        """
        Scan all functions in the binary.  For efficiency, only checks
        functions that have PLT calls to both a setuid-family function
        AND a fork-family function.
        """
        if not self._plt:
            return []

        has_setuid = any(n in self._plt for n in _SETUID_FUNCS)
        has_fork   = any(n in self._plt for n in _FORK_FUNCS)
        has_exec   = any(n in self._plt for n in _EXEC_FUNCS)
        if not (has_setuid and has_fork and has_exec):
            return []

        raw: List[SetuidForkFinding] = []
        for va in self._ctx.func_starts:
            raw.extend(self._scan_func(va))

        # Deduplicate: PLT stub scan windows may overlap into the same chain.
        # For each unique (setuid_va, fork_va, exec_va), keep the finding whose
        # func_va is the largest func_start that is still <= setuid_va
        # (i.e., the actual enclosing function, not an earlier scan window).
        all_starts = sorted(self._ctx.func_starts)
        seen: Set[Tuple[int, int, int]] = set()
        results: List[SetuidForkFinding] = []
        for f in sorted(raw, key=lambda f: (f.setuid_va, f.fork_va, f.exec_va)):
            key = (f.setuid_va, f.fork_va, f.exec_va)
            if key not in seen:
                seen.add(key)
                # Correct func_va to the enclosing function
                enclosing = f.func_va
                for s in all_starts:
                    if s <= f.setuid_va:
                        enclosing = s
                f.func_va = enclosing
                results.append(f)
        return results
