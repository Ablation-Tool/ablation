"""
fork_exec_classifier.py: classify fork() callers in x86-64 ELF binaries as
worker processes, exec-after-fork, or exit-in-child patterns.

Background
----------
Fork() callers fall into three security-relevant patterns:

  WORKER          — child enters an event/connection loop; no exec() in child path.
                    → ELIMINATED as injection vector (no new process image loaded).

  EXEC_AFTER_FORK — child calls exec*() immediately after fork.
                    → Trace what exec() receives as argv[0] and classify further.

  EXIT_IN_CHILD   — child does minimal setup then calls exit()/_exit().
                    → ELIMINATED (child terminates before doing anything useful).

  UNKNOWN         — child branch CFG is too complex or exec could not be determined.

Manual analysis during FortiADC RE required tracing 4 fork() callers in httproxy3
(~2 hours). This module automates that to <1 second per binary.

Algorithm
---------
1. Locate fork PLT VA via .rela.plt relocations.
2. Scan for all `call <fork_plt>` sites.
3. At each call site, locate the parent/child branch split:
      test eax, eax   (or test rax, rax)
      js   <error_path>    (negative = error)
      jne  <parent_path>   (non-zero = parent, has child PID)
      <child_path starts here>   (eax == 0 = child)
4. BFS from child entry VA, bounded to _MAX_CHILD_BLOCKS basic blocks.
5. In each block, check for:
      call <exec*_plt>  → EXEC_AFTER_FORK
      call <exit_plt>   → EXIT_IN_CHILD
      indirect jmp (event loop return) → WORKER
6. If no exec/exit found within bounds → WORKER (assume event loop).

Usage:
    from ablation.analyzers.fork_exec_classifier import ForkExecClassifier

    clf = ForkExecClassifier.from_path('/path/to/binary')
    results = clf.classify()
    print(clf.report(results))

    # Filter to only EXEC_AFTER_FORK findings (need further trace)
    exec_forks = [r for r in results if r.verdict == 'EXEC_AFTER_FORK']
"""

from __future__ import annotations

import struct
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_CS_OK = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import (
        X86_OP_REG, X86_OP_MEM, X86_OP_IMM,
        X86_REG_RAX, X86_REG_EAX,
        X86_INS_TEST, X86_INS_CMP,
        X86_INS_JNE, X86_INS_JS, X86_INS_JG, X86_INS_JGE,
        X86_INS_JMP, X86_INS_RET,
        X86_INS_CALL,
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

# Re-use the shared PLT/func-start helpers from sink_arg_classifier
try:
    from .sink_arg_classifier import _extract_plt_x86, _extract_func_starts
except ImportError:
    from sink_arg_classifier import _extract_plt_x86, _extract_func_starts

# ── exec-family and exit-family sink names ────────────────────────────────────
_EXEC_SINKS: Set[str] = {
    'execve', 'execvp', 'execvpe', 'execl', 'execlp', 'execle',
    'execv', 'fexecve', 'posix_spawn', 'posix_spawnp',
    'system', 'popen',   # shell-invoking
}
_EXIT_SINKS: Set[str] = {
    'exit', '_exit', '__exit', '_Exit', 'abort',
    # NOTE: __stack_chk_fail intentionally excluded: it's in every function's
    # error path and would cause WORKER processes to be classified as EXIT_IN_CHILD.
}

# BFS depth cap for child branch walk
_MAX_CHILD_BLOCKS = 32
# Max bytes to disassemble per function
_MAX_FUNC_BYTES   = 8192
# Instruction window to search for test/jne after fork call
_BRANCH_SCAN      = 12


# ── Verdict constants ─────────────────────────────────────────────────────────
WORKER          = 'WORKER'
EXEC_AFTER_FORK = 'EXEC_AFTER_FORK'
EXIT_IN_CHILD   = 'EXIT_IN_CHILD'
UNKNOWN         = 'UNKNOWN'


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ForkCallerResult:
    """Classification result for one fork() call site."""
    caller_va:      int           # VA of the `call fork` instruction
    func_va:        int           # function containing the call
    verdict:        str           # WORKER | EXEC_AFTER_FORK | EXIT_IN_CHILD | UNKNOWN
    child_entry_va: int = 0       # VA where the child branch begins (eax==0 path)
    exec_target:    str = ''      # exec function name if EXEC_AFTER_FORK
    exec_call_va:   int = 0       # VA of exec call if EXEC_AFTER_FORK
    blocks_walked:  int = 0       # BFS blocks examined
    detail:         str = ''

    def fmt(self) -> str:
        extra = ''
        if self.verdict == EXEC_AFTER_FORK:
            extra = f'  exec={self.exec_target}@0x{self.exec_call_va:x}'
        elif self.child_entry_va:
            extra = f'  child_entry=0x{self.child_entry_va:x}'
        return (
            f"  {self.verdict:16s}  call@0x{self.caller_va:x}"
            f"  func@0x{self.func_va:x}"
            f"  blocks={self.blocks_walked}"
            f"{extra}"
            f"  {self.detail}"
        )

    def as_dict(self) -> dict:
        return {
            'caller_va':      hex(self.caller_va),
            'func_va':        hex(self.func_va),
            'verdict':        self.verdict,
            'child_entry_va': hex(self.child_entry_va),
            'exec_target':    self.exec_target,
            'exec_call_va':   hex(self.exec_call_va) if self.exec_call_va else '',
            'blocks_walked':  self.blocks_walked,
            'detail':         self.detail,
        }


# ── Classifier ────────────────────────────────────────────────────────────────

class ForkExecClassifier:
    """
    Classify fork() callers in a stripped x86-64 ELF binary.

    For each fork() call site, determines whether the child process:
      - Runs a worker event loop (WORKER → ELIMINATED)
      - Calls exec*() to load a new process image (EXEC_AFTER_FORK → investigate)
      - Calls exit() immediately (EXIT_IN_CHILD → ELIMINATED)
    """

    def __init__(self, binary_path: str):
        self._path = binary_path
        self._data: bytes = Path(binary_path).read_bytes()
        self._plt: Dict[int, str] = {}       # PLT VA → symbol name
        self._plt_rev: Dict[str, int] = {}   # symbol name → PLT VA
        self._func_starts: List[int] = []
        self._md: Optional[Cs] = None
        self._bin = None
        self._fork_plt: Optional[int] = None
        self._exec_plts: Dict[int, str] = {} # PLT VA → exec name
        self._exit_plts: Set[int] = set()
        if _CS_OK:
            self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            self._md.detail = True
        if _LIEF_OK:
            self._bin = _lief.parse(binary_path)
        self._init()

    @classmethod
    def from_path(cls, path: str) -> 'ForkExecClassifier':
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'ForkExecClassifier':
        obj = cls(ctx.path)
        obj._plt = ctx.plt.copy()
        obj._plt_rev = {v: k for k, v in obj._plt.items()}
        obj._func_starts = list(ctx.func_starts)
        obj._init_sink_plts()
        return obj

    # ── initialisation ────────────────────────────────────────────────────────

    def _init(self) -> None:
        if not _LIEF_OK or self._bin is None:
            return
        self._plt = _extract_plt_x86(self._bin, self._data)
        for va, name in self._plt.items():
            self._plt_rev[name] = va
        if not self._func_starts:
            self._func_starts = _extract_func_starts(self._bin, self._data)
        self._init_sink_plts()

    def _init_sink_plts(self) -> None:
        self._fork_plt = self._plt_rev.get('fork') or self._plt_rev.get('vfork')
        self._exec_plts = {
            va: name for va, name in self._plt.items()
            if name in _EXEC_SINKS
        }
        self._exit_plts = {
            va for va, name in self._plt.items()
            if name in _EXIT_SINKS
        }

    # ── helpers ───────────────────────────────────────────────────────────────

    def _va_to_off(self, va: int) -> int:
        if self._bin is None:
            return va
        try:
            return self._bin.virtual_address_to_offset(va)
        except Exception:
            return -1

    def _read_va(self, va: int, size: int) -> bytes:
        off = self._va_to_off(va)
        if off < 0 or off + size > len(self._data):
            return b''
        return self._data[off:off + size]

    def _find_func_start(self, va: int) -> int:
        """Return the function start that contains VA (nearest start <= va)."""
        for i in range(len(self._func_starts) - 1, -1, -1):
            if self._func_starts[i] <= va:
                return self._func_starts[i]
        return va

    # ── fork caller scan ──────────────────────────────────────────────────────

    def _find_fork_callers(self) -> List[Tuple[int, int]]:
        """Return [(caller_va, func_va), ...] for all `call fork_plt` sites."""
        if self._fork_plt is None or self._bin is None:
            return []
        results: List[Tuple[int, int]] = []
        target = self._fork_plt

        data = self._data
        for sec in self._bin.sections:
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
                if tgt_va == target:
                    func_va = self._find_func_start(call_va)
                    results.append((call_va, func_va))
        return results

    # ── child branch identification ───────────────────────────────────────────

    def _find_child_entry(
        self, insns: list, call_idx: int
    ) -> Tuple[int, int]:
        """
        After a fork() call, locate the child branch entry VA.

        Standard pattern:
            test eax, eax   (or cmp eax, 0)
            js   <error>    (eax < 0 → error)
            jne  <parent>   (eax > 0 → parent, has child PID)
            <child_entry>   (fall-through: eax == 0)

        Returns (child_entry_va, parent_entry_va). Either may be 0 if not found.
        """
        child_entry = 0
        parent_entry = 0
        seen_test = False

        for k in range(call_idx + 1, min(call_idx + _BRANCH_SCAN, len(insns))):
            insn = insns[k]
            mnem = insn.mnemonic.lower()

            if mnem in ('test', 'cmp'):
                seen_test = True
                continue

            if not seen_test:
                continue

            # js / jl = error path (ignore for child detection)
            if mnem in ('js', 'jl', 'jle', 'jng'):
                continue

            # jne / jnz / jg = parent path (has child PID > 0)
            if mnem in ('jne', 'jnz', 'jg', 'jge', 'jnle'):
                if insn.operands and insn.operands[0].type == X86_OP_IMM:
                    parent_entry = insn.operands[0].imm
                    # Fall-through of this jne = child path
                    if k + 1 < len(insns):
                        child_entry = insns[k + 1].address
                break

        return child_entry, parent_entry

    # ── child CFG BFS ─────────────────────────────────────────────────────────

    def _bfs_child(
        self,
        child_entry_va: int,
        func_bound_va: int,
    ) -> Tuple[str, str, int, int]:
        """
        BFS from child_entry_va, bounded to _MAX_CHILD_BLOCKS basic blocks.

        Returns (verdict, exec_name, exec_call_va, blocks_walked).
        """
        if not _CS_OK or self._md is None:
            return (UNKNOWN, '', 0, 0)

        visited: Set[int] = set()
        queue: deque = deque()
        queue.append(child_entry_va)
        blocks_walked = 0

        while queue and blocks_walked < _MAX_CHILD_BLOCKS:
            bb_va = queue.popleft()
            if bb_va in visited or bb_va == 0:
                continue
            visited.add(bb_va)
            blocks_walked += 1

            raw = self._read_va(bb_va, 256)
            if not raw:
                continue

            insns = list(self._md.disasm(raw, bb_va))
            for insn in insns:
                mnem = insn.mnemonic.lower()

                # Exec-class call → EXEC_AFTER_FORK
                if mnem == 'call' and insn.operands:
                    op = insn.operands[0]
                    if op.type == X86_OP_IMM:
                        tgt = op.imm
                        if tgt in self._exec_plts:
                            return (EXEC_AFTER_FORK, self._exec_plts[tgt], insn.address, blocks_walked)
                        if tgt in self._exit_plts:
                            return (EXIT_IN_CHILD, '', insn.address, blocks_walked)

                # Unconditional jump
                if mnem == 'jmp' and insn.operands:
                    op = insn.operands[0]
                    if op.type == X86_OP_IMM:
                        tgt = op.imm
                        if tgt not in visited:
                            queue.append(tgt)
                    elif op.type == X86_OP_REG:
                        # Indirect jmp (register) = dispatch or event loop return
                        return (WORKER, '', 0, blocks_walked)
                    break

                # Conditional branch: push both targets
                if (mnem.startswith('j') and mnem not in ('jmp',)
                        and insn.operands):
                    op = insn.operands[0]
                    if op.type == X86_OP_IMM and op.imm not in visited:
                        queue.append(op.imm)

                # Return without exec = worker pattern
                if mnem in ('ret', 'retq', 'retn'):
                    break

        # Exhausted search window without finding exec or exit → assume WORKER
        return (WORKER, '', 0, blocks_walked)

    # ── main classify ─────────────────────────────────────────────────────────

    def classify(self) -> List[ForkCallerResult]:
        """Classify all fork() callers in the binary."""
        if not _CS_OK or self._md is None or self._fork_plt is None:
            return []

        callers = self._find_fork_callers()
        if not callers:
            return []

        results: List[ForkCallerResult] = []
        for caller_va, func_va in callers:
            result = self._classify_one(caller_va, func_va)
            results.append(result)
        return results

    def classify_caller(self, caller_va: int) -> ForkCallerResult:
        """Classify a single fork() caller by VA."""
        func_va = self._find_func_start(caller_va)
        return self._classify_one(caller_va, func_va)

    def _classify_one(self, caller_va: int, func_va: int) -> ForkCallerResult:
        raw = self._read_va(func_va, _MAX_FUNC_BYTES)
        if not raw:
            return ForkCallerResult(caller_va=caller_va, func_va=func_va,
                                    verdict=UNKNOWN, detail='could not read function bytes')

        insns = list(self._md.disasm(raw, func_va))

        # Find call_idx (position of fork call in instruction list)
        call_idx = -1
        for i, insn in enumerate(insns):
            if insn.address == caller_va:
                call_idx = i
                break

        if call_idx < 0:
            return ForkCallerResult(caller_va=caller_va, func_va=func_va,
                                    verdict=UNKNOWN, detail='fork call VA not found in function disasm')

        # Identify child branch entry
        child_entry_va, parent_entry_va = self._find_child_entry(insns, call_idx)

        if not child_entry_va:
            return ForkCallerResult(
                caller_va=caller_va, func_va=func_va,
                verdict=UNKNOWN,
                detail='could not identify child branch (no test/jne pattern after call)'
            )

        # BFS child branch
        func_end_va = insns[-1].address if insns else func_va + _MAX_FUNC_BYTES
        verdict, exec_name, exec_call_va, blocks = self._bfs_child(
            child_entry_va, func_end_va
        )

        return ForkCallerResult(
            caller_va=caller_va,
            func_va=func_va,
            verdict=verdict,
            child_entry_va=child_entry_va,
            exec_target=exec_name,
            exec_call_va=exec_call_va,
            blocks_walked=blocks,
            detail=f'child_entry=0x{child_entry_va:x} parent_entry=0x{parent_entry_va:x}',
        )

    # ── reporting ─────────────────────────────────────────────────────────────

    def report(self, results: List[ForkCallerResult]) -> str:
        if not results:
            if self._fork_plt is None:
                return '[fork_exec_classifier] fork() not imported by this binary\n'
            return '[fork_exec_classifier] no fork() callers found\n'

        counts: Dict[str, int] = {}
        for r in results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1

        hdr = (
            f'[fork_exec_classifier] {len(results)} fork() caller(s)  fork_plt=0x{self._fork_plt or 0:x}  '
            + '  '.join(f'{k}={v}' for k, v in sorted(counts.items()))
            + '\n'
        )
        lines = [hdr]
        for r in sorted(results, key=lambda x: x.caller_va):
            lines.append(r.fmt())
        return '\n'.join(lines) + '\n'


# ── CLI ───────────────────────────────────────────────────────────────────────

def _cli() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='Classify fork() callers as WORKER/EXEC_AFTER_FORK/EXIT_IN_CHILD')
    ap.add_argument('binary')
    ap.add_argument('--exec-only', action='store_true',
                    help='Show only EXEC_AFTER_FORK results')
    ap.add_argument('--caller', type=lambda x: int(x, 0),
                    help='Classify a single caller at this VA')
    args = ap.parse_args()

    clf = ForkExecClassifier.from_path(args.binary)

    if args.caller:
        r = clf.classify_caller(args.caller)
        print(clf.report([r]))
        return

    results = clf.classify()
    if args.exec_only:
        results = [r for r in results if r.verdict == EXEC_AFTER_FORK]
    print(clf.report(results))


if __name__ == '__main__':
    _cli()
