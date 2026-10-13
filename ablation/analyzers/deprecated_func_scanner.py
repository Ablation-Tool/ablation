"""
deprecated_func_scanner.py — Inherently unsafe deprecated function detector.

4 things that weren't possible before in Ablation:

1. **Detect CWE-242 without taint analysis.** gets(), mktemp(), tmpnam(), and
   getwd() have no safe use — their mere presence in PLT is a confirmed finding
   regardless of call context. No taint path needed.

2. **Calculate overflow offset at each gets() call site.** For gets() calls
   where the destination buffer is at [rbp-N], the module extracts N from the
   preceding LEA instruction and reports the exact byte count needed to reach
   the saved RIP. Defenders get a direct exploit primitive.

3. **Report the reachability chain per call site.** Using call_edges from
   BinaryContext, the module walks one level up the call graph to show which
   functions can trigger each gets() call. This replaces manual call graph
   tracing that was previously needed before every taint run.

4. **Distinguish CWE-377 (race conditions in temp file creation) from
   CWE-121 (stack overflow).** mktemp/tmpnam findings are tagged separately
   from gets/getwd stack findings so triagers can prioritize correctly.

Usage:
    scanner = DeprecatedFuncScanner.from_context(ctx)
    hits = scanner.scan()
    print(scanner.report(hits))

    # Direct path (builds context internally):
    scanner = DeprecatedFuncScanner.from_path('/path/to/binary')
    hits = scanner.scan()
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone

from ablation.analyzers.binary_context import BinaryContext


# ── Dangerous function metadata ───────────────────────────────────────────────

_DANGEROUS: Dict[str, dict] = {
    'gets':   {'cwe': 'CWE-242/CWE-121', 'overflow': True,
               'reason': 'reads stdin with no bounds check'},
    'getwd':  {'cwe': 'CWE-242/CWE-121', 'overflow': True,
               'reason': 'unbounded getcwd alternative'},
    'mktemp': {'cwe': 'CWE-242/CWE-377', 'overflow': False,
               'reason': 'predictable temp filename (race condition)'},
    'tmpnam': {'cwe': 'CWE-242/CWE-377', 'overflow': False,
               'reason': 'predictable temp filename (race condition)'},
}

# ── Hit dataclass ─────────────────────────────────────────────────────────────

@dataclass
class DeprecatedHit:
    va: int               # VA of the call instruction
    func_va: int          # VA of the containing function
    func_name: str        # name of the containing function
    plt_name: str         # the dangerous function (gets, mktemp, etc.)
    cwe: str              # CWE class (CWE-242/CWE-121 or CWE-242/CWE-377)
    reason: str           # one-line description
    buf_size: int = -1    # -1 = unknown; bytes from buf start to frame base
    frame_size: int = -1  # -1 = unknown; total frame allocation
    overflow_offset: int = -1  # -1 = unknown; bytes to overwrite saved RIP
    callers: List[str] = field(default_factory=list)

    def fmt(self) -> str:
        parts = [
            f"[{self.cwe}] {self.plt_name}() call at {self.va:#x}",
            f"  in:     {self.func_name or f'{self.func_va:#x}'}",
            f"  reason: {self.reason}",
        ]
        if self.buf_size >= 0:
            parts.append(f"  buf:    {self.buf_size} bytes at [rbp-{self.buf_size:#x}]")
        if self.overflow_offset >= 0:
            parts.append(f"  overflow_offset: {self.overflow_offset:#x} ({self.overflow_offset}) bytes to saved RIP")
        if self.callers:
            parts.append(f"  callers: {', '.join(self.callers)}")
        return "\n".join(parts)


# ── Scanner ───────────────────────────────────────────────────────────────────

class DeprecatedFuncScanner:
    """
    Finds calls to inherently unsafe libc functions: gets, mktemp, tmpnam, getwd.

    For gets() and getwd(), the module also estimates the stack buffer size and
    overflow offset by inspecting the LEA/MOV sequence before each call site.
    """

    def __init__(self, ctx: BinaryContext) -> None:
        self._ctx = ctx
        if not ctx.path:
            raise ValueError("BinaryContext has no binary path — cannot read bytes")
        self._data = Path(ctx.path).read_bytes()
        self._base = ctx.base_va
        self._plt_rev: Dict[int, str] = {va: name for va, name in ctx.plt.items()}
        self._exp_rev: Dict[int, str] = {va: name for va, name in ctx.exports.items()}
        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._md.detail = True

    @classmethod
    def from_context(cls, ctx: BinaryContext) -> 'DeprecatedFuncScanner':
        return cls(ctx)

    @classmethod
    def from_path(cls, path: str) -> 'DeprecatedFuncScanner':
        return cls(BinaryContext.load_or_build(path))

    # -- internal helpers ------------------------------------------------------

    def _disasm(self, start_va: int, max_bytes: int = 512):
        off = start_va - self._base
        if off < 0 or off >= len(self._data):
            return []
        chunk = self._data[off:off + max_bytes]
        return list(self._md.disasm(chunk, start_va))

    def _frame_size(self, func_va: int) -> int:
        """Extract frame allocation from `sub rsp, N` in function prologue."""
        for insn in self._disasm(func_va, 48):
            if insn.mnemonic == 'sub' and 'rsp' in insn.op_str:
                if insn.operands and len(insn.operands) >= 2:
                    op = insn.operands[1]
                    if op.type == capstone.x86.X86_OP_IMM:
                        return op.imm
            if insn.mnemonic == 'ret':
                break
        return -1

    def _gets_buf_size(self, call_va: int, max_lookback: int = 128) -> int:
        """
        Read backward from a gets() call to find the buffer size.

        Recognises:
          lea rax, [rbp - N]  ;  mov rdi, rax
          lea rdi, [rbp - N]
        Returns N, or -1 if pattern not found.
        """
        # Disassemble the function containing call_va from its start
        func_va = self._find_func_start(call_va)
        if func_va < 0:
            return -1

        insns = []
        for insn in self._disasm(func_va, min(call_va - func_va + 16, 4096)):
            insns.append(insn)
            if insn.address >= call_va:
                break

        # Walk backward through recent instructions
        rbp_offset: Optional[int] = None
        for insn in reversed(insns[-24:]):
            if insn.address >= call_va:
                continue
            # lea rdi, [rbp - N]
            if insn.mnemonic == 'lea' and 'rdi' in insn.op_str:
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == capstone.x86.X86_OP_MEM:
                    mem = ops[1].mem
                    if mem.base == capstone.x86.X86_REG_RBP and mem.disp < 0:
                        return -mem.disp
            # lea rax, [rbp - N]  (will be moved to rdi by next MOV)
            if insn.mnemonic == 'lea' and ('rax' in insn.op_str or 'rcx' in insn.op_str
                                            or 'rdx' in insn.op_str):
                ops = insn.operands
                if len(ops) >= 2 and ops[1].type == capstone.x86.X86_OP_MEM:
                    mem = ops[1].mem
                    if mem.base == capstone.x86.X86_REG_RBP and mem.disp < 0:
                        rbp_offset = -mem.disp
            # mov rdi, rax (or similar) right after a lea rax, [rbp-N]
            if rbp_offset is not None and insn.mnemonic == 'mov':
                if 'rdi' in insn.op_str or 'edi' in insn.op_str:
                    return rbp_offset
        return -1

    def _find_func_start(self, va: int) -> int:
        """Find the function start VA that contains the given VA."""
        func_starts = sorted(self._ctx.func_starts)
        if not func_starts:
            return -1
        idx = bisect.bisect_right(func_starts, va) - 1
        return func_starts[idx] if idx >= 0 else -1

    def _callers_of(self, func_va: int) -> List[str]:
        """Return names of functions that call func_va, from call_edges."""
        caller_vas: Set[int] = set()
        for edge in self._ctx.call_edges:
            caller_va, callee_va, _ = edge
            if callee_va == func_va:
                caller_vas.add(caller_va)
        result = []
        for cva in caller_vas:
            name = self._ctx.name(cva) or self._exp_rev.get(cva) or f'{cva:#x}'
            result.append(name)
        return result

    # -- scan ------------------------------------------------------------------

    def scan(self) -> List[DeprecatedHit]:
        """
        Scan for dangerous function call sites.

        Returns one DeprecatedHit per call site (not per import).
        """
        hits: List[DeprecatedHit] = []
        seen_call_vas: Set[int] = set()

        # Build PLT -> dangerous name map (only functions we care about)
        targets: Dict[int, str] = {}
        for plt_va, name in self._ctx.plt.items():
            base_name = name.split('@')[0]
            if base_name in _DANGEROUS:
                targets[plt_va] = base_name

        if not targets:
            return hits

        # Walk all function starts and find call sites
        sorted_starts = sorted(self._ctx.func_starts)
        for idx, func_va in enumerate(sorted_starts):
            func_name = (self._ctx.name(func_va)
                         or self._exp_rev.get(func_va)
                         or f'sub_{func_va:#x}')
            off = func_va - self._base
            if off < 0 or off >= len(self._data):
                continue
            # Limit scan to this function's code range only
            next_va = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else func_va + 4096
            max_bytes = min(next_va - func_va, 4096)
            for insn in self._disasm(func_va, max_bytes):
                if insn.mnemonic not in ('call', 'jmp'):
                    if insn.mnemonic == 'ret':
                        break
                    continue
                if not insn.operands:
                    continue
                op = insn.operands[0]
                if op.type != capstone.x86.X86_OP_IMM:
                    continue
                target_va = op.imm
                if target_va not in targets:
                    continue
                if insn.address in seen_call_vas:
                    continue
                seen_call_vas.add(insn.address)

                plt_name = targets[target_va]
                meta = _DANGEROUS[plt_name]

                buf_size = -1
                frame_sz = -1
                overflow_off = -1

                if meta['overflow']:
                    buf_size = self._gets_buf_size(insn.address)
                    frame_sz = self._frame_size(func_va)
                    if buf_size >= 0:
                        # saved RIP = [rbp+8]; buffer starts at [rbp-buf_size]
                        overflow_off = buf_size + 8

                callers = self._callers_of(func_va)

                hits.append(DeprecatedHit(
                    va=insn.address,
                    func_va=func_va,
                    func_name=func_name,
                    plt_name=plt_name,
                    cwe=meta['cwe'],
                    reason=meta['reason'],
                    buf_size=buf_size,
                    frame_size=frame_sz,
                    overflow_offset=overflow_off,
                    callers=callers,
                ))

        return hits

    # -- report ----------------------------------------------------------------

    def report(self, hits: List[DeprecatedHit]) -> str:
        if not hits:
            return "DeprecatedFuncScanner: no dangerous function calls found.\n"
        lines = [
            f"DeprecatedFuncScanner: {len(hits)} finding(s)",
            "",
        ]
        for h in hits:
            lines.append(h.fmt())
            lines.append("")
        return "\n".join(lines)
