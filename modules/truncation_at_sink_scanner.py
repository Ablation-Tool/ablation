"""
truncation_at_sink_scanner.py: Wide-to-narrow type truncation detector.

Detects narrowing truncation of a length or index value immediately before
it feeds an allocation or memory-operation sink. This is distinct from
signed/unsigned confusion (SignedLengthArgScanner) — here the concern is
a uint32_t being truncated to uint16_t, or a 64-bit network-received value
being narrowed to 8-bit for comparison, producing a wrapped-around length.

Example (Ariane 5 pattern):
    uint32_t pkt_len = recv_u32();  // 0x00010001
    uint16_t alloc_size = (uint16_t)pkt_len;  // → 0x0001 = 1
    char *buf = malloc(alloc_size);  // tiny allocation
    memcpy(buf, data, pkt_len);      // 0x00010001 bytes → heap overflow

Detection strategy:
  1. Find allocation/copy/I/O sinks in PLT.
  2. For each sink call, walk backwards in the same basic block looking for
     AND instructions that mask the length register to fewer bits:
       AND reg, 0xFFFF  → truncation to 16-bit
       AND reg, 0xFF    → truncation to 8-bit
       MOVZX word ptr   → zero-extension to word (implicit truncation from wider)
       UXTH (ARM)       → zero-extend halfword
       UXTB (ARM)       → zero-extend byte
  3. Flag as HIGH when the AND mask is 0xFF or 0xFFFF and the result feeds
     a heap allocation sink. Flag as MEDIUM for I/O size sinks.

Usage:
    scanner = TruncationAtSinkScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


# Sinks where truncated length is dangerous
_ALLOC_SINKS: frozenset = frozenset({
    'malloc', 'calloc', 'realloc', 'alloca', 'HeapAlloc',
    'VirtualAlloc', 'VirtualAllocEx', 'mmap',
})
_IO_SINKS: frozenset = frozenset({
    'read', 'recv', 'recvfrom', 'recvmsg', 'memcpy', 'memmove', 'memset',
    'snprintf', 'strncpy', 'strncat', 'fread',
})

_ALL_SINKS = _ALLOC_SINKS | _IO_SINKS

# Length argument index per sink (0-based)
_LENGTH_ARG: dict[str, int] = {
    'malloc': 0, 'calloc': 1, 'realloc': 1, 'alloca': 0,
    'HeapAlloc': 2, 'VirtualAlloc': 1, 'VirtualAllocEx': 2, 'mmap': 1,
    'read': 2, 'recv': 2, 'recvfrom': 2, 'recvmsg': 2,
    'memcpy': 2, 'memmove': 2, 'memset': 2, 'snprintf': 2,
    'strncpy': 2, 'strncat': 2, 'fread': 2,
}

_ARG_REGS_X86_64 = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
_ARG_REGS_ARM64  = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5']

# Truncation patterns: mnemonic → truncation width bits
_TRUNC_MNEMONICS: dict[str, int] = {
    'movzx': 16,    # movzx r64, r16 — may mean value was 16-bit
    'movzb': 8,     # AT&T syntax
    'uxth': 16,     # ARM: zero-extend halfword
    'uxtb': 8,      # ARM: zero-extend byte
    'and': 0,       # handled separately by looking at immediate operand
}

_AND_MASKS: dict[int, int] = {
    0xFF: 8,
    0xFFFF: 16,
    0xFFFFFF: 24,
    0xFF00: 8,      # masking low byte into high byte position
}


@dataclass
class TruncationFinding:
    func_va:      int
    func_name:    str
    call_va:      int
    sink:         str
    trunc_width:  int     # bits: 8, 16, 24
    trunc_insn:   str     # the truncating instruction
    trunc_va:     int
    severity:     str     # HIGH / MEDIUM

    def fmt(self) -> str:
        return (f"  {self.severity:6s}  [TRUNCATION]  {self.func_name}\n"
                f"         {self.sink}() length arg truncated to {self.trunc_width} bits\n"
                f"         truncation: {self.trunc_insn} at 0x{self.trunc_va:x}\n"
                f"         sink call at 0x{self.call_va:x}")


class TruncationAtSinkScanner:
    """Detect wide-to-narrow truncation in length arguments before allocation/I/O sinks."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'TruncationAtSinkScanner':
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

    def _plt_map(self, ctx) -> dict[int, str]:
        result: dict[int, str] = {}
        for name, va in ctx.plt_entries():
            base = name.split('@')[0].lstrip('_')
            result[va] = base
        return result

    def _length_reg(self, sink_name: str, arch: str) -> str:
        idx = _LENGTH_ARG.get(sink_name, -1)
        if idx < 0:
            return ''
        regs = _ARG_REGS_ARM64 if ('arm' in arch.lower() or arch == 'aarch64') else _ARG_REGS_X86_64
        return regs[idx] if idx < len(regs) else ''

    def _arch(self, ctx) -> str:
        try:
            return ctx.arch()
        except Exception:
            return 'x86_64'

    def _check_truncation(self, insn) -> tuple[int, str]:
        mn = insn.mnemonic.lower().split()[0]
        op = insn.op_str.lower()

        if mn in ('uxth',):
            return 16, f'{mn} {insn.op_str}'
        if mn in ('uxtb',):
            return 8, f'{mn} {insn.op_str}'
        if mn == 'movzx':
            if 'word ptr' in op or 'w,' in op:
                return 16, f'{mn} {insn.op_str}'
            return 8, f'{mn} {insn.op_str}'

        if mn == 'and':
            # Extract immediate operand
            parts = op.split(',')
            if len(parts) >= 2:
                imm_str = parts[-1].strip()
                try:
                    imm = int(imm_str, 16) if '0x' in imm_str else int(imm_str)
                    width = _AND_MASKS.get(imm, 0)
                    if width:
                        return width, f'{mn} {insn.op_str}'
                except ValueError:
                    pass
        return 0, ''

    def scan(self) -> List[TruncationFinding]:
        ctx = self._load_ctx()
        plt_map = self._plt_map(ctx)
        arch = self._arch(ctx)
        findings: list[TruncationFinding] = []

        for func_va in ctx.func_starts:
            insns = list(ctx.disasm_func(func_va))
            func_name = ctx.name(func_va)

            for idx, insn in enumerate(insns):
                mn = insn.mnemonic.lower().split()[0]
                if mn not in ('call', 'bl', 'blx', 'jalr', 'jal'):
                    continue

                try:
                    target = int(insn.op_str.strip().lstrip('#'), 16)
                except (ValueError, AttributeError):
                    continue

                sink_name = plt_map.get(target)
                if sink_name not in _ALL_SINKS:
                    continue

                length_reg = self._length_reg(sink_name, arch)
                if not length_reg:
                    continue

                lookback = insns[max(0, idx - 20):idx]
                for prev in reversed(lookback):
                    prev_op = prev.op_str.lower()
                    if not prev_op.startswith(length_reg):
                        continue
                    width, trunc_str = self._check_truncation(prev)
                    if width > 0:
                        severity = 'HIGH' if sink_name in _ALLOC_SINKS else 'MEDIUM'
                        findings.append(TruncationFinding(
                            func_va=func_va,
                            func_name=func_name,
                            call_va=insn.address,
                            sink=sink_name,
                            trunc_width=width,
                            trunc_insn=trunc_str,
                            trunc_va=prev.address,
                            severity=severity,
                        ))
                        break

        return findings

    def report(self, findings: Optional[List[TruncationFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'TruncationAtSinkScanner: no width-truncation findings in {self._path}'
        lines = [f'TruncationAtSinkScanner: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
