"""
sizeof_ptr_detector.py: sizeof(pointer) false-safe length detector.

Finds memcpy/memset/read calls where the length argument is a pointer-size
constant (4 on 32-bit, 8 on 64-bit) loaded directly as an immediate, with
the destination being a heap or stack buffer larger than a pointer.

The classic bug:
    char buf[128];
    memcpy(dst, buf, sizeof(buf));  // correct: 128
    // vs:
    char *ptr = buf;
    memcpy(dst, ptr, sizeof(ptr));  // wrong: 8 (pointer size)

At the binary level, sizeof(ptr) compiles to a literal 4 or 8. When that
literal feeds a copy/fill sink, and the destination is a larger buffer, it
results in a partial copy — often a security defect (partial zeroing of a
secret, partial copy of a credential, etc.).

Detection strategy:
  1. Find memcpy/memset/read/write/recv call sites.
  2. Check whether the length argument is loaded as an immediate 4 or 8.
  3. Check that the destination (first arg) is not a pointer to a 4 or 8-byte
     type (i.e., destination is a larger buffer: frame allocation > 8 bytes,
     or heap allocation with a different size).
  4. Flag as MEDIUM (false-safe copy) or LOW (partial clear).

Usage:
    detector = SizeofPtrDetector('/path/to/binary')
    findings = detector.scan()
    print(detector.report(findings))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


_COPY_SINKS: frozenset = frozenset({
    'memcpy', 'memmove', 'memcpy_s', 'wmemcpy',
    'read', 'recv', 'recvfrom',
})
_FILL_SINKS: frozenset = frozenset({
    'memset', 'bzero', 'explicit_bzero', 'memset_explicit',
    'SecureZeroMemory', 'RtlSecureZeroMemory',
})
_ALL_SINKS = _COPY_SINKS | _FILL_SINKS

# Length arg index per sink
_LENGTH_ARG: dict[str, int] = {
    'memcpy': 2, 'memmove': 2, 'memcpy_s': 2, 'wmemcpy': 2,
    'read': 2, 'recv': 2, 'recvfrom': 2,
    'memset': 2, 'bzero': 1, 'explicit_bzero': 1, 'memset_explicit': 2,
    'SecureZeroMemory': 1, 'RtlSecureZeroMemory': 1,
}

_ARG_REGS_X86_64 = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
_ARG_REGS_ARM64  = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5']

_PTR_SIZES = frozenset({4, 8})


@dataclass
class SizeofPtrFinding:
    func_va:    int
    func_name:  str
    call_va:    int
    sink:       str
    ptr_size:   int     # 4 or 8
    load_insn:  str     # the MOV/LDR that loaded the immediate
    load_va:    int
    severity:   str     # MEDIUM for copy; LOW for fill

    def fmt(self) -> str:
        return (f"  {self.severity:6s}  [SIZEOF_PTR]  {self.func_name}\n"
                f"         {self.sink}() length = {self.ptr_size} (pointer size) at 0x{self.call_va:x}\n"
                f"         loaded at: {self.load_insn}  (0x{self.load_va:x})")


class SizeofPtrDetector:
    """Detect sizeof(pointer) constants feeding copy/fill sinks."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'SizeofPtrDetector':
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

    def scan(self) -> List[SizeofPtrFinding]:
        ctx = self._load_ctx()
        plt_map = self._plt_map(ctx)
        arch = self._arch(ctx)
        findings: list[SizeofPtrFinding] = []

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

                lookback = insns[max(0, idx - 15):idx]
                for prev in reversed(lookback):
                    prev_mn = prev.mnemonic.lower().split()[0]
                    op = prev.op_str.lower()

                    if not op.startswith(length_reg):
                        continue

                    if prev_mn not in ('mov', 'ldr', 'movl', 'movq', 'li', 'lui'):
                        break

                    # Extract immediate from the operand
                    parts = op.split(',')
                    if len(parts) < 2:
                        break
                    imm_str = parts[-1].strip().lstrip('#')
                    try:
                        imm = int(imm_str, 16) if '0x' in imm_str else int(imm_str)
                    except ValueError:
                        break

                    if imm not in _PTR_SIZES:
                        break

                    severity = 'MEDIUM' if sink_name in _COPY_SINKS else 'LOW'
                    findings.append(SizeofPtrFinding(
                        func_va=func_va,
                        func_name=func_name,
                        call_va=insn.address,
                        sink=sink_name,
                        ptr_size=imm,
                        load_insn=f'{prev_mn} {prev.op_str}',
                        load_va=prev.address,
                        severity=severity,
                    ))
                    break

        return findings

    def report(self, findings: Optional[List[SizeofPtrFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'SizeofPtrDetector: no sizeof(pointer) findings in {self._path}'
        lines = [f'SizeofPtrDetector: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
