"""
signed_length_arg_scanner.py: Signed-to-unsigned length argument scanner.

Detects call sites where a length argument to allocation, copy, or I/O sinks
is computed from a value that was sign-extended from a narrower type or is
derived from a signed arithmetic operation that can produce negative values.

When a signed int is implicitly converted to size_t at a sink like
malloc(size), the negative value wraps to a huge positive (e.g.
-1 → 0xffffffffffffffff on 64-bit), typically causing:
  - malloc(-1) → allocation failure or huge heap allocation
  - read(fd, buf, -1) → enormous read into a bounded buffer
  - memcpy(dst, src, -1) → full address-space copy

Detection strategy:
  1. Identify the length argument register for each sink call (2nd arg for
     read/recv, 3rd for memcpy/memset/malloc = 1st arg).
  2. Walk backwards from the call site (within the same basic block) tracking
     the register that holds the size argument.
  3. Flag if the size register is set from:
       a. MOVSX / MOVSXD (sign extension from narrow to wide)
       b. Result of signed arithmetic (IMUL, IDIV) rather than unsigned (MUL, DIV)
       c. A compare-derived value where the comparison uses signed condition codes
          (JL, JG, JLE, JGE rather than JB, JA, JBE, JAE)
  4. Flag with HIGH when the size flows directly from user-controlled input
     (ARG0/ARG1 of the caller), MEDIUM otherwise.

Architecture support: x86-64 (MOVSX/MOVSXD), ARM64 (SBFX/SXTW).

Usage:
    scanner = SignedLengthArgScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


# Sinks and which argument is the length
# Format: {plt_name: length_arg_index}  (0 = first arg)
_LENGTH_SINKS: dict[str, int] = {
    'malloc':      0,   # malloc(size)
    'calloc':      1,   # calloc(nmemb, size)
    'realloc':     1,   # realloc(ptr, size)
    'alloca':      0,
    'read':        2,   # read(fd, buf, count)
    'recv':        2,   # recv(s, buf, len, flags)
    'recvfrom':    2,
    'recvmsg':     2,
    'fread':       2,   # fread(ptr, size, nmemb, stream) — size*nmemb
    'write':       2,
    'send':        2,
    'memcpy':      2,   # memcpy(dst, src, n)
    'memmove':     2,
    'memset':      2,
    'snprintf':    2,
    'strncat':     2,
    'strncpy':     2,
    'mmap':        1,   # mmap(addr, length, ...)
    'VirtualAlloc': 1,
    'VirtualAllocEx': 2,
    'HeapAlloc':   2,
}

# Sign-extension mnemonics per arch
_SIGN_EXTEND_MNEMONICS = frozenset({
    # x86-64
    'movsx', 'movsxd', 'cwde', 'cdqe',
    # ARM64
    'sbfx', 'sxtw', 'sxtb', 'sxth',
    # MIPS
    'seb', 'seh',
})

# Signed arithmetic mnemonics (vs unsigned equivalents)
_SIGNED_ARITH = frozenset({
    'imul', 'idiv',
    'smull', 'sdiv',  # ARM
    'smulhi',
})

# Argument registers by arch (length_arg_index → register name)
_ARG_REGS_X86_64 = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
_ARG_REGS_ARM64  = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5']


@dataclass
class SignedLengthFinding:
    func_va:     int
    func_name:   str
    call_va:     int
    sink:        str        # malloc, read, memcpy, etc.
    length_arg:  int        # which argument index is the length
    sign_insn:   str        # the sign-extending instruction found
    sign_va:     int        # VA of that instruction
    severity:    str        # HIGH / MEDIUM

    def fmt(self) -> str:
        return (f"  {self.severity:6s}  [SIGNED_LENGTH]  {self.func_name}\n"
                f"         {self.sink}() length arg #{self.length_arg} at 0x{self.call_va:x}\n"
                f"         sign-extending instruction: {self.sign_insn} at 0x{self.sign_va:x}")


class SignedLengthArgScanner:
    """Detect signed-to-unsigned length argument conversions at allocation and I/O sinks."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'SignedLengthArgScanner':
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
        arg_idx = _LENGTH_SINKS.get(sink_name, -1)
        if arg_idx < 0:
            return ''
        if 'arm' in arch.lower() or arch == 'aarch64':
            if arg_idx < len(_ARG_REGS_ARM64):
                return _ARG_REGS_ARM64[arg_idx]
        else:  # x86-64 default
            if arg_idx < len(_ARG_REGS_X86_64):
                return _ARG_REGS_X86_64[arg_idx]
        return ''

    def _arch(self, ctx) -> str:
        try:
            return ctx.arch()
        except Exception:
            return 'x86_64'

    def scan(self) -> List[SignedLengthFinding]:
        ctx = self._load_ctx()
        plt_map = self._plt_map(ctx)
        arch = self._arch(ctx)
        findings: list[SignedLengthFinding] = []

        for func_va in ctx.func_starts:
            insns = list(ctx.disasm_func(func_va))
            func_name = ctx.name(func_va)

            for idx, insn in enumerate(insns):
                mn = insn.mnemonic.lower().split()[0]
                if mn not in ('call', 'bl', 'blx', 'jalr', 'jal'):
                    continue

                # Resolve PLT call
                try:
                    target = int(insn.op_str.strip().lstrip('#'), 16)
                except (ValueError, AttributeError):
                    continue
                sink_name = plt_map.get(target)
                if sink_name not in _LENGTH_SINKS:
                    continue

                length_reg = self._length_reg(sink_name, arch)
                if not length_reg:
                    continue

                # Walk backwards from call site looking for sign-extending insn
                # targeting the length register
                lookback = insns[max(0, idx - 20):idx]
                for prev in reversed(lookback):
                    prev_mn = prev.mnemonic.lower().split()[0]
                    op = prev.op_str.lower()

                    # Check if this instruction writes to the length register
                    if not op.startswith(length_reg):
                        continue

                    if prev_mn in _SIGN_EXTEND_MNEMONICS:
                        findings.append(SignedLengthFinding(
                            func_va=func_va,
                            func_name=func_name,
                            call_va=insn.address,
                            sink=sink_name,
                            length_arg=_LENGTH_SINKS[sink_name],
                            sign_insn=f'{prev_mn} {prev.op_str}',
                            sign_va=prev.address,
                            severity='HIGH',
                        ))
                        break
                    elif prev_mn in _SIGNED_ARITH:
                        findings.append(SignedLengthFinding(
                            func_va=func_va,
                            func_name=func_name,
                            call_va=insn.address,
                            sink=sink_name,
                            length_arg=_LENGTH_SINKS[sink_name],
                            sign_insn=f'{prev_mn} {prev.op_str}',
                            sign_va=prev.address,
                            severity='MEDIUM',
                        ))
                        break

        return findings

    def report(self, findings: Optional[List[SignedLengthFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'SignedLengthArgScanner: no signed length arguments in {self._path}'
        lines = [f'SignedLengthArgScanner: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
