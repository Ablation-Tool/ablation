"""
length_underflow.py -- Protocol parser integer underflow detector.

Detects the C12-class bug pattern across any x86-64 binary:

  movzwl/movzbl <mem>, %reg      -- narrow load of user-supplied length field
    ...
  lea -N(%reg), %dest            -- subtract fixed header size (N in [4..256])
   OR sub $N, %reg
    ...
  movzwl %?x, %dest              -- truncate to uint16 (wraps if len < N)
    ...
  call <target>                  -- pass wrapped value as argument

Without a prior cmp/test bounds check on %reg after the subtraction, values
1..N-1 wrap around to 65523..65535 (for uint16) and get passed to the callee.

This pattern was confirmed in libips.so.new (FortiOS 8.0.0) as C12:
  0x21b3f6: cmp $0xf, %r12d     (checks BUFFER SPACE, not chunk_length)
  0x21b51e: lea -0x10(%r9), %edx  (chunk_length - 16)
  0x21b529: movzwl %dx, %edx     (uint16 truncation: 3-16 = 65523)
  0x21b52c: call 0x17b660         (Diameter parser, rdx=65523 -> OOB read)

The pattern generalizes to DNS, GRE, PPTP, SCTP, Diameter -- any parser that
strips a fixed header from a user-supplied length field.

Usage:
    scanner = LengthUnderflowScanner('/path/to/binary')
    findings = scanner.scan()
    for f in findings:
        if not f.guarded:
            print(f.fmt())

    # With existing BinaryContext (avoid rebuild):
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = LengthUnderflowScanner.from_context(ctx)
    findings = scanner.scan()
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Register family map: any alias -> canonical name
_REG_FAMILIES: Dict[str, str] = {}

def _build_reg_families() -> Dict[str, str]:
    families = {
        'rax': ['rax', 'eax', 'ax', 'al', 'ah'],
        'rbx': ['rbx', 'ebx', 'bx', 'bl', 'bh'],
        'rcx': ['rcx', 'ecx', 'cx', 'cl', 'ch'],
        'rdx': ['rdx', 'edx', 'dx', 'dl', 'dh'],
        'rsi': ['rsi', 'esi', 'si', 'sil'],
        'rdi': ['rdi', 'edi', 'di', 'dil'],
        'rbp': ['rbp', 'ebp', 'bp', 'bpl'],
        'rsp': ['rsp', 'esp', 'sp', 'spl'],
        'r8':  ['r8',  'r8d',  'r8w',  'r8b'],
        'r9':  ['r9',  'r9d',  'r9w',  'r9b'],
        'r10': ['r10', 'r10d', 'r10w', 'r10b'],
        'r11': ['r11', 'r11d', 'r11w', 'r11b'],
        'r12': ['r12', 'r12d', 'r12w', 'r12b'],
        'r13': ['r13', 'r13d', 'r13w', 'r13b'],
        'r14': ['r14', 'r14d', 'r14w', 'r14b'],
        'r15': ['r15', 'r15d', 'r15w', 'r15b'],
    }
    m = {}
    for canon, aliases in families.items():
        for a in aliases:
            m[a] = canon
    return m

_REG_FAMILIES = _build_reg_families()

# Header size range considered interesting (covers Ethernet/IP/TCP/UDP/SCTP/GRE/etc.)
_HEADER_SIZE_RANGE = range(4, 257)

# Window sizes for pattern matching
_GUARD_LOOKBACK  = 25   # instructions before sub/lea to check for bounds guard
_TRUNC_LOOKAHEAD = 10   # instructions after sub/lea to find truncation
_CALL_LOOKAHEAD  = 10   # instructions after truncation to find call


@dataclass
class UnderflowFinding:
    func_va: int        # owning function start
    sub_va: int         # VA of the subtraction (lea -N or sub $N)
    sub_const: int      # N (header size constant)
    sub_reg: str        # destination register of subtraction
    truncate_va: int    # VA of movzwl/movzbl (uint16/uint8 truncation)
    call_va: int        # VA of the call instruction
    call_target: int    # target VA of the call
    call_label: str     # PLT name if resolved, else ''
    guarded: bool       # True if a cmp/test bounds check was found upstream

    def fmt(self) -> str:
        guard_tag = 'GUARDED' if self.guarded else 'UNGUARDED'
        label = f' ({self.call_label})' if self.call_label else ''
        return (
            f"UnderflowFinding [{guard_tag}]\n"
            f"  func    : 0x{self.func_va:x}\n"
            f"  sub     : 0x{self.sub_va:x}  {self.sub_reg} -= 0x{self.sub_const:x} ({self.sub_const})\n"
            f"  truncate: 0x{self.truncate_va:x}  movzwl/movzbl\n"
            f"  call    : 0x{self.call_va:x}  -> 0x{self.call_target:x}{label}\n"
        )


def _reg_family(reg: str) -> str:
    return _REG_FAMILIES.get(reg.lower(), reg.lower())


# Precompiled patterns for instruction parsing
_LEA_NEG_RE = re.compile(
    r'^(\w+),\s*\[(\w+)\s*[+-]\s*(0x[0-9a-f]+|\d+)\]',
    re.IGNORECASE
)
_SUB_IMM_RE = re.compile(
    r'^(\w+),\s*(0x[0-9a-f]+|\d+)$',
    re.IGNORECASE
)
_MOVZX_RE = re.compile(
    r'^(\w+),\s*(\w+)$',
    re.IGNORECASE
)
_CALL_RE = re.compile(r'^(0x[0-9a-f]+|\d+)$', re.IGNORECASE)
_TOK_RE = re.compile(r'\b([a-z][a-z0-9]*)\b', re.IGNORECASE)


# Stack pointer registers: lea [rbp/rsp - N] is stack variable access, not length math
_STACK_BASE_REGS = frozenset(['rbp', 'ebp', 'bp', 'rsp', 'esp', 'sp'])

# x86-64 SysV caller-saved registers (clobbered across any call)
_CALLER_SAVED_FAMILIES = frozenset(['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'])

# Mnemonics that write to their first (dest) operand and clobber prior arithmetic.
# Only fires if the first operand is a register (no brackets) in dest_family.
_DEST_CLOBBER_MNEMS = frozenset([
    # SET family: write boolean 0/1 to 8-bit reg, clobbering prior subtraction result
    'sete', 'setne', 'setb', 'setbe', 'seta', 'setae', 'setl', 'setle',
    'setg', 'setge', 'sets', 'setns', 'seto', 'setno', 'setp', 'setnp',
    # General arithmetic/logic that overwrites dest with a new unrelated value
    'add', 'sub', 'or', 'and', 'xor', 'neg', 'not', 'inc', 'dec',
    'imul', 'mul', 'shl', 'shr', 'sar', 'sal', 'rol', 'ror',
    'mov', 'movabs',
    # BSF/BSR/POPCNT/TZCNT/LZCNT write unconditionally to dest
    'bsf', 'bsr', 'popcnt', 'tzcnt', 'lzcnt', 'bswap',
])


def _parse_sub_const(mnem: str, ops: str) -> Optional[Tuple[str, int]]:
    """Return (dest_reg, const) if this instruction subtracts a constant, else None."""
    mnem = mnem.lower()
    ops = ops.strip()

    if mnem == 'lea':
        # Intel syntax: 'lea edx, [r9 - 0x10]'
        # Detect negative displacement
        m = _LEA_NEG_RE.match(ops)
        if not m:
            return None
        dest = m.group(1)
        base_reg = m.group(2).lower()
        # Skip stack-relative addressing (rbp/rsp -- these are local variable accesses)
        if base_reg in _STACK_BASE_REGS:
            return None
        # Check the sign: '[reg - N]' is subtraction, '[reg + N]' is addition
        # We only care about subtraction (negative offset)
        if '-' not in ops.split(',', 1)[1] if ',' in ops else True:
            return None
        try:
            const = int(m.group(3), 0)
        except ValueError:
            return None
        if const in _HEADER_SIZE_RANGE:
            return (dest, const)
        return None

    if mnem == 'sub':
        # Intel syntax: 'sub eax, 0x10' or 'sub eax, 16'
        m = _SUB_IMM_RE.match(ops)
        if not m:
            return None
        dest = m.group(1)
        try:
            const = int(m.group(2), 0)
        except ValueError:
            return None
        if const in _HEADER_SIZE_RANGE:
            return (dest, const)
        return None

    return None


def _is_truncation(mnem: str, ops: str, target_family: str) -> bool:
    """Return True if this is register-to-register movzwl/movzbl on target_family."""
    mnem = mnem.lower()
    if mnem not in ('movzx', 'movzwl', 'movzbl'):
        return False
    # Source must be a register, not a memory operand
    # e.g. 'movzx edx, byte ptr [rdx + 6]' is a mem load -- rdx is a pointer, not value
    if '[' in ops:
        return False
    # Check if source register is in the target family
    m = _MOVZX_RE.match(ops.strip())
    if m:
        src = m.group(2)
        return _reg_family(src) == target_family
    # Fallback: check all tokens (no brackets present since we checked above)
    for tok in _TOK_RE.findall(ops):
        if _reg_family(tok) == target_family:
            return True
    return False


def _is_guard(mnem: str, ops: str, target_family: str) -> bool:
    """Return True if this is a cmp/test that includes target_family register."""
    mnem = mnem.lower()
    if mnem not in ('cmp', 'test'):
        return False
    ops_clean = ops.replace('[', ' ').replace(']', ' ')
    for tok in _TOK_RE.findall(ops_clean):
        if _reg_family(tok) == target_family:
            return True
    return False


def _parse_call_target(ops: str) -> Optional[int]:
    """Return integer call target if direct call, else None."""
    ops = ops.strip()
    m = _CALL_RE.match(ops)
    if m:
        try:
            return int(ops, 16) if ops.startswith('0x') else int(ops)
        except ValueError:
            return None
    return None


class LengthUnderflowScanner:
    """
    Scans x86-64 stripped ELF binaries for protocol parser integer underflow.

    Pattern detected:
      1. lea -N(%reg), %dest  OR  sub $N, %reg    (header subtraction)
      2. movzwl/movzbl %?x, %dest                  (uint16/uint8 truncation)
      3. call <target>                              (truncated value as arg)
      Without: cmp/test on %dest in prior 25 instructions.
    """

    def __init__(self, binary_path: str, ctx=None):
        self.binary_path = binary_path
        self._ctx = ctx
        self._plt: Dict[int, str] = {}

    @classmethod
    def from_context(cls, ctx) -> 'LengthUnderflowScanner':
        scanner = cls(ctx.path, ctx=ctx)
        scanner._plt = ctx.plt
        return scanner

    def _load_plt(self) -> None:
        if self._plt:
            return
        if self._ctx:
            self._plt = self._ctx.plt
            return
        try:
            from ablation.analyzers.binary_context import BinaryContext
            ctx = BinaryContext.load_or_build(self.binary_path)
            self._ctx = ctx
            self._plt = ctx.plt
        except Exception:
            pass

    def _func_containing(self, va: int) -> int:
        if self._ctx:
            return self._ctx.func_containing(va) or va
        return va

    def scan(self) -> List[UnderflowFinding]:
        """Scan entire binary .text section for underflow pattern. Returns all findings."""
        self._load_plt()

        try:
            import capstone
            import lief
        except ImportError:
            return []

        binary = lief.parse(self.binary_path)
        if not isinstance(binary, lief.ELF.Binary):
            return []

        text_sec = binary.get_section('.text')
        if not text_sec:
            return []

        text_data = bytes(text_sec.content)
        text_va = text_sec.virtual_address

        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = False

        findings: List[UnderflowFinding] = []

        # Sliding deque of recent instructions for guard lookback
        recent: deque = deque(maxlen=_GUARD_LOOKBACK + 2)
        # Forward buffer for lookahead
        lookahead: List[Tuple[int, str, str]] = []

        # We need forward lookahead, so buffer instructions in a rolling window
        # Strategy: accumulate all instructions into a list (memory ~500MB for 5M insns)
        # For large binaries, process in chunks of 100k instructions
        CHUNK = 100_000
        insns_iter = cs.disasm(text_data, text_va)

        buf: List[Tuple[int, str, str]] = []
        idx = 0

        def _drain_buf():
            nonlocal idx
            while idx < len(buf):
                va, mnem, ops = buf[idx]
                recent.append((va, mnem, ops))

                sub_info = _parse_sub_const(mnem, ops)
                if sub_info is not None:
                    dest_reg, const = sub_info
                    dest_family = _reg_family(dest_reg)

                    # Scan guard: check recent instructions BEFORE this one for bounds check
                    guarded = any(
                        _is_guard(r[1], r[2], dest_family)
                        for r in list(recent)[:-1]  # exclude current instruction
                    )

                    # Scan forward for truncation
                    trunc_va = None
                    call_va = None
                    call_target = None

                    lookahead_end = min(idx + _TRUNC_LOOKAHEAD + _CALL_LOOKAHEAD + 2, len(buf))
                    for j in range(idx + 1, lookahead_end):
                        if j >= len(buf):
                            break
                        jva, jmnem, jops = buf[j]

                        # Unconditional jmp or ret terminates the linear chain
                        # (switch dispatch, tail call, or function boundary)
                        if jmnem.lower() in ('jmp', 'ret', 'retn', 'retf', 'retq'):
                            break

                        if trunc_va is None:
                            if j - idx > _TRUNC_LOOKAHEAD:
                                break
                            # Call before truncation clobbers caller-saved dest register
                            if jmnem.lower() == 'call':
                                if dest_family in _CALLER_SAVED_FAMILIES:
                                    break
                            # SET*/BSF/BSR/etc. write a non-arithmetic value to dest,
                            # clobbering the sub result before we find the truncation
                            if jmnem.lower() in _DEST_CLOBBER_MNEMS:
                                # check if first operand is in dest_family
                                first_op = jops.split(',')[0].strip().lower()
                                if _reg_family(first_op) == dest_family:
                                    break
                            if _is_truncation(jmnem, jops, dest_family):
                                trunc_va = jva

                        elif call_va is None:
                            if j - (idx + 1) > _TRUNC_LOOKAHEAD + _CALL_LOOKAHEAD:
                                break
                            if jmnem.lower() == 'call':
                                t = _parse_call_target(jops)
                                if t is not None:
                                    call_va = jva
                                    call_target = t
                                    break

                    if trunc_va is not None and call_va is not None:
                        func_va = self._func_containing(va)
                        call_label = self._plt.get(call_target, '')
                        findings.append(UnderflowFinding(
                            func_va=func_va,
                            sub_va=va,
                            sub_const=const,
                            sub_reg=dest_reg,
                            truncate_va=trunc_va,
                            call_va=call_va,
                            call_target=call_target,
                            call_label=call_label,
                            guarded=guarded,
                        ))

                idx += 1

        # Fill buffer in chunks to bound memory
        chunk_count = 0
        for insn in insns_iter:
            buf.append((insn.address, insn.mnemonic, insn.op_str))
            chunk_count += 1
            if chunk_count >= CHUNK:
                _drain_buf()
                # Keep the last guard-lookback + lookahead instructions in buf
                keep = _GUARD_LOOKBACK + _TRUNC_LOOKAHEAD + _CALL_LOOKAHEAD + 4
                if idx > keep:
                    buf = buf[idx - keep:]
                    idx = keep
                chunk_count = 0

        _drain_buf()
        return findings

    def scan_unguarded(self) -> List[UnderflowFinding]:
        """Return only unguarded (no upstream cmp/test) findings."""
        return [f for f in self.scan() if not f.guarded]

    def report(self, findings: Optional[List[UnderflowFinding]] = None) -> str:
        """Format findings as a text report."""
        if findings is None:
            findings = self.scan()
        if not findings:
            return 'LengthUnderflowScanner: no findings\n'
        lines = [
            f'LengthUnderflowScanner: {len(findings)} findings '
            f'({sum(1 for f in findings if not f.guarded)} unguarded)',
            '',
        ]
        for f in sorted(findings, key=lambda x: x.guarded):
            lines.append(f.fmt())
        return '\n'.join(lines)
