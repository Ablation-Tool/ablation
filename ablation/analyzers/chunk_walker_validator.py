"""
chunk_walker_validator.py -- Detect TLV/chunk parsers missing alignment.

Many protocols (SCTP RFC 9260, DNS RFC 1035, GRE, PPTP, IS-IS) require
chunk/TLV boundaries to be aligned to 4 bytes. Parsers that advance the
chunk pointer by the raw user-supplied length field without rounding up to
the next multiple of 4 will misparse the next chunk: padding bytes become
the next chunk's type and length fields.

Pattern detected:
  1. Pointer advance: ptr += length (raw: add/lea without AND mask)
  2. No alignment: missing '(len + 3) & ~3' pattern within 5 insns
  3. Field read from advanced pointer (next chunk parse begins)

This is the C13-class candidate pattern from a stripped protocol parser binary
processor at 0x21f062-0x21f0ac.

Usage:
    scanner = ChunkWalkerValidator('/path/to/binary')
    findings = scanner.scan()
    for f in findings:
        if not f.aligned:
            print(f.fmt())

    # With existing context:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = ChunkWalkerValidator.from_context(ctx)
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

_REG_FAMILIES: dict = {}

def _build_reg_families() -> dict:
    families = {
        'rax': ['rax','eax','ax','al','ah'], 'rbx': ['rbx','ebx','bx','bl','bh'],
        'rcx': ['rcx','ecx','cx','cl','ch'], 'rdx': ['rdx','edx','dx','dl','dh'],
        'rsi': ['rsi','esi','si','sil'],     'rdi': ['rdi','edi','di','dil'],
        'rbp': ['rbp','ebp','bp','bpl'],     'rsp': ['rsp','esp','sp','spl'],
        'r8':  ['r8','r8d','r8w','r8b'],     'r9':  ['r9','r9d','r9w','r9b'],
        'r10': ['r10','r10d','r10w','r10b'], 'r11': ['r11','r11d','r11w','r11b'],
        'r12': ['r12','r12d','r12w','r12b'], 'r13': ['r13','r13d','r13w','r13b'],
        'r14': ['r14','r14d','r14w','r14b'], 'r15': ['r15','r15d','r15w','r15b'],
    }
    m = {}
    for canon, aliases in families.items():
        for a in aliases:
            m[a] = canon
    return m

_REG_FAMILIES = _build_reg_families()

def _reg_family(reg: str) -> str:
    return _REG_FAMILIES.get(reg.lower(), reg.lower())

# Mnemonics that overwrite (clobber) their first operand register
_CLOBBER_MNEMS = frozenset([
    'add', 'sub', 'imul', 'mul', 'idiv', 'div', 'neg', 'not',
    'shl', 'shr', 'sar', 'sal', 'rol', 'ror', 'rcl', 'rcr',
    'and', 'or', 'xor', 'inc', 'dec',
    'movsx', 'movsxd',  # overwrites dest with sign-extended value
    'bswap', 'popcnt', 'tzcnt', 'lzcnt',
])

_ALIGN_MASK_VALUES = {0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFF8}  # AND masks for 4/2/8-byte align
_ALIGN_ADD_CONST   = {3, 7}                                  # ADD before AND: +3 for 4-byte, +7 for 8-byte

# Window: instructions after pointer advance to find alignment or field read
_ALIGN_LOOKAHEAD = 5
_READ_LOOKAHEAD  = 8

# Precompile patterns
_TOKEN_RE = re.compile(r'\b([a-z][a-z0-9]*)\b', re.IGNORECASE)
_HEX_RE   = re.compile(r'0x[0-9a-f]+', re.IGNORECASE)


@dataclass
class ChunkWalkFinding:
    func_va: int        # owning function start
    advance_va: int     # VA of pointer advance instruction
    advance_reg: str    # pointer register being advanced
    length_reg: str     # length register used in advance
    aligned: bool       # True if alignment pattern found in lookahead
    read_va: int        # VA of next field read (0 if not found)

    def fmt(self) -> str:
        tag = 'ALIGNED' if self.aligned else 'UNALIGNED'
        rd = f'0x{self.read_va:x}' if self.read_va else 'not found'
        return (
            f"ChunkWalkFinding [{tag}]\n"
            f"  func   : 0x{self.func_va:x}\n"
            f"  advance: 0x{self.advance_va:x}  {self.advance_reg} += {self.length_reg}\n"
            f"  next_read: {rd}\n"
        )


def _tokens(ops: str) -> List[str]:
    return _TOKEN_RE.findall(ops)


def _hex_immediates(ops: str) -> Set[int]:
    vals = set()
    for m in _HEX_RE.finditer(ops):
        try:
            vals.add(int(m.group(0), 16))
        except ValueError:
            pass
    return vals


def _is_mem_length_load(mnem: str, ops: str) -> Optional[tuple]:
    """Detect loading a chunk length field from memory into a register.

    Matches:
      movzwl offset(%ptr_reg), %dest_reg  -- 16-bit length field (e.g. SCTP chunk length)
      movzbl offset(%ptr_reg), %dest_reg  -- 8-bit length field
      movzx  %dest_reg, offset(%ptr_reg)  -- Intel syntax variant

    Returns (dest_reg, ptr_reg) if matched, else None.
    """
    mnem = mnem.lower()
    if mnem not in ('movzx', 'movzwl', 'movzbl'):
        return None
    ops = ops.strip()
    # Intel syntax: 'movzx eax, word ptr [rbx + 2]' or 'movzwl 0x2(%rbx), %eax'
    # Capstone uses Intel: 'movzx eax, word ptr [rbx + 2]'
    # Match: dest, [ptr_reg + offset] or dest, [ptr_reg]
    m = re.match(r'(\w+),\s*(?:(?:word|byte)\s+ptr\s+)?\[(\w+)(?:\s*[+-]\s*[0-9a-fx]+)?\]$',
                 ops, re.IGNORECASE)
    if m:
        dest = m.group(1)
        ptr = m.group(2).lower()
        # RIP-relative loads access global/static data -- not user-controlled packet fields
        if ptr == 'rip':
            return None
        # Stack-relative loads (rbp/rsp) are stack frame variables, not packet fields
        if ptr in ('rbp', 'ebp', 'bp', 'rsp', 'esp', 'sp'):
            return None
        return (dest, ptr)
    return None


def _is_ptr_advance_with_reg(mnem: str, ops: str, length_reg: str) -> Optional[tuple]:
    """Detect pointer advancement using a specific length register.

    Returns (ptr_reg, len_reg) if this is ptr += length_reg (where length_reg
    matches the expected register family), else None.
    """
    mnem = mnem.lower()
    len_family = _reg_family(length_reg)

    if mnem == 'add':
        parts = [p.strip() for p in ops.split(',')]
        if len(parts) != 2:
            return None
        dst, src = parts[0], parts[1]
        if '[' in ops or ']' in ops:
            return None
        if dst.startswith('0x') or src.startswith('0x'):
            return None
        if dst.isdigit() or src.isdigit():
            return None
        # Check if src or dst is in the length register family
        if _reg_family(src) == len_family:
            return (dst, src)
        if _reg_family(dst) == len_family:
            return (src, dst)
        return None

    if mnem == 'lea':
        m = re.match(r'(\w+),\s*\[(\w+)\s*\+\s*(\w+)\]$', ops.strip())
        if m:
            dest, base, idx = m.group(1), m.group(2), m.group(3)
            if (not base.startswith('0x') and not idx.startswith('0x')
                    and not base.isdigit() and not idx.isdigit()):
                if _reg_family(idx) == len_family:
                    return (dest, idx)
                if _reg_family(base) == len_family:
                    return (dest, base)
        return None

    return None


def _has_alignment(insns_window: List[tuple], len_reg: str) -> bool:
    """Check if a 4-byte alignment mask is present in the instruction window.

    Alignment requires an AND with 0xFFFFFFFC (or 0xFFFFFFF8 for 8-byte):
      and reg, 0xfffffffc   -- 4-byte alignment mask (canonical)
      and reg, -4           -- same in signed decimal form

    We don't require the preceding 'add reg, 3' since 'add reg, 3' is
    too common in protocol code. The AND mask is the definitive signal.
    """
    for va, mnem, ops in insns_window:
        if mnem.lower() != 'and':
            continue
        imms = _hex_immediates(ops)
        if imms & _ALIGN_MASK_VALUES:
            return True
        # Signed form: and reg, -4 (capstone sometimes emits as decimal)
        parts = [p.strip() for p in ops.split(',')]
        for part in parts:
            try:
                val = int(part)
                if val < 0 and (-val) in {4, 2, 8}:
                    return True
            except ValueError:
                pass
    return False


def _find_field_read(insns_window: List[tuple], ptr_reg: str) -> Optional[int]:
    """Find first memory read using ptr_reg in window. Returns VA or None."""
    ptr_lower = ptr_reg.lower()
    for va, mnem, ops in insns_window:
        if mnem.lower() in ('mov', 'movzx', 'movzwl', 'movzbl', 'movsx', 'movsxd'):
            if ptr_lower in ops.lower() and '[' in ops:
                return va
    return None


class ChunkWalkerValidator:
    """
    Scans x86-64 ELF binary for TLV/chunk pointer advancement without alignment.

    A finding is UNALIGNED if ptr += raw_length without rounding to the next
    4-byte boundary (the (length + 3) & ~3 pattern) before reading the next
    chunk's header fields.
    """

    def __init__(self, binary_path: str, ctx=None):
        self.binary_path = binary_path
        self._ctx = ctx

    @classmethod
    def from_context(cls, ctx) -> 'ChunkWalkerValidator':
        return cls(ctx.path, ctx=ctx)

    def _func_containing(self, va: int) -> int:
        if self._ctx:
            return self._ctx.func_containing(va) or va
        return va

    def scan(self) -> List[ChunkWalkFinding]:
        """Scan .text for unaligned chunk pointer advancement patterns.

        Two-phase pattern:
          1. movzwl/movzbl from memory into length_reg (chunk header field read)
          2. Within ADVANCE_LOOKAHEAD insns: ptr += length_reg (add or lea)
          3. Check for alignment ((len+3)&~3) between step 1 and step 2
          4. Within READ_LOOKAHEAD insns after advance: field read from new ptr
        """
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

        ADVANCE_LOOKAHEAD = 12  # instructions after mem-load to find advance
        BUF_KEEP = ADVANCE_LOOKAHEAD + _READ_LOOKAHEAD + 4

        findings: List[ChunkWalkFinding] = []
        buf: List[tuple] = []
        idx = 0
        CHUNK = 100_000

        def _drain():
            nonlocal idx
            while idx < len(buf):
                va, mnem, ops = buf[idx]

                # Phase 1: look for memory-based length field load
                load_info = _is_mem_length_load(mnem, ops)
                if load_info is not None:
                    len_reg, src_ptr = load_info

                    # Phase 2: look for pointer advance using length_reg
                    # Track whether length_reg is clobbered (invalidates match)
                    window_end = min(idx + ADVANCE_LOOKAHEAD, len(buf))
                    len_family = _reg_family(len_reg)
                    for j in range(idx + 1, window_end):
                        jva, jmnem, jops = buf[j]

                        # If length_reg is arithmetically modified, stop looking
                        if jmnem.lower() in _CLOBBER_MNEMS:
                            jparts = [p.strip() for p in jops.split(',')]
                            if jparts and _reg_family(jparts[0]) == len_family:
                                break  # length register clobbered

                        adv = _is_ptr_advance_with_reg(jmnem, jops, len_reg)
                        if adv is not None:
                            ptr_reg, _ = adv
                            # Check alignment in the window between load and advance
                            between = buf[idx + 1: j]
                            aligned = _has_alignment(between, len_reg)
                            # Phase 4: look for field read after advance
                            after = buf[j + 1: min(j + _READ_LOOKAHEAD + 1, len(buf))]
                            read_va_opt = _find_field_read(after, ptr_reg)
                            read_va = read_va_opt if read_va_opt else 0
                            if read_va:
                                func_va = self._func_containing(va)
                                findings.append(ChunkWalkFinding(
                                    func_va=func_va,
                                    advance_va=jva,
                                    advance_reg=ptr_reg,
                                    length_reg=len_reg,
                                    aligned=aligned,
                                    read_va=read_va,
                                ))
                            break  # one advance per load

                idx += 1

        chunk_count = 0
        for insn in cs.disasm(text_data, text_va):
            buf.append((insn.address, insn.mnemonic, insn.op_str))
            chunk_count += 1
            if chunk_count >= CHUNK:
                _drain()
                if idx > BUF_KEEP:
                    buf = buf[idx - BUF_KEEP:]
                    idx = BUF_KEEP
                chunk_count = 0
        _drain()

        return findings

    def scan_unaligned(self) -> List[ChunkWalkFinding]:
        """Return only unaligned findings (no alignment pattern detected)."""
        return [f for f in self.scan() if not f.aligned]

    def report(self, findings: Optional[List[ChunkWalkFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return 'ChunkWalkerValidator: no findings\n'
        unaligned = [f for f in findings if not f.aligned]
        lines = [
            f'ChunkWalkerValidator: {len(findings)} advances, {len(unaligned)} unaligned',
            '',
        ]
        for f in sorted(findings, key=lambda x: x.aligned):
            lines.append(f.fmt())
        return '\n'.join(lines)
