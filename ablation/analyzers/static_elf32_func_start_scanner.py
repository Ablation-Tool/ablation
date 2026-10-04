"""
ELF32 stripped static binary function start discovery via i386 prologue pattern scan.

Motivation: lief populates func_starts only from .symtab / .dynsym entries.
Statically linked stripped i386 ELF binaries have neither table populated.
Without func_starts, SemanticSearcher and TaintTracker cannot run.

Solution: scan every PT_LOAD+PF_X segment for i386 function prologue byte patterns.

    Primary:   55 89 e5        push ebp; mov ebp, esp    (CDECL, ~95% of GCC functions)
    Secondary: 55 57 56        push ebp; push edi; push esi  (callee-save variant)
               55 53           push ebp; push ebx            (small function variant)

False-positive rate for GCC i386 code: low. The 3-byte primary pattern is highly
discriminating — ModRM 0xe5 encodes (mod=11, reg=4/ESP, rm=5/EBP), a combination
that appears inside other instructions only coincidentally.

Usage:

    from ablation.analyzers.static_elf32_func_start_scanner import StaticELF32FuncStartScanner

    scanner = StaticELF32FuncStartScanner.from_path('/path/to/stripped.elf')
    starts = scanner.scan()                 # List[int] of VAs
    scanner.inject(ctx)                     # push into an existing BinaryContext

Integration note:
    BinaryContext._extract_func_starts() calls this scanner automatically for
    x86_32 binaries when starts would otherwise be empty (no eh_frame, no exports).
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ablation.analyzers.binary_context import BinaryContext

# Primary pattern: push ebp (55) + mov ebp, esp (89 e5)
_PRIMARY = b'\x55\x89\xe5'

# Secondary patterns — shorter, included only when primary count is very low
_SECONDARY = [
    b'\x55\x57\x56',   # push ebp; push edi; push esi
    b'\x55\x53',       # push ebp; push ebx
]

# ELF32 program header offsets (little-endian)
_PT_LOAD = 1
_PF_X    = 0x1

# ELF32 phdr field offsets within a 32-byte program header entry
_PHDR32_TYPE    = 0x00  # Elf32_Word  p_type
_PHDR32_OFFSET  = 0x04  # Elf32_Off   p_offset
_PHDR32_VADDR   = 0x08  # Elf32_Addr  p_vaddr
_PHDR32_FILESZ  = 0x10  # Elf32_Word  p_filesz
_PHDR32_FLAGS   = 0x18  # Elf32_Word  p_flags
_PHDR32_SIZE    = 32


@dataclass
class ScanResult:
    path: str
    starts: List[int] = field(default_factory=list)
    patterns_used: List[str] = field(default_factory=list)
    segment_count: int = 0

    def report(self) -> str:
        lines = [
            f"StaticELF32FuncStartScanner: {self.path}",
            f"  executable segments scanned: {self.segment_count}",
            f"  patterns used: {', '.join(self.patterns_used)}",
            f"  function starts found: {len(self.starts)}",
        ]
        if self.starts:
            lines.append(f"  first VA: 0x{self.starts[0]:08x}  last VA: 0x{self.starts[-1]:08x}")
        return "\n".join(lines)


class StaticELF32FuncStartScanner:
    """Discover function entry points in stripped static ELF32 binaries via prologue scan."""

    def __init__(self, raw: bytes, path: str = ""):
        self._raw = raw
        self._path = path

    @classmethod
    def from_path(cls, path: str) -> "StaticELF32FuncStartScanner":
        with open(path, "rb") as fh:
            return cls(fh.read(), path)

    @classmethod
    def from_context(cls, ctx: "BinaryContext") -> "StaticELF32FuncStartScanner":
        return cls.from_path(ctx.path)

    def scan(self) -> List[int]:
        """Return sorted list of function entry VAs."""
        result = self._scan_internal()
        return result.starts

    def scan_full(self) -> ScanResult:
        """Return full ScanResult with metadata."""
        return self._scan_internal()

    def inject(self, ctx: "BinaryContext") -> int:
        """Push discovered func_starts into an existing BinaryContext.

        Returns the number of starts injected. Updates ctx.func_starts in place.
        Only injects when ctx.func_starts is empty (avoids overwriting eh_frame data).
        """
        if ctx.func_starts:
            return 0
        starts = self.scan()
        if starts:
            ctx.func_starts = starts
        return len(starts)

    def _scan_internal(self) -> ScanResult:
        raw = self._raw
        result = ScanResult(path=self._path)

        if len(raw) < 0x34 or raw[:4] != b'\x7fELF':
            return result
        if raw[4] != 1:   # EI_CLASS must be ELFCLASS32
            return result
        if raw[5] != 1:   # EI_DATA must be ELFDATA2LSB (little-endian)
            return result

        e_phoff     = struct.unpack_from('<I', raw, 0x1c)[0]
        e_phentsize = struct.unpack_from('<H', raw, 0x2a)[0]
        e_phnum     = struct.unpack_from('<H', raw, 0x2c)[0]

        if e_phentsize < _PHDR32_SIZE or e_phnum == 0:
            return result

        starts: set = set()
        for i in range(e_phnum):
            ph = e_phoff + i * e_phentsize
            if ph + _PHDR32_SIZE > len(raw):
                break
            p_type   = struct.unpack_from('<I', raw, ph + _PHDR32_TYPE)[0]
            p_flags  = struct.unpack_from('<I', raw, ph + _PHDR32_FLAGS)[0]
            p_offset = struct.unpack_from('<I', raw, ph + _PHDR32_OFFSET)[0]
            p_vaddr  = struct.unpack_from('<I', raw, ph + _PHDR32_VADDR)[0]
            p_filesz = struct.unpack_from('<I', raw, ph + _PHDR32_FILESZ)[0]

            if p_type != _PT_LOAD or not (p_flags & _PF_X) or p_filesz == 0:
                continue
            if p_offset + p_filesz > len(raw):
                continue

            result.segment_count += 1
            seg = raw[p_offset: p_offset + p_filesz]
            seg_base = p_vaddr

            # Primary scan: push ebp; mov ebp, esp
            pos = 0
            while True:
                idx = seg.find(_PRIMARY, pos)
                if idx < 0:
                    break
                starts.add(seg_base + idx)
                pos = idx + 1

        if 'primary (55 89 e5)' not in result.patterns_used and starts:
            result.patterns_used.append('primary (55 89 e5)')

        # Fall back to secondary patterns only if primary finds very few starts
        # (threshold: fewer than 10, suggesting a non-CDECL or unusual binary)
        if len(starts) < 10:
            for pat in _SECONDARY:
                pat_starts: set = set()
                for i in range(e_phnum):
                    ph = e_phoff + i * e_phentsize
                    if ph + _PHDR32_SIZE > len(raw):
                        break
                    p_type   = struct.unpack_from('<I', raw, ph + _PHDR32_TYPE)[0]
                    p_flags  = struct.unpack_from('<I', raw, ph + _PHDR32_FLAGS)[0]
                    p_offset = struct.unpack_from('<I', raw, ph + _PHDR32_OFFSET)[0]
                    p_vaddr  = struct.unpack_from('<I', raw, ph + _PHDR32_VADDR)[0]
                    p_filesz = struct.unpack_from('<I', raw, ph + _PHDR32_FILESZ)[0]
                    if p_type != _PT_LOAD or not (p_flags & _PF_X) or p_filesz == 0:
                        continue
                    if p_offset + p_filesz > len(raw):
                        continue
                    seg = raw[p_offset: p_offset + p_filesz]
                    seg_base = p_vaddr
                    pos = 0
                    while True:
                        idx = seg.find(pat, pos)
                        if idx < 0:
                            break
                        pat_starts.add(seg_base + idx)
                        pos = idx + 1
                if pat_starts:
                    starts.update(pat_starts)
                    result.patterns_used.append(f'secondary ({pat.hex()})')

        result.starts = sorted(starts)
        return result
