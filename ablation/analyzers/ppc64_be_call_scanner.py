"""
ppc64_be_call_scanner.py: brute-force BL call-site scanner for stripped PPC64 BE ELFv1.

Why this exists:
  1. Stripped PPC64 BE ELFv1 binaries (IBM POWER Linux, GPFS, LoadLeveler) have no symbol
     table. callers_of() returns [] because the call graph requires symbol-based function
     starts to build CFG edges.
  2. callers_of() also can't resolve ELFv1 function descriptor indirection (.opd section).
  3. ROCm libLLVMOffload.so analysis (IBM-RE session 6) required a one-off BL word-sweep.
     This module codifies that pattern as a reusable analyzer.

Gap IDs: IBM-LLVM-GAP-001, GPFS-CALLGRAPH-001, LOADL-CALLGRAPH-001.

How it works:
  - PPC64 BL instruction encoding: bits[0:5]=0b010010 (opcode 18), bit[30]=1 (LK=link).
    Numeric: upper 6 bits = 0x48 AND lower 2 bits include AA=0, LK=1.
    Word value: (opcode=18 << 26) | (LI << 2) | AA | LK
    where LI is a 24-bit signed immediate (branch offset / 4, sign-extended).
    Mask: (word & 0xFC000001) == 0x48000001 for BL with AA=0.
  - Sweep every 4-byte-aligned word in .text; check BL mask; decode target VA.
  - Return all call sites whose computed target matches the requested PLT stub VA.

Usage:
    from ablation.analyzers.ppc64_be_call_scanner import PPC64BECallScanner

    scanner = PPC64BECallScanner.from_path('/tmp/extract/usr/lib/libLLVMOffload.so')
    call_sites = scanner.scan_calls_to(plt_va=0x9cbf0)   # PLT VA of system()
    for va in call_sites:
        print(f"  BL system() caller at 0x{va:x}")

    # Or scan all sink PLT entries at once:
    hits = scanner.scan_all_sinks()
    for sink_name, call_vas in hits.items():
        for va in call_vas:
            print(f"  BL {sink_name} at 0x{va:x}")
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, List, Optional

__all__ = ['PPC64BECallScanner']

# Default exec-class sinks (same as SinkArgClassifier)
_DEFAULT_SINKS = frozenset([
    'system', 'popen', 'execve', 'execvp', 'execvpe',
    'execl', 'execlp', 'execle', '__libc_system',
])

# PPC64 BL (Branch and Link, AA=0) opcode mask and match
_BL_MASK  = 0xFC000001
_BL_MATCH = 0x48000001   # opcode=18, AA=0, LK=1


def _decode_bl_target(insn_va: int, word: int) -> int:
    """Decode the absolute branch target of a BL instruction."""
    # LI field: bits[6:29] (24 bits), sign-extended, shifted left by 2
    li = (word >> 2) & 0x00FFFFFF
    if li & 0x800000:           # sign-extend
        li -= 0x1000000
    return insn_va + (li * 4)


class PPC64BECallScanner:
    """
    Brute-force BL call-site scanner for stripped PPC64 BE ELFv1 (AIX/POWER Linux).

    Sweeps the .text section word-by-word, identifies BL instructions, and returns
    call sites targeting specified PLT stub VAs.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._data: bytes = Path(path).read_bytes()
        self._text_va: int = 0
        self._text_off: int = 0
        self._text_size: int = 0
        self._plt: Dict[str, int] = {}    # symbol name → PLT stub VA
        self._init()

    @classmethod
    def from_path(cls, path: str) -> 'PPC64BECallScanner':
        return cls(path)

    @classmethod
    def from_context(cls, ctx) -> 'PPC64BECallScanner':
        """Accept a BinaryContext for API consistency; uses ctx.path and ctx.plt."""
        scanner = cls(ctx.path)
        # Override PLT with BinaryContext's already-parsed table
        scanner._plt = {v: k for k, v in ctx.plt.items()}
        return scanner

    def _init(self) -> None:
        try:
            import lief as _lief
            binary = _lief.parse(self._path)
            if binary is None:
                return
            # Find .text section
            for sec in binary.sections:
                if sec.name == '.text':
                    self._text_va   = sec.virtual_address
                    self._text_off  = sec.offset
                    self._text_size = sec.size
                    break
            # Build PLT: symbol name → PLT stub VA from pltgot relocations
            for rel in binary.pltgot_relocations:
                if not rel.has_symbol or not rel.symbol.name:
                    continue
                name = rel.symbol.name.split('@')[0]
                # For ppc64 BE ELFv1: PLT stubs are 7-instruction sequences.
                # LIEF's rel.address is the GOT entry. We need the stub VA.
                # Use the standard ppc64_elfv1_resolver if available.
                try:
                    from ablation.analyzers.ppc64_elfv1_resolver import resolve_plt_stub
                    stub_va = resolve_plt_stub(binary, rel)
                    if stub_va:
                        self._plt[name] = stub_va
                except ImportError:
                    pass
        except Exception:
            pass

    def set_plt(self, name: str, stub_va: int) -> None:
        """Manually register a PLT stub VA (for binaries where auto-detection fails)."""
        self._plt[name] = stub_va

    def scan_calls_to(self, plt_va: int) -> List[int]:
        """
        Return VAs of all BL instructions in .text whose decoded target == plt_va.

        This is a complete sweep: O(text_size / 4) word reads.
        """
        if self._text_size == 0:
            return []
        results: List[int] = []
        text_bytes = self._data[self._text_off:self._text_off + self._text_size]
        for i in range(0, len(text_bytes) - 3, 4):
            word = struct.unpack_from('>I', text_bytes, i)[0]
            if (word & _BL_MASK) != _BL_MATCH:
                continue
            insn_va = self._text_va + i
            target = _decode_bl_target(insn_va, word)
            if target == plt_va:
                results.append(insn_va)
        return results

    def scan_all_sinks(
        self,
        sinks: Optional[frozenset] = None,
    ) -> Dict[str, List[int]]:
        """
        Sweep .text for BL instructions targeting any known exec-class PLT stub.

        Returns {sink_name: [call_site_va, ...]} — only sinks with ≥1 call site.

        Uses the PLT table built during _init(). Caller can pre-populate it with
        set_plt() for binaries where auto-detection is incomplete.
        """
        target_sinks = sinks if sinks is not None else _DEFAULT_SINKS
        results: Dict[str, List[int]] = {}
        for name, stub_va in self._plt.items():
            if name not in target_sinks:
                continue
            calls = self.scan_calls_to(stub_va)
            if calls:
                results[name] = calls
        return results

    def scan_for_plt_va(self, plt_va: int, label: str = '') -> List[int]:
        """Alias for scan_calls_to() with an optional label (for logging)."""
        return self.scan_calls_to(plt_va)
