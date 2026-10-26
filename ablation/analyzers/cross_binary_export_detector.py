"""
cross_binary_export_detector.py: Identify compiled functions with zero callers
in the current binary that are likely called from a companion binary.

In multi-binary firmware suites (daemon + helper + shared library), some
functions have zero CALL rel32 callers in binary A because they are only
invoked from binary B via function pointer tables, vtables, or direct symbol
calls. Static analysis stops at the binary boundary — these functions appear
"unreachable" even though they are active entry points.

CrossBinaryExportDetector distinguishes genuinely dead code from cross-binary
exports using a four-part heuristic. A function is tagged CROSS_BINARY_EXPORT
when ALL of these hold:

  1. No CALL rel32 callers in the binary's call_edges.
  2. Not present in any vtable recovered by VtableDispatchMapper.
  3. Has a stack canary (mov rax, fs:[0x28] pattern near the prologue) — rules
     out compiler-generated trampolines, exception landing pads, and stubs.
  4. Has at least one debug log string referencing a source file path — rules
     out hot-patch stubs and compiler-generated helpers.

Usage:
    from ablation.analyzers.cross_binary_export_detector import CrossBinaryExportDetector

    det = CrossBinaryExportDetector.from_context(ctx)
    exports = det.detect()
    for e in exports:
        print(e.fmt())
    print(det.report(exports))
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class CrossBinaryExport:
    """A function with zero local callers that is likely called from another binary."""
    func_va:      int
    name:         str        # ctx name or hex string
    canary:       bool
    debug_string: str        # first matched source-path string, or ''
    caller_count: int        # always 0 by definition

    def fmt(self) -> str:
        tag = '[CROSS_BINARY_EXPORT]'
        name_s = self.name or hex(self.func_va)
        dbg = f"  debug: {self.debug_string!r}" if self.debug_string else ""
        return (
            f"  {tag}  {name_s} @ {self.func_va:#010x}"
            f"  canary={self.canary}{dbg}"
        )

    def as_dict(self) -> dict:
        return {
            'func_va':      hex(self.func_va),
            'name':         self.name,
            'canary':       self.canary,
            'debug_string': self.debug_string,
            'caller_count': self.caller_count,
        }


# ── Detector ──────────────────────────────────────────────────────────────────

# Byte patterns for stack canary reads on x86-64:
#   64 48 8b 04 25 28 00 00 00   mov rax, qword ptr fs:[0x28]  (FS prefix)
#   48 8b 04 25 28 00 00 00      mov rax, qword ptr [0x28]     (rare)
_CANARY_PATTERNS = [
    b'\x64\x48\x8b\x04\x25\x28\x00\x00\x00',
    b'\x48\x8b\x04\x25\x28\x00\x00\x00',
]

# Source-path heuristic: a string that looks like a C++ source file path.
# Must contain '/' and end in .cpp, .c, .h, .cc, .cxx (case-insensitive).
_SRC_PATH_RE = re.compile(rb'/[^\x00]{4,200}\.(cpp|c|h|cc|cxx)\x00', re.IGNORECASE)

# How far past the ENDBR64 to search for a stack canary (bytes)
_CANARY_SEARCH_BYTES = 128

# How far past the function start to look for a debug string xref (bytes)
_DEBUG_SEARCH_BYTES  = 512


class CrossBinaryExportDetector:
    """
    Detect functions that have zero local callers and are likely cross-binary
    entry points.
    """

    def __init__(self, ctx) -> None:
        self._ctx  = ctx
        self._data: bytes = Path(ctx.path).read_bytes()
        self._text_off  = self._find_text_offset()
        self._text_va   = self._find_text_va()

    @classmethod
    def from_context(cls, ctx) -> 'CrossBinaryExportDetector':
        return cls(ctx)

    # ── public API ────────────────────────────────────────────────────────────

    def detect(
        self,
        vtable_mapper=None,
        min_func_size: int = 16,
    ) -> List[CrossBinaryExport]:
        """
        Return all functions that match the cross-binary export heuristic.

        Args:
            vtable_mapper: a VtableDispatchMapper instance, or None. When
                           provided, functions in any vtable are excluded.
            min_func_size: skip functions smaller than this (trampolines).
        """
        ctx = self._ctx

        # Build incoming-call-edge count map
        incoming: Dict[int, int] = {}
        for src, dst, _ann in ctx.call_edges:
            incoming[dst] = incoming.get(dst, 0) + 1

        # Functions in vtables (exclude them from results)
        vtable_fns: Set[int] = set()
        if vtable_mapper is not None:
            for fn_va in vtable_mapper._rev:
                vtable_fns.add(fn_va)

        results: List[CrossBinaryExport] = []

        for fn_va in ctx.func_starts:
            # Criterion 1: zero call-edge callers
            if incoming.get(fn_va, 0) > 0:
                continue

            # Criterion 2: not in a vtable
            if fn_va in vtable_fns:
                continue

            # Criterion 3: stack canary present
            canary = self._has_canary(fn_va, _CANARY_SEARCH_BYTES)
            if not canary:
                continue

            # Criterion 4: at least one debug/source string xref nearby
            debug_str = self._find_debug_string(fn_va, _DEBUG_SEARCH_BYTES)
            if not debug_str:
                continue

            # Size guard: skip obvious stubs
            next_fn = self._next_func_after(fn_va, ctx.func_starts)
            if next_fn and (next_fn - fn_va) < min_func_size:
                continue

            name = ctx.name(fn_va) if hasattr(ctx, 'name') else hex(fn_va)
            results.append(CrossBinaryExport(
                func_va      = fn_va,
                name         = name,
                canary       = canary,
                debug_string = debug_str,
                caller_count = 0,
            ))

        return results

    def report(self, exports: List[CrossBinaryExport]) -> str:
        lines = [
            f"CrossBinaryExportDetector: {Path(self._ctx.path).name}",
            f"  candidates: {len(exports)}",
            "",
        ]
        for e in exports:
            lines.append(e.fmt())
        return "\n".join(lines)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _find_text_offset(self) -> int:
        # TEXT section file offset: for PIE, va == file offset
        data = self._data
        if data[:4] != b'\x7fELF':
            return 0
        e_shoff, = struct.unpack_from('<Q', data, 40)
        e_shentsize, = struct.unpack_from('<H', data, 58)
        e_shnum, = struct.unpack_from('<H', data, 60)
        e_shstrndx, = struct.unpack_from('<H', data, 62)
        if e_shoff == 0 or e_shstrndx >= e_shnum:
            return 0
        str_hdr = e_shoff + e_shstrndx * e_shentsize
        str_off, = struct.unpack_from('<Q', data, str_hdr + 24)
        str_size, = struct.unpack_from('<Q', data, str_hdr + 32)
        strtab = data[str_off:str_off + str_size]
        for i in range(e_shnum):
            hdr = e_shoff + i * e_shentsize
            sh_name, = struct.unpack_from('<I', data, hdr)
            if sh_name >= len(strtab):
                continue
            end = strtab.find(b'\x00', sh_name)
            name = strtab[sh_name:end].decode('utf-8', errors='replace')
            if name == '.text':
                sh_off, = struct.unpack_from('<Q', data, hdr + 24)
                return sh_off
        return 0

    def _find_text_va(self) -> int:
        # For standard PIE (base=0), file offset == VA in .text
        return self._text_off

    def _va_to_off(self, va: int) -> int:
        # PIE: offset == va (base 0)
        return va

    def _has_canary(self, fn_va: int, search_bytes: int) -> bool:
        off = self._va_to_off(fn_va)
        window = self._data[off:off + search_bytes]
        return any(p in window for p in _CANARY_PATTERNS)

    def _find_debug_string(self, fn_va: int, search_bytes: int) -> str:
        """Return first source-path string xreffed within search_bytes of fn_va."""
        off = self._va_to_off(fn_va)
        window = self._data[off:off + search_bytes]
        # Look for LEA rip-relative instructions referencing source path strings
        # Pattern: 48 8d xx [rip + disp32] (REX.W LEA) or 4c 8d xx
        i = 0
        while i < len(window) - 7:
            b = window[i]
            # LEA with RIP-relative: 48|4c|4d 8d [ModRM with mod=00,rm=101] disp32
            if b in (0x48, 0x4c, 0x4d, 0x49) and i + 6 < len(window):
                if window[i + 1] == 0x8d:
                    modrm = window[i + 2]
                    mod = (modrm >> 6) & 3
                    rm  = modrm & 7
                    if mod == 0 and rm == 5:  # RIP-relative
                        disp = struct.unpack_from('<i', window, i + 3)[0]
                        target_va = fn_va + i + 7 + disp
                        t_off = self._va_to_off(target_va)
                        if 0 <= t_off < len(self._data) - 4:
                            # Check if it's a source path string
                            candidate = self._data[t_off:t_off + 220]
                            m = _SRC_PATH_RE.match(candidate)
                            if m:
                                return candidate[:m.end() - 1].decode('utf-8', errors='replace')
            i += 1
        return ''

    @staticmethod
    def _next_func_after(fn_va: int, func_starts) -> Optional[int]:
        """Return the smallest func_start > fn_va, or None."""
        nxt = None
        for va in func_starts:
            if va > fn_va:
                if nxt is None or va < nxt:
                    nxt = va
        return nxt
