"""
i386 absolute-address string xref scanner.

Motivation: x86-32 (i386) encodes string and data references as 4-byte LE
absolute immediates embedded in instructions (e.g. `push imm32`, `mov reg, imm32`,
`lea reg, [addr]`). The existing BinaryContext xref scanner uses RIP-relative
displacement arithmetic (x86-64 only) and finds almost nothing in i386 code.

    wsconv (675KB static stripped ELF32): 21 xrefs from RIP-relative scanner,
    hundreds expected. This scanner yields the correct count.

Algorithm: scan every byte offset in .text for 4-byte LE values that land exactly
on a known string VA. Attribute each hit to the enclosing function via func_starts
binary search. False-positive rate is low because the filter requires an exact
match with a known null-terminated string boundary.

ELF32 only. PE32 (i386 DLL/EXE) is not supported — PE32 binaries use import-table
indirection for most string access and a direct scan produces too many false positives
from jump-table and vtable entries that happen to fall in .rdata ranges.

Usage:

    from ablation.analyzers.i386_absolute_xref_scanner import I386AbsoluteXrefScanner

    scanner = I386AbsoluteXrefScanner.from_context(ctx)
    result  = scanner.scan_full()
    print(result.report())

    # Or inject directly into ctx:
    n = scanner.inject(ctx)           # populates ctx._str_xref_idx, ctx._func_str_idx

Integration note:
    BinaryContext._build_string_xref_index() calls this scanner automatically for
    x86_32 ELF binaries. It fires AFTER func_starts are populated (StaticELF32FuncStartScanner
    runs first), so func_containing() works correctly.
"""

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ablation.analyzers.binary_context import BinaryContext

try:
    import numpy as np
    _NUMPY_OK = True
except ImportError:
    _NUMPY_OK = False


@dataclass
class XrefResult:
    path: str
    xrefs: List[Tuple[int, int]] = field(default_factory=list)  # (code_va, string_va)
    strings_scanned: int = 0
    text_bytes: int = 0

    def report(self) -> str:
        lines = [
            f"I386AbsoluteXrefScanner: {self.path}",
            f"  .text size    : {self.text_bytes} bytes",
            f"  string VAs    : {self.strings_scanned}",
            f"  xref pairs    : {len(self.xrefs)}",
        ]
        if self.xrefs:
            uniq_strs = len({sv for _, sv in self.xrefs})
            uniq_funcs = len({cv for cv, _ in self.xrefs})
            lines.append(f"  unique strings: {uniq_strs}  unique functions: {uniq_funcs}")
        return "\n".join(lines)

    def str_xref_idx(self) -> Dict[int, List[int]]:
        """string_va → [code_va, ...]"""
        idx: Dict[int, List[int]] = {}
        for code_va, sva in self.xrefs:
            idx.setdefault(sva, []).append(code_va)
        return idx

    def func_str_idx(
        self,
        func_containing_fn,
    ) -> Dict[int, List[int]]:
        """func_va → [string_va, ...]  (deduplicated)"""
        idx: Dict[int, List[int]] = {}
        for code_va, sva in self.xrefs:
            fva = func_containing_fn(code_va)
            if fva is not None:
                idx.setdefault(fva, []).append(sva)
        return {k: list(dict.fromkeys(v)) for k, v in idx.items()}


class I386AbsoluteXrefScanner:
    """Scan i386 ELF32 .text for absolute 4-byte string VA references."""

    def __init__(self, path: str, ctx: "Optional[BinaryContext]" = None):
        self._path = path
        self._ctx = ctx

    @classmethod
    def from_path(cls, path: str) -> "I386AbsoluteXrefScanner":
        return cls(path, ctx=None)

    @classmethod
    def from_context(cls, ctx: "BinaryContext") -> "I386AbsoluteXrefScanner":
        return cls(ctx.path, ctx=ctx)

    def scan_full(self) -> XrefResult:
        import lief
        result = XrefResult(path=self._path)

        binary = lief.parse(self._path)
        if binary is None:
            return result

        text_sec = binary.get_section(".text")
        if text_sec is None:
            return result

        text_data = bytes(text_sec.content)
        text_va   = int(text_sec.virtual_address)
        result.text_bytes = len(text_data)

        # Collect string VAs.  If we have a context, use its strings dict
        # (already scanned from .rodata).  Otherwise build a minimal set
        # from .rodata null-terminated strings.
        if self._ctx is not None and self._ctx.strings:
            string_vas = sorted(self._ctx.strings.keys())
        else:
            string_vas = self._scan_strings(binary)

        result.strings_scanned = len(string_vas)
        if not string_vas or len(text_data) < 4:
            return result

        if _NUMPY_OK:
            xrefs = self._scan_numpy(text_data, text_va, string_vas)
        else:
            xrefs = self._scan_pure(text_data, text_va, string_vas)

        result.xrefs = xrefs
        return result

    def inject(self, ctx: "BinaryContext") -> int:
        """Populate ctx._str_xref_idx and ctx._func_str_idx in-place.

        Returns number of xref pairs injected.  Skips if ctx already has xrefs.
        """
        if ctx._str_xref_idx:
            return 0
        result = self.scan_full()
        if not result.xrefs:
            return 0

        str_xref: Dict[int, List[int]] = {}
        func_str: Dict[int, List[int]] = {}

        for code_va, sva in result.xrefs:
            fva = ctx.func_containing(code_va)
            if fva is None:
                continue
            str_xref.setdefault(sva, []).append(code_va)
            func_str.setdefault(fva, []).append(sva)

        ctx._str_xref_idx = str_xref
        ctx._func_str_idx = {k: list(dict.fromkeys(v)) for k, v in func_str.items()}
        return sum(len(v) for v in str_xref.values())

    # ── internals ────────────────────────────────────────────────────────────

    def _scan_numpy(
        self,
        text_data: bytes,
        text_va: int,
        string_vas: List[int],
    ) -> List[Tuple[int, int]]:
        from numpy.lib.stride_tricks import as_strided

        N = len(text_data)
        end = N - 3

        # Build 4-byte LE windows at every byte offset
        buf_u8 = np.frombuffer(text_data, dtype=np.uint8)
        windows = as_strided(buf_u8, shape=(end, 4), strides=(1, 1))
        abs_u32 = (
            windows[:, 0].astype(np.uint32)
            | (windows[:, 1].astype(np.uint32) << 8)
            | (windows[:, 2].astype(np.uint32) << 16)
            | (windows[:, 3].astype(np.uint32) << 24)
        ).astype(np.int64)

        # i386 absolute: target VA = the raw 4-byte LE value itself
        str_va_arr = np.array(string_vas, dtype=np.int64)

        hits = np.searchsorted(str_va_arr, abs_u32)
        clipped = np.minimum(hits, len(str_va_arr) - 1)
        valid = str_va_arr[clipped] == abs_u32

        positions = np.arange(end, dtype=np.int64)
        hit_pos  = positions[valid].tolist()
        hit_svas = abs_u32[valid].tolist()

        return [(text_va + int(p), int(sv)) for p, sv in zip(hit_pos, hit_svas)]

    def _scan_pure(
        self,
        text_data: bytes,
        text_va: int,
        string_vas: List[int],
    ) -> List[Tuple[int, int]]:
        """Pure-Python fallback (slow but correct)."""
        sva_set = set(string_vas)
        xrefs = []
        N = len(text_data) - 3
        for i in range(N):
            val = struct.unpack_from("<I", text_data, i)[0]
            if val in sva_set:
                xrefs.append((text_va + i, val))
        return xrefs

    @staticmethod
    def _scan_strings(binary) -> List[int]:
        """Fallback: scan .rodata for null-terminated strings when no ctx available."""
        import lief
        rodata = binary.get_section(".rodata")
        if rodata is None:
            return []
        data = bytes(rodata.content)
        base = int(rodata.virtual_address)
        vas = []
        i = 0
        while i < len(data):
            j = data.find(b'\x00', i)
            if j < 0:
                break
            if j > i:   # non-empty string
                vas.append(base + i)
            i = j + 1
        return vas
