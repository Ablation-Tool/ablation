"""
ps3_opd_vtable_scanner.py — PS3 Cell PPU (PPC64) OPD-indirect C++ vtable scanner.

## Why this exists

3 things that weren't possible before in Ablation:

1. Finding any C++ vtables in PS3 PPC64 binaries. CppVtableReconstructorAnalyzer
   scans for RELA relocations and direct 8-byte text pointers. PS3 Cell PPU binaries
   use PPC64 ELF ABI v1 function descriptors (OPDs): every vtable slot is a 4-byte
   pointer into the data segment that resolves to an 8-byte {code_va, toc_va} OPD
   entry. No RELA section, no direct text pointers — zero vtables returned.

2. Locating Demonware BD / any other inline-linked C++ class virtual dispatch tables
   in a stripped PS3 game binary. Without vtables there is no way to find processPacket
   or processRelayPacket implementations short of exhaustive manual disassembly.

3. Resolving the two-level indirection automatically: vtable_ptr → OPD_entry →
   code_va. Once resolved, code VAs are injected into BinaryContext as confirmed
   function names (e.g. "vtbl_0xAB1234_slot2") and cross-referenced with nearby
   string evidence to identify the owning class.

OPD format (PS3 32-bit pointer mode):
    Each OPD entry at data VA `p`:
        code_va = u32 BE at p+0    (must be in text segment)
        toc_va  = u32 BE at p+4    (universal constant for single-module binary)

Vtable layout (Itanium ABI, PS3 variant):
    [-8] or [-4]: offset-to-top (signed, 4 bytes in 32-bit mode) — often 0 or 0xFFFFFFFF
    [-4] or [-0]: typeinfo pointer (4 bytes, data VA or 0)
    [0]:          first virtual function OPD pointer (4 bytes)
    [4]:          second virtual function OPD pointer
    ...

Usage:
    from ablation.analyzers.ps3_opd_vtable_scanner import PS3OPDVtableScanner

    scanner = PS3OPDVtableScanner.from_context(ctx)
    vtables = scanner.scan(min_slots=3)
    print(scanner.report(vtables, ctx))

    # Inject resolved function names for further analysis
    scanner.inject_into_context(vtables, ctx)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class OPDVtable:
    """A resolved vtable found in a PS3 Cell PPU binary."""

    va: int              # data segment VA of first vtable slot (past RTTI header)
    slots: int           # number of virtual method slots
    method_vas: List[int] = field(default_factory=list)  # resolved code VAs per slot
    null_slots: List[int] = field(default_factory=list)  # slot indices pointing to null stub
    rtti_offset: int = 0  # bytes before `va` where RTTI header starts
    class_hint: str = ""  # nearest string evidence, if any


class PS3OPDVtableScanner:
    """
    Scans a PS3 Cell PPU binary for C++ vtables using OPD function descriptor
    indirection.

    PS3 PPC64 binaries use PPC64 ELF ABI v1 function descriptors (OPDs):
      - Each vtable entry is a 4-byte data-segment VA pointing to an OPD.
      - Each OPD = {code_va: u32 BE, toc_va: u32 BE}.
      - toc_va is constant across all OPDs in a single-module static binary.

    Two-level scan:
      1. Scan data segment for dense runs of 4-byte values where each value
         is a valid OPD pointer (target in data, data[target+0..3] in text,
         data[target+4..7] == toc).
      2. Optionally detect the 8-byte RTTI header immediately before the run
         (offset-to-top + typeinfo pointer) to establish precise vtable bounds.

    The scanner auto-detects the TOC by scanning the OPD table at the binary's
    entry point.  Pass `toc=` to override.
    """

    # Dual-TOC note: PS3 binaries statically linking multiple C++ modules (e.g. GoldenEye
    # with r2_game and r2_BD) have two distinct TOC values. scan() uses a single toc= argument
    # and will only find vtables for that module. Call scan() twice with each TOC to get full
    # coverage. _detect_toc() returns the majority TOC from the first 64 OPD entries.

    def __init__(
        self,
        data: bytes,
        text_lo: int,
        text_hi: int,
        data_lo: int,
        data_hi: int,
        toc: int,
        null_stub: Optional[int] = None,
        strings: Optional[Dict[int, str]] = None,
    ) -> None:
        self._data     = data
        self._text_lo  = text_lo
        self._text_hi  = text_hi
        self._data_lo  = data_lo
        self._data_hi  = data_hi
        self._toc      = toc
        self._null_stub = null_stub
        self._strings  = strings or {}  # va -> str for class_hint lookup

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_context(cls, ctx, toc: Optional[int] = None) -> "PS3OPDVtableScanner":
        """Build from a BinaryContext (must be ppc64 arch)."""
        if ctx.arch not in ("ppc64", "ppc32"):
            raise ValueError(
                f"PS3OPDVtableScanner requires ppc64/ppc32 arch, got {ctx.arch!r}"
            )
        path = getattr(ctx, "path", None) or getattr(ctx, "_path", None)
        if not path:
            raise ValueError("BinaryContext has no path attribute")
        with open(path, "rb") as fh:
            data = fh.read()
        text_lo, text_hi, data_lo, data_size = _parse_segments(data)
        data_hi = data_lo + data_size
        detected_toc = toc or _detect_toc(data, text_lo, text_hi, data_lo, data_hi)
        null_stub    = _detect_null_stub(data, text_lo, text_hi, data_lo, data_hi, detected_toc)
        strings      = dict(ctx.strings) if hasattr(ctx, "strings") else {}
        return cls(data, text_lo, text_hi, data_lo, data_hi, detected_toc, null_stub, strings)

    @classmethod
    def from_path(cls, elf_path: str, toc: Optional[int] = None) -> "PS3OPDVtableScanner":
        """Build directly from an ELF path."""
        with open(elf_path, "rb") as fh:
            data = fh.read()
        text_lo, text_hi, data_lo, data_size = _parse_segments(data)
        data_hi = data_lo + data_size
        detected_toc = toc or _detect_toc(data, text_lo, text_hi, data_lo, data_hi)
        null_stub    = _detect_null_stub(data, text_lo, text_hi, data_lo, data_hi, detected_toc)
        return cls(data, text_lo, text_hi, data_lo, data_hi, detected_toc, null_stub)

    # ── Core scan ────────────────────────────────────────────────────────────

    def scan(self, min_slots: int = 3) -> List[OPDVtable]:
        """
        Find all vtables in the data segment.

        Args:
            min_slots: Minimum consecutive valid OPD slots to qualify as a vtable.

        Returns:
            List of OPDVtable sorted by va ascending.
        """
        data     = self._data
        data_lo  = self._data_lo
        data_hi  = self._data_hi
        text_lo  = self._text_lo
        text_hi  = self._text_hi
        toc      = self._toc

        vtables: List[OPDVtable] = []
        run_start: Optional[int] = None
        run_methods:  List[int]  = []
        run_nulls:    List[int]  = []
        run_slot_idx: int        = 0

        i = data_lo
        while i + 4 <= data_hi:
            ptr = _u32(data, i)
            code_va = self._resolve_opd(ptr)
            if code_va is not None:
                if run_start is None:
                    run_start     = i
                    run_methods   = []
                    run_nulls     = []
                    run_slot_idx  = 0
                is_null = (self._null_stub is not None and code_va == self._null_stub)
                run_methods.append(code_va)
                if is_null:
                    run_nulls.append(run_slot_idx)
                run_slot_idx += 1
                i += 4
            else:
                if run_start is not None and len(run_methods) >= min_slots:
                    rtti_off = self._detect_rtti_header(run_start)
                    hint = self._class_hint(run_start, run_methods)
                    vtables.append(OPDVtable(
                        va          = run_start,
                        slots       = len(run_methods),
                        method_vas  = list(run_methods),
                        null_slots  = list(run_nulls),
                        rtti_offset = rtti_off,
                        class_hint  = hint,
                    ))
                run_start    = None
                run_methods  = []
                run_nulls    = []
                run_slot_idx = 0
                i += 4

        # flush trailing run
        if run_start is not None and len(run_methods) >= min_slots:
            rtti_off = self._detect_rtti_header(run_start)
            hint = self._class_hint(run_start, run_methods)
            vtables.append(OPDVtable(
                va          = run_start,
                slots       = len(run_methods),
                method_vas  = list(run_methods),
                null_slots  = list(run_nulls),
                rtti_offset = rtti_off,
                class_hint  = hint,
            ))

        return sorted(vtables, key=lambda v: v.va)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _resolve_opd(self, ptr: int) -> Optional[int]:
        """
        Resolve a 4-byte OPD pointer to a code VA.
        Returns None if ptr is not a valid OPD pointer.
        """
        data    = self._data
        data_lo = self._data_lo
        data_hi = self._data_hi
        text_lo = self._text_lo
        text_hi = self._text_hi
        toc     = self._toc

        if not (data_lo <= ptr <= data_hi - 8):
            return None
        code_va = _u32(data, ptr)
        toc_va  = _u32(data, ptr + 4)
        if not (text_lo <= code_va < text_hi):
            return None
        if toc_va != toc:
            return None
        return code_va

    def _detect_rtti_header(self, vtable_va: int) -> int:
        """
        Check whether the 8 bytes immediately before the vtable VA look like
        a C++ RTTI header (offset-to-top + typeinfo pointer).
        Returns the byte offset from the RTTI start to the vtable body (8 or 0).
        """
        if vtable_va - 8 < self._data_lo:
            return 0
        offset_to_top = _u32(self._data, vtable_va - 8)
        typeinfo_ptr  = _u32(self._data, vtable_va - 4)
        # offset_to_top: 0 or 0xFFFFFFFF (−1) are the common primary-vtable values
        valid_oto = offset_to_top in (0x00000000, 0xFFFFFFFF)
        # typeinfo_ptr: 0 (abstract) or points into data segment
        valid_ti  = (typeinfo_ptr == 0 or
                     self._data_lo <= typeinfo_ptr < self._data_hi)
        if valid_oto and valid_ti:
            return 8
        return 0

    def _build_string_index(self) -> None:
        """Build sorted string VA index for O(log n) proximity lookup."""
        if not hasattr(self, "_sorted_str_vas"):
            self._sorted_str_vas = sorted(self._strings.keys())

    def _class_hint(self, vtable_va: int, method_vas: List[int]) -> str:
        """
        Return the nearest string within 256 bytes of the vtable as a class hint.
        Uses bisect for O(log n) lookup.
        """
        if not self._strings:
            return ""
        import bisect
        self._build_string_index()
        idx = bisect.bisect_left(self._sorted_str_vas, vtable_va)
        candidates = []
        for i in range(max(0, idx - 8), min(len(self._sorted_str_vas), idx + 8)):
            sva = self._sorted_str_vas[i]
            dist = abs(sva - vtable_va)
            if dist <= 256:
                s = self._strings[sva]
                if len(s) > 4 and " " not in s:
                    candidates.append((dist, s))
        if not candidates:
            return ""
        candidates.sort()
        return candidates[0][1][:60]

    # ── Injection ────────────────────────────────────────────────────────────

    def inject_into_context(self, vtables: List[OPDVtable], ctx) -> int:
        """
        Register vtable method VAs as named functions in ctx.

        Names follow the pattern: vtbl_<vtable_va_hex>_s<slot_index>
        Non-null slots get: vtbl_<vtable_va>_s<N>
        If ctx already has a name for a VA, it is not overwritten.

        Returns the number of new names injected.
        """
        count = 0
        for vtbl in vtables:
            for slot_idx, code_va in enumerate(vtbl.method_vas):
                if slot_idx in vtbl.null_slots:
                    continue
                existing = ctx.name(code_va)
                if existing and not existing.startswith("0x"):
                    continue  # already named
                name = f"vtbl_{vtbl.va:x}_s{slot_idx}"
                ctx.set_name(code_va, name, source="opd_vtable")
                count += 1
        return count

    # ── Reporting ─────────────────────────────────────────────────────────────

    def report(
        self,
        vtables: List[OPDVtable],
        ctx=None,
        top_n: int = 50,
        min_slots: int = 0,
    ) -> str:
        """ASCII table of found vtables, sorted by slot count descending."""
        name_fn = ctx.name if ctx is not None else lambda va: f"0x{va:x}"
        filtered = [v for v in vtables if v.slots >= min_slots]
        filtered.sort(key=lambda v: v.slots, reverse=True)

        lines = [f"PS3 OPD vtable scan — {len(vtables)} vtables found"]
        lines.append(f"  toc=0x{self._toc:x}  null_stub={f'0x{self._null_stub:x}' if self._null_stub else 'none'}")
        lines.append("")
        lines.append(f"  {'VA':<12}  {'slots':>5}  {'null':>4}  {'hint':<40}  first_methods")
        lines.append("  " + "-" * 100)

        for vtbl in filtered[:top_n]:
            null_idx_set = set(vtbl.null_slots)
            first = "  ".join(
                name_fn(va)
                for idx, va in enumerate(vtbl.method_vas[:3])
                if idx not in null_idx_set
            )
            hint = vtbl.class_hint[:38] if vtbl.class_hint else ""
            rtti = f" [rtti-{vtbl.rtti_offset}B]" if vtbl.rtti_offset else ""
            lines.append(
                f"  0x{vtbl.va:08x}  {vtbl.slots:5d}  {len(vtbl.null_slots):4d}  "
                f"{hint:<40}  {first}{rtti}"
            )

        return "\n".join(lines)

    def find_by_method_name(
        self,
        vtables: List[OPDVtable],
        name: str,
        ctx,
    ) -> List[Tuple[OPDVtable, int, int]]:
        """
        Find vtables containing a slot whose code VA has the given name in ctx.
        Returns list of (vtable, slot_index, code_va).
        """
        results = []
        for vtbl in vtables:
            for slot_idx, code_va in enumerate(vtbl.method_vas):
                if ctx.name(code_va) == name:
                    results.append((vtbl, slot_idx, code_va))
        return results

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def toc(self) -> int:
        return self._toc

    @property
    def null_stub(self) -> Optional[int]:
        return self._null_stub


# ── Module-level helpers ──────────────────────────────────────────────────────

def _u32(data: bytes, offset: int) -> int:
    """Read a big-endian unsigned 32-bit integer."""
    return struct.unpack_from(">I", data, offset)[0]


def _parse_segments(data: bytes) -> Tuple[int, int, int, int]:
    """
    Parse the first ELF64 BE LOAD segments to find text and data ranges.
    Returns (text_lo, text_hi, data_lo, data_size).
    """
    if data[:4] != b"\x7fELF":
        raise ValueError("Not a valid ELF file")
    e_phoff      = struct.unpack_from(">Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from(">HH", data, 0x36)

    text_lo = text_hi = data_lo = data_size = 0
    for i in range(e_phnum):
        poff = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = \
            struct.unpack_from(">IIQQQQQQ", data, poff)
        if p_type != 1 or p_filesz == 0:  # PT_LOAD with data
            continue
        if p_flags & 0x1:  # execute bit → text
            text_lo = p_vaddr
            text_hi = p_vaddr + p_filesz
        elif p_flags & 0x2:  # write bit → data
            data_lo   = p_vaddr
            data_size = p_filesz

    return text_lo, text_hi, data_lo, data_size


def _detect_toc(
    data: bytes,
    text_lo: int, text_hi: int,
    data_lo: int, data_hi: int,
) -> int:
    """
    Auto-detect the TOC (r2) value by scanning the entry point OPD table.
    The TOC appears as the second u32 in every OPD entry; it is constant for
    a single-module PS3 game binary.

    Uses the ELF entry point to find the OPD region, then takes a majority vote
    over the first 32 OPD entries.
    """
    e_entry = struct.unpack_from(">Q", data, 0x18)[0]

    # e_entry may be a 64-bit value but PS3 uses 32-bit addressing
    if e_entry > 0xFFFFFFFF:
        e_entry = e_entry & 0xFFFFFFFF

    toc_votes: Dict[int, int] = {}

    # Scan from entry OPD outward
    for i in range(0, 0x200, 8):
        off = e_entry + i
        if off + 8 > len(data) or off + 8 > data_hi:
            break
        code_va = _u32(data, off)
        toc_va  = _u32(data, off + 4)
        if text_lo <= code_va < text_hi and data_lo <= toc_va < data_hi:
            toc_votes[toc_va] = toc_votes.get(toc_va, 0) + 1

    if not toc_votes:
        raise RuntimeError(
            f"Could not detect TOC from OPD at entry 0x{e_entry:x}. "
            "Pass toc= explicitly."
        )
    return max(toc_votes, key=toc_votes.__getitem__)


def _detect_null_stub(
    data: bytes,
    text_lo: int, text_hi: int,
    data_lo: int, data_hi: int,
    toc: int,
    opd_scan_limit: int = 0x4000,
) -> Optional[int]:
    """
    Detect the pure-virtual / null stub VA by finding the most common code_va
    among OPD entries (after a threshold of repetitions).  Pure-virtual stubs
    appear dozens of times across all vtables.
    """
    e_entry = struct.unpack_from(">Q", data, 0x18)[0] & 0xFFFFFFFF

    freq: Dict[int, int] = {}
    for i in range(0, opd_scan_limit, 8):
        off = e_entry + i
        if off + 8 > len(data) or off + 8 > data_hi:
            break
        code_va = _u32(data, off)
        toc_va  = _u32(data, off + 4)
        if text_lo <= code_va < text_hi and toc_va == toc:
            freq[code_va] = freq.get(code_va, 0) + 1

    if not freq:
        return None
    # The null stub is the VA appearing most frequently (≥4 times)
    top_va, top_count = max(freq.items(), key=lambda kv: kv[1])
    return top_va if top_count >= 4 else None
