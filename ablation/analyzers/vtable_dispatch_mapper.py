"""
vtable_dispatch_mapper.py: Recover C++ vtable layouts from R_X86_64_RELATIVE
relocations in PIE x86-64 ELF binaries.

In stripped PIE C++ binaries, virtual dispatch is opaque to call-graph analysis:
callers use `call *[reg+offset]` with no static target. VtableDispatchMapper
reverses the vtable to answer "which vtable(s) contain this function VA, and at
which slot?" — making virtual callers discoverable.

Algorithm summary:
  1. Parse .rela.dyn for R_X86_64_RELATIVE (type 8) entries whose addends fall
     in the TEXT section (function pointers, not metadata).
  2. Sort by r_offset. Group consecutive r_offsets that differ by exactly 8
     (pointer-width) into runs of ≥ MIN_VTABLE_SLOTS entries.
  3. For each run, emit a Vtable: start VA (in .data.rel.ro), function slot list,
     and reverse index from each function VA to its vtable slots.

Usage:
    from ablation.analyzers.vtable_dispatch_mapper import VtableDispatchMapper

    mapper = VtableDispatchMapper.from_context(ctx)
    slots = mapper.callers_via_vtable(0x156210)   # CheckHip
    for s in slots:
        print(f"vtable @ {s.vtable_va:#x}  slot {s.slot_index}")

    # or from a binary path:
    mapper = VtableDispatchMapper.from_path('/path/to/binary')
    print(mapper.report())
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_LIEF_OK = False
try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    pass

# Minimum consecutive function-pointer slots required to call a run a vtable.
# 2 catches even tiny pure-virtual classes; raise to 3 to reduce noise.
MIN_VTABLE_SLOTS = 2

# R_X86_64_RELATIVE relocation type
_R_RELATIVE = 8


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class VtableSlot:
    """One function's presence in a vtable."""
    vtable_va:   int   # VA of the start of the vtable (in .data.rel.ro)
    slot_index:  int   # 0-based index of this function within the vtable
    func_va:     int   # function VA (r_addend of the RELATIVE reloc)


@dataclass
class Vtable:
    """A recovered vtable: a contiguous run of function-pointer slots."""
    va:      int         # VA of the first slot (in .data.rel.ro)
    slots:   List[int]   # ordered function VAs for each slot (None if non-TEXT)
    size:    int         # number of slots

    def slot_of(self, func_va: int) -> Optional[int]:
        """Return 0-based slot index of func_va, or None."""
        for i, va in enumerate(self.slots):
            if va == func_va:
                return i
        return None


# ── Main class ────────────────────────────────────────────────────────────────

class VtableDispatchMapper:
    """
    Build the full vtable map for a PIE x86-64 ELF binary and answer
    reverse-dispatch queries: given a function VA, which vtables contain it?
    """

    def __init__(self, binary_path: str) -> None:
        self._path = binary_path
        self._data: bytes = Path(binary_path).read_bytes()
        self._vtables:  List[Vtable] = []
        self._rev: Dict[int, List[VtableSlot]] = {}   # func_va → slots
        self._text_start = 0
        self._text_end   = 0
        self._built = False

    @classmethod
    def from_path(cls, path: str) -> 'VtableDispatchMapper':
        obj = cls(path)
        obj._build()
        return obj

    @classmethod
    def from_context(cls, ctx) -> 'VtableDispatchMapper':
        obj = cls(ctx.path)
        obj._build()
        return obj

    # ── public API ────────────────────────────────────────────────────────────

    def callers_via_vtable(self, func_va: int) -> List[VtableSlot]:
        """Return all vtable slots containing func_va."""
        return self._rev.get(func_va, [])

    def vtable_at(self, va: int) -> Optional[Vtable]:
        """Return vtable whose start VA matches exactly."""
        for vt in self._vtables:
            if vt.va == va:
                return vt
        return None

    def vtable_containing(self, va: int) -> Optional[Tuple[Vtable, int]]:
        """Return (vtable, slot_index) if va falls inside any vtable slot."""
        for vt in self._vtables:
            slot = vt.slot_of(va)
            if slot is not None:
                return (vt, slot)
        return None

    def all_vtables(self) -> List[Vtable]:
        return list(self._vtables)

    def report(self, max_vtables: int = 20) -> str:
        lines = [
            f"VtableDispatchMapper: {Path(self._path).name}",
            f"  vtables found : {len(self._vtables)}",
            f"  functions in vtables: {len(self._rev)}",
            f"  text range    : {self._text_start:#010x} – {self._text_end:#010x}",
            "",
        ]
        for vt in self._vtables[:max_vtables]:
            lines.append(f"  vtable @ {vt.va:#010x}  ({vt.size} slots)")
            for i, fn in enumerate(vt.slots):
                lines.append(f"    [{i:2d}] {fn:#010x}")
        if len(self._vtables) > max_vtables:
            lines.append(f"  ... ({len(self._vtables) - max_vtables} more)")
        return "\n".join(lines)

    # ── build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        if self._built:
            return
        self._built = True

        if not _LIEF_OK:
            return
        binary = _lief.parse(self._path)
        if not isinstance(binary, _lief.ELF.Binary):
            return

        # Locate TEXT section to filter function-pointer addends
        text_sec = binary.get_section('.text')
        if text_sec:
            self._text_start = text_sec.virtual_address
            self._text_end   = text_sec.virtual_address + text_sec.size
        else:
            # Fallback: scan all executable segments
            for seg in binary.segments:
                if seg.has(getattr(_lief.ELF.Segment.FLAGS, 'X', None) or 0x1):
                    if self._text_start == 0 or seg.virtual_address < self._text_start:
                        self._text_start = seg.virtual_address
                    end = seg.virtual_address + seg.virtual_size
                    if end > self._text_end:
                        self._text_end = end

        # Collect all RELATIVE relocs whose addend points into TEXT
        rela_dyn = binary.get_section('.rela.dyn')
        if not rela_dyn:
            return
        rela_data = bytes(rela_dyn.content)
        n = len(rela_data) // 24

        fn_relocs: List[Tuple[int, int]] = []  # (r_offset, addend)
        for i in range(n):
            off = i * 24
            r_offset, r_info, r_addend = struct.unpack_from('<QQq', rela_data, off)
            r_type = r_info & 0xffffffff
            if r_type == _R_RELATIVE and self._text_start <= r_addend < self._text_end:
                fn_relocs.append((r_offset, r_addend))

        # Sort by location in .data.rel.ro
        fn_relocs.sort(key=lambda x: x[0])

        # Group consecutive 8-byte-aligned runs → vtable candidates
        if not fn_relocs:
            return

        current_run: List[Tuple[int, int]] = [fn_relocs[0]]

        def _flush(run: List[Tuple[int, int]]) -> None:
            if len(run) < MIN_VTABLE_SLOTS:
                return
            vt = Vtable(
                va    = run[0][0],
                slots = [addend for _, addend in run],
                size  = len(run),
            )
            self._vtables.append(vt)
            for idx, (_, fn_va) in enumerate(run):
                slot = VtableSlot(vtable_va=vt.va, slot_index=idx, func_va=fn_va)
                self._rev.setdefault(fn_va, []).append(slot)

        for prev, cur in zip(fn_relocs, fn_relocs[1:]):
            if cur[0] - prev[0] == 8:
                current_run.append(cur)
            else:
                _flush(current_run)
                current_run = [cur]
        _flush(current_run)
