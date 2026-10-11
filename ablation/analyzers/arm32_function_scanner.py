"""
arm32_function_scanner.py: Find function starts in stripped ARM32 ELF by prologue scan.

Scans for PUSH {rN.., lr} prologues in ARM (4-byte) and Thumb-2/Thumb-1 (2-byte) mode.
Fills the gap in ARM32TaintTracker when .eh_frame is absent and no symbols exist.
"""
from __future__ import annotations

from typing import List, Optional, Set

try:
    import lief as _lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False


class ARM32FunctionScanner:
    """
    Finds function starts in stripped ARM32 ELF binaries by scanning for
    PUSH {rN.., lr} prologues in ARM (4-byte) and Thumb-2/Thumb-1 (2-byte) mode.

    Three patterns detected:
    - ARM32  PUSH with lr:   `?? [4x-7x|Cx-Fx] 2D E9` at 4-byte-aligned offsets
    - Thumb-2 PUSH with lr:  `2D E9 ?? [4x-7x|Cx-Fx]` at 2-byte-aligned offsets
    - Thumb-1 PUSH with lr:  halfword hi-byte == 0xB5 at 2-byte-aligned offsets

    In ARM32 little-endian the LR bit (register 14, bit 14 of the instruction word)
    lands in byte[1] of the 4-byte word (byte[1] & 0x40 == 0x40). Thumb-2 shares
    the same `2D E9` byte pair but at a different position; byte[3] carries the LR
    bit in that encoding. Thumb-1 puts LR in the high byte of the 16-bit instruction
    (0xB5xx), stored at the high-byte position in LE memory.
    """

    def __init__(
        self,
        data: bytes,
        text_offset: int,
        text_size: int,
        text_va: int,
        thumb_only: bool = False,
    ) -> None:
        self._data = data
        self._text_off = text_offset
        self._text_size = text_size
        self._text_va = text_va
        self._thumb_only = thumb_only

    @classmethod
    def from_path(cls, path: str) -> "ARM32FunctionScanner":
        """Build from an ARM32 ELF file path."""
        if not _LIEF_OK:
            raise ImportError("lief is required for ARM32FunctionScanner.from_path()")
        data = open(path, "rb").read()
        binary = _lief.parse(data)
        if not isinstance(binary, _lief.ELF.Binary):
            raise ValueError(f"Not an ELF binary: {path}")
        text_sec = binary.get_section(".text")
        if text_sec is not None:
            text_off = text_sec.offset
            text_size = text_sec.size
            text_va = text_sec.virtual_address
        else:
            # Fall back to first executable LOAD segment
            found = False
            for seg in binary.segments:
                if str(seg.type) == "SEGMENT_TYPES.LOAD" and (seg.flags & 1):
                    text_off = seg.file_offset
                    text_size = seg.physical_size
                    text_va = seg.virtual_address
                    found = True
                    break
            if not found:
                raise ValueError(f"No .text and no executable LOAD segment in {path}")
        thumb_only = bool(binary.header.entrypoint & 1)
        return cls(data, text_off, text_size, text_va, thumb_only)

    @classmethod
    def from_context(cls, ctx) -> "ARM32FunctionScanner":
        """Build from a BinaryContext (uses ctx.binary_path)."""
        return cls.from_path(ctx.binary_path)

    def scan(self) -> List[int]:
        """
        Return sorted list of VAs that appear to be ARM32 or Thumb function starts.

        ARM32 mode  (entry-point bit 0 == 0): ARM32 + Thumb-2 prologue scan only.
        Thumb-only  (entry-point bit 0 == 1): Thumb-2 + Thumb-1 prologue scan only.

        Thumb-1 (0xB5 byte scan) is intentionally suppressed in ARM32 mode: the
        `?? B5` byte pair appears at odd byte-positions inside ARM32 BL instruction
        encodings, producing zero-precision hits.
        """
        text = self._data[self._text_off: self._text_off + self._text_size]
        starts: Set[int] = set()

        if not self._thumb_only:
            self._scan_arm32(text, starts)
        else:
            self._scan_thumb2(text, starts)
            self._scan_thumb1(text, starts)

        return sorted(starts)

    def inject_into_context(self, ctx) -> int:
        """
        Inject discovered function starts into a BinaryContext's func_starts list.
        Returns the count of VAs added (already-known VAs are skipped).
        """
        found = self.scan()
        existing: Set[int] = set(getattr(ctx, "func_starts", None) or [])
        new_vas = [va for va in found if va not in existing]
        if new_vas:
            ctx.func_starts = sorted(existing | set(new_vas))
        return len(new_vas)

    # -------------------------------------------------------------------------
    # Internal scan routines
    # -------------------------------------------------------------------------

    def _scan_arm32(self, text: bytes, out: Set[int]) -> None:
        """ARM32: STMFD r13!, {rN.., lr} = bytes [rlist_lo] [rlist_hi|0x40] [0x2D] [0xE9]."""
        pos = 0
        while True:
            pos = text.find(b"\x2d\xe9", pos)
            if pos < 0:
                break
            insn_start = pos - 2
            if (
                insn_start >= 0
                and insn_start % 4 == 0
                and pos + 1 < len(text)
                and text[insn_start + 1] & 0x40  # LR bit in byte[1]
            ):
                out.add(self._text_va + insn_start)
            pos += 1

    def _scan_thumb2(self, text: bytes, out: Set[int]) -> None:
        """Thumb-2 32-bit: STMDB SP!, {rN.., lr} = bytes [0x2D] [0xE9] [rlist_lo] [rlist_hi|0x40].

        First halfword 0xE92D stored LE = bytes 2D E9.
        Second halfword (register list) has LR in bit 14 → hi-byte & 0x40.
        """
        pos = 0
        while True:
            pos = text.find(b"\x2d\xe9", pos)
            if pos < 0:
                break
            if (
                pos % 2 == 0
                and pos + 3 < len(text)
                and text[pos + 3] & 0x40  # LR bit in second halfword hi-byte
            ):
                out.add(self._text_va + pos)
            pos += 1

    def _scan_thumb1(self, text: bytes, out: Set[int]) -> None:
        """Thumb-1 16-bit: PUSH {rlist, lr} = halfword [rlist_lo] [0xB5] (LR bit in hi-byte)."""
        pos = 1  # B5 is the high byte; starts at byte 1
        while True:
            pos = text.find(b"\xb5", pos)
            if pos < 0:
                break
            insn_start = pos - 1
            if insn_start >= 0 and insn_start % 2 == 0:
                out.add(self._text_va + insn_start)
            pos += 2

    # -------------------------------------------------------------------------
    # Reporting
    # -------------------------------------------------------------------------

    @staticmethod
    def report(starts: List[int]) -> str:
        if not starts:
            return "ARM32FunctionScanner: 0 function starts found"
        return (
            f"ARM32FunctionScanner: {len(starts)} function starts found\n"
            f"  range: {hex(starts[0])} – {hex(starts[-1])}"
        )
