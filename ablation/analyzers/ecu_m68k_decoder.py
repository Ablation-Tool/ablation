"""
Motorola M68K / CPU32 decoder for ECU firmware.

CPU32 is the core used in GM P-series PCMs (P01, P04, P05, P08, P10, P11,
P59).  It is a derivative of the 68020 instruction set.  Capstone 5.0.7
decodes M68K via CS_ARCH_M68K / CS_MODE_M68K_020; CPU32-specific instructions
are a subset of 68020 so that mode is correct.

Capstone handles variable-length M68K instruction decoding (2, 4, 6, or 8
bytes per instruction).  This module adds:

* ``M68kInsn`` — a dataclass wrapping Capstone output with the same field
  conventions as ``VLEInsn`` so both can be fed to the same pipeline stage.
* ``function_starts()`` — pure pattern scan for ``LINK.W A6, #-N`` (GM CPU32
  frame-allocation convention) and ``MOVEM.L regs, -(SP)`` (callee-save-only
  leaf functions); no Capstone round-trip needed for the scan.

Usage::

    from ablation.analyzers.ecu_m68k_decoder import EcuM68kDecoder

    dec = EcuM68kDecoder(rom_bytes, base_va=0)
    insns = dec.disassemble(start=0xB00, end=0x1000)
    starts = dec.function_starts()

    for va in starts[:5]:
        print(f"  function @ 0x{va:08X}")
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from capstone import Cs, CS_ARCH_M68K, CS_MODE_M68K_020
    _CAPSTONE_OK = True
except ImportError:
    _CAPSTONE_OK = False


@dataclass
class M68kInsn:
    """A decoded M68K instruction."""

    offset: int
    mnemonic: str
    op_str: str
    insn_type: str
    raw: bytes
    size: int
    target: Optional[int] = None

    def __str__(self) -> str:
        target_str = f"  -> 0x{self.target:08X}" if self.target is not None else ""
        return (
            f"0x{self.offset:08X}  [M68K/{self.size}]  "
            f"{self.mnemonic:<16} {self.op_str}{target_str}"
        )


class EcuM68kDecoder:
    """
    Decode M68K / CPU32 instructions from a raw ROM buffer.

    Parameters
    ----------
    data
        Raw ROM bytes.  Accepts ``bytes``, ``str`` path, or ``Path``.
    base_va
        Virtual address of the first byte in ``data``.

    Notes
    -----
    ``__init__``, ``from_path``, and ``from_bytes`` are equivalent entry
    points.  ``from_path`` and ``from_bytes`` are convenience wrappers.
    ``disassemble()`` requires Capstone.  ``function_starts()`` and
    ``insn_length()`` are pure-Python pattern scans and do not require it.
    """

    # M68K prologue opcodes
    _LINK_W_A6    = 0x4E56   # LINK.W A6, #-N (frame allocation)
    _MOVEM_PUSH   = 0x48E7   # MOVEM.L regs, -(SP)
    _RTS          = 0x4E75   # RTS (return)
    _RTD          = 0x4E74   # RTD #N (return with displacement, CPU32)

    def __init__(self, data: "str | Path | bytes", base_va: int = 0):
        if isinstance(data, (str, Path)):
            try:
                self._data = open(data, "rb").read()
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"EcuM68kDecoder: {data!r} not found"
                ) from exc
        else:
            self._data = bytes(data)
        self._base_va = base_va
        if _CAPSTONE_OK:
            self._cs = Cs(CS_ARCH_M68K, CS_MODE_M68K_020)
            self._cs.detail = False
        else:
            self._cs = None

    @classmethod
    def from_path(cls, path: "str | Path", base_va: int = 0) -> "EcuM68kDecoder":
        """Convenience wrapper; equivalent to EcuM68kDecoder(path, base_va)."""
        return cls(path, base_va)

    @classmethod
    def from_bytes(cls, data: bytes, base_va: int = 0) -> "EcuM68kDecoder":
        """Convenience wrapper; equivalent to EcuM68kDecoder(data, base_va)."""
        return cls(data, base_va)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def insn_length(self, offset: int) -> int:
        """Return the byte length of the instruction at ``offset`` (2, 4, 6, or 8).

        Uses a single Capstone call for accuracy.  Returns 2 when Capstone is
        not installed or cannot decode the bytes (safe minimum for M68K).
        """
        data = self._data
        n = len(data)
        if offset >= n:
            return 0
        if not _CAPSTONE_OK or self._cs is None:
            return 2
        chunk = data[offset:min(offset + 10, n)]
        va = self._base_va + offset
        for insn in self._cs.disasm(chunk, va):
            return len(insn.bytes)
        return 2

    def decode_one(self, offset: int) -> Optional[M68kInsn]:
        """Decode a single instruction at ``offset``.

        Raises ``ImportError`` if Capstone is not installed.  Returns None
        at EOF or when Capstone cannot decode the bytes at ``offset``.
        """
        if not _CAPSTONE_OK:
            raise ImportError(
                "EcuM68kDecoder.decode_one() requires Capstone. "
                "Install with: pip install capstone"
            )
        data = self._data
        n = len(data)
        if offset >= n:
            return None
        va = self._base_va + offset
        chunk = data[offset:min(offset + 10, n)]
        for insn in self._cs.disasm(chunk, va):
            raw = bytes(insn.bytes)
            mnem = insn.mnemonic
            itype = self._classify(mnem, raw)
            target = self._branch_target(insn) if itype in ("BRANCH", "CALL") else None
            return M68kInsn(
                offset=va,
                mnemonic=mnem,
                op_str=insn.op_str,
                insn_type=itype,
                raw=raw,
                size=len(raw),
                target=target,
            )
        return None

    def disassemble(
        self, start: int = 0, end: Optional[int] = None
    ) -> list[M68kInsn]:
        """
        Decode all instructions in the byte range ``[start, end)``.

        Raises ``ImportError`` if Capstone is not installed.
        ``start`` and ``end`` are byte offsets within the data buffer.
        """
        if not _CAPSTONE_OK:
            raise ImportError(
                "EcuM68kDecoder.disassemble() requires Capstone. "
                "Install with: pip install capstone"
            )
        if end is None:
            end = len(self._data)
        end = min(end, len(self._data))
        chunk = self._data[start:end]
        if not chunk:
            return []
        va_start = self._base_va + start
        results: list[M68kInsn] = []
        for insn in self._cs.disasm(chunk, va_start):
            raw = bytes(insn.bytes)
            mnem = insn.mnemonic
            itype = self._classify(mnem, raw)
            target = self._branch_target(insn) if itype in ("BRANCH", "CALL") else None
            results.append(M68kInsn(
                offset=insn.address,
                mnemonic=mnem,
                op_str=insn.op_str,
                insn_type=itype,
                raw=raw,
                size=len(raw),
                target=target,
            ))
        return results

    def function_starts(self) -> list[int]:
        """
        Return probable function-start VAs by scanning for M68K prologues.

        Two prologue forms are detected:

        *Frame-allocating functions* — ``LINK.W A6, #-N``: opcode ``0x4E56``
        at any even offset, followed by a negative 16-bit displacement (bit 15
        set).  This is the standard CPU32 frame setup for the GM P-series ABI.

        *Save-only leaf functions* — ``MOVEM.L regs, -(SP)``: opcode ``0x48E7``
        at any even offset.  Only accepted when the immediately preceding 4
        bytes at ``i-4`` are NOT a ``LINK.W`` (which would mean this is the
        second instruction of a frame-allocating function, not a start).

        Returns virtual addresses (``base_va + offset``), sorted.
        """
        data = self._data
        n = len(data)
        starts: set[int] = set()

        for i in range(0, n - 3, 2):
            hw = struct.unpack_from(">H", data, i)[0]

            if hw == self._LINK_W_A6:
                if i + 4 <= n:
                    disp = struct.unpack_from(">H", data, i + 2)[0]
                    if disp & 0x8000:
                        starts.add(self._base_va + i)

            elif hw == self._MOVEM_PUSH:
                va = self._base_va + i
                if va not in starts:
                    # Don't count MOVEM that immediately follows a LINK
                    if i >= 4:
                        prev_hw = struct.unpack_from(">H", data, i - 4)[0]
                        if prev_hw == self._LINK_W_A6:
                            continue
                    starts.add(va)

        return sorted(starts)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify(mnemonic: str, raw: bytes) -> str:
        mn = mnemonic.lower()
        if mn in ("rts", "rtd", "rte", "rtr"):
            return "RETURN"
        if mn.startswith("jsr") or mn == "bsr" or mn.startswith("bsr."):
            return "CALL"
        if mn.startswith("jmp"):
            return "BRANCH"
        if mn.startswith("b") and mn not in ("bkpt",):
            return "BRANCH"
        if mn.startswith("link"):
            # LINK with negative displacement is a prologue
            if len(raw) >= 4:
                disp = struct.unpack_from(">H", raw, 2)[0]
                if disp & 0x8000:
                    return "PROLOGUE"
            return "MISC"
        if mn.startswith(("move", "movem", "moveq")):
            return "MISC"
        if mn in ("nop",):
            return "MISC"
        return "MISC"

    @staticmethod
    def _branch_target(insn) -> Optional[int]:
        """Extract absolute branch target from Capstone op_str when available.

        Handles forms: ``$addr``, ``$addr.w``, ``$addr.l``, ``#$addr`` —
        Capstone M68K branch/call targets always start with ``$`` and may
        carry a ``.w`` / ``.l`` size suffix.  Indirect targets (e.g., ``(A0)``)
        return None; that is correct — the address is not statically known.
        """
        op = insn.op_str.strip()
        if not op.startswith(("#$", "$")):
            return None
        hex_part = op.lstrip("#$").split(".")[0].strip()
        try:
            return int(hex_part, 16)
        except ValueError:
            return None
