"""
Arch-agnostic function-start scanner for flat ECU ROM images.

Finds probable function entry virtual addresses in a raw binary (no ELF
header, no IHEX wrapper) by combining two complementary strategies:

1. **Call-target harvesting** — follows the reset vector, decodes branch/call
   instructions for the detected ISA, and recursively collects all reachable
   call targets.  Any address that is the target of a direct call is a confirmed
   function entry.

2. **Prologue pattern scan** — byte-scans the image for ISA-specific prologue
   byte sequences and adds those VAs to the result set.

When ``EcuArchDetector`` returns HIGH or MEDIUM confidence the scanner uses
only that ISA's catalog.  When confidence is LOW it runs all five catalogs and
returns the union.

Usage::

    from ablation.analyzers.flat_binary_func_start_scanner import FlatBinaryFuncStartScanner

    scanner = FlatBinaryFuncStartScanner(rom_bytes, base_va=0x0)
    result = scanner.scan()
    print(result.arch, result.confidence)
    for va in result.function_starts[:20]:
        print(hex(va))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ablation.analyzers.ecu_arch_detector import EcuArchDetector, ArchDetectResult


@dataclass
class FuncStartResult:
    """Result of a function-start scan."""

    arch: str
    confidence: str
    function_starts: list[int] = field(default_factory=list)
    call_targets: list[int] = field(default_factory=list)
    prologue_hits: list[int] = field(default_factory=list)
    detect_result: Optional[ArchDetectResult] = None


class FlatBinaryFuncStartScanner:
    """
    Arch-agnostic function-start scanner for flat ECU ROM images.

    Parameters
    ----------
    data
        Raw ROM bytes.  Accepts ``bytes``, file path (``str``/``Path``), or
        any buffer-protocol object.
    base_va
        Load address of byte 0 in the target address space.  Defaults to 0.
    max_call_depth
        Maximum recursion depth for call-target harvesting.  Defaults to 64.
    """

    def __init__(
        self,
        data: "str | Path | bytes",
        base_va: int = 0,
        max_call_depth: int = 64,
    ):
        if isinstance(data, (str, Path)):
            try:
                with open(data, "rb") as f:
                    self._data = f.read()
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"FlatBinaryFuncStartScanner: {data!r} not found"
                ) from exc
        else:
            self._data = bytes(data)
        self._base_va = base_va
        self._max_depth = max_call_depth

    @classmethod
    def from_path(
        cls, path: "str | Path", base_va: int = 0, max_call_depth: int = 64
    ) -> "FlatBinaryFuncStartScanner":
        return cls(path, base_va, max_call_depth)

    @classmethod
    def from_bytes(
        cls, data: bytes, base_va: int = 0, max_call_depth: int = 64
    ) -> "FlatBinaryFuncStartScanner":
        return cls(data, base_va, max_call_depth)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, arch: Optional[str] = None) -> FuncStartResult:
        """
        Run the full scan and return a ``FuncStartResult``.

        Parameters
        ----------
        arch
            Force a specific ISA (``arm_cm``, ``m68k``, ``ppc32``, ``ppc_vle``,
            ``sh2a``).  When ``None`` (the default), the ISA is auto-detected via
            ``EcuArchDetector``.

        Returns
        -------
        FuncStartResult
            ``.function_starts`` is the deduplicated union of call targets and
            prologue hits, sorted by VA.  ``.call_targets`` and
            ``.prologue_hits`` give the individual contributions.
        """
        if arch is not None:
            detect = ArchDetectResult(
                arch=arch, confidence="HIGH", score=1.0, reason="caller-supplied"
            )
        else:
            detect = EcuArchDetector(self._data).detect()

        arch_tok = detect.arch

        if detect.confidence in ("HIGH", "MEDIUM") and arch_tok != "unknown":
            call_targets = self._harvest_call_targets(arch_tok)
            prologue_hits = self._prologue_scan(arch_tok)
        else:
            call_targets = []
            prologue_hits = []
            for tok in ("arm_cm", "m68k", "ppc32", "ppc_vle", "sh2a"):
                call_targets.extend(self._harvest_call_targets(tok))
                prologue_hits.extend(self._prologue_scan(tok))

        combined = sorted(set(call_targets) | set(prologue_hits))
        return FuncStartResult(
            arch=arch_tok,
            confidence=detect.confidence,
            function_starts=combined,
            call_targets=sorted(set(call_targets)),
            prologue_hits=sorted(set(prologue_hits)),
            detect_result=detect,
        )

    # ------------------------------------------------------------------
    # Call-target harvesting
    # ------------------------------------------------------------------

    def _harvest_call_targets(self, arch: str) -> list[int]:
        """
        Walk from the reset entry point following direct call instructions,
        collecting branch targets.  Returns a list of reachable call-target VAs.
        """
        entry = self._reset_entry(arch)
        if entry is None:
            return []

        n = len(self._data)
        visited: set[int] = set()
        queue: list[int] = [entry]
        targets: set[int] = {entry}

        depth_map: dict[int, int] = {entry: 0}

        while queue:
            va = queue.pop()
            if va in visited:
                continue
            visited.add(va)
            depth = depth_map.get(va, 0)
            if depth >= self._max_depth:
                continue

            offset = va - self._base_va
            if offset < 0 or offset >= n - 1:
                continue

            for call_target in self._scan_calls_at(va, arch):
                if call_target not in targets:
                    targets.add(call_target)
                    tgt_off = call_target - self._base_va
                    if 0 <= tgt_off < n:
                        queue.append(call_target)
                        depth_map[call_target] = depth + 1

        return sorted(targets)

    def _reset_entry(self, arch: str) -> Optional[int]:
        """Return the reset handler VA for the given ISA."""
        data = self._data
        n = len(data)
        if n < 8:
            return None

        if arch == "arm_cm":
            reset_vec = struct.unpack_from("<I", data, 4)[0]
            entry = reset_vec & ~1
            off = entry - self._base_va
            return entry if 0 <= off < n else None

        if arch in ("m68k", "sh2a", "ppc32", "ppc_vle"):
            reset_va = struct.unpack_from(">I", data, 4)[0]
            off = reset_va - self._base_va
            return reset_va if 0 <= off < n else None

        return None

    def _scan_calls_at(self, start_va: int, arch: str) -> list[int]:
        """
        Linear scan from ``start_va`` for call instructions in the given ISA.
        Returns a list of call targets found in one pass (not recursive).
        The caller handles recursion.  Stops at the first return instruction
        or after 512 instructions.
        """
        data = self._data
        n = len(data)
        base = self._base_va
        targets: list[int] = []

        if arch == "arm_cm":
            # Thumb-2: BL is a 32-bit instruction encoded as two halfwords.
            # First halfword: 1111 0xxx xxxx xxxx (0xF000–0xF7FF)
            # Second halfword: 1111 1xxx xxxx xxxx (0xF800–0xFFFF) with H=1
            va = start_va
            limit = 512
            while limit > 0:
                off = va - base
                if off < 0 or off + 2 > n:
                    break
                hw1 = struct.unpack_from("<H", data, off)[0]

                # BL / BLX encoding: two 16-bit halfwords
                if (hw1 & 0xF800) == 0xF000 and off + 4 <= n:
                    hw2 = struct.unpack_from("<H", data, off + 2)[0]
                    if (hw2 & 0xD000) == 0xD000:
                        # BL: imm11 from hw2, imm10 from hw1
                        s   = (hw1 >> 10) & 1
                        i1  = (~((hw2 >> 13) & 1) ^ s) & 1
                        i2  = (~((hw2 >> 11) & 1) ^ s) & 1
                        imm11 = hw2 & 0x7FF
                        imm10 = hw1 & 0x3FF
                        offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                        if s:
                            offset -= (1 << 25)
                        tgt = (va + 4 + offset) & ~1
                        tgt_off = tgt - base
                        if 0 <= tgt_off < n:
                            targets.append(tgt)
                        va += 4
                        limit -= 1
                        continue
                    # BLX: H=01
                    if (hw2 & 0xD000) == 0xC000:
                        s   = (hw1 >> 10) & 1
                        i1  = (~((hw2 >> 13) & 1) ^ s) & 1
                        i2  = (~((hw2 >> 11) & 1) ^ s) & 1
                        imm10h = hw1 & 0x3FF
                        imm10l = (hw2 >> 1) & 0x3FF
                        offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10h << 12) | (imm10l << 2)
                        if s:
                            offset -= (1 << 25)
                        tgt = (va + 4 + offset) & ~3
                        tgt_off = tgt - base
                        if 0 <= tgt_off < n:
                            targets.append(tgt)
                        va += 4
                        limit -= 1
                        continue

                # BX LR = 0x4770 (return) — stop linear scan
                if hw1 == 0x4770:
                    break
                # 16-bit instruction
                va += 2
                limit -= 1

        elif arch == "m68k":
            # BSR.W: 0x6100 + 16-bit displacement
            # BSR.L: 0x61FF + 32-bit displacement
            # JSR: 0x4E90-0x4EBF (various EA modes)
            va = start_va
            limit = 512
            while limit > 0:
                off = va - base
                if off < 0 or off + 2 > n:
                    break
                hw = struct.unpack_from(">H", data, off)[0]

                if hw == 0x6100 and off + 4 <= n:
                    # BSR.W: opcode word + 16-bit signed displacement; PC = va+2 at decode time
                    disp = struct.unpack_from(">h", data, off + 2)[0]
                    tgt = va + 2 + disp
                    tgt_off = tgt - base
                    if 0 <= tgt_off < n:
                        targets.append(tgt)
                    va += 4
                    limit -= 1
                    continue
                if hw == 0x61FF and off + 6 <= n:
                    # BSR.L: 32-bit displacement
                    disp = struct.unpack_from(">i", data, off + 2)[0]
                    tgt = va + 2 + disp
                    tgt_off = tgt - base
                    if 0 <= tgt_off < n:
                        targets.append(tgt)
                    va += 6
                    limit -= 1
                    continue
                # RTS = 0x4E75 — stop
                if hw == 0x4E75:
                    break
                va += 2
                limit -= 1

        elif arch == "ppc32" or arch == "ppc_vle":
            # PPC BL: opcode 18 (0x48000001 | ...) — bits[31:26]=18, LK=1, AA=0
            va = start_va
            limit = 512
            while limit > 0:
                off = va - base
                if off < 0 or off + 4 > n:
                    break
                word = struct.unpack_from(">I", data, off)[0]
                opcode = (word >> 26) & 0x3F
                lk = word & 1
                aa = (word >> 1) & 1

                if opcode == 18 and lk == 1:
                    if aa == 0:
                        # BL: LI is bits[25:2], sign-extended * 4
                        raw_li = (word >> 2) & 0xFFFFFF
                        if raw_li & 0x800000:
                            raw_li -= 0x1000000
                        tgt = va + raw_li * 4
                    else:
                        # BLA: absolute
                        raw_li = (word >> 2) & 0xFFFFFF
                        if raw_li & 0x800000:
                            raw_li -= 0x1000000
                        tgt = raw_li * 4
                    tgt_off = tgt - base
                    if 0 <= tgt_off < n:
                        targets.append(tgt)

                # BLRL (BLR LK=1): 4E800021 — not a call target harvesting signal
                # BLR (return): 4E800020 — stop
                if word == 0x4E800020:
                    break
                va += 4
                limit -= 1

        elif arch == "sh2a":
            # BSR: 1011 dddd dddd dddd (B=BSR, 12-bit signed disp)
            # JSR: 0100 mmmm 0000 1011 (indirect, can't resolve statically)
            va = start_va
            limit = 512
            while limit > 0:
                off = va - base
                if off < 0 or off + 2 > n:
                    break
                hw = struct.unpack_from(">H", data, off)[0]

                # BSR disp12: 1011 dddd dddd dddd
                if (hw & 0xF000) == 0xB000:
                    disp = hw & 0xFFF
                    if disp & 0x800:
                        disp -= 0x1000
                    # PC at branch sees va+4 (delay slot)
                    tgt = va + 4 + disp * 2
                    tgt_off = tgt - base
                    if 0 <= tgt_off < n:
                        targets.append(tgt)
                    va += 4  # skip delay slot
                    limit -= 1
                    continue

                # RTS: 0x000B — return
                if hw == 0x000B:
                    break
                va += 2
                limit -= 1

        return targets

    # ------------------------------------------------------------------
    # Prologue pattern scan
    # ------------------------------------------------------------------

    def _prologue_scan(self, arch: str) -> list[int]:
        """
        Byte-scan the full image for ISA-specific function prologue patterns.
        Returns a list of VAs that look like function entries.
        """
        data = self._data
        n = len(data)
        base = self._base_va
        hits: list[int] = []

        if arch == "arm_cm":
            # PUSH {lr} (Thumb2): 0x2D E9 xx xx (PUSH.W) or 0x10 B5 (PUSH {r4, lr})
            # Most common Thumb2 prologue: PUSH {r4-r7, lr}
            # Detect 16-bit PUSH with LR bit set: 0x?? B5 (format: 1011 0101 xxxx xxxx)
            # Actually push = 1011 x10x xxxx xxxx; LR = 1011 0101 = 0xB5 (register_list has r14)
            for i in range(0, n - 1, 2):
                b0 = data[i]
                b1 = data[i + 1]
                # 16-bit PUSH with LR: 10110101 = 0xB5 in second byte (Thumb encoding low-byte first LE)
                # LE: first byte is low byte; PUSH {registers} = 1011 0reg_list
                # push {lr} = 0x00 0xB5? No: Thumb LE: opcode in hw = data[i] | (data[i+1] << 8)
                # hw = data[i] | (data[i+1] << 8) for LE thumb
                hw = data[i] | (data[i + 1] << 8)
                # PUSH {lr, ...}: hw & 0xFF00 == 0xB500 (register_list has r14=bit8)
                if (hw & 0xFF00) == 0xB500:
                    hits.append(base + i)

        elif arch == "m68k":
            # LINK.W A6, #-N: 0x4E56 followed by a negative 16-bit word
            for i in range(0, n - 3, 2):
                if data[i] == 0x4E and data[i + 1] == 0x56:
                    disp = struct.unpack_from(">H", data, i + 2)[0]
                    if disp & 0x8000:
                        hits.append(base + i)

        elif arch == "ppc32":
            # MFLR r0: 7C 08 02 A6 (big-endian) — save link register, common prologue
            for i in range(0, n - 3, 4):
                if (data[i] == 0x7C and data[i + 1] == 0x08
                        and data[i + 2] == 0x02 and data[i + 3] == 0xA6):
                    hits.append(base + i)

        elif arch == "ppc_vle":
            # e_stwu r1, -N(r1): 0x1C21 as the first halfword
            # VLE e_stwu: se=0, opcode=7, subopcode identifies the form
            # Byte pattern: first byte 0x1C (0x1C & 0x90 == 0x10 → VLE 32-bit)
            for i in range(0, n - 3, 4):
                hw = struct.unpack_from(">H", data, i)[0]
                if hw == 0x1C21:
                    # Check that displacement is negative (frame allocation)
                    word = struct.unpack_from(">I", data, i)[0]
                    # e_stwu D8(0), RA(21:25)=r1, RS(11:15)=r1
                    d8 = word & 0xFF
                    if d8 & 0x80:  # negative displacement
                        hits.append(base + i)

        elif arch == "sh2a":
            # STS.L PR, @-R15: 0x4F22
            for i in range(0, n - 1, 2):
                hw = struct.unpack_from(">H", data, i)[0]
                if hw == 0x4F22:
                    hits.append(base + i)
                # STS PR, Rn (leaf): (hw & 0xF0FF) == 0x002A, not preceded by 0x4F22
                elif (hw & 0xF0FF) == 0x002A:
                    if i >= 2:
                        prev = struct.unpack_from(">H", data, i - 2)[0]
                        if prev != 0x4F22:
                            hits.append(base + i)
                    else:
                        hits.append(base + i)

        return hits
