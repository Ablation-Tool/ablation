"""
Static-seed SecurityAccess handler fingerprinter for M68K/CPU32 and PPC32 ECUs.

Scans raw ROM bytes for the instruction pattern that indicates a UDS/KWP2000
SecurityAccess service always returns a static (non-random) seed. When the seed
is static, any seed/key pair computed from a known algorithm can be replayed
offline, granting unauthenticated access to protected diagnostic services.

Two architectures are supported:

M68K / CPU32 (GM P-series PCMs: P01, P04, P05, P08, P10, P11, P59)
    requestSeed handler stores 0x67 (SA subfunction code) into the seed
    response buffer, then immediately clears the remaining bytes. In
    M68K assembly:

        move.b  #$67, <mem>     ; seed[0] = 0x67
        clr.b   <mem+1>         ; seed[1] = 0x00
        clr.b   <mem+2>         ; seed[2] = 0x00

    The 0x67 immediate is the requestSeed subfunction code echoed back
    verbatim as the seed. Any key derived from it is predictable.

PPC32 (GM E38 PCM: PPC e200 region)
    The equivalent pattern in PPC32 big-endian code:

        li      rX, 0x67        ; seed byte = subfunction code
        stb     rX, N(rA)       ; store to seed buffer
        ...
        li      rY, 0           ; following bytes are zero
        stb     rY, N+1(rA)
        ...
        li      rZ, 0
        stb     rZ, N+2(rA)

Both patterns were confirmed across the full GM ECU corpus in:
    targets/automotive/auto_ecu_corpus_re.py (gitignored)

Usage::

    from ablation.analyzers.ecu_security_access_scanner import EcuSecurityAccessScanner

    findings = EcuSecurityAccessScanner(rom_bytes).scan()
    for f in findings:
        print(f)

    # Guard against calibration-only images before scanning
    from ablation.analyzers.ecu_rom_layout_analyzer import EcuROMLayoutAnalyzer
    layout = EcuROMLayoutAnalyzer.from_bytes(rom_bytes).analyze()
    cal_only, reason = layout.is_calibration_only()
    if cal_only:
        print(f"Skipping SA scan: {reason}")
    else:
        findings = EcuSecurityAccessScanner(rom_bytes).scan()
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SecurityAccessFinding:
    offset: int         # byte offset of the triggering instruction
    arch: str           # "M68K" or "PPC32"
    pattern: str        # short pattern name
    evidence: bytes     # raw bytes of the triggering instruction sequence
    note: str = ""      # human-readable description

    def __str__(self) -> str:
        hex_ev = self.evidence.hex(" ")
        return (
            f"0x{self.offset:08X}  [{self.arch}]  {self.pattern}"
            + (f"  — {self.note}" if self.note else "")
            + f"\n  evidence: {hex_ev}"
        )


class EcuSecurityAccessScanner:
    """
    Fingerprint static-seed SecurityAccess handlers in M68K and PPC32 ECU ROMs.

    Parameters
    ----------
    path_or_data
        Path to the ROM file, or raw bytes.
    window
        Byte radius around each seed instruction to search for the confirming
        CLR.B / zero-store pair. Default 256. M68K corpus patterns use ≤8 bytes;
        PPC32 patterns can have intervening setup code up to ~200 bytes.
        Same value applies to both architectures.
    """

    def __init__(self, path_or_data: "str | Path | bytes", window: int = 256):
        if isinstance(path_or_data, (str, Path)):
            self._data = open(path_or_data, "rb").read()
        else:
            self._data = bytes(path_or_data)
        self._window = window

    @classmethod
    def from_path(cls, path: "str | Path", window: int = 32) -> "EcuSecurityAccessScanner":
        return cls(path, window)

    @classmethod
    def from_bytes(cls, data: bytes, window: int = 32) -> "EcuSecurityAccessScanner":
        return cls(data, window)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def scan(self) -> list[SecurityAccessFinding]:
        """Return all static-seed SecurityAccess findings in the ROM."""
        findings: list[SecurityAccessFinding] = []
        findings.extend(self._scan_m68k())
        findings.extend(self._scan_ppc32())
        return findings

    # ------------------------------------------------------------------ #
    # M68K scanner                                                        #
    # ------------------------------------------------------------------ #

    def _scan_m68k(self) -> list[SecurityAccessFinding]:
        """Scan for MOVE.B #$67 followed by 2x CLR.B within self._window bytes."""
        data = self._data
        n = len(data)
        findings: list[SecurityAccessFinding] = []
        window = self._window

        # MOVE.B #imm, <ea> encodes as:
        #   byte[0]: 0x1? — top nibble 0x1 marks MOVE.B (size=01)
        #   byte[1]: low 6 bits == 0x3C — source EA = #imm (mode=111, reg=100)
        #   byte[2]: 0x00 — high byte of immediate word for byte value
        #   byte[3]: 0x67 — the actual byte value (requestSeed subfunction code)
        #
        # This mask catches all destination addressing modes:
        #   (Dn), (An), (An)+, -(An), (d16,An), abs.W, abs.L
        i = 0
        while i + 4 <= n:
            b0, b1, b2, b3 = data[i], data[i + 1], data[i + 2], data[i + 3]
            if (b0 & 0xF0) == 0x10 and (b1 & 0x3F) == 0x3C and b2 == 0x00 and b3 == 0x67:
                clrb_count = self._count_m68k_clrb(data, i, window)
                if clrb_count >= 2:
                    end = min(i + 4 + window, n)
                    evidence = data[i:end]
                    findings.append(SecurityAccessFinding(
                        offset=i,
                        arch="M68K",
                        pattern="static-seed-requestSeed",
                        evidence=evidence,
                        note=(
                            "move.b #$67 + 2x clr.b: requestSeed returns static zero seed; "
                            "any key computed offline is accepted"
                        ),
                    ))
            i += 2  # M68K instructions are 2-byte aligned
        return findings

    @staticmethod
    def _count_m68k_clrb(data: bytes, site: int, window: int) -> int:
        """Count CLR.B instructions within [site+4, site+4+window)."""
        count = 0
        end = min(site + 4 + window, len(data) - 1)
        j = site + 4
        # Align to next even address
        if j & 1:
            j += 1
        while j + 2 <= end:
            # CLR.B <ea>: opcode word 0x4200-0x423F
            #   byte[0] == 0x42, byte[1] < 0x40 (size field = 00 = byte)
            if data[j] == 0x42 and data[j + 1] < 0x40:
                count += 1
                if count >= 2:
                    break
            j += 2
        return count

    # ------------------------------------------------------------------ #
    # PPC32 scanner                                                       #
    # ------------------------------------------------------------------ #

    def _scan_ppc32(self) -> list[SecurityAccessFinding]:
        """Scan for li rX, 0x67 + stb, then 2x (li rY, 0 + stb) within self._window bytes."""
        data = self._data
        n = len(data)
        findings: list[SecurityAccessFinding] = []
        window = self._window

        # li rX, 0x67 = addi rX, r0, 0x67
        #   opcode 14 (0xE), RA=0, RD=any, simm=0x0067
        #   word & 0xFC1FFFFF == 0x38000067
        #
        # stb rS, d(rA)
        #   opcode 38 (0x26) in bits[31:26]
        #   (word >> 26) == 38

        i = 0
        while i + 8 <= n:
            w0 = struct.unpack_from(">I", data, i)[0]
            if (w0 & 0xFC1FFFFF) == 0x38000067:
                w1 = struct.unpack_from(">I", data, i + 4)[0]
                if (w1 >> 26) == 38:  # stb immediately follows
                    zero_pairs = self._count_ppc32_zero_pairs(data, i, window)
                    if zero_pairs >= 2:
                        end = min(i + 8 + window, n)
                        evidence = data[i:end]
                        findings.append(SecurityAccessFinding(
                            offset=i,
                            arch="PPC32",
                            pattern="static-seed-requestSeed",
                            evidence=evidence,
                            note=(
                                "li rX,0x67 + stb + 2x(li rY,0 + stb): "
                                "requestSeed returns static zero seed"
                            ),
                        ))
            i += 4  # PPC32 instructions are 4-byte aligned
        return findings

    @staticmethod
    def _count_ppc32_zero_pairs(data: bytes, site: int, window: int) -> int:
        """Count (li rX, 0 + stb) pairs within [site+8, site+8+window)."""
        count = 0
        end_off = min(site + 8 + window, len(data))
        j = site + 8
        # Align to next 4-byte boundary
        rem = j & 3
        if rem:
            j += 4 - rem
        while j + 8 <= end_off:
            w0 = struct.unpack_from(">I", data, j)[0]
            # li rX, 0 = addi rX, r0, 0 — any register, simm=0
            if (w0 & 0xFC1FFFFF) == 0x38000000:
                w1 = struct.unpack_from(">I", data, j + 4)[0]
                if (w1 >> 26) == 38:  # stb
                    count += 1
                    if count >= 2:
                        break
                    j += 8
                    continue
            j += 4
        return count
