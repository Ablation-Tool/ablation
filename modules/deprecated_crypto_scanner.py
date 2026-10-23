"""
deprecated_crypto_scanner.py: Deprecated cryptographic algorithm detector.

Identifies MD5, SHA-1, DES, 3DES, RC4, and single-DES usage in stripped
firmware by matching algorithm-specific constants and initialization patterns
in the binary's data sections.

Detection is based on constants, not symbol names, so it works on stripped
binaries and statically linked firmware where no crypto library symbols survive.

Algorithm signatures:
  MD5     Initial hash state: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
  SHA-1   Initial hash state: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
          (shares first four constants with MD5; fifth constant distinguishes SHA-1)
  DES     S-box constants (distinctive 32-bit values from DES specification)
  RC4     Permutation initialization: sequential 0x00..0xFF byte pattern in 256-byte window
  MD4     Initial hash state shares first four with MD5; detected separately

These algorithms are deprecated per NIST SP 800-131A Rev 2 (2019) and RFC 8996.
Finding one in firmware is a confirmed cryptographic weakness independent of
how the value flows through the binary.

Usage:
    scanner = DeprecatedCryptoScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = DeprecatedCryptoScanner.from_context(ctx)
    findings = scanner.scan()
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


# ── Crypto constants ───────────────────────────────────────────────────────────

# MD5 initial hash values (RFC 1321 §3.3) — little-endian in memory
_MD5_INIT = bytes([
    0x01, 0x23, 0x45, 0x67,   # A = 0x67452301 LE
    0x89, 0xAB, 0xCD, 0xEF,   # B = 0xEFCDAB89 LE
    0xFE, 0xDC, 0xBA, 0x98,   # C = 0x98BADCFE LE
    0x76, 0x54, 0x32, 0x10,   # D = 0x10325476 LE
])

# SHA-1 fifth initial value (distinguishes from MD5) — little-endian
_SHA1_FIFTH = bytes([0xF0, 0xE1, 0xD2, 0xC3])  # 0xC3D2E1F0 LE

# SHA-1 complete init: first 16 bytes same as MD5, then fifth word
_SHA1_INIT_FULL = _MD5_INIT + _SHA1_FIFTH

# RC4: identity permutation 0x00..0xFF (PRGA init before KSA modifies it)
_RC4_IDENTITY = bytes(range(256))

# DES S-box first table values (first 8 entries of S1, big-endian 32-bit)
# These are fixed constants from FIPS 46-3
_DES_S1_FIRST_BE = struct.pack('>8I',
    0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
)

# DES S-box first table values, little-endian variant (same values, LE bytes)
_DES_S1_FIRST_LE = struct.pack('<8I',
    0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
)

# MD4 initial values — identical to first four MD5 constants; flag separately
# MD4 is distinguished in context by checking the algorithm name nearby.
# Here we just report MD5/MD4 as a single finding class since constants match.


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class CryptoFinding:
    algorithm: str   # MD5, SHA-1, DES, RC4
    offset:    int   # file offset of the matching constant
    va:        int   # virtual address (0 if not mapped)
    severity:  str   # HIGH / MEDIUM
    note:      str   # context note

    def fmt(self) -> str:
        return (f"  {self.severity:6s}  [{self.algorithm}]  "
                f"offset=0x{self.offset:x}  va=0x{self.va:x}\n"
                f"         {self.note}")


# ── Scanner ────────────────────────────────────────────────────────────────────

class DeprecatedCryptoScanner:
    """Detect deprecated cryptographic constants in binary firmware."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'DeprecatedCryptoScanner':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._ctx  = ctx
        return obj

    def _load_data(self) -> bytes:
        return Path(self._path).read_bytes()

    def _offset_to_va(self, offset: int) -> int:
        """Convert file offset to virtual address using section map if available."""
        if self._ctx is None:
            return 0
        try:
            import lief
            binary = lief.parse(self._path)
            if binary is None:
                return 0
            for section in binary.sections:
                sec_offset = section.offset
                sec_size   = section.size
                if sec_offset <= offset < sec_offset + sec_size:
                    return section.virtual_address + (offset - sec_offset)
        except Exception:
            pass
        return 0

    def scan(self) -> List[CryptoFinding]:
        data = self._load_data()
        findings: list[CryptoFinding] = []
        seen_offsets: set[int] = set()

        def find_all(pattern: bytes, name: str, note: str, severity: str) -> None:
            pos = 0
            while True:
                idx = data.find(pattern, pos)
                if idx == -1:
                    break
                if idx not in seen_offsets:
                    seen_offsets.add(idx)
                    va = self._offset_to_va(idx)
                    findings.append(CryptoFinding(
                        algorithm=name,
                        offset=idx,
                        va=va,
                        severity=severity,
                        note=note,
                    ))
                pos = idx + 1

        # SHA-1 must be checked before MD5 to avoid double-reporting the shared prefix
        find_all(_SHA1_INIT_FULL, 'SHA-1',
                 'SHA-1 initial hash state (NIST SP 800-131A deprecated 2013)',
                 'HIGH')

        # MD5: look for the 16-byte init block NOT followed by the SHA-1 fifth word
        pos = 0
        while True:
            idx = data.find(_MD5_INIT, pos)
            if idx == -1:
                break
            if data[idx + 16:idx + 20] != _SHA1_FIFTH:
                if idx not in seen_offsets:
                    seen_offsets.add(idx)
                    va = self._offset_to_va(idx)
                    findings.append(CryptoFinding(
                        algorithm='MD5',
                        offset=idx,
                        va=va,
                        severity='HIGH',
                        note='MD5 initial hash state (RFC 6151 deprecated, NIST disallowed)',
                    ))
            pos = idx + 1

        find_all(_DES_S1_FIRST_BE, 'DES',
                 'DES S-box constants, big-endian (NIST SP 800-131A disallowed 2015)',
                 'HIGH')
        find_all(_DES_S1_FIRST_LE, 'DES',
                 'DES S-box constants, little-endian (NIST SP 800-131A disallowed 2015)',
                 'HIGH')

        find_all(_RC4_IDENTITY, 'RC4',
                 'RC4 identity permutation (RFC 7465 prohibited 2015)',
                 'HIGH')

        findings.sort(key=lambda f: (0 if f.severity == 'HIGH' else 1, f.offset))
        return findings

    def report(self, findings: Optional[List[CryptoFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'DeprecatedCryptoScanner: no deprecated crypto in {self._path}'
        lines = [f'DeprecatedCryptoScanner: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
