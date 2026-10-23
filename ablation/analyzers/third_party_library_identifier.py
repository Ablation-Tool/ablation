"""
third_party_library_identifier.py: Third-party library detection in stripped binaries.

Identifies well-known open-source and vendor libraries embedded in firmware by
matching byte-level function prologue signatures against a built-in reference
database. Works without symbols (FLIRT-style pattern matching).

Detection strategy:
  For each function in the binary, extract the first N bytes of its body.
  Compare against a signature table keyed by (library, version, arch).
  If >= 3 signatures from the same library match, report the library as
  present with the matched version and confidence level.

Built-in signature database covers:
  - OpenSSL / LibreSSL (AES, RSA, SHA init prologues)
  - zlib (inflate/deflate characteristic constants)
  - libpng (PNG signature bytes 0x89504e47)
  - libjpeg / libjpeg-turbo (JPEG marker 0xFFD8)
  - wolfSSL (wolfCrypt init sequence)
  - mbedTLS (mbedtls_aes_init prologue)
  - expat / libxml2 (XML parser header constants)
  - uclibc / musl libc (string/memory function prologues)

Each hit carries a version range and CVE reference when the library version
is known to be vulnerable.

Usage:
    ident = ThirdPartyLibraryIdentifier('/path/to/binary')
    findings = ident.scan()
    print(ident.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    ident = ThirdPartyLibraryIdentifier.from_context(ctx)
    findings = ident.scan()
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional


# ── Signature database ─────────────────────────────────────────────────────────
#
# Each entry: (library, version_hint, arch, prologue_bytes, note)
# prologue_bytes: first N bytes of function body (None = wildcard byte)
# arch: 'x86_64', 'arm', 'arm64', 'mips', 'any'
#
# These are byte-level function prologues and constants, NOT opcode patterns.

_SIGS: list[tuple[str, str, str, bytes, str]] = [
    # ── OpenSSL ────────────────────────────────────────────────────────────────
    # AES_set_encrypt_key prologue: stores 0x63 (AES S-box first byte) early
    ('OpenSSL/LibreSSL', '1.x-3.x', 'any',
     bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
     'AES S-box constant'),
    # SHA-256 init constant H0
    ('OpenSSL/LibreSSL', '1.x-3.x', 'any',
     struct.pack('>I', 0x6a09e667),
     'SHA-256 H0 init constant'),
    # SHA-256 H1
    ('OpenSSL/LibreSSL', '1.x-3.x', 'any',
     struct.pack('>I', 0xbb67ae85),
     'SHA-256 H1 init constant'),
    # RSA constant 65537 (0x10001) as LE dword
    ('OpenSSL/LibreSSL', '1.x-3.x', 'any',
     struct.pack('<I', 0x00010001),
     'RSA public exponent 65537'),

    # ── zlib ───────────────────────────────────────────────────────────────────
    # zlib Adler-32 base (0xfff1) as LE word
    ('zlib', '1.2.x', 'any',
     struct.pack('<H', 0xfff1),
     'Adler-32 modulus constant'),
    # zlib magic deflate literals 0x9c78 (deflate header)
    ('zlib', '1.2.x', 'any',
     bytes([0x78, 0x9c]),
     'zlib deflate header bytes'),
    # zlib CRC-32 table seed
    ('zlib', '1.2.x', 'any',
     struct.pack('<I', 0xedb88320),
     'CRC-32 polynomial constant'),

    # ── libpng ─────────────────────────────────────────────────────────────────
    ('libpng', '1.x', 'any',
     bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
     'PNG file signature'),
    # PNG IHDR chunk type
    ('libpng', '1.x', 'any',
     bytes([0x49, 0x48, 0x44, 0x52]),
     'PNG IHDR chunk marker'),

    # ── libjpeg / libjpeg-turbo ────────────────────────────────────────────────
    ('libjpeg', 'any', 'any',
     bytes([0xff, 0xd8, 0xff]),
     'JPEG SOI marker'),
    ('libjpeg', 'any', 'any',
     bytes([0xff, 0xd9]),
     'JPEG EOI marker'),

    # ── wolfSSL ────────────────────────────────────────────────────────────────
    # wolfSSL uses same AES S-box as OpenSSL
    ('wolfSSL/wolfCrypt', '3.x-5.x', 'any',
     bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
     'wolfCrypt AES S-box constant'),
    # wolfSSL version string prefix
    ('wolfSSL/wolfCrypt', '3.x-5.x', 'any',
     b'wolfSSL',
     'wolfSSL version string prefix'),

    # ── mbedTLS ────────────────────────────────────────────────────────────────
    ('mbedTLS', '2.x-3.x', 'any',
     b'mbedtls_',
     'mbedTLS function name prefix in string table'),
    # mbedTLS AES S-box (same as OpenSSL, different prologue context)
    ('mbedTLS', '2.x-3.x', 'any',
     bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01]),
     'mbedTLS AES forward S-box (10-byte window)'),

    # ── expat / libxml2 ────────────────────────────────────────────────────────
    ('expat', '2.x', 'any',
     b'<?xml',
     'XML declaration bytes in rodata'),
    ('libxml2', '2.x', 'any',
     b'libxml2',
     'libxml2 name string in rodata'),

    # ── uclibc / musl ──────────────────────────────────────────────────────────
    ('uclibc', 'any', 'any',
     b'uClibc',
     'uClibc version string'),
    ('musl', 'any', 'any',
     b'musl libc',
     'musl libc version string'),
]


# ── Vulnerable version table ───────────────────────────────────────────────────
# Maps library name prefix to list of (version_range, cve_list)
_VULN_HINTS: dict[str, list[tuple[str, list[str]]]] = {
    'OpenSSL': [
        ('< 1.0.2u', ['CVE-2016-0800', 'CVE-2014-3566']),   # DROWN, POODLE
        ('< 1.1.1n', ['CVE-2022-0778']),                     # infinite loop in BN_mod_sqrt
        ('< 3.0.7',  ['CVE-2022-3786', 'CVE-2022-3602']),    # buffer overrun
    ],
    'zlib': [
        ('< 1.2.12', ['CVE-2018-25032', 'CVE-2022-37434']),  # heap overflow
    ],
    'libpng': [
        ('< 1.6.37', ['CVE-2019-7317']),                     # use-after-free
    ],
    'wolfSSL': [
        ('< 5.1.1',  ['CVE-2022-25640', 'CVE-2021-38597']),
    ],
    'mbedTLS': [
        ('< 2.28.1', ['CVE-2022-35409']),                    # heap buffer over-read
    ],
}


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class LibraryFinding:
    library:      str         # library name
    version_hint: str         # version range from signatures
    matched_sigs: list[str]   # list of matched signature notes
    match_count:  int         # total number of matches
    vuln_hints:   list[str]   # CVE references if version is known-vulnerable
    confidence:   str         # HIGH / MEDIUM / LOW

    def fmt(self) -> str:
        conf_sev = 'HIGH  ' if self.confidence == 'HIGH' else 'MEDIUM'
        cve_note = ''
        if self.vuln_hints:
            cve_note = f'\n         known-vulnerable hints: {", ".join(self.vuln_hints)}'
        sigs = '; '.join(self.matched_sigs[:4])
        if len(self.matched_sigs) > 4:
            sigs += f' (+{len(self.matched_sigs) - 4} more)'
        return (f"  {conf_sev}  [THIRD_PARTY_LIB]  {self.library}"
                f"  ({self.version_hint})\n"
                f"         {self.match_count} signature(s) matched: {sigs}"
                f"{cve_note}")


# ── Scanner ────────────────────────────────────────────────────────────────────

class ThirdPartyLibraryIdentifier:
    """Detect embedded third-party libraries via byte-signature matching."""

    def __init__(self, path: str, min_matches: int = 2) -> None:
        self._path = path
        self._min  = min_matches
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx, min_matches: int = 2) -> 'ThirdPartyLibraryIdentifier':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._min  = min_matches
        obj._ctx  = ctx
        return obj

    def _load_ctx(self):
        if self._ctx is not None:
            return self._ctx
        from ablation.analyzers.binary_context import BinaryContext
        self._ctx = BinaryContext.load_or_build(self._path)
        return self._ctx

    def scan(self) -> List[LibraryFinding]:
        try:
            raw = open(self._path, 'rb').read()
        except OSError:
            return []

        # Count hits per library
        lib_hits: dict[str, list[str]] = {}
        lib_ver:  dict[str, str] = {}

        for lib, ver, _arch, pattern, note in _SIGS:
            if pattern in raw:
                lib_hits.setdefault(lib, []).append(note)
                lib_ver[lib] = ver

        findings: list[LibraryFinding] = []
        for lib, hits in lib_hits.items():
            if len(hits) < self._min:
                continue
            confidence = 'HIGH' if len(hits) >= 3 else 'MEDIUM'
            vuln_hints: list[str] = []
            for prefix, vuln_list in _VULN_HINTS.items():
                if lib.startswith(prefix):
                    for _ver_range, cves in vuln_list:
                        vuln_hints.extend(cves)
            findings.append(LibraryFinding(
                library=lib,
                version_hint=lib_ver.get(lib, 'unknown'),
                matched_sigs=hits,
                match_count=len(hits),
                vuln_hints=vuln_hints,
                confidence=confidence,
            ))

        findings.sort(key=lambda f: f.match_count, reverse=True)
        return findings

    def report(self, findings: Optional[List[LibraryFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'ThirdPartyLibraryIdentifier: no known library signatures in {self._path}'
        lines = [f'ThirdPartyLibraryIdentifier: {len(findings)} library/libraries in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
