"""
sbom_extractor.py: Software Bill of Materials extractor for firmware binaries.

Extracts an SBOM from a stripped firmware binary by combining three sources:

  1. Version strings in rodata: many open-source libraries embed a version
     string (e.g. "OpenSSL 1.1.1k", "zlib 1.2.11") even in stripped builds.
     A regex sweep over all printable strings in the binary recovers these.

  2. ThirdPartyLibraryIdentifier results: byte-signature matches confirm
     library presence even when no version string is present.

  3. PE/ELF metadata: file-level fields such as DT_NEEDED shared library names,
     PE ImportDirectory DLL names, and elf comment sections (.comment).

Output: SBOM as a list of SBOMComponent entries. Each entry maps to the
CycloneDX and SPDX field conventions where possible.

Usage:
    extractor = SBOMExtractor('/path/to/binary')
    components = extractor.extract()
    print(extractor.report(components))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    extractor = SBOMExtractor.from_context(ctx)
    components = extractor.extract()
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import List, Optional


# ── Version string patterns ────────────────────────────────────────────────────
#
# These regexes match version strings that libraries embed in rodata.
# Each group: (library_canonical_name, regex, name_group_index, version_group_index)

_VERSION_PATTERNS: list[tuple[str, re.Pattern, int, int]] = [
    ('OpenSSL', re.compile(rb'OpenSSL\s+([\d]+\.[\d]+\.[\d]+\w*)'), 0, 1),
    ('LibreSSL', re.compile(rb'LibreSSL\s+([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('wolfSSL', re.compile(rb'wolfSSL\s+([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('wolfCrypt', re.compile(rb'wolfCrypt\s+([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('mbedTLS', re.compile(rb'mbed\s*TLS\s+([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('zlib', re.compile(rb'zlib\s+([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('libpng', re.compile(rb'libpng\s+version\s+([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('libjpeg', re.compile(rb'libjpeg-turbo\s+([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('libjpeg', re.compile(rb'JPEG\s+image\s+library[,\s]+version\s+([\d]+)'), 0, 1),
    ('expat', re.compile(rb'expat_([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('libxml2', re.compile(rb'libxml2\s+([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('SQLite', re.compile(rb'SQLite\s+version\s+([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('SQLite', re.compile(rb'SQLite ([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('OpenWRT', re.compile(rb'OpenWrt\s+([\w\d\.-]+)'), 0, 1),
    ('Linux kernel', re.compile(rb'Linux version\s+([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('BusyBox', re.compile(rb'BusyBox v([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('OpenSSH', re.compile(rb'OpenSSH_([\d]+\.[\d]+p[\d]+)'), 0, 1),
    ('dropbear', re.compile(rb'Dropbear v([\d]+\.[\d]+)'), 0, 1),
    ('curl', re.compile(rb'libcurl/([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('uclibc', re.compile(rb'uClibc-([\d]+\.[\d]+\.[\d]+)'), 0, 1),
    ('musl', re.compile(rb'musl libc\s+\(([\d]+\.[\d]+\.[\d]+)\)'), 0, 1),
    ('glibc', re.compile(rb'GNU C Library[^\d]+([\d]+\.[\d]+)'), 0, 1),
]


# ── SPDX ID lookup ─────────────────────────────────────────────────────────────
_SPDX_IDS: dict[str, str] = {
    'OpenSSL':        'OpenSSL',
    'LibreSSL':       'OpenSSL',
    'wolfSSL':        'GPL-2.0-or-later',
    'mbedTLS':        'Apache-2.0',
    'zlib':           'Zlib',
    'libpng':         'Libpng',
    'libjpeg':        'IJG',
    'expat':          'MIT',
    'libxml2':        'MIT',
    'SQLite':         'blessing',
    'BusyBox':        'GPL-2.0-only',
    'OpenSSH':        'SSH-OpenSSH',
    'dropbear':       'MIT',
    'curl':           'curl',
    'uclibc':         'LGPL-2.1-only',
    'musl':           'MIT',
    'glibc':          'LGPL-2.1-or-later',
}


# ── Component record ───────────────────────────────────────────────────────────

@dataclass
class SBOMComponent:
    name:       str              # canonical library name
    version:    str              # version string, 'unknown' if not found
    source:     str              # 'version_string' / 'signature' / 'metadata'
    spdx_id:    str              # SPDX license identifier if known
    confidence: str              # HIGH / MEDIUM
    notes:      list[str] = field(default_factory=list)

    def fmt(self) -> str:
        lic = f'  license={self.spdx_id}' if self.spdx_id else ''
        notes = ''
        if self.notes:
            notes = '  [' + '; '.join(self.notes) + ']'
        return (f"  {self.confidence:6s}  {self.name} {self.version}"
                f"  (via {self.source}){lic}{notes}")


# ── Extractor ──────────────────────────────────────────────────────────────────

class SBOMExtractor:
    """Extract software bill of materials from a firmware binary."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'SBOMExtractor':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._ctx  = ctx
        return obj

    def _load_ctx(self):
        if self._ctx is not None:
            return self._ctx
        from ablation.analyzers.binary_context import BinaryContext
        self._ctx = BinaryContext.load_or_build(self._path)
        return self._ctx

    def _read_raw(self) -> bytes:
        try:
            return open(self._path, 'rb').read()
        except OSError:
            return b''

    def _version_string_components(self, raw: bytes) -> list[SBOMComponent]:
        seen: set[str] = set()
        results: list[SBOMComponent] = []
        for lib_name, pat, _ng, vg in _VERSION_PATTERNS:
            for m in pat.finditer(raw):
                version = m.group(vg).decode('ascii', errors='replace')
                key = f'{lib_name}:{version}'
                if key in seen:
                    continue
                seen.add(key)
                results.append(SBOMComponent(
                    name=lib_name,
                    version=version,
                    source='version_string',
                    spdx_id=_SPDX_IDS.get(lib_name, ''),
                    confidence='HIGH',
                ))
        return results

    def _signature_components(self, existing_names: set[str]) -> list[SBOMComponent]:
        from modules.third_party_library_identifier import ThirdPartyLibraryIdentifier
        ident = ThirdPartyLibraryIdentifier(self._path, min_matches=2)
        sig_findings = ident.scan()
        results: list[SBOMComponent] = []
        for f in sig_findings:
            if f.library in existing_names:
                continue
            results.append(SBOMComponent(
                name=f.library,
                version=f.version_hint,
                source='signature',
                spdx_id=_SPDX_IDS.get(f.library.split('/')[0], ''),
                confidence=f.confidence,
                notes=f.matched_sigs[:2],
            ))
        return results

    def _metadata_components(self, raw: bytes) -> list[SBOMComponent]:
        results: list[SBOMComponent] = []
        # ELF .comment section: strip null bytes, split on nulls
        comment_idx = raw.find(b'.comment')
        if comment_idx != -1:
            chunk = raw[comment_idx:comment_idx + 256]
            printable = bytes(b if 0x20 <= b < 0x7f else 0x0a for b in chunk)
            for token in printable.split(b'\n'):
                t = token.strip()
                if len(t) > 3:
                    results.append(SBOMComponent(
                        name='(build toolchain)',
                        version=t.decode('ascii', errors='replace'),
                        source='metadata(.comment)',
                        spdx_id='',
                        confidence='MEDIUM',
                    ))
                    break  # first meaningful token only
        # DT_NEEDED shared library names (ELF dynamic section)
        needed_pat = re.compile(rb'lib[\w\.-]+\.so[\.\d]*')
        for m in needed_pat.finditer(raw):
            name = m.group().decode('ascii', errors='replace')
            results.append(SBOMComponent(
                name=name,
                version='dynamic',
                source='metadata(DT_NEEDED)',
                spdx_id='',
                confidence='MEDIUM',
            ))
        return results

    def extract(self) -> List[SBOMComponent]:
        raw = self._read_raw()
        if not raw:
            return []

        components = self._version_string_components(raw)
        existing_names = {c.name for c in components}

        sig_components = self._signature_components(existing_names)
        components.extend(sig_components)
        existing_names.update(c.name for c in sig_components)

        meta = self._metadata_components(raw)
        # Only keep metadata entries not already found by version string
        for m in meta:
            if m.name not in existing_names:
                components.append(m)

        # Stable sort: HIGH first, then alphabetical
        components.sort(key=lambda c: (0 if c.confidence == 'HIGH' else 1, c.name))
        return components

    def report(self, components: Optional[List[SBOMComponent]] = None) -> str:
        if components is None:
            components = self.extract()
        if not components:
            return f'SBOMExtractor: no components identified in {self._path}'
        lines = [f'SBOMExtractor: {len(components)} component(s) in {self._path}', '']
        for c in components:
            lines.append(c.fmt())
        lines.append('')
        return '\n'.join(lines)
