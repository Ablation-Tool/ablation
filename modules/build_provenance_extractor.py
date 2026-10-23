"""
build_provenance_extractor.py: Build toolchain and provenance extractor.

Extracts compiler, linker, and build-system provenance from ELF/PE binaries:

  - .comment section: GCC/Clang/ICC version string
  - .note.gnu.build-id: SHA-1 or MD5 hash for debuginfo matching
  - DW_AT_producer strings: compiler version from DWARF debug info
  - Linker version strings: GNU ld / gold / LLD version
  - Build timestamps: PE TimeDateStamp, DWARF DW_AT_comp_dir
  - Target triple: architecture + ABI from file header + dynamic linker path

Output: BuildProvenanceResult with structured fields mapping to SPDX
toolchain metadata conventions.

Usage:
    extractor = BuildProvenanceExtractor('/path/to/binary')
    result = extractor.extract()
    print(extractor.report(result))
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Optional


# ── Compiler version patterns (in .comment or DWARF strings) ──────────────────

_COMPILER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ('GCC',   re.compile(rb'GCC:\s*\(([^)]+)\)\s*([\d]+\.[\d]+\.[\d]+)')),
    ('Clang', re.compile(rb'clang\s+version\s+([\d]+\.[\d]+\.[\d]+)')),
    ('ICC',   re.compile(rb'Intel\(R\)\s+C\+\+\s+Compiler\s+([\d]+\.[\d]+)')),
    ('MSVC',  re.compile(rb'Microsoft\s*\(R\)\s*C/C\+\+\s*Optimizing\s*Compiler\s*Version\s*([\d]+\.[\d]+)')),
    ('armcc', re.compile(rb'ARM\s+Compiler\s+([\d]+\.[\d]+)')),
    ('IAR',   re.compile(rb'IAR\s+C/C\+\+\s+Compiler\s+V([\d]+\.[\d]+)')),
]

_LINKER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ('GNU ld', re.compile(rb'GNU\s+ld\s+\(([^)]+)\)\s*([\d]+\.[\d]+)')),
    ('LLD',    re.compile(rb'LLD\s+([\d]+\.[\d]+)')),
    ('gold',   re.compile(rb'GNU\s+gold[^)]*\)\s*([\d]+\.[\d]+)')),
    ('mold',   re.compile(rb'mold\s+([\d]+\.[\d]+)')),
]

# Dynamic linker path → libc hint
_DYNLINKER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ('glibc',    re.compile(rb'/lib(?:64)?/ld-linux[^\\x00]+')),
    ('musl',     re.compile(rb'/lib/ld-musl[^\\x00]+')),
    ('uclibc',   re.compile(rb'/lib/ld-uClibc[^\\x00]+')),
    ('Android',  re.compile(rb'/system/bin/linker(?:64)?')),
]


@dataclass
class BuildProvenanceResult:
    compiler:        str = ''          # e.g. "GCC 12.2.0"
    compiler_detail: str = ''          # e.g. "Debian 12.2.0-14"
    linker:          str = ''          # e.g. "GNU ld 2.40"
    build_id:        str = ''          # hex build-id hash
    libc:            str = ''          # glibc / musl / uclibc / Android
    dynlinker:       str = ''          # /lib64/ld-linux-x86-64.so.2
    target_arch:     str = ''          # x86_64 / aarch64 / mips etc.
    build_timestamp: str = ''          # PE timestamp or DWARF comp_dir hint
    dwarf_producers: list[str] = field(default_factory=list)
    raw_comment:     str = ''          # raw .comment section bytes

    def is_empty(self) -> bool:
        return not any([self.compiler, self.build_id, self.linker, self.libc])


class BuildProvenanceExtractor:
    """Extract compiler, linker, and build provenance from ELF/PE binaries."""

    def __init__(self, path: str) -> None:
        self._path = path

    @classmethod
    def from_context(cls, ctx) -> 'BuildProvenanceExtractor':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        return obj

    def _read_raw(self) -> bytes:
        try:
            return open(self._path, 'rb').read()
        except OSError:
            return b''

    def _extract_comment_section(self, raw: bytes) -> bytes:
        idx = raw.find(b'.comment\x00')
        if idx == -1:
            return b''
        # ELF section header: sh_offset at +16 (32-bit) or +24 (64-bit)
        # Simple heuristic: grab up to 512 bytes after the marker
        return raw[idx:idx + 512]

    def _extract_build_id(self, raw: bytes) -> str:
        # .note.gnu.build-id: type 3, name "GNU\0"
        pattern = re.compile(b'GNU\x00\x04\x00\x00\x00[\x01\x02]', re.DOTALL)
        for m in pattern.finditer(raw):
            # The build-id bytes follow: namesz=4, descsz=20 (SHA-1) or 16 (MD5)
            offset = m.start()
            # Try to find a 20-byte SHA-1 after the note header
            hdr_end = offset + 16
            if hdr_end + 20 <= len(raw):
                candidate = raw[hdr_end:hdr_end + 20]
                if all(b != 0 for b in candidate[:4]):
                    return candidate.hex()
        # Fallback: search for build-id note via section name
        idx = raw.find(b'GNU\x00')
        if idx != -1 and idx + 24 <= len(raw):
            candidate = raw[idx + 4:idx + 24]
            if any(b != 0 for b in candidate):
                return candidate.hex()
        return ''

    def _extract_arch(self, raw: bytes) -> str:
        if len(raw) < 18:
            return ''
        if raw[:4] == b'\x7fELF':
            e_machine = struct.unpack_from('<H', raw, 18)[0]
            _MACHINES = {
                0x03: 'x86', 0x3e: 'x86_64', 0x28: 'arm32',
                0xb7: 'aarch64', 0x08: 'mips', 0x15: 'ppc32',
                0x15: 'ppc32', 0x16: 'ppc64', 0xf3: 'riscv',
                0x5c: 'mips64',
            }
            return _MACHINES.get(e_machine, f'e_machine=0x{e_machine:x}')
        if raw[:2] == b'MZ':
            return 'x86/PE'
        return ''

    def _extract_pe_timestamp(self, raw: bytes) -> str:
        if len(raw) < 64:
            return ''
        try:
            pe_offset = struct.unpack_from('<I', raw, 60)[0]
            if pe_offset + 8 >= len(raw):
                return ''
            if raw[pe_offset:pe_offset + 4] != b'PE\x00\x00':
                return ''
            ts = struct.unpack_from('<I', raw, pe_offset + 8)[0]
            if ts == 0 or ts == 0xffffffff:
                return ''
            return str(ts)
        except struct.error:
            return ''

    def extract(self) -> BuildProvenanceResult:
        raw = self._read_raw()
        if not raw:
            return BuildProvenanceResult()

        result = BuildProvenanceResult()
        result.target_arch = self._extract_arch(raw)
        result.build_id = self._extract_build_id(raw)
        result.build_timestamp = self._extract_pe_timestamp(raw)

        # Compiler from .comment
        comment_chunk = self._extract_comment_section(raw)
        result.raw_comment = comment_chunk.decode('ascii', errors='replace').strip()
        for name, pat in _COMPILER_PATTERNS:
            m = pat.search(raw)
            if m:
                groups = m.groups()
                version = groups[-1].decode('ascii', errors='replace')
                detail = groups[0].decode('ascii', errors='replace') if len(groups) > 1 else ''
                result.compiler = f'{name} {version}'
                result.compiler_detail = detail
                break

        # Linker
        for name, pat in _LINKER_PATTERNS:
            m = pat.search(raw)
            if m:
                version = m.groups()[-1].decode('ascii', errors='replace')
                result.linker = f'{name} {version}'
                break

        # Dynamic linker / libc
        for libc_name, pat in _DYNLINKER_PATTERNS:
            m = pat.search(raw)
            if m:
                result.libc = libc_name
                result.dynlinker = m.group().decode('ascii', errors='replace')
                break

        return result

    def report(self, result: Optional[BuildProvenanceResult] = None) -> str:
        if result is None:
            result = self.extract()
        if result.is_empty():
            return f'BuildProvenanceExtractor: no provenance found in {self._path}'
        lines = [f'BuildProvenanceExtractor: {self._path}', '']
        if result.compiler:
            detail = f'  ({result.compiler_detail})' if result.compiler_detail else ''
            lines.append(f'  compiler:   {result.compiler}{detail}')
        if result.linker:
            lines.append(f'  linker:     {result.linker}')
        if result.libc:
            lines.append(f'  libc:       {result.libc}  ({result.dynlinker})')
        if result.target_arch:
            lines.append(f'  arch:       {result.target_arch}')
        if result.build_id:
            lines.append(f'  build-id:   {result.build_id}')
        if result.build_timestamp:
            lines.append(f'  timestamp:  {result.build_timestamp}')
        lines.append('')
        return '\n'.join(lines)
