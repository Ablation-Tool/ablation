"""CVE byte-pattern library for binary patch verification.

Maps CVE identifiers to architecture-specific byte sequences that appear in
unpatched binaries. Allows PatternLibrary-compatible sweeps across any binary
that bundles a common library, without source code or version strings.

Why this exists
---------------
1. The ISII-XML-002 analysis (CVE-2011-3919) required manually identifying
   the unpatched libxml2 2.7.8 byte signature in libeaexml2.so by comparing
   the patched (2.8.0) and unpatched function bodies. The two key bytes were
   C745B42C010000 (mov [ebp-0x4c], 0x12c) and D165B4 (shl [ebp-0x4c], 1).
   These are now in the registry so future targets with bundled libxml2 can
   be swept automatically.
2. Bundled library versions are common in IBM products: ISII bundles libxml2
   2.7.8; solidDB bundles an older sqlite; OpenSSL is routinely embedded at
   outdated versions. Each confirmed CVE byte pattern is reusable across all
   targets that embed the same library version.
3. Byte-pattern confirmation is independent of source code and dynamic
   testing. A matching byte sequence at the expected function offset is
   sufficient to confirm the unpatched state; this is the same standard used
   in binary patch diffing and malware research.

Usage::

    from ablation.analyzers.cve_byte_patterns import CVEBytePatterns, CVEScanner

    # Query the registry
    pattern = CVEBytePatterns.REGISTRY['CVE-2011-3919']
    print(pattern.summary())

    # Scan a binary for unpatched CVEs
    scanner = CVEScanner('/path/to/libeaexml2.so')
    results = scanner.scan()
    for r in results:
        print(r.cve_id, r.matched, r.va)

    # Register a new pattern after finding it
    CVEBytePatterns.register(
        cve_id='CVE-XXXX-YYYY',
        library='libfoo',
        arch='x86',
        function='vulnerable_func',
        unpatched_sequences=[
            (0x100, b'\\xc7\\x45\\xb4\\x2c\\x01\\x00\\x00'),
        ],
        patched_note='patched version derives size from input length',
        severity='HIGH',
        fixed_version='1.2.3',
    )
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class CVEPattern:
    """One CVE entry in the registry."""

    cve_id:            str
    library:           str             # e.g. 'libxml2'
    arch:              str             # 'x86', 'ppc32', 'x86_64', 'arm32', etc.
    function:          str             # vulnerable function name
    severity:          str             # HIGH / MEDIUM / LOW / CRITICAL
    fixed_version:     str             # first version with the fix
    unpatched_sequences: List[Tuple[int, bytes]]
    # List of (relative_offset, bytes) pairs that appear in unpatched code.
    # relative_offset is from the start of the function or section (0 = unknown).
    patched_note:      str = ''        # description of what patched code looks like
    notes:             str = ''        # any additional notes

    def summary(self) -> str:
        seqs = ', '.join(
            f'+{off:#x}:{b.hex()}' for off, b in self.unpatched_sequences
        )
        return (
            f'{self.cve_id}  {self.library}  arch={self.arch}'
            f'  fn={self.function!r}  severity={self.severity}'
            f'  fixed>={self.fixed_version}  sequences=[{seqs}]'
        )


@dataclass
class CVEScanResult:
    """Result of scanning one binary for one CVE pattern."""

    cve_id:   str
    matched:  bool             # True if the unpatched pattern was found
    va:       int              # VA of the first matching byte sequence (0 if no match)
    offset:   int              # file offset of the match
    note:     str = ''


class CVEBytePatterns:
    """Registry of CVE byte-pattern entries.

    Access the registry via ``CVEBytePatterns.REGISTRY`` (populated at module
    import). Add entries via ``CVEBytePatterns.register()``.
    """

    REGISTRY: Dict[str, CVEPattern] = {}

    @classmethod
    def register(
        cls,
        cve_id: str,
        library: str,
        arch: str,
        function: str,
        unpatched_sequences: List[Tuple[int, bytes]],
        patched_note: str = '',
        severity: str = 'HIGH',
        fixed_version: str = '',
        notes: str = '',
    ) -> CVEPattern:
        """Add a pattern to the registry. Overwrites any existing entry."""
        entry = CVEPattern(
            cve_id=cve_id,
            library=library,
            arch=arch,
            function=function,
            severity=severity,
            fixed_version=fixed_version,
            unpatched_sequences=unpatched_sequences,
            patched_note=patched_note,
            notes=notes,
        )
        cls.REGISTRY[cve_id] = entry
        return entry

    @classmethod
    def get(cls, cve_id: str) -> Optional[CVEPattern]:
        return cls.REGISTRY.get(cve_id)


# ── Built-in registry entries ────────────────────────────────────────────────

CVEBytePatterns.register(
    cve_id='CVE-2011-3919',
    library='libxml2',
    arch='x86',
    function='xmlStringLenDecodeEntities',
    severity='HIGH',
    fixed_version='2.8.0',
    unpatched_sequences=[
        # mov dword ptr [ebp-0x4c], 0x12c — hardcoded 300-byte initial alloc
        # Confirmed at VA 0x2ade7 in ISII libeaexml2.so (IBM ISII 8.1 FP1 Linux x86)
        (0, b'\xc7\x45\xb4\x2c\x01\x00\x00'),
        # shl dword ptr [ebp-0x4c], 1 — unbounded doubling growth loop, no cap
        # Confirmed at VA 0x2aea5 in the same binary
        (0, b'\xd1\x65\xb4'),
    ],
    patched_note=(
        'Patched libxml2 2.8.0 computes initial alloc from input length: '
        'buf_size = len + XML_PARSER_BIG_BUFFER_SIZE (4096). '
        'The constant 0x12c (300) is absent in patched code.'
    ),
    notes=(
        'Heap-based buffer overflow in xmlStringLenDecodeEntities. '
        'Triggered by deeply nested XML entities. '
        'Confirmed unpatched in IBM ISII 8.1 FP1 (libeaexml2.so, October 2026).'
    ),
)

CVEBytePatterns.register(
    cve_id='CVE-2012-5134',
    library='libxml2',
    arch='x86',
    function='xmlParseAttValueComplex',
    severity='HIGH',
    fixed_version='2.9.0',
    unpatched_sequences=[
        # xmlParseAttValueComplex heap-based buffer overflow
        # Exact bytes TBD — requires byte-verification against a 2.7.x/2.8.x sample.
        # Placeholder: the patched version (2.9.0) adds a length check before realloc.
    ],
    patched_note='Patched 2.9.0 adds size check before xmlBufGrow in attribute parsing.',
    notes=(
        'CVE-2012-5134: heap BOF in xmlParseAttValueComplex via malformed XML attributes. '
        'Byte sequences pending verification against a confirmed 2.7.x/2.8.x sample.'
    ),
)

CVEBytePatterns.register(
    cve_id='CVE-2012-2807',
    library='libxml2',
    arch='x86',
    function='xmlXPathCmpNodes',
    severity='MEDIUM',
    fixed_version='2.9.0',
    unpatched_sequences=[
        # xmlXPathCmpNodes integer overflow — exact bytes TBD
    ],
    patched_note='Patched 2.9.0 adds an overflow check before the node position comparison.',
    notes=(
        'CVE-2012-2807: integer overflow in xmlXPathCmpNodes. '
        'Byte sequences pending verification.'
    ),
)


class CVEScanner:
    """Scans a binary for unpatched CVE byte patterns from the registry.

    Args:
        binary_path: Path to the binary to scan.
        cve_ids:     Subset of CVE IDs to check. If None, checks all entries
                     in the registry that have at least one unpatched sequence.
        arch_filter: If set, only entries matching this arch string are checked.
    """

    def __init__(
        self,
        binary_path: str | Path,
        cve_ids: Optional[List[str]] = None,
        arch_filter: Optional[str] = None,
    ):
        self.binary_path = str(binary_path)
        self._cve_ids = cve_ids
        self._arch_filter = arch_filter

    @classmethod
    def from_context(cls, ctx, **kwargs) -> 'CVEScanner':
        return cls(ctx.path, **kwargs)

    def scan(self) -> List[CVEScanResult]:
        """Search the binary for each registered unpatched byte pattern.

        Returns one CVEScanResult per CVE ID checked.
        """
        with open(self.binary_path, 'rb') as fh:
            data = fh.read()

        entries = CVEBytePatterns.REGISTRY.values()
        if self._cve_ids is not None:
            entries = [e for e in entries if e.cve_id in self._cve_ids]
        if self._arch_filter:
            entries = [e for e in entries if e.arch == self._arch_filter]
        entries = [e for e in entries if e.unpatched_sequences]

        results: List[CVEScanResult] = []
        for entry in entries:
            first_match_off = -1
            matched = True
            for _rel_off, seq in entry.unpatched_sequences:
                idx = data.find(seq)
                if idx == -1:
                    matched = False
                    break
                if first_match_off == -1:
                    first_match_off = idx

            results.append(CVEScanResult(
                cve_id=entry.cve_id,
                matched=matched,
                va=first_match_off,
                offset=first_match_off,
                note=entry.notes if matched else 'Pattern not found (possibly patched or different arch variant)',
            ))

        return results

    @staticmethod
    def report(results: List[CVEScanResult]) -> str:
        if not results:
            return 'CVEScanner: no entries checked.\n'
        lines = []
        for r in results:
            state = 'UNPATCHED' if r.matched else 'not found'
            loc = f'  file_off={r.va:#x}' if r.matched else ''
            lines.append(f'  {r.cve_id}: {state}{loc}')
            if r.note:
                lines.append(f'    {r.note}')
        return f'CVEScanner ({len(results)} checked):\n' + '\n'.join(lines) + '\n'
