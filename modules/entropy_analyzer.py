"""
entropy_analyzer.py: Per-section Shannon entropy analyzer for ELF firmware.

Computes Shannon entropy for each ELF section/segment and flags regions with
entropy > 7.0 as likely packed, compressed, or encrypted.  Packed sections
produce poor SemanticSearcher and TaintTracker results because the code is not
yet decompressed at static analysis time.  Running this module first lets the
analyst decide whether to unpack before analyzing.

Shannon entropy H = -sum(p(x) * log2(p(x))) over byte value frequencies.
Ranges:
  0.0 – 4.0  : sparse data, zero-filled, or very short sections
  4.0 – 6.5  : normal compiled code or data
  6.5 – 7.0  : compressed-like data, dense code, or crypto material
  7.0 – 8.0  : packed / encrypted / compressed — analysis results unreliable

Usage:
    scanner = EntropyAnalyzer('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = EntropyAnalyzer.from_context(ctx)
    findings = scanner.scan()
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


# Threshold above which a section is flagged as likely packed/encrypted.
ENTROPY_THRESHOLD = 7.0

# Minimum section size to analyze (very small sections produce noisy entropy).
MIN_SECTION_BYTES = 256


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class EntropyFinding:
    section_name: str   # ELF section name or segment description
    va:           int   # virtual address of section start
    size:         int   # section size in bytes
    entropy:      float # computed Shannon entropy (0.0 – 8.0)
    verdict:      str   # PACKED / HIGH_ENTROPY / NORMAL

    def fmt(self) -> str:
        bar_len = int(self.entropy / 8.0 * 40)
        bar = '█' * bar_len + '░' * (40 - bar_len)
        return (f"  {self.verdict:12s}  {self.section_name:<20s}  "
                f"va=0x{self.va:08x}  size={self.size:7d}B  "
                f"H={self.entropy:.3f}  |{bar}|")


# ── Core entropy calculation ───────────────────────────────────────────────────

def _shannon_entropy(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


# ── Scanner ────────────────────────────────────────────────────────────────────

class EntropyAnalyzer:
    """Compute per-section entropy and flag packed/encrypted regions."""

    def __init__(self, path: str, threshold: float = ENTROPY_THRESHOLD) -> None:
        self._path      = path
        self._ctx       = None
        self._threshold = threshold

    @classmethod
    def from_context(cls, ctx, threshold: float = ENTROPY_THRESHOLD) -> 'EntropyAnalyzer':
        obj = cls.__new__(cls)
        obj._path      = ctx.path
        obj._ctx       = ctx
        obj._threshold = threshold
        return obj

    def _iter_sections(self):
        """Yield (name, va, data) for each analyzable section."""
        try:
            import lief
            binary = lief.parse(self._path)
            if binary is None:
                return
            for section in binary.sections:
                if section.size < MIN_SECTION_BYTES:
                    continue
                data = bytes(section.content)
                if not data:
                    continue
                yield section.name, section.virtual_address, data
        except Exception:
            # Fallback: treat the entire file as one block
            data = Path(self._path).read_bytes()
            if len(data) >= MIN_SECTION_BYTES:
                yield '<file>', 0, data

    def scan(self) -> List[EntropyFinding]:
        findings: list[EntropyFinding] = []
        for name, va, data in self._iter_sections():
            h = _shannon_entropy(data)
            if h >= self._threshold:
                verdict = 'PACKED'
            elif h >= 6.5:
                verdict = 'HIGH_ENTROPY'
            else:
                continue  # normal sections not included
            findings.append(EntropyFinding(
                section_name=name,
                va=va,
                size=len(data),
                entropy=h,
                verdict=verdict,
            ))
        findings.sort(key=lambda f: -f.entropy)
        return findings

    def scan_all(self) -> List[EntropyFinding]:
        """Return entropy findings for every section, including normal ones."""
        findings: list[EntropyFinding] = []
        for name, va, data in self._iter_sections():
            h = _shannon_entropy(data)
            if h >= self._threshold:
                verdict = 'PACKED'
            elif h >= 6.5:
                verdict = 'HIGH_ENTROPY'
            else:
                verdict = 'NORMAL'
            findings.append(EntropyFinding(
                section_name=name,
                va=va,
                size=len(data),
                entropy=h,
                verdict=verdict,
            ))
        findings.sort(key=lambda f: -f.entropy)
        return findings

    def is_likely_packed(self) -> bool:
        """Return True if any section exceeds the packed-entropy threshold."""
        return any(f.verdict == 'PACKED' for f in self.scan())

    def report(self, findings: Optional[List[EntropyFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'EntropyAnalyzer: all sections normal entropy in {self._path}'
        packed = [f for f in findings if f.verdict == 'PACKED']
        lines = [
            f'EntropyAnalyzer: {len(findings)} elevated-entropy section(s) in {self._path}',
            f'  {len(packed)} section(s) above packing threshold ({self._threshold})',
            '',
        ]
        for f in findings:
            lines.append(f.fmt())
        if packed:
            lines.append('')
            lines.append('WARNING: SemanticSearcher and TaintTracker results are unreliable')
            lines.append('         on packed sections. Unpack or decrypt before analysis.')
        return '\n'.join(lines)
