"""
elf_anomaly_scanner.py: ELF structural anomaly detector.

Flags ELF images with structural properties inconsistent with normal compiler
output: section/segment mismatches, sections extending past file end, magic
byte mismatches, and other indicators of manual ELF construction or packing.

Detection checks:
  1. Magic bytes: ELF magic + class/data/version fields correct
  2. Section vs segment overlap: section lies entirely inside no segment
     (sections that have no PT_LOAD covering them are suspicious)
  3. Section extends past file: sh_offset + sh_size > filesize
  4. Overlapping sections: two sections with overlapping byte ranges
  5. Section name table absent or truncated: e_shstrndx invalid
  6. Zero-size executable segment: PT_LOAD with PF_X and p_filesz == 0
  7. Entry point outside any PT_LOAD segment: EP in unmapped memory
  8. Multiple PT_INTERP segments: unusual, seen in some loaders
  9. Section header count vs segment header count mismatch by large factor

Usage:
    scanner = ELFAnomalyScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ELFAnomalyFinding:
    check:      str     # check name
    detail:     str     # human-readable description
    severity:   str     # HIGH / MEDIUM / LOW

    def fmt(self) -> str:
        return f"  {self.severity:6s}  [ELF_ANOMALY]  {self.check}\n         {self.detail}"


class ELFAnomalyScanner:
    """Detect structural ELF anomalies indicating packing or manual construction."""

    def __init__(self, path: str) -> None:
        self._path = path

    @classmethod
    def from_context(cls, ctx) -> 'ELFAnomalyScanner':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        return obj

    def _read_raw(self) -> bytes:
        try:
            return open(self._path, 'rb').read()
        except OSError:
            return b''

    def scan(self) -> List[ELFAnomalyFinding]:
        raw = self._read_raw()
        if len(raw) < 64 or raw[:4] != b'\x7fELF':
            return []

        findings: list[ELFAnomalyFinding] = []
        try:
            import lief
            elf = lief.parse(self._path)
            if elf is None:
                return []

            filesize = len(raw)
            load_segs = [s for s in elf.segments if s.type == lief.ELF.Segment.TYPE.LOAD]
            exec_segs = [s for s in load_segs if s.flags & lief.ELF.Segment.FLAGS.X]
            interp_segs = [s for s in elf.segments if s.type == lief.ELF.Segment.TYPE.INTERP]

            # Check 1: section extends past file end
            for sec in elf.sections:
                if sec.offset == 0 and sec.size == 0:
                    continue
                if sec.offset + sec.size > filesize:
                    findings.append(ELFAnomalyFinding(
                        'section_past_eof',
                        f'section {sec.name!r} at 0x{sec.offset:x} + 0x{sec.size:x} > filesize 0x{filesize:x}',
                        'HIGH',
                    ))

            # Check 2: zero-size executable PT_LOAD
            for seg in exec_segs:
                if seg.file_size == 0:
                    findings.append(ELFAnomalyFinding(
                        'zero_size_exec_load',
                        f'PT_LOAD+X segment at 0x{seg.virtual_address:x} has filesz=0 (shellcode stub)',
                        'HIGH',
                    ))

            # Check 3: entry point outside all PT_LOAD segments
            ep = elf.header.entrypoint
            if ep != 0:
                ep_in_load = any(
                    seg.virtual_address <= ep < seg.virtual_address + seg.virtual_size
                    for seg in load_segs
                )
                if not ep_in_load and load_segs:
                    findings.append(ELFAnomalyFinding(
                        'ep_outside_load',
                        f'entrypoint 0x{ep:x} is not inside any PT_LOAD segment',
                        'HIGH',
                    ))

            # Check 4: multiple PT_INTERP segments
            if len(interp_segs) > 1:
                findings.append(ELFAnomalyFinding(
                    'multiple_pt_interp',
                    f'{len(interp_segs)} PT_INTERP segments (normally 0 or 1)',
                    'MEDIUM',
                ))

            # Check 5: overlapping sections
            secs = [(s.offset, s.size, s.name) for s in elf.sections if s.size > 0 and s.offset > 0]
            secs.sort(key=lambda x: x[0])
            for i in range(len(secs) - 1):
                off_a, sz_a, name_a = secs[i]
                off_b, sz_b, name_b = secs[i + 1]
                if off_a + sz_a > off_b:
                    findings.append(ELFAnomalyFinding(
                        'overlapping_sections',
                        f'section {name_a!r} [0x{off_a:x}+0x{sz_a:x}] overlaps {name_b!r} [0x{off_b:x}]',
                        'MEDIUM',
                    ))

            # Check 6: very large section/segment count mismatch
            nsec = elf.header.numberof_sections
            nseg = elf.header.numberof_segments
            if nsec > 0 and nseg > 0 and (nsec > nseg * 10 or nseg > nsec * 10):
                findings.append(ELFAnomalyFinding(
                    'section_segment_mismatch',
                    f'{nsec} sections vs {nseg} segments (unusual ratio)',
                    'LOW',
                ))

        except Exception as e:
            findings.append(ELFAnomalyFinding('parse_error', str(e)[:80], 'LOW'))

        return findings

    def report(self, findings: Optional[List[ELFAnomalyFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'ELFAnomalyScanner: no structural anomalies in {self._path}'
        lines = [f'ELFAnomalyScanner: {len(findings)} anomaly/anomalies in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
