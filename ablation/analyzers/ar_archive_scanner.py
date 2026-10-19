"""
ar_archive_scanner.py: scan Unix ar (.a) static library archives for exec-class sinks.

Why this exists:
  MASS/Linux/MASS_4.4_rhel5.tar.gz lib64/libmass_64.a required manually extracting
  ar members before SinkArgClassifier could run. Any static library (.a file)
  ships with pre-compiled .o object files whose exec-class surface must be checked.
  Gap ID: IBM-ARCH-002 (ar static library exec-class gap).

  ar format: magic header '!<arch>\\n' (8 bytes), then for each member:
    60-byte header: name(16), mtime(12), uid(6), gid(6), mode(8), size(10), end(2)
    member data (size bytes, padded to even boundary)

  Special members:
    '/'   = symbol table (GNU format)
    '//'  = long name table (GNU format)
    '__.SYMDEF' = BSD-style symbol table

Usage:
    from ablation.analyzers.ar_archive_scanner import ArArchiveScanner

    scanner = ArArchiveScanner.from_path('/path/to/libmass_64.a')
    results = scanner.scan_exec_class()
    print(scanner.report(results))

    # Check any .a file quickly:
    ArArchiveScanner.quick_check('/path/to/libfoo.a')  # prints summary
"""

from __future__ import annotations

import io
import struct
import tempfile
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import lazily to avoid hard dep when not analyzing
_SAC_AVAILABLE = False
try:
    from ablation.analyzers.sink_arg_classifier import SinkArgClassifier
    from ablation.analyzers.sink_arg_classifier_x86_32 import SinkArgClassifierI386
    _SAC_AVAILABLE = True
except ImportError:
    pass


_AR_MAGIC = b'!<arch>\n'
_MBR_HDR_SIZE = 60
_MBR_END = b'\x60\x0a'


@dataclass
class ArMemberResult:
    member_name: str
    size: int
    elf_format: Optional[str]    # e.g. 'ELF64-LE-ppc64' or None
    exec_hits: int
    verdicts: List[Tuple[str, str]]   # (sink_name, verdict)
    error: Optional[str] = None


class ArArchiveScanner:
    """Scan ar (.a) archives for exec-class sinks across all ELF object members."""

    def __init__(self, data: bytes):
        self._data = data

    @classmethod
    def from_path(cls, path: str) -> 'ArArchiveScanner':
        return cls(Path(path).read_bytes())

    def _iter_members(self):
        """Yield (name, data) for each non-special member."""
        data = self._data
        if not data.startswith(_AR_MAGIC):
            raise ValueError('Not an ar archive (bad magic)')

        pos = len(_AR_MAGIC)
        long_name_table: Optional[bytes] = None

        while pos + _MBR_HDR_SIZE <= len(data):
            hdr = data[pos:pos + _MBR_HDR_SIZE]
            if len(hdr) < _MBR_HDR_SIZE:
                break

            raw_name = hdr[0:16].rstrip()
            raw_size = hdr[48:58].rstrip()
            end_chars = hdr[58:60]

            if end_chars != _MBR_END:
                break  # corrupted header

            try:
                size = int(raw_size)
            except ValueError:
                break

            pos += _MBR_HDR_SIZE
            member_data = data[pos:pos + size]
            pos += size + (size % 2)  # pad to even boundary

            name = raw_name.decode('ascii', errors='replace').rstrip('/')

            # GNU long name table
            if raw_name.rstrip() == b'//':
                long_name_table = member_data
                continue

            # GNU symbol table
            if raw_name.rstrip() in (b'/', b'__.SYMDEF'):
                continue

            # Resolve GNU long names: '/N' where N is offset into //
            if name.startswith('/') and name[1:].isdigit() and long_name_table:
                off = int(name[1:])
                end = long_name_table.find(b'/\n', off)
                if end >= 0:
                    name = long_name_table[off:end].decode('ascii', errors='replace')

            yield name.rstrip(), member_data

    def scan_exec_class(self) -> List[ArMemberResult]:
        """Run SinkArgClassifier on each ELF object member. Returns results for exec-class members."""
        results: List[ArMemberResult] = []

        if not _SAC_AVAILABLE:
            return results

        for name, member_data in self._iter_members():
            if len(member_data) < 4:
                continue
            if member_data[:4] != b'\x7fELF':
                continue  # not ELF

            # Identify architecture
            ei_class = member_data[4]  # 1=32, 2=64
            ei_data  = member_data[5]  # 1=LE, 2=BE
            if len(member_data) >= 20:
                if ei_data == 1:
                    e_machine = struct.unpack_from('<H', member_data, 18)[0]
                else:
                    e_machine = struct.unpack_from('>H', member_data, 18)[0]
            else:
                e_machine = 0

            cls_s  = {1: 'ELF32', 2: 'ELF64'}.get(ei_class, 'ELF?')
            end_s  = {1: 'LE', 2: 'BE'}.get(ei_data, '?')
            arch_s = {0x03: 'x86', 0x14: 'ppc32', 0x15: 'ppc64', 0x28: 'ARM',
                      0x3e: 'x86_64', 0xb7: 'AArch64'}.get(e_machine, f'EM0x{e_machine:x}')
            elf_fmt = f'{cls_s}-{end_s}-{arch_s}'

            # Write to temp file
            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.o', prefix='ar_mbr_')
            try:
                os.write(tmp_fd, member_data)
                os.close(tmp_fd)

                # Choose classifier by architecture
                is_i386 = (e_machine == 0x03 and ei_class == 1)
                try:
                    if is_i386:
                        clf = SinkArgClassifierI386.from_path(tmp_path)
                    else:
                        clf = SinkArgClassifier.from_path(tmp_path)
                    sac_results = clf.classify_all()
                    exec_hits = [
                        (r.sink_name, r.verdict) for r in sac_results
                        if r.sink_name in ('execve', 'execv', 'execvp', 'execl', 'system', 'popen', 'fork')
                    ]
                    results.append(ArMemberResult(
                        member_name=name,
                        size=len(member_data),
                        elf_format=elf_fmt,
                        exec_hits=len(exec_hits),
                        verdicts=exec_hits,
                    ))
                except Exception as ex:
                    results.append(ArMemberResult(
                        member_name=name,
                        size=len(member_data),
                        elf_format=elf_fmt,
                        exec_hits=0,
                        verdicts=[],
                        error=str(ex)[:80],
                    ))
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        return results

    def report(self, results: List[ArMemberResult]) -> str:
        lines = []
        total = len(results)
        exec_members = [r for r in results if r.exec_hits > 0]
        lines.append(f'ArArchiveScanner: {total} ELF members, {len(exec_members)} with exec-class hits')
        for r in results:
            tag = 'EXEC' if r.exec_hits > 0 else 'safe'
            err = f' [{r.error}]' if r.error else ''
            lines.append(f'  [{tag}] {r.member_name} ({r.size}B {r.elf_format}) hits={r.exec_hits} {r.verdicts[:3]}{err}')
        return '\n'.join(lines)

    @classmethod
    def quick_check(cls, path: str) -> None:
        scanner = cls.from_path(path)
        results = scanner.scan_exec_class()
        print(scanner.report(results))
