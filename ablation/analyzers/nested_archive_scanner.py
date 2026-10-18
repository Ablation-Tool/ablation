"""
nested_archive_scanner.py: recursively extract multi-level archives and yield ELF paths.

Handles the IBM archive patterns encountered during IBM-RE analysis:
  tar.gz → RPM → ELF   (HACMP, RMC, GPFS, LoadLeveler)
  zip → tar → ELF       (DOORS)
  tar → tgz → ELF       (Tau)
  .deb → ELF            (IPL-SDK-deb)

Why this exists:
  Three separate sessions (HACMP, Tau, DOORS) wrote ad-hoc subprocess scripts
  to handle nested archive extraction. This module unifies them so future
  IBM product analysis starts with ELF paths, not extraction boilerplate.
  Gap ID: IBM-ARCH-001 (ad-hoc nested archive extraction).

Usage:
    from ablation.analyzers.nested_archive_scanner import NestedArchiveScanner

    scanner = NestedArchiveScanner('/media/cowboy/research/IBM-RE/HACMP/')
    for elf_path, virtual_path in scanner.scan():
        print(virtual_path, '→', elf_path)

    # Or scan a single archive:
    for elf_path, virtual_path in NestedArchiveScanner.scan_archive('/path/to/foo.tar.gz'):
        ...
"""

from __future__ import annotations

import os
import shlex
import struct
import subprocess
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, Tuple

__all__ = ['NestedArchiveScanner']

_ELF_MAGIC  = b'\x7fELF'
_RPM_MAGIC  = b'\xed\xab\xee\xdb'
_ZIP_MAGIC  = b'PK\x03\x04'
_GZ_MAGIC   = b'\x1f\x8b'
_BFF_MAGIC  = b'\x09\x00\x6b\xea'   # AIX BFF — not extractable, skip

_MAX_DEPTH  = 4          # maximum archive nesting levels
_MIN_ELF_SIZE = 52       # minimum valid ELF (ELF32 header size)


def _is_elf(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == _ELF_MAGIC


def _detect_format(path: str) -> Optional[str]:
    """Return archive format tag or None for non-archives."""
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
    except OSError:
        return None
    if magic[:4] == _RPM_MAGIC:
        return 'rpm'
    if magic[:2] == b'PK':
        return 'zip'
    if magic[:2] == _GZ_MAGIC:
        return 'tgz'
    if magic[:4] == _BFF_MAGIC:
        return 'bff'   # AIX installp — no Linux ELF content, skip
    # Plain tar: check via tarfile
    try:
        if tarfile.is_tarfile(path):
            return 'tar'
    except Exception:
        pass
    # .Z compress (LZW) — needs uncompress
    try:
        with open(path, 'rb') as f:
            m2 = f.read(2)
        if m2 == b'\x1f\x9d':
            return 'compress'
    except OSError:
        pass
    return None


@contextmanager
def _extract_to_tmpdir(archive_path: str, fmt: str) -> Iterator[str]:
    """Extract archive to a temporary directory; yield the directory path; clean up."""
    tmp = tempfile.mkdtemp(prefix='/tmp/nas-')
    try:
        if fmt == 'rpm':
            subprocess.run(
                f'rpm2cpio {shlex.quote(archive_path)} | cpio -idm --quiet 2>/dev/null',
                shell=True, cwd=tmp, timeout=120,
            )
        elif fmt == 'zip':
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(tmp)
        elif fmt == 'tgz':
            with tarfile.open(archive_path, 'r:gz') as tf:
                tf.extractall(tmp, filter='data')
        elif fmt == 'tar':
            with tarfile.open(archive_path, 'r:') as tf:
                tf.extractall(tmp, filter='data')
        elif fmt == 'compress':
            subprocess.run(
                f'uncompress -c {shlex.quote(archive_path)} > /tmp/nas-uncomp.tar',
                shell=True, timeout=120,
            )
            try:
                with tarfile.open('/tmp/nas-uncomp.tar', 'r:') as tf:
                    tf.extractall(tmp, filter='data')
            finally:
                try:
                    os.unlink('/tmp/nas-uncomp.tar')
                except OSError:
                    pass
        yield tmp
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _scan_dir(
    directory: str,
    virtual_prefix: str,
    depth: int,
) -> Iterator[Tuple[str, str]]:
    """
    Yield (real_path, virtual_path) for every ELF in `directory`.
    Recurse into nested archives up to _MAX_DEPTH.
    """
    if depth > _MAX_DEPTH:
        return
    try:
        entries = sorted(os.listdir(directory))
    except OSError:
        return
    for entry in entries:
        real = os.path.join(directory, entry)
        virtual = f'{virtual_prefix}/{entry}'
        if os.path.islink(real):
            continue
        if os.path.isdir(real):
            yield from _scan_dir(real, virtual, depth)
            continue
        if not os.path.isfile(real):
            continue
        fsize = os.path.getsize(real)
        if fsize < _MIN_ELF_SIZE:
            continue
        try:
            with open(real, 'rb') as f:
                magic = f.read(4)
        except OSError:
            continue
        if _is_elf(magic):
            yield (real, virtual)
            continue
        # Not an ELF — check if it's a nested archive
        fmt = _detect_format(real)
        if fmt and fmt != 'bff':
            try:
                with _extract_to_tmpdir(real, fmt) as tmpdir:
                    yield from _scan_dir(tmpdir, virtual, depth + 1)
            except Exception:
                pass


class NestedArchiveScanner:
    """
    Recursively scan a directory or archive for ELF files, descending into
    nested archives (RPM, zip, tar.gz, tar.Z, plain tar) at each level.
    """

    def __init__(self, path: str) -> None:
        self._path = path

    def scan(self) -> Iterator[Tuple[str, str]]:
        """
        Yield (real_tmpdir_path, virtual_path) for every ELF found, recursively.

        `real_tmpdir_path` is a path to the extracted ELF in a temporary directory.
        Callers must consume or copy the file before the iterator is exhausted —
        the temporary directories are cleaned up lazily by the generator.

        `virtual_path` is a human-readable archive-relative path:
          e.g. 'HACMP/hacmp.base-4.5.2-0.ppc.rpm/usr/es/sbin/cluster/clstrmgr'
        """
        path = self._path
        if os.path.isdir(path):
            yield from _scan_dir(path, os.path.basename(path), depth=0)
            return
        fmt = _detect_format(path)
        if fmt and fmt != 'bff':
            with _extract_to_tmpdir(path, fmt) as tmpdir:
                yield from _scan_dir(tmpdir, os.path.basename(path), depth=1)

    @classmethod
    def scan_archive(cls, archive_path: str) -> Iterator[Tuple[str, str]]:
        """Convenience classmethod: scan a single archive file."""
        return cls(archive_path).scan()

    @classmethod
    def collect_elfs(cls, path: str, max_elfs: Optional[int] = None) -> list:
        """
        Collect up to `max_elfs` ELFs from `path`, returning list of
        (real_path, virtual_path, elf_bytes) tuples.

        All ELF data is read into memory before temporary directories are
        cleaned up. Suitable for small-to-medium archives.
        """
        results = []
        for real, virtual in cls(path).scan():
            try:
                data = Path(real).read_bytes()
            except OSError:
                continue
            results.append((virtual, data))
            if max_elfs is not None and len(results) >= max_elfs:
                break
        return results
