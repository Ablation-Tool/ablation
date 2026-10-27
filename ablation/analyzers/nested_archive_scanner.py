"""
nested_archive_scanner.py: recursively extract multi-level archives and yield ELF paths.

Handles tar.gz, RPM, ZIP, tar, and .Z inputs with traversal checks and
resource budgets shared across all nesting levels.

Usage:
    from ablation.analyzers.nested_archive_scanner import NestedArchiveScanner

    for elf_path, virtual_path in NestedArchiveScanner.scan_archive('/path/to/foo.tar.gz'):
        print(virtual_path, elf_path)
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import warnings
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Iterator, Optional, Tuple

__all__ = ['NestedArchiveScanner']

_ELF_MAGIC = b'\x7fELF'
_RPM_MAGIC = b'\xed\xab\xee\xdb'
_GZIP_MAGIC = b'\x1f\x8b'
_BFF_MAGIC = b'\x09\x00\x6b\xea'

_MAX_DEPTH = 4
_MIN_ELF_SIZE = 52
_MAX_INPUT_BYTES = 256 * 1024 * 1024
_MAX_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_INTERMEDIATE_BYTES = 512 * 1024 * 1024
_MAX_FILES = 4096
_COPY_CHUNK = 1024 * 1024


def _is_elf(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == _ELF_MAGIC


def _detect_format(path: str) -> Optional[str]:
    try:
        with open(path, 'rb') as handle:
            magic = handle.read(4)
    except OSError:
        return None
    if magic == _RPM_MAGIC:
        return 'rpm'
    if magic[:2] == b'PK':
        return 'zip'
    if magic[:2] == _GZIP_MAGIC:
        return 'tgz'
    if magic == _BFF_MAGIC:
        return 'bff'
    try:
        if tarfile.is_tarfile(path):
            return 'tar'
    except (OSError, tarfile.TarError):
        pass
    try:
        with open(path, 'rb') as handle:
            if handle.read(2) == b'\x1f\x9d':
                return 'compress'
    except OSError:
        pass
    return None


def _new_budget() -> dict[str, int]:
    return {'bytes': 0, 'files': 0}


def _charge(size: int, budget: dict[str, int]) -> None:
    if size < 0 or size > _MAX_MEMBER_BYTES:
        raise ValueError(f'archive member size exceeds {_MAX_MEMBER_BYTES} bytes')
    if budget['files'] + 1 > _MAX_FILES:
        raise ValueError(f'archive contains more than {_MAX_FILES} files')
    if budget['bytes'] + size > _MAX_TOTAL_BYTES:
        raise ValueError(f'archive expands beyond {_MAX_TOTAL_BYTES} bytes')
    budget['files'] += 1
    budget['bytes'] += size


def _output_path(root: str, name: str) -> Path:
    relative = PurePosixPath(name.replace('\\', '/'))
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError(f'unsafe archive member path: {name!r}')
    if not relative.parts or relative == PurePosixPath('.'):
        raise ValueError('empty archive member path')
    root_path = Path(root).resolve()
    destination = root_path.joinpath(*relative.parts).resolve()
    if root_path != destination and root_path not in destination.parents:
        raise ValueError(f'archive member escapes extraction directory: {name!r}')
    return destination


def _copy_member(source, destination: Path, declared_size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    remaining = declared_size
    with destination.open('xb') as output:
        while remaining:
            chunk = source.read(min(_COPY_CHUNK, remaining))
            if not chunk:
                raise ValueError(f'truncated archive member: {destination.name!r}')
            output.write(chunk)
            remaining -= len(chunk)
        if source.read(1):
            raise ValueError(f'archive member exceeds declared size: {destination.name!r}')


def _extract_zip(archive_path: str, tmp: str, budget: dict[str, int]) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError(f'archive links are not allowed: {info.filename!r}')
            _charge(info.file_size, budget)
            destination = _output_path(tmp, info.filename)
            with archive.open(info) as source:
                _copy_member(source, destination, info.file_size)


def _extract_tar(archive_path: str, mode: str, tmp: str, budget: dict[str, int]) -> None:
    with tarfile.open(archive_path, mode) as archive:
        for member in archive:
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f'archive links and special files are not allowed: {member.name!r}')
            _charge(member.size, budget)
            destination = _output_path(tmp, member.name)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f'unreadable archive member: {member.name!r}')
            with source:
                _copy_member(source, destination, member.size)


def _run_to_file(command: list[str], destination: Path, timeout: int = 120) -> None:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    total = 0
    try:
        with destination.open('xb') as output:
            while True:
                chunk = process.stdout.read(_COPY_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_INTERMEDIATE_BYTES:
                    raise ValueError(f'intermediate archive exceeds {_MAX_INTERMEDIATE_BYTES} bytes')
                output.write(chunk)
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise ValueError(f'archive helper timed out: {command[0]}') from exc
    except Exception:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    if process.returncode != 0:
        raise ValueError(f'archive helper failed: {command[0]} ({process.returncode})')


def _validate_cpio_listing(listing: str, budget: dict[str, int]) -> None:
    for line in listing.splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 5)
        if len(fields) < 6:
            raise ValueError('unrecognized cpio listing row')
        try:
            size = int(fields[4])
        except ValueError as exc:
            raise ValueError('unrecognized cpio member size') from exc
        remainder = fields[5].split(None, 3)
        if len(remainder) < 4:
            raise ValueError('unrecognized cpio member name')
        _charge(size, budget)
        _output_path('/tmp/cpio-validation', remainder[3])


def _extract_rpm(archive_path: str, tmp: str, budget: dict[str, int]) -> None:
    cpio_path = Path(tmp) / '.nested-package.cpio'
    try:
        _run_to_file(['rpm2cpio', archive_path], cpio_path)
        with cpio_path.open('rb') as source:
            listing = subprocess.run(
                ['cpio', '-itv', '--quiet'], stdin=source,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=120,
            )
        if listing.returncode != 0:
            raise ValueError('could not list RPM cpio payload')
        _validate_cpio_listing(listing.stdout, budget)
        with cpio_path.open('rb') as source:
            result = subprocess.run(
                ['cpio', '-idm', '--quiet', '--no-absolute-filenames'],
                stdin=source, cwd=tmp, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=120,
            )
        if result.returncode != 0:
            raise ValueError('could not extract RPM cpio payload')
    finally:
        cpio_path.unlink(missing_ok=True)


@contextmanager
def _extract_to_tmpdir(
    archive_path: str,
    fmt: str,
    budget: Optional[dict[str, int]] = None,
) -> Iterator[str]:
    budget = budget if budget is not None else _new_budget()
    if os.path.getsize(archive_path) > _MAX_INPUT_BYTES:
        raise ValueError(f'archive input exceeds {_MAX_INPUT_BYTES} bytes')
    tmp = tempfile.mkdtemp(prefix='nas-')
    try:
        if fmt == 'rpm':
            _extract_rpm(archive_path, tmp, budget)
        elif fmt == 'zip':
            _extract_zip(archive_path, tmp, budget)
        elif fmt in {'tgz', 'tar'}:
            _extract_tar(archive_path, 'r:*', tmp, budget)
        elif fmt == 'compress':
            tar_path = Path(tmp) / '.nested-uncompressed.tar'
            try:
                _run_to_file(['uncompress', '-c', archive_path], tar_path)
                _extract_tar(str(tar_path), 'r:', tmp, budget)
            finally:
                tar_path.unlink(missing_ok=True)
        else:
            raise ValueError(f'unsupported archive format: {fmt}')
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _scan_dir(
    directory: str,
    virtual_prefix: str,
    depth: int,
    budget: dict[str, int],
) -> Iterator[Tuple[str, str]]:
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
            yield from _scan_dir(real, virtual, depth, budget)
            continue
        if not os.path.isfile(real):
            continue
        file_size = os.path.getsize(real)
        if file_size < _MIN_ELF_SIZE:
            continue
        try:
            with open(real, 'rb') as handle:
                magic = handle.read(4)
        except OSError:
            continue
        if _is_elf(magic):
            yield real, virtual
            continue
        fmt = _detect_format(real)
        if fmt and fmt != 'bff':
            try:
                with _extract_to_tmpdir(real, fmt, budget) as tmpdir:
                    yield from _scan_dir(tmpdir, virtual, depth + 1, budget)
            except Exception as exc:
                warnings.warn(f'Skipping archive {virtual}: {exc}', RuntimeWarning, stacklevel=2)


class NestedArchiveScanner:
    """Scan a directory or supported archive for ELF files recursively."""

    def __init__(self, path: str) -> None:
        self._path = path

    def scan(self) -> Iterator[Tuple[str, str]]:
        path = self._path
        budget = _new_budget()
        if os.path.isdir(path):
            yield from _scan_dir(path, os.path.basename(path), depth=0, budget=budget)
            return
        fmt = _detect_format(path)
        if fmt and fmt != 'bff':
            with _extract_to_tmpdir(path, fmt, budget) as tmpdir:
                yield from _scan_dir(tmpdir, os.path.basename(path), depth=1, budget=budget)

    @classmethod
    def scan_archive(cls, archive_path: str) -> Iterator[Tuple[str, str]]:
        return cls(archive_path).scan()

    @classmethod
    def collect_elfs(cls, path: str, max_elfs: Optional[int] = None) -> list:
        """Return up to ``max_elfs`` ``(virtual_path, elf_bytes)`` tuples."""
        results = []
        for real, virtual in cls(path).scan():
            try:
                if os.path.getsize(real) > _MAX_MEMBER_BYTES:
                    warnings.warn(f'Skipping oversized ELF {virtual}', RuntimeWarning, stacklevel=2)
                    continue
                data = Path(real).read_bytes()
            except OSError:
                continue
            results.append((virtual, data))
            if max_elfs is not None and len(results) >= max_elfs:
                break
        return results
