"""
AmiCramFSExtractor — pure-Python reader for AMI-modified CramFS firmware images.

AMI modifies standard CramFS for BMC firmware (SPX Redfish, ASPEED AST2xxx targets).
The standard CramFS magic (0x28cd3d45) is preserved, but the inode structure is
extended from 12 bytes to 16 bytes:

  Standard CramFS inode (12 bytes):
    [w0: mode(16)|uid(16)] [w1: size(24)|gid(8)] [w2: namelen(6)|offset(26)]

  AMI extended inode (16 bytes):
    [w0: mode(16)|uid(16)] [w1: size(24)|gid(8)] [w2: 0|namelen(6,@bits8-13)|flags]
    [w3: data_off (4-byte units from CramFS start)]

AMI changes:
  - namelen moved to bits[8:13] of w2 (standard: bits[0:5])
  - data offset moved from bits[6:31] of w2 to a separate 4th word (w3)
  - data_off × 4 = absolute byte offset from start of CramFS image

Data storage is UNCHANGED from standard CramFS:
  - Directories: raw uncompressed inode list (no count prefix)
  - Files: zlib-compressed 4 KB blocks with end-pointer table

Confirmed on: QTECH BMC G4DCL-UX-V3R29A-L01-C06087 (ASPEED AST2xxx, 36.5 MB rootfs).
"""
from __future__ import annotations

import os
import struct
import zlib
from pathlib import Path
from typing import Callable, Generator, List, Optional, Tuple


CRAMFS_MAGIC = 0x28cd3d45
PAGE_SIZE    = 4096
_ROOT_INODE_OFF = 0x40  # always at fixed offset in superblock

S_IFMT  = 0xF000
S_IFDIR = 0x4000
S_IFREG = 0x8000
S_IFLNK = 0xA000


class AmiCramFSEntry:
    """A single inode + name from an AMI CramFS directory."""

    __slots__ = ('name', 'mode', 'uid', 'gid', 'size', 'data_off')

    def __init__(self, name: str, mode: int, uid: int, gid: int,
                 size: int, data_off: int) -> None:
        self.name     = name
        self.mode     = mode
        self.uid      = uid
        self.gid      = gid
        self.size     = size
        self.data_off = data_off  # in 4-byte units

    @property
    def is_dir(self) -> bool:
        return (self.mode & S_IFMT) == S_IFDIR

    @property
    def is_reg(self) -> bool:
        return (self.mode & S_IFMT) == S_IFREG

    @property
    def is_lnk(self) -> bool:
        return (self.mode & S_IFMT) == S_IFLNK

    @property
    def byte_offset(self) -> int:
        return self.data_off * 4

    def __repr__(self) -> str:
        t = 'd' if self.is_dir else ('l' if self.is_lnk else '-')
        return f"AmiCramFSEntry({t} {self.name!r} size={self.size} off=0x{self.byte_offset:x})"


def _parse_inode(data: bytes, off: int) -> Tuple[int, int, int, int, int, int, int]:
    """Return (mode, uid, size, gid, namelen, data_off, next_off)."""
    w0, w1, w2, w3 = struct.unpack_from('<IIII', data, off)
    mode     = w0 & 0xFFFF
    uid      = (w0 >> 16) & 0xFFFF
    size     = w1 & 0xFFFFFF
    gid      = (w1 >> 24) & 0xFF
    namelen  = (w2 >> 8) & 0x3F   # bits[8:13]
    data_off = w3
    next_off = off + 16 + namelen * 4
    return mode, uid, size, gid, namelen, data_off, next_off


def _parse_entries(cramfs: bytes, byte_off: int, dir_size: int) -> List[AmiCramFSEntry]:
    """Parse all directory entries from a raw (uncompressed) directory data block."""
    entries = []
    off = byte_off
    end = byte_off + dir_size
    while off < end:
        if off + 16 > len(cramfs):
            break
        mode, uid, size, gid, namelen, data_off, next_off = _parse_inode(cramfs, off)
        if namelen == 0:
            break
        if next_off > len(cramfs):  # malformed: name field extends past image
            break
        name_raw = cramfs[off + 16: off + 16 + namelen * 4]
        name     = name_raw.rstrip(b'\x00').decode('ascii', errors='replace')
        entries.append(AmiCramFSEntry(name, mode, uid, gid, size, data_off))
        off = next_off
    return entries


def _decompress_file(cramfs: bytes, data_off: int, size: int) -> bytes:
    """Decompress a regular file from the CramFS block pointer table."""
    if size == 0:
        return b''
    nblocks  = (size + PAGE_SIZE - 1) // PAGE_SIZE
    ptr_base = data_off * 4
    if ptr_base + nblocks * 4 > len(cramfs):
        return b''
    ptrs     = list(struct.unpack_from(f'<{nblocks}I', cramfs, ptr_base))
    result   = bytearray()
    for i in range(nblocks):
        blk_start = ptr_base + nblocks * 4 if i == 0 else ptrs[i - 1]
        blk_end   = ptrs[i]
        if blk_end <= blk_start:  # malformed pointer table
            break
        compressed = cramfs[blk_start:blk_end]
        try:
            chunk = zlib.decompress(compressed)
        except zlib.error:
            # AMI occasionally prefixes a block with raw data (e.g. a pre-relocated
            # GOT table) before the actual zlib stream.  Scan for the first valid
            # zlib CMF byte and retry from there.
            chunk = None
            for scan in range(len(compressed) - 1):
                if compressed[scan] == 0x78 and compressed[scan + 1] in (0x01, 0x5e, 0x9c, 0xda):
                    try:
                        chunk = zlib.decompress(compressed[scan:])
                        break
                    except zlib.error:
                        pass
            if chunk is None:
                chunk = compressed  # genuinely uncompressed block
        result.extend(chunk)
    return bytes(result[:size])


class AmiCramFSExtractor:
    """
    Extract files and directories from an AMI-modified CramFS image.

    Usage::

        ext = AmiCramFSExtractor.from_bytes(cramfs_bytes)
        for path in ext.list_files():
            print(path)
        data = ext.extract_file('/usr/local/bin/spx_restservice')
        ext.extract_all('/tmp/bmc_root/')

    Or with a raw firmware image::

        ext = AmiCramFSExtractor.from_image('/path/to/bmc.ima', offset=0x160000)
    """

    def __init__(self, cramfs: bytes) -> None:
        magic = struct.unpack_from('<I', cramfs, 0)[0]
        if magic != CRAMFS_MAGIC:
            raise ValueError(f"Not a CramFS image (magic=0x{magic:08x})")
        self._cramfs = cramfs
        # Root inode at fixed offset 0x40
        _, w1, _, root_doff = struct.unpack_from('<IIII', cramfs, _ROOT_INODE_OFF)
        self._root_size    = w1 & 0xFFFFFF
        self._root_data_va = root_doff * 4

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_bytes(cls, data: bytes) -> 'AmiCramFSExtractor':
        return cls(data)

    @classmethod
    def from_path(cls, path: str) -> 'AmiCramFSExtractor':
        file_size = os.path.getsize(path)
        if file_size > cls._MAX_IMAGE_BYTES:
            raise ValueError(
                f'{path}: file size {file_size} exceeds {cls._MAX_IMAGE_BYTES} byte limit'
            )
        with open(path, 'rb') as f:
            return cls(f.read())

    _MAX_IMAGE_BYTES = 256 * 1024 * 1024  # 256 MB guard against malformed total_size

    @classmethod
    def from_image(cls, image_path: str, offset: int) -> 'AmiCramFSExtractor':
        """Extract a CramFS partition from inside a larger firmware image."""
        file_size = os.path.getsize(image_path)
        with open(image_path, 'rb') as f:
            f.seek(offset)
            header = f.read(8)
            magic, total_size = struct.unpack_from('<II', header, 0)
            if magic != CRAMFS_MAGIC:
                raise ValueError(f"No CramFS at offset 0x{offset:x} (magic=0x{magic:08x})")
            if total_size > cls._MAX_IMAGE_BYTES:
                raise ValueError(
                    f"CramFS total_size={total_size} exceeds {cls._MAX_IMAGE_BYTES} byte limit"
                )
            if offset + total_size > file_size:
                raise ValueError(
                    f"CramFS total_size={total_size} extends past image "
                    f"(offset=0x{offset:x}, file_size={file_size})"
                )
            f.seek(offset)
            return cls(f.read(total_size))

    # ── Public API ────────────────────────────────────────────────────────────

    def list_files(self) -> Generator[str, None, None]:
        """Yield all file/symlink paths in the image (relative, no leading /)."""
        yield from self._walk_paths(self._root_data_va, self._root_size, '')

    def list_entries(self, dir_path: str = '') -> List[AmiCramFSEntry]:
        """List entries of a single directory."""
        byte_off, size = self._resolve_dir(dir_path.strip('/'))
        return _parse_entries(self._cramfs, byte_off, size)

    def extract_file(self, path: str) -> bytes:
        """
        Return the decompressed contents of a regular file or symlink target.
        Raises FileNotFoundError if the path doesn't exist.
        """
        entry = self._lookup(path.strip('/'))
        if entry is None:
            raise FileNotFoundError(path)
        return _decompress_file(self._cramfs, entry.data_off, entry.size)

    def extract_all(self, out_dir: str,
                    progress: Optional[Callable[[str], None]] = None) -> None:
        """
        Extract the entire CramFS to out_dir, recreating the directory tree.
        Symlinks are created as real symlinks. Files are decompressed.
        progress(path) is called for each file extracted if provided.
        """
        self._walk_extract(self._root_data_va, self._root_size, '', out_dir, progress)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _walk_paths(self, byte_off: int, dir_size: int,
                    prefix: str) -> Generator[str, None, None]:
        for entry in _parse_entries(self._cramfs, byte_off, dir_size):
            rel = f"{prefix}/{entry.name}" if prefix else entry.name
            if entry.is_dir:
                if entry.size > 0:
                    yield from self._walk_paths(entry.byte_offset, entry.size, rel)
            else:
                yield rel

    def _walk_extract(self, byte_off: int, dir_size: int,
                      rel_dir: str, out_dir: str,
                      progress: Optional[Callable[[str], None]]) -> None:
        os.makedirs(os.path.join(out_dir, rel_dir), exist_ok=True)
        for entry in _parse_entries(self._cramfs, byte_off, dir_size):
            child_rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            child_abs = os.path.join(out_dir, child_rel)
            if entry.is_dir:
                if entry.size > 0:
                    self._walk_extract(entry.byte_offset, entry.size,
                                       child_rel, out_dir, progress)
                else:
                    os.makedirs(child_abs, exist_ok=True)
            elif entry.is_lnk:
                if '/' in entry.name or entry.name in ('..', '.'):
                    continue  # skip unsafe filename
                target_raw = _decompress_file(self._cramfs, entry.data_off, entry.size)
                target_str = target_raw.decode('ascii', errors='replace').rstrip('\x00')
                # Resolve symlink target relative to its parent dir and verify it
                # stays inside out_dir (prevents ../../etc/passwd-style escapes)
                link_parent = os.path.dirname(child_abs)
                resolved = os.path.realpath(os.path.join(link_parent, target_str))
                real_out = os.path.realpath(out_dir)
                if not resolved.startswith(real_out + os.sep) and resolved != real_out:
                    if progress:
                        progress(f'SKIP unsafe symlink {child_rel} -> {target_str}')
                    continue
                try:
                    os.symlink(target_str, child_abs)
                except FileExistsError:
                    pass
                if progress:
                    progress(child_rel)
            elif entry.is_reg:
                if '/' in entry.name or entry.name in ('..', '.'):
                    continue  # skip unsafe filename
                file_data = _decompress_file(self._cramfs, entry.data_off, entry.size)
                with open(child_abs, 'wb') as f:
                    f.write(file_data)
                os.chmod(child_abs, entry.mode & 0o777)
                if progress:
                    progress(child_rel)

    def _resolve_dir(self, path: str) -> Tuple[int, int]:
        """Return (byte_offset, size) for a directory path, or root if path=''."""
        if not path:
            return self._root_data_va, self._root_size
        parts   = path.split('/')
        cur_off = self._root_data_va
        cur_sz  = self._root_size
        for part in parts:
            entries = _parse_entries(self._cramfs, cur_off, cur_sz)
            hit = next((e for e in entries if e.name == part), None)
            if hit is None or not hit.is_dir:
                raise FileNotFoundError(f"Directory not found: {path!r}")
            cur_off = hit.byte_offset
            cur_sz  = hit.size
        return cur_off, cur_sz

    def _lookup(self, path: str) -> Optional[AmiCramFSEntry]:
        """Look up an entry by path. Returns None if not found."""
        parts   = path.split('/')
        cur_off = self._root_data_va
        cur_sz  = self._root_size
        for i, part in enumerate(parts):
            entries = _parse_entries(self._cramfs, cur_off, cur_sz)
            hit = next((e for e in entries if e.name == part), None)
            if hit is None:
                return None
            if i == len(parts) - 1:
                return hit
            if not hit.is_dir:
                return None
            cur_off = hit.byte_offset
            cur_sz  = hit.size
        return None
