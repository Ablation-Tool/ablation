"""CRC-checked, read-only JFFS2 filesystem parsing."""

from __future__ import annotations

import os
import stat
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

_NODE_HEADER = struct.Struct("<HHII")
_DIRENT = struct.Struct("<4IBB2x2I")
_INODE = struct.Struct("<3I2H7I2BH2I")
_MAGIC = 0x1985
_DIRENT_TYPE = 0xE001
_INODE_TYPE = 0xE002
_INODE_HEADER_SIZE = _NODE_HEADER.size + _INODE.size
_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_MAX_PATH_BYTES = 4096


class Jffs2Error(ValueError):
    """A malformed, unsupported, or incomplete JFFS2 image."""


@dataclass(frozen=True)
class Jffs2Entry:
    """One reconstructed filesystem entry."""

    path: str
    ino: int
    mode: int
    uid: int
    gid: int
    mtime: int
    data: bytes

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)

    @property
    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.mode)

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(frozen=True)
class Jffs2Image:
    """A validated filesystem reconstructed without mounting the image."""

    entries: Mapping[str, Jffs2Entry]
    node_count: int
    inode_count: int
    unparsed_bytes: int
    rejected_dirents: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", MappingProxyType(dict(self.entries)))

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        max_input_bytes: int = _MAX_INPUT_BYTES,
        max_file_bytes: int = _MAX_FILE_BYTES,
        max_output_bytes: int = _MAX_OUTPUT_BYTES,
    ) -> "Jffs2Image":
        source = Path(path)
        _validate_limits(max_input_bytes, max_file_bytes, max_output_bytes)
        size = source.stat().st_size
        if size > max_input_bytes:
            raise Jffs2Error(
                f"input size {size} exceeds {max_input_bytes} byte limit"
            )
        return cls.from_bytes(
            source.read_bytes(),
            max_input_bytes=max_input_bytes,
            max_file_bytes=max_file_bytes,
            max_output_bytes=max_output_bytes,
        )

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        max_input_bytes: int = _MAX_INPUT_BYTES,
        max_file_bytes: int = _MAX_FILE_BYTES,
        max_output_bytes: int = _MAX_OUTPUT_BYTES,
    ) -> "Jffs2Image":
        _validate_limits(max_input_bytes, max_file_bytes, max_output_bytes)
        data = bytes(raw)
        if len(data) > max_input_bytes:
            raise Jffs2Error(
                f"input size {len(data)} exceeds {max_input_bytes} byte limit"
            )
        nodes = _read_nodes(
            data, max_file_bytes=max_file_bytes, max_output_bytes=max_output_bytes
        )
        if not nodes.node_count:
            raise Jffs2Error("no valid JFFS2 nodes found")
        entries = _reconstruct(nodes)
        if "/" not in entries or not entries["/"].is_dir:
            raise Jffs2Error("filesystem has no root directory")
        return cls(
            entries, nodes.node_count, nodes.inode_count,
            nodes.unparsed_bytes, nodes.rejected_dirents,
        )

    def read_file(self, path: str) -> bytes:
        """Return a file or symlink's bytes; never follow the symlink."""
        try:
            entry = self.entries[path]
        except KeyError as exc:
            raise KeyError(f"JFFS2 path not found: {path}") from exc
        if entry.is_dir:
            raise IsADirectoryError(path)
        return entry.data

    def file_paths(self) -> tuple[str, ...]:
        """Return sorted non-directory paths."""
        return tuple(sorted(path for path, entry in self.entries.items() if not entry.is_dir))

    def metadata(self) -> dict[str, object]:
        """Return JSON-compatible filesystem statistics."""
        return {
            "format": "jffs2-le",
            "node_count": self.node_count,
            "inode_count": self.inode_count,
            "entries": len(self.entries),
            "files": len(self.file_paths()),
            "unparsed_bytes": self.unparsed_bytes,
            "rejected_dirents": self.rejected_dirents,
        }


@dataclass(frozen=True)
class _Chunk:
    version: int
    offset: int
    data: bytes


@dataclass
class _Nodes:
    node_count: int = 0
    inode_count: int = 0
    unparsed_bytes: int = 0
    rejected_dirents: int = 0
    infos: dict[int, tuple] | None = None
    chunks: dict[tuple[int, int], _Chunk] | None = None
    links: dict[tuple[int, str], tuple] | None = None


def _read_nodes(data: bytes, *, max_file_bytes: int, max_output_bytes: int) -> _Nodes:
    nodes = _Nodes(infos={}, chunks={}, links={})
    assert nodes.infos is not None
    assert nodes.chunks is not None
    assert nodes.links is not None
    position = 0
    expanded_total = 0
    while position + _NODE_HEADER.size <= len(data):
        if data[position:position + 4] in (b"\xff" * 4, b"\x00" * 4):
            position += 4
            continue
        magic, kind, length, expected_crc = _NODE_HEADER.unpack_from(data, position)
        if magic != _MAGIC:
            nodes.unparsed_bytes += 4
            position += 4
            continue
        if length < _NODE_HEADER.size or position + length > len(data):
            raise Jffs2Error(f"invalid node length at {position:#x}")
        if _crc(data[position:position + 8]) != expected_crc:
            raise Jffs2Error(f"node-header CRC mismatch at {position:#x}")
        nodes.node_count += 1

        if kind == _DIRENT_TYPE:
            if length < _NODE_HEADER.size + _DIRENT.size:
                raise Jffs2Error(f"truncated dirent at {position:#x}")
            (
                pino, version, ino, mctime, name_size, file_type,
                node_crc, name_crc,
            ) = _DIRENT.unpack_from(data, position + _NODE_HEADER.size)
            name_offset = position + _NODE_HEADER.size + _DIRENT.size
            if name_offset + name_size > position + length:
                raise Jffs2Error(f"truncated filename at {position:#x}")
            if _crc(data[position:position + 32]) != node_crc:
                raise Jffs2Error(f"dirent CRC mismatch at {position:#x}")
            name_bytes = data[name_offset:name_offset + name_size]
            if _crc(name_bytes) != name_crc:
                raise Jffs2Error(f"dirent-name CRC mismatch at {position:#x}")
            name = os.fsdecode(name_bytes)
            if name in ("", ".", "..") or "/" in name or "\x00" in name:
                nodes.rejected_dirents += 1
                position = _next_node(position, length)
                continue
            key = (pino, name)
            previous = nodes.links.get(key)
            if previous is not None and version < previous[0]:
                position = _next_node(position, length)
                continue
            if previous is not None and version == previous[0] and previous[1:] != (ino, mctime, file_type):
                raise Jffs2Error(f"conflicting dirent at {position:#x}")
            nodes.links[key] = (version, ino, mctime, file_type)
        elif kind == _INODE_TYPE:
            if length < _INODE_HEADER_SIZE:
                raise Jffs2Error(f"truncated inode at {position:#x}")
            fields = _INODE.unpack_from(data, position + _NODE_HEADER.size)
            (
                ino, version, mode, uid, gid, isize, atime, mtime, ctime,
                offset, csize, dsize, compression, user_compression, flags,
                data_crc, node_crc,
            ) = fields
            if _crc(data[position:position + 60]) != node_crc:
                raise Jffs2Error(f"inode CRC mismatch at {position:#x}")
            if isize > max_file_bytes or offset > isize or dsize > isize - offset:
                raise Jffs2Error(f"invalid file extent at {position:#x}")
            if position + _INODE_HEADER_SIZE + csize > position + length:
                raise Jffs2Error(f"truncated inode payload at {position:#x}")
            expanded_total += dsize
            if expanded_total > max_output_bytes:
                raise Jffs2Error("expanded filesystem exceeds output limit")
            payload_offset = position + _INODE_HEADER_SIZE
            payload = data[payload_offset:payload_offset + csize]
            plain = _decompress(payload, dsize, compression)
            if _crc(payload) != data_crc:
                raise Jffs2Error(f"inode-data CRC mismatch at {position:#x}")
            nodes.inode_count += 1
            previous = nodes.infos.get(ino)
            metadata = (mode, uid, gid, isize, mtime)
            if previous is not None and version == previous[0] and previous[1:] != metadata:
                raise Jffs2Error(f"conflicting inode metadata at {position:#x}")
            if previous is None or version >= previous[0]:
                nodes.infos[ino] = (version, *metadata)
            key = (ino, offset)
            old_chunk = nodes.chunks.get(key)
            if old_chunk is None or version > old_chunk.version:
                nodes.chunks[key] = _Chunk(version, offset, plain)
            elif version == old_chunk.version and plain != old_chunk.data:
                raise Jffs2Error(f"conflicting inode extent at {position:#x}")
        position = _next_node(position, length)
    nodes.unparsed_bytes += max(0, len(data) - position)
    return nodes


def _reconstruct(nodes: _Nodes) -> dict[str, Jffs2Entry]:
    assert nodes.infos is not None
    assert nodes.chunks is not None
    assert nodes.links is not None
    paths_by_ino: dict[int, list[str]] = {1: ["/"]}
    paths_by_link: dict[tuple[int, int, str], str] = {}
    children: dict[int, list[tuple[int, str]]] = {}
    for (parent, name), (_, ino, _, _) in nodes.links.items():
        children.setdefault(ino, []).append((parent, name))
    visiting: set[int] = set()

    def resolve(ino: int, parent: int, name: str, depth: int) -> str:
        key = (ino, parent, name)
        if key in paths_by_link:
            return paths_by_link[key]
        if ino in visiting:
            raise Jffs2Error("directory-parent cycle")
        if depth > 256:
            raise Jffs2Error("directory nesting exceeds 256 levels")
        visiting.add(ino)
        if parent == 1:
            path = "/" + name
        else:
            matches = children.get(parent, [])
            if len(matches) != 1:
                raise Jffs2Error(f"missing or ambiguous parent for inode {parent}")
            grandparent, parent_name = matches[0]
            parent_path = resolve(parent, grandparent, parent_name, depth + 1)
            path = parent_path + "/" + name if parent_path != "/" else name
        if len(os.fsencode(path)) > _MAX_PATH_BYTES:
            raise Jffs2Error("filesystem path exceeds 4096 bytes")
        paths_by_link[key] = path
        visiting.remove(ino)
        return path

    for parent, name in sorted(nodes.links):
        _, ino, _, _ = nodes.links[(parent, name)]
        if not ino or ino == 1:
            continue
        path = resolve(ino, parent, name, 0)
        if path not in paths_by_ino.setdefault(ino, []):
            paths_by_ino[ino].append(path)

    entries: dict[str, Jffs2Entry] = {}
    for ino, (version, mode, uid, gid, isize, mtime) in nodes.infos.items():
        paths = paths_by_ino.get(ino, [])
        if not paths:
            continue
        if stat.S_ISDIR(mode):
            content = b""
        else:
            content_array = bytearray(isize)
            chunks = sorted(
                (chunk for (chunk_ino, _), chunk in nodes.chunks.items() if chunk_ino == ino),
                key=lambda chunk: (chunk.offset, chunk.version),
            )
            for chunk in chunks:
                content_array[chunk.offset:chunk.offset + len(chunk.data)] = chunk.data
            content = bytes(content_array)
        for path in paths:
            entries[path] = Jffs2Entry(path, ino, mode, uid, gid, mtime, content)
    if 1 not in nodes.infos:
        entries["/"] = Jffs2Entry(
            "/", 1, stat.S_IFDIR | 0o755, 0, 0, 0, b"",
        )
    return entries


def _decompress(payload: bytes, expected_size: int, compression: int) -> bytes:
    if compression in (0, 4):
        plain = payload
    elif compression == 1:
        if any(payload):
            raise Jffs2Error("nonzero payload in zero-compressed inode")
        plain = bytes(expected_size)
    elif compression == 6:
        if not payload:
            if expected_size:
                raise Jffs2Error("missing compressed inode payload")
            return b""
        try:
            decoder = zlib.decompressobj()
            plain = decoder.decompress(payload, expected_size + 1)
        except zlib.error as exc:
            raise Jffs2Error("invalid zlib-compressed inode") from exc
        if decoder.unconsumed_tail or not decoder.eof or decoder.unused_data:
            raise Jffs2Error("incomplete or trailing zlib inode data")
    else:
        raise Jffs2Error(f"unsupported JFFS2 compression {compression}")
    if len(plain) != expected_size:
        raise Jffs2Error("inode data length does not match dsize")
    return plain


def _crc(data: bytes) -> int:
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def _next_node(position: int, length: int) -> int:
    return (position + length + 3) & ~3


def _validate_limits(input_limit: int, file_limit: int, output_limit: int) -> None:
    if min(input_limit, file_limit, output_limit) < 0:
        raise ValueError("input, file, and output limits must be nonnegative")
