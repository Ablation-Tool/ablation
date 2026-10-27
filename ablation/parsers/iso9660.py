"""Small ISO9660/Rock Ridge reader for firmware userlands."""
from __future__ import annotations

import mmap
import os
import posixpath
import struct
from dataclasses import dataclass
from pathlib import Path

SECTOR_SIZE = 2048


@dataclass(frozen=True)
class ISOEntry:
    path: str
    extents: tuple[tuple[int, int, int], ...]
    mode: int
    directory: bool
    symlink_target: str | None = None

    @property
    def size(self) -> int:
        return sum(extent[2] for extent in self.extents)

    @property
    def extent_key(self) -> tuple[int, int]:
        return self.extents[0][0], self.size


def _safe_parts(path: str) -> tuple[str, ...]:
    path = path.replace("\\", "/")
    if path.startswith("/") or "\x00" in path:
        raise ValueError(f"Unsafe ISO path: {path!r}")
    parts = tuple(part for part in path.split("/") if part not in ("", "."))
    if any(part == ".." for part in parts):
        raise ValueError(f"Unsafe ISO path: {path!r}")
    return parts


def _display_name(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")
    if ";" in text:
        text = text.rsplit(";", 1)[0]
    if text.endswith("."):
        text = text[:-1]
    return text


def _susp(data: bytes) -> dict[str, object]:
    result: dict[str, object] = {}
    names: list[bytes] = []
    links: list[tuple[str, bytes]] = []
    offset = 0
    while offset + 4 <= len(data):
        signature = data[offset:offset + 2]
        length = data[offset + 2]
        if length < 4 or offset + length > len(data):
            break
        payload = data[offset + 4:offset + length]
        if signature == b"NM" and payload:
            names.append(payload[1:])
        elif signature == b"PX" and len(payload) >= 8:
            result["mode"] = struct.unpack_from("<I", payload)[0]
        elif signature == b"SL" and payload:
            index = 1
            while index + 2 <= len(payload):
                flags, size = payload[index], payload[index + 1]
                index += 2
                if index + size > len(payload):
                    break
                component = payload[index:index + size]
                index += size
                if flags & 1:
                    if links:
                        links[-1] = (links[-1][0], links[-1][1] + component)
                    else:
                        links.append(("component", component))
                elif flags & 2:
                    links.append(("current", b"."))
                elif flags & 4:
                    links.append(("parent", b".."))
                elif flags & 8:
                    links.append(("root", b"/"))
                elif flags & 16:
                    links.append(("root", b"/"))
                else:
                    links.append(("component", component))
        offset += length
    if names:
        result["name"] = b"".join(names).decode("utf-8", errors="replace")
    if links:
        target = ""
        for kind, component in links:
            if kind == "root":
                target = "/"
            elif kind == "current":
                target += "./"
            elif kind == "parent":
                target += "../"
            else:
                target += component.decode("utf-8", errors="replace") + "/"
        result["symlink"] = target.rstrip("/") or "/"
    return result


class ISO9660:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._stream = open(self.path, "rb")
        self.data = mmap.mmap(self._stream.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            descriptor = self.data[16 * SECTOR_SIZE:17 * SECTOR_SIZE]
            if len(descriptor) != SECTOR_SIZE or descriptor[0] != 1 or descriptor[1:6] != b"CD001":
                raise ValueError("Not an ISO9660 primary volume descriptor")
            self._root_record = descriptor[156:156 + descriptor[156]]
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if getattr(self, "data", None) is not None:
            self.data.close()
            self.data = None
        if getattr(self, "_stream", None) is not None:
            self._stream.close()
            self._stream = None

    def __enter__(self) -> "ISO9660":
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def _record(self, data: bytes, offset: int) -> tuple[dict[str, object], int]:
        length = data[offset]
        if length == 0:
            return {}, (offset // SECTOR_SIZE + 1) * SECTOR_SIZE
        if offset + length > len(data) or length < 34:
            raise ValueError("Invalid ISO9660 directory record")
        record = data[offset:offset + length]
        name_length = record[32]
        if 33 + name_length > len(record):
            raise ValueError("Truncated ISO9660 filename")
        extent = struct.unpack_from("<I", record, 2)[0]
        size = struct.unpack_from("<I", record, 10)[0]
        flags = record[25]
        raw_name = record[33:33 + name_length]
        susp_offset = 33 + name_length + (1 if name_length % 2 == 0 else 0)
        susp = _susp(record[susp_offset:])
        name = susp.get("name") or _display_name(raw_name)
        return {
            "name": name,
            "extent": extent,
            "size": size,
            "directory": bool(flags & 2),
            "multi": bool(flags & 0x80),
            "mode": susp.get("mode", 0o40755 if flags & 2 else 0o100644),
            "symlink": susp.get("symlink"),
            "special": raw_name in (b"\x00", b"\x01"),
        }, offset + length

    def _directory_records(self, extents: tuple[tuple[int, int, int], ...]) -> list[dict[str, object]]:
        contents = self._read_extents(extents)
        records: list[dict[str, object]] = []
        offset = 0
        while offset < len(contents):
            record, next_offset = self._record(contents, offset)
            if next_offset <= offset:
                raise ValueError("Invalid ISO9660 directory progression")
            if record and not record["special"]:
                records.append(record)
            offset = next_offset
        return records

    def _read_extents(self, extents: tuple[tuple[int, int, int], ...]) -> bytes:
        result = bytearray()
        for extent, offset, size in extents:
            start = extent * SECTOR_SIZE + offset
            if start < 0 or start + size > len(self.data):
                raise ValueError("ISO9660 extent lies outside the image")
            result.extend(self.data[start:start + size])
        return bytes(result)

    def entries(self) -> list[ISOEntry]:
        root = self._record(self._root_record, 0)[0]
        output: list[ISOEntry] = []
        visited: set[tuple[int, int]] = set()

        def walk(extents: tuple[tuple[int, int, int], ...], prefix: str) -> None:
            key = (extents[0][0], sum(extent[2] for extent in extents))
            if key in visited:
                raise ValueError(f"ISO9660 directory cycle at {prefix!r}")
            visited.add(key)
            records = self._directory_records(extents)
            index = 0
            while index < len(records):
                record = records[index]
                name = str(record["name"])
                parts = _safe_parts(name)
                if not parts:
                    index += 1
                    continue
                path = posixpath.join(prefix, *parts) if prefix else posixpath.join(*parts)
                fragments = [(int(record["extent"]), 0, int(record["size"]))]
                directory = bool(record["directory"])
                while record["multi"] and index + 1 < len(records):
                    index += 1
                    record = records[index]
                    if str(record["name"]) != name or bool(record["directory"]) != directory:
                        raise ValueError(f"Invalid multi-extent file {path!r}")
                    fragments.append((int(record["extent"]), 0, int(record["size"])))
                entry = ISOEntry(
                    path=path,
                    extents=tuple(fragments),
                    mode=int(record["mode"]),
                    directory=directory,
                    symlink_target=record["symlink"] if isinstance(record["symlink"], str) else None,
                )
                output.append(entry)
                if directory:
                    walk(entry.extents, path)
                index += 1

        walk(((int(root["extent"]), 0, int(root["size"])),), "")
        return output

    def read_file(self, entry: ISOEntry) -> bytes:
        if entry.directory or entry.symlink_target is not None:
            raise ValueError(f"Not a regular ISO file: {entry.path}")
        return self._read_extents(entry.extents)

    def _safe_link(self, entry: ISOEntry) -> str:
        target = entry.symlink_target or ""
        if "\x00" in target:
            raise ValueError(f"Unsafe symlink target for {entry.path!r}")
        if target.startswith("/"):
            resolved = target.lstrip("/")
        else:
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(entry.path), target))
        parts = _safe_parts(resolved)
        return os.path.relpath(os.path.join(*parts) if parts else ".", posixpath.dirname(entry.path) or ".")

    def extract_all(self, output_dir: str | Path) -> list[ISOEntry]:
        root = Path(output_dir).resolve()
        root.mkdir(parents=True, exist_ok=True)
        entries = self.entries()
        effective: dict[str, ISOEntry] = {}
        for entry in entries:
            previous = effective.get(entry.path)
            if previous is not None and previous.directory and not entry.directory:
                continue
            effective[entry.path] = entry
        entries = list(effective.values())
        for entry in entries:
            if entry.directory:
                (root.joinpath(*_safe_parts(entry.path))).mkdir(parents=True, exist_ok=True)
        hardlinks: dict[tuple[int, int], Path] = {}
        for entry in entries:
            if entry.directory:
                continue
            destination = root.joinpath(*_safe_parts(entry.path))
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_symlink() or destination.is_file():
                destination.unlink()
            if entry.symlink_target is not None:
                destination.symlink_to(self._safe_link(entry))
                continue
            key = entry.extent_key
            if key in hardlinks:
                os.link(hardlinks[key], destination)
                continue
            temporary = destination.with_name(destination.name + ".tmp")
            with open(temporary, "wb") as stream:
                stream.write(self.read_file(entry))
            os.replace(temporary, destination)
            os.chmod(destination, entry.mode & 0o7777)
            hardlinks[key] = destination
        return entries
