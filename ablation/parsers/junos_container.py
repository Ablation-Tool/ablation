"""Decode Juniper's block-compressed ISO9660 containers."""
from __future__ import annotations

import argparse
import json
import mmap
import os
import struct
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

BLOCK_SIZE = 65536
COMPOSITE_MAGIC = b"\x55\xaa\x06\x43"


@dataclass(frozen=True)
class JunosISOInfo:
    base: int
    block_count: int
    uncompressed_size: int
    composite: bool


def _parse_info(data: mmap.mmap, base: int, composite: bool) -> JunosISOInfo:
    if base < 0 or base + 16 > len(data):
        raise ValueError("Truncated Junos compressed-ISO header")
    block_count, uncompressed_size = struct.unpack_from(">II", data, base)
    table_end = base + 8 + block_count * 8
    if block_count == 0 or table_end > len(data):
        raise ValueError("Invalid Junos compressed-ISO block table")
    if uncompressed_size == 0 or uncompressed_size > block_count * BLOCK_SIZE:
        raise ValueError("Invalid Junos compressed-ISO output size")
    return JunosISOInfo(base, block_count, uncompressed_size, composite)


def _locate(data: mmap.mmap) -> JunosISOInfo:
    magic_offset = data.find(COMPOSITE_MAGIC)
    if magic_offset >= 0 and magic_offset + 16 <= len(data):
        self_offset = struct.unpack_from(">I", data, magic_offset + 4)[0]
        if self_offset == magic_offset:
            return _parse_info(data, magic_offset + 8, True)
    return _parse_info(data, 0, False)


def probe(path: str | Path) -> JunosISOInfo:
    if Path(path).stat().st_size == 0:
        raise ValueError("Empty Junos compressed-ISO input")
    with open(path, "rb") as stream:
        data = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            return _locate(data)
        finally:
            data.close()


def decompress(path: str | Path, output_path: str | Path) -> JunosISOInfo:
    if Path(path).stat().st_size == 0:
        raise ValueError("Empty Junos compressed-ISO input")
    output = Path(output_path)
    temporary = output.with_name(output.name + ".tmp")
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "rb") as stream:
        data = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            info = _locate(data)
            written = 0
            with open(temporary, "wb") as out:
                for index in range(info.block_count):
                    offset, size = struct.unpack_from(">II", data, info.base + 8 + index * 8)
                    start = info.base + offset
                    if start < 0 or size == 0 or start + size > len(data):
                        raise ValueError(f"Invalid compressed block {index}: offset={offset:#x}, size={size:#x}")
                    block = data[start:start + size]
                    if size != BLOCK_SIZE:
                        try:
                            block = zlib.decompress(block, -15)
                        except zlib.error as exc:
                            raise ValueError(f"Cannot decompress block {index}: {exc}") from exc
                    if len(block) > BLOCK_SIZE:
                        raise ValueError(f"Block {index} expands beyond {BLOCK_SIZE} bytes")
                    out.write(block)
                    written += len(block)
                if written < info.uncompressed_size:
                    raise ValueError(
                        f"Expanded data is shorter than declared ISO size: {written} < {info.uncompressed_size}"
                    )
                out.truncate(info.uncompressed_size)
            os.replace(temporary, output)
            return info
        finally:
            data.close()
            if temporary.exists():
                temporary.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()
    info = decompress(args.input, args.output)
    print(json.dumps({"output": args.output, **asdict(info)}, indent=2))


if __name__ == "__main__":
    main()
