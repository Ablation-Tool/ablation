"""Bounded bFLT v4 executable parsing for flat embedded firmware."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

_HEADER_SIZE = 64
_HEADER = struct.Struct(">4s15I")
_FLAG_RAM = 0x01
_FLAG_ROM = 0x02
_FLAG_GOTPIC = 0x04
_FLAG_GZIP = 0x08
_FLAG_GZIP_EXEC = 0x10
_KNOWN_FLAGS = _FLAG_RAM | _FLAG_ROM | _FLAG_GOTPIC | _FLAG_GZIP | _FLAG_GZIP_EXEC
_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_MEMORY_BYTES = 64 * 1024 * 1024


class BfltError(ValueError):
    """A malformed or unsupported bFLT executable."""


@dataclass(frozen=True)
class BfltImage:
    """A bFLT v4 header and its address-indexed flat memory image."""

    entry: int
    data_start: int
    data_end: int
    bss_end: int
    stack_size: int
    reloc_start: int
    reloc_count: int
    flags: int
    build_date: int
    memory_image: bytes
    relocations: bytes
    file_size: int
    trailing_bytes: int

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        max_input_bytes: int = _MAX_INPUT_BYTES,
        max_memory_bytes: int = _MAX_MEMORY_BYTES,
    ) -> "BfltImage":
        source = Path(path)
        _validate_limits(max_input_bytes, max_memory_bytes)
        size = source.stat().st_size
        if size > max_input_bytes:
            raise BfltError(
                f"input size {size} exceeds {max_input_bytes} byte limit"
            )
        return cls.from_bytes(
            source.read_bytes(),
            max_input_bytes=max_input_bytes,
            max_memory_bytes=max_memory_bytes,
        )

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        max_input_bytes: int = _MAX_INPUT_BYTES,
        max_memory_bytes: int = _MAX_MEMORY_BYTES,
    ) -> "BfltImage":
        _validate_limits(max_input_bytes, max_memory_bytes)
        data = bytes(raw)
        if len(data) > max_input_bytes:
            raise BfltError(
                f"input size {len(data)} exceeds {max_input_bytes} byte limit"
            )
        if len(data) < _HEADER_SIZE:
            raise BfltError("file is shorter than the bFLT header")
        fields = _HEADER.unpack_from(data)
        if fields[0] != b"bFLT":
            raise BfltError("invalid bFLT magic")
        (
            revision, entry, data_start, data_end, bss_end, stack_size,
            reloc_start, reloc_count, flags, build_date, *reserved,
        ) = fields[1:]
        if revision != 4:
            raise BfltError(f"unsupported bFLT revision {revision}")
        if any(reserved):
            raise BfltError("reserved bFLT header fields are nonzero")
        if flags & ~_KNOWN_FLAGS:
            raise BfltError(f"unsupported bFLT flags {flags:#x}")
        if flags & _FLAG_GZIP_EXEC:
            raise BfltError("gzip-exec bFLT images are not supported")
        if flags & (_FLAG_ROM | _FLAG_GOTPIC):
            raise BfltError("ROM and GOT-PIC bFLT layouts are not supported")
        if not _HEADER_SIZE <= entry < data_start:
            raise BfltError("entry point lies outside the text segment")
        if not data_start <= data_end <= bss_end:
            raise BfltError("invalid data/BSS address ordering")
        if bss_end > max_memory_bytes:
            raise BfltError(
                f"memory size {bss_end} exceeds {max_memory_bytes} byte limit"
            )
        minimum_reloc = _HEADER_SIZE if flags & _FLAG_GZIP else data_end
        if reloc_start < minimum_reloc or reloc_start > len(data):
            raise BfltError("relocation table lies outside the file")
        reloc_end = reloc_start + reloc_count * 4
        if reloc_end > len(data):
            raise BfltError("truncated relocation table")

        if flags & _FLAG_GZIP:
            memory = data[:_HEADER_SIZE] + _decompress_exact(
                data[_HEADER_SIZE:reloc_start], data_end - _HEADER_SIZE
            )
        else:
            if data_end > len(data):
                raise BfltError("flat memory image extends beyond the file")
            memory = data[:data_end]
        if len(memory) != data_end:
            raise BfltError("flat memory image size does not match data_end")
        return cls(
            entry=entry,
            data_start=data_start,
            data_end=data_end,
            bss_end=bss_end,
            stack_size=stack_size,
            reloc_start=reloc_start,
            reloc_count=reloc_count,
            flags=flags,
            build_date=build_date,
            memory_image=memory,
            relocations=data[reloc_start:reloc_end],
            file_size=len(data),
            trailing_bytes=len(data) - reloc_end,
        )

    @property
    def text_bytes(self) -> bytes:
        """Return text bytes, excluding the 64-byte file header."""
        return self.memory_image[_HEADER_SIZE:self.data_start]

    @property
    def data_bytes(self) -> bytes:
        """Return initialized data, without the BSS or relocation table."""
        return self.memory_image[self.data_start:self.data_end]

    @property
    def compressed(self) -> bool:
        return bool(self.flags & _FLAG_GZIP)

    def read_memory(self, address: int, size: int) -> bytes:
        """Read from the flat address space, whose first byte is the header."""
        if size < 0:
            raise ValueError("size must be nonnegative")
        if address < 0 or address + size > len(self.memory_image):
            raise BfltError("memory read lies outside initialized data")
        return self.memory_image[address:address + size]

    def metadata(self) -> dict[str, object]:
        """Return JSON-compatible layout information."""
        return {
            "format": "bflt",
            "revision": 4,
            "entry": self.entry,
            "text_range": [_HEADER_SIZE, self.data_start],
            "data_range": [self.data_start, self.data_end],
            "bss_end": self.bss_end,
            "stack_size": self.stack_size,
            "relocation_count": self.reloc_count,
            "flags": self.flags,
            "compressed": self.compressed,
            "file_size": self.file_size,
            "trailing_bytes": self.trailing_bytes,
        }


def _decompress_exact(data: bytes, expected_size: int) -> bytes:
    if expected_size < 0:
        raise BfltError("invalid uncompressed image size")
    try:
        decoder = zlib.decompressobj(wbits=31)
        result = decoder.decompress(data, expected_size + 1)
    except zlib.error as exc:
        raise BfltError("invalid gzip-compressed bFLT payload") from exc
    if len(result) != expected_size or decoder.unconsumed_tail:
        raise BfltError("uncompressed bFLT size does not match data_end")
    if not decoder.eof or decoder.unused_data:
        raise BfltError("incomplete gzip stream or trailing compressed data")
    return result


def _validate_limits(input_limit: int, memory_limit: int) -> None:
    if input_limit < 0 or memory_limit < 0:
        raise ValueError("input and memory limits must be nonnegative")
