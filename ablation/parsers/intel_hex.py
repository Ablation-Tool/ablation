"""Strict Intel HEX ingestion with sparse and dense image representations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_DENSE_BYTES = 64 * 1024 * 1024


class IntelHexError(ValueError):
    """An Intel HEX validation error with optional source-line context."""

    def __init__(self, message: str, line_number: int | None = None) -> None:
        self.line_number = line_number
        prefix = f"line {line_number}: " if line_number is not None else ""
        super().__init__(prefix + message)


@dataclass(frozen=True)
class IntelHexImage:
    """A validated Intel HEX image."""

    data: Mapping[int, int]
    spans: tuple[tuple[int, int], ...]
    record_types: Mapping[int, int]
    start_address: tuple[str, int] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", MappingProxyType(dict(self.data)))
        object.__setattr__(
            self, "record_types", MappingProxyType(dict(self.record_types))
        )

    @classmethod
    def from_path(
        cls, path: str | Path, *, max_input_bytes: int = _MAX_INPUT_BYTES,
    ) -> "IntelHexImage":
        source = Path(path)
        if max_input_bytes < 0:
            raise ValueError("max_input_bytes must be nonnegative")
        size = source.stat().st_size
        if size > max_input_bytes:
            raise IntelHexError(
                f"input size {size} exceeds {max_input_bytes} byte limit"
            )
        return cls.from_bytes(
            source.read_bytes(), max_input_bytes=max_input_bytes
        )

    @classmethod
    def from_bytes(
        cls, hexdata: str | bytes, *, max_input_bytes: int = _MAX_INPUT_BYTES,
    ) -> "IntelHexImage":
        if max_input_bytes < 0:
            raise ValueError("max_input_bytes must be nonnegative")
        if isinstance(hexdata, str):
            try:
                raw_input = hexdata.encode("ascii")
            except UnicodeEncodeError as exc:
                raise IntelHexError("input is not ASCII") from exc
        else:
            raw_input = bytes(hexdata)
        if len(raw_input) > max_input_bytes:
            raise IntelHexError(
                f"input size {len(raw_input)} exceeds {max_input_bytes} byte limit"
            )
        try:
            text = raw_input.decode("ascii")
        except UnicodeDecodeError as exc:
            raise IntelHexError("input is not ASCII") from exc

        data: dict[int, int] = {}
        record_types: dict[int, int] = {}
        start_address: tuple[str, int] | None = None
        base = 0
        eof = False

        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            if eof:
                raise IntelHexError("content after EOF record", line_number)
            if not line.startswith(":"):
                raise IntelHexError("missing record marker", line_number)
            try:
                raw = bytes.fromhex(line[1:])
            except ValueError as exc:
                raise IntelHexError("invalid hexadecimal record", line_number) from exc
            if len(raw) < 5 or len(raw) != raw[0] + 5:
                raise IntelHexError("invalid record length", line_number)
            if sum(raw) & 0xFF:
                raise IntelHexError("checksum mismatch", line_number)

            count = raw[0]
            offset = int.from_bytes(raw[1:3], "big")
            record_type = raw[3]
            payload = raw[4:-1]
            expected_lengths = {1: 0, 2: 2, 3: 4, 4: 2, 5: 4}
            if record_type not in (0, *expected_lengths):
                raise IntelHexError(
                    f"unsupported record type {record_type:#x}", line_number
                )
            if record_type and count != expected_lengths[record_type]:
                raise IntelHexError(
                    f"invalid payload length for record type {record_type:#x}",
                    line_number,
                )
            if record_type and offset != 0:
                raise IntelHexError(
                    f"nonzero address for record type {record_type:#x}", line_number
                )
            record_types[record_type] = record_types.get(record_type, 0) + 1

            if record_type == 0:
                address = base + offset
                if address + count > 0x100000000:
                    raise IntelHexError("data address exceeds 32 bits", line_number)
                for index, value in enumerate(payload):
                    location = address + index
                    if location in data and data[location] != value:
                        raise IntelHexError(
                            f"conflicting overlap at {location:#x}", line_number
                        )
                    data[location] = value
            elif record_type == 1:
                eof = True
            elif record_type == 2:
                base = int.from_bytes(payload, "big") << 4
            elif record_type == 3:
                start_address = cls._merge_start_address(
                    start_address, ("segment", int.from_bytes(payload, "big")), line_number
                )
            elif record_type == 4:
                base = int.from_bytes(payload, "big") << 16
            elif record_type == 5:
                start_address = cls._merge_start_address(
                    start_address, ("linear", int.from_bytes(payload, "big")), line_number
                )

        if not eof:
            raise IntelHexError("missing EOF record")
        if not data:
            raise IntelHexError("image contains no data records")
        return cls(data, cls._compute_spans(data), record_types, start_address)

    @staticmethod
    def _merge_start_address(
        current: tuple[str, int] | None,
        new: tuple[str, int],
        line_number: int,
    ) -> tuple[str, int]:
        if current is not None and current != new:
            raise IntelHexError("conflicting start-address records", line_number)
        return new

    @staticmethod
    def _compute_spans(data: dict[int, int]) -> tuple[tuple[int, int], ...]:
        spans: list[tuple[int, int]] = []
        for address in sorted(data):
            if spans and address == spans[-1][1]:
                spans[-1] = (spans[-1][0], address + 1)
            else:
                spans.append((address, address + 1))
        return tuple(spans)

    def address_range(self) -> tuple[int, int]:
        """Return the half-open range covering all sparse data."""
        if not self.data:
            return (0, 0)
        return min(self.data), max(self.data) + 1

    def to_sparse(self) -> dict[int, int]:
        """Return a copy of the sparse address-to-byte mapping."""
        return dict(self.data)

    def to_bytes(
        self,
        fill: int = 0xFF,
        base: int | None = None,
        *,
        max_dense_bytes: int = _MAX_DENSE_BYTES,
    ) -> bytes:
        """Materialize a dense image with explicit gap fill and base."""
        if not 0 <= fill <= 0xFF:
            raise ValueError("fill must be a byte value")
        if max_dense_bytes < 0:
            raise ValueError("max_dense_bytes must be nonnegative")
        if not self.data:
            return b""
        low, high = self.address_range()
        dense_base = low if base is None else base
        if not 0 <= dense_base <= low:
            raise ValueError("base must be nonnegative and no greater than the first data address")
        size = high - dense_base
        if size > max_dense_bytes:
            raise IntelHexError(
                f"dense size {size} exceeds {max_dense_bytes} byte limit"
            )
        image = bytearray([fill]) * size
        for address, value in self.data.items():
            image[address - dense_base] = value
        return bytes(image)

    def metadata(self) -> dict:
        """Return JSON-compatible image metadata."""
        return {
            "data_bytes": len(self.data),
            "spans": [
                [f"0x{start:X}", f"0x{stop:X}", stop - start]
                for start, stop in self.spans
            ],
            "record_types": {
                str(record_type): count
                for record_type, count in sorted(self.record_types.items())
            },
            "start_address": (
                None if self.start_address is None else {
                    "type": self.start_address[0],
                    "value": self.start_address[1],
                }
            ),
        }
