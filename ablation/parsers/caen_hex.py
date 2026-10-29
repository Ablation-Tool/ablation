"""Strict decoder for CAEN's ASCII-hex firmware update containers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_MAX_INPUT_BYTES = 16 * 1024 * 1024
_HEX_BYTES = frozenset(b"0123456789ABCDEF\n")
_PREFIX = b"#NuovoFirmware"
_MODEL_RE = re.compile(rb"[A-Za-z0-9_.-]+")


class CaenHexError(ValueError):
    """The input is not a valid CAEN ASCII-hex firmware container."""


@dataclass(frozen=True)
class CaenHexFirmware:
    """A validated CAEN firmware payload and its additive checksum."""

    board: str
    payload: bytes
    checksum: int
    computed_checksum: int

    @classmethod
    def from_path(
        cls, path: str | Path, *, max_input_bytes: int = _MAX_INPUT_BYTES
    ) -> "CaenHexFirmware":
        source = Path(path)
        _validate_limit(max_input_bytes)
        size = source.stat().st_size
        if size > max_input_bytes:
            raise CaenHexError(
                f"input size {size} exceeds {max_input_bytes} byte limit"
            )
        return cls.from_bytes(
            source.read_bytes(), max_input_bytes=max_input_bytes
        )

    @classmethod
    def from_bytes(
        cls, raw: bytes, *, max_input_bytes: int = _MAX_INPUT_BYTES
    ) -> "CaenHexFirmware":
        _validate_limit(max_input_bytes)
        data = bytes(raw)
        if len(data) > max_input_bytes:
            raise CaenHexError(
                f"input size {len(data)} exceeds {max_input_bytes} byte limit"
            )
        if b"\x04" not in data:
            raise CaenHexError("missing end-of-text marker")
        body, trailer = data.split(b"\x04", 1)
        trailer = trailer.strip(b"\n")
        if not body or any(value not in _HEX_BYTES for value in body):
            raise CaenHexError("body must contain uppercase hex digits and LF only")
        if len(trailer) != 8 or any(
            value not in b"0123456789ABCDEF" for value in trailer
        ):
            raise CaenHexError("trailer must contain eight uppercase hex digits")
        try:
            decoded = bytes.fromhex(body.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise CaenHexError("invalid hexadecimal payload") from exc
        if not decoded.startswith(_PREFIX):
            raise CaenHexError("missing #NuovoFirmware header")
        marker_end = decoded.find(b"#", 1)
        if marker_end < 0:
            raise CaenHexError("unterminated firmware header")
        model = decoded[len(_PREFIX):marker_end]
        if not _MODEL_RE.fullmatch(model):
            raise CaenHexError("invalid board identifier")
        payload = decoded[marker_end + 1:]
        if not payload:
            raise CaenHexError("container has no firmware payload")

        checksum = int(trailer, 16)
        computed = sum(value for value in body if value != 0x0A) & 0xFFFFFFFF
        if checksum != computed:
            raise CaenHexError(
                f"checksum mismatch: trailer {checksum:#010x}, computed {computed:#010x}"
            )
        return cls(model.decode("ascii"), payload, checksum, computed)

    def metadata(self) -> dict[str, object]:
        """Return JSON-compatible container metadata."""
        return {
            "format": "caen-ascii-hex",
            "board": self.board,
            "payload_bytes": len(self.payload),
            "checksum": f"0x{self.checksum:08X}",
            "checksum_verified": True,
        }


def _validate_limit(limit: int) -> None:
    if limit < 0:
        raise ValueError("max_input_bytes must be nonnegative")
