"""Strict decoder for Xilinx ASCII NPI hexadecimal RNPI and RCDO images."""

from __future__ import annotations

import io
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass(frozen=True)
class NpiHexMetadata:
    created_by: str
    design_name: str
    architecture: str
    part: str
    date: str
    bits: int

    @property
    def byte_count(self) -> int:
        return self.bits // 8


class XilinxNpiHex:
    MAGIC = "Xilinx ASCII NPI Deviceimage"
    MAX_TEXT_BYTES = 128 * 1024 * 1024
    MAX_DECODED_BYTES = 128 * 1024 * 1024
    MAX_LINE_BYTES = 4096

    def __init__(self, data: bytes, metadata: NpiHexMetadata, label: str = "") -> None:
        self._data = data
        self.metadata = metadata
        self.label = label

    @classmethod
    def from_path(cls, path: str) -> "XilinxNpiHex":
        source = Path(path)
        if source.stat().st_size > cls.MAX_TEXT_BYTES:
            raise ValueError(f"NPI text exceeds {cls.MAX_TEXT_BYTES} bytes: {source}")
        with source.open("rb") as stream:
            return cls._parse(stream, source.name)

    @classmethod
    def from_bytes(cls, data: bytes, label: str = "<bytes>") -> "XilinxNpiHex":
        if len(data) > cls.MAX_TEXT_BYTES:
            raise ValueError(f"NPI text exceeds {cls.MAX_TEXT_BYTES} bytes")
        return cls._parse(io.BytesIO(data), label)

    @classmethod
    def _parse(cls, stream: BinaryIO, label: str) -> "XilinxNpiHex":
        header: list[str] = []
        output = bytearray()
        expected_words = 0
        word_count = 0
        total_bytes = 0
        for line_number, raw_line in enumerate(stream, 1):
            total_bytes += len(raw_line)
            if total_bytes > cls.MAX_TEXT_BYTES:
                raise ValueError(f"NPI text exceeds {cls.MAX_TEXT_BYTES} bytes")
            if len(raw_line) > cls.MAX_LINE_BYTES:
                raise ValueError(f"NPI line {line_number} exceeds {cls.MAX_LINE_BYTES} bytes")
            try:
                line = raw_line.strip().decode("ascii")
            except UnicodeDecodeError as error:
                raise ValueError(f"NPI line {line_number} is not ASCII") from error
            if line_number == 1:
                if line != cls.MAGIC:
                    raise ValueError("missing Xilinx ASCII NPI Deviceimage header")
                header.append(line)
                continue
            if line_number <= 7:
                header.append(line)
                if line_number == 7:
                    metadata = cls._parse_metadata(header)
                    if metadata.bits <= 0 or metadata.bits % 32:
                        raise ValueError("NPI bit count must be a positive multiple of 32")
                    expected_words = metadata.bits // 32
                    if metadata.byte_count > cls.MAX_DECODED_BYTES:
                        raise ValueError(f"NPI payload exceeds {cls.MAX_DECODED_BYTES} bytes")
                    output = bytearray(metadata.byte_count)
                continue
            if word_count >= expected_words:
                raise ValueError(f"NPI has more words than declared at line {line_number}")
            if re.fullmatch(r"[0-9A-Fa-f]{8}", line) is None:
                raise ValueError(f"invalid NPI word at line {line_number}")
            struct.pack_into("<I", output, word_count * 4, int(line, 16))
            word_count += 1
        if len(header) < 7:
            raise ValueError("truncated NPI metadata header")
        if word_count != expected_words:
            raise ValueError(f"NPI word count mismatch: declared {expected_words}, found {word_count}")
        return cls(bytes(output), metadata, label)

    @staticmethod
    def _parse_metadata(header: list[str]) -> NpiHexMetadata:
        fields = []
        for line_number, (line, label) in enumerate(
                zip(header[1:], ("Created by", "Design name", "Architecture", "Part", "Date", "Bits")), 2):
            prefix = "Created by " if label == "Created by" else f"{label}:"
            if not line.startswith(prefix):
                raise ValueError(f"invalid NPI metadata at line {line_number}: expected {label}")
            value = line[len(prefix):].strip()
            if not value:
                raise ValueError(f"empty NPI metadata at line {line_number}: {label}")
            fields.append(value)
        try:
            bits = int(fields[-1], 10)
        except ValueError as error:
            raise ValueError("invalid NPI bit count") from error
        return NpiHexMetadata(*fields[:-1], bits)

    @property
    def word_count(self) -> int:
        return len(self._data) // 4

    def decode(self) -> bytes:
        return self._data

    def to_versal_pdi(self):
        from .versal_pdi import VersalPdi
        return VersalPdi.from_bytes(self._data, self.label)
