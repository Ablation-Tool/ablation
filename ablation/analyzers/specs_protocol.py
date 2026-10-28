"""SPECS serial-frame codec and archived simulation-header parser."""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import islice
from typing import Iterable

MODES = {"i2c": 0, "jtag": 1, "parallel": 2, "register": 3}
_TRANSACTION = re.compile(r"1_[0-9A-Fa-f]{4}_([0-9A-Fa-f]{8})")
_MAX_FRAME_WORDS = 0x10000


def _limited_tuple(values: Iterable, name: str) -> tuple:
    result = tuple(islice(values, _MAX_FRAME_WORDS + 1))
    if len(result) > _MAX_FRAME_WORDS:
        raise ValueError(f"{name} exceeds {_MAX_FRAME_WORDS} word limit")
    return result


def _byte_tuple(values: Iterable[int], name: str) -> tuple[int, ...]:
    result = _limited_tuple(values, name)
    if any(not isinstance(value, int) or not 0 <= value <= 0xFF for value in result):
        raise ValueError(f"{name} contains a value outside the 8-bit range")
    return result


def header_checksum(header: Iterable[int]) -> int:
    """Return the SPECS four-bit header checksum."""
    values = _byte_tuple(header, "SPECS header")
    if len(values) != 4:
        raise ValueError("SPECS header must contain four bytes")
    checksum = 0
    for value in values[:3]:
        checksum ^= (value >> 4) ^ (value & 0x0F)
    return checksum ^ (values[3] >> 4)


def payload_checksum(payload: Iterable[int]) -> int:
    """Return the XOR checksum over payload bytes only."""
    checksum = 0
    for value in _byte_tuple(payload, "SPECS payload"):
        checksum ^= value
    return checksum


@dataclass(frozen=True)
class SpecsWord:
    """One transmitted byte and its final-payload-marker bit."""

    value: int
    last: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.value, int) or not 0 <= self.value <= 0xFF:
            raise ValueError("SPECS word value outside 8-bit range")


def encode_frame(header: Iterable[int], payload: Iterable[int]) -> list[SpecsWord]:
    """Encode three header bytes and a payload into SPECS words."""
    header_values = _byte_tuple(header, "SPECS header")
    if len(header_values) != 3:
        raise ValueError("encode_frame takes three header bytes")
    payload_values = _byte_tuple(payload, "SPECS payload")
    check = header_checksum((*header_values, 0))
    words = [SpecsWord(value) for value in (*header_values, check)]
    words.extend(SpecsWord(value) for value in payload_values)
    words.append(SpecsWord(payload_checksum(payload_values)))
    if payload_values:
        words[-2] = SpecsWord(payload_values[-1], True)
    return words


def decode_frame(words: Iterable[SpecsWord]) -> tuple[list[int], list[int]]:
    """Validate and decode a complete SPECS frame."""
    word_values = _limited_tuple(words, "SPECS frame")
    if len(word_values) < 5:
        raise ValueError("frame is too short")
    if any(not isinstance(word, SpecsWord) for word in word_values):
        raise TypeError("decode_frame expects SpecsWord instances")
    values = _byte_tuple((word.value for word in word_values), "SPECS frame")
    if header_checksum(values[:4]) != values[3] & 0x0F:
        raise ValueError("header checksum mismatch")
    if payload_checksum(values[4:-1]) != values[-1]:
        raise ValueError("payload checksum mismatch")
    expected_last = len(values) - 2 if len(values) > 5 else None
    for index, word in enumerate(word_values):
        if word.last != (index == expected_last):
            raise ValueError("last-data bit mismatch")
    return list(values[:3]), list(values[4:-1])


def first_header_byte(address: int, mode: str | int) -> int:
    """Construct the address/mode byte used by a SPECS frame."""
    if not isinstance(address, int) or not 0 <= address <= 0x3F:
        raise ValueError("SPECS slave address is six bits")
    mode_value = MODES.get(mode, mode) if isinstance(mode, str) else mode
    if mode_value not in range(4):
        raise ValueError("invalid SPECS mode")
    return (address << 2) | mode_value


def _read_count(value: int) -> int:
    if not isinstance(value, int) or not 0 <= value <= 0xFF:
        raise ValueError("read count outside 8-bit range")
    return value


def is_long_frame_count(read_count: int) -> bool:
    """Implement the RTL long-frame threshold, including the 128/129 boundary."""
    return _read_count(read_count) > 0x80


def reported_read_count(read_count: int) -> int:
    """Mask the long-frame flag from the externally reported count."""
    return _read_count(read_count) & 0x7F


@dataclass(frozen=True)
class SpecsSimulationHeader:
    """A three-byte header recovered from an archived transaction vector."""

    header: tuple[int, int, int]

    def __post_init__(self) -> None:
        values = _byte_tuple(self.header, "SPECS simulation header")
        if len(values) != 3:
            raise ValueError("SPECS simulation header must contain three bytes")
        object.__setattr__(self, "header", values)

    @property
    def read_count(self) -> int:
        return self.header[1]

    @property
    def long_frame(self) -> bool:
        return is_long_frame_count(self.read_count)

    @property
    def reported_count(self) -> int:
        return reported_read_count(self.read_count)

    @property
    def computed_header_checksum(self) -> int:
        return header_checksum((*self.header, 0))


def parse_simulation_headers(text: str) -> list[SpecsSimulationHeader]:
    """Recover headers following 0x76543210 markers in SPECS vector text."""
    if not isinstance(text, str):
        raise TypeError("simulation vector input must be text")
    without_comments = "\n".join(
        line.split("//", 1)[0] for line in text.splitlines()
    )
    words = [int(value, 16) for value in _TRANSACTION.findall(without_comments)]
    headers: list[SpecsSimulationHeader] = []
    for index, word in enumerate(words[:-1]):
        if word != 0x76543210:
            continue
        header_word = words[index + 1]
        headers.append(SpecsSimulationHeader((
            (header_word >> 16) & 0xFF,
            (header_word >> 8) & 0xFF,
            header_word & 0xFF,
        )))
    return headers
