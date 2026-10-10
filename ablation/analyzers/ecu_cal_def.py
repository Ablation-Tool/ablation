"""Shared dataclasses and protocol for ECU calibration definition parsers."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CalibrationAxis:
    """One axis (breakpoint array) for a calibration table."""
    address: Optional[int]          # file offset; None = DALINK / no address
    count: int                      # number of breakpoints
    element_bits: int               # bits per element: 8, 16, or 32
    little_endian: bool
    scale: float                    # physical = raw * scale + bias
    bias: float
    unit: str
    shared_from: Optional[str]      # name of the table this axis is shared from


@dataclass
class CalibrationTable:
    """One calibration object: scalar, 1-D curve, or 2-D map."""
    name: str
    description: str
    category: str
    table_type: str                 # "VALUE", "CURVE", or "MAP"
    address: int                    # file offset of the data block
    rows: int                       # row count (ny direction, y-axis length)
    cols: int                       # column count (nx direction, x-axis length)
    element_bits: int
    little_endian: bool
    scale: float
    bias: float
    unit: str
    x_axis: Optional[CalibrationAxis]
    y_axis: Optional[CalibrationAxis]
    relocated_address: Optional[int] = None   # set by fingerprint relocation
    source_file: str = ""

    @property
    def effective_address(self) -> int:
        """Return the relocated address when available, otherwise the default."""
        return self.relocated_address if self.relocated_address is not None else self.address

    def label_map(self) -> dict:
        """Return {file_offset: label_string} entries for BinaryContext injection."""
        result: dict = {self.effective_address: self.name}
        if self.x_axis and self.x_axis.address is not None:
            result[self.x_axis.address] = f"{self.name}.x_axis"
        if self.y_axis and self.y_axis.address is not None:
            result[self.y_axis.address] = f"{self.name}.y_axis"
        return result

    def read_data(self, rom: bytes) -> list:
        """
        Extract the raw data values from rom at effective_address.

        Returns a list of rows x cols integers (pre-scaling). Raises IndexError
        when the slice falls outside rom. Does not apply scaling.
        """
        addr = self.effective_address
        n = self.rows * self.cols
        elem_bytes = self.element_bits // 8
        end = addr + n * elem_bytes
        if end > len(rom):
            raise IndexError(
                f"{self.name}: address 0x{addr:X} + {n}*{elem_bytes} = 0x{end:X} "
                f"exceeds ROM size 0x{len(rom):X}"
            )
        fmt_char = {8: "B", 16: "H", 32: "I"}[self.element_bits]
        endian = "<" if self.little_endian else ">"
        raw = struct.unpack(f"{endian}{n}{fmt_char}", rom[addr:end])
        if self.rows == 1:
            return list(raw)
        return [list(raw[r * self.cols:(r + 1) * self.cols]) for r in range(self.rows)]


def eval_math_equation(equation: str, raw: float) -> float:
    """
    Evaluate a TunerPro MATH equation string against one raw value X.

    Supports: basic arithmetic, parentheses, and the variable X.
    Returns the raw value unchanged on parse failure.
    """
    try:
        # Replace X with the actual value
        safe = re.sub(r"\bX\b", str(float(raw)), equation)
        # Allow only digits, operators, parens, dots, e/E for scientific notation
        if not re.match(r"^[\d\s\+\-\*/\(\)\.\eE]+$", safe):
            return float(raw)
        return float(eval(safe))          # nosec: safe subset validated above
    except Exception:
        return float(raw)
