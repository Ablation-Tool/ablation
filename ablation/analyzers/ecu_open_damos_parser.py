"""
open_damos.json calibration definition parser for Bosch ECU ROM analysis.

Parses the open_damos.json format used by the open-car-reprog project (Poisson48)
and performs fingerprint relocation: each axis carries a numeric fingerprint (the
expected physical breakpoint values) so the parser can find the table in any ROM
variant of the ECU family, not just the baseline firmware used to build the file.

Fingerprint relocation is the primary reason to use this parser over a fixed-address
tool. The same JSON works for every PSA/Bosch EDC16C34 firmware variant regardless
of minor address differences between software generations.

Usage::

    from ablation.analyzers.ecu_open_damos_parser import EcuOpenDamosParser

    parser = EcuOpenDamosParser.from_file("open_damos.json")
    rom = open("9663944680.bin", "rb").read()

    # Locate all tables in this specific ROM variant
    located = parser.locate_in_rom(rom)    # {name: file_offset}

    # Build label map from located addresses
    labels = parser.label_map(rom)         # {file_offset: label}

    for offset, name in labels.items():
        ctx.set_name(offset, name, source="open_damos")
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ablation.analyzers.ecu_cal_def import CalibrationAxis, CalibrationTable


# ------------------------------------------------------------------ #
# Record layout registry                                              #
# ------------------------------------------------------------------ #

@dataclass
class RecordLayout:
    """Describes the byte-level layout of one table type."""
    record_type: str            # "MAP", "CURVE", or "VALUE"
    header_bytes: int           # bytes before axis data encoding {nx, ny}
    header_big_endian: bool     # header word byte order
    axis_big_endian: bool       # axis array byte order
    axis_signed: bool           # axis elements are signed
    data_big_endian: bool       # data array byte order
    data_signed: bool           # data elements are signed


_TYPE_MAP = {
    "UWORD_BE": (False, True, 2),   # (signed, big_endian, bytes)
    "SWORD_BE": (True,  True, 2),
    "UWORD_LE": (False, False, 2),
    "SWORD_LE": (True,  False, 2),
    "UBYTE":    (False, True, 1),
    "SBYTE":    (True,  True, 1),
}


def _parse_record_layout(name: str, d: dict) -> RecordLayout:
    axis_type = d.get("axisDataType", "SWORD_BE")
    data_type = d.get("dataType", "SWORD_BE")
    hdr_type  = d.get("headerType", "UWORD_BE")

    axis_signed, axis_be, _ = _TYPE_MAP.get(axis_type, (True, True, 2))
    data_signed, data_be, _ = _TYPE_MAP.get(data_type, (True, True, 2))
    _,           hdr_be,  _ = _TYPE_MAP.get(hdr_type,  (False, True, 2))

    return RecordLayout(
        record_type=d.get("type", "MAP"),
        header_bytes=d.get("headerBytes", 0),
        header_big_endian=hdr_be,
        axis_big_endian=axis_be,
        axis_signed=axis_signed,
        data_big_endian=data_be,
        data_signed=data_signed,
    )


# ------------------------------------------------------------------ #
# Parser                                                              #
# ------------------------------------------------------------------ #

class EcuOpenDamosParser:
    """
    Parse an open_damos.json file and relocate tables in a target ROM.

    Every characteristic in open_damos.json carries a ``fingerprint`` array
    on each axis: the physical values (RPM, load percentage, etc.) encoded as
    a Python list of numbers. ``locate_in_rom`` converts each fingerprint back
    to the raw integer encoding the ECU uses, then byte-searches the ROM for
    that exact sequence. The first hit whose header bytes match the expected
    table dimensions is accepted as the relocated address.

    When multiple hits exist for the same fingerprint (several tables share the
    same axis array), the parser returns all candidates and picks the one whose
    header dimensions match ``dims``.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        with open(path) as f:
            self._doc = json.load(f)
        self._layouts: dict[str, RecordLayout] = {
            k: _parse_record_layout(k, v)
            for k, v in self._doc.get("recordLayouts", {}).items()
        }
        self._tables: list[CalibrationTable] = self._build_tables()

    @classmethod
    def from_file(cls, path: str | Path) -> "EcuOpenDamosParser":
        return cls(path)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def calibration_tables(self) -> list[CalibrationTable]:
        return list(self._tables)

    def locate_in_rom(self, rom: bytes) -> dict[str, int]:
        """
        Search rom for each characteristic's axis fingerprint.

        Returns {characteristic_name: file_offset} for every table found.
        Tables not found in this ROM variant are omitted from the result.
        The returned offset points to the start of the table header (before
        any axis data), matching the convention used by EcuCalibrationTableScanner.
        """
        result: dict = {}
        for tbl in self._tables:
            off = self._find_table(tbl, rom)
            if off is not None:
                result[tbl.name] = off
        return result

    def label_map(self, rom: Optional[bytes] = None) -> dict[int, str]:
        """
        Return {file_offset: label} for all tables.

        When rom is supplied, fingerprint relocation is performed first so the
        offsets reflect this ROM variant. When rom is None, defaultAddress
        offsets from the JSON are used as-is (suitable only for the baseline ROM).
        """
        if rom is not None:
            located = self.locate_in_rom(rom)
            for tbl in self._tables:
                if tbl.name in located:
                    tbl.relocated_address = located[tbl.name]

        result: dict = {}
        for tbl in self._tables:
            result.update(tbl.label_map())
        return result

    def summary(self) -> str:
        n_map   = sum(1 for t in self._tables if t.table_type == "MAP")
        n_curve = sum(1 for t in self._tables if t.table_type == "CURVE")
        n_val   = sum(1 for t in self._tables if t.table_type == "VALUE")
        ecu = self._doc.get("ecu", "unknown")
        ver = self._doc.get("version", "?")
        return (
            f"open_damos  {self._path.name}\n"
            f"  ecu      : {ecu}  v{ver}\n"
            f"  tables   : {len(self._tables)} "
            f"({n_map} MAP  {n_curve} CURVE  {n_val} VALUE)\n"
            f"  layouts  : {', '.join(self._layouts.keys())}"
        )

    # ------------------------------------------------------------------ #
    # Table construction                                                   #
    # ------------------------------------------------------------------ #

    def _build_tables(self) -> list[CalibrationTable]:
        tables = []
        for c in self._doc.get("characteristics", []):
            try:
                tables.append(self._build_one(c))
            except Exception:
                continue
        return tables

    def _build_one(self, c: dict) -> CalibrationTable:
        name         = c["name"]
        description  = c.get("description", "")
        category     = c.get("category", "")
        ctype        = c.get("type", "MAP")
        rl_name      = c.get("recordLayout", "")
        rl           = self._layouts.get(rl_name)
        dims         = c.get("dims", {})
        nx           = dims.get("nx", 1)
        ny           = dims.get("ny", 1)
        default_addr = int(c.get("defaultAddress", "0x0"), 16)

        data_info    = c.get("data", {})
        data_scale   = data_info.get("factor", 1.0)
        data_bias    = data_info.get("offset", 0.0)
        data_unit    = data_info.get("unit", "")

        # Resolve endianness and signedness from recordLayout
        be = rl.data_big_endian if rl else True
        signed = rl.data_signed if rl else True
        bits = 16   # Bosch EDC16 uses int16 throughout
        little_endian = not be

        axes = c.get("axes", [])
        x_axis: Optional[CalibrationAxis] = None
        y_axis: Optional[CalibrationAxis] = None

        if ctype in ("MAP", "CURVE") and len(axes) >= 1:
            x_axis = self._build_axis(axes[0], rl, nx)
        if ctype == "MAP" and len(axes) >= 2:
            y_axis = self._build_axis(axes[1], rl, ny)

        # data address: for Bosch EDC16C34 the data follows the header + axes inline
        # defaultAddress points to the START of the record (before the header)
        data_addr = default_addr
        if rl and rl.header_bytes > 0:
            # Data starts after headerBytes + nx*2 bytes (x-axis) + ny*2 bytes (y-axis)
            ax_bytes = nx * 2 + (ny * 2 if ctype == "MAP" else 0)
            data_addr = default_addr + rl.header_bytes + ax_bytes

        return CalibrationTable(
            name=name,
            description=description,
            category=category,
            table_type=ctype,
            address=data_addr,
            rows=ny if ctype == "MAP" else 1,
            cols=nx,
            element_bits=bits,
            little_endian=little_endian,
            scale=data_scale,
            bias=data_bias,
            unit=data_unit,
            x_axis=x_axis,
            y_axis=y_axis,
            source_file=str(self._path),
        )

    @staticmethod
    def _build_axis(axis_dict: dict, rl: Optional[RecordLayout], count: int) -> CalibrationAxis:
        be   = rl.axis_big_endian if rl else True
        sgn  = rl.axis_signed     if rl else True
        return CalibrationAxis(
            address=None,           # set at relocation time
            count=count,
            element_bits=16,
            little_endian=not be,
            scale=axis_dict.get("factor", 1.0),
            bias=axis_dict.get("offset", 0.0),
            unit=axis_dict.get("unit", ""),
            shared_from=None,
        )

    # ------------------------------------------------------------------ #
    # Fingerprint relocation                                              #
    # ------------------------------------------------------------------ #

    def _find_table(self, tbl: CalibrationTable, rom: bytes) -> Optional[int]:
        """
        Locate tbl in rom using the first axis's fingerprint array.

        Returns the file offset of the table header (where headerBytes begin),
        or None when no match is found.
        """
        # Find the characteristic entry for this table by name
        char = next(
            (c for c in self._doc.get("characteristics", []) if c["name"] == tbl.name),
            None,
        )
        if char is None:
            return None

        axes = char.get("axes", [])
        if not axes:
            return None

        # Use the first axis fingerprint for relocation
        ax = axes[0]
        fp = ax.get("fingerprint")
        if not fp:
            return None

        factor = ax.get("factor", 1.0)
        offset_val = ax.get("offset", 0.0)
        count = len(fp)

        rl_name = char.get("recordLayout", "")
        rl = self._layouts.get(rl_name)
        header_bytes = rl.header_bytes if rl else 0
        axis_be  = (not rl.axis_big_endian) if rl else False  # little_endian flag
        axis_sgn = rl.axis_signed if rl else True

        # Encode fingerprint as the raw integer array the ECU stores
        raw_fp = self._encode_fingerprint(fp, factor, offset_val, axis_sgn)
        if raw_fp is None:
            return None

        endian_char = ">" if not axis_be else "<"
        fmt_char = "h" if axis_sgn else "H"
        try:
            fp_bytes = struct.pack(f"{endian_char}{count}{fmt_char}", *raw_fp)
        except struct.error:
            return None

        nx = char.get("dims", {}).get("nx", 1)
        ny = char.get("dims", {}).get("ny", 1)
        expected_type = char.get("type", "MAP")

        # Search ROM for fingerprint sequence
        pos = 0
        while True:
            idx = rom.find(fp_bytes, pos)
            if idx == -1:
                break

            # The fingerprint IS the x-axis; it starts right after the header
            table_start = idx - header_bytes
            if table_start < 0:
                pos = idx + 1
                continue

            # Validate header bytes (encode nx, ny for MAP types)
            if header_bytes >= 4 and expected_type == "MAP":
                hdr_endian = ">" if (rl is None or rl.header_big_endian) else "<"
                try:
                    hdr_nx, hdr_ny = struct.unpack(
                        f"{hdr_endian}HH", rom[table_start:table_start + 4]
                    )
                    if hdr_nx == nx and hdr_ny == ny:
                        return table_start
                except struct.error:
                    pass
            elif header_bytes >= 2 and expected_type == "CURVE":
                hdr_endian = ">" if (rl is None or rl.header_big_endian) else "<"
                try:
                    (hdr_nx,) = struct.unpack(
                        f"{hdr_endian}H", rom[table_start:table_start + 2]
                    )
                    if hdr_nx == nx:
                        return table_start
                except struct.error:
                    pass
            elif header_bytes == 0:
                # No header to validate; accept the first hit
                return table_start

            pos = idx + 1

        return None

    @staticmethod
    def _encode_fingerprint(
        fp: list, factor: float, offset_val: float, signed: bool
    ) -> Optional[list[int]]:
        """Convert physical fingerprint values back to raw integer encoding."""
        if factor == 0:
            return None
        raw = []
        for v in fp:
            r = round((v - offset_val) / factor)
            limit = 32767 if signed else 65535
            min_v = -32768 if signed else 0
            if r < min_v or r > limit:
                return None
            raw.append(r)
        return raw
