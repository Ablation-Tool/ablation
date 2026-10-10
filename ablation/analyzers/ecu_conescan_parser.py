"""
Conescan ECU definition XML parser.

Parses the ConnorRigby conescan ECU definition format used for Mazda SH705x
and SH7055-based ECUs (MX5, RX8). The format is a single-ROM XML without the
base/variant split used by RomRaider MS43/MS45 definitions.

Format overview:

    <rom>
      <romid>
        <xmlid>LFG2EE</xmlid>
        <internalidaddress>b8046</internalidaddress>   <!-- hex, no 0x prefix -->
        <internalidstring>LFG2EE</internalidstring>
        <memmodel>SH7058</memmodel>
        <make>Mazda</make>
        <model>MX5</model>
        ...
      </romid>
      <scaling name="758256" storagetype="float" endian="big"
               toexpr="x" frexpr="x" units="" format="%0.2f" ... />
      <scaling name="VSS_SPD" storagetype="float" endian="big" toexpr="x" ... />
      <table name="CC Sensitivity - Non Gear" type="2D" category="DBW"
             address="b91f0" elements="39" scaling="758256">
        <table name="VSS_DELTA" address="b9154" elements="39"
               scaling="VSS_SPD" type="Y Axis" />
      </table>
      <table name="CC Target APP" type="3D" address="ba2a0"
             elements="54" scaling="762528">
        <table name="GEAR" address="ba288" elements="6"
               scaling="762504" type="X Axis" />
        <table name="VSS" address="ba264" elements="9"
               scaling="762468" type="Y Axis" />
      </table>
      <table name="Idle Target RPM" type="1D" address="1234" elements="1"
             scaling="RPM" />
    </rom>

XML type to CalibrationTable type:
    "1D" → VALUE  (scalar or 1-D lookup; no axis children)
    "2D" → CURVE  (1-D map with one Y Axis child)
    "3D" → MAP    (2-D map with X Axis + Y Axis children)

All addresses are hex without the "0x" prefix.
internalidaddress is hex without the "0x" prefix.

Identification: search for internalidstring in a window around internalidaddress.

Usage::

    from ablation.analyzers.ecu_conescan_parser import EcuConescanParser

    parser = EcuConescanParser.from_file("lfg2ee.xml")
    print(parser.summary())

    rom = open("LFG2EE_stock.bin", "rb").read()
    if parser.identify_rom(rom):
        tables = parser.calibration_tables()
        for offset, name in parser.label_map().items():
            ctx.set_name(offset, name, source="conescan")
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ablation.analyzers.ecu_cal_def import CalibrationAxis, CalibrationTable


# ------------------------------------------------------------------ #
# Storagetype mapping                                                  #
# ------------------------------------------------------------------ #

_STORAGE_MAP: dict[str, tuple[int, bool, bool]] = {
    "uint8":   (8,  False, False),
    "int8":    (8,  True,  False),
    "uint16":  (16, False, False),
    "int16":   (16, True,  False),
    "uint32":  (32, False, False),
    "int32":   (32, True,  False),
    "float":   (32, False, True),
    "float32": (32, False, True),
}


def _parse_storage(s: str) -> tuple[int, bool, bool]:
    return _STORAGE_MAP.get(s.lower().strip(), (8, False, False))


# ------------------------------------------------------------------ #
# Scaling expression parser (shared with RomRaider parser)             #
# ------------------------------------------------------------------ #

def _expr_to_linear(expr: str) -> tuple[float, float]:
    """
    Extract (scale, bias) from a conescan toexpr attribute.

    Handles the same forms as EcuRomRaiderParser._expr_to_linear:
    identity, x*k, k*x, x/k, x*k+b, (x*k)+b, (x*k)-b, x+b, (x+offset)*k.

    Returns (0.0, 0.0) sentinel for non-linear or unparseable expressions.
    """
    e = expr.replace(" ", "").lower()
    if e in ("x", "(x)"):
        return 1.0, 0.0

    _F = r"(-?[0-9]*\.?[0-9]+(?:[eE][+\-]?[0-9]+)?)"
    _FB = r"([+\-][0-9]*\.?[0-9]+(?:[eE][+\-]?[0-9]+)?)"

    m = re.match(rf"^{_F}\*x$", e)
    if m:
        return float(m.group(1)), 0.0

    m = re.match(rf"^\(?x\*{_F}\)?$", e)
    if m:
        return float(m.group(1)), 0.0

    m = re.match(rf"^\(?x/{_F}\)?$", e)
    if m:
        k = float(m.group(1))
        return (1.0 / k if k != 0 else 0.0), 0.0

    m = re.match(rf"^\(?x\*{_F}\)?{_FB}$", e)
    if m:
        return float(m.group(1)), float(m.group(2))

    m = re.match(rf"^x{_FB}$", e)
    if m:
        return 1.0, float(m.group(1))

    m = re.match(rf"^\(x{_FB}\)\*{_F}$", e)
    if m:
        offset = float(m.group(1))
        k = float(m.group(2))
        return k, offset * k

    return 0.0, 0.0


# ------------------------------------------------------------------ #
# Internal data structures                                             #
# ------------------------------------------------------------------ #

@dataclass
class _ScalingDef:
    """Named scaling object from a top-level <scaling> element."""
    name: str
    element_bits: int
    little_endian: bool
    signed: bool
    is_float: bool
    scale: float
    bias: float
    unit: str


# ------------------------------------------------------------------ #
# Parser                                                               #
# ------------------------------------------------------------------ #

class EcuConescanParser:
    """
    Parse a conescan ECU definition XML file.

    Unlike the RomRaider format, each conescan file covers exactly one ECU
    variant. All calibration table addresses are absolute file offsets. There
    is no base/variant inheritance.

    Attributes available after construction:

    - ``xmlid``: the ROM ID string (e.g. 'LFG2EE')
    - ``make``, ``model``, ``memmodel``: ECU metadata
    - ``internal_id_address``: internalidaddress as int (hex)
    - ``internal_id_string``: internalidstring

    Usage::

        parser = EcuConescanParser.from_file("lfg2ee.xml")

        rom = open("LFG2EE_stock.bin", "rb").read()
        if parser.identify_rom(rom):
            for offset, name in parser.label_map().items():
                ctx.set_name(offset, name, source="conescan")
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self.xmlid: str = ""
        self.make: str = ""
        self.model: str = ""
        self.memmodel: str = ""
        self.internal_id_address: int = 0
        self.internal_id_string: str = ""
        self._scalings: dict[str, _ScalingDef] = {}
        self._tables: list[CalibrationTable] = []
        self._parse(ET.parse(str(path)).getroot())

    @classmethod
    def from_file(cls, path: str | Path) -> "EcuConescanParser":
        return cls(path)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def identify_rom(self, rom: bytes, search_window: int = 32) -> bool:
        """
        Return True when the ROM contains the ECU's internalidstring near
        internalidaddress.

        The search window is ±search_window bytes around internal_id_address.
        """
        if not self.internal_id_string:
            return False
        needle = self.internal_id_string.encode("ascii", errors="replace")
        addr = self.internal_id_address
        lo = max(0, addr - search_window)
        hi = min(len(rom), addr + search_window + len(needle))
        return rom.find(needle, lo, hi) != -1

    def calibration_tables(self) -> list[CalibrationTable]:
        """Return all CalibrationTable objects parsed from this definition."""
        return list(self._tables)

    def label_map(self) -> dict[int, str]:
        """Return {file_offset: name} for all tables and axes."""
        result: dict[int, str] = {}
        for t in self._tables:
            result.update(t.label_map())
        return result

    def summary(self) -> str:
        n_map   = sum(1 for t in self._tables if t.table_type == "MAP")
        n_curve = sum(1 for t in self._tables if t.table_type == "CURVE")
        n_val   = sum(1 for t in self._tables if t.table_type == "VALUE")
        lines = [
            f"Conescan  {self._path.name}",
            f"  rom      : {self.xmlid}  {self.make} {self.model}  {self.memmodel}",
            f"  tables   : {len(self._tables)} total "
            f"({n_map} MAP  {n_curve} CURVE  {n_val} VALUE)",
            f"  scalings : {len(self._scalings)} named",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Parsing                                                              #
    # ------------------------------------------------------------------ #

    def _parse(self, root: ET.Element) -> None:
        # Root may be <rom> directly or <roms> containing <rom>
        if root.tag == "roms":
            rom_el = root.find("rom")
        else:
            rom_el = root  # root IS <rom>
        if rom_el is None:
            return

        # Parse romid
        rid = rom_el.find("romid")
        if rid is not None:
            self.xmlid = rid.findtext("xmlid", "")
            self.make  = rid.findtext("make", "")
            self.model = rid.findtext("model", "")
            self.memmodel = rid.findtext("memmodel", "")
            self.internal_id_string = rid.findtext("internalidstring", "")
            addr_str = rid.findtext("internalidaddress", "0")
            try:
                self.internal_id_address = int(addr_str, 16)
            except ValueError:
                self.internal_id_address = 0

        # Parse named scalings
        for sc_el in rom_el.findall("scaling"):
            name = sc_el.get("name", "")
            if not name:
                continue
            storagetype = sc_el.get("storagetype", "uint8")
            endian = sc_el.get("endian", "big")
            bits, signed, is_float = _parse_storage(storagetype)
            little_endian = endian.lower() == "little"
            toexpr = sc_el.get("toexpr", "x")
            scale, bias = _expr_to_linear(toexpr)
            unit = sc_el.get("units", "")
            self._scalings[name] = _ScalingDef(
                name=name,
                element_bits=bits,
                little_endian=little_endian,
                signed=signed,
                is_float=is_float,
                scale=scale,
                bias=bias,
                unit=unit,
            )

        # Parse tables; skip malformed entries so one bad element does not
        # abort the whole file, matching EcuXDFParser's resilience pattern.
        for tbl_el in rom_el.findall("table"):
            try:
                ct = self._parse_table(tbl_el)
                if ct is not None:
                    self._tables.append(ct)
            except Exception:
                continue

    def _parse_table(self, tbl_el: ET.Element) -> Optional[CalibrationTable]:
        name = tbl_el.get("name", "").strip()
        if not name:
            return None
        raw_type = tbl_el.get("type", "1D")
        category = tbl_el.get("category", "")
        address_str = tbl_el.get("address", "")
        if not address_str:
            return None
        try:
            address = int(address_str, 16)
        except ValueError:
            return None

        elements = int(tbl_el.get("elements", "1") or "1")
        scaling_name = tbl_el.get("scaling", "")
        sc = self._scalings.get(scaling_name)

        # Resolve storagetype from scaling
        if sc is not None:
            element_bits = sc.element_bits
            little_endian = sc.little_endian
            signed = sc.signed
            is_float = sc.is_float
            scale = sc.scale
            bias = sc.bias
            unit = sc.unit
        else:
            element_bits = 8
            little_endian = False
            signed = False
            is_float = False
            scale = 1.0
            bias = 0.0
            unit = ""

        # Parse axis children
        x_axis_el: Optional[ET.Element] = None
        y_axis_el: Optional[ET.Element] = None
        for child in tbl_el.findall("table"):
            ax_type = child.get("type", "")
            if ax_type == "X Axis":
                x_axis_el = child
            elif ax_type == "Y Axis":
                y_axis_el = child

        # Determine table type and dimensions
        if raw_type == "3D":
            if x_axis_el is None or y_axis_el is None:
                return None
            table_type = "MAP"
            cols = int(x_axis_el.get("elements", "1"))
            rows = int(y_axis_el.get("elements", "1"))
        elif raw_type == "2D":
            table_type = "CURVE"
            rows = 1
            cols = elements
        else:
            table_type = "VALUE"
            rows = 1
            cols = elements

        # Build CalibrationAxis objects
        x_axis: Optional[CalibrationAxis] = None
        if x_axis_el is not None:
            x_axis = self._parse_axis(x_axis_el)

        y_axis: Optional[CalibrationAxis] = None
        if y_axis_el is not None:
            y_axis = self._parse_axis(y_axis_el)

        return CalibrationTable(
            name=name,
            description="",
            category=category,
            table_type=table_type,
            address=address,
            rows=rows,
            cols=cols,
            element_bits=element_bits,
            little_endian=little_endian,
            scale=scale,
            bias=bias,
            unit=unit,
            x_axis=x_axis,
            y_axis=y_axis,
            source_file=str(self._path),
            is_float=is_float,
        )

    def _parse_axis(self, ax_el: ET.Element) -> Optional[CalibrationAxis]:
        addr_str = ax_el.get("address", "")
        if not addr_str:
            return None
        try:
            address = int(addr_str, 16)
        except ValueError:
            return None
        elements = int(ax_el.get("elements", "1") or "1")
        scaling_name = ax_el.get("scaling", "")
        sc = self._scalings.get(scaling_name)
        if sc is not None:
            bits = sc.element_bits
            le = sc.little_endian
            scale = sc.scale
            bias = sc.bias
            unit = sc.unit
        else:
            bits, le, scale, bias, unit = 8, False, 1.0, 0.0, ""
        return CalibrationAxis(
            address=address,
            count=elements,
            element_bits=bits,
            little_endian=le,
            scale=scale,
            bias=bias,
            unit=unit,
            shared_from=None,
        )
