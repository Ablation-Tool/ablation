"""
RomRaider ECU definition XML parser.

Parses the RomRaider open-source ECU definition format used by RomRaider,
EcuFlash, and the RomRaider-based tuning community. The format is used for
BMW Siemens MS43/MS45 (MPC555 PPC32), Subaru Denso SH705x, Nissan, and
many other platforms.

Format overview:

    <roms>
      <rom>                        # Base ROM: structure only, no addresses
        <romid>
          <xmlid>BMWMS45BASE</xmlid>
          ...
        </romid>
        <table type="3D" name="..." sizex="16" sizey="20" storagetype="uint8" endian="big">
          <scaling units="..." expression="..." />
          <table type="X Axis" storagetype="uint16" endian="big">
            <scaling units="RPM" expression="x" />
          </table>
          <table type="Y Axis" storagetype="uint16" endian="big">
            <scaling units="mg/stroke" expression="x*.0212" />
          </table>
        </table>
        ...
      </rom>
      <rom base="BMWMS45BASE">     # Variant ROM: addresses only
        <romid>
          <xmlid>4570LO00</xmlid>
          <internalidaddress>13</internalidaddress>
          <internalidstring>4570LO00</internalidstring>
          <filesize>116kb</filesize>
          ...
        </romid>
        <table name="...ignition..." storageaddress="0xB24C">
          <table type="X Axis" storageaddress="0x8812" />
          <table type="Y Axis" storageaddress="0x8992" />
        </table>
        ...
      </rom>
    </roms>

Identification: each variant's <romid> carries an internalidaddress (decimal
file offset) and internalidstring (ASCII or hex digits). identify_rom() searches
a ±16-byte window around that offset for the string, allowing for minor layout
differences between ECU generations.

Usage::

    from ablation.analyzers.ecu_romraider_parser import EcuRomRaiderParser

    parser = EcuRomRaiderParser.from_file("MS45 ECU Definitions.xml")
    rom = open("525i manual ms45.bin", "rb").read()

    variant_id = parser.identify_rom(rom)
    if variant_id:
        tables = parser.calibration_tables(variant_id)
        for offset, name in parser.label_map(variant_id).items():
            ctx.set_name(offset, name, source="romraider")
    else:
        # List available variants
        print(parser.variants())
"""

from __future__ import annotations

import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ablation.analyzers.ecu_cal_def import CalibrationAxis, CalibrationTable


# ------------------------------------------------------------------ #
# Storagetype mapping                                                  #
# ------------------------------------------------------------------ #

# Maps RomRaider storagetype string → (element_bits, signed, float_type)
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
    """Return (element_bits, signed, is_float) for a storagetype string."""
    return _STORAGE_MAP.get(s.lower().strip(), (8, False, False))


# ------------------------------------------------------------------ #
# Scaling expression parser                                            #
# ------------------------------------------------------------------ #

def _expr_to_linear(expr: str) -> tuple[float, float]:
    """
    Extract (scale, bias) from a RomRaider scaling expression.

    Handles all MS43/MS45/Subaru expression forms:
    - identity: "x"
    - "x*k", "x/k", "(x*k)", "k*x"  (k may be negative)
    - "x*k+b", "x*k-b", "(x*k)+b", "(x*k)-b"
    - "x+b", "x-b"
    - "(x-offset)*k" → scale=k, bias=-offset*k  (linear, not inverse)

    Returns (0.0, 0.0) as a sentinel when non-linear (e.g. "1/(x*k)") or
    unparseable; callers treat scale=0.0 as "raw values only".
    """
    e = expr.replace(" ", "").lower()
    if e in ("x", "(x)"):
        return 1.0, 0.0

    # Unsigned or signed float literal pattern: optional leading sign,
    # digits, optional fractional, optional exponent
    _F = r"(-?[0-9]*\.?[0-9]+(?:[eE][+\-]?[0-9]+)?)"
    _FB = r"([+\-][0-9]*\.?[0-9]+(?:[eE][+\-]?[0-9]+)?)"  # bias (always has sign)

    # k*x  (coefficient before x)
    m = re.match(rf"^{_F}\*x$", e)
    if m:
        return float(m.group(1)), 0.0

    # x*k or (x*k)
    m = re.match(rf"^\(?x\*{_F}\)?$", e)
    if m:
        return float(m.group(1)), 0.0

    # x/k
    m = re.match(rf"^\(?x/{_F}\)?$", e)
    if m:
        k = float(m.group(1))
        return (1.0 / k if k != 0 else 0.0), 0.0

    # x*k+b or x*k-b or (x*k)+b or (x*k)-b
    m = re.match(rf"^\(?x\*{_F}\)?{_FB}$", e)
    if m:
        return float(m.group(1)), float(m.group(2))

    # x+b or x-b
    m = re.match(rf"^x{_FB}$", e)
    if m:
        return 1.0, float(m.group(1))

    # (x-offset)*k or (x+offset)*k  — linear: scale=k, bias=offset*k
    # _FB captures the signed offset (e.g. "-65535"), so bias = offset * k
    m = re.match(rf"^\(x{_FB}\)\*{_F}$", e)
    if m:
        offset = float(m.group(1))   # already signed (e.g. -65535.0)
        k = float(m.group(2))
        return k, offset * k

    # Non-linear (1/(x*k), log, etc.) or unknown form
    return 0.0, 0.0


# ------------------------------------------------------------------ #
# Internal data structures                                             #
# ------------------------------------------------------------------ #

@dataclass
class _AxisDef:
    """Axis definition from the base ROM entry."""
    axis_type: str      # "X Axis" or "Y Axis"
    name: str
    element_bits: int
    little_endian: bool
    signed: bool
    scale: float
    bias: float
    unit: str


@dataclass
class _TableDef:
    """Table definition from the base ROM entry (structure only, no addresses)."""
    name: str
    table_type: str     # "VALUE", "CURVE", "MAP", "Switch", "BitwiseSwitch"
    category: str
    rows: int           # sizey
    cols: int           # sizex
    element_bits: int
    little_endian: bool
    signed: bool
    scale: float
    bias: float
    unit: str
    x_axis: Optional[_AxisDef] = None
    y_axis: Optional[_AxisDef] = None


@dataclass
class _VariantAddr:
    """Per-table address override from a variant ROM entry."""
    data_addr: Optional[int]
    x_addr: Optional[int]
    y_addr: Optional[int]


@dataclass
class _VariantInfo:
    """Metadata and address table for one ROM variant."""
    xmlid: str
    base_xmlid: str
    ecuid: str
    year: str
    make: str
    model: str
    filesize_kb: int
    internalidaddress: int       # decimal file offset for ROM identification
    internalidstring: str        # ASCII string to search at that offset
    addrs: dict[str, _VariantAddr] = field(default_factory=dict)


# ------------------------------------------------------------------ #
# Parser                                                               #
# ------------------------------------------------------------------ #

class EcuRomRaiderParser:
    """
    Parse a RomRaider ECU definition XML file.

    Attributes available after construction:

    - ``base_xmlid``: the xmlid of the base definition (e.g. 'BMWMS45BASE')
    - ``variants()``: list of all (xmlid, model, filesize_kb) tuples

    Usage::

        parser = EcuRomRaiderParser.from_file("MS45 ECU Definitions.xml")

        # Auto-identify
        variant = parser.identify_rom(rom_bytes)
        if variant:
            labels = parser.label_map(variant)
            tables = parser.calibration_tables(variant)

        # Manual variant selection
        print(parser.variants())
        tables = parser.calibration_tables("4570LO00")
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        root = ET.parse(str(path)).getroot()
        self._base_defs: dict[str, _TableDef] = {}
        self._variants: list[_VariantInfo] = []
        self.base_xmlid: str = ""
        self._parse(root)

    @classmethod
    def from_file(cls, path: str | Path) -> "EcuRomRaiderParser":
        return cls(path)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def variants(self) -> list[tuple[str, str, int]]:
        """Return list of (xmlid, model, filesize_kb) for all variants."""
        return [(v.xmlid, v.model, v.filesize_kb) for v in self._variants]

    def identify_rom(self, rom: bytes, search_window: int = 32) -> Optional[str]:
        """
        Search rom for each variant's internalidstring near internalidaddress.

        Returns the matching variant's xmlid, or None when no variant matches.
        When multiple variants match (same ECU, different file sizes), returns
        the variant whose filesize_kb is closest to len(rom) // 1024.

        The internalidaddress is interpreted first as decimal, then as hex (some
        community XML files write hex values without the "0x" prefix — e.g. "100"
        means 0x100 = 256). Both interpretations are searched.
        """
        rom_kb = len(rom) // 1024
        candidates: list[tuple[int, _VariantInfo]] = []

        for v in self._variants:
            if not v.internalidstring:
                continue
            needle = v.internalidstring.encode("ascii", errors="replace")

            # Build candidate addresses: decimal as written, and hex interpretation
            addrs_to_try: list[int] = [v.internalidaddress]
            # Try hex interpretation only when the decimal value looks like it
            # could be a hex number (all hex digits, no 'e'/'+' that would suggest
            # scientific notation, and value differs from hex interpretation)
            try:
                hex_interp = int(str(v.internalidaddress), 16)
                if hex_interp != v.internalidaddress:
                    addrs_to_try.append(hex_interp)
            except ValueError:
                pass

            found = False
            for base_addr in addrs_to_try:
                lo = max(0, base_addr - search_window)
                hi = min(len(rom), base_addr + search_window + len(needle))
                idx = rom.find(needle, lo, hi)
                if idx != -1:
                    found = True
                    break

            if found:
                size_diff = abs(v.filesize_kb - rom_kb)
                candidates.append((size_diff, v))

        if not candidates:
            return None

        # Filter out candidates that resolve almost no tables. A genuine match
        # should have at least 1/5 of the base definitions with addresses, or
        # at least 20 — whichever is smaller. Candidates that fall below this
        # are false positives from coincidental string hits in code regions.
        min_tables = max(1, min(20, len(self._base_defs) // 5))
        qualified = [
            (diff, v) for diff, v in candidates
            if sum(1 for a in v.addrs.values() if a.data_addr is not None) >= min_tables
        ]
        if not qualified:
            return None
        # Among qualified, pick the variant whose filesize is closest to the ROM
        qualified.sort(key=lambda t: t[0])
        return qualified[0][1].xmlid

    def calibration_tables(self, variant_id: str) -> list[CalibrationTable]:
        """
        Return all CalibrationTable objects for the named variant.

        Merges base structure with variant addresses. Tables whose
        storageaddress is missing in the variant are omitted.
        """
        variant = self._variant_by_id(variant_id)
        if variant is None:
            return []
        tables = []
        for name, defn in self._base_defs.items():
            addr_info = variant.addrs.get(name)
            if addr_info is None or addr_info.data_addr is None:
                continue
            # Build x_axis
            x_axis: Optional[CalibrationAxis] = None
            if defn.x_axis is not None:
                x_axis = CalibrationAxis(
                    address=addr_info.x_addr,
                    count=defn.cols,
                    element_bits=defn.x_axis.element_bits,
                    little_endian=defn.x_axis.little_endian,
                    scale=defn.x_axis.scale,
                    bias=defn.x_axis.bias,
                    unit=defn.x_axis.unit,
                    shared_from=None,
                )
            # Build y_axis
            y_axis: Optional[CalibrationAxis] = None
            if defn.y_axis is not None:
                y_axis = CalibrationAxis(
                    address=addr_info.y_addr,
                    count=defn.rows,
                    element_bits=defn.y_axis.element_bits,
                    little_endian=defn.y_axis.little_endian,
                    scale=defn.y_axis.scale,
                    bias=defn.y_axis.bias,
                    unit=defn.y_axis.unit,
                    shared_from=None,
                )
            tables.append(CalibrationTable(
                name=name,
                description="",
                category=defn.category,
                table_type=defn.table_type,
                address=addr_info.data_addr,
                rows=defn.rows,
                cols=defn.cols,
                element_bits=defn.element_bits,
                little_endian=defn.little_endian,
                scale=defn.scale,
                bias=defn.bias,
                unit=defn.unit,
                x_axis=x_axis,
                y_axis=y_axis,
                source_file=str(self._path),
            ))
        return tables

    def label_map(self, variant_id: str) -> dict[int, str]:
        """Return {file_offset: name} for all tables and axes in a variant."""
        result: dict[int, str] = {}
        for t in self.calibration_tables(variant_id):
            result.update(t.label_map())
        return result

    def summary(self, variant_id: Optional[str] = None) -> str:
        lines = [
            f"RomRaider  {self._path.name}",
            f"  base     : {self.base_xmlid}",
            f"  base defs: {len(self._base_defs)} tables",
            f"  variants : {len(self._variants)}",
        ]
        if variant_id:
            v = self._variant_by_id(variant_id)
            if v:
                tables = self.calibration_tables(variant_id)
                n_map   = sum(1 for t in tables if t.table_type == "MAP")
                n_curve = sum(1 for t in tables if t.table_type == "CURVE")
                n_val   = sum(1 for t in tables if t.table_type == "VALUE")
                n_sw    = sum(1 for t in tables if t.table_type in ("Switch", "BitwiseSwitch"))
                lines.append(f"  variant  : {v.xmlid}  {v.model}  {v.filesize_kb} KB")
                lines.append(
                    f"  tables   : {len(tables)} total "
                    f"({n_map} MAP  {n_curve} CURVE  {n_val} VALUE  {n_sw} Switch)"
                )
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Parsing                                                              #
    # ------------------------------------------------------------------ #

    def _parse(self, root: ET.Element) -> None:
        roms = list(root)
        if not roms:
            return
        # First <rom> with no 'base' attribute is the base definition
        self._parse_base(roms[0])
        for rom_el in roms[1:]:
            v = self._parse_variant(rom_el)
            if v is not None:
                self._variants.append(v)

    def _parse_base(self, rom_el: ET.Element) -> None:
        rid = rom_el.find("romid")
        if rid is not None:
            self.base_xmlid = rid.findtext("xmlid", "")
        for tbl_el in rom_el.findall("table"):
            defn = self._parse_base_table(tbl_el)
            if defn is not None:
                self._base_defs[defn.name] = defn

    def _parse_base_table(self, tbl_el: ET.Element) -> Optional[_TableDef]:
        name = tbl_el.get("name", "").strip()
        if not name:
            return None
        raw_type = tbl_el.get("type", "").strip()
        category = tbl_el.get("category", "")

        # Map XML table type to CalibrationTable type
        if raw_type == "3D":
            table_type = "MAP"
        elif raw_type == "2D":
            table_type = "CURVE"
        elif raw_type == "1D":
            table_type = "VALUE"
        elif raw_type in ("Switch", "BitwiseSwitch"):
            table_type = raw_type
        else:
            table_type = "VALUE"

        sizex = int(tbl_el.get("sizex", "1") or "1")
        sizey = int(tbl_el.get("sizey", "1") or "1")
        storagetype = tbl_el.get("storagetype", "uint8")
        endian_str = tbl_el.get("endian", "big")
        little_endian = endian_str.lower() == "little"
        bits, signed, _ = _parse_storage(storagetype)

        # Scaling from <scaling> child
        scale, bias, unit = 1.0, 0.0, ""
        sc_el = tbl_el.find("scaling")
        if sc_el is not None:
            unit = sc_el.get("units", "")
            scale, bias = _expr_to_linear(sc_el.get("expression", "x"))

        # Axis definitions
        x_axis: Optional[_AxisDef] = None
        y_axis: Optional[_AxisDef] = None
        for child in tbl_el.findall("table"):
            ax_type = child.get("type", "")
            if ax_type not in ("X Axis", "Y Axis"):
                continue
            ax_name = child.get("name", ax_type)
            ax_storage = child.get("storagetype", "uint16")
            ax_endian = child.get("endian", endian_str)
            ax_le = ax_endian.lower() == "little"
            ax_bits, ax_signed, _ = _parse_storage(ax_storage)
            ax_scale, ax_bias, ax_unit = 1.0, 0.0, ""
            ax_sc = child.find("scaling")
            if ax_sc is not None:
                ax_unit = ax_sc.get("units", "")
                ax_scale, ax_bias = _expr_to_linear(ax_sc.get("expression", "x"))
            ax_def = _AxisDef(
                axis_type=ax_type,
                name=ax_name,
                element_bits=ax_bits,
                little_endian=ax_le,
                signed=ax_signed,
                scale=ax_scale,
                bias=ax_bias,
                unit=ax_unit,
            )
            if ax_type == "X Axis":
                x_axis = ax_def
            else:
                y_axis = ax_def

        return _TableDef(
            name=name,
            table_type=table_type,
            category=category,
            rows=sizey,
            cols=sizex,
            element_bits=bits,
            little_endian=little_endian,
            signed=signed,
            scale=scale,
            bias=bias,
            unit=unit,
            x_axis=x_axis,
            y_axis=y_axis,
        )

    def _parse_variant(self, rom_el: ET.Element) -> Optional[_VariantInfo]:
        base_ref = rom_el.get("base", "")
        if not base_ref:
            # Another base definition or unexpected structure — skip
            return None
        rid = rom_el.find("romid")
        if rid is None:
            return None

        xmlid = rid.findtext("xmlid", "")
        ecuid = rid.findtext("ecuid", "")
        year  = rid.findtext("year", "")
        make  = rid.findtext("make", "")
        model = rid.findtext("model", "")
        filesize_str = rid.findtext("filesize", "0kb").lower().replace("kb", "").strip()
        try:
            filesize_kb = int(filesize_str)
        except ValueError:
            filesize_kb = 0

        idaddr_str = rid.findtext("internalidaddress", "0")
        idstr = rid.findtext("internalidstring", "")
        try:
            internalidaddress = int(idaddr_str)
        except ValueError:
            internalidaddress = 0

        # Parse address overrides
        addrs: dict[str, _VariantAddr] = {}
        for tbl_el in rom_el.findall("table"):
            name = tbl_el.get("name", "").strip()
            if not name:
                continue
            data_addr = self._hex_or_none(tbl_el.get("storageaddress"))
            x_addr: Optional[int] = None
            y_addr: Optional[int] = None
            for child in tbl_el.findall("table"):
                ax_type = child.get("type", "")
                ax_addr = self._hex_or_none(child.get("storageaddress"))
                if ax_type == "X Axis":
                    x_addr = ax_addr
                elif ax_type == "Y Axis":
                    y_addr = ax_addr
            addrs[name] = _VariantAddr(data_addr=data_addr, x_addr=x_addr, y_addr=y_addr)

        return _VariantInfo(
            xmlid=xmlid,
            base_xmlid=base_ref,
            ecuid=ecuid,
            year=year,
            make=make,
            model=model,
            filesize_kb=filesize_kb,
            internalidaddress=internalidaddress,
            internalidstring=idstr,
            addrs=addrs,
        )

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _variant_by_id(self, xmlid: str) -> Optional[_VariantInfo]:
        for v in self._variants:
            if v.xmlid == xmlid:
                return v
        return None

    @staticmethod
    def _hex_or_none(s: Optional[str]) -> Optional[int]:
        if s is None:
            return None
        try:
            return int(s, 0)
        except (ValueError, TypeError):
            return None
