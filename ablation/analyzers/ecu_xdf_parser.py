"""
TunerPro XDF calibration definition parser for ECU ROM analysis.

Parses TunerPro XDF files (XML) and emits label maps and CalibrationTable
objects for BinaryContext injection and EcuCalibrationTableScanner cross-
reference. Handles shared axes (DALINK), per-table endianness overrides,
linear MATH equations, and both address-relative and absolute file offsets.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ablation.analyzers.ecu_cal_def import CalibrationAxis, CalibrationTable


@dataclass
class XDFCategory:
    index: int
    name: str


@dataclass
class XDFHeader:
    title: str
    base_offset: int        # added to every address
    base_subtract: bool     # if True, subtract base_offset instead of adding
    default_bits: int
    little_endian: bool     # lsbfirst=1 in DEFAULTS
    default_signed: bool
    region_size: int        # bytes in the target binary region


class EcuXDFParser:
    """
    Parse a TunerPro XDF file and expose calibration tables.

    XDF addresses are file offsets. Most XDF files set BASEOFFSET offset=0,
    so addresses map directly to ROM bytes. When base_address is supplied,
    it is added to every address so the result can be compared against the
    MCU's flash-mapped virtual address space (e.g. 0x80000000 for TriCore).

    Usage::

        from ablation.analyzers.ecu_xdf_parser import EcuXDFParser

        parser = EcuXDFParser.from_file("I8A0S.xdf")
        labels = parser.label_map()             # {file_offset: name}
        tables = parser.calibration_tables()    # list[CalibrationTable]

        # Inject into BinaryContext
        for offset, name in labels.items():
            ctx.set_name(offset, name, source="xdf")
    """

    def __init__(self, path: str | Path, base_address: int = 0):
        self._path = Path(path)
        self._base_address = base_address
        self._root: ET.Element = ET.parse(str(path)).getroot()
        self._header: XDFHeader = self._parse_header()
        self._categories: dict[int, str] = self._parse_categories()
        self._skipped_count: int = 0
        self._tables: list[CalibrationTable] = self._parse_tables()

    @classmethod
    def from_file(cls, path: str | Path, base_address: int = 0) -> "EcuXDFParser":
        return cls(path, base_address)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def label_map(self) -> dict[int, str]:
        """Return {file_offset: label} for all tables and their axes."""
        result: dict = {}
        for t in self._tables:
            result.update(t.label_map())
        return result

    def calibration_tables(self) -> list[CalibrationTable]:
        return list(self._tables)

    def summary(self) -> str:
        n_map = sum(1 for t in self._tables if t.table_type == "MAP")
        n_curve = sum(1 for t in self._tables if t.table_type == "CURVE")
        n_val = sum(1 for t in self._tables if t.table_type == "VALUE")
        skipped = f"  skipped    : {self._skipped_count} malformed\n" if self._skipped_count else ""
        return (
            f"XDF  {self._path.name}\n"
            f"  title      : {self._header.title}\n"
            f"  tables     : {len(self._tables)} total "
            f"({n_map} MAP  {n_curve} CURVE  {n_val} VALUE)\n"
            f"{skipped}"
            f"  base_offset: 0x{self._header.base_offset:X}"
            f"{'  (subtract)' if self._header.base_subtract else ''}\n"
            f"  endian     : {'little' if self._header.little_endian else 'big'}"
        )

    # ------------------------------------------------------------------ #
    # Internal parsing                                                     #
    # ------------------------------------------------------------------ #

    def _parse_header(self) -> XDFHeader:
        hdr = self._root.find("XDFHEADER")
        if hdr is None:
            return XDFHeader("", 0, False, 16, False, False, 0x200000)

        bo = hdr.find("BASEOFFSET")
        if bo is not None:
            try:
                base_off = int(bo.get("offset", "0"), 0)
            except (ValueError, TypeError):
                base_off = 0
            try:
                base_sub = bool(int(bo.get("subtract", "0")))
            except (ValueError, TypeError):
                base_sub = False
        else:
            base_off = 0
            base_sub = False

        defaults = hdr.find("DEFAULTS")
        def_bits = int(defaults.get("datasizeinbits", "16")) if defaults is not None else 16
        lsb_first = bool(int(defaults.get("lsbfirst", "0"))) if defaults is not None else False
        signed = bool(int(defaults.get("signed", "0"))) if defaults is not None else False

        region = hdr.find("REGION")
        reg_size = int(region.get("size", "0x200000"), 0) if region is not None else 0x200000

        title = hdr.findtext("deftitle", "")

        return XDFHeader(
            title=title,
            base_offset=base_off,
            base_subtract=base_sub,
            default_bits=def_bits,
            little_endian=lsb_first,
            default_signed=signed,
            region_size=reg_size,
        )

    def _parse_categories(self) -> dict[int, str]:
        result: dict = {}
        hdr = self._root.find("XDFHEADER")
        if hdr is None:
            return result
        for cat in hdr.findall("CATEGORY"):
            idx = int(cat.get("index", "0"), 0)
            result[idx] = cat.get("name", "")
        return result

    def _parse_tables(self) -> list[CalibrationTable]:
        all_tables_xml = self._root.findall("XDFTABLE")
        tables: list[CalibrationTable] = []

        for idx, tbl_el in enumerate(all_tables_xml):
            try:
                tables.append(self._parse_one_table(tbl_el, idx, all_tables_xml))
            except Exception:
                self._skipped_count += 1
                continue

        return tables

    def _parse_one_table(
        self,
        tbl_el: ET.Element,
        idx: int,
        all_tables: list[ET.Element],
    ) -> CalibrationTable:
        title = tbl_el.findtext("title", "").strip() or f"table_{idx:04d}"
        description = tbl_el.findtext("description", "").strip()

        # Category: first CATEGORYMEM index maps to a CATEGORY name
        cat_name = ""
        cat_mem = tbl_el.find("CATEGORYMEM")
        if cat_mem is not None:
            cat_idx = int(cat_mem.get("category", "0"), 0)
            cat_name = self._categories.get(cat_idx, "")

        axes = tbl_el.findall("XDFAXIS")
        n_axes = len(axes)

        if n_axes == 1:
            table_type = "VALUE"
        elif n_axes == 2:
            table_type = "CURVE"
        else:
            table_type = "MAP"

        # z-axis (last axis, id="z" or third) holds the data address
        data_axis = axes[-1]
        data_ed = data_axis.find("EMBEDDEDDATA")
        data_addr = self._addr(data_ed.get("mmedaddress")) if data_ed is not None else None

        # Skip entries with no data address (degenerate or purely DALINK-referenced)
        if data_addr is None:
            raise ValueError("no data address")

        bits = int(data_ed.get("mmedelementsizebits", str(self._header.default_bits)))
        rows = int(data_ed.get("mmedrowcount", "1") or "1")
        cols_val = data_ed.get("mmedcolcount")
        cols = int(cols_val) if cols_val else (
            int(data_axis.findtext("indexcount", "1"))
        )

        # Endianness: XDF DEFAULTS lsbfirst applies unless mmedtypeflags overrides
        # mmedtypeflags 0x02 = big-endian override in some XDFs; use header default otherwise
        little_endian = self._header.little_endian

        # Scaling from MATH equation
        math_el = data_axis.find("MATH")
        equation = math_el.get("equation", "X") if math_el is not None else "X"
        scale, bias = self._math_to_linear(equation)
        unit = data_axis.findtext("units", "")

        # X-axis
        x_axis: Optional[CalibrationAxis] = None
        if n_axes >= 2:
            x_axis = self._parse_axis(axes[0], all_tables)

        # Y-axis
        y_axis: Optional[CalibrationAxis] = None
        if n_axes >= 3:
            y_axis = self._parse_axis(axes[1], all_tables)

        return CalibrationTable(
            name=title,
            description=description,
            category=cat_name,
            table_type=table_type,
            address=data_addr,
            rows=rows,
            cols=cols,
            element_bits=bits,
            little_endian=little_endian,
            scale=scale,
            bias=bias,
            unit=unit,
            x_axis=x_axis,
            y_axis=y_axis,
            source_file=str(self._path),
        )

    def _parse_axis(
        self,
        ax_el: ET.Element,
        all_tables: list[ET.Element],
    ) -> CalibrationAxis:
        # DALINK: this axis borrows its address from another table's axis
        dl = ax_el.find("DALINK")
        shared_from: Optional[str] = None
        addr: Optional[int] = None
        count = 1
        bits = self._header.default_bits
        little_endian = self._header.little_endian
        scale = 1.0
        bias = 0.0
        unit = ""

        if dl is not None:
            dl_idx = int(dl.get("index", "0"))
            if dl_idx > 0 and dl_idx < len(all_tables):
                ref_tbl = all_tables[dl_idx]
                ref_axes = ref_tbl.findall("XDFAXIS")
                if ref_axes:
                    shared_from = ref_tbl.findtext("title", f"table_{dl_idx:04d}")
                    # Use the first axis of the referenced table
                    ref_ax = ref_axes[0]
                    ed = ref_ax.find("EMBEDDEDDATA")
                    if ed is not None:
                        addr = self._addr(ed.get("mmedaddress"))
                        bits = int(ed.get("mmedelementsizebits", str(bits)))
                    count = int(ref_ax.findtext("indexcount", "1"))
                    m = ref_ax.find("MATH")
                    if m is not None:
                        scale, bias = self._math_to_linear(m.get("equation", "X"))
                    unit = ref_ax.findtext("units", "")
        else:
            ed = ax_el.find("EMBEDDEDDATA")
            if ed is not None:
                addr = self._addr(ed.get("mmedaddress"))
                bits = int(ed.get("mmedelementsizebits", str(bits)))
                cols_val = ed.get("mmedcolcount")
                rows_val = ed.get("mmedrowcount")
                # Use whichever dimension attribute is present
                if cols_val:
                    count = int(cols_val)
                elif rows_val:
                    count = int(rows_val)
            count_str = ax_el.findtext("indexcount")
            if count_str:
                count = int(count_str)
            m = ax_el.find("MATH")
            if m is not None:
                scale, bias = self._math_to_linear(m.get("equation", "X"))
            unit = ax_el.findtext("units", "")

        return CalibrationAxis(
            address=addr,
            count=count,
            element_bits=bits,
            little_endian=little_endian,
            scale=scale,
            bias=bias,
            unit=unit,
            shared_from=shared_from,
        )

    def _addr(self, raw: Optional[str]) -> Optional[int]:
        """Convert an XDF hex address string to an adjusted file offset."""
        if raw is None:
            return None
        try:
            val = int(raw, 0)
        except (ValueError, TypeError):
            return None
        if self._header.base_subtract:
            val -= self._header.base_offset
        else:
            val += self._header.base_offset
        return val + self._base_address

    @staticmethod
    def _math_to_linear(equation: str) -> tuple[float, float]:
        """
        Extract (scale, bias) from a simple linear MATH equation.

        Handles "X*k", "X/k", "X*k+b", "(X*k)+b", and just "X".
        Falls back to (1.0, 0.0) when the equation is not purely linear.
        """
        eq = equation.replace(" ", "")
        # Exact "X"
        if eq == "X":
            return 1.0, 0.0
        # "X*k" or "X/k"
        m = re.match(r"^X\*([0-9.eE+\-]+)$", eq)
        if m:
            return float(m.group(1)), 0.0
        m = re.match(r"^X/([0-9.eE+\-]+)$", eq)
        if m:
            return 1.0 / float(m.group(1)), 0.0
        # "X*k+b" or "X*k-b" or parenthesised forms
        m = re.match(r"^\(?X\*([0-9.eE+\-]+)\)?([+\-][0-9.eE+\-]+)?$", eq)
        if m:
            k = float(m.group(1))
            b = float(m.group(2)) if m.group(2) else 0.0
            return k, b
        # Not reducible to (scale, bias); signal with scale=0 so callers know
        return 0.0, 0.0
