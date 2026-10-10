"""Pytrex Nissan ECU calibration definition parser.

Handles the three-level inheritance format used by Pytrex for Nissan
SH705x ECUs: a global ScalingData.xml scaling library, an A2L.xml master
structure file, and per-variant XML overlays carrying ROM addresses.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ablation.analyzers.ecu_cal_def import CalibrationAxis, CalibrationTable


# ── storage type lookup tables ───────────────────────────────────────────────

_BITS: dict[str, int] = {
    "uint8": 8, "int8": 8,
    "uint16": 16, "int16": 16,
    "uint32": 32, "int32": 32,
    "float32": 32, "float64": 64,
}

_SIGNED: frozenset[str] = frozenset({"int8", "int16", "int32"})
_FLOAT: frozenset[str] = frozenset({"float32", "float64"})


# ── scaling expression parser ────────────────────────────────────────────────

_F  = r"([0-9]*\.?[0-9]+(?:[eE][+\-]?[0-9]+)?)"
_FB = r"([+\-][0-9]*\.?[0-9]+(?:[eE][+\-]?[0-9]+)?)"

_RE_X_MUL    = re.compile(rf"^x\*{_F}$")
_RE_MUL_X    = re.compile(rf"^{_F}\*x$")
_RE_X_DIV    = re.compile(rf"^x/{_F}$")
_RE_X_MUL_FB = re.compile(rf"^\(?x\*{_F}\)?{_FB}$")
_RE_X_FB     = re.compile(rf"^x{_FB}$")


def _parse_expression(expr: str) -> tuple[float, float]:
    """Return (scale, bias) for a linear Nissan expression.

    Returns (0.0, 0.0) for non-linear or unrecognized forms.
    No eval() is used.
    """
    eq = expr.replace(" ", "").lower()
    if eq in ("x", "(x)"):
        return (1.0, 0.0)
    m = _RE_X_MUL.match(eq)
    if m:
        return (float(m.group(1)), 0.0)
    m = _RE_MUL_X.match(eq)
    if m:
        return (float(m.group(1)), 0.0)
    m = _RE_X_DIV.match(eq)
    if m:
        d = float(m.group(1))
        return (1.0 / d, 0.0) if d != 0.0 else (0.0, 0.0)
    m = _RE_X_MUL_FB.match(eq)
    if m:
        return (float(m.group(1)), float(m.group(2)))
    m = _RE_X_FB.match(eq)
    if m:
        return (1.0, float(m.group(1)))
    return (0.0, 0.0)


# ── internal types ───────────────────────────────────────────────────────────

@dataclass
class _NissanAxis:
    storagetype: str
    scaling_base: str
    is_static: bool
    count: int


@dataclass
class _NissanTableDef:
    name: str
    table_type: str       # "VALUE" / "CURVE" / "MAP" / "BITWISE"
    storagetype: str
    sizex: int
    sizey: int
    scaling_base: str
    category: str
    description: str
    x_axis: Optional[_NissanAxis]
    y_axis: Optional[_NissanAxis]


@dataclass
class _AddrEntry:
    data_addr: int
    x_addr: Optional[int]
    y_addr: Optional[int]


@dataclass
class _NissanVariantInfo:
    xmlid: str
    base_xmlid: str
    endian: str
    year: str
    make: str
    model: str
    transmission: str
    internalidaddress: int
    internalidstring: str
    filesize_kb: int
    addrs: dict[str, _AddrEntry]


# ── parser ───────────────────────────────────────────────────────────────────

class EcuNissanParser:
    """
    Parse Pytrex Nissan ECU calibration definitions.

    Accepts the Pytrex NissanDefinitions directory layout: one ScalingData.xml
    and one A2L.xml at the top level, alongside subdirectories containing
    per-variant XML files that carry ROM addresses.
    """

    def __init__(self) -> None:
        self._scalings: dict[str, tuple[float, float, str]] = {}
        self._base_defs: dict[str, _NissanTableDef] = {}
        self._variants: dict[str, _NissanVariantInfo] = {}
        self._variant_files: dict[str, Path] = {}

    # ── constructors ─────────────────────────────────────────────────────────

    @classmethod
    def from_dir(cls, definitions_dir: str | Path) -> "EcuNissanParser":
        """
        Load all definitions from a Pytrex NissanDefinitions directory.

        Reads ScalingData.xml and A2L.xml from the top level, then walks
        all subdirectories loading variant XML files. Malformed files are
        silently skipped.
        """
        root = Path(definitions_dir)
        parser = cls()
        parser._parse_scalings(root / "ScalingData.xml")
        parser._parse_structure(root / "A2L.xml")
        for xml_path in sorted(root.rglob("*.xml")):
            if xml_path.name in ("ScalingData.xml", "A2L.xml"):
                continue
            try:
                parser._load_variant(xml_path)
            except Exception:
                pass
        return parser

    # ── public API ───────────────────────────────────────────────────────────

    def variants(self) -> list[str]:
        """Return all loaded variant xmlid strings, sorted."""
        return sorted(self._variants)

    def calibration_tables(self, variant_id: str) -> list[CalibrationTable]:
        """
        Return CalibrationTable objects for one variant.

        Resolves the inheritance chain to build a merged address map, then
        combines structure from A2L.xml and scaling from ScalingData.xml.
        Tables with no address in the merged chain are omitted.
        """
        info = self._variants.get(variant_id)
        if info is None:
            return []
        little_endian = info.endian.lower() != "big"
        addrs = self._resolve_chain_addrs(variant_id)
        tables: list[CalibrationTable] = []
        for name, defn in self._base_defs.items():
            if defn.table_type == "BITWISE":
                continue
            entry = addrs.get(name)
            if entry is None:
                continue
            scale, bias, unit = self._resolve_scaling(defn.scaling_base)
            bits = _BITS.get(defn.storagetype, 16)
            is_float = defn.storagetype in _FLOAT
            x_axis = self._build_axis(defn.x_axis, entry.x_addr, little_endian)
            y_axis = self._build_axis(defn.y_axis, entry.y_addr, little_endian)
            tables.append(CalibrationTable(
                name=name,
                description=defn.description,
                category=defn.category,
                table_type=defn.table_type,
                address=entry.data_addr,
                rows=defn.sizey,
                cols=defn.sizex,
                element_bits=bits,
                little_endian=little_endian,
                scale=scale,
                bias=bias,
                unit=unit,
                x_axis=x_axis,
                y_axis=y_axis,
                source_file=str(self._variant_files.get(variant_id, "")),
                is_float=is_float,
            ))
        return tables

    def identify_rom(self, rom: bytes) -> Optional[str]:
        """
        Return the variant xmlid whose internalidstring matches rom at internalidaddress.

        Returns None when no variant matches.
        """
        for vid, info in self._variants.items():
            addr = info.internalidaddress
            idstr = info.internalidstring
            if not addr or not idstr:
                continue
            encoded = idstr.encode("latin-1", errors="replace")
            end = addr + len(encoded)
            if end <= len(rom) and rom[addr:end] == encoded:
                return vid
        return None

    def label_map(self, variant_id: str) -> dict[int, str]:
        """Return {file_offset: label} for BinaryContext injection."""
        result: dict[int, str] = {}
        for t in self.calibration_tables(variant_id):
            for offset, label in t.label_map().items():
                result[offset] = label
        return result

    def summary(self) -> str:
        """Return a short text summary of loaded definitions."""
        n_v = len(self._variants)
        n_t = len(self._base_defs)
        n_s = len(self._scalings)
        counts: dict[str, int] = {}
        for d in self._base_defs.values():
            counts[d.table_type] = counts.get(d.table_type, 0) + 1
        detail = "  ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        return (
            f"Nissan Pytrex definitions\n"
            f"  scalings   : {n_s}\n"
            f"  table defs : {n_t} total ({detail})\n"
            f"  variants   : {n_v}"
        )

    # ── private: ScalingData.xml ─────────────────────────────────────────────

    def _parse_scalings(self, path: Path) -> None:
        try:
            raw = path.read_bytes()
        except (FileNotFoundError, OSError):
            return
        root = self._parse_xml_tolerant(raw)
        if root is None:
            return
        for el in root.iter("scalingbase"):
            name = el.get("name", "").strip()
            if not name:
                continue
            expr = el.get("expression", "x").strip()
            units = el.get("units", "").strip()
            scale, bias = _parse_expression(expr)
            self._scalings[name] = (scale, bias, units)

    # ── private: A2L.xml ─────────────────────────────────────────────────────

    @staticmethod
    def _parse_xml_tolerant(raw: bytes) -> Optional[ET.Element]:
        """Parse XML bytes, recovering from a missing root close tag."""
        try:
            return ET.fromstring(raw)
        except ET.ParseError:
            pass
        m = re.match(rb"<([A-Za-z][A-Za-z0-9_:-]*)", raw.lstrip())
        if not m:
            return None
        root_tag = m.group(1).decode("ascii", errors="replace")
        try:
            return ET.fromstring(raw + f"</{root_tag}>".encode())
        except ET.ParseError:
            return None

    def _parse_structure(self, path: Path) -> None:
        try:
            raw = path.read_bytes()
        except (FileNotFoundError, OSError):
            return
        root_el = self._parse_xml_tolerant(raw)
        if root_el is None:
            return
        for tbl_el in root_el.findall("table"):
            raw_type = tbl_el.get("type", "")
            if raw_type not in ("1D", "2D", "3D", "BitwiseSwitch"):
                continue
            defn = self._parse_base_table(tbl_el)
            if defn is not None:
                self._base_defs[defn.name] = defn

    def _parse_base_table(self, el: ET.Element) -> Optional[_NissanTableDef]:
        type_map = {
            "1D": "VALUE",
            "2D": "CURVE",
            "3D": "MAP",
            "BitwiseSwitch": "BITWISE",
        }
        raw_type = el.get("type", "")
        table_type = type_map.get(raw_type, "VALUE")
        name = el.get("name", "").strip()
        if not name:
            return None
        storagetype = el.get("storagetype", "uint16").strip()
        try:
            sizex = int(el.get("sizex", "1"))
        except ValueError:
            sizex = 1
        try:
            sizey = int(el.get("sizey", "1"))
        except ValueError:
            sizey = 1
        category = el.get("category", "").strip()
        scaling_el = el.find("scaling")
        scaling_base = scaling_el.get("base", "").strip() if scaling_el is not None else ""
        description = self._read_description(el)
        x_axis: Optional[_NissanAxis] = None
        y_axis: Optional[_NissanAxis] = None
        for child in el.findall("table"):
            child_type = child.get("type", "")
            child_st = child.get("storagetype", storagetype)
            child_sc_el = child.find("scaling")
            child_sc = child_sc_el.get("base", "").strip() if child_sc_el is not None else ""
            data_count = len(child.findall("data"))
            if child_type == "Static X Axis":
                x_axis = _NissanAxis(
                    storagetype=child_st,
                    scaling_base=child_sc or scaling_base,
                    is_static=True,
                    count=data_count if data_count > 0 else sizex,
                )
            elif child_type == "Static Y Axis":
                y_axis = _NissanAxis(
                    storagetype=child_st,
                    scaling_base=child_sc or scaling_base,
                    is_static=True,
                    count=data_count if data_count > 0 else sizey,
                )
            elif child_type == "X Axis":
                x_axis = _NissanAxis(
                    storagetype=child_st,
                    scaling_base=child_sc or scaling_base,
                    is_static=False,
                    count=sizex,
                )
            elif child_type == "Y Axis":
                y_axis = _NissanAxis(
                    storagetype=child_st,
                    scaling_base=child_sc or scaling_base,
                    is_static=False,
                    count=sizey,
                )
        return _NissanTableDef(
            name=name,
            table_type=table_type,
            storagetype=storagetype,
            sizex=sizex,
            sizey=sizey,
            scaling_base=scaling_base,
            category=category,
            description=description,
            x_axis=x_axis,
            y_axis=y_axis,
        )

    @staticmethod
    def _read_description(el: ET.Element) -> str:
        desc_el = el.find("description")
        if desc_el is None:
            return ""
        parts: list[str] = []
        if desc_el.text:
            parts.append(desc_el.text)
        for child in desc_el:
            if child.tail:
                parts.append(child.tail)
        return "".join(parts).strip()

    # ── private: variant loading ─────────────────────────────────────────────

    def _load_variant(self, path: Path) -> None:
        try:
            tree = ET.parse(str(path))
        except (ET.ParseError, OSError):
            return
        root_el = tree.getroot()
        if root_el.tag != "rom":
            return
        base_xmlid = root_el.get("base", "").strip()
        if not base_xmlid:
            return
        rid = root_el.find("romid")
        if rid is None:
            return
        xmlid = rid.findtext("xmlid", "").strip()
        if not xmlid:
            return
        endian = rid.findtext("endian", "Big").strip()
        year = rid.findtext("year", "").strip()
        make = rid.findtext("make", "Nissan").strip()
        model = rid.findtext("model", "").strip()
        transmission = rid.findtext("transmission", "").strip()
        idaddr_str = rid.findtext("internalidaddress", "0").strip()
        idstr = rid.findtext("internalidstring", "").strip()
        filesize_str = (
            rid.findtext("filesize", "0kb").lower().replace("kb", "").strip()
        )
        try:
            internalidaddress = int(idaddr_str, 16)
        except (ValueError, TypeError):
            internalidaddress = 0
        try:
            filesize_kb = int(filesize_str)
        except ValueError:
            filesize_kb = 0
        addrs: dict[str, _AddrEntry] = {}
        for tbl_el in root_el.findall("table"):
            tname = tbl_el.get("name", "").strip()
            addr_str = tbl_el.get("storageaddress", "").strip()
            if not tname or not addr_str:
                continue
            try:
                data_addr = int(addr_str, 16)
            except ValueError:
                continue
            x_addr: Optional[int] = None
            y_addr: Optional[int] = None
            for child in tbl_el.findall("table"):
                child_type = child.get("type", "")
                child_addr_str = child.get("storageaddress", "").strip()
                if not child_addr_str:
                    continue
                try:
                    child_addr = int(child_addr_str, 16)
                except ValueError:
                    continue
                if child_type == "X Axis":
                    x_addr = child_addr
                elif child_type == "Y Axis":
                    y_addr = child_addr
            addrs[tname] = _AddrEntry(
                data_addr=data_addr, x_addr=x_addr, y_addr=y_addr
            )
        self._variants[xmlid] = _NissanVariantInfo(
            xmlid=xmlid,
            base_xmlid=base_xmlid,
            endian=endian,
            year=year,
            make=make,
            model=model,
            transmission=transmission,
            internalidaddress=internalidaddress,
            internalidstring=idstr,
            filesize_kb=filesize_kb,
            addrs=addrs,
        )
        self._variant_files[xmlid] = path

    # ── private: chain resolution ─────────────────────────────────────────────

    def _resolve_chain_addrs(self, variant_id: str) -> dict[str, _AddrEntry]:
        """
        Walk the base chain and return a merged address map.

        Traversal starts at the requested variant and walks toward the root.
        A child variant's addresses take priority over any ancestor's. Stops
        when base_xmlid is "A2L" or is not found in the loaded variants.
        """
        merged: dict[str, _AddrEntry] = {}
        seen: set[str] = set()
        current: Optional[str] = variant_id
        while current and current not in seen and current != "A2L":
            seen.add(current)
            info = self._variants.get(current)
            if info is None:
                break
            for name, entry in info.addrs.items():
                if name not in merged:
                    merged[name] = entry
            current = info.base_xmlid
        return merged

    # ── private: table building ───────────────────────────────────────────────

    def _resolve_scaling(self, name: str) -> tuple[float, float, str]:
        entry = self._scalings.get(name)
        if entry is not None:
            return entry
        return (0.0, 0.0, "")

    def _build_axis(
        self,
        axis_def: Optional[_NissanAxis],
        addr: Optional[int],
        little_endian: bool,
    ) -> Optional[CalibrationAxis]:
        if axis_def is None:
            return None
        scale, bias, unit = self._resolve_scaling(axis_def.scaling_base)
        bits = _BITS.get(axis_def.storagetype, 16)
        eff_addr: Optional[int] = None if axis_def.is_static else addr
        return CalibrationAxis(
            address=eff_addr,
            count=axis_def.count,
            element_bits=bits,
            little_endian=little_endian,
            scale=scale,
            bias=bias,
            unit=unit,
            shared_from=None,
        )
