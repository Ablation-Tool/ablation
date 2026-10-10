"""
ASAM/ASAP2 A2L calibration definition parser for ECU ROM analysis.

Parses A2L files (ASAM MCD-2 MC standard, ASAP2 v1.31+) and emits label maps
and CalibrationTable objects for BinaryContext injection. A2L is the industry
standard calibration description format used by Bosch (EDC16, EDC17, MED17),
Continental, Delphi, Siemens, and most OEMs. A single EDC16 A2L covers 3,999
CHARACTERISTICs; a large EDC17 covers 25,000+.

Format overview:

    /begin PROJECT name "description"
      /begin MODULE name "description"
        /begin COMPU_METHOD
            name "description" RAT_FUNC "format" "unit"
            COEFFS a b c d e f
        /end COMPU_METHOD
        /begin RECORD_LAYOUT name
            NO_AXIS_PTS_X  position datatype
            AXIS_PTS_X     position datatype INDEX_INCR DIRECT
            FNC_VALUES     position datatype COLUMN_DIR DIRECT
        /end RECORD_LAYOUT
        /begin CHARACTERISTIC
            name "description" type address record_layout max_diff
            compu_method lower_limit upper_limit
            [FORMAT "..."]
            [/begin AXIS_DESCR
                axis_type input_quantity compu_method max_axis_pts lower upper
            /end AXIS_DESCR]
        /end CHARACTERISTIC
        /begin AXIS_PTS
            name "description" address input_qty record_layout max_diff
            compu_method lower_limit upper_limit max_axis_pts
        /end AXIS_PTS
      /end MODULE
    /end PROJECT

COMPU_METHOD RAT_FUNC scaling formula:
    physical = (a * raw^2 + b * raw + c) / (d * raw^2 + e * raw + f)
    Linear case (a=d=0, e=0): scale = b/f, bias = c/f

Encoding: A2L files are Latin-1 (ISO 8859-1). Not UTF-8.

Usage::

    from ablation.analyzers.ecu_a2l_parser import EcuA2LParser

    parser = EcuA2LParser.from_file("edc16_13.a2l")
    print(parser.summary())

    for offset, name in parser.label_map().items():
        ctx.set_name(offset, name, source="a2l")

    tables = parser.calibration_tables()   # List[CalibrationTable]
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ablation.analyzers.ecu_cal_def import CalibrationAxis, CalibrationTable


# ------------------------------------------------------------------ #
# Type maps                                                           #
# ------------------------------------------------------------------ #

_DATATYPE_MAP: dict[str, tuple[int, bool, bool]] = {
    "UBYTE":       (8,  False, False),
    "SBYTE":       (8,  True,  False),
    "UWORD":       (16, False, False),
    "SWORD":       (16, True,  False),
    "ULONG":       (32, False, False),
    "SLONG":       (32, True,  False),
    "FLOAT32_IEEE":(32, False, True),
    "FLOAT64_IEEE":(64, False, True),
    "A_UINT64":    (64, False, False),
    "A_INT64":     (64, True,  False),
}


def _parse_datatype(s: str) -> tuple[int, bool, bool]:
    """Return (bits, signed, is_float) for an A2L datatype keyword."""
    return _DATATYPE_MAP.get(s.upper().strip(), (16, False, False))


# ------------------------------------------------------------------ #
# Internal data structures                                            #
# ------------------------------------------------------------------ #

@dataclass
class _CompuMethod:
    name: str
    unit: str
    scale: float     # b/f from COEFFS 0 b c 0 0 f
    bias: float      # c/f
    is_linear: bool  # False when non-linear; scale/bias are sentinels (0.0)


@dataclass
class _RecordLayout:
    name: str
    fnc_datatype: str    # e.g. "SWORD"
    has_no_axis_x: bool  # NO_AXIS_PTS_X present (count stored in ROM)
    has_no_axis_y: bool  # NO_AXIS_PTS_Y present
    has_axis_x: bool     # AXIS_PTS_X present (inline axis data in record)
    has_axis_y: bool     # AXIS_PTS_Y present


# ------------------------------------------------------------------ #
# Text preprocessing helpers                                          #
# ------------------------------------------------------------------ #

_RE_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)


def _strip_comments(text: str) -> str:
    return _RE_COMMENT.sub(' ', text)


def _strip_nested_blocks(text: str, block_type: str) -> str:
    """
    Remove all /begin BLOCK_TYPE ... /end BLOCK_TYPE spans from text,
    handling nested /begin ... /end pairs of any type correctly.
    """
    result = []
    i = 0
    begin_pat = re.compile(r'/begin\s+(\w+)', re.IGNORECASE)
    end_pat   = re.compile(r'/end\s+(\w+)',   re.IGNORECASE)
    target    = block_type.upper()
    n         = len(text)

    while i < n:
        m = begin_pat.search(text, i)
        if m is None:
            result.append(text[i:])
            break
        tag = m.group(1).upper()
        if tag != target:
            result.append(text[i:m.end()])
            i = m.end()
            continue
        # Found /begin TARGET; append text before this block
        result.append(text[i:m.start()])
        # Skip to matching /end TARGET, tracking depth
        depth = 1
        j = m.end()
        while j < n and depth > 0:
            bm = begin_pat.search(text, j)
            em = end_pat.search(text, j)
            if em is None:
                j = n
                break
            if bm is not None and bm.start() < em.start():
                depth += 1
                j = bm.end()
            else:
                depth -= 1
                j = em.end()
        i = j

    return ''.join(result)


def _extract_blocks(text: str, block_type: str) -> list[str]:
    """
    Return list of raw text spans for each /begin BLOCK_TYPE ... /end BLOCK_TYPE.
    Handles nested /begin ... /end pairs of any type.
    """
    results = []
    i = 0
    begin_pat = re.compile(r'/begin\s+(\w+)', re.IGNORECASE)
    end_pat   = re.compile(r'/end\s+(\w+)',   re.IGNORECASE)
    target    = block_type.upper()
    n         = len(text)

    while i < n:
        m = begin_pat.search(text, i)
        if m is None:
            break
        tag = m.group(1).upper()
        if tag != target:
            i = m.end()
            continue
        start = m.start()
        depth = 1
        j = m.end()
        while j < n and depth > 0:
            bm = begin_pat.search(text, j)
            em = end_pat.search(text, j)
            if em is None:
                j = n
                break
            if bm is not None and bm.start() < em.start():
                depth += 1
                j = bm.end()
            else:
                depth -= 1
                j = em.end()
        results.append(text[start:j])
        i = j

    return results


# ------------------------------------------------------------------ #
# Token helpers                                                       #
# ------------------------------------------------------------------ #

_RE_TOKEN = re.compile(
    r'"[^"]*"'            # quoted string
    r'|/begin\b'          # /begin keyword
    r'|/end\b'            # /end keyword
    r'|[^\s"]+',          # bare word, number, hex, identifier
    re.IGNORECASE,
)


def _tokenize(text: str) -> list[str]:
    return _RE_TOKEN.findall(text)


def _token_value(tok: str) -> str:
    """Strip quotes from a string token."""
    if tok.startswith('"') and tok.endswith('"'):
        return tok[1:-1]
    return tok


def _parse_number(tok: str) -> Optional[float]:
    try:
        return float(int(tok, 0))
    except (ValueError, TypeError):
        try:
            return float(tok)
        except (ValueError, TypeError):
            return None


# ------------------------------------------------------------------ #
# Block parsers                                                       #
# ------------------------------------------------------------------ #

def _parse_compu_method(block_text: str) -> Optional[_CompuMethod]:
    """
    Parse one COMPU_METHOD block and return a _CompuMethod.
    Only RAT_FUNC is supported; other types (IDENTICAL, LINEAR, TAB_VERB,
    TAB_NOINTP, FORMULA) return is_linear=False with scale=1.0, bias=0.0.
    """
    tokens = _tokenize(block_text)
    # Remove /begin COMPU_METHOD header tokens
    # Structure: /begin COMPU_METHOD name "desc" type "format" "unit" COEFFS...
    try:
        idx = 0
        while idx < len(tokens) and tokens[idx].upper() != 'COMPU_METHOD':
            idx += 1
        idx += 1  # skip COMPU_METHOD keyword
        if idx >= len(tokens):
            return None
        name = _token_value(tokens[idx]); idx += 1
        # desc
        idx += 1
        if idx >= len(tokens):
            return None
        ctype = tokens[idx].upper(); idx += 1
        # format string
        idx += 1
        if idx >= len(tokens):
            return None
        unit = _token_value(tokens[idx]); idx += 1

        if ctype == 'IDENTICAL':
            return _CompuMethod(name=name, unit=unit, scale=1.0, bias=0.0, is_linear=True)
        if ctype == 'LINEAR':
            # LINEAR: COEFFS a b   where physical = a + b * raw
            while idx < len(tokens) and tokens[idx].upper() != 'COEFFS':
                idx += 1
            idx += 1
            if idx + 1 >= len(tokens):
                return None
            a_v = _parse_number(tokens[idx]); idx += 1
            b_v = _parse_number(tokens[idx]); idx += 1
            a = a_v if a_v is not None else 0.0
            b = b_v if b_v is not None else 1.0
            return _CompuMethod(name=name, unit=unit, scale=b, bias=a, is_linear=True)
        if ctype != 'RAT_FUNC':
            return _CompuMethod(name=name, unit=unit, scale=1.0, bias=0.0, is_linear=False)

        # RAT_FUNC: COEFFS a b c d e f
        # physical = (a*raw^2 + b*raw + c) / (d*raw^2 + e*raw + f)
        while idx < len(tokens) and tokens[idx].upper() != 'COEFFS':
            idx += 1
        idx += 1  # skip COEFFS
        if idx + 5 >= len(tokens):
            return None
        a_v = _parse_number(tokens[idx]); a = a_v if a_v is not None else 0.0; idx += 1
        b_v = _parse_number(tokens[idx]); b = b_v if b_v is not None else 0.0; idx += 1
        c_v = _parse_number(tokens[idx]); c = c_v if c_v is not None else 0.0; idx += 1
        d_v = _parse_number(tokens[idx]); d = d_v if d_v is not None else 0.0; idx += 1
        e_v = _parse_number(tokens[idx]); e = e_v if e_v is not None else 0.0; idx += 1
        f_v = _parse_number(tokens[idx]); f = f_v if f_v is not None else 1.0; idx += 1

        # Check for non-linear terms
        if a != 0.0 or d != 0.0 or e != 0.0 or f == 0.0:
            return _CompuMethod(name=name, unit=unit, scale=0.0, bias=0.0, is_linear=False)

        # Linear: physical = (b*raw + c) / f
        scale = b / f
        bias  = c / f
        return _CompuMethod(name=name, unit=unit, scale=scale, bias=bias, is_linear=True)
    except (IndexError, ZeroDivisionError):
        return None


def _parse_record_layout(block_text: str) -> Optional[_RecordLayout]:
    """Parse one RECORD_LAYOUT block."""
    tokens = _tokenize(block_text)
    try:
        idx = 0
        while idx < len(tokens) and tokens[idx].upper() != 'RECORD_LAYOUT':
            idx += 1
        idx += 1
        if idx >= len(tokens):
            return None
        name = _token_value(tokens[idx]); idx += 1

        fnc_datatype = "SWORD"
        has_no_axis_x = False
        has_no_axis_y = False
        has_axis_x = False
        has_axis_y = False

        while idx < len(tokens):
            kw = tokens[idx].upper()
            if kw in ('/END', 'END'):
                break
            if kw == 'FNC_VALUES':
                # FNC_VALUES position datatype [options...]
                if idx + 2 < len(tokens):
                    fnc_datatype = tokens[idx + 2].upper()
                idx += 1
            elif kw == 'NO_AXIS_PTS_X':
                has_no_axis_x = True
                idx += 1
            elif kw == 'NO_AXIS_PTS_Y':
                has_no_axis_y = True
                idx += 1
            elif kw == 'AXIS_PTS_X':
                has_axis_x = True
                idx += 1
            elif kw == 'AXIS_PTS_Y':
                has_axis_y = True
                idx += 1
            else:
                idx += 1

        return _RecordLayout(
            name=name,
            fnc_datatype=fnc_datatype,
            has_no_axis_x=has_no_axis_x,
            has_no_axis_y=has_no_axis_y,
            has_axis_x=has_axis_x,
            has_axis_y=has_axis_y,
        )
    except IndexError:
        return None


def _parse_axis_descr(block_text: str) -> tuple[int, str]:
    """
    Parse one AXIS_DESCR block and return (max_axis_pts, compu_method_name).
    Positional fields: axis_type input_quantity compu_method max_axis_pts lower upper
    """
    tokens = _tokenize(block_text)
    try:
        idx = 0
        while idx < len(tokens) and tokens[idx].upper() != 'AXIS_DESCR':
            idx += 1
        idx += 1  # skip AXIS_DESCR keyword
        # axis_type (STD_AXIS / COM_AXIS / FIX_AXIS / RES_AXIS / CURVE_AXIS)
        idx += 1
        # input_quantity
        idx += 1
        # compu_method name
        cm_name = _token_value(tokens[idx]); idx += 1
        # max_axis_pts
        pts_val = _parse_number(tokens[idx])
        max_pts = int(pts_val) if pts_val is not None else 1
        return max_pts, cm_name
    except (IndexError, TypeError):
        return 1, ""


# ------------------------------------------------------------------ #
# Parser                                                              #
# ------------------------------------------------------------------ #

class EcuA2LParser:
    """
    Parse an ASAM/ASAP2 A2L ECU calibration definition file.

    Supports ASAP2 v1.3x and v1.61. Covers Bosch EDC16, EDC17, MED17, and any
    other A2L-compliant definition file. Files are Latin-1 encoded.

    Scaling: only RAT_FUNC, IDENTICAL, and LINEAR COMPU_METHOD types produce
    CalibrationTable.scale/bias. All other types (TAB_VERB, FORMULA, etc.)
    produce scale=0.0 as a sentinel that callers use to suppress unit conversion.

    Dimensions: A2L defines max_axis_pts in each AXIS_DESCR block. For STD_AXIS
    tables (most common), the actual count is stored in the ROM. The parser uses
    max_axis_pts as the column/row count. When you need exact dimensions, read
    the record layout's NO_AXIS_PTS_X/Y word from the ROM image.

    Usage::

        parser = EcuA2LParser.from_file("edc16_13.a2l")
        print(parser.summary())
        for offset, label in parser.label_map().items():
            ctx.set_name(offset, label, source="a2l")
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self.module_name: str = ""
        self.project_name: str = ""
        self.byte_order: str = "MSB_FIRST"    # default: big-endian
        self._compu: dict[str, _CompuMethod] = {}
        self._layouts: dict[str, _RecordLayout] = {}
        self._tables: list[CalibrationTable] = []
        self._parse(self._path)

    @classmethod
    def from_file(cls, path: str | Path) -> "EcuA2LParser":
        return cls(path)

    # ------------------------------------------------------------------ #
    # Public API                                                          #
    # ------------------------------------------------------------------ #

    def calibration_tables(self) -> list[CalibrationTable]:
        """Return all CalibrationTable objects parsed from CHARACTERISTICs."""
        return list(self._tables)

    def label_map(self) -> dict[int, str]:
        """Return {file_offset: name} for all calibration objects and their axes."""
        result: dict[int, str] = {}
        for t in self._tables:
            result.update(t.label_map())
        return result

    def summary(self) -> str:
        n_map   = sum(1 for t in self._tables if t.table_type == "MAP")
        n_curve = sum(1 for t in self._tables if t.table_type == "CURVE")
        n_val   = sum(1 for t in self._tables if t.table_type == "VALUE")
        endian = "big" if self.byte_order == "MSB_FIRST" else "little"
        return (
            f"A2L  {self._path.name}\n"
            f"  project   : {self.project_name}  module: {self.module_name}\n"
            f"  tables    : {len(self._tables)} total "
            f"({n_map} MAP  {n_curve} CURVE  {n_val} VALUE)\n"
            f"  compu_meth: {len(self._compu)} named\n"
            f"  rec_layout: {len(self._layouts)} named\n"
            f"  byte_order: {endian}"
        )

    # ------------------------------------------------------------------ #
    # Parsing pipeline                                                    #
    # ------------------------------------------------------------------ #

    def _parse(self, path: Path) -> None:
        try:
            text = path.read_text(encoding='latin-1')
        except UnicodeDecodeError:
            text = path.read_text(encoding='utf-8', errors='replace')

        text = _strip_comments(text)

        # Extract project/module names for summary
        pm = re.search(r'/begin\s+PROJECT\s+(\S+)', text, re.IGNORECASE)
        if pm:
            self.project_name = _token_value(pm.group(1))
        mm = re.search(r'/begin\s+MODULE\s+(\S+)', text, re.IGNORECASE)
        if mm:
            self.module_name = _token_value(mm.group(1))

        # Extract byte order from MOD_PAR or anywhere in the module
        bo_m = re.search(r'\bBYTE_ORDER\s+(MSB_FIRST|MSB_LAST)\b', text, re.IGNORECASE)
        if bo_m:
            self.byte_order = bo_m.group(1).upper()

        # Strip A2ML and IF_DATA blocks before scanning — they have sub-grammars
        # that can contain spurious /begin and /end tokens
        text = _strip_nested_blocks(text, 'A2ML')
        text = _strip_nested_blocks(text, 'IF_DATA')

        little_endian = (self.byte_order == 'MSB_LAST')

        # Parse COMPU_METHOD blocks
        for block in _extract_blocks(text, 'COMPU_METHOD'):
            cm = _parse_compu_method(block)
            if cm:
                self._compu[cm.name] = cm

        # Parse RECORD_LAYOUT blocks
        for block in _extract_blocks(text, 'RECORD_LAYOUT'):
            rl = _parse_record_layout(block)
            if rl:
                self._layouts[rl.name] = rl

        # Parse CHARACTERISTIC blocks
        for block in _extract_blocks(text, 'CHARACTERISTIC'):
            try:
                ct = self._parse_characteristic(block, little_endian)
                if ct is not None:
                    self._tables.append(ct)
            except Exception:
                continue

    def _parse_characteristic(
        self, block_text: str, little_endian: bool
    ) -> Optional[CalibrationTable]:
        """
        Parse one CHARACTERISTIC block.

        Positional fields (in order after /begin CHARACTERISTIC):
            name "description" type address record_layout max_diff
            compu_method lower_limit upper_limit
        Followed by optional keyword sections.
        """
        # Strip nested AXIS_DESCR blocks before tokenizing main fields
        axis_descr_texts = _extract_blocks(block_text, 'AXIS_DESCR')
        stripped = _strip_nested_blocks(block_text, 'AXIS_DESCR')
        tokens = _tokenize(stripped)

        try:
            idx = 0
            # Advance past /begin CHARACTERISTIC
            while idx < len(tokens) and tokens[idx].upper() != 'CHARACTERISTIC':
                idx += 1
            idx += 1

            if idx >= len(tokens):
                return None

            name = _token_value(tokens[idx]);      idx += 1
            # description
            idx += 1
            char_type = tokens[idx].upper();       idx += 1
            addr_str = tokens[idx];                idx += 1
            try:
                address = int(addr_str, 0)
            except ValueError:
                return None
            record_layout_name = tokens[idx];      idx += 1
            idx += 1  # max_diff
            cm_name = tokens[idx];                 idx += 1
            lower = _parse_number(tokens[idx])  or 0.0; idx += 1
            upper = _parse_number(tokens[idx])  or 0.0; idx += 1

        except IndexError:
            return None

        # Resolve scaling from COMPU_METHOD
        cm = self._compu.get(cm_name)
        if cm and cm.is_linear:
            scale, bias, unit = cm.scale, cm.bias, cm.unit
        else:
            scale, bias = 1.0 if cm else 0.0, 0.0
            unit = cm.unit if cm else cm_name

        # Resolve element type from RECORD_LAYOUT
        rl = self._layouts.get(record_layout_name)
        if rl:
            bits, signed, is_float = _parse_datatype(rl.fnc_datatype)
        else:
            bits, signed, is_float = 16, True, False

        # Determine table type and dimensions from AXIS_DESCR blocks
        if char_type == 'VALUE' or not axis_descr_texts:
            table_type = "VALUE"
            rows, cols = 1, 1
            x_axis, y_axis = None, None
        elif char_type == 'CURVE' or len(axis_descr_texts) == 1:
            table_type = "CURVE"
            max_pts, ax_cm = _parse_axis_descr(axis_descr_texts[0])
            rows, cols = 1, max_pts
            x_axis = self._axis_from_descr(axis_descr_texts[0], little_endian)
            y_axis = None
        else:
            # MAP or CUBOID etc.
            table_type = "MAP"
            max_x, _ = _parse_axis_descr(axis_descr_texts[0])
            max_y, _ = _parse_axis_descr(axis_descr_texts[1])
            rows, cols = max_y, max_x
            x_axis = self._axis_from_descr(axis_descr_texts[0], little_endian)
            y_axis = self._axis_from_descr(axis_descr_texts[1], little_endian)

        if address == 0:
            return None

        return CalibrationTable(
            name=name,
            description="",
            category="",
            table_type=table_type,
            address=address,
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
            is_float=is_float,
        )

    def _axis_from_descr(
        self, axis_descr_text: str, little_endian: bool
    ) -> Optional[CalibrationAxis]:
        """Build a CalibrationAxis from an AXIS_DESCR block."""
        max_pts, cm_name = _parse_axis_descr(axis_descr_text)
        cm = self._compu.get(cm_name)
        if cm and cm.is_linear:
            scale, bias, unit = cm.scale, cm.bias, cm.unit
        else:
            scale, bias = 1.0, 0.0
            unit = cm.unit if cm else ""
        return CalibrationAxis(
            address=None,
            count=max_pts,
            element_bits=16,
            little_endian=little_endian,
            scale=scale,
            bias=bias,
            unit=unit,
            shared_from=None,
        )
