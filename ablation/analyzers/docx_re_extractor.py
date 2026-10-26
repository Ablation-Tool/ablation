"""
docx_re_extractor.py: DOCX reverse-engineering extractor for ASIC specifications.

Extracts structured content from .docx files (OOXML format): paragraph text,
section headings, register tables, and inline constants. No third-party
dependencies beyond the Python standard library and the zipfile module that
is already part of CPython.

The primary use case is ASIC specification documents like the HCC Specification
where register maps are in tables (columns: Bit#, Default, Function) and
protocol constants appear inline in bold or list paragraphs.

Run-split text: OOXML splits runs mid-word for spell-check and revision
tracking. All <w:t> elements within a paragraph are concatenated directly
(no separator), respecting xml:space="preserve" for leading/trailing spaces.

Usage:
    ext = DocxReExtractor.from_path('/path/to/spec.docx')
    print(ext.text()[:500])                # full document text
    for tbl in ext.register_tables():      # tables with Bit/Field columns
        print(tbl.header, tbl.rows[:3])
    print(ext.constants())                 # hex and named constants from text
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── OOXML namespace and tag constants ─────────────────────────────────────────

_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_W = f"{{{_W_NS}}}"

# Tags we work with
_TAG_BODY      = f"{_W}body"
_TAG_P         = f"{_W}p"
_TAG_R         = f"{_W}r"
_TAG_T         = f"{_W}t"
_TAG_BR        = f"{_W}br"
_TAG_TBL       = f"{_W}tbl"
_TAG_TR        = f"{_W}tr"
_TAG_TC        = f"{_W}tc"
_TAG_PPR       = f"{_W}pPr"
_TAG_RPR       = f"{_W}rPr"
_TAG_PSTYLE    = f"{_W}pStyle"
_TAG_BOLD      = f"{_W}b"
_TAG_BOLD_CS   = f"{_W}bCs"
_XML_SPACE     = "{http://www.w3.org/XML/1998/namespace}space"

# Column header patterns that identify register/bit-field tables
_REG_HEADER_WORDS = frozenset([
    "bit", "bits", "bit#", "bit #", "bit no",
    "field", "function", "description",
    "default", "reset",
    "register", "reg", "address", "addr",
])


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class DocxParagraph:
    """One paragraph from the document."""
    text: str
    is_bold: bool = False
    style: str = ""
    # (run_text, is_bold) pairs for per-run bold inspection
    runs: List[Tuple[str, bool]] = field(default_factory=list)


@dataclass
class DocxTable:
    """One table from the document."""
    rows: List[List[str]] = field(default_factory=list)
    # Context: bold paragraph immediately before the table
    preceding_heading: str = ""

    @property
    def header(self) -> List[str]:
        return self.rows[0] if self.rows else []

    @property
    def data_rows(self) -> List[List[str]]:
        return self.rows[1:] if len(self.rows) > 1 else []

    def is_register_table(self) -> bool:
        """True if the header row contains bit-field or register column names."""
        if not self.rows:
            return False
        hdr_lower = {h.lower().strip() for h in self.header}
        return bool(hdr_lower & _REG_HEADER_WORDS)


# ── Internal XML helpers ──────────────────────────────────────────────────────

def _run_is_bold(run_el) -> bool:
    """True if the <w:r> element has a bold (<w:b/>) property."""
    rpr = run_el.find(_TAG_RPR)
    if rpr is None:
        return False
    b = rpr.find(_TAG_BOLD)
    if b is None:
        return False
    # <w:b w:val="0"/> explicitly disables bold
    val = b.get(f"{_W}val", "1")
    return val not in ("0", "false", "off")


def _run_text(run_el) -> str:
    """Concatenate text from all <w:t> and <w:br> elements in a run."""
    parts = []
    for child in run_el:
        if child.tag == _TAG_T:
            txt = child.text or ""
            # xml:space="preserve" → keep surrounding whitespace as-is
            # default → the XML parser already strips it, so nothing extra needed
            parts.append(txt)
        elif child.tag == _TAG_BR:
            parts.append("\n")
    return "".join(parts)


def _para_content(para_el) -> DocxParagraph:
    """Extract text and bold status from a <w:p> element."""
    # Paragraph style
    style = ""
    ppr = para_el.find(_TAG_PPR)
    if ppr is not None:
        ps = ppr.find(_TAG_PSTYLE)
        if ps is not None:
            style = ps.get(f"{_W}val", "")

    runs: List[Tuple[str, bool]] = []
    for child in para_el:
        if child.tag == _TAG_R:
            txt = _run_text(child)
            bold = _run_is_bold(child)
            if txt:
                runs.append((txt, bold))
        elif child.tag == _TAG_T:
            # Bare <w:t> outside a run (rare but valid)
            txt = child.text or ""
            if txt:
                runs.append((txt, False))

    full_text = "".join(t for t, _ in runs)
    any_bold = any(b for _, b in runs)
    return DocxParagraph(
        text=full_text,
        is_bold=any_bold,
        style=style,
        runs=runs,
    )


def _cell_text(cell_el) -> str:
    """Extract plain text from a <w:tc> table cell (multi-paragraph aware)."""
    para_texts = []
    for child in cell_el:
        if child.tag == _TAG_TBL:
            # Nested table inside a cell: skip (handled by _extract_table_rows)
            continue
        if child.tag == _TAG_P:
            p = _para_content(child)
            if p.text:
                para_texts.append(p.text)
    return " ".join(para_texts)


def _extract_table_rows(tbl_el) -> List[List[str]]:
    """
    Extract rows from a <w:tbl> element, unwrapping the DOCX "wrapper table"
    pattern where the entire data table is nested inside a single outer cell.

    Pattern detected:
      <w:tbl>                    ← outer layout table
        <w:tr>
          <w:tc>
            <w:tbl>...</w:tbl>   ← inner data table
          </w:tc>
        </w:tr>
      </w:tbl>

    When this pattern is found, the inner table's rows are returned.
    """
    outer_rows = tbl_el.findall(_TAG_TR)

    # Detect wrapper: single row, single cell, that cell contains a nested table
    if len(outer_rows) == 1:
        cells = outer_rows[0].findall(_TAG_TC)
        if len(cells) == 1:
            nested = cells[0].find(_TAG_TBL)
            if nested is not None:
                return _extract_table_rows(nested)

    # Normal case: extract rows directly
    rows = []
    for tr in outer_rows:
        cells_text = [_cell_text(tc) for tc in tr.findall(_TAG_TC)]
        row = [c for c in cells_text]
        if any(c.strip() for c in row):
            rows.append(row)
    return rows


def _parse_body(body_el) -> Tuple[List[DocxParagraph], List[DocxTable]]:
    """
    Walk the <w:body> in document order, separating paragraphs and tables.
    Returns (paragraphs, tables). Tables carry the immediately preceding
    bold paragraph as preceding_heading for context.
    """
    paragraphs: List[DocxParagraph] = []
    tables: List[DocxTable] = []
    last_bold_text = ""

    for child in body_el:
        if child.tag == _TAG_P:
            p = _para_content(child)
            paragraphs.append(p)
            if p.is_bold and p.text.strip():
                last_bold_text = p.text.strip()
        elif child.tag == _TAG_TBL:
            tbl = DocxTable(preceding_heading=last_bold_text)
            tbl.rows = _extract_table_rows(child)
            tables.append(tbl)

    return paragraphs, tables


# ── Constant extraction from plain text ──────────────────────────────────────

# Patterns used by constants()
_HEX_RE = re.compile(r'\b(0[xX][0-9a-fA-F]+)\b')
_BIN_RE = re.compile(r'\b(0b[01]+)\b')
# NAME = value or NAME: value where NAME is CAPS_WITH_UNDERSCORES
_NAMED_ASSIGN_RE = re.compile(
    r'\b([A-Z][A-Z0-9_]{2,})\s*[:=]\s*([^\s,;|]+)'
)
# Bit width + value: "3 bits, 101" or "3 bits: 0x5"
_BIT_FIELD_RE = re.compile(
    r'(\d+)\s*bits?\s*[,:]?\s*([0-9a-fxXbB01]{2,})'
)


# ── Main class ────────────────────────────────────────────────────────────────

class DocxReExtractor:
    """
    Extracts RE-relevant content from a .docx ASIC specification.

    Build with DocxReExtractor.from_path(path).
    """

    def __init__(
        self,
        path: str,
        paragraphs: List[DocxParagraph],
        tables: List[DocxTable],
    ) -> None:
        self._path = path
        self._paragraphs = paragraphs
        self._tables = tables
        self._text_cache: Optional[str] = None

    # ── Construction ──────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str) -> "DocxReExtractor":
        """
        Parse *path* (a .docx file) and return an extractor.

        Raises FileNotFoundError if the file does not exist.
        Raises zipfile.BadZipFile if the file is not a valid DOCX/ZIP.
        """
        import xml.etree.ElementTree as ET

        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(path)

        with zipfile.ZipFile(p) as z:
            doc_xml = z.read("word/document.xml").decode("utf-8", errors="replace")

        root = ET.fromstring(doc_xml)
        body = root.find(f".//{_TAG_BODY}")
        if body is None:
            # Empty or malformed document
            return cls(str(path), [], [])

        paragraphs, tables = _parse_body(body)
        return cls(str(path), paragraphs, tables)

    # ── Text extraction ───────────────────────────────────────────────────────

    def text(self) -> str:
        """Full document text, paragraphs separated by newlines."""
        if self._text_cache is None:
            lines = [p.text for p in self._paragraphs if p.text.strip()]
            self._text_cache = "\n".join(lines)
        return self._text_cache

    def paragraphs(self) -> List[DocxParagraph]:
        """All paragraphs in document order."""
        return list(self._paragraphs)

    def bold_sections(self) -> List[str]:
        """Text of paragraphs where any run is bold (section headers, key values)."""
        return [p.text for p in self._paragraphs if p.is_bold and p.text.strip()]

    # ── Table extraction ──────────────────────────────────────────────────────

    def tables(self) -> List[DocxTable]:
        """All tables in document order."""
        return list(self._tables)

    def register_tables(self) -> List[DocxTable]:
        """
        Tables whose header row indicates a register or bit-field map.

        Detection: any cell in the first row matches a known column header word
        (bit, bits, bit#, field, function, default, address, register, ...).
        """
        return [t for t in self._tables if t.is_register_table()]

    # ── Constant extraction ───────────────────────────────────────────────────

    def constants(self) -> Dict[str, str]:
        """
        Named constants found in the document text.

        Sources:
          1. CAPS_NAME = value  or  CAPS_NAME: value  patterns in paragraphs
          2. Hex literals (0x...) associated with a preceding ALL_CAPS name
          3. Register table default values keyed by their function description

        Returns {name: value} — last occurrence wins on duplicates.
        """
        result: Dict[str, str] = {}
        text = self.text()

        # Named assignments: CAPS_NAME = value or CAPS_NAME: value
        for m in _NAMED_ASSIGN_RE.finditer(text):
            name, val = m.group(1), m.group(2).rstrip(".,;)")
            result[name] = val

        # Register table defaults: {function_description: default_value}
        for tbl in self.register_tables():
            hdr = [h.lower() for h in tbl.header]
            # Find column indices
            bit_col = next((i for i, h in enumerate(hdr)
                            if "bit" in h), None)
            default_col = next((i for i, h in enumerate(hdr)
                                if "default" in h or "reset" in h), None)
            func_col = next((i for i, h in enumerate(hdr)
                             if any(w in h for w in
                                    ("function", "description", "field"))), None)

            if default_col is not None and func_col is not None:
                for row in tbl.data_rows:
                    if len(row) > max(default_col, func_col):
                        func = row[func_col].strip()
                        val = row[default_col].strip()
                        if func and val and val != "":
                            # Derive a key: first CAPS word or sanitized function text
                            key_m = re.match(r'[A-Z][A-Za-z0-9_]+', func)
                            key = key_m.group(0) if key_m else func[:30]
                            result[key] = val

        return result

    # ── Reporting ─────────────────────────────────────────────────────────────

    def report(self) -> str:
        """One-block summary of what was extracted."""
        reg_tables = self.register_tables()
        bold = [p.text for p in self._paragraphs
                if p.is_bold and p.text.strip()]
        lines = [
            f"DocxReExtractor: {self._path}",
            f"  paragraphs        : {len(self._paragraphs)}",
            f"  bold paragraphs   : {len(bold)}",
            f"  tables total      : {len(self._tables)}",
            f"  register tables   : {len(reg_tables)}",
        ]
        for tbl in reg_tables[:8]:
            hdr_str = " | ".join(tbl.header[:5])
            ctx = f" [{tbl.preceding_heading[:30]}]" if tbl.preceding_heading else ""
            lines.append(f"    {hdr_str}{ctx} ({len(tbl.data_rows)} rows)")
        return "\n".join(lines)
