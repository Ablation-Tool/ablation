"""
Tests for DocxReExtractor — DOCX ASIC specification RE extractor.

Tests use minimal synthetic DOCX ZIP files that reproduce the structures
found in real specs:
  - Plain paragraph text with run-split words
  - Bold paragraphs (section headers)
  - Normal tables with Bit/Function/Default columns
  - Wrapper tables: outer <w:tbl> (1 row, 1 cell) → nested inner table

No third-party dependencies — all OOXML built from scratch.
"""

import io
import os
import tempfile
import zipfile

import pytest

from ablation.analyzers.docx_re_extractor import (
    DocxReExtractor,
    DocxTable,
)


# ── Minimal DOCX builder ───────────────────────────────────────────────────────

_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_REL_RELS = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""
_CONTENT_TYPES = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""


def _make_docx(document_xml: str) -> bytes:
    """Wrap document_xml in a minimal DOCX ZIP and return bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _REL_RELS)
        z.writestr("word/document.xml", document_xml)
    return buf.getvalue()


def _docx_file(document_xml: str, path: str) -> str:
    """Write synthetic DOCX to path and return the path."""
    with open(path, "wb") as f:
        f.write(_make_docx(document_xml))
    return path


def _wrap(body_content: str) -> str:
    """Wrap body content in a minimal OOXML document."""
    return f"""\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="{_W}">
<w:body>{body_content}</w:body>
</w:document>"""


def _para(text: str, bold: bool = False, style: str = "") -> str:
    """Build a simple paragraph XML snippet."""
    style_xml = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    b_open = "<w:b/>" if bold else ""
    return f"""
<w:p>
  {style_xml}
  <w:r>
    <w:rPr>{b_open}</w:rPr>
    <w:t xml:space="preserve">{text}</w:t>
  </w:r>
</w:p>"""


def _split_para(parts: list) -> str:
    """Paragraph with multiple runs (to test run-split word reassembly)."""
    runs = "".join(
        f'<w:r><w:t xml:space="preserve">{p}</w:t></w:r>'
        for p in parts
    )
    return f"<w:p>{runs}</w:p>"


def _cell(text: str) -> str:
    return f"""<w:tc>
  <w:p><w:r><w:t xml:space="preserve">{text}</w:t></w:r></w:p>
</w:tc>"""


def _row(*cells: str) -> str:
    return f'<w:tr>{"".join(_cell(c) for c in cells)}</w:tr>'


def _table(*rows: str) -> str:
    return f'<w:tbl>{"".join(rows)}</w:tbl>'


def _nested_table_wrapper(*rows: str) -> str:
    """Outer wrapper table (1 row, 1 cell) containing an inner data table."""
    inner = _table(*rows)
    return f"""<w:tbl>
  <w:tr>
    <w:tc>{inner}</w:tc>
  </w:tr>
</w:tbl>"""


# ── Paragraph tests ───────────────────────────────────────────────────────────

def test_paragraph_text_extracted():
    body = _para("Hello world")
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        assert "Hello world" in ext.text()


def test_run_split_words_joined():
    """Words split across runs ('tran' + 'smit') must reassemble to 'transmit'."""
    body = _split_para(["tran", "smit", " the signal"])
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        assert "transmit the signal" in ext.text()


def test_bold_paragraph_detected():
    body = _para("Section Header", bold=True) + _para("Normal text")
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        bold = ext.bold_sections()
        assert "Section Header" in bold
        assert "Normal text" not in bold


def test_multiple_paragraphs():
    body = _para("Para one") + _para("Para two") + _para("Para three")
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        assert len(ext.paragraphs()) == 3


# ── Table tests ───────────────────────────────────────────────────────────────

def test_simple_table_extracted():
    body = _table(
        _row("Bit#", "Default", "Function"),
        _row("0", "0", "Use PLL Clock"),
        _row("1", "1", "Enable driver"),
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        tbls = ext.tables()
        assert len(tbls) == 1
        assert tbls[0].header == ["Bit#", "Default", "Function"]
        assert len(tbls[0].data_rows) == 2


def test_register_table_detected():
    """Table with 'Bit#' in header must be returned by register_tables()."""
    body = _table(
        _row("Bit#", "Default", "Function"),
        _row("0", "0", "Clock enable"),
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        assert len(ext.register_tables()) == 1


def test_non_register_table_not_in_register_tables():
    """Table with no bit/field/register columns must not appear in register_tables()."""
    body = _table(
        _row("Date", "Author", "Notes"),
        _row("2012-01-01", "FMN", "Initial release"),
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        assert len(ext.register_tables()) == 0


def test_table_preceding_heading():
    """register_tables()[i].preceding_heading must be the bold para before the table."""
    body = (
        _para("Status Register", bold=True) +
        _table(
            _row("Bit", "Description"),
            _row("0", "PLL Lock"),
        )
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        reg_tbls = ext.register_tables()
        assert len(reg_tbls) == 1
        assert reg_tbls[0].preceding_heading == "Status Register"


# ── Wrapper table (nested table) tests ───────────────────────────────────────

def test_wrapper_table_unwrapped():
    """
    Wrapper table (outer 1-row/1-cell → inner data table) must be unwrapped.
    The inner table rows must appear as the DocxTable's rows.
    """
    body = _nested_table_wrapper(
        _row("Bit#", "Default", "Function"),
        _row("0", "0", "Use PLL Clock"),
        _row("1", "1", "Enable driver"),
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        tbls = ext.tables()
        assert len(tbls) == 1, "Wrapper table must produce exactly one DocxTable"
        # The inner table's rows should be accessible
        assert tbls[0].header == ["Bit#", "Default", "Function"]
        assert len(tbls[0].data_rows) == 2


def test_wrapper_table_register_detected():
    """Unwrapped wrapper table with Bit# column must appear in register_tables()."""
    body = _nested_table_wrapper(
        _row("Bit#", "Default", "Function"),
        _row("0-2", "100", "Driver current"),
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        assert len(ext.register_tables()) == 1


# ── Constants extraction ──────────────────────────────────────────────────────

def test_constants_from_register_table_defaults():
    """constants() must derive {function_name: default_value} from register tables."""
    body = _table(
        _row("Bit#", "Default", "Function"),
        _row("0", "0", "Use PLL Clock"),
        _row("1", "1", "Enable driver"),
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        consts = ext.constants()
        # Function name is the start of the description
        assert "Use" in consts or "Enable" in consts  # at least one extracted


def test_constants_from_text_assignment():
    """constants() must find NAME = value patterns in paragraph text."""
    body = _para("L0_CMD = 0x05 and R3_HEADER = 101")
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(_wrap(body), os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        consts = ext.constants()
        assert "L0_CMD" in consts
        assert consts["L0_CMD"] == "0x05"


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_empty_document():
    """Document with no body content must return empty extractor."""
    doc = _wrap("")
    with tempfile.TemporaryDirectory() as tmp:
        path = _docx_file(doc, os.path.join(tmp, "test.docx"))
        ext = DocxReExtractor.from_path(path)
        assert ext.text() == ""
        assert ext.tables() == []


def test_file_not_found_raises():
    with pytest.raises(FileNotFoundError):
        DocxReExtractor.from_path("/nonexistent/path/file.docx")


def test_docxtable_is_register_table_logic():
    """DocxTable.is_register_table() must recognize common column names."""
    tbl = DocxTable(rows=[["Bit#", "Default", "Function"]])
    assert tbl.is_register_table()

    tbl2 = DocxTable(rows=[["Date", "Author", "Notes"]])
    assert not tbl2.is_register_table()

    tbl3 = DocxTable(rows=[["Bits", "Action"]])
    assert tbl3.is_register_table()

    tbl4 = DocxTable(rows=[["Address", "Value"]])
    assert tbl4.is_register_table()


# ── Integration: real HCC specification ──────────────────────────────────────

HCC_PATH = "/media/cowboy/research/CERN/asic/hcc/HCC_Specification_V1.3.1_Oct_3.docx"

@pytest.mark.skipif(not os.path.exists(HCC_PATH), reason="HCC spec not mounted")
def test_hcc_register_table_count():
    """HCC spec must have at least 8 register/bit-field tables."""
    ext = DocxReExtractor.from_path(HCC_PATH)
    assert len(ext.register_tables()) >= 8


@pytest.mark.skipif(not os.path.exists(HCC_PATH), reason="HCC spec not mounted")
def test_hcc_control_register_table():
    """HCC control register table must have Bit#/Function/Default columns."""
    ext = DocxReExtractor.from_path(HCC_PATH)
    # Find the table with 'Bit #' and 'Default' columns
    for tbl in ext.register_tables():
        hdr = [h.strip() for h in tbl.header]
        if "Default" in hdr and any("Bit" in h for h in hdr):
            # Must have at least 10 rows (HCC CR has 25+)
            assert len(tbl.data_rows) >= 10
            # First data row: bit 0 = Use PLL Clock
            bit_col = next(i for i, h in enumerate(hdr) if "Bit" in h)
            func_col = next(i for i, h in enumerate(hdr)
                           if "Function" in h or "Description" in h)
            row0 = tbl.data_rows[0]
            assert row0[bit_col].strip() == "0"
            assert "PLL" in row0[func_col]
            return
    pytest.fail("No Bit#/Default/Function table found in HCC spec")


@pytest.mark.skipif(not os.path.exists(HCC_PATH), reason="HCC spec not mounted")
def test_hcc_paragraph_count():
    """HCC spec must produce at least 100 paragraphs."""
    ext = DocxReExtractor.from_path(HCC_PATH)
    assert len(ext.paragraphs()) >= 100


@pytest.mark.skipif(not os.path.exists(HCC_PATH), reason="HCC spec not mounted")
def test_hcc_key_protocol_text():
    """HCC spec text must contain key protocol identifiers."""
    ext = DocxReExtractor.from_path(HCC_PATH)
    text = ext.text()
    for keyword in ("L0_CMD", "R3", "ABC130", "GBT"):
        assert keyword in text, f"missing keyword: {keyword}"
