"""
Tests for LatexReExtractor — LaTeX ASIC/firmware specification RE extractor.

Tests cover:
  - _strip_latex: markup removal, math substitution, comment stripping
  - sections(): hierarchy extraction and body slicing
  - commands(): \\newcommand / \\def definition extraction
  - tables(): tabular environment parsing, \\hline / & / \\\\ handling
  - parameters(): inline numeric parameter extraction with units
  - labeled_items(): \\textbf{label}: description pairs
  - Integration: real TDR tarballs at /media/cowboy/research/CERN/fw/tdr/
"""

import os
import tarfile
import io

import pytest

from ablation.analyzers.latex_re_extractor import (
    LatexReExtractor,
    LatexSection,
    LatexTable,
    _strip_latex,
)


# ── _strip_latex unit tests ───────────────────────────────────────────────────

def test_strip_latex_textbf_keeps_content():
    assert _strip_latex(r"\textbf{Hello}") == "Hello"


def test_strip_latex_textit_keeps_content():
    assert _strip_latex(r"\textit{world}") == "world"


def test_strip_latex_emph_keeps_content():
    assert _strip_latex(r"\emph{emphasis}") == "emphasis"


def test_strip_latex_comment_removed():
    result = _strip_latex("hello % this is a comment\nworld")
    assert "comment" not in result
    assert "hello" in result
    assert "world" in result


def test_strip_latex_inline_math_replaced():
    result = _strip_latex(r"speed is $N \times 40$ MHz")
    assert "$" not in result
    # Inline math replaced with ?
    assert "?" in result


def test_strip_latex_ref_removed():
    result = _strip_latex(r"see figure~\ref{fig:overview} for details")
    assert "ref" not in result
    assert "see figure" in result
    assert "for details" in result


def test_strip_latex_cite_removed():
    result = _strip_latex(r"in~\cite{gbt_website} we see")
    assert "cite" not in result
    assert "in" in result
    assert "we see" in result


def test_strip_latex_label_removed():
    result = _strip_latex(r"\label{fig:test} Some text")
    assert "label" not in result
    assert "Some text" in result


def test_strip_latex_plain_text_unchanged():
    result = _strip_latex("The data rate is 640 Mb/s.")
    assert "640 Mb/s" in result


# ── LatexReExtractor.from_text tests ─────────────────────────────────────────

def test_from_text_builds():
    ext = LatexReExtractor.from_text(r"\section{Test}")
    assert ext is not None


def test_raw_returns_original():
    src = r"\section{Hello} world"
    ext = LatexReExtractor.from_text(src)
    assert ext.raw() == src


def test_text_strips_markup():
    ext = LatexReExtractor.from_text(r"\textbf{Fast} data at 640 Mb/s")
    t = ext.text()
    assert "Fast" in t
    assert "640 Mb/s" in t
    assert r"\textbf" not in t


# ── sections() tests ─────────────────────────────────────────────────────────

def test_sections_empty_document():
    ext = LatexReExtractor.from_text("No sections here.")
    assert ext.sections() == []


def test_sections_single_section():
    ext = LatexReExtractor.from_text(r"\section{Introduction} Some text.")
    secs = ext.sections()
    assert len(secs) == 1
    assert secs[0].title == "Introduction"
    assert secs[0].level == 2
    assert secs[0].kind == "section"


def test_sections_hierarchy():
    src = r"""
\section{Top}
Body of top.
\subsection{Sub}
Body of sub.
\subsubsection{SubSub}
Body of subsub.
"""
    ext = LatexReExtractor.from_text(src)
    secs = ext.sections()
    assert len(secs) == 3
    assert secs[0].level == 2   # section
    assert secs[1].level == 3   # subsection
    assert secs[2].level == 4   # subsubsection
    assert secs[0].title == "Top"
    assert secs[1].title == "Sub"
    assert secs[2].title == "SubSub"


def test_sections_body_contains_text():
    src = r"\section{Intro} The ITk strip detector uses 640 Mb/s links."
    ext = LatexReExtractor.from_text(src)
    secs = ext.sections()
    assert len(secs) == 1
    assert "640 Mb/s" in secs[0].body


def test_sections_paragraph_level():
    src = r"\paragraph{Detail} Some details here."
    ext = LatexReExtractor.from_text(src)
    secs = ext.sections()
    assert len(secs) == 1
    assert secs[0].level == 5
    assert secs[0].kind == "paragraph"


# ── commands() tests ─────────────────────────────────────────────────────────

def test_commands_empty():
    ext = LatexReExtractor.from_text("No commands here.")
    assert ext.commands() == {}


def test_commands_newcommand_simple():
    src = r"\newcommand{\LinkSpeed}{640}"
    ext = LatexReExtractor.from_text(src)
    cmds = ext.commands()
    assert "LinkSpeed" in cmds
    assert cmds["LinkSpeed"] == "640"


def test_commands_def_simple():
    src = r"\def\NumLinks{14}"
    ext = LatexReExtractor.from_text(src)
    cmds = ext.commands()
    assert "NumLinks" in cmds
    assert cmds["NumLinks"] == "14"


def test_commands_multiple():
    src = r"""
\newcommand{\LinkSpeed}{640}
\newcommand{\FibreSpeed}{10000}
\def\NumChips{10}
"""
    ext = LatexReExtractor.from_text(src)
    cmds = ext.commands()
    assert "LinkSpeed" in cmds
    assert "FibreSpeed" in cmds
    assert "NumChips" in cmds
    assert cmds["LinkSpeed"] == "640"
    assert cmds["FibreSpeed"] == "10000"
    assert cmds["NumChips"] == "10"


def test_commands_renewcommand():
    src = r"\renewcommand{\BaseRate}{320}"
    ext = LatexReExtractor.from_text(src)
    assert "BaseRate" in ext.commands()


def test_commands_with_arg_count():
    # \newcommand{\Cmd}[2]{body} — skip parametric commands
    src = r"\newcommand{\myCmd}[2]{arg1 and arg2}"
    ext = LatexReExtractor.from_text(src)
    # Current impl skips [N] count by the regex — should still find it
    cmds = ext.commands()
    # The regex handles [N] via (?:\[\d+\])? — should match
    assert "myCmd" in cmds


# ── tables() tests ───────────────────────────────────────────────────────────

def test_tables_empty():
    ext = LatexReExtractor.from_text("No tables here.")
    assert ext.tables() == []


def test_tables_simple():
    src = r"""
\begin{tabular}{|l|l|}
\hline
Bit & Function \\
\hline
0 & Clock enable \\
1 & Data enable \\
\hline
\end{tabular}
"""
    ext = LatexReExtractor.from_text(src)
    tbls = ext.tables()
    assert len(tbls) == 1
    assert tbls[0].header == ["Bit", "Function"]
    assert len(tbls[0].data_rows) == 2


def test_tables_three_columns():
    src = r"""
\begin{tabular}{|l|l|l|}
Bit & Default & Function \\
0 & 0 & Use PLL \\
1 & 1 & Enable driver \\
\end{tabular}
"""
    ext = LatexReExtractor.from_text(src)
    tbls = ext.tables()
    assert len(tbls) == 1
    assert tbls[0].header == ["Bit", "Default", "Function"]
    assert tbls[0].data_rows[0] == ["0", "0", "Use PLL"]


def test_tables_caption_extracted():
    src = r"""
\caption{Register Map for Control Register 1}
\begin{tabular}{|l|l|}
Bit & Function \\
0 & Clock \\
\end{tabular}
"""
    ext = LatexReExtractor.from_text(src)
    tbls = ext.tables()
    assert len(tbls) == 1
    assert "Register Map" in tbls[0].caption


def test_tables_hline_stripped():
    src = r"""
\begin{tabular}{|l|l|}
\hline
A & B \\
\hline
1 & 2 \\
\hline
\end{tabular}
"""
    ext = LatexReExtractor.from_text(src)
    tbls = ext.tables()
    assert len(tbls) == 1
    # hline rows should not appear as data rows
    for row in tbls[0].rows:
        assert not all(c == "" for c in row)


def test_latextable_header_datrows_properties():
    tbl = LatexTable(rows=[["A", "B"], ["1", "2"], ["3", "4"]])
    assert tbl.header == ["A", "B"]
    assert len(tbl.data_rows) == 2


def test_latextable_empty():
    tbl = LatexTable(rows=[])
    assert tbl.header == []
    assert tbl.data_rows == []


# ── parameters() tests ───────────────────────────────────────────────────────

def test_parameters_empty():
    ext = LatexReExtractor.from_text("No numbers here.")
    assert ext.parameters() == []


def test_parameters_detects_mbps():
    src = r"The HCC transmits at 640Mb serial e-links."
    ext = LatexReExtractor.from_text(src)
    params = ext.parameters()
    values = [(v, u) for v, u, _ in params]
    assert ("640", "Mb") in values


def test_parameters_detects_gbps():
    src = r"The optical fibre runs at 10Gb per link."
    ext = LatexReExtractor.from_text(src)
    params = ext.parameters()
    values = [(v, u) for v, u, _ in params]
    assert ("10", "Gb") in values


def test_parameters_detects_mhz():
    src = r"The clock runs at 40 MHz for readout."
    ext = LatexReExtractor.from_text(src)
    params = ext.parameters()
    values = [(v, u) for v, u, _ in params]
    assert ("40", "MHz") in values


def test_parameters_deduplication():
    """Same value+unit appearing multiple times should deduplicate."""
    src = "640Mb links and another 640Mb link."
    ext = LatexReExtractor.from_text(src)
    params = ext.parameters()
    count_640mb = sum(1 for v, u, _ in params if v == "640" and u.lower().startswith("mb"))
    assert count_640mb == 1


def test_parameters_context_line_returned():
    src = r"Each HCC has 640Mb serial e-links to the GBTx."
    ext = LatexReExtractor.from_text(src)
    params = ext.parameters()
    assert len(params) >= 1
    val, unit, ctx = params[0]
    assert "640" in ctx or "GBTx" in ctx  # context is the line


def test_parameters_counts_bytes():
    src = r"Packets are less than 50 bytes in length."
    ext = LatexReExtractor.from_text(src)
    params = ext.parameters()
    values = [v for v, u, _ in params]
    assert "50" in values


def test_parameters_counts_links():
    src = r"Each FELIX handles about 100 links."
    ext = LatexReExtractor.from_text(src)
    params = ext.parameters()
    values = [(v, u) for v, u, _ in params]
    assert ("100", "links") in values


# ── labeled_items() tests ─────────────────────────────────────────────────────

def test_labeled_items_empty():
    ext = LatexReExtractor.from_text("No labeled items here.")
    assert ext.labeled_items() == []


def test_labeled_items_basic():
    src = r"\textbf{DCS data:} This is high priority data."
    ext = LatexReExtractor.from_text(src)
    items = ext.labeled_items()
    assert len(items) >= 1
    labels = [label for label, _ in items]
    assert "DCS data:" in labels


def test_labeled_items_multiple():
    src = r"""
\item \textbf{DCS data:} High priority data.
\item \textbf{L1Track data:} Regional trigger data.
"""
    ext = LatexReExtractor.from_text(src)
    items = ext.labeled_items()
    labels = [label for label, _ in items]
    assert "DCS data:" in labels
    assert "L1Track data:" in labels


def test_labeled_items_description_stripped():
    src = r"\textbf{Event data:} Data with \textit{variable} length packets."
    ext = LatexReExtractor.from_text(src)
    items = ext.labeled_items()
    assert len(items) >= 1
    _, desc = items[0]
    assert "variable" in desc
    assert r"\textit" not in desc


# ── from_path / from_tar error tests ─────────────────────────────────────────

def test_from_path_missing_raises():
    with pytest.raises(FileNotFoundError):
        LatexReExtractor.from_path("/nonexistent/path/doc.tex")


def test_from_tar_missing_member_raises():
    # Create a minimal tarball in memory with no .tex file
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        data = b"hello"
        info = tarfile.TarInfo(name="readme.txt")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    buf.seek(0)

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
        f.write(buf.getvalue())
        tmp_path = f.name

    try:
        with pytest.raises(KeyError):
            LatexReExtractor.from_tar(tmp_path, "nonexistent.tex")
    finally:
        os.unlink(tmp_path)


# ── report() test ─────────────────────────────────────────────────────────────

def test_report_includes_counts():
    src = r"""
\newcommand{\Rate}{640}
\section{Test}
The rate is 640 Mb/s.
\begin{tabular}{|l|l|}
Bit & Function \\
0 & Enable \\
\end{tabular}
\textbf{Key feature:} Important thing.
"""
    ext = LatexReExtractor.from_text(src, label="test.tex")
    report = ext.report()
    assert "sections" in report
    assert "tabular" in report
    assert "parameters" in report


# ── Integration: TDR tarballs ────────────────────────────────────────────────

TDR1 = "/media/cowboy/research/CERN/fw/tdr/tdr_readout_control_20160622.tar.gz"
TDR2 = "/media/cowboy/research/CERN/fw/tdr/tdr_readout_control_20160705.tar.gz"


@pytest.mark.skipif(not os.path.exists(TDR1), reason="TDR1 tarball not mounted")
def test_tdr1_loads_from_tar():
    ext = LatexReExtractor.from_tar(TDR1, "tdr_readout_control.tex")
    assert len(ext.raw()) > 10000


@pytest.mark.skipif(not os.path.exists(TDR1), reason="TDR1 tarball not mounted")
def test_tdr1_sections_found():
    ext = LatexReExtractor.from_tar(TDR1, "tdr_readout_control.tex")
    secs = ext.sections()
    titles = [s.title for s in secs]
    assert any("FELIX" in t for t in titles)
    assert any("LTI" in t or "Data Handler" in t for t in titles)


@pytest.mark.skipif(not os.path.exists(TDR1), reason="TDR1 tarball not mounted")
def test_tdr1_parameters_640mb():
    ext = LatexReExtractor.from_tar(TDR1, "tdr_readout_control.tex")
    params = ext.parameters()
    values_units = [(v, u.lower()) for v, u, _ in params]
    # 640 Mb/s e-links is the key ITk strip link speed
    assert any(v == "640" for v, u in values_units)


@pytest.mark.skipif(not os.path.exists(TDR2), reason="TDR2 tarball not mounted")
def test_tdr2_strips_tex_loads():
    ext = LatexReExtractor.from_tar(TDR2, "tdr_readout_control_strips.tex")
    assert len(ext.raw()) > 5000


@pytest.mark.skipif(not os.path.exists(TDR2), reason="TDR2 tarball not mounted")
def test_tdr2_strips_parameters():
    ext = LatexReExtractor.from_tar(TDR2, "tdr_readout_control_strips.tex")
    params = ext.parameters()
    # 640 Mb e-links, 10 Gb fibre, 100 links per FELIX
    values = [v for v, _, _ in params]
    assert "640" in values
    assert "10" in values
    assert "100" in values


@pytest.mark.skipif(not os.path.exists(TDR2), reason="TDR2 tarball not mounted")
def test_tdr2_strips_labeled_items():
    ext = LatexReExtractor.from_tar(TDR2, "tdr_readout_control_strips.tex")
    items = ext.labeled_items()
    labels = [label for label, _ in items]
    # DCS data and L1Track data are the two labeled items in the strips TDR
    assert any("DCS" in label for label in labels)
    assert any("L1Track" in label for label in labels)


@pytest.mark.skipif(not os.path.exists(TDR2), reason="TDR2 tarball not mounted")
def test_tdr2_common_tex_loads():
    ext = LatexReExtractor.from_tar(TDR2, "tdr_readout_control_common.tex")
    secs = ext.sections()
    assert len(secs) > 0
