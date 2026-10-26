"""
latex_re_extractor.py: LaTeX document RE extractor for ASIC/firmware specifications.

Extracts structured content from LaTeX source files: section hierarchy,
\\newcommand definitions, tabular tables, inline numeric parameters with
units, and \\textbf{label}: item pairs.

Primary use case: ITk Strip Detector TDR-style documents where architecture
parameters (link speeds, buffer sizes, chip counts) are scattered through
prose paragraphs, and where \\newcommand definitions encode protocol constants.

Can read .tex files directly or from .tar.gz archives without extraction.

Usage:
    ext = LatexReExtractor.from_path('/path/to/doc.tex')
    ext = LatexReExtractor.from_tar('/path/to/doc.tar.gz', 'member.tex')

    print(ext.sections())         # [{level, title, body_text}]
    print(ext.commands())         # {NAME: value} from \\newcommand/\\def
    print(ext.tables())           # [LatexTable] from tabular environments
    print(ext.parameters())       # [(value, unit, context_line)]
    print(ext.labeled_items())    # [(label, description)] from \\textbf{x}: ...
"""

from __future__ import annotations

import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── LaTeX stripping helpers ───────────────────────────────────────────────────

# Commands where we keep only the argument text
_KEEP_ARG_CMDS = re.compile(
    r'\\(?:textbf|textit|emph|textrm|texttt|textsc|text|mbox)\{([^}]*)\}',
    re.IGNORECASE
)
# Commands where we drop the entire command + argument
_DROP_CMD_ARGS = re.compile(
    r'\\(?:label|ref|cite|includegraphics|footnote|href|url|vspace|hspace|'
    r'phantom|rule|raisebox|colorbox|fbox)\s*(?:\[[^\]]*\])?\{[^}]*\}'
)
# Math environments (inline and display): replace with placeholder
_INLINE_MATH = re.compile(r'\$[^$]*\$')
_DISPLAY_MATH = re.compile(r'\$\$.*?\$\$', re.DOTALL)
# LaTeX comments
_COMMENT = re.compile(r'%[^\n]*')
# Remaining lone backslash commands (no arg): \textbackslash, \LaTeX, etc.
_LONE_CMD = re.compile(r'\\[a-zA-Z]+\*?\s*')
# OOXML-style braces that remain
_BRACES = re.compile(r'[{}]')


def _strip_latex(text: str) -> str:
    """
    Strip LaTeX markup, returning approximate plain text.
    Inline math is preserved as '?' to keep sentence structure intact.
    """
    text = _COMMENT.sub("", text)
    text = _DISPLAY_MATH.sub(" ", text)
    text = _INLINE_MATH.sub("?", text)
    text = _DROP_CMD_ARGS.sub("", text)
    text = _KEEP_ARG_CMDS.sub(r"\1", text)
    text = _LONE_CMD.sub(" ", text)
    text = _BRACES.sub("", text)
    # Collapse runs of whitespace but preserve newlines
    text = re.sub(r'[^\S\n]+', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


# ── Section parsing ───────────────────────────────────────────────────────────

# section level → (depth, regex)
_SECTION_RE = re.compile(
    r'\\(part|chapter|section|subsection|subsubsection|paragraph|subparagraph)'
    r'\*?\{([^}]+)\}',
    re.MULTILINE
)
_LEVEL_MAP = {
    "part": 0, "chapter": 1, "section": 2, "subsection": 3,
    "subsubsection": 4, "paragraph": 5, "subparagraph": 6,
}


@dataclass
class LatexSection:
    """One section/subsection from the document."""
    level: int          # 0=part, 1=chapter, 2=section, 3=subsection, ...
    kind: str           # 'section', 'subsection', etc.
    title: str          # plain-text title
    body: str           # plain-text body (up to the next section of same/higher level)


# ── Table parsing ─────────────────────────────────────────────────────────────

_TABULAR_RE = re.compile(
    r'\\begin\{tabular\}(\{[^}]*\})?(.*?)\\end\{tabular\}',
    re.DOTALL
)
_HLINE_RE = re.compile(r'\\hline\s*')
_CLINE_RE = re.compile(r'\\cline\{[^}]*\}\s*')
_MULTIROW_RE = re.compile(r'\\multirow\{[^}]*\}\{[^}]*\}\{([^}]*)\}')
_MULTICOLUMN_RE = re.compile(r'\\multicolumn\{[^}]*\}\{[^}]*\}\{([^}]*)\}')


@dataclass
class LatexTable:
    """One tabular environment from the document."""
    rows: List[List[str]] = field(default_factory=list)
    # Heading found just before the table (from \caption or preceding text)
    caption: str = ""

    @property
    def header(self) -> List[str]:
        return self.rows[0] if self.rows else []

    @property
    def data_rows(self) -> List[List[str]]:
        return self.rows[1:] if len(self.rows) > 1 else []


def _parse_tabular(body: str) -> List[List[str]]:
    """Extract rows and cells from a tabular body string."""
    # Remove \\hline and \\cline markup
    body = _HLINE_RE.sub("", body)
    body = _CLINE_RE.sub("", body)
    # Expand \multirow and \multicolumn — keep their text content
    body = _MULTIROW_RE.sub(r"\1", body)
    body = _MULTICOLUMN_RE.sub(r"\1", body)

    rows = []
    for row_str in re.split(r'\\\\', body):
        row_str = row_str.strip()
        if not row_str:
            continue
        cells = [_strip_latex(c.strip()) for c in row_str.split('&')]
        if any(c.strip() for c in cells):
            rows.append(cells)
    return rows


# ── Command/define parsing ────────────────────────────────────────────────────

# \newcommand{\NAME}{value} or \newcommand{\NAME}[N]{value}
_NEWCMD_RE = re.compile(
    r'\\(?:newcommand|renewcommand|providecommand)\s*\{\\([A-Za-z]+)\}'
    r'(?:\[\d+\])?\s*\{([^}]*)\}'
)
# \def\NAME{value}
_DEF_RE = re.compile(r'\\def\\([A-Za-z]+)\s*\{([^}]*)\}')


# ── Inline parameter extraction ───────────────────────────────────────────────

# Units relevant to ITk/ATLAS RE
_UNIT_PATTERN = (
    r'(?:Gbps?|Mbps?|kbps?|MHz|GHz|kHz|'
    r'Gbit/s|Mbit/s|kbit/s|Gbs?|Mbs?|kbs?|'
    r'bits?|bytes?|[kKMG]?[Bb](?:it|yte)?s?|'
    r'ns|µs|us|ms|ps|'
    r'TB?|GB?|MB?|kB?|'
    r'V|mV|A|mA|'
    r'links?|e-?links?|fibre?s?|channels?|fibres?|'
    r'registers?|chips?|modules?|hybrids?|staves?|petals?)'
)

_PARAM_RE = re.compile(
    r'(\d+(?:[.,]\d+)?)\s*(' + _UNIT_PATTERN + r')\b',
    re.IGNORECASE
)

# \textbf{label} description patterns — separator is optional (colon may be inside braces)
_LABELED_ITEM_RE = re.compile(
    r'\\textbf\{([^}]+)\}(?:\s*[:{])?\s*([^\n]{5,})',
    re.MULTILINE
)


# ── Main class ────────────────────────────────────────────────────────────────

class LatexReExtractor:
    """
    Extracts RE-relevant content from a LaTeX ASIC/firmware specification.

    Build with LatexReExtractor.from_path(path) or
    LatexReExtractor.from_tar(tar_path, member_name).
    """

    def __init__(self, source: str, text: str) -> None:
        self._source = source
        self._raw = text
        self._plain_cache: Optional[str] = None

    # ── Construction ──────────────────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: str) -> "LatexReExtractor":
        """Parse a .tex file from disk."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(path)
        text = p.read_text(encoding="utf-8", errors="replace")
        return cls(str(path), text)

    @classmethod
    def from_tar(cls, tar_path: str, member: str) -> "LatexReExtractor":
        """
        Parse a .tex file from inside a .tar.gz archive without extraction.

        *member* is the name of the .tex file within the archive.
        """
        with tarfile.open(tar_path) as t:
            f = t.extractfile(member)
            if f is None:
                raise KeyError(f"{member} not found in {tar_path}")
            text = f.read().decode("utf-8", errors="replace")
        return cls(f"{tar_path}::{member}", text)

    @classmethod
    def from_text(cls, text: str, label: str = "<inline>") -> "LatexReExtractor":
        """Build from a string (useful for testing)."""
        return cls(label, text)

    # ── Plain text ────────────────────────────────────────────────────────────

    def raw(self) -> str:
        """Full raw LaTeX source."""
        return self._raw

    def text(self) -> str:
        """Full plain text with LaTeX markup stripped."""
        if self._plain_cache is None:
            self._plain_cache = _strip_latex(self._raw)
        return self._plain_cache

    # ── Structural extraction ─────────────────────────────────────────────────

    def sections(self) -> List[LatexSection]:
        """
        All sections in document order, with plain-text title and body.

        Body text is the content between this section heading and the
        next heading of the same or higher level.
        """
        # Find all section headings with their positions
        hits: List[Tuple[int, str, str]] = []  # (pos, kind, title)
        for m in _SECTION_RE.finditer(self._raw):
            kind = m.group(1)
            title = _strip_latex(m.group(2))
            hits.append((m.end(), kind, title))

        sections: List[LatexSection] = []
        for i, (pos, kind, title) in enumerate(hits):
            level = _LEVEL_MAP.get(kind, 3)
            # Body runs from this heading end to the next heading start
            if i + 1 < len(hits):
                next_start = self._raw.rfind('\\', 0, hits[i + 1][0])
                # Find the start of the next section command
                m_next = _SECTION_RE.search(self._raw, pos)
                body_end = m_next.start() if m_next else len(self._raw)
            else:
                body_end = len(self._raw)
            body = _strip_latex(self._raw[pos:body_end])
            sections.append(LatexSection(level=level, kind=kind,
                                         title=title, body=body))
        return sections

    # ── Command definitions ───────────────────────────────────────────────────

    def commands(self) -> Dict[str, str]:
        """
        All \\newcommand, \\renewcommand, and \\def definitions.

        Returns {NAME: value_text} where value_text is stripped of LaTeX markup.
        Last definition wins on redefined commands.
        """
        result: Dict[str, str] = {}
        for m in _NEWCMD_RE.finditer(self._raw):
            result[m.group(1)] = _strip_latex(m.group(2))
        for m in _DEF_RE.finditer(self._raw):
            result[m.group(1)] = _strip_latex(m.group(2))
        return result

    # ── Table extraction ──────────────────────────────────────────────────────

    def tables(self) -> List[LatexTable]:
        """All tabular environments as LatexTable objects."""
        results = []
        for m in _TABULAR_RE.finditer(self._raw):
            rows = _parse_tabular(m.group(2))
            if rows:
                # Look backward for a \caption{...}
                preceding = self._raw[max(0, m.start() - 400):m.start()]
                cap_m = re.search(r'\\caption\{([^}]*)\}', preceding)
                caption = _strip_latex(cap_m.group(1)) if cap_m else ""
                results.append(LatexTable(rows=rows, caption=caption))
        return results

    # ── Inline parameter extraction ───────────────────────────────────────────

    def parameters(self) -> List[Tuple[str, str, str]]:
        """
        All inline numeric parameters with units.

        Returns list of (value, unit, context_line) tuples where context_line
        is the stripped text of the sentence containing the parameter.

        Example: ('640', 'Mb', '640Mb serial e-links to the GBTx(s) at the EoS')
        """
        results = []
        seen: set = set()
        for line in self._raw.splitlines():
            plain = _strip_latex(line)
            for m in _PARAM_RE.finditer(line):
                key = (m.group(1), m.group(2).lower().rstrip('s'))
                if key not in seen:
                    seen.add(key)
                    results.append((m.group(1), m.group(2), plain.strip()))
        return results

    # ── Labeled item extraction ───────────────────────────────────────────────

    def labeled_items(self) -> List[Tuple[str, str]]:
        """
        \\textbf{label}: description pairs from itemize/enumerate lists.

        Returns [(label, description_plain_text)] in document order.
        """
        results = []
        for m in _LABELED_ITEM_RE.finditer(self._raw):
            label = m.group(1).strip()
            desc = _strip_latex(m.group(2).strip())
            results.append((label, desc))
        return results

    # ── Reporting ─────────────────────────────────────────────────────────────

    def report(self) -> str:
        """One-block summary of extracted content."""
        secs = self.sections()
        cmds = self.commands()
        tbls = self.tables()
        params = self.parameters()
        items = self.labeled_items()
        lines = [
            f"LatexReExtractor: {self._source}",
            f"  raw lines         : {self._raw.count(chr(10))}",
            f"  sections          : {len(secs)}",
            f"  \\newcommand/\\def  : {len(cmds)}",
            f"  tabular tables    : {len(tbls)}",
            f"  inline parameters : {len(params)}",
            f"  labeled items     : {len(items)}",
        ]
        if params:
            lines.append("  Parameters (sample):")
            for val, unit, ctx in params[:8]:
                lines.append(f"    {val} {unit:<12} {ctx[:60]}")
        if cmds:
            lines.append("  Commands (sample):")
            for name, val in list(cmds.items())[:8]:
                lines.append(f"    \\{name} = {val[:50]}")
        return "\n".join(lines)
