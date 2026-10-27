# LatexReExtractor

  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [LatexReExtractor](#latexreextractor-1)
  - [Usage](#usage)
  - [Example output](#example-output)
  - [Known targets](#known-targets)
  - [See also](#see-also)

**File:** `ablation/analyzers/latex_re_extractor.py`

---

## Why this exists <sup>[↑](#latexreextractor)</sup>

1. **ATLAS ITk TDR documents are LaTeX.** The Strip Detector Technical Design Report is distributed as `.tar.gz` archives containing `.tex` source. Architecture parameters — link speeds, buffer depths, ASIC counts — are embedded in prose paragraphs, not in a register table or header file. `grep` finds them, but without context or structure. `LatexReExtractor` returns `(value, unit, context_line)` triples so parameters can be cross-verified against VHDL reset values and DOCX register maps.

2. **Other spec documents use `\newcommand` to define protocol constants.** `\newcommand{\GbtFrameWidth}{120}` is a machine-readable constant definition that `grep` turns into noise. The extractor surfaces it as `{"GbtFrameWidth": "120"}` alongside constants from DOCX and VHDL sources.

3. **Register-map PDFs sometimes originate as LaTeX `tabular` environments.** When the upstream source is LaTeX, the extractor recovers structured rows with header detection — the same information a `DocxReExtractor` gets from Word documents, but from the LaTeX source before it becomes PDF.

4. **No LaTeX engine required.** Proper LaTeX is Turing-complete (macros expand recursively). For firmware spec RE the useful content is flat: `\newcommand` with literal values, `tabular` with aligned columns, prose sentences with numeric units. Regex on the flat source captures these without installing TeX Live or writing a macro expander.

---

## How it works <sup>[↑](#latexreextractor)</sup>

### `_strip_latex(text)`

Strips LaTeX markup to approximate plain text in five passes:

1. **Comments**: `%[^\n]*` → empty (LaTeX comments run to end of line).
2. **Display math**: `$$...$$` → space (preserves surrounding sentence structure).
3. **Inline math**: `$...$` → `?` (placeholder keeps word boundaries; `"at $N \times 40$~MHz"` → `"at ?~MHz"` still matches the MHz unit).
4. **Drop commands**: `\ref{...}`, `\cite{...}`, `\label{...}`, `\includegraphics{...}` → empty.
5. **Keep-arg commands**: `\textbf{X}`, `\textit{X}`, `\emph{X}` → `X`.
6. **Lone commands**: `\LaTeX`, `\hspace` etc. → space.
7. **Brace collapse**: remaining `{` and `}` → empty.

### Section extraction

`_SECTION_RE` matches `\section`, `\subsection`, `\subsubsection`, `\paragraph`, `\subparagraph` with an optional `*`. Each match records `(end_pos, kind, title)`. The body of section `i` runs from `end_pos[i]` to the start of the next section command — sliced from raw text and stripped. The `_LEVEL_MAP` assigns numeric depth: `section=2`, `subsection=3`, `subsubsection=4`, `paragraph=5`.

### Command extraction

`_NEWCMD_RE` matches `\newcommand{\NAME}{value}`, `\renewcommand`, and `\providecommand`, with an optional `[N]` argument-count spec that is skipped. `_DEF_RE` matches `\def\NAME{value}`. Both extract NAME as the key and strip-latex the value. Last definition of a name wins (redefined commands).

**Limitation:** Value argument is `{([^}]*)}` — does not handle nested braces in the value (e.g., `\newcommand{\Foo}{\textbf{bar}}`). For firmware specs this is not a problem — constant definitions use literal numbers or simple strings.

### Table extraction

`_TABULAR_RE` matches `\begin{tabular}{spec}...body...\end{tabular}` with DOTALL. `_parse_tabular(body)`:

1. Strips `\hline` and `\cline{...}` (border markup).
2. Expands `\multirow{n}{w}{text}` and `\multicolumn{n}{spec}{text}` to just their text content.
3. Splits on `\\` (row separator), then on `&` (cell separator).
4. Strips LaTeX from each cell.
5. Discards rows where all cells are empty.

Caption is searched in the 400 characters preceding the `\begin{tabular}` and returned as `LatexTable.caption`.

### Parameter extraction

`_PARAM_RE` matches `(\d+(?:[.,]\d+)?)\s*(unit)\b` where the unit alternation covers:

- **Link rates**: `Gbps`, `Mbps`, `kbps`, `MHz`, `GHz`, `kHz`, `Gbit/s`, `Mbit/s`
- **Compact notation**: `Gb`, `Mb`, `kb`, `Gbs`, `Mbs`, `kbs`
- **Sizes**: `bits`, `bytes`, `kB`, `MB`, `GB`, `TB`
- **Time**: `ns`, `µs`, `us`, `ms`, `ps`
- **Power**: `V`, `mV`, `A`, `mA`
- **Counts**: `links`, `e-links`, `fibres`, `channels`, `registers`, `chips`, `modules`, `hybrids`, `staves`, `petals`

Deduplication: `(value, unit.lower().rstrip('s'))` as key — `"640 Mb"` and `"640 Mb"` on two lines produce one entry. The context line is the stripped plain text of the line containing the parameter.

### Labeled item extraction

`_LABELED_ITEM_RE` matches `\textbf{label}` followed by an optional `:` or `{` separator, then at least 5 non-newline characters of description. The separator is optional because TDR documents put the colon inside the braces (`\textbf{DCS data:}`) while other documents put it outside (`\textbf{DCS data}: description`). Both forms are captured.

---

## LatexReExtractor <sup>[↑](#latexreextractor)</sup>

```python
from ablation.analyzers.latex_re_extractor import LatexReExtractor

# From a .tex file on disk
ext = LatexReExtractor.from_path('/path/to/doc.tex')

# From a .tex file inside a .tar.gz archive — no extraction needed
ext = LatexReExtractor.from_tar('/path/to/doc.tar.gz', 'member.tex')

# From a string (tests, inline documents)
ext = LatexReExtractor.from_text(latex_source, label='doc.tex')
```

**Key methods:**

| Method | Returns | Notes |
|---|---|---|
| `from_path(path)` | `LatexReExtractor` | Raises `FileNotFoundError` if missing |
| `from_tar(tar_path, member)` | `LatexReExtractor` | Raises `KeyError` if member not in archive |
| `from_text(text, label)` | `LatexReExtractor` | Useful for testing |
| `raw()` | `str` | Full raw LaTeX source |
| `text()` | `str` | Plain text (LaTeX stripped, cached) |
| `sections()` | `List[LatexSection]` | All section/subsection headings with body text |
| `commands()` | `Dict[str, str]` | `\newcommand` / `\def` definitions |
| `tables()` | `List[LatexTable]` | All tabular environments |
| `parameters()` | `List[Tuple[str, str, str]]` | `(value, unit, context_line)` inline numeric params |
| `labeled_items()` | `List[Tuple[str, str]]` | `(label, description)` `\textbf{}` item pairs |
| `report()` | `str` | Summary: counts + sample parameters |

**LatexSection fields:**

| Field | Type | Notes |
|---|---|---|
| `.level` | `int` | 0=part, 1=chapter, 2=section, 3=subsection, 4=subsubsection, 5=paragraph |
| `.kind` | `str` | `'section'`, `'subsection'`, etc. |
| `.title` | `str` | Plain-text title (LaTeX stripped) |
| `.body` | `str` | Plain-text body up to the next section heading |

**LatexTable fields:**

| Field | Type | Notes |
|---|---|---|
| `.rows` | `List[List[str]]` | All rows including header |
| `.header` | `List[str]` | First row (property) |
| `.data_rows` | `List[List[str]]` | Rows after header (property) |
| `.caption` | `str` | `\caption{...}` text found before the table |

---

## Usage <sup>[↑](#latexreextractor)</sup>

**Extract architecture parameters from a TDR tarball:**

```python
from ablation.analyzers.latex_re_extractor import LatexReExtractor

ext = LatexReExtractor.from_tar(
    '/media/cowboy/research/facility/fw/tdr/tdr_readout_control_20160705.tar.gz',
    'tdr_readout_control_strips.tex'
)

for val, unit, ctx in ext.parameters():
    print(f"{val} {unit:12} — {ctx[:60]}")
```

Output:
```
8    chips        — On the detector, within a module, a hybrid hosts 10-14 ABC...
640  Mb           — 8B/10B encoded and transmitted via 640Mb serial e-links to...
10   Gb           — The LpGBTx aggregates up to 14 640Mb e-links onto a 10Gb...
14   e-links      — The LpGBTx aggregates up to 14 640Mb e-links onto a 10Gb...
```

**Extract `\newcommand` constants from a spec with defined constants:**

```python
consts = ext.commands()
# Returns: {'LinkSpeed': '640', 'NumChips': '10', ...}
```

**Extract register tables from a LaTeX spec:**

```python
for tbl in ext.tables():
    if tbl.caption:
        print(f"--- {tbl.caption} ---")
    print(tbl.header)
    for row in tbl.data_rows:
        print(row)
```

**Get all labeled items from a document:**

```python
for label, desc in ext.labeled_items():
    print(f"  {label}: {desc[:80]}")
```

**Navigate section hierarchy:**

```python
for sec in ext.sections():
    indent = "  " * (sec.level - 2)
    print(f"{indent}{sec.title} (level={sec.level})")
    # sec.body contains stripped prose of that section
```

---

## Example output <sup>[↑](#latexreextractor)</sup>

```
LatexReExtractor: tdr_readout_control_20160705.tar.gz::tdr_readout_control_strips.tex
  raw lines         : 192
  sections          : 9
  \newcommand/\def  : 0
  tabular tables    : 0
  inline parameters : 9
  labeled items     : 2
  Parameters (sample):
    8    chips        On the detector, within a module, a hybrid hosts 10-14
    640  Mb           8B/10B encoded and transmitted via 640Mb serial e-links
    10   Gb           The LpGBTx aggregates up to 14 640Mb e-links onto a 10G
    14   e-links      The LpGBTx aggregates up to 14 640Mb e-links onto a 10G
    4    bytes        Data sent from an HCC consists of variable length packet
    50   bytes        Data sent from an HCC consists of variable length packet
    100  links        Strips expects 4-8k GBT uplinks, and each FELIX is expec
    2    modules      So with 10 chips per barrel hybrid, 2 hybrids per module
```

Section titles (strips TDR):
```
  Strips Off-detector Readout/Control Electronics...  (level=3)
    Scope                                              (level=4)
    Strips Architecture                                (level=4)
    Strips-FELIX                                       (level=4)
    Strips-FELIX Functions                             (level=4)
      FE-frame interface, decoding:                    (level=5)
      Data-type handling:                              (level=5)
    Calibration                                        (level=4)
    Bandwidth Estimations                              (level=4)
    Link Architecture and FE protocols                 (level=4)
    L1Track Considerations                             (level=4)
```

Labeled items (strips TDR):
```
  DCS data:: This is considered high priority (although not critical) for det...
  L1Track data:: When a regional trigger is used, high priority data for L1Tr...
```

---

## Known targets <sup>[↑](#latexreextractor)</sup>

| File | Key content |
|---|---|
| `fw/tdr/tdr_readout_control_20160622.tar.gz::tdr_readout_control.tex` | Sections: FELIX, Data Handler, LTI, ITk Controller, Calibration; 640 Mb/s link speed, 10 Gb fibre |
| `fw/tdr/tdr_readout_control_20160705.tar.gz::tdr_readout_control_strips.tex` | Strips-specific: 640 Mb HCC e-links, 14 e-links per LpGBTx, 10 Gb optical, 100 links/FELIX; DCS and L1Track labeled items |
| `fw/tdr/tdr_readout_control_20160705.tar.gz::tdr_readout_control_common.tex` | Common ITk readout sections: FELIX, Data Handler, LTI, ITk Controller |

---

## See also <sup>[↑](#latexreextractor)</sup>

- `re/atlas/felix_re.py` — lpGBT elink map sourced in part from TDR parameters
- `DocxReExtractor` — for ASIC specs in `.docx` format (HCC, ABC130)
- `HdlHtmlExtractor` — for HDL Designer HTML exports
- `VerilogSemantic` — VHDL/Verilog constant and FSM extraction
