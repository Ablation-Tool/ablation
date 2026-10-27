# DocxReExtractor

  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [DocxReExtractor](#docxreextractor-1)
  - [Usage](#usage)
  - [Example output](#example-output)
  - [Known targets](#known-targets)
  - [See also](#see-also)

**File:** `ablation/analyzers/docx_re_extractor.py`

---

## Why this exists <sup>[↑](#docxreextractor)</sup>

1. **ASIC specifications live in Word documents.** The HCC Specification V1.3.1 is a `.docx` file with 198 paragraphs and 13 tables. Register maps, bit-field definitions, and protocol constants are in tables with columns like `Bit#`, `Default`, `Function`. These can't be grepped or fed to VerilogSemantic.

2. **OOXML has two structural traps that naive tag-stripping fails.** First, run-split text: OOXML splits runs mid-word for spell-check and revision tracking. `"tran" + "smit"` → `"transmit"` only if runs are concatenated without a separator. Second, wrapper tables: HDL-generated register maps in the HCC spec are stored as an outer `<w:tbl>` with 1 row → 1 cell → nested inner `<w:tbl>` holding the actual data. A single-level table traversal produces a one-row table with all content in a single cell blob.

3. **No third-party dependencies.** `zipfile` and `xml.etree.ElementTree` are stdlib. `python-docx` is not available in the ablation environment.

---

## How it works <sup>[↑](#docxreextractor)</sup>

A `.docx` is a ZIP containing `word/document.xml`. The extractor:

1. Opens the ZIP, reads `word/document.xml`, parses with `ET.fromstring()`.
2. Walks `<w:body>` direct children, separating `<w:p>` (paragraphs) and `<w:tbl>` (tables) in document order.
3. **Paragraph extraction**: concatenates all `<w:t>` text across runs, respecting `xml:space="preserve"`. Detects bold from `<w:b/>` in `<w:rPr>`.
4. **Table extraction via `_extract_table_rows()`**: detects the wrapper-table pattern (1 outer row, 1 cell, 1 nested `<w:tbl>`) and recursively unwraps to the inner table. Normal tables extract rows directly.
5. **`register_tables()`**: filters tables whose header row contains any of: `bit`, `bits`, `bit#`, `field`, `function`, `description`, `default`, `reset`, `register`, `address`.
6. **`constants()`**: mines `CAPS_NAME = value` / `CAPS_NAME: value` patterns from paragraph text, plus `{Function: Default}` pairs from register table rows.

---

## DocxReExtractor <sup>[↑](#docxreextractor)</sup>

```python
from ablation.analyzers.docx_re_extractor import DocxReExtractor

ext = DocxReExtractor.from_path('/path/to/spec.docx')
```

**Key methods:**

| Method | Returns | Notes |
|---|---|---|
| `from_path(path)` | `DocxReExtractor` | Raises `FileNotFoundError` if missing |
| `text()` | `str` | Full document text, `\n`-separated paragraphs |
| `paragraphs()` | `List[DocxParagraph]` | Each has `.text`, `.is_bold`, `.style`, `.runs` |
| `bold_sections()` | `List[str]` | Text of bold paragraphs (section headers) |
| `tables()` | `List[DocxTable]` | All tables, wrapper-unwrapped |
| `register_tables()` | `List[DocxTable]` | Tables with bit/field/register columns |
| `constants()` | `Dict[str, str]` | Named constants from text + table defaults |
| `report()` | `str` | Summary: counts + register table list |

**DocxTable fields:**

| Field | Type | Notes |
|---|---|---|
| `.rows` | `List[List[str]]` | All rows including header |
| `.header` | `List[str]` | First row (property) |
| `.data_rows` | `List[List[str]]` | Rows after header (property) |
| `.preceding_heading` | `str` | Bold paragraph immediately before the table |
| `.is_register_table()` | `bool` | True if header contains bit/field keywords |

---

## Usage <sup>[↑](#docxreextractor)</sup>

**Extract register maps from an ASIC spec:**

```python
from ablation.analyzers.docx_re_extractor import DocxReExtractor

ext = DocxReExtractor.from_path(
    '/media/cowboy/research/facility/asic/hcc/HCC_Specification_V1.3.1_Oct_3.docx'
)
for tbl in ext.register_tables():
    print(f"--- {tbl.preceding_heading} ---")
    print(tbl.header)
    for row in tbl.data_rows:
        print(row)
```

**Search full text for protocol constants:**

```python
import re
text = ext.text()
# Find all hex literals
for m in re.finditer(r'0x[0-9a-fA-F]+', text):
    print(m.group(0))
```

**Get constants dict (named assignments + register defaults):**

```python
consts = ext.constants()
# Returns: {'L0_CMD': '0x05', 'Use': '0', 'Enable': '1', ...}
```

---

## Example output <sup>[↑](#docxreextractor)</sup>

```
DocxReExtractor: HCC_Specification_V1.3.1_Oct_3.docx
  paragraphs        : 198
  bold paragraphs   : 104
  tables total      : 13
  register tables   : 10
    Function  (COMMANDS) | Steps | R/W | bits | Purpose [(not clear ...)] (11 rows)
    Bit  |  | Description  [Status Registers] (6 rows)
    Bit # | Function | Default | Description  [@#1 Bit Controlled Functions] (19 rows)
    Bit# | Default | Function  [@#2 Driver Current / GPIO R] (9 rows)
    ...
```

Register table 2 data rows (Control Register 1):

```
['0',  'Use PLL Clock',           '0', '=0  use incoming clock on HCC']
['1',  'Power on/off FEICs',      '0', '=1  for FEIC regulators enabled (ON)']
['2',  'Stave Data Rate Set',     '0', '=0 for 160Mbps  = 1 for 320Mbps']
['3',  'Data Driver 1 Enable',    '1', '=1 for enable']
```

---

## Known targets <sup>[↑](#docxreextractor)</sup>

| File | Register tables | Key content |
|---|---|---|
| `asic/hcc/HCC_Specification_V1.3.1_Oct_3.docx` | 10 | CR1 bit map (25 bits), status register, driver current registers, delay control, monitor limits |

---

## See also <sup>[↑](#docxreextractor)</sup>

- `re/atlas/hcc_re.py` — HCC constants sourced from this extractor
- `LatexReExtractor` — for TDR-style LaTeX documents (registers, parameters)
- `DocxParagraph`, `DocxTable` — data classes returned by the extractor
