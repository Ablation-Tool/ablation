# EcuConescanParser

**File:** `ablation/analyzers/ecu_conescan_parser.py`

---

## Why this exists

3 things that were not possible before in Ablation:

**1. No conescan format support.** The ConnorRigby conescan project carries ECU definitions for
Mazda Renesis and L8 engines on SH705x and SH7055 MCUs. The MX5 definition file alone covers 507
calibration tables (117 MAP, 107 CURVE, 283 VALUE) across every subsystem: drive-by-wire throttle,
cruise control, idle speed, fuel injection, ignition advance, and VTCS valve control. Without a
parser for this format, all of those addresses and labels were inaccessible to Ablation.

**2. No global named scaling dictionary.** The conescan format separates scaling objects from table
definitions by name. A table entry carries `scaling="758256"` and the file holds a top-level
`<scaling name="758256" storagetype="float" endian="big" toexpr="x" .../>`. The same scaling name
can be referenced by multiple tables that share a common physical unit or range. Parsing tables
without first building a keyed scaling dictionary produces objects with no unit, no scale, and no
endianness. This parser builds the dictionary in one pass before processing any table element.

**3. No single-ROM format path.** RomRaider MS43/MS45 definitions use a base/variant split: one
`<rom>` defines structure, another supplies addresses. Conescan definitions embed all addresses
inline in a single `<rom>` element with no variant inheritance. A parser that expects the two-pass
RomRaider model fails silently on conescan files. `EcuConescanParser` handles both `<rom>` as the
document root and `<roms>/<rom>` wrapping so it parses either layout without caller configuration.

---

## Format overview

Each conescan file is a single `<rom>` element (or a `<roms>` wrapper with one child `<rom>`).

**`<romid>`** carries ECU metadata: `xmlid`, `internalidaddress` (hex without `0x`),
`internalidstring`, `memmodel`, `make`, `model`.

**`<scaling>`** elements define named scaling objects: `name`, `storagetype`, `endian`, `toexpr`
(physical from raw expression), `units`.

**`<table>`** elements define calibration objects: `name`, `type` (1D/2D/3D), `address` (hex
without `0x`), `elements` (count), `scaling` (name reference), `category`.

```xml
<rom>
  <romid>
    <xmlid>LFG2EE</xmlid>
    <internalidaddress>b8046</internalidaddress>
    <internalidstring>LFG2EE</internalidstring>
    <memmodel>SH7058</memmodel>
    <make>Mazda</make>
    <model>MX5</model>
  </romid>

  <scaling name="RPM_ID" storagetype="float" endian="big"
           toexpr="x" frexpr="x" units="rpm" />
  <scaling name="TORQUE_ID" storagetype="float" endian="big"
           toexpr="x" frexpr="x" units="Nm" />

  <!-- VALUE: 1 element, no axis children -->
  <table name="Idle RPM Target" type="1D" category="Idle"
         address="6da68" elements="1" scaling="RPM_ID" />

  <!-- CURVE: 39 data elements, one Y Axis child -->
  <table name="CC Sensitivity" type="2D" category="DBW"
         address="b91f0" elements="39" scaling="TORQUE_ID">
    <table name="VSS" address="b9154" elements="39"
           scaling="VSS_ID" type="Y Axis" />
  </table>

  <!-- MAP: X*Y data elements, X Axis + Y Axis children -->
  <table name="CC Target APP" type="3D" category="DBW"
         address="ba2a0" elements="54" scaling="TORQUE_ID">
    <table name="GEAR" address="ba288" elements="6"
           scaling="GEAR_ID" type="X Axis" />
    <table name="VSS" address="ba264" elements="9"
           scaling="VSS_SPD" type="Y Axis" />
  </table>
</rom>
```

### XML type to CalibrationTable type

| XML `type` | CalibrationTable `table_type` | Dimensions |
|---|---|---|
| `1D` | `VALUE` | `rows=1, cols=elements` |
| `2D` | `CURVE` | `rows=1, cols=elements` |
| `3D` | `MAP` | `rows=Y_Axis.elements, cols=X_Axis.elements` |

For MAP tables, the parent `elements` attribute equals `rows * cols` but the parser derives
dimensions from the axis child `elements` attributes, not the parent count.

---

## Usage

```python
from ablation.analyzers.ecu_conescan_parser import EcuConescanParser

parser = EcuConescanParser.from_file("lfg2ee.xml")
print(parser.summary())

rom = open("LFG2EE_stock.bin", "rb").read()
if parser.identify_rom(rom):
    tables = parser.calibration_tables()
    for t in tables:
        print(f"0x{t.address:08X}  {t.table_type:5s}  {t.rows}x{t.cols}  {t.name}")

    for offset, name in parser.label_map().items():
        ctx.set_name(offset, name, source="conescan")
```

---

## API reference

### `EcuConescanParser.from_file(path)`

Parse a conescan ECU definition XML file. Raises `xml.etree.ElementTree.ParseError` on malformed
XML. Raises `FileNotFoundError` when the path does not exist.

### `identify_rom(rom, search_window=32) -> bool`

Return `True` when `rom` contains `internalidstring` within `±search_window` bytes of
`internalidaddress`. Both the string and the address come from `<romid>`.

Returns `False` when `internalidstring` is absent from the XML or when the search misses.

### `calibration_tables() -> list[CalibrationTable]`

Return all parsed `CalibrationTable` objects. Tables with no valid `address` attribute are omitted.
Malformed table elements are silently skipped so one bad entry does not abort the whole file.

### `label_map() -> dict[int, str]`

Return `{file_offset: label}` for all tables and axes. Pass entries to
`ctx.set_name(offset, name, source="conescan")`.

### `summary() -> str`

Return a text block with ECU metadata and table type counts.

---

## Validated results

### Mazda MX5 SH7058 (lfg2ee.xml)

```
Conescan  lfg2ee.xml
  rom      : LFG2EE  Mazda MX5  SH7058
  tables   : 507 total (117 MAP  107 CURVE  283 VALUE)
  scalings : 829 named
```

All 117 MAPs have both X and Y axis objects with correct element counts and file addresses.
Sample MAP (`CC Target APP - Base`): 9 rows (Y axis, 9 speed breakpoints) x 6 cols (X axis,
6 gear positions). Data address `0xBA2A0`, X axis at `0xBA288`, Y axis at `0xBA264`.

### Mazda RX8 SH7055 (N3K1EU000.xml)

The community RX8 definition file is a minimal example with 2 named scalings and 1 CURVE table.
The ROM `SW-N3K1EU00013SN020.bin` (512 KB) identifies correctly. A second RX8 ROM
`JM1FE173250150913-N3ZBEH00013H6020.bin` (512 KB) does not identify: the ECU ID string
`N3K1EU000` is absent from that image; it carries a different firmware variant (`N3ZBEH000`).

---

## Differences from EcuRomRaiderParser

| Aspect | EcuConescanParser | EcuRomRaiderParser |
|---|---|---|
| Variants per file | One (single ROM) | Many (base + 1 to N variants) |
| Address source | Inline on every table | Variant `<rom>` overlay on base |
| Scaling definition | Global named `<scaling>` | Inline `<scaling>` inside each `<table>` |
| `identify_rom()` return type | `bool` | `Optional[str]` (variant xmlid) |
| XML type attribute | `1D / 2D / 3D` | `VALUE / 2D / 3D` (no 1D) |
| Expression field | `toexpr=` | `expression=` |

---

## Limitations

- **Identification by string only.** When a ROM variant carries the same `internalidstring` at a
  different offset, `identify_rom()` returns `False` even for a genuine match. No fallback address
  search is implemented for the single-ROM format.

- **Minimal RX8 definition.** The community RX8 XML covers only 1 CURVE table. Most RX8 calibration
  analysis still requires an XDF file or manual address lookup.

- **Non-linear `toexpr` expressions.** Expressions not matching the linear forms in `_expr_to_linear()`
  return `scale=0.0` as a sentinel. The table is still parsed and returned; only scaling is absent.

- **3D table with missing axis child.** A `type="3D"` table whose XML is missing either the
  `<table type="X Axis">` or `<table type="Y Axis">` child is silently skipped. Degenerate MAP
  entries in community definition files are discarded rather than returned with incorrect dimensions.
