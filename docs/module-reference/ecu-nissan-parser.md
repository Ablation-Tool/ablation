# EcuNissanParser

**File:** `ablation/analyzers/ecu_nissan_parser.py`

---

## Why this exists

4 things that were not possible before in Ablation:

**1. No Pytrex Nissan format support.** Pytrex NissanDefinitions is the primary open-source
calibration definition set for Nissan SH705x ECUs, covering the 350Z, G35, Altima, Maxima,
Sentra, Stagea, Skyline, Murano, and 11 other models across 188 ECU variants. The format uses a
three-file inheritance architecture that no other parser handles: a shared ScalingData.xml scaling
library, an A2L.xml master structure file, and per-variant XML overlays that carry ROM addresses.
Without a parser for this format, all 188 variants and their calibration objects were inaccessible.

**2. No shared scaling library resolution.** The Pytrex format stores scaling expressions in a
central ScalingData.xml rather than inline with each table. A table entry carries only a scaling
name (`<scaling base="BFS (x*0.000488)"/>`); the expression and unit are resolved from the
library. A parser that reads only the address overlay XML produces CalibrationTable objects with
scale=0.0 and no unit for every entry. This parser loads the scaling library first and resolves
each table's scaling by name before building any CalibrationTable.

**3. No three-level inheritance resolution.** Variants form a base chain: a terminal variant
(e.g., CD001) references an intermediate variant (CD515), which references the structure root
(A2L). A variant with no table entries of its own inherits all entries from its ancestor chain.
This parser walks the chain child-first, so a variant can override specific ancestor addresses
without re-specifying all of them. The walk terminates at base="A2L" or when a base xmlid is
not found in the loaded set.

**4. No tolerant XML parsing for truncated files.** ScalingData.xml is 810 lines and missing
its closing root tag, causing ET.parse to raise ParseError on every load. This parser detects
the root element name from the file's opening tag and synthesizes the missing close tag before
re-parsing, recovering all 273 scaling definitions from a file that standard parsers reject.

---

## Format overview

The Pytrex NissanDefinitions directory layout:

```
Nissan Definitions/
  ScalingData.xml          -- shared scaling library (273 entries)
  A2L.xml                  -- master table structure (188 tables + 46 bitwise)
  350Z/
    CD515.xml              -- base variant: <rom base="A2L">  (125 addr entries)
    CD001.xml              -- leaf variant: <rom base="CD515"> (0 own entries)
    CD415.xml              -- leaf variant with axis addresses
    ...
  G35/
    CF92A.xml
    ...
```

### ScalingData.xml

Each `<scalingbase>` entry carries a name, expression, and unit:

```xml
<scalingbase name="BFS (x*0.000488)" units="ms" expression="x*0.000488"
             to_byte="x/0.000488" format="0.000" .../>
```

The `expression=` field is a linear formula in `x`. Supported forms:

| Form | scale | bias |
|---|---|---|
| `x` | 1.0 | 0.0 |
| `x*k` | k | 0.0 |
| `k*x` | k | 0.0 |
| `x/k` | 1/k | 0.0 |
| `x*k+b` or `(x*k)+b` | k | b |
| `x+b` or `x-b` | 1.0 | b or -b |
| Non-linear (e.g., `1881.6/x`) | 0.0 sentinel | 0.0 |

A scale of `0.0` is the sentinel for "scaling unavailable." The table is still returned with
all address and dimension information; only the unit conversion is absent.

### A2L.xml

Each `<table>` element is a top-level calibration object. The `type=` attribute sets the
table class:

| type | table_type | rows | cols |
|---|---|---|---|
| `1D` | `VALUE` | 1 | 1 |
| `2D` | `CURVE` | 1 | sizex |
| `3D` | `MAP` | sizey | sizex |
| `BitwiseSwitch` | skipped | — | — |

Child `<table>` elements describe axes:

| child type | description |
|---|---|
| `Static X Axis` | constant breakpoints in A2L.xml; address=None in CalibrationAxis |
| `Static Y Axis` | same, Y direction |
| `X Axis` | dynamic breakpoints; address comes from variant overlay |
| `Y Axis` | same, Y direction |

Static axes carry inline `<data>` elements. Dynamic axes carry their storagetype and scaling
reference but no data; their ROM address is supplied by the variant overlay.

### Variant XMLs

Each variant XML carries a `<rom base="...">` attribute and a `<romid>` block. The `base=`
attribute names either another variant xmlid or `A2L` (the structure root). Address entries
are direct children of `<rom>`:

```xml
<rom base="A2L">
  <romid>
    <xmlid>CD515</xmlid>
    <internalidaddress>828C</internalidaddress>  <!-- hex, no 0x prefix -->
    <internalidstring>CD515</internalidstring>
    <endian>Big</endian>
    ...
  </romid>
  <table name="Fuel Compensation Map (16x16)" storageaddress="0x6C09">
    <table type="X Axis" storageaddress="0x836D"/>
    <table type="Y Axis" storageaddress="0x8311"/>
  </table>
  ...
</rom>
```

Axis address children are optional. When absent, dynamic axes are returned with address=None.

---

## Usage

```python
from ablation.analyzers.ecu_nissan_parser import EcuNissanParser

# Load the full definitions directory
parser = EcuNissanParser.from_dir("/path/to/Nissan Definitions")
print(parser.summary())

# List all available variants
for vid in parser.variants():
    print(vid)

# Get calibration tables for one variant
tables = parser.calibration_tables("CD515")
for t in tables:
    print(f"0x{t.address:05X}  {t.table_type:5s}  {t.rows}x{t.cols}  {t.scale}  {t.name}")

# Inject into BinaryContext
for offset, name in parser.label_map("CD515").items():
    ctx.set_name(offset, name, source="nissan-pytrex")

# Identify a ROM image
with open("rom.bin", "rb") as fh:
    rom = fh.read()
variant_id = parser.identify_rom(rom)
```

---

## API reference

### `EcuNissanParser.from_dir(definitions_dir)`

Load all definitions from a Pytrex NissanDefinitions directory. Reads ScalingData.xml and
A2L.xml from the top level, then walks all subdirectories loading variant XML files.
Malformed files and individual load errors are silently skipped. ScalingData.xml is loaded
tolerantly: a missing root close tag is recovered by synthesizing the correct close tag
before re-parsing.

### `calibration_tables(variant_id) -> list[CalibrationTable]`

Return CalibrationTable objects for one variant. Resolves the inheritance chain to build
a merged address map (child overrides ancestor), then combines structure from A2L.xml and
scaling from ScalingData.xml. Tables not present in the merged address chain are omitted.
BitwiseSwitch tables are always omitted.

### `variants() -> list[str]`

Return all loaded variant xmlid strings, sorted.

### `identify_rom(rom: bytes) -> Optional[str]`

Return the variant xmlid whose `internalidstring` matches `rom` at `internalidaddress`.
Returns None when no variant matches. The `internalidaddress` field is interpreted as a hex
integer (with or without `0x` prefix).

### `label_map(variant_id) -> dict[int, str]`

Return `{file_offset: label}` for all tables and their axes for a variant. Pass entries to
`ctx.set_name(offset, name, source="nissan-pytrex")`.

### `summary() -> str`

Return a text block with scaling count, table definition breakdown, and loaded variant count.

---

## Validated results

### 350Z corpus

```
Nissan Pytrex definitions
  scalings   : 273
  table defs : 188 total (46 BITWISE  69 CURVE  37 MAP  36 VALUE)
  variants   : 188
```

| Variant | Model | Tables | Axis addresses |
|---|---|---|---|
| CD515 | 350Z 2003 AT USDM | 55 | — |
| CD001 | 350Z 2003 MT USDM (inherits CD515) | 55 | — |
| CD415 | 350Z | 39 | X Axis + Y Axis per MAP |
| CF42A | 350Z (largest) | 132 | mixed |
| CF92A | G35 | 79 | — |

Sample MAP table from CD415: `Fuel Compensation Map (16x16)` at data=0x6C09,
x_axis=0x836D, y_axis=0x8311, scale=0.78125, unit=`Compensation (%)`.

### Model coverage

| Model | Variants |
|---|---|
| 350Z | 52 |
| G35 | 36 |
| Maxima | 24 |
| Sentra | 16 |
| Altima | 14 |
| Skyline | 8 |
| Tiida + Teana | 12 |
| Other | 26 |

---

## Differences from other ECU parsers

| Aspect | EcuNissanParser | EcuRomRaiderParser | EcuXDFParser |
|---|---|---|---|
| Format | Pytrex Nissan XML | RomRaider XML | TunerPro XDF |
| Scaling source | ScalingData.xml library | expression= attribute | MATH equation |
| Structure source | A2L.xml master | base XML | XDF file |
| Address source | variant XML overlays | variant XML overlays | XDF file |
| Inheritance depth | 3 levels (library + structure + address) | 2 levels (base + variant) | 1 level |
| Identify ROM | internalidstring byte match | internalidstring byte match | Not supported |
| Byte order source | endian= in romid | endian= attribute | lsbfirst in DEFAULTS |
| Axis addresses | optional per-table child elements | separate X/Y Axis table entries | EMBEDDEDDATA attributes |

---

## Limitations

- **Static axis values not stored.** Static axis breakpoints (inline `<data>` elements in
  A2L.xml) are counted for `CalibrationAxis.count` but not stored in the CalibrationAxis
  object. The physical breakpoint values require reading A2L.xml separately.

- **Dynamic axis addresses optional.** When a variant does not supply axis addresses (most
  CD5xx entries), `CalibrationAxis.address` is None for dynamic axes. The table data address
  is always present when the table itself appears in the merged chain.

- **Non-linear expressions produce scale=0.0.** Expressions like `1881.6/x` (reciprocal AFR
  formula) are non-linear and produce scale=0.0 as a sentinel. The table is still returned
  with address and dimension data intact.

- **BitwiseSwitch tables omitted.** The 46 BitwiseSwitch tables in A2L.xml are not returned
  by `calibration_tables()`. They describe bitmask configuration registers, not numeric
  calibration maps.
