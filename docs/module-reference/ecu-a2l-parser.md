# EcuA2LParser

**File:** `ablation/analyzers/ecu_a2l_parser.py`

---

## Why this exists

4 things that were not possible before in Ablation:

**1. No A2L format support.** ASAM/ASAP2 A2L is the industry-standard ECU calibration description
format. Every major OEM and supplier uses it: Bosch (EDC16, EDC17, MED17), Continental, Delphi,
Siemens, Denso, ZF, and most others. A single EDC16U34 A2L file covers 11,427 calibration objects;
an EDC17CP46 covers 26,016. Without a parser, none of those addresses or labels were accessible to
Ablation for BinaryContext injection or calibration table scanning.

**2. No cross-ECU scaling resolution.** A2L separates COMPU_METHOD objects (which carry the
physical conversion formula) from RECORD_LAYOUT objects (which carry the byte layout and type) from
CHARACTERISTIC objects (which carry the ROM address and dimensions). A table entry carries only
names: it references a record layout by name and a compu method by name. Parsing the address
without resolving the cross-references produces a CalibrationTable with no unit, no scale, and no
type. This parser builds the COMPU_METHOD and RECORD_LAYOUT dictionaries in one pass before
processing any CHARACTERISTIC block.

**3. No RAT_FUNC coefficient reduction.** A2L COMPU_METHOD objects describe physical-to-raw
conversion using the RAT_FUNC formula: `physical = (a*x^2 + b*x + c) / (d*x^2 + e*x + f)`.
For the linear case (a=d=e=0), this reduces to scale=b/f, bias=c/f. Extracting scale and bias
from the six COEFFS values requires parsing the positional fields, detecting non-linear terms,
and handling the zero-denominator case. Without this reduction, all A2L tables would carry
scale=0.0 (the non-linear sentinel) even for the majority that are simple linear conversions.

**4. No A2ML / IF_DATA block stripping.** A2L files embed A2ML sub-grammar blocks (transport-layer
interface definitions) and IF_DATA blocks (INCA and CANape private data) using the same
`/begin ... /end` syntax as calibration blocks. A2ML blocks can contain `{}`, `()`, and `;`
characters that break a naive `/begin`-`/end` token counter. Not stripping these blocks first
causes the parser to miscount nesting depth and either skip legitimate CHARACTERISTIC blocks
or produce wrong extraction boundaries for the ones immediately after an A2ML block.

---

## Format overview

A2L is an ASCII text format encoded in Latin-1 (ISO 8859-1). C-style block comments
(`/* ... */`) are valid anywhere. The structure is:

```
/begin PROJECT name "description"
  /begin MODULE name "description"

    /begin COMPU_METHOD
        name "description" RAT_FUNC "format" "unit"
        COEFFS a b c d e f
    /end COMPU_METHOD

    /begin RECORD_LAYOUT name
        NO_AXIS_PTS_X  position SWORD
        AXIS_PTS_X     position SWORD  INDEX_INCR  DIRECT
        FNC_VALUES     position SWORD  COLUMN_DIR  DIRECT
    /end RECORD_LAYOUT

    /begin CHARACTERISTIC
        name "description" VALUE 0xADDR RecordLayout 0.0 CompuMethod -32768 32767
        [/begin AXIS_DESCR
            STD_AXIS InputQty CompuMethod max_axis_pts lower upper
        /end AXIS_DESCR]
    /end CHARACTERISTIC

  /end MODULE
/end PROJECT
```

### Supported COMPU_METHOD types

| Type | Scale | Bias | Behavior |
|---|---|---|---|
| `IDENTICAL` | 1.0 | 0.0 | physical = raw |
| `LINEAR` | b | a | physical = a + b * raw |
| `RAT_FUNC` (linear case) | b/f | c/f | physical = (b*raw + c) / f |
| `RAT_FUNC` (non-linear) | 0.0 sentinel | 0.0 | a, d, or e non-zero |
| All others | 0.0 sentinel | 0.0 | TAB_VERB, FORMULA, etc. |

A scale of `0.0` is the parser's sentinel for "scaling unavailable." The table is still returned
with all address and dimension information; only the unit conversion is absent.

### RECORD_LAYOUT types

| A2L keyword | bits | signed | is_float |
|---|---|---|---|
| `UBYTE` | 8 | no | no |
| `SBYTE` | 8 | yes | no |
| `UWORD` | 16 | no | no |
| `SWORD` | 16 | yes | no |
| `ULONG` | 32 | no | no |
| `SLONG` | 32 | yes | no |
| `FLOAT32_IEEE` | 32 | no | yes |
| `FLOAT64_IEEE` | 64 | no | yes |

### CHARACTERISTIC types

| A2L `type` | CalibrationTable `table_type` | Dimensions |
|---|---|---|
| `VALUE` | `VALUE` | `rows=1, cols=1` |
| `CURVE` | `CURVE` | `rows=1, cols=max_axis_pts` |
| `MAP` | `MAP` | `rows=Y_AXIS.max_axis_pts, cols=X_AXIS.max_axis_pts` |
| `CUBOID` and others | `MAP` | same as MAP (first two AXIS_DESCR blocks used) |

The `max_axis_pts` field in each AXIS_DESCR block is the upper bound for that axis. For
`STD_AXIS` tables (most common), the actual count is stored as an integer in the ROM image
at a fixed offset before the data. Use `EcuROMLayoutAnalyzer` to locate that offset if the
exact dimension matters.

---

## Usage

```python
from ablation.analyzers.ecu_a2l_parser import EcuA2LParser

parser = EcuA2LParser.from_file("edc16_13.a2l")
print(parser.summary())

tables = parser.calibration_tables()
for t in tables:
    print(f"0x{t.address:08X}  {t.table_type:5s}  {t.rows}x{t.cols}  {t.name}  [{t.unit}]")

for offset, name in parser.label_map().items():
    ctx.set_name(offset, name, source="a2l")
```

---

## API reference

### `EcuA2LParser.from_file(path)`

Parse an A2L file. Reads as Latin-1, falls back to UTF-8 with replacement on decode error.
Raises `FileNotFoundError` when the path does not exist.

### `calibration_tables() -> list[CalibrationTable]`

Return all parsed CalibrationTable objects. Tables with address `0x00000000` are omitted.
Malformed CHARACTERISTIC blocks are silently skipped so one bad entry does not abort the parse.

### `label_map() -> dict[int, str]`

Return `{file_offset: label}` for all tables and their axes. Pass entries to
`ctx.set_name(offset, name, source="a2l")`. When tables reference shared axis data
(COM_AXIS), `CalibrationAxis.address` is `None` and no label is emitted for that axis.

### `summary() -> str`

Return a text block with project/module names, table type counts, dictionary sizes, and
detected byte order.

### Instance attributes

| Attribute | Type | Description |
|---|---|---|
| `project_name` | `str` | `/begin PROJECT name` |
| `module_name` | `str` | `/begin MODULE name` |
| `byte_order` | `str` | `MSB_FIRST` (big-endian) or `MSB_LAST` (little-endian) |

---

## Validated results

### Bosch EDC16U34 — VW/Audi 1.9 TDI

```
A2L  03G906021KE_9970_501409_P447_HAXN_EDC16U34_3.41.a2l
  project   : X447  module: DIM
  tables    : 11427 total (533 MAP  536 CURVE  10358 VALUE)
  compu_meth: 442 named
  rec_layout: 39 named
  byte_order: big
```

Sample MAP: `ACCCD_facEnv_MAP` — 6x6 table at `0x1C22AE`, scale=8192.0, unit=`[-]`.

### Bosch EDC17CP46 — VW/Audi 2.0 TDI

```
A2L  03L906018CG_5152_504704_P643_X5F5_EDC17CP46_2.7.a2l
  project   : P643  module: DIM
  tables    : 26016 total (1433 MAP  1498 CURVE  23085 VALUE)
  compu_meth: 2917 named
  rec_layout: 59 named
  byte_order: little
```

The EDC17CP46 runs on an Infineon TriCore TC1766 (little-endian, `MSB_LAST`). Virtual addresses
start at `0x80000000` — the TriCore PFLASH segment base. Pass this as `base_address=0x80000000`
to shift addresses down to ROM file offsets when needed.

### ASAP2 Demo V1.61

```
A2L  ASAP2_Demo_V161.a2l
  project   : ASAP2_Example  module: Example
  tables    : 45 total (3 MAP  10 CURVE  32 VALUE)
  compu_meth: 14 named
  rec_layout: 24 named
  byte_order: little
```

Covers all ASAP2 v1.61 CHARACTERISTIC types including CUBOID (treated as MAP).

---

## Differences from other ECU parsers

| Aspect | EcuA2LParser | EcuXDFParser | EcuRomRaiderParser |
|---|---|---|---|
| Format | ASAM/ASAP2 A2L text | TunerPro XDF XML | RomRaider XML |
| Scaling source | COMPU_METHOD block | MATH equation | expression= attribute |
| Layout source | RECORD_LAYOUT block | EMBEDDEDDATA attributes | scaling storagetype |
| Identify ROM | Not supported (no ROM signature) | Not supported | `identify_rom(rom)` |
| Byte order source | `BYTE_ORDER` keyword | `DEFAULTS lsbfirst` | endian= attribute |
| Address format | Hex literal `0xADDR` | Hex in mmedaddress | Hex without 0x |

A2L files do not carry ROM identification strings — the file's filename and header comment are
the only link to a specific ROM image. Use `EcuRomRaiderParser.identify_rom()` or
`EcuConescanParser.identify_rom()` when the ROM variant is unknown.

---

## Limitations

- **No ROM identification.** A2L files contain no `internalidstring` or checksum field.
  Matching an A2L to a specific ROM image requires external tooling or filename correlation.

- **max_axis_pts used for dimensions.** For `STD_AXIS` tables, the actual axis count lives in
  the ROM at a fixed position before the data. The parser uses `max_axis_pts` from the
  AXIS_DESCR block as the upper bound. Tables with variable-length axes will have columns or
  rows set to the maximum possible, not the actual runtime count.

- **A2ML and IF_DATA stripped.** The parser does not parse transport-layer or tool-private
  metadata. All `A2ML` and `IF_DATA` blocks are removed before the calibration pass.

- **Non-linear COMPU_METHOD produces scale=0.0.** `TAB_VERB`, `TAB_NOINTP`, `FORMULA`, and
  non-linear RAT_FUNC methods produce `scale=0.0` as a sentinel. The table is still returned
  with all address and dimension information intact.
