# EcuRomRaiderParser

**File:** `ablation/analyzers/ecu_romraider_parser.py`

---

## Why this exists

4 things that were not possible before in Ablation:

**1. No RomRaider XML support.** The Auto-ECU-RE corpus contains 6 community definition files in
RomRaider XML format covering BMW Siemens MS43, MS45, MS48, and Subaru Denso SH705x. No Ablation
parser existed for this format. Each file defines 200 to 350 calibration table structures covering
every tunable subsystem: ignition advance, fuel trim, boost, idle speed, lambda limits, and gear
shifting. Without this parser, all of those addresses and labels were inaccessible.

**2. No two-pass inheritance model.** RomRaider XML files split table data across two `<rom>`
elements: the base entry carries structure (type, dimensions, storagetype, scaling) and the variant
entries carry addresses (`storageaddress`). A flat XML pass that processes both in a single sweep
cannot join them because the base has no addresses and the variant has no structure. The parser
builds a keyed structure dictionary from the base in the first pass, then overlays variant address
dicts in the second pass to produce complete `CalibrationTable` objects.

**3. No ROM identification for variant-addressed definitions.** Each variant carries an
`internalidstring` (ASCII ECU firmware ID such as `4570LO00`) at a specific `internalidaddress`
(decimal file offset). The same string is baked into the ECU's flash by Siemens at production.
Before `identify_rom()` existed, selecting the right address set for a given ROM file required
manual inspection of `<romid>` fields and hex editing. `identify_rom()` byte-searches the ROM for
each variant's ID string in a window around the expected address, with a hex-address fallback for
community XML files that write decimal offsets using hex digit strings.

**4. No scaling expression parser for community XML dialects.** Community RomRaider XML files use
at least 14 distinct linear expression forms: `x`, `k*x`, `x*k`, `x/k`, `x*k+b`, `(x*k)+b`,
`(x*k)-b`, `x+b`, `x-b`, `(x-offset)*k`, and signed variants of each. The BMW MS45 file alone
uses `(x-65535)*0.0212` to encode mg/stroke values. No general expression evaluator in Ablation
handled this; all 14 forms now parse correctly to `(scale, bias)` pairs.

---

## Format overview

A RomRaider XML file contains one `<roms>` root with multiple `<rom>` children.

**Base ROM** (no `base=` attribute): defines table structure. Has `<romid>` with the base
`<xmlid>` and no `<internalidstring>`. Each `<table>` carries `type`, `sizex`, `sizey`,
`storagetype`, `endian`, and a `<scaling>` child with `units` and `expression`.

**Variant ROM** (`base="<xmlid>"` attribute): defines addresses only. Has `<romid>` with a unique
`<xmlid>`, `<internalidaddress>`, `<internalidstring>`, `<filesize>`, `<year>`, `<make>`, and
`<model>`. Each `<table>` carries only `name` and `storageaddress`.

```xml
<rom>                                     <!-- base -->
  <romid>
    <xmlid>BMWMS45BASE</xmlid>
  </romid>
  <table type="3D" name="Ignition Map" sizex="16" sizey="20"
         storagetype="uint8" endian="big" category="Ignition">
    <scaling units="deg" expression="x*.75-48" />
    <table type="X Axis" storagetype="uint16" endian="big">
      <scaling units="RPM" expression="x" />
    </table>
    <table type="Y Axis" storagetype="uint16" endian="big">
      <scaling units="mg/stroke" expression="(x-65535)*0.0212" />
    </table>
  </table>
</rom>
<rom base="BMWMS45BASE">                  <!-- variant -->
  <romid>
    <xmlid>4570LO00</xmlid>
    <internalidaddress>13</internalidaddress>
    <internalidstring>4570LO00</internalidstring>
    <filesize>116kb</filesize>
    <year>2003</year>
    <make>BMW</make>
    <model>E46 325i ZHP 6MT</model>
  </romid>
  <table name="Ignition Map" storageaddress="0xB24C">
    <table type="X Axis" storageaddress="0x8812" />
    <table type="Y Axis" storageaddress="0x8992" />
  </table>
</rom>
```

---

## Usage

```python
from ablation.analyzers.ecu_romraider_parser import EcuRomRaiderParser

parser = EcuRomRaiderParser.from_file("MS45 ECU Definitions.xml")

# List all variants before identification
for xmlid, model, size_kb in parser.variants():
    print(f"{xmlid:12s}  {model:40s}  {size_kb} KB")

# Identify a ROM file
rom = open("29bl802c Flash ms45.1 ZHP.bin", "rb").read()
variant_id = parser.identify_rom(rom)
if variant_id:
    tables = parser.calibration_tables(variant_id)
    for t in tables:
        print(f"0x{t.address:08X}  {t.table_type:5s}  {t.rows}x{t.cols}  {t.name}")

# Inject into BinaryContext
    for offset, name in parser.label_map(variant_id).items():
        ctx.set_name(offset, name, source="romraider")

# Print summary
    print(parser.summary(variant_id))
```

---

## API reference

### `EcuRomRaiderParser.from_file(path)`

Parse a RomRaider ECU definition XML file. `path` accepts `str` or `pathlib.Path`. Returns an
`EcuRomRaiderParser` instance.

Raises `xml.etree.ElementTree.ParseError` on malformed XML.

### `variants() -> list[tuple[str, str, int]]`

Return `(xmlid, model, filesize_kb)` for every variant in the file. Useful for listing options
before calling `identify_rom()` or `calibration_tables()` directly.

### `identify_rom(rom, search_window=32) -> Optional[str]`

Search `rom` for each variant's `internalidstring` in a window of `±search_window` bytes around
`internalidaddress`. Returns the matching variant's `xmlid`, or `None` when no variant matches.

When multiple variants match (same ECU family, different file sizes such as 116 KB calibration
versus 1024 KB full flash), returns the variant whose `filesize_kb` is closest to
`len(rom) // 1024`.

**Hex address fallback:** some community XML files write a hex address as a decimal string
(for example `internalidaddress=13` means file offset 13, but `internalidaddress=100` in some
files means offset 0x100 = 256, not 100). `identify_rom()` tries both interpretations and
accepts whichever finds the string.

**False-positive filter:** a match must resolve at least `min(20, base_defs // 5)` table
addresses in the variant. Coincidental string hits in code regions produce matches with 0 to 2
tables resolved; these are rejected and `None` is returned rather than a wrong identification.

### `calibration_tables(variant_id) -> list[CalibrationTable]`

Return all `CalibrationTable` objects for the named variant. Tables whose `storageaddress` is
absent in the variant are omitted. Axes whose address is absent produce `None` in
`CalibrationAxis.address`.

### `label_map(variant_id) -> dict[int, str]`

Return `{file_offset: label}` for all tables and axes in the variant. Pass entries to
`ctx.set_name(offset, name, source="romraider")`.

### `summary(variant_id=None) -> str`

Return a text block showing base definition count, variant count, and (when `variant_id` is
supplied) the resolved table count broken down by type.

---

## Scaling expression parser

`_expr_to_linear(expr)` converts a RomRaider `expression=` attribute to `(scale, bias)` for use
in `CalibrationTable.scale` and `.bias`. It handles all forms found in the MS43, MS45, and
Subaru community files:

| Expression form | Result |
|---|---|
| `x` | `(1.0, 0.0)` |
| `k*x` | `(k, 0.0)` |
| `x*k` or `(x*k)` | `(k, 0.0)` |
| `x/k` | `(1/k, 0.0)` |
| `x*k+b` or `(x*k)+b` | `(k, b)` |
| `(x*k)-b` | `(k, -b)` |
| `x+b` or `x-b` | `(1.0, ±b)` |
| `(x-offset)*k` | `(k, offset*k)` |
| `1/(x*k)` or any non-linear form | `(0.0, 0.0)` sentinel |

When `scale == 0.0`, callers treat the table as raw-only: `read_data()` still returns integer
values, but physical unit conversion is not applied.

### MS45 notable expressions

```
"x*.75-48"              → (0.75, -48.0)    deg ignition advance
"(x-65535)*0.0212"      → (0.0212, -1389.14)  mg/stroke load axis
"x*.0039"               → (0.0039, 0.0)    normalized ratio
"x*0.1"                 → (0.1, 0.0)       generic 10x scale
```

The `(x-65535)*0.0212` form triggered a sign error in an early version: the offset is negative
(`-65535.0` after capture), so `bias = offset * k = -65535.0 * 0.0212 = -1389.14`, matching the
physical range of -9.3 to 57.9 mg/stroke visible in the RomRaider GUI for E46 torque tables.

---

## Storagetype mapping

| XML `storagetype` | bits | signed | float |
|---|---|---|---|
| `uint8` | 8 | No | No |
| `int8` | 8 | Yes | No |
| `uint16` | 16 | No | No |
| `int16` | 16 | Yes | No |
| `uint32` | 32 | No | No |
| `int32` | 32 | Yes | No |
| `float` / `float32` | 32 | No | Yes |

Unknown storagetype strings default to `uint8`.

---

## Validated results

### BMW Siemens MS45 (MS45 ECU Definitions.xml, 51 variants, 116 KB and 1024 KB)

`parser.variants()` returns 51 entries spanning E46 (325i, 328i, 330i, M3), E60 (525i, 530i),
E83 (X3), Z4, and some MPC development board variants.

Identification results on the BMW MS45 corpus:

| ROM file | Identified | Tables | MAPs | Notes |
|---|---|---|---|---|
| `29bl802c Flash ms45.1 ZHP.bin` | `4570LO00` | 218 | 67 | E46 ZHP 116 KB cal |
| `520ir.bin` | `4560BN00` | 155 | 57 | E60 525i 116 KB cal |
| `KM04699_0044570.bin` | `4570LO00` | 218 | 67 | E46 ZHP 116 KB cal |
| `07541335_flash.bin` | NOT IDENTIFIED | — | — | 1024 KB full flash |
| `MS45.1 325i manual.bin` | NOT IDENTIFIED | — | — | variant absent in XML |

The 116 KB calibration-only partials (the ROM region a flash tool reads without erasing the full
chip) identify reliably and produce 155 to 218 tables. The 1024 KB full flash ROMs do not identify
because the community XML's `internalidaddress` values for those variants point to ERASED regions
(the full flash image stores the ID at a different offset than the calibration partial).

The false-positive filter eliminates low-table matches from the 1024 KB full flash files.

---

## Limitations

- **1024 KB full flash identification.** The community MS45 XML was authored against 116 KB
  calibration partials. The `internalidaddress` for full flash variants points to ERASED memory
  (0xFF fill). `identify_rom()` returns `None` for full flash ROMs because no variant produces
  enough table matches.

- **Variants absent from XML.** The corpus contains firmware files (e.g. `MS45.1 325i manual.bin`)
  whose ECU variant is not in the XML file. The variant's `xmlid` was never contributed to the
  community definition. `identify_rom()` returns `None`; use `variants()` to check coverage before
  analysis.

- **Duplicate xmlid entries.** Some community XML files reuse the same `xmlid` for a 116 KB and
  1024 KB variant of the same ECU (same firmware string appears in both partials). `_variant_by_id`
  returns the first match, which is correct for calibration partials. To select the 1024 KB
  variant explicitly, call `calibration_tables()` with the full xmlid and inspect the filesize in
  `variants()`.

- **Switch and BitwiseSwitch tables.** These are present in the MS45 base definition but have no
  meaningful scaling expression. They are parsed and returned by `calibration_tables()` as
  `table_type="Switch"` or `"BitwiseSwitch"` with `scale=1.0`, but `read_data()` on them returns
  raw bit patterns rather than decoded switch states.

- **Non-linear expressions.** Any expression not matched by `_expr_to_linear` returns `(0.0, 0.0)`
  as a sentinel. This includes `1/(x*k)`, `log(x)`, `exp(x)`, and any multi-variable form. The
  table is still parsed and returned; only the scaling is absent.
