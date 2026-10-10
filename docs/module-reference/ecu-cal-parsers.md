# ECU Calibration Definition Parsers

**Files:**
- `ablation/analyzers/ecu_cal_def.py` — shared dataclasses (`CalibrationTable`, `CalibrationAxis`)
- `ablation/analyzers/ecu_xdf_parser.py` — TunerPro XDF (XML) parser
- `ablation/analyzers/ecu_open_damos_parser.py` — open_damos.json parser with fingerprint relocation

---

## Why this exists

3 things that were not possible before in Ablation:

**1. No calibration map label source for ECU ROMs.** Binary RE on a stripped ECU firmware meant every
array of uint16 values was anonymous. The 293 XDF files and 40+ open_damos definitions in the Auto-ECU-RE
corpus encode the exact memory address, shape, and scaling of every fuel, boost, and timing table. These
parsers inject those definitions into `BinaryContext` via `ctx.set_name()` so the ROM reads like a vendor-
labelled binary.

**2. No ROM-variant relocation.** XDF files record a fixed file offset tied to one firmware version. A
calibration table for `AccPed_trqEngHiGear_MAP` at offset `0x1C1448` in the baseline firmware moves to
`0x1C1AB4` in a later service release. `EcuOpenDamosParser` carries a fingerprint array (the physical
axis breakpoints such as `[400, 650, 750, 1000, ..., 5300]` RPM) on each axis entry. `locate_in_rom()`
encodes that fingerprint back to raw integer bytes and byte-searches the target ROM. The table address
found this way is correct for any variant in the ECU family, not just the baseline.

**3. No shared datatype.** Every downstream scanner (`EcuCalibrationTableScanner`,
`EcuROMLayoutAnalyzer`) needed its own representation of a calibration table. `CalibrationTable` and
`CalibrationAxis` are the shared type; both parsers emit them, and every tool consumes them.

---

## CalibrationTable

```python
@dataclass
class CalibrationTable:
    name: str               # map name from the definition file
    description: str
    category: str           # e.g. "Boost Control", "Fuel"
    table_type: str         # "VALUE", "CURVE", or "MAP"
    address: int            # default file offset from the definition
    rows: int               # row count (y-axis length for MAPs)
    cols: int               # column count (x-axis length)
    element_bits: int       # bits per data element: 8, 16, or 32
    little_endian: bool
    scale: float            # physical = raw * scale + bias
    bias: float
    unit: str               # physical unit string, e.g. "Nm", "hPa", "rpm"
    x_axis: Optional[CalibrationAxis]
    y_axis: Optional[CalibrationAxis]
    relocated_address: Optional[int]   # set by fingerprint relocation
    source_file: str
```

`effective_address` returns `relocated_address` when set, otherwise `address`. All downstream
tools call `effective_address` rather than `address` directly.

`label_map()` returns `{file_offset: label}` entries for the table, its x-axis, and its y-axis.
Pass these to `ctx.set_name(off, name, source="xdf")`.

`read_data(rom)` extracts the raw integer values from `rom` at `effective_address`. Returns a flat
list for VALUE/CURVE types, and a list of rows for MAP types. Does not apply scaling.

---

## EcuXDFParser

Parses TunerPro XDF files (XML). XDF is used for BMW MSD80/MSV70, VW MED17/Simos, GM PCMs, and
most aftermarket Subaru/Nissan/Honda definitions. The corpus contains 293 XDF files.

XDF addresses are raw file offsets by default. `BASEOFFSET subtract=0` means no adjustment is
needed. Supply `base_address` when the definition was authored against a virtual address space
(rare: most community XDFs use file offsets).

```python
from ablation.analyzers.ecu_xdf_parser import EcuXDFParser

parser = EcuXDFParser.from_file("I8A0S.xdf")
print(parser.summary())

# All tables
tables = parser.calibration_tables()
maps_2d = [t for t in tables if t.rows > 1 and t.cols > 1]
print(f"{len(maps_2d)} 2-D maps")

# Inject into BinaryContext
for offset, name in parser.label_map().items():
    ctx.set_name(offset, name, source="xdf")
```

### XDF format internals

An `XDFTABLE` entry contains up to three `XDFAXIS` children (id=`x`, `y`, `z`). The `z` axis
always holds the data address in its `EMBEDDEDDATA mmedaddress` attribute. The `x` and `y` axes
hold axis (breakpoint) addresses.

**Shared axes (DALINK):** when multiple tables share the same x-axis breakpoints, the x-axis
element carries `<DALINK index="N">` pointing to the table whose axis it borrows. The parser
resolves this and records the shared address in `CalibrationAxis.shared_from`.

**Scaling:** the `MATH equation="X*k+b"` attribute on the z-axis encodes a linear transform.
`_math_to_linear()` extracts `(scale, bias)` from simple linear equations. Non-linear equations
(e.g. `"(X*2.653)*0.0145"`) return `scale=0.0` as a signal; the raw values are still accessible
via `read_data()`.

**Endianness:** the `DEFAULTS lsbfirst=` attribute sets byte order for the whole file.
`lsbfirst=0` (big-endian) is standard for Bosch and BMW ECUs; `lsbfirst=1` for Subaru Denso.

### Output per 770-table BMW N54 XDF (I8A0S.xdf)

```
XDF  I8A0S.xdf
  title      : I8A0S
  tables     : 755 total (755 MAP  0 CURVE  0 VALUE)
  base_offset: 0x0
  endian     : big
```

| Item | Count |
|---|---|
| Total tables parsed | 755 |
| 2-D maps (rows > 1, cols > 1) | 155 |
| Label map entries | 754 |
| Tables with valid address | 755 |

---

## EcuOpenDamosParser

Parses the open_damos.json format used by the open-car-reprog project (Poisson48). This format
covers Bosch EDC16C34 (PSA 1.6 HDi: Berlingo, C3/C4, 206/207/307, Mazda 2/3), EDC16C39,
EDC17C42/49/50, and several other Bosch diesel ECU variants.

The key feature is fingerprint relocation: every axis carries a `fingerprint` array encoding the
physical breakpoint values (RPM, load percentage, etc.) that the ECU stores in flash. The parser
converts this fingerprint back to raw integer bytes and searches the target ROM for that exact
sequence, finding the correct table address in any firmware variant of the ECU family.

```python
from ablation.analyzers.ecu_open_damos_parser import EcuOpenDamosParser

parser = EcuOpenDamosParser.from_file("open_damos.json")
rom = open("9663944680.bin", "rb").read()

# Locate tables in this specific firmware variant
located = parser.locate_in_rom(rom)          # {name: file_offset}
print(f"{len(located)} of {len(parser.calibration_tables())} tables located")

# Build label map from relocated addresses
for offset, name in parser.label_map(rom).items():
    ctx.set_name(offset, name, source="open_damos")
```

### Fingerprint relocation algorithm

For each `CHARACTERISTIC` entry:

1. Take the first axis's `fingerprint` array (e.g. `[400, 650, 750, ..., 5300]` RPM).
2. Divide each value by `factor` and round to get the raw integer the ECU stores.
3. Pack those integers as `SWORD_BE` (signed 16-bit big-endian) and byte-search the ROM.
4. For each hit at position `idx`: compute `table_start = idx - header_bytes`.
5. If the table header encodes the expected dimensions (`nx`, `ny`), accept `table_start` as the
   relocated address.

The EDC16C34 uses 4-byte headers encoding `(nx, ny)` as two `UWORD_BE` fields. A MAP with
`dims: {nx: 16, ny: 10}` will have header bytes `00 10 00 0A` immediately before the x-axis data.

### Results on 9663944680.bin (PSA Berlingo EDC16C34)

```
open_damos  open_damos.json
  ecu      : edc16c34  v1.6.0
  tables   : 40 (26 MAP  5 CURVE  9 VALUE)
  layouts  : Kf_Xs16_Ys16_Ws16, Kl_Xs16_Ws16, Kw_Ws16
```

16 of 31 MAP/CURVE tables located in firmware `9663944680.bin`. The 9 VALUE tables are scalars
with no axis fingerprint and are not relocatable by this method. Tables that share the same x-axis
fingerprint appear at the same relocation address: disambiguation requires a y-axis fingerprint
check (planned for v2).

### Notable tables in the EDC16C34 definition

| Name | Type | Dims | Unit | Description |
|---|---|---|---|---|
| `AccPed_trqEngHiGear_MAP` | MAP | 16x10 | Nm | Torque demand from accelerator in high gears |
| `FMTC_trq2qBas_MAP` | MAP | 16x16 | mg/cyc | Torque-to-fuel-quantity base conversion |
| `Rail_pSetPointBase_MAP` | MAP | 16x16 | hPa | Fuel rail pressure setpoint |
| `FlMng_rLmbdSmk_MAP` | MAP | 16x16 | dimensionless | Smoke limiter lambda ratio |
| `Rail_pSetPointMax_MAP` | MAP | 12x8 | hPa | Maximum allowed rail pressure |

`FMTC_trq2qBas_MAP` and `Rail_pSetPointBase_MAP` are the primary diesel tuning targets:
they control how much fuel is injected per engine cycle at each RPM and load point.

---

## Cross-reference with EcuCalibrationTableScanner

Both parsers emit `CalibrationTable` objects with `effective_address` set. Pass them to
`EcuCalibrationTableScanner` to cross-reference scanner hits against known definitions:

```python
from ablation.analyzers.ecu_cal_def import CalibrationTable
from ablation.analyzers.ecu_rom_layout_analyzer import EcuROMLayoutAnalyzer
from ablation.analyzers.ecu_xdf_parser import EcuXDFParser

# Step 1: identify calibration region boundaries
ana = EcuROMLayoutAnalyzer.from_path("E38_2048KiB_12607218.bin")
layout = ana.analyze()
cal_regions = layout.calibration_regions()

# Step 2: load known definitions for this ECU
# (use XDF for GM E38; use open_damos for EDC16C34)
parser = EcuXDFParser.from_file("E38.xdf")
known = {t.address: t for t in parser.calibration_tables()}

# Step 3: inject labels into BinaryContext
for offset, name in parser.label_map().items():
    ctx.set_name(offset, name, source="xdf")
```

---

## Limitations

- `EcuXDFParser` only parses linear MATH equations. Equations containing `log`, `exp`, or
  multi-variable forms return `scale=0.0`; the raw data is still readable via `read_data()`.
- `EcuOpenDamosParser` fingerprint relocation requires the ROM variant to use the same axis
  breakpoints as the definition baseline. ECU variants with a different calibration team may
  use different axis spacing.
- VALUE (scalar) tables in open_damos have no axis fingerprint and are located by default address
  only; they are correct for the baseline firmware but will be wrong on other variants.
- XDF DALINK shared-axis resolution follows the index literally; entries with `DALINK index=0`
  (the "no linked table" convention) produce `shared_from=None` with no address.
