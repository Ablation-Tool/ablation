# EcuROMLayoutAnalyzer

**File:** `ablation/analyzers/ecu_rom_layout_analyzer.py`

---

## Why this exists

3 things that were not possible before in Ablation:

**1. No region map for ECU ROMs.** Before this module, applying any ECU scanner to a firmware dump
required knowing which address range held code and which held calibration data. For a 2 MB GM E38
PCM image, the first 1.6 MB is PPC32 application code; a 208 KB erased gap separates it from 256 KB
of calibration tables at the end. Running a table scanner over the code region, or a disassembler over
the calibration region, wastes time and produces false positives. This module maps the full ROM before
any other analysis runs.

**2. No arch-agnostic classifier.** Every ROM layout tool in the existing codebase depended on
disassembly, which requires knowing the architecture first. `EcuROMLayoutAnalyzer` operates on bytes
only. It never calls a disassembler. The result is correct for TriCore, PPC32, M68k, SH705x, and
ARM Cortex-M ROMs because Shannon entropy and instruction density are independent of ISA identity.

**3. No calibration region boundary source for downstream scanners.** `EcuCalibrationTableScanner`
needs a list of `(start, end)` byte ranges to search. `ROMLayout.calibration_regions()` returns them
directly so the scanner never processes ERASED or CODE ranges.

---

## Classification algorithm

The analyzer divides the ROM into `window_size` (default 4096-byte) windows and classifies each one
using three signals: Shannon entropy, fill-byte ratio, and PPC32 instruction density.

### Shannon entropy

Shannon entropy measures the randomness of a byte window:

```
H = -sum( p_i * log2(p_i) ) for each unique byte value i
```

A window full of identical bytes has H = 0. A window with a flat byte distribution has H = 8.
Real-world ROM regions fall into distinct bands:

| Region type | Typical H range | Reason |
|---|---|---|
| ERASED (0xFF fill) | 0.0 | Single byte value |
| PADDING (0x00 fill) | 0.0 | Single byte value |
| CALIBRATION | 2.5 to 6.5 | Structured numeric tables with bounded values |
| MIXED | 6.5 to 6.8 | Code/cal boundaries; descriptor tables |
| CODE | 5.4 to 6.3 (fixed-width ISA) | Aligned instruction streams with clustered opcodes |

The overlap between CALIBRATION and CODE in the 4.8 to 6.5 range is the core classification
problem. Fixed-width ISAs (PPC32, M68k, TriCore, SH) produce lower code entropy than x86 because
their aligned instructions cluster in a smaller opcode space.

### Fill-byte ratio

The fraction of bytes equal to the fill byte (0xFF for NOR flash). ERASED regions have a ratio
above 0.85. Sparse calibration data has a ratio above 0.08 because empty table cells are often
left at the erased value. PPC code regions have a ratio below 0.01.

### PPC32 instruction density

The fraction of 4-byte-aligned words whose high byte falls in the standard PPC32 opcode ranges.
This discriminator fires only in the ambiguous 4.8 to 6.5 entropy band where both code and dense
calibration tables live.

```
PPC opcode ranges (high byte):
  0x38-0x3F  addi, addic, ori, xori, andis, addis
  0x80-0x9F  lbz, lhz, lha, lwz, stb, sth, stw (loads + stores)
  0xB0-0xBF  stbu, sthu, stwu, lmw, stmw
  0x48, 0x4C, 0x4E  b, bl, bc, bclr, bctr (branches)
  0x7C-0x7F  integer arithmetic, compare, move
  0x60-0x63  ori, oris, xor, xoris, andi
  0x20, 0x21, 0x28, 0x29  lfsx, stfsx, lfsux, stfsux (FPU)
```

Measured densities:
- GM E38 PPC32 code windows: 0.63 to 0.66
- EDC16C34 calibration windows: 0.00 to 0.07
- Threshold: 0.20

### The four-variable decision

```
if fill_ratio >= 0.85:   ERASED
if entropy <= 1.5:        PADDING
if entropy <= 6.5:
    if entropy < 4.8:     CALIBRATION  (too low for any ISA's code)
    if fill_ratio >= 0.08: CALIBRATION (sparse table with erased cells)
    if ppc_density >= 0.20: CODE        (PPC32 instruction stream confirmed)
    else:                  CALIBRATION  (could not confirm as code)
if entropy <= 6.8:        MIXED
else:                     CODE
```

The `_T_CODE_FLOOR = 4.8` threshold is the key discovery from testing on GM E38 vs EDC16C34 ROMs:
dense Bosch calibration tables (lookup arrays, descriptor structs) reach entropy 5.0 to 5.9 with
low fill ratio, so they pass the original entropy-only test for CODE. The floor cuts them out
because no ISA in the corpus produces instruction streams below 4.8 bits/byte.

---

## Usage

```python
from ablation.analyzers.ecu_rom_layout_analyzer import EcuROMLayoutAnalyzer

# Analyze from file path
ana = EcuROMLayoutAnalyzer.from_path("9663944680.bin")
layout = ana.analyze()
print(ana.report(layout))

# Feed calibration regions to EcuCalibrationTableScanner
for r in layout.calibration_regions():
    print(f"CALIBRATION  0x{r.start:08X} - 0x{r.end:08X}  {r.size // 1024} KB")

# Feed code regions to disassembly pipeline
for r in layout.code_regions():
    print(f"CODE         0x{r.start:08X} - 0x{r.end:08X}  {r.size // 1024} KB")

# Analyze from raw bytes (for pipeline use)
data = open("firmware.bin", "rb").read()
ana = EcuROMLayoutAnalyzer.from_bytes(data, window_size=1024)
layout = ana.analyze()
```

### Constructor parameters

| Parameter | Default | Description |
|---|---|---|
| `window_size` | 4096 | Window size in bytes. Use 1024 for ROMs smaller than 256 KB. |
| `fill_byte` | 0xFF | Erased flash fill byte. NOR flash erases to 0xFF; some NAND to 0x00. |
| `fill_threshold` | 0.85 | Fill-byte proportion above which a window is ERASED. |

---

## ROMLayout API

`EcuROMLayoutAnalyzer.analyze()` returns a `ROMLayout`:

```python
@dataclass
class ROMLayout:
    file_size: int
    regions: list[ROMRegion]
    window_size: int
    fill_byte: int

    def code_regions(self) -> list[ROMRegion]
    def calibration_regions(self) -> list[ROMRegion]
    def erased_regions(self) -> list[ROMRegion]
    def active_start(self) -> int    # first non-ERASED/PADDING offset
    def active_end(self) -> int      # last non-ERASED/PADDING offset
```

Each `ROMRegion`:

```python
@dataclass
class ROMRegion:
    start: int          # first byte (inclusive)
    end: int            # last byte (exclusive)
    region_type: str    # ERASED, CODE, CALIBRATION, MIXED, PADDING
    entropy: float      # mean entropy across all windows in this region
    window_count: int

    @property
    def size(self) -> int
```

---

## Validated results

### EDC16C34 PSA Berlingo (9663944680.bin, 2 MB, calibration-only)

```
Offset              Type          Size   Entropy
0x00000000-0x1C0000  ERASED       1792 KB  0.00
0x1C0000-0x1C4000    CALIBRATION    16 KB  3.68
0x1C4000-0x1C5000    PADDING         4 KB  0.31
0x1C5000-0x1E4000    CALIBRATION   124 KB  4.81
0x1E4000-0x1E5000    PADDING         4 KB  0.21
0x1E5000-0x1F3000    CALIBRATION    56 KB  4.53
0x1F3000-0x1F4000    PADDING         4 KB  0.04
0x1F4000-0x1FF000    CALIBRATION    44 KB  4.31
0x1FF000-0x200000    ERASED          4 KB  0.00
```

Zero CODE regions. Correct: the EDC16C34 PSA image is a calibration-only dump with no application
firmware.

### GM E38 PCM (E38_2048KiB_12607218.bin, 2 MB, PPC32 full flash)

```
Offset              Type          Size   Entropy
0x00000-0x05000      CODE           20 KB  5.65
0x05000-0x0A000      CALIBRATION    20 KB  5.21
0x0A000-0x12000      CODE           32 KB  5.71
...
0x5D000-0x12C000     CODE          828 KB  5.73   (largest code block)
...
0x18B000-0x1BF000    ERASED        208 KB  0.00   (gap between code and cal)
0x1BF000-0x1FF000    CALIBRATION   256 KB  4.65
0x1FF000-0x200000    ERASED          4 KB  0.00
```

6 CODE regions totaling 1520 KB (PPC32 application + OS). 13 CALIBRATION regions totaling 240 KB.
The 208 KB ERASED gap at 0x18B000 cleanly separates the code image from the calibration image.

---

## Reset vector detection

`detect_reset_vector()` returns the file offset of the MCU reset vector or `None`.

It checks the Infineon TriCore TC1x reset vector at offset 0x100 (internal flash start after the
Boot Mode Header) and the Renesas SH705x/SH7058 reset vector at offset 0x000. Both are 32-bit
big-endian pointers. The first non-erased word at either candidate offset is returned.

This supplements but does not replace `EcuArchDetector` (planned): a full reset-vector chain trace
that walks the interrupt vector table to confirm the architecture.

---

## Limitations

- PPC32 instruction density fires only on PPC32 ROMs. For TriCore, M68k, SH705x, or ARM Cortex-M
  ROMs where the ambiguous entropy band contains both code and calibration data, the classifier
  defaults to CALIBRATION on uncertain windows. This is conservative: false CALIBRATION is safer
  than false CODE because calibration scanners ignore non-table byte patterns.
- Window size matters on small ROMs. A 256 KB SH705x ROM with the default 4 KB window gives only
  64 windows; use `window_size=1024` for finer resolution.
- The MIXED category is a placeholder. No scanner currently consumes MIXED regions. Most MIXED
  windows are at code/calibration boundaries and span less than one window.
- `detect_reset_vector()` cannot distinguish TriCore from SH705x when both patterns are present.
  Use `EcuXDFParser` to check for an architecture-specific definition file first.
