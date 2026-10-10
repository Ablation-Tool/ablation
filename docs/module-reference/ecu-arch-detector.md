# EcuArchDetector

**File:** `ablation/analyzers/ecu_arch_detector.py`

---

## Why this exists

3 things that were not possible before in Ablation:

**1. No ISA identification for unknown flat ECU ROMs.** When a ROM image arrives without any
container format (no ELF, no IHEX, no SREC wrapper), there is no reliable way to know
what instruction set it contains before Ablation selects a decoder.  Choosing the wrong
decoder silently misaligns on every instruction, making all downstream RE work garbage.
Before this module, ISA identification was a manual step — inspecting hex dumps, looking at
reset vectors, pattern-matching by eye.  `EcuArchDetector` runs six discriminators in one
call and returns a confident verdict (HIGH/MEDIUM/LOW) with a human-readable reason, so
the RE pipeline can select the correct decoder without a manual step.

**2. No coverage for the ARM Cortex-M ISA in the ECU decoder family.**  The existing ECU
decoders cover M68K/CPU32 (GM P-series), PPC32 (GM E38), PPC VLE (GM E39a/E54/E92), and
SH-2A (Honda/Subaru).  Many modern ECUs (Bosch MED17, Continental SIMOS, Delphi DCM) run
ARM Cortex-M.  `EcuArchDetector` adds an ARM Cortex-M discriminator, providing ISA detection
coverage for those targets and establishing where a future `ARM32TaintTracker` or Capstone
ARM wrapper would fit in the pipeline.

**3. No detection for Infineon TriCore AURIX flat binary dumps.**  TriCore AURIX (TC1.6/
TC2xx/TC3xx) is used in Bosch ME17/MED17 engine controllers, Continental MG1, and Waqas
GEN3 ECU platforms.  Without this discriminator, a TriCore flat dump was misidentified as
M68K — the big-endian reset-vector check at offset 4 fired on arbitrary bytes that happened
to fall in range.  The TriCore discriminator scans the full image for little-endian pointer
values in the AURIX physical address map (PFLASH at 0x80000000–0xBFFFFFFF, peripherals at
0xE0000000–0xFFFFFFFF; both ranges from TC1.8 Architecture Manual Vol 1, §8 Table 13) and
includes an artifact guard that rejects big-endian ROMs whose instruction bytes, when
misread as LE words, produce spurious address hits.

---

## Supported architectures

| Arch token | ISA | Typical targets |
|---|---|---|
| `arm_cm` | ARM Cortex-M (Thumb-2, LE vector table) | Bosch MED17, Continental SIMOS |
| `tricore` | Infineon TriCore AURIX (TC1.6/TC2xx/TC3xx, LE) | Bosch ME17/MED17, Continental MG1, Waqas GEN3 |
| `m68k` | Motorola 68K / CPU32 | GM P01/P04/P05/P08/P10/P11/P59 (CPU32) |
| `ppc32` | PowerPC 32-bit Book E | GM E38 PCM, Denso ECUs |
| `ppc_vle` | PowerPC VLE (NXP e200z) | GM E39a/E54/E92 (MPC5566) |
| `sh2a` | Renesas SH-2A / SH-2 | Honda SH7058/SH7059, Subaru EcuFlash |
| `unknown` | No discriminator above threshold | — |

---

## Usage

```python
from ablation.analyzers.ecu_arch_detector import EcuArchDetector

# From file
det = EcuArchDetector.from_path("unknown_rom.bin")
result = det.detect()
print(result.arch, result.confidence)   # e.g.  "sh2a"  "HIGH"
print(result.reason)

# From bytes
det = EcuArchDetector.from_bytes(rom_bytes)
result = det.detect()

# All candidates ranked by score
for cand in det.candidates():
    print(f"  {cand.arch:12s}  score={cand.score:.2f}  {cand.reason}")
```

### Constructor parameters

| Parameter | Default | Description |
|---|---|---|
| `data` | — | `bytes`, file path (`str`/`Path`), or buffer |
| `sample_size` | 4096 | Bytes from start of image to use for density sampling. Pass 0 to sample the full image. |

---

## ArchDetectResult fields

```python
@dataclass
class ArchDetectResult:
    arch:        str              # best-match ISA or "unknown"
    confidence:  str              # "HIGH" (≥0.75) / "MEDIUM" (≥0.40) / "LOW" (<0.40)
    score:       float            # numeric score for the winning arch (0.0–1.0)
    reason:      str              # one-sentence explanation
    candidates:  list[ArchCandidate]  # all arches sorted by score desc

    @property
    def is_confident(self) -> bool: ...  # True for HIGH or MEDIUM
```

---

## Discriminators

### TriCore AURIX

Scans the **full image** (not the 4 KB sample) for little-endian 32-bit pointer values in
AURIX-specific address ranges (TC1.8 Architecture Manual Vol 1, §8 Table 13):
- PFLASH (code+data flash, cached + uncached): `0x80000000–0xBFFFFFFF` (segments 8–B)
- Peripheral space (SFRs): `0xE0000000–0xFFFFFFFF` (segments E–F)

Secondary signal: ELF `e_machine == 44` (EM_TRICORE) with `EI_DATA == 1` (LE) → score 0.90
immediately without any density scan.

Artifact guard: big-endian ROMs (SH-2A, M68K, PPC32) produce false PFLASH hits when their
instruction bytes are read as LE 32-bit words.  The guard fires when
`periph_density > 15 % AND periph_density > 2 × pflash_density`, which is characteristic
of BE instruction streams misread as LE (periph:pflash ratio 3–6×) but is never seen in real
TriCore firmware (ratio ~1.1×).

Score 0.85 when PFLASH density ≥ 3 % and peripheral density ≥ 1 %; 0.75 for PFLASH ≥ 3 %
only; 0.60 for PFLASH ≥ 1.5 %; 0.45 for peripheral ≥ 2 % only.

### ARM Cortex-M

Vector table at offset 0 (little-endian):
- Word at offset 0: initial MSP — must be in SRAM range `0x20000000–0x3FFFFFFF`
- Word at offset 4: reset handler — must have Thumb bit set (LSB=1) and point into flash (`< 0x20000000`)

Score 0.90 when both hold; 0.55 when only MSP is in SRAM.

### M68K / CPU32

Big-endian reset vector:
- Word at offset 4: initial PC — must be within the image size

Secondary signal: LINK.W A6, #-N prologue density (`0x4E56` + negative 16-bit displacement).

Score 0.85 when reset-in-range + LINK density ≥ 1%; 0.70 for reset only; 0.35 for LINK density ≥ 2% with no reset vector.

### PPC32 Book E

Primary opcode density in PPC32-characteristic ranges:
- `0x08–0x0F`: subfic/addic/addi/addis/BC
- `0x38–0x3F`: load/store immediate (stb/sth/stw/lbz/lhz/lwz)
- `0x80–0x9F`: load/store family

Score = opcode-density fraction (capped at 1.0); only fires at ≥ 35% density.

### PPC VLE

First-byte pattern for VLE 32-bit instructions: `(byte0 & 0x90) == 0x10`.
Score = `min(density * 2.5, 0.92)`; fires at ≥ 15% VLE-halfword density.

### SH-2A / SH-2

Big-endian reset vector at offset 4 + instruction density:
- `0x4F22` (STS.L PR, @-R15) — primary prologue: density ≥ 0.1%
- `0x000B` (RTS) — return instruction: density ≥ 0.2%

Score 0.88 for reset + STS.L density; 0.75 for reset + RTS density; 0.60 for reset only; 0.40 for STS.L density without reset.

---

## Limitations

- Discriminators are density-based: a ROM with very little code in the first 4 KB sample (e.g., a ROM that starts with calibration tables) may misidentify or return LOW confidence.  Pass `sample_size=0` to sample the full image.
- ARM Cortex-M identification is based solely on the vector table (no instruction density signal).  A ROM that happens to have a 4-byte value in the SRAM range at offset 0 will false-positive.  Use with `is_confident` check.
- No support for RISC-V, RH850, or SH-4 — add a new `_score_*` method following the same pattern.
- TriCore detection requires scanning the full image; calling `EcuArchDetector(data, sample_size=N)` with a small N will still cause the TriCore discriminator to scan all of `data`, not the sample.  This is intentional: startup code density is too low in the first few KB.
- TriCore artifact guard (`periph > 2 × pflash AND periph > 15 %`) may reject a legitimate TriCore binary if the code region happens to have very heavy SFR access with low function-call density.  In that case pass `sample_size=0` and verify manually.
