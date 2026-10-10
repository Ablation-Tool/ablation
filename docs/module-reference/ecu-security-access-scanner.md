# EcuSecurityAccessScanner

**File:** `ablation/analyzers/ecu_security_access_scanner.py`

---

## Why this exists

2 things that were not possible before in Ablation:

**1. No SecurityAccess static-seed fingerprinter for M68K/CPU32 ECUs.** The GM P-series PCM
family (P01, P04, P05, P08, P10, P11, P59) runs on Motorola CPU32, which is a M68K derivative.
Before this module, there was no way to detect the static-seed requestSeed flaw in M68K ROM
images. The flaw stores 0x67 (the SA subfunction code) directly into the seed response buffer and
clears the remaining bytes. Any key algorithm computed from a known static value is trivially
reproduced offline. Manual inspection required recognizing the `MOVE.B #$67; CLR.B; CLR.B`
sequence by hand, with no tool support.

**2. No SecurityAccess static-seed fingerprinter for PPC32 ECUs.** The GM E38 PCM runs a PPC
e200 core. The same flaw appears as `li rX, 0x67; stb; li rY, 0; stb; li rZ, 0; stb`. Before
this module, identifying this pattern required manual disassembly of each SA handler candidate.
There was no automated way to scan a 2 MB PPC32 ROM and locate the exact instruction site.

---

## The flaw

A UDS/KWP2000 SecurityAccess implementation is required to return a cryptographic challenge
(seed) that changes on every invocation. If the seed is static, the challenge is fixed and
an attacker can precompute the key offline, replay it, and bypass SecurityAccess entirely.

In the GM corpus, the static seed is `0x67` followed by zero bytes because the requestSeed
handler copies the SA subfunction code into the seed response buffer instead of generating a
random value. The pattern is identical across all P-series CPU32 variants and the E38 PPC32
region.

---

## Detection algorithm

### M68K / CPU32 fingerprint

The M68K encoding for `MOVE.B #$67, <mem>` always satisfies:

```
byte[0] & 0xF0 == 0x10   (MOVE.B opcode: top nibble = 1)
byte[1] & 0x3F == 0x3C   (source EA = immediate: mode=111, reg=100)
byte[2] == 0x00           (high byte of immediate word)
byte[3] == 0x67           (the seed byte value)
```

This mask covers all M68K destination addressing modes in one comparison:
`(Dn)`, `(An)`, `(An)+`, `-(An)`, `(d16,An)`, `abs.W`, and `abs.L`.

After the MOVE.B is found, the scanner looks within the next `window` bytes (default 256) for
at least two CLR.B instructions. CLR.B encodes as:

```
byte[0] == 0x42           (CLR opcode high byte)
byte[1] < 0x40            (size = byte: bits[7:6] = 00)
```

Both conditions must be satisfied at a 2-byte-aligned offset.

### PPC32 fingerprint

`li rX, N` encodes as `addi rX, r0, N` (opcode 14). The register field sits in bits [25:21].
Masking with `0xFC1FFFFF` zeroes those bits, making one comparison match all 32 registers:

```
(word & 0xFC1FFFFF) == 0x38000067   (li rX, 0x67, any register)
```

The immediately following word must be `stb` (opcode 38 = `0x26`):

```
(word >> 26) == 38
```

After this `li/stb` trigger is found, the scanner looks within the next `window` bytes for
two `(li rY, 0; stb)` pairs using the same masks with `simm16 = 0`:

```
(word & 0xFC1FFFFF) == 0x38000000   (li rY, 0, any register)
followed by: (word >> 26) == 38     (stb)
```

---

## Usage

```python
from ablation.analyzers.ecu_security_access_scanner import EcuSecurityAccessScanner

# Scan from path
findings = EcuSecurityAccessScanner.from_path("E38_2048KiB_12607218.bin").scan()
for f in findings:
    print(f)

# Scan from bytes already loaded
findings = EcuSecurityAccessScanner.from_bytes(rom_bytes).scan()

# Always check is_calibration_only() first on an unknown image
from ablation.analyzers.ecu_rom_layout_analyzer import EcuROMLayoutAnalyzer

layout = EcuROMLayoutAnalyzer.from_bytes(rom_bytes).analyze()
cal_only, reason = layout.is_calibration_only()
if not cal_only:
    findings = EcuSecurityAccessScanner.from_bytes(rom_bytes).scan()
```

### Constructor parameters

| Parameter | Default | Description |
|---|---|---|
| `window` | 256 | Byte radius to search for confirming instructions. M68K corpus patterns use ≤8 bytes; PPC32 can have setup code up to ~200 bytes before the confirming stores. |

---

## SecurityAccessFinding

Each finding in the returned list:

```python
@dataclass
class SecurityAccessFinding:
    offset: int     # byte offset of the triggering instruction in the ROM
    arch: str       # "M68K" or "PPC32"
    pattern: str    # "static-seed-requestSeed"
    evidence: bytes # raw bytes from trigger site to end of window
    note: str       # human-readable description

    def __str__(self) -> str
```

---

## Validated results

### GM P01 (CPU32, J1850 VPW OBD-II)

```
0x00000B60  [M68K]  static-seed-requestSeed
  move.b  #$67, $34(a5)   ; seed[0] = 0x67
  clr.b   $35(a5)          ; seed[1] = 0x00
  clr.b   $36(a5)          ; seed[2] = 0x00
```

Confirmed across full P-series family: P01, P04, P05, P08, P10, P11, P59. All use the same
requestSeed handler; offset varies by variant but byte pattern is identical. GM-DIAG-001 (CRITICAL):
combined with the unconditional sendKey acceptance in GM-DIAG-002, this is a full unauthenticated
reflash chain over OBD-II DLC pin 2.

### GM E38 PCM (PPC e200, PPC32 region)

```
0x00006114  [PPC32]  static-seed-requestSeed
  li    r3, 0x67    ; seed[0] = 0x67
  stb   r3, 0(r4)
  li    r3, 0       ; seed[1] = 0x00
  stb   r3, 1(r4)
  li    r3, 0       ; seed[2] = 0x00
  stb   r3, 2(r4)
```

Confirmed at VA 0x6114. A second service 0x27 handler exists at 0x6404 but maps to an internal
SWCAN command index, not UDS SecurityAccess. The SA handler at 0x6114 feeds a state machine
via SRAM variable 0x3FFFE98E; see `auto_ecu_corpus_re.py` for the full state machine analysis.

---

## Limitations

- The scanner does not disassemble. It applies fixed byte masks. A compressed or encrypted
  code region will not match even if the underlying code contains the pattern.
- PPC32 VLE (Variable Length Encoding) instructions used in the GM E38 upper address region
  are not decoded. VLE opcodes do not match the fixed-width masks, so VLE regions produce no
  false positives but also no detections. Use `EcuROMLayoutAnalyzer.code_regions()` to check
  whether the ROM has VLE content before concluding a negative result is definitive.
- No M32R, SH-2A, or TriCore patterns are implemented. These ISAs are present in the corpus
  (Subaru SH7058S, Honda CBR250RR) but their SA handlers were not analyzed.
- The `window` parameter applies to both architectures. For a heavily optimized ROM where the
  compiler reorders instructions extensively, increasing `window` may be needed, at the cost of
  more false positives on images with accidental 0x67 byte occurrences.
