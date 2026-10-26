# XilinxFrameDecoder

Decode Xilinx Type1/Type2 configuration packets from uncompressed bitstreams. Compare configuration frame data across firmware versions.

---

## Why this exists

1. **The ATLAS ITk strip detector ships 60+ firmware versions for the ABC130 driver (XC3S50AN) and 160+ for the Atlys ITSDAQ (XC6SLX45).** Version archaeology — understanding what changed between e.g. va017 and va455 — requires frame-level comparison. Without this module, all 60+ bitfiles look like opaque binary blobs.

2. **BinaryContext/Capstone cannot run on FPGA configuration bitstreams.** A `.bit` file is not an ELF or PE. Its executable content is FPGA fabric configuration (LUT init values, routing bits, I/O configuration), not CPU instructions. The XilinxBitfile parser gets the header metadata; XilinxFrameDecoder gets the configuration content.

3. **Spartan-6 uses streaming FDRI mode, not Type2-wrapped bulk writes.** After CMD=WCFG, frame data flows as raw 32-bit words without packet wrappers — the FPGA's internal FAR auto-increments. Standard `0x5000xxxx` Type2 scan finds only frame data bytes that happen to match the pattern, not real headers. `heuristic_frame_bytes()` correctly extracts the frame region by skipping the setup header and epilogue.

4. **Spartan-6 bitstreams have TWO sync words.** The first (`0xAA995566` at offset ~16) is a bus-width detection marker. The second (at offset ~84) marks the actual configuration stream start. Using the wrong sync word produces garbage packet decodes.

---

## Constructor

```python
from ablation.analyzers.xilinx_bitfile import XilinxBitfile
from ablation.analyzers.xilinx_frame_decoder import XilinxFrameDecoder

bf  = XilinxBitfile.from_path('/path/to/design.bit')
dec = XilinxFrameDecoder.from_bitfile(bf)
print(dec.summary())
```

No `from_context()` variant — this is a file-format analyzer, not a binary code analyzer.

---

## Key methods

| Method | Returns |
|---|---|
| `dec.summary()` | Part, family, sync offset, packet count, frame data size |
| `dec.packets()` | List of `ConfigPacket` (setup packets for S6; all packets for 7-series) |
| `dec.config_registers()` | Dict `{reg_name: final_value}` for single-word writes |
| `dec.frame_data()` | List of raw payload bytes per FDRI write (7-series only) |
| `dec.far_fdri_pairs()` | List of `(far_addr, frame_bytes)` tuples (7-series) |
| `dec.heuristic_frame_bytes()` | Raw frame region bytes (skips setup/epilogue; works for all families) |
| `dec.frame_diff(other)` | Dict `{word_offset: (bytes_self, bytes_other)}` for differing words |
| `dec.idcode()` | IDCODE value from IDCODE write packet, or 0 if not present |
| `dec.family()` | Family tag: `'7s'`, `'s6'`, `'s3'`, `'ku'` |
| `dec.frame_words()` | Words per configuration frame (65 for S6, 101 for 7-series) |

---

## Version archaeology workflow (Spartan-6 Atlys)

```python
import glob
from ablation.analyzers.xilinx_bitfile import XilinxBitfile
from ablation.analyzers.xilinx_frame_decoder import XilinxFrameDecoder

paths = sorted(glob.glob('/media/.../atlys_itsdaq_va*.bit'))
decoders = [XilinxFrameDecoder.from_bitfile(XilinxBitfile.from_path(p)) for p in paths]

# Compare consecutive versions
for i in range(len(decoders) - 1):
    diff = decoders[i].frame_diff(decoders[i + 1])
    print(f'{paths[i].split("/")[-1]} → {paths[i+1].split("/")[-1]}: {len(diff)} differing words')
```

`frame_diff()` automatically uses `heuristic_frame_bytes()` for Spartan-6 when `frame_data()` is empty.

---

## Family-specific notes

| Family | Sync words | FDRI extraction | Packet decode |
|---|---|---|---|
| 7-series (xc7k, xc7a, xc7v) | 1 | T1(wc=0)→T2 Write, `frame_data()` | Full |
| Spartan-6 (6slx) | 2 (use second) | Streaming mode, `heuristic_frame_bytes()` | Setup packets only |
| Spartan-3AN (3s) | 0 (absent) | `heuristic_frame_bytes()` (full bitstream minus preamble) | None |
| UltraScale+ (xcku) | 1 | Compressed (FELIX FLX712) — use `part_name()` only | None |

---

## Packet format (7-series and Spartan-6 share the same header encoding)

```
Type1: [31:29]=001  [28:27]=opcode  [26:18]=rsvd  [17:13]=reg(5b)  [12:11]=rsvd  [10:0]=wcount(11b)
Type2: [31:29]=010  [28:27]=opcode  [26:0]=wcount(27b)
NOP:   Type1 with opcode=00, wcount=0 (word 0x20002000)
Sync:  0xAA995566
```

Opcodes: `00`=NOP, `01`=Read, `10`=Write, `11`=Reserved

---

## Register maps

**7-series (UG470):** FAR=0x01, FDRI=0x02, CMD=0x04, CTL0=0x05, IDCODE=0x0C

**Spartan-6 (UG380):** FAR_MAJ=0x01, FAR_MIN=0x02, FDRI=0x03, CMD=0x05, CTL=0x06, IDCODE=0x0E

---

## FORGE status

**PASSED** 0 CRITICAL, 0 HIGH, 1 MEDIUM. Cached in ~/.ablation/forge_cache.json.

| Finding | Severity |
|---|---|
| `from_bitfile()` accepts untyped `object`; non-XilinxBitfile raises opaque `AttributeError` | MEDIUM |
