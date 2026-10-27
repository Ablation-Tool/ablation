# LpgbtDecoder

  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [API reference](#api-reference)
  - [Usage](#usage)
  - [Example output](#example-output)
  - [Known targets](#known-targets)
  - [See also](#see-also)

**File:** `ablation/analyzers/lpgbt_decoder.py`

---

## Why this exists <sup>[↑](#lpgbtdecoder)</sup>

1. **Three distinct serial encodings run on ATLAS ITk lpGBT e-links.** The lpGBT chip (Low Power Gigabit Transceiver) is the hub for all front-end communication in the ITk Strip detector. Each lpGBT sits at the End-of-Stave (EoS) and aggregates up to 14 HCC ASIC uplinks and one downlink broadcast. Three physically separate serial streams converge at the lpGBT, each with its own encoding:

   | Direction | Rate | Encoding | Carrier |
   |---|---|---|---|
   | lpGBT → HCC (downlink) | 640 Mb/s | Custom 6B/8B | LCB (Low-latency Command Broadcast) |
   | ABC130 → lpGBT (uplink) | 160 Mb/s | 4-bit symbols | STAR FLINK |
   | HCC → lpGBT (uplink) | 640 Mb/s | Standard 8B/10B | Variable-length packets |

2. **The 6B/8B codec is non-standard and not documented outside the facility VHDL source.** It was derived by Paul Sherwood (facility) and implemented by Matt Warren (UCL HEP) in 2016. The table in `lcb_pkg_globals.vhd` is the only authoritative source; `LpgbtDecoder` embeds the complete table verified against the VHDL decode case-statement in `lcb_decoder.vhd`.

3. **LCB frame structure is the trigger and control backbone.** Every Level-0 Accept (L0A) trigger and Bunch Counter Reset (BCR) reaches the HCC ASICs through LCB frames. Understanding LCB decoding is prerequisite to any latency or trigger-pipeline RE.

4. **Captured serial data exists in the collection.** `data/wireshark_funny_packet_5740.pcap` contains Ethernet-layer FELIX captures; `data/stlog880.txt` contains logged LCB streams from the ITSDAQ test stand. This decoder enables RE of those captures without an FPGA or simulation environment.

---

## How it works <sup>[↑](#lpgbtdecoder)</sup>

### LCB 6B/8B encoding

The LCB encoding maps 6-bit values (0–63) to 8-bit bytes via a custom lookup table `MAP_6B_8B`. Every valid codeword has exactly **4 set bits** (Hamming weight 4 = "4-of-8 code"). This property:

- Guarantees at least two 0→1 transitions per byte at 640 Mb/s — adequate for CDR lock.
- Enables a single-bit parity check: `symbol[7] XOR ... XOR symbol[0]` = 0 for any valid codeword (even weight → XOR of all bits = 0). `lcb_frame_sync.vhd` exploits this for a free per-symbol integrity check.

Four K-symbols (K0–K3) use different 4-of-8 patterns not present in the data table:

| Symbol | Byte | Binary |
|---|---|---|
| K0 | 0x47 | 01000111 |
| K1 | 0x55 | 01010101 |
| K2 | 0x78 | 01111000 |
| K3 | 0x6a | 01101010 |

IDLE_FRAME = K0‖K1 = **0x4755** (16-bit). The frame sync state machine in `lcb_frame_sync.vhd` counts consecutive IDLE_FRAME occurrences at both byte phases; after `COUNTS_MAX` (15) consecutive hits at one phase, it declares locked.

### LCB frame structure

Frames are 16 bits (2 bytes = 2 encoded symbols), transmitted MSB first:

```
  Symbol0 (FSYNC_SYMB0)        Symbol1 (FSYNC_FRAME)
  ┌─────────────────────┐      ┌─────────────────────┐
  │ 8-bit encoded byte  │      │ 8-bit encoded byte  │
  └─────────────────────┘      └─────────────────────┘
  decoded 6-bit value:         meaning depends on Symbol0:
    bit 5: tag_msb               data sym: tag_lsbs[5:0]
    bits 4:1: l0a_map[3:0]       K2 sym:   fast_cmd[3:0]
    bit 0: bcr                   K3 sym:   cmd_hccid[4:0]
```

Frame classification (`LcbFrameType`):

| Symbol0 | Symbol1 | Frame type |
|---|---|---|
| K0 | K1 | IDLE |
| K2 | data | CMD (fast command) |
| K3 | data | CMD (extended — HCC ID in Symbol1) |
| data, l0a_map≠0 | data | L0A (Level-0 Accept) |
| data, bcr=1 only | data | BCR (Bunch Counter Reset) |

7-bit L0A tag: `(tag_msb << 6) | tag_lsbs[5:0]` reconstructed across two frames.

### STAR FLINK encoding

4-bit symbols at 160 Mb/s (one symbol per 40 MHz BCO clock). The 16 possible nibble values:

| Symbol | Value | Meaning |
|---|---|---|
| sIDLE | 0x1 | Idle |
| sBCR | 0x2 | Bunch Counter Reset |
| sLS | 0x3 | Line Sync |
| sBCRLS | 0x4 | BCR + Line Sync |
| sPR | 0x5 | Pipeline Reset header (3 data symbols follow with 9-bit L0ID) |
| sLP | 0x6 | Linpulse header (3 data symbols follow with 9-bit L0ID) |
| sDATA7 | 0x7 | data[2:0] = 111 |
| sDATA0–6 | 0x8–0xe | data[2:0] = 000–110 |

PR/LP packets carry a 9-bit L0ID across 3 consecutive data symbols (3 bits each), MSB first: `L0ID = (d0 << 6) | (d1 << 3) | d2`.

### Standard 8B/10B (HCC uplink)

Industry-standard ANSI X3.230-1994 (identical to Fibre Channel / GBT). The decoder table is built from first principles using the 5B/6B and 3B/4B sub-tables from IEEE 802.3 Table 36-2/36-3. Both RD− and RD+ codewords decode to the same byte value. The 12 standard K-symbols (K28.1, K28.5 comma, etc.) are supported.

---

## API reference <sup>[↑](#lpgbtdecoder)</sup>

```python
from ablation.analyzers.lpgbt_decoder import (
    LpgbtDecoder,
    LcbDecoder, LcbFrame, LcbFrameType,
    StarFlinkDecoder, StarFlinkEvent, StarFlinkEventType, StarFlinkSymbol,
    decode_6b8b, encode_6b8b,
    decode_8b10b, encode_8b10b, decode_8b10b_stream,
    LCB_K0, LCB_K1, LCB_K2, LCB_K3, LCB_IDLE_FRAME,
    LCB_SYMB_ECR, LCB_SYMB_ABCRST, LCB_SYMB_HCCRST,
    K28_5, K28_1,
)
```

**Top-level wrapper:**

| Method | Input | Output |
|---|---|---|
| `LpgbtDecoder.lcb(data)` | `bytes` | `List[LcbFrame]` |
| `LpgbtDecoder.star_flink(nibbles)` | `Sequence[int]` | `List[StarFlinkEvent]` |
| `LpgbtDecoder.hcc_8b10b(bits)` | `Sequence[int]` (0/1) | `List[(offset, byte, is_k)]` |

**LcbDecoder:**

| Method | Notes |
|---|---|
| `LcbDecoder.decode_stream(data)` | Phase-aligns automatically (even/odd phase selection) |
| `LcbDecoder.report(frames)` | Summary: counts per frame type + first 5 non-idle frames |

**LcbFrame fields:**

| Field | Type | Notes |
|---|---|---|
| `.offset` | `int` | Byte offset in source stream |
| `.frame_type` | `LcbFrameType` | IDLE / L0A / BCR / CMD / UNKNOWN |
| `.l0a_map` | `int` | 4-bit trigger map from Symbol0[4:1] |
| `.bcr` | `bool` | Bunch Counter Reset from Symbol0[0] |
| `.tag_msb` | `int` | Tag counter MSB from Symbol0[5] |
| `.tag_lsbs` | `int` | Tag LSBs [5:0] from Symbol1 |
| `.fast_cmd` | `int` | Fast command nibble (K2 frames only) |
| `.cmd_hccid` | `int` | HCC ID [4:0] (K3 frames only) |
| `.tag()` | `int` | `(tag_msb << 6) \| tag_lsbs` — reconstructed 7-bit tag |

**StarFlinkDecoder:**

| Method | Notes |
|---|---|
| `StarFlinkDecoder.decode_stream(nibbles)` | Sequence of 4-bit integers |
| `StarFlinkDecoder.report(events)` | Summary + first 5 PR events |

**StarFlinkEvent fields:**

| Field | Type | Notes |
|---|---|---|
| `.offset` | `int` | Nibble offset |
| `.event_type` | `StarFlinkEventType` | IDLE / BCR / LS / BCRLS / PR / LP / INVALID |
| `.l0id` | `int` | 9-bit L0ID (PR/LP events only) |

**Primitive functions:**

| Function | Returns | Notes |
|---|---|---|
| `decode_6b8b(byte)` | `(int, bool)` or `None` | `(6bit_value, is_k)` |
| `encode_6b8b(value, is_k)` | `int` | 8-bit codeword |
| `decode_8b10b(word10)` | `(int, bool)` or `None` | `(byte, is_k)` |
| `encode_8b10b(byte)` | `int` | 10-bit RD− codeword |
| `decode_8b10b_stream(bits)` | `List[(offset, byte, is_k)]` | Flat 0/1 bit list |

---

## Usage <sup>[↑](#lpgbtdecoder)</sup>

**Decode an LCB downlink capture:**

```python
from ablation.analyzers.lpgbt_decoder import LpgbtDecoder, LcbFrameType

with open('/media/cowboy/research/facility/data/stlog880.txt') as f:
    # Parse the text log to extract raw LCB bytes (site-specific parsing)
    lcb_bytes = parse_stlog(f.read())

frames = LpgbtDecoder.lcb(bytes(lcb_bytes))

# Count L0A triggers
l0a_frames = [f for f in frames if f.frame_type == LcbFrameType.L0A]
print(f"{len(l0a_frames)} L0A triggers")

# Find BCR events
bcr_frames = [f for f in frames if f.frame_type == LcbFrameType.BCR]
for f in bcr_frames:
    print(f"BCR at offset {f.offset:#06x}")
```

**Decode a STAR FLINK capture:**

```python
nibbles = [int(n, 16) for n in captured_nibble_hex_list]
events = LpgbtDecoder.star_flink(nibbles)

for evt in events:
    if evt.event_type.name in ('PR', 'LP'):
        print(f"{evt.event_type.name} L0ID={evt.l0id:#04x}")
```

**Decode the 6B/8B codebook:**

```python
from ablation.analyzers.lpgbt_decoder import decode_6b8b, LCB_ASIC_HCC, LCB_ASIC_ABC

# Identify a captured byte
byte = 0xcc
result = decode_6b8b(byte)
if result:
    val, is_k = result
    print(f"0x{byte:02x} → 6b={val:#08b} {'K' if is_k else 'D'}")
# Note: 0xcc = HCC ASIC identifier constant (not a valid LCB codeword — weight 4 violation)
```

**Check 8B/10B decode for HCC uplink:**

```python
from ablation.analyzers.lpgbt_decoder import decode_8b10b, K28_5

# K28.5 comma — used for frame sync and idle fill
result = decode_8b10b(0b0011111010)  # K28.5 RD−
# Returns: (188, True) — byte=0xbc, is_k=True
```

---

## Example output <sup>[↑](#lpgbtdecoder)</sup>

**LcbDecoder.report()** on a 100-frame capture (10 IDLEs, 85 L0As, 3 BCRs, 2 CMDs):

```
LcbDecoder: 100 frames
  IDLE    : 10
  L0A     : 85
  BCR     : 3
  CMD     : 2
  UNKNOWN : 0
  invalid : 0 (bad codewords)
  Non-idle frames (first 5):
    @0002 L0A L0A=0b00011 tag=0x05 [0x96|0x35]
    @0004 L0A L0A=0b00011 tag=0x06 [0x96|0x36]
    @0006 L0A L0A=0b00011 tag=0x07 [0x96|0x1e]
    @0008 BCR [0x71|0x59]
    @000a CMD fast_cmd=0b0011 [0x78|0x8b]
```

**StarFlinkDecoder.report()** on 50 events (40 IDLEs, 8 PRs, 2 BCRs):

```
StarFlinkDecoder: 50 events
  IDLE    : 40
  BCR     : 2
  LS      : 0
  BCRLS   : 0
  PR      : 8
  LP      : 0
  INVALID : 0
  PR events (first 5):
    @0001 PR L0ID=0x000
    @0006 PR L0ID=0x001
    @000b PR L0ID=0x002
```

---

## Known targets <sup>[↑](#lpgbtdecoder)</sup>

| Data file | Protocol | Key content |
|---|---|---|
| `data/stlog880.txt` | LCB downlink | ITSDAQ test stand log — raw HEX LCB frames |
| `data/wireshark_funny_packet_5740.pcap` | Ethernet (FELIX) | FELIX DMA captures — unwrap lpGBT frames from FELIX chunk headers |
| `sims/lcb/downlink/` | LCB VHDL simulation | HDL Designer exports; use `HdlHtmlExtractor` to read |
| `sims/star_flink/readout130/` | STAR FLINK VHDL simulation | HDL Designer exports |

---

## See also <sup>[↑](#lpgbtdecoder)</sup>

- `re/atlas/felix_re.py` — FELIX lpGBT elink assignment map + GENERICS constants
- `HdlHtmlExtractor` — for reading the VHDL sources in `sims/lcb/` and `sims/star_flink/`
- `DocxReExtractor` — for HCC Specification V1.3.1 (register maps)
- `LatexReExtractor` — for lpGBT TDR documents (architecture parameters)
