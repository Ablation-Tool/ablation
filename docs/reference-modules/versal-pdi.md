# VersalPdi

  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [API reference](#api-reference)
  - [Usage](#usage)
  - [Example output](#example-output)
  - [Known targets](#known-targets)
  - [See also](#see-also)

**File:** `ablation/analyzers/versal_pdi.py`

---

## Why this exists <sup>[↑](#versalpdi)</sup>

1. **Versal PDI is the primary firmware delivery format for Xilinx Versal ACAP.** Every programmable image that runs on Versal (VC1902, VCK5000, and variants) is packaged as a PDI — including the PL bitstream, PLM bootloader, AI Engine CDO, and NoC configuration. The CERN ATLAS ITk FELIX and GEP boards use Versal; understanding the PDI format is prerequisite to any firmware RE or build-provenance tracking on those targets.

2. **Two physically distinct PDI sub-formats exist in the collection.** `bootgen` produces different headers depending on the output type. A pld PDI (PL-only, no boot) has 4 sync words followed by a plaintext Image Header Table. A boot PDI (full system image with PLM) has 5 sync words and an "XLNX" identification word; its IHT is partially opaque because the MetaHeader CDO wraps it. Both are present in the ATLAS GEP/FELIX collection; a parser that only handles one type silently fails on the other.

3. **Git hashes are embedded in two independent locations.** Every PDI built by `bootgen` embeds the 4-byte truncated commit hash: (a) at image header offset +0x2c for pld PDIs, and (b) as the 4th payload word of the `XILPDI/IMG_ID` CDO command broadcast into every CDO section. This dual-embedding means `VersalPdi.git_hash()` can recover the build commit for both PDI types — and for arbitrary CDO blobs extracted from encrypted partitions.

4. **CDO sections carry all high-value register and configuration data.** A PDI's entire NPI (NoC/PL interface) initialization, error-handling setup, and image metadata lives in CDO sections. Parsing CDO commands exposes: register write sequences, NPI addresses touched during boot, module identifiers, and the XILPDI broadcast payload. For security-relevant RE (boot-time privilege escalation, PL misconfiguration, register backdoors) the CDO command stream is the primary artifact.

5. **Existing `XilinxBitfile` does not parse PDI.** PDI is structurally unrelated to the `.bit` format parsed by `XilinxBitfile`. `.bit` is a Type1/Type2 configuration packet stream for 7-series and earlier; PDI is a container format for Versal that includes CDO sections, ELF partition payloads, and a Versal-specific IHT. A separate module is required.

---

## How it works <sup>[↑](#versalpdi)</sup>

### PDI format overview

A PDI file starts with a **MetaHeader**: a sequence of 32-bit LE sync words that identify the file type:

```
pld PDI (PL-only, e.g. GCI GCM415 / GEP GCM3):
  [0x00]  0x000000DD  sync0
  [0x04]  0x11223344  sync1
  [0x08]  0x55667788  sync2
  [0x0C]  0x99AABBCC  sync3
  [0x10]  IHT starts here

boot PDI (full system with PLM, e.g. GCI boot / FLX182):
  [0x00]  0x000000DD  sync0
  [0x04]  0x11223344  sync1
  [0x08]  0x55667788  sync2
  [0x0C]  0x99AABBCC  sync3
  [0x10]  0xAA995566  sync4 (5th sync, distinguishes boot PDI)
  [0x14]  0x584C4E58  "XLNX" identification
  [0x14]  IHT starts here (same offset as XLNX word for boot PDI)
```

### Image Header Table (IHT)

For pld PDI (confirmed from GCI_GCM415_pld RE at 2026-10):

| Field | Offset from IHT | Semantics |
|---|---|---|
| pdi_flags | +0x00 | PDI type flags (0x00040000 for pld) |
| no_of_imgs | +0x04 | Count of image headers |
| img_hdr_off | +0x08 | Word offset from file start to first image header |
| total_no_of_prtns | +0x0C | Total partition count |
| part_hdr_off | +0x10 | Word offset from file start to first partition header |
| sbd_off | +0x14 | Secondary boot device offset |
| checksum | +0x18 | XOR checksum |

For boot PDI: fields at +0x08 and +0x0C hold fixed magic constants (`0x00000F80`, `0xF2000000`) that are the same across all known boot PDIs — they are not variable counts. The parser records these under `pdi_flags` and `no_of_imgs` but marks `img_hdr_off = 0` as unreliable.

### Image headers

Image headers (0x40 bytes each) are at `img_hdr_off × 4` bytes from file start. Key fields:

| Offset | Field | Notes |
|---|---|---|
| +0x00 | first_prtn_hdr_off | Word offset to first partition header |
| +0x04 | no_of_prtns | Partitions in this image |
| +0x0C | img_attrb | Image attribute flags |
| +0x10 | img_name[16] | Null-terminated ASCII; "CONFIG_MASTER" for PL images |
| +0x20 | img_id | 32-bit image identifier |
| +0x2C | git_hash | 4-byte truncated commit hash, confirmed vs. filename suffix |

The `git_hash` at +0x2C was independently verified: `GCI_GCM415_pld-v0.159.38-35A2CC3.pdi` → `img_hdr[+0x2C] = 0x035A2CC3` (filename suffix `35A2CC3`). Same for `GEP_2ACC_GCM3_pld-v0.159.40-F119A21.pdi` → `0x0F119A21` (suffix `F119A21`).

### Partition headers

Partition headers (0x3C bytes each) immediately follow at `part_hdr_off × 4`. Key fields:

| Offset | Field | Notes |
|---|---|---|
| +0x00 | enc_data_word_len | Encrypted size in 32-bit words |
| +0x04 | unenc_data_word_len | Unencrypted size |
| +0x08 | total_data_word_len | Total size including auth certificate |
| +0x0C | next_prtn_off | Word offset to next PH (0 = last) |
| +0x10/+0x14 | dst_exec_addr lo/hi | 64-bit execution address |
| +0x18/+0x1C | dst_load_addr lo/hi | 64-bit load address; `0xFFFF_FFFF_FFFF_FFFF` = PL/CFRAME |
| +0x20 | data_word_off | Word offset to partition data payload |
| +0x24 | prtn_attrb | Type in bits[4:0], encryption in bit[23] |
| +0x28 | section_count | |
| +0x38 | checksum | XOR |

**Partition type codes** (bits[4:0] of `prtn_attrb`):

| Code | Name | Meaning |
|---|---|---|
| 0x01 | ELF/A72 | APU ELF image |
| 0x02 | CDO | Generic CDO subsystem config |
| 0x03 | PMC_CDO | PMC-specific CDO |
| 0x04 | AIE_CDO | AI Engine CDO |
| 0x05 | ELF/R5 | RPU ELF image |
| 0x06 | CFICDR/PL | PL config frame (bitstream) |

A `dst_load_addr = 0xFFFFFFFFFFFFFFFF` marks PL CFRAME partitions — the PL config data goes directly to the CFRAME interface, not a memory address.

### CDO section format

Every partition data payload starts with a 4-byte prefix word followed by the CDO magic `CDO\x00`:

```
partition_data_offset = data_word_off × 4      # the 4-byte prefix
CDO_magic_offset      = data_word_off × 4 + 4  # "CDO\x00"
```

CDO header (4 × 4 = 16 bytes):

| Word | Field | Confirmed value |
|---|---|---|
| 0 | magic | `0x004F4443` = "CDO\x00" LE |
| 1 | version | `0x00000200` = "2.0" (bits[15:8]=major=2, bits[7:0]=minor=0) |
| 2 | length_words | Payload word count (excludes the 4-word CDO header) |
| 3 | checksum | XOR of all payload words |

CDO commands follow at CDO_base + 16. The CDO scanner finds all CDO sections by scanning for the `CDO\x00` magic pattern directly — this works for both pld and boot PDI types, and for arbitrary extracted CDO blobs.

### CDO command format

Each CDO command is a 32-bit LE header word followed by `payload_len` × 4-byte words:

```
bits[31:28]  reserved
bits[27:16]  payload_length_words
bits[15:8]   module_id
bits[7:0]    cmd_id
```

Important module/command combinations found in GEP/FELIX PDIs:

| Module | Module ID | Command | Cmd ID | Payload summary |
|---|---|---|---|---|
| GENERIC | 0x01 | WRITE32 | 0x01 | addr, value |
| GENERIC | 0x01 | MASK_WRITE32 | 0x03 | addr, mask, value |
| GENERIC | 0x01 | NPI_WRITE | 0x13 | npi_addr, data… |
| GENERIC | 0x01 | KEYHOLE_WRITE | 0x0D | bulk data write |
| GENERIC | 0x01 | SSIT_SYNC | 0x19 | type, string bytes |
| GENERIC | 0x01 | NOP | 0x1B | (variable, padding) |
| ERROR | 0x02 | various | — | error/event config |
| XILPDI | 0x07 | IMG_ID | 0x04 | imgid, hash1, hash2, **git_hash** |

The XILPDI `IMG_ID` command (module=0x07, cmd=0x04) carries 4 words: the image ID and 3 hash/version words, with the git hash always at payload[3] (confirmed from GCI GCM415 builds).

---

## API reference <sup>[↑](#versalpdi)</sup>

```python
from ablation.analyzers.versal_pdi import (
    VersalPdi,
    VersalPdiResult,
    PdiIHT, PdiImageHeader, PdiPartitionHeader,
    CdoSection, CdoCommand,
    CDO_MAGIC, PDI_SYNC_WORD_0,
    PRTN_TYPE_CFICDR, PRTN_TYPE_ELF, PRTN_TYPE_CDO,
    PRTN_TYPE_NAMES,
    CDO_MOD_GENERIC, CDO_MOD_XILPDI,
    CDO_CMD_WRITE, CDO_CMD_NPI_WRITE, CDO_CMD_NOP, CDO_CMD_XILPDI_IMGID,
)
```

**Top-level parser:**

| Method | Input | Returns |
|---|---|---|
| `VersalPdi.from_path(path)` | file path `str` | `VersalPdi` |
| `VersalPdi.from_bytes(data, label)` | `bytes`, optional label | `VersalPdi` |
| `VersalPdi.scan_directory(dir, glob)` | directory path | `List[VersalPdi]` |
| `VersalPdi.report_all(pdis)` | `Sequence[VersalPdi]` | multi-entry report `str` |

**VersalPdi instance accessors:**

| Property / Method | Returns | Notes |
|---|---|---|
| `.result` | `VersalPdiResult` | Full parse result; computed once |
| `.cdo_sections()` | `List[CdoSection]` | All CDO sections found by pattern scan |
| `.images()` | `List[PdiImageHeader]` | Image headers (pld PDI only; empty for boot) |
| `.partitions()` | `List[PdiPartitionHeader]` | Partition headers (pld PDI only) |
| `.git_hash()` | `str` | 8-char hex; "" if not found |
| `.report()` | `str` | Human-readable summary |

**VersalPdiResult fields:**

| Field | Type | Notes |
|---|---|---|
| `path` | `str` | File path or label |
| `file_size` | `int` | Bytes |
| `pdi_type` | `str` | `"pld"`, `"boot"`, or `"unknown"` |
| `sync_word_count` | `int` | 4 (pld) or 5 (boot) |
| `iht` | `Optional[PdiIHT]` | Image Header Table; None if truncated |
| `images` | `List[PdiImageHeader]` | |
| `partitions` | `List[PdiPartitionHeader]` | |
| `cdo_sections` | `List[CdoSection]` | All CDO sections found |
| `parse_warnings` | `List[str]` | Non-fatal issues |

**PdiPartitionHeader key properties:**

| Property | Type | Notes |
|---|---|---|
| `.prtn_type` | `int` | bits[4:0] of prtn_attrb |
| `.prtn_type_name` | `str` | Human name from `PRTN_TYPE_NAMES` |
| `.is_pl` | `bool` | True if `CFICDR/PL` type |
| `.is_encrypted` | `bool` | True if bit[23] of prtn_attrb set |
| `.data_byte_offset` | `int` | `data_word_off × 4` (prefix word) |
| `.cdo_byte_offset` | `int` | `data_word_off × 4 + 4` (CDO magic) |
| `.data_size_bytes` | `int` | `enc_data_word_len × 4` |

**CdoSection fields:**

| Field | Type | Notes |
|---|---|---|
| `offset` | `int` | Byte offset of CDO magic in file |
| `version` | `int` | Version word (0x00000200 in known files) |
| `version_str` | `str` | `"major.minor"` (0x00000200 → "2.0") |
| `length_words` | `int` | Payload word count |
| `checksum` | `int` | XOR checksum of payload |
| `commands` | `List[CdoCommand]` | Parsed commands (capped at 50,000) |
| `parse_error` | `str` | Set if command parsing was truncated |

**CdoCommand fields:**

| Field | Type | Notes |
|---|---|---|
| `offset` | `int` | Byte offset of command header in file |
| `module_id` | `int` | Module ID bits[15:8] |
| `cmd_id` | `int` | Command ID bits[7:0] |
| `payload` | `Tuple[int, ...]` | Up to 8 stored payload words |
| `module_name` | `str` | From `CDO_MOD_NAMES` |
| `cmd_name` | `str` | From per-module command tables |
| `string_payload` | `str` | Extracted ASCII (SSIT_SYNC / MARKER commands) |
| `npi_addr` | `Optional[int]` | NPI address for WRITE32 / NPI_WRITE to 0xF0...+ |
| `npi_data` | `Optional[int]` | First data word for NPI writes |

---

## Usage <sup>[↑](#versalpdi)</sup>

**Parse a pld PDI and print its summary:**

```python
from ablation.analyzers.versal_pdi import VersalPdi

vp = VersalPdi.from_path('/media/cowboy/research/CERN/fw/gep/GCI_GCM415_pld-v0.159.38-35A2CC3.pdi')
print(vp.report())
# VersalPdi: GCI_GCM415_pld-v0.159.38-35A2CC3.pdi
#   type=pld  sync_words=4  size=0x159680 bytes (1.3 MB)
#   git_hash=035a2cc3
#   IHT at 0x10:  no_of_imgs=1  total_prtns=1  ...
#   Images (1):
#     [CONFIG_MASTER]  id=0x...  git=0x035a2cc3  prtns=1
#   Partitions (1):
#     [0] CFICDR/PL  size=0x...B  dst=0xffffffffffffffff  data_off=0x54(→0x154)
#   CDO sections (2):
#     @0x00000154  v2.0  len=...w  ...
```

**Extract all NPI writes from a boot PDI:**

```python
from ablation.analyzers.versal_pdi import VersalPdi, CDO_MOD_GENERIC, CDO_CMD_NPI_WRITE, CDO_CMD_WRITE

vp = VersalPdi.from_path('/media/cowboy/research/CERN/fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi')

npi_writes = []
for section in vp.cdo_sections():
    for cmd in section.commands:
        if cmd.npi_addr is not None:
            npi_writes.append((cmd.offset, cmd.npi_addr, cmd.npi_data))

print(f"{len(npi_writes)} NPI register writes")
for off, addr, val in npi_writes[:10]:
    print(f"  @{off:#x}  NPI[{addr:#010x}] = {val:#010x}")
```

**Recover git hash from a boot PDI:**

```python
vp = VersalPdi.from_path('/media/cowboy/research/CERN/fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi')
print(vp.git_hash())  # → "035a2cc3"
# Works via XILPDI IMG_ID command even when IHT image header offsets are opaque
```

**Batch-parse a firmware directory:**

```python
pdis = VersalPdi.scan_directory('/media/cowboy/research/CERN/fw/gep', glob='*.pdi')
for vp in pdis:
    print(f"{vp.result.path}  git={vp.git_hash()}  type={vp.result.pdi_type}  "
          f"cdos={len(vp.cdo_sections())}")
```

**Extract string labels from CDO SSIT_SYNC commands:**

```python
for section in vp.cdo_sections():
    for cmd in section.commands:
        if cmd.string_payload:
            print(f"  @{cmd.offset:#010x} [{cmd.module_name}/{cmd.cmd_name}] \"{cmd.string_payload}\"")
# e.g.:
#   @0x0000b984 [GENERIC/SSIT_SYNC] "bolt_la"  ← block label prefix
#   @0x0000b9c4 [GENERIC/SSIT_SYNC] "servrpla"
```

**Scan an arbitrary CDO blob (no PDI sync words):**

```python
# Extracted CDO partition, no MetaHeader wrapper
with open('/tmp/extracted_cdo.bin', 'rb') as f:
    data = f.read()

vp = VersalPdi.from_bytes(data, 'extracted_cdo.bin')
# pdi_type will be "unknown" but cdo_sections() still works
print(f"Found {len(vp.cdo_sections())} CDO sections in blob")
```

---

## Example output <sup>[↑](#versalpdi)</sup>

**`vp.report()`** on `GCI_GCM415_pld-v0.159.38-35A2CC3.pdi`:

```
VersalPdi: GCI_GCM415_pld-v0.159.38-35A2CC3.pdi
  type=pld  sync_words=4  size=0x159680 bytes (1.3 MB)
  git_hash=035a2cc3
  IHT at 0x10:  no_of_imgs=1  total_prtns=1  img_hdr_off=0x24  part_hdr_off=0x34
  Images (1):
    [CONFIG_MASTER]  id=0x18700001  git=0x035a2cc3  prtns=1
  Partitions (1):
    [0] CFICDR/PL  size=0x005ba330B  dst=0xffffffffffffffff  data_off=0x54(→0x154)
  CDO sections (3):
    @0x00000154  v2.0  len=11437w (44KB)  cmds=40  [GENERIC/WRITE32×22, GENERIC/MASK_WRITE32×10, ...]
    @0x0000b974  v2.0  len=861w (3KB)    cmds=20  [GENERIC/WRITE32×12, GENERIC/NOP×4, ...]
    @0x0000c160  v2.0  len=89984w (351KB) cmds=6  [GENERIC/KEYHOLE_WRITE×4, ...]
```

**`vp.report()`** on `GCI_GCM415_boot-v0.159.38-35A2CC3.pdi`:

```
VersalPdi: GCI_GCM415_boot-v0.159.38-35A2CC3.pdi
  type=boot  sync_words=5  size=0x15a0a8 bytes (1.4 MB)
  git_hash=035a2cc3
  IHT at 0x14:  no_of_imgs=0  total_prtns=0  img_hdr_off=0x0  part_hdr_off=0x9600
  CDO sections (8):
    @0x0004f3c4  v2.0  len=9671w (37KB)   cmds=50  [GENERIC/SSIT_SYNC×21, GENERIC/WRITE32×18, ...]
    @0x00059144  v2.0  len=93323w (364KB) cmds=50  [GENERIC/KEYHOLE_WRITE×40, ...]
    ...
```

---

## Known targets <sup>[↑](#versalpdi)</sup>

| PDI file | Type | Git hash | Description |
|---|---|---|---|
| `fw/gep/GCI_GCM415_pld-v0.159.38-35A2CC3.pdi` | pld | `035a2cc3` | GEP GCM415 PL-only, 1.3 MB |
| `fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi` | boot | `035a2cc3` | Same build, full boot image with PLM, 1.4 MB |
| `fw/gep/GEP_2ACC_GCM3_pld-v0.159.40-F119A21.pdi` | pld | `0f119a21` | Larger PL fabric (GCM3), 12 MB |
| `fw/felix/FLX182_STRIPS_..._1448.pdi` | boot | — | FELIX FLX182 boot image, 35 MB |

**Build provenance:** All known GCI/GEP pld PDIs contain `img_name = "CONFIG_MASTER"`. The `git_hash` at image header +0x2C always matches the hex suffix in the filename (e.g. `35A2CC3` → `0x035a2cc3`). This provides tamper-evident version tracking without unpacking the bitstream.

---

## See also <sup>[↑](#versalpdi)</sup>

- `XilinxBitfile` — parser for Spartan-3/6/7-series `.bit` files (not for Versal PDI)
- `XilinxFrameDecoder` — Type1/Type2 config packet decoder (not applicable to PDI)
- `re/atlas/gep_re.py` — GEP/GCI build inventory and git hash timeline
- `LpgbtDecoder` — lpGBT e-link protocol decoder used in the GEP/FELIX firmware
- `LatexReExtractor` — for reading lpGBT/HCC specification documents alongside PDI analysis
