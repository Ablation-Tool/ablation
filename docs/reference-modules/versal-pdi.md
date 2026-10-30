# VersalPdi

  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [API reference](#api-reference)
  - [Usage](#usage)
  - [Example output](#example-output)
  - [Known platforms](#known-platforms)
  - [See also](#see-also)

**File:** `ablation/analyzers/versal_pdi.py`

---

## Why this exists <sup>[↑](#versalpdi)</sup>

1. **Versal PDI is the primary firmware delivery format for Xilinx Versal ACAP.** Versal devices such as VC1902 and VCK5000 package programmable images as PDIs, including the PL bitstream, PLM bootloader, AI Engine CDO, and NoC configuration. The facility ATLAS ITk FELIX and GEP boards use Versal; understanding the PDI format is prerequisite to firmware RE and build-provenance tracking on those platforms.

2. **Two physically distinct PDI sub-formats exist in the collection.** `bootgen` produces different headers depending on the output type. A PL-only pld PDI has 4 sync words followed by a plaintext Image Header Table. A full-system boot PDI has 5 sync words and an "XLNX" identification word; its IHT is partially opaque because the MetaHeader CDO wraps it. Both are present in the ATLAS GEP/FELIX collection; a parser that only handles one type silently fails on the other.

3. **Some images carry an optional truncated Git identifier in two possible locations.** In the reviewed Hog-generated GCI builds, the identifier occurs at image header offset +0x2c for pld PDIs and as the fourth payload word of a `LOADER/SET_IMAGE_INFO` CDO command. Newer GEP GCM4 images leave both fields zero, proving that a filename suffix is not guaranteed to be embedded. `VersalPdi.git_hash()` returns the nonzero identifier when present and an empty string when absent.

4. **CDO sections carry all high-value register and configuration data.** A PDI's entire NoC/PL interface initialization, error-handling setup, and image metadata lives in CDO sections. Parsing CDO commands exposes register write sequences, NPI addresses touched during boot, module identifiers, and loader image metadata. For security research into boot-time privilege escalation, PL misconfiguration, and register backdoors, the CDO command stream is the primary artifact.

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

For boot PDI: fields at +0x08 and +0x0C hold fixed magic constants `0x00000F80` and `0xF2000000` that are the same across all known boot PDIs: they are not variable counts. The parser records these under `pdi_flags` and `no_of_imgs` but marks `img_hdr_off = 0` as unreliable.

### Image headers

Image headers (0x40 bytes each) are at `img_hdr_off × 4` bytes from file start. Key fields:

| Offset | Field | Notes |
|---|---|---|
| +0x00 | first_prtn_hdr_off | Word offset to first partition header |
| +0x04 | no_of_prtns | Partitions in this image |
| +0x0C | img_attrb | Image attribute flags |
| +0x10 | img_name[16] | Null-terminated ASCII; "CONFIG_MASTER" for PL images |
| +0x20 | img_id | 32-bit image identifier |
| +0x2C | git_hash | Optional 4-byte truncated commit hash; zero means absent |

The `git_hash` at +0x2C was independently verified: `GCI_GCM415_pld-v0.159.38-35A2CC3.pdi` → `img_hdr[+0x2C] = 0x035A2CC3` (filename suffix `35A2CC3`). Same for `GEP_2ACC_GCM3_pld-v0.159.40-F119A21.pdi` → `0x0F119A21` (suffix `F119A21`). The reviewed GEP GCM4 v0.159.66 PLD instead stores zero.

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

A `dst_load_addr = 0xFFFFFFFFFFFFFFFF` marks PL CFRAME partitions: the PL config data goes directly to the CFRAME interface, not a memory address.

### CDO section format

Every partition data payload starts with a 4-byte prefix word followed by the CDO magic `CDO\x00`:

```
partition_data_offset = data_word_off × 4      # the 4-byte prefix
CDO_magic_offset      = data_word_off × 4 + 4  # "CDO\x00"
```

CDO header (prefix + 4 × 4 = 20 bytes):

| Word | Field | Confirmed value |
|---|---|---|
| 0 | prefix | Partition payload prefix, normally `0x00000004` |
| 1 | magic | `0x004F4443` = "CDO\x00" LE |
| 2 | version | `0x00000200` = "2.0": bits 15:8 hold major version 2 and bits 7:0 hold minor version 0 |
| 3 | length_words | Payload word count (excludes prefix and header) |
| 4 | checksum | Bitwise inverse of the 32-bit sum of words 0–3 |

CDO commands follow at CDO_base + 16. Blind discovery requires the header checksum to match; this rejects accidental `CDO\x00` strings in compressed PL data. Direct partition parsing retains invalid-header diagnostics. The checksum authenticates only the header, not the payload, so command-boundary validation is also required.

### CDO command format

Each short CDO command is a 32-bit LE header word followed by `payload_len` × 4-byte words:

```
bits[31:28]  reserved
bits[27:16]  payload_length_words (8-bit value; 0xFF means extended)
bits[15:8]   module_id
bits[7:0]    cmd_id
```

When the length byte is `0xFF`, the next word is the full payload length and the payload starts two words after the command header. The parser skips the complete payload, rejects truncation, and stops at `GENERIC/END` (`0x000001FF`). This prevents PL and MicroBlaze data inside long `DmaWrite`/`DmaWriteKeyHole` commands from being misreported as CDO commands.

Important module/command combinations found in GEP/FELIX PDIs:

| Module | Module ID | Command | Cmd ID | Payload summary |
|---|---|---|---|---|
| GENERIC | 0x01 | MASK_POLL | 0x01 | addr, mask, value, count |
| GENERIC | 0x01 | MASK_WRITE | 0x02 | addr, mask, value |
| GENERIC | 0x01 | WRITE | 0x03 | addr, value |
| GENERIC | 0x01 | KEYHOLE_WRITE | 0x0D | bulk data write |
| GENERIC | 0x01 | NOP | 0x11 | variable-length padding |
| GENERIC | 0x01 | MARKER | 0x19 | type, string bytes |
| XILPM | 0x02 | ADD_NODE | 0x39 | node ID and class-specific arguments |
| XILPM | 0x02 | ADD_NODE_PARENT | 0x3A | node ID, parent IDs |
| XILPM | 0x02 | INIT_NODE | 0x3E | node ID, function, arguments |
| LOADER | 0x07 | SET_IMAGE_INFO | 0x04 | image ID, two metadata words, optional Git identifier |
| ERROR | 0x08 | various |: | error/event config |

The LOADER `SET_IMAGE_INFO` command uses module `0x07` and command `0x04`. It carries an image ID and three metadata words. In the reviewed GCI GCM415 builds, the fourth word is a truncated Git identifier. GEP GCM4 v0.159.66 images leave it zero, and `git_hash()` skips zero values. The second and third words should remain metadata until their platform-specific semantics are established. XILPM `INIT_NODE` handles power-domain, PL-device, and AIE-device initialization; it does not decode XPPU/XMPU protection configuration. AMD XilPM 2024.2 and later silently ignores deprecated protection-class `ADD_NODE` records, so protection conclusions require actual register writes rather than topology or marker names.

---

## API reference <sup>[↑](#versalpdi)</sup>

```python
from ablation.analyzers.versal_pdi import (
    VersalPdi,
    VersalPdiResult,
    PdiIHT, PdiImageHeader, PdiPartitionHeader,
    CdoSection, CdoCommand, DmaWriteSegment,
    CDO_MAGIC, PDI_SYNC_WORD_0,
    PRTN_TYPE_CFICDR, PRTN_TYPE_ELF, PRTN_TYPE_CDO,
    PRTN_TYPE_NAMES,
    CDO_MOD_GENERIC, CDO_MOD_XILPM, CDO_MOD_LOADER,
    CDO_CMD_WRITE, CDO_CMD_WRITE64, CDO_CMD_DMA_WRITE, CDO_CMD_NOP,
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
| `.command_payload(cmd)` | `bytes` | Complete payload, including long commands |
| `.dma_write_segments(section=None)` | `List[DmaWriteSegment]` | Reconstructed destination address and raw load bytes |
| `.embedded_cdo_sections(trailing_words=0)` | `List[EmbeddedCdoSection]` | Reconstructed keyhole-contained CDO images with original offsets and parse errors preserved |
| `.embedded_elf()` | `List[EmbeddedElf]` | Strictly validated embedded ELF payloads; empty if none pass |
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
| `checksum` | `int` | Stored inverse-sum header checksum |
| `header_checksum_valid` | `Optional[bool]` | Prefix + magic + version + length checksum result |
| `commands` | `List[CdoCommand]` | Parsed commands, capped at 50,000 |
| `parse_error` | `str` | Set if command parsing was truncated |
| `end_detected` | `bool` | Whether GENERIC/END terminated the stream |
| `consumed_words` | `int` | Words consumed before END, an error, or section end |

**CdoCommand fields:**

| Field | Type | Notes |
|---|---|---|
| `offset` | `int` | Byte offset of command header in file |
| `module_id` | `int` | Module ID bits[15:8] |
| `cmd_id` | `int` | Command ID bits[7:0] |
| `payload` | `Tuple[int, ...]` | Up to 8 stored payload words |
| `payload_offset` | `int` | File offset of complete payload |
| `payload_length` | `int` | Complete payload length in words |
| `is_long` | `bool` | Whether the extended-length header was used |
| `module_name` | `str` | From `CDO_MOD_NAMES` |
| `cmd_name` | `str` | From per-module command tables |
| `string_payload` | `str` | Extracted ASCII (MARKER / MARKER commands) |
| `npi_addr` | `Optional[int]` | NPI address for WRITE / WRITE64 to 0xF0...+ |
| `npi_data` | `Optional[int]` | First data word for NPI writes |
| `xilpm_node_id` | `Optional[int]` | Node ID for XILPM ADD_NODE / ADD_NODE_PARENT / ADD_NODE_NAME / INIT_NODE |
| `xilpm_function` | `Optional[int]` | INIT_NODE function word |
| `xilpm_node_class` | `Optional[int]` | Node class bits[29:26]; `XPM_NODECLASS_PROTECTION` = 9 |

---

## Usage <sup>[↑](#versalpdi)</sup>

**Parse a pld PDI and print its summary:**

```python
from ablation.analyzers.versal_pdi import VersalPdi

vp = VersalPdi.from_path('/media/cowboy/research/facility/fw/gep/GCI_GCM415_pld-v0.159.38-35A2CC3.pdi')
print(vp.report())
# VersalPdi: GCI_GCM415_pld-v0.159.38-35A2CC3.pdi
#   type=pld  sync_words=4  size=0x7765e0 bytes (7.5 MB)
#   git_hash=035a2cc3
#   IHT at 0x10:  no_of_imgs=1  total_prtns=1  ...
#   Images (1):
#     [CONFIG_MASTER]  id=0x...  git=0x035a2cc3  prtns=1
#   Partitions (1):
#     [0] CFICDR/PL  size=0x...B  dst=0xffffffffffffffff  data_off=0x54(→0x154)
#   CDO sections (1):
#     @0x00000154  v2.0  len=...w  ...
```

**Extract all NPI writes from a boot PDI:**

```python
from ablation.analyzers.versal_pdi import VersalPdi

vp = VersalPdi.from_path('/media/cowboy/research/facility/fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi')

npi_writes = []
for section in vp.cdo_sections():
    for cmd in section.commands:
        if cmd.npi_addr is not None:
            npi_writes.append((cmd.offset, cmd.npi_addr, cmd.npi_data))

print(f"{len(npi_writes)} NPI register writes")
for off, addr, val in npi_writes[:10]:
    print(f"  @{off:#x}  NPI[{addr:#010x}] = {val:#010x}")
```

**Reconstruct and inspect DMA load segments:**

```python
segments = sorted(vp.dma_write_segments(), key=lambda segment: segment.address)
loads = [s for s in segments if 0xF6130000 <= s.address < 0xF6140000]
if loads:
    image = b"".join(s.data for s in loads)
    print(f"Recovered {len(image)} bytes at {loads[0].address:#x}")
```

`DmaWriteSegment` also records `command_offset`, `section_offset`, and `end_address`. The bytes are addressed payload data, not necessarily code, PLM, or an ELF container. Establish the architecture and purpose before disassembly. For independently validated MicroBlaze code, use `MicroBlazeDecoder` with `byte_order="little"` for these CDO DMA words.

**Recover CDO images embedded in keyhole payloads:**

```python
for embedded in vp.embedded_cdo_sections():
    print(hex(embedded.offset), len(embedded.data), embedded.complete)
    print(embedded.section.parse_error)
```

Multi-SLR packages can carry one CDO image inside another section's keyhole payloads. `embedded_cdo_sections()` searches only keyhole data for checksum-valid CDO headers, unwraps consecutive chunks, removes their three-word prefixes, and preserves non-keyhole commands. It does not blindly treat every `CDO\x00` string as an independent top-level image.

Each `EmbeddedCdoSection` records `offset`, `container_offset`, `command_offset`, reconstructed `data`, and the parsed `section`. The `complete` property is true only when there is no parse error and the declared length is consumed. `trailing_words` accepts 0 through 16 for bounded analysis of a declared stream that ends before its actual command stream. The original parse error remains visible even when trailing data is returned.

**Recover an optional Git identifier from a boot PDI:**

```python
vp = VersalPdi.from_path('/media/cowboy/research/facility/fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi')
print(vp.git_hash())  # → "035a2cc3"
# Works via LOADER/SET_IMAGE_INFO even when IHT image header offsets are opaque
# Returns "" when every candidate Git word is zero
```

**Batch-parse a firmware directory:**

```python
pdis = VersalPdi.scan_directory('/media/cowboy/research/facility/fw/gep', glob='*.pdi')
for vp in pdis:
    print(f"{vp.result.path}  git={vp.git_hash()}  type={vp.result.pdi_type}  "
          f"cdos={len(vp.cdo_sections())}")
```

**Extract string labels from CDO MARKER commands:**

```python
for section in vp.cdo_sections():
    for cmd in section.commands:
        if cmd.string_payload:
            print(f"  @{cmd.offset:#010x} [{cmd.module_name}/{cmd.cmd_name}] \"{cmd.string_payload}\"")
# e.g.:
#   @0x0000b984 [GENERIC/MARKER] "bolt_la"  ← block label prefix
#   @0x0000b9c4 [GENERIC/MARKER] "servrpla"
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
  type=pld  sync_words=4  size=0x7765e0 bytes (7.5 MB)
  git_hash=035a2cc3
  IHT at 0x10:  no_of_imgs=1  total_prtns=1  img_hdr_off=0x24  part_hdr_off=0x34
  Images (1):
    [CONFIG_MASTER]  id=0x18700001  git=0x035a2cc3  prtns=1
  Partitions (1):
    [0] CFICDR/PL  size=0x776490B  dst=0xffffffffffffffff  data_off=0x54(→0x154)
  CDO sections (1):
    @0x00000154  v2.0  len=1956124w (7641KB)  checksum=ok  stream=complete
    cmds=8342  [GENERIC/Write×7344, GENERIC/Nop×313, GENERIC/DmaWriteKeyHole×158]
```

**`vp.report()`** on `GCI_GCM415_boot-v0.159.38-35A2CC3.pdi`:

```
VersalPdi: GCI_GCM415_boot-v0.159.38-35A2CC3.pdi
  type=boot  sync_words=5  size=0x1578a0 bytes (1.3 MB)
  git_hash=035a2cc3
  IHT at 0x14:  no_of_imgs=0  total_prtns=0  img_hdr_off=0x0  part_hdr_off=0x9600
  CDO sections (5):
    @0x0004f3c4  v2.0  len=9593w (37KB)  checksum=ok  stream=complete  cmds=1768
    @0x00059144  v2.0  len=93828w (366KB)  checksum=ok  stream=complete  cmds=921
    @0x000b4b74  v2.0  len=2590w (10KB)  checksum=ok  stream=complete  cmds=346
    @0x000c6184  v2.0  len=1043w (4KB)  checksum=ok  stream=complete  cmds=139
    @0x000c71e4  v2.0  len=147882w (577KB)  checksum=ok  stream=complete  cmds=27102
```

---

## What this adds for the user

`VersalPdi` is an ingestion and evidence-extraction layer. It exposes the container and command structure needed by later boot, register, and MicroBlaze analysis instead of forcing users to search raw bytes for recognizable words. The parser can remain useful on its own for inventory and provenance work, or serve as a backend in a larger boot-image workflow.

Additional command decoders can be added as their layouts are validated. Unsupported or partially opaque fields should remain explicit; a parsed header does not establish protection policy, a recovered register write does not establish its runtime effect, and a git identifier does not authenticate the image.

## Known platforms <sup>[↑](#versalpdi)</sup>

| PDI file | Type | Git hash | Description |
|---|---|---|---|
| `fw/gep/GCI_GCM415_pld-v0.159.38-35A2CC3.pdi` | pld | `035a2cc3` | GEP GCM415 PL-only, 7.5 MB |
| `fw/gep/GCI_GCM415_boot-v0.159.38-35A2CC3.pdi` | boot | `035a2cc3` | Same build, full boot image with PLM, 1.3 MB |
| `fw/gep/GEP_2ACC_GCM3_pld-v0.159.40-F119A21.pdi` | pld | `0f119a21` | Larger PL fabric (GCM3), 12 MB |
| `fw/felix/FLX182_STRIPS_..._1448.pdi` | boot |: | FELIX FLX182 boot image, 35 MB |
| `fw/felix/FLX155_..._2141.tar.gz` | boot |: | Two-SLR FELIX package with six top-level and four embedded CDO images |

**Build provenance:** All known GCI/GEP pld PDIs contain `img_name = "CONFIG_MASTER"`. In the reviewed GCI and GEP GCM3 files, the `git_hash` at image header +0x2C matches the hexadecimal filename suffix. The reviewed GEP GCM4 v0.159.66 boot and PLD images instead leave their candidate Git words zero. A nonzero match is a build-provenance clue, not tamper evidence: the truncated identifier and filename can both be modified, and the header checksum does not authenticate the payload.

---

## FORGE audit <sup>[↑](#versalpdi)</sup>

`FORGE.audit_module()` and the SAFE CODE 10-section review pass with zero open findings. File and buffer inputs are capped at 512 MiB, command storage is capped at 50,000 commands per section, and embedded recovery is capped at 64 images and 512 MiB of retained data. CDO payload length is bounded by the containing input rather than a separate eight-million-word ceiling. Regression tests cover malformed lengths, size limits, a valid 8,000,001-word section, split keyhole reconstruction, invalid embedded checksums, embedded byte limits, and trailing-word analysis.

Residual limitations: boot IHT fields remain partially opaque, the header checksum does not authenticate the payload, and valid CDO streams without an END command are accepted when their declared length is consumed. Embedded recovery is limited to validated three-word-prefixed keyhole streams; other nesting layouts require separate evidence. Security conclusions about register semantics require independent validation.

---

## See also <sup>[↑](#versalpdi)</sup>

- `XilinxNpiHex`: strict RNPI/RCDO ASCII-hex ingestion for this binary parser
- `XilinxBitfile`: parser for Spartan-3/6/7-series `.bit` files (not for Versal PDI)
- `XilinxFrameDecoder`: Type1/Type2 config packet decoder (not applicable to PDI)
- `re/atlas/gep_re.py`: GEP/GCI build inventory and git hash timeline
- `LpgbtDecoder`: lpGBT e-link protocol decoder used in the GEP/FELIX firmware
- `LatexReExtractor`: for reading lpGBT/HCC specification documents alongside PDI analysis
