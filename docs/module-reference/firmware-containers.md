# Firmware Container Modules

Parsers for binary firmware container formats and video container forensics.

---

## FirmwareContainer

**File:** `ablation/analyzers/firmware_container.py`

Parses partitioned firmware images that use a plaintext header and a fixed-record partition
table. No encryption or compression at the container level; individual partitions may be
gzip, ext2/3/4, xz, ELF, cpio, or other formats detected automatically.

This module handles any firmware container with the following structure:

- 8-byte magic prefix identifying the container version
- Fixed-width header fields: firmware version, vendor string, product string, language
- Partition table starting at offset 0x54 — fixed 296-byte records

### Partition record layout

```
+0x00  version  char[16]    partition version string
+0x10  name     char[16]    partition name (e.g. "kernel", "bin")
+0x20  offset   uint32 LE   byte offset from container start
+0x24  size     uint32 LE   partition size in bytes
+0x28  destpath char[64]    flash destination path
+0x68  pad      byte[184]   zeros
```

### Payload detection

Each partition's payload type is detected from its leading bytes:

| Type | Detection |
|---|---|
| `gzip` | `\x1f\x8b` at offset 0 |
| `xz` | `\xfd7zXZ` at offset 0 |
| `zstd` | `\x28\xb5\x2f\xfd` at offset 0 |
| `lz4` | `\x02\x21\x4c\x18` at offset 0 |
| `lzo` | `\x89\x4c\x5a\x4f` at offset 0 |
| `cpio_newc` | `070701` at offset 0 |
| `cpio_odc` | `070707` at offset 0 |
| `elf` | `\x7fELF` at offset 0 |
| `pe` | `MZ` at offset 0 |
| `ext2/3/4` | superblock magic `\x53\xef` at offset 0x438 |
| `unknown` | none of the above matched |

Note: bzImage kernels match `pe` (MZ setup stub at offset 0) — this is expected.

### Usage

```python
from ablation.analyzers.firmware_container import FirmwareContainer

fw = FirmwareContainer.from_path('/path/to/firmware.BIN')

# Print partition table
fw.dump_partitions()

# Inspect partitions
for p in fw.partitions:
    print(p.name, p.payload_type, hex(p.offset), p.size)

# Read raw bytes for a partition
raw = fw.read_partition('bin')

# Extract one partition
fw.extract('kernel', '/tmp/kernel.bin')

# Extract all partitions
fw.extract_all('/tmp/parts/')
```

### CLI

```
python3 -m ablation.analyzers.firmware_container <image.BIN>
python3 -m ablation.analyzers.firmware_container <image.BIN> extract <outdir>
```

### API reference

| Method | Returns | Description |
|---|---|---|
| `FirmwareContainer.from_path(path)` | `FirmwareContainer` | Load and parse image |
| `.dump_partitions()` | None | Print formatted partition table |
| `.get_partition(name)` | `FirmwarePartition \| None` | Find partition by name |
| `.read_partition(name)` | `bytes` | Raw bytes for named partition |
| `.extract(name, out_path)` | `Path` | Write partition to file |
| `.extract_all(out_dir)` | `list[Path]` | Extract all partitions |

### FirmwarePartition fields

| Field | Type | Description |
|---|---|---|
| `index` | int | Position in partition table |
| `name` | str | Partition name |
| `version` | str | Partition version string |
| `offset` | int | Byte offset in container |
| `size` | int | Partition size in bytes |
| `destpath` | str | Flash destination path |
| `payload_type` | str | Detected payload type |

---

## VideoContainerAnalyzer

**File:** `ablation/analyzers/video_container.py`

Forensic scanner for MP4/MOV, MKV/WebM, and AVI container files. Detects structural
anomalies that indicate polyglot files, appended payloads, or malformed containers used
to exploit media parsers.

### Checks performed

**Polyglot detection** — scans the first 8 bytes for multiple valid magic signatures
(e.g., ZIP + MP4, ELF + MP4). A dual-magic file is a polyglot and warrants manual
inspection.

**Trailer data (appended payload)** — computes the declared container end from the
top-level atom/chunk structure and compares against the file size. Bytes after the
declared end are reported with their length and a hex preview.

**Atom/box size overflow (MP4/MOV)** — checks each top-level atom for declared sizes
that exceed the remaining file. An overflowing atom typically crashes or exploits a
vulnerable media parser.

**EBML length abuse (MKV/WebM)** — checks for EBML unknown-length elements outside of
`Cluster` scope, where they are not valid. Parsers that accept them may process
attacker-controlled data.

**RIFF chunk miscount (AVI)** — verifies that the sum of chunk sizes in the LIST/movi
hierarchy matches the declared `movi` size.

### Usage

```python
from ablation.analyzers.video_container import VideoContainerAnalyzer

analyzer = VideoContainerAnalyzer.from_path('/path/to/sample.mp4')
findings = analyzer.scan()
print(analyzer.report(findings))
```

### API reference

| Method | Returns | Description |
|---|---|---|
| `VideoContainerAnalyzer.from_path(path)` | `VideoContainerAnalyzer` | Load file, detect format |
| `.scan()` | `list[VideoFinding]` | Run all checks, return findings |
| `.report(findings)` | `str` | Human-readable report |

### VideoFinding fields

| Field | Type | Description |
|---|---|---|
| `check` | str | Check name (e.g. `polyglot`, `trailer_data`) |
| `severity` | str | `HIGH`, `MEDIUM`, or `INFO` |
| `detail` | str | Human-readable description |
| `offset` | int \| None | File offset where anomaly was found |

---

## Huawei AA55AA55 Container (RE findings)

**File:** `targets/huawei/ascend_npu_firmware_re.py`

Reverse-engineered proprietary firmware container used in Huawei Ascend NPU
packages (910, 910b, Atlas A3 training cards).

### Magic and variants

Magic: `AA 55 AA 55` (4 bytes, big-endian mnemonic).

Two distinct variants observed:

**Variant A — Ascend 910 (HI1980)**

```
0x00  4   Magic: AA55AA55
0x04  4   Version/flags
0x08  4   Payload length (bytes, excludes header)
0x0C  4   Header length = 0x478 (1144 bytes)
0x10  4   Firmware type (0=NVE, 3=ASIC.fd, 8=IMU, 9=network_fw)
0x14  4   Board ID mask
0x18  20  Firmware version string (ASCII)
0x2C  32  SHA-256 hash of payload
0x25C 512 RSA-2048 signature block
0x45C 4   CRC32 of header[0..0x45B]
0x460 24  Plaintext version tag
0x478 ... Payload begins
EOF-12    Footer magic: 56 43 48 53 ("VCHS")
```

**Variant B — Ascend 910b / Atlas A3**

```
0x00  4   Magic: AA55AA55
0x04  4   Version/flags (different encoding)
0x08  4   Payload length
0x0C  4   Header length (smaller than Variant A)
0x10  4   Firmware type (see type map below)
0x??  16  MD5 hash of payload (downgrade from SHA-256)
          No RSA block at fixed offset; no VCHS footer.
```

### Firmware type maps

**910 upgrade-tool types** (from `upgrade.cfg`):

| Type | File | Description |
|---|---|---|
| 0 | `nve.bin` | Non-volatile environment (factory calibration) |
| 3 | `HI1980_ASIC.fd` | TF-A BL1/BL2/BL31 + UEFI EDK2 (AArch64 PE32+) |
| 8 | `IMU_task.bin` | IMU RTOS (AArch64 bare-metal) |
| 9 | `network_fw_asic.bin` | Network MCU firmware (ARM Thumb-2) |

**910b / Atlas A3 types**:

| Type | Description |
|---|---|
| 11 | HBOOT1_a — XLOADER stage1 (EL3 secure boot entry) |
| 12 | HBOOT1_b — XLOADER stage2 (EL3 init; contains "turing" build path) |
| 18 | HiLink32 SerDes firmware (32 Gbps) |
| 27 | HiLink60 SerDes firmware (60 Gbps) |

### Secure boot chain

```
910:   ROM BL1 → TF-A BL2 → BL31 (ATF) → UEFI DXE stack
910b:  XLOADER stage1 → XLOADER stage2 (custom; not standard TF-A)
```

The 910b switch from TF-A to proprietary XLOADER removes the benefit of open-source
auditing. MD5-only integrity checking in Variant B is a hash-strength regression from
the RSA-2048 + SHA-256 scheme used in Variant A.

### Embedded build artifacts (910b HBOOT1_b)

- Build path leak: `/usr1/turing/open_source/newlib-install/` — Huawei internal
  codename for Ascend 910 is **"turing"**
- XLink die-to-die interconnect string: `XLink` (Huawei proprietary multi-die fabric)

### SerDes firmware versions

```
HiLink32:  HiLink32LRT7V300_API_V1.0.7_SRAM_V3.0.4
HiLink60:  pUDLL: rev.4.00 API: 3.34 Target: H60LR V101A
```

### Makeself extraction

Packages are distributed as Makeself 2.5.0 `.run` archives. Safe passive extraction:

```bash
# Find payload offset from stub line count
skip=$(grep -m1 '^skip=' package.run | cut -d= -f2)
dd if=package.run bs=1 skip=$(awk "NR<=$skip{c+=length(\$0)+1} END{print c}" package.run) \
   | tar xzf - -C /tmp/out/
```

Never execute `.run` files — the embedded `upgrade-tool` writes to NPU hardware
via `/dev/davinciN` ioctls.

### Mate60Pro partition table (ALN-AL00, HarmonyOS 4.x, 206.0.0.108 SP6)

UFS sector size: **4096 bytes** (non-standard GPT; header_size field = 65536).
Three GPT header copies at file offsets 0x200, 0x28A00, 0x2CE00 (primary, backup, vendor recovery).

Security-critical partitions:

| Partition | Size | Role |
|---|---|---|
| `teeos` | 8 MB | Huawei iTrustee TEE OS |
| `trustfirmware` | 2 MB | TF-A BL31 for Kirin 9010 |
| `hhee` | 4 MB | Hypervisor (EL2) |
| `hisee_img` | 4 MB | HiSEE secure element firmware |
| `hisee_encos` | 4 MB | HiSEE encrypted OS blob (hardware-key bound) |
| `hisee_fs` | 8 MB | HiSEE secure filesystem |
| `thee` | 4 MB | Trusted HEE variant |
| `tzsp` | 12 MB | TrustZone secure partition runtime |
| `fastboot` | 12 MB | Huawei fastboot |
| `veritykey` | 1 MB | dm-verity public key |
| `bl2` | 4 MB | Secure boot BL2 stage |
| `rvt` | 4 MB | Rollback version table |

X.509 cert in `sec_xloader_header`: CN=secimg level1 cert, OU=Huawei Signature Center,
RSA-PSS/SHA-256, valid 2025–2055. Issuer: Huawei internal Product CA.
30-year validity is atypically long for a code-signing cert.
