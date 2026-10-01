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

---

## Huawei VRP OLT Container (RE findings)

**File:** `targets/huawei/ma5800_olt_re.py`

Reverse-engineered proprietary firmware container used in Huawei MA5800/MA5600/EA5800
carrier OLT packages (SmartAX series, GPON/XGS-PON OLTs).

### HUAWEI PRODUCT BINARY FILE format

Magic: `"HUAWEI PRODUCT BINARY FILE\x00"` (27 bytes).

Header (0x180 = 384 bytes per container level):

```
0x00  27  Magic: "HUAWEI PRODUCT BINARY FILE\x00"
0x21  10  Version: "VER 1.1"
0x2A  64  Package filename (null-padded)
0x6C   4  Total payload size LE32
0x70  16  Product line: "SmartAX MA5600"
0x91  32  Board version: "MA5800V100R018C00B056"
0xC2  20  Build timestamp: "2017-10-27 17:49:09"
0xD8   1  Directory entry count
0xDF   4  Directory entry count LE32
0xFA  32  First sub-package filename
0x16C  4  First sub-package size LE32
0x170  4  First sub-package offset LE32
```

Three nesting levels: outer package → mainboardpacket.bin sub-package → EFS directory.

EFS directory entries: 0x84 (132) bytes each. Filename at entry[8:40], board version
at entry[0x4D:0x6D], LE16 checksum at entry[6:8].

Text manifest after directory: `"\n\nName: <file>.efs\nDigest: <sha256hex>\n"` per component.

`patch_bak.efs` is zlib-deflate compressed (magic `0x78 0x9C`); decompresses to a nested
HUAWEI PRODUCT BINARY FILE container.

### VRP OS (ARM Cortex-A15, Linux 3.10.53-HULK2)

- **Internal codename**: "Saturn" (`RTOS_Saturn_201706`)
- **Build path**: `/usr1/CloudTools/cross_tools/RTOS_Saturn_201706/V100R005C00/armA15le_3.10_ek/`
- **Dual architecture**: MPU = ARM Cortex-A15 (armA15le); LPU = x86-i386 (data plane)
- **535 VRP modules** including AAA, RADIUS, HWTACACS, SSH, SNMP v3, vsftpd 3.0.2.8
- `libtpmagent.so` — TPM-based PCR attestation and file integrity measurement
- `libli.so` — Lawful Intercept module (carrier regulatory requirement)
- `libdbg_server.so` / `libdbg_agent.so` — debug server/agent **in production** (component types 50/51)
- `minios` and `monitor` binaries: **with debug_info, NOT stripped** (unusual for production)

### Security findings

| Finding | Severity | Detail |
|---|---|---|
| GPON password exposure | HIGH | `GPONNNI_QueryPortDecryptPassWord` returns plaintext ONU passwords; `GPONNNI_GetGemPortCarAes` returns AES keys |
| Debug server in production | MEDIUM | `dbg_server` + `dbg_agent` components loaded in production CPT list |
| SNMP USM MD5 | LOW | `UsmUserLocalizeMD5` present (RFC 8353 deprecated) |
| vsftpd 3.0.2.8 | INFO | Huawei custom fork, version not in upstream history |
| Build path leak | INFO | Saturn codename + HULK2 kernel fork name |

---

## Huawei HWNP ONT Container (RE findings)

**File:** `targets/huawei/echolife_ont_re.py`

Reverse-engineered firmware container for EchoLife GPON/XGS-PON ONT devices
(HG8245H, HG8346M, HG8546M, HS8145C5, EG8145V5).

### HWNP format

Magic: `"HWNP"` (4 bytes). Header size: always **0x168 = 360 bytes** across all versions.

```
0x00  4   Magic: "HWNP"
0x04  1   Version (0=oldest, 1, 2=newest)
0x05  3   Partial hash bytes
0x08  4   CRC32 of payload LE32
0x10  4   Secondary CRC32 LE32
0x14  4   Sub-image count LE32 (4, 8, or 12)
0x1C  4   Header size LE32 = 0x168 (confirmed constant)
0x24  64  Variant IDs: pipe-separated 4-char board codes
          e.g. "148C|15BD|15FE|COMMON|CHINA|CMCC|"
0x168 ... Payload (sub-image table + binaries)
```

Three device generations:

| Device | Kernel | Sub-images | SoC |
|---|---|---|---|
| HG8245H (V100) | Linux 2.6.34.10 | 1–8 | HiSilicon SD5115 |
| HG8245H (V300), HG8346M | Linux 2.6.34 | 8 | HiSilicon SD5115 family |
| HG8546M V5, HS8145C5 | Linux 3.10.53-HULK2 | 4–12 | HiSilicon (newer) |

U-Boot image header (magic `0x27051956`) encodes the kernel version string at +32 bytes
(big-endian `img_size` at +12). Both newer ONT generations share Linux 3.10.53-HULK2
with the MA5800 OLT — same Huawei embedded Linux platform across OLT and ONT.

Upgrade validation path embedded in HS8145C5: `file:/var/UpgradeCheck.xml`.

### Cross-product PKI note

All Huawei product lines use CMS/PKCS#7 OID `1.2.840.113549.1.7.2` for firmware
signing (Ascend NPU, VRP OLT/router/switch, iBMC HPM, ONT). Single Huawei internal PKI;
compromise of the Signature Center CA would affect all product lines simultaneously.

---

## Huawei VRP V800 RPG Container (RE findings)

**File:** `targets/huawei/ne8000_router_re.py`

Reverse-engineered firmware container for NE8000-F1A carrier-grade core router
(VRP V800R023 platform, also used by CE6810EI datacenter switch).

### RPG_YUNSHAN / RPG_PNF dual-container structure

Magic prefix: `"RPG_"` followed by platform codename and version string.

The NE8000 uses two nested codenames:

- **YUNSHAN** — outer container (`RPG_YUNSHANV800R023C00SPC500B697`)
- **PNF** — inner platform package (`RPG_PNF`, `PKG_PNFV800R023C00SPC500B697`)

"PNF" = Physical Network Function — Huawei's NFV architecture term for hardware
appliances (counterpart is VNF = Virtual Network Function for VM-based NE deployment).

`.cc` container version byte for NE8000: `0x00000002` (older VRP series used `0x00000001`).
`package_format_ver: 1.3.1` (embedded in RPG header).

### Architecture (from PAT binary scan)

| ELF arch | Role |
|---|---|
| x86-64 | Control-plane routing daemons, management processes |
| AArch64 | NPU / forwarding-engine linecard modules |

### Patch package format (RPG_PNF SPH patches)

Patch units are named `HP000XXX.pat` (HP = Hotfix Patch), numbered sequentially.
SPH120 contains patches HP000020 through HP000126.

`patch.rinfo` fields:
```
Name:        V800R023
Version:     1.1.120        (major.minor.sph_level)
rpgName:     PKG_PNF
rpgVersion:  V800R023C00SPC500B697
patPkgType:  COLD           (requires system reboot to activate)
```

`patchtype.info` format: `<pkg_name>:<comma-separated CPT type IDs>`

`patchpkg.txt` manifest columns (14 fields, tab-separated):
`SHA256  NA  path  filename  dest  type_id  0  owner:uid  group:gid  perms  NA  0  NA  NA`

### Filesystem users (from patch file ownership)

| User/Group | ID | Role |
|---|---|---|
| `root` | 0 | Privileged VRP processes |
| `ftpvrpv8` | UID 1001 | FTP service (VRP V8 generation) |
| `swm` | GID 2000 | Software Management daemon |
| `verona` | GID 2001 | Third internal codename group (development codename) |

### Hardware types (HWTYPE) observed in SPH120

| HWTYPE | Description |
|---|---|
| `0x00137F3` | NE8000-F1A standard control plane board |
| `0x01137F3` | NE8000-F1A extended feature board |
| `0x0C137F3` | NE8000 carrier/cluster variant |

Each HWTYPE has separate `.cms`, `.pss.cms`, and `.crl` signature files (dual
CAdES+RSA-PSS algorithms with inline CRL distribution).

### Security findings

| Finding | Severity | Detail |
|---|---|---|
| Dual CAdES+PSS signatures + CRL on filelists | INFO | Both .cms (7814B) and .pss.cms per HWTYPE; explicit CRL (4975B) distributed inline |
| "verona" group (GID 2001) — third codename | INFO | Alongside YUNSHAN/PNF; controls VRP module file access |
| COLD patch — all 120 patches require reboot | INFO | Carrier operator deferral risk amplifies exposure window |
| swm-owned modules with perms 777 | LOW | Group-writable if group membership misconfigured post-auth |

---

## Huawei VRP V200 Switch Bootloader (RE findings)

**File:** `targets/huawei/s6720_switch_re.py`

Reverse-engineered S6720EI campus switch bootloader SquashFS (VRP V200R012C00).

### Platform architecture

| Component | Detail |
|---|---|
| Management CPU | Freescale e500mc (PowerPC 32-bit, big-endian) |
| Data-plane ASIC | Broadcom BCM56xxx (Trident2/Tomahawk, iProc) |
| Secondary CPU | HiSilicon Hi1215 (board initialization) |
| OS | Wind River Linux 6.0.0.36 (LTSI) |
| Kernel | Linux 3.10.62-ltsi-WR6.0.0.36_standard |
| RTOS | Dopra Linux (`taskDopra.ko` LKM) |

Confirmed from ELF header (`ELF 32-bit MSB executable, PowerPC or cisco 4500`) and
build path in bootloader binary: `/usr1/Codes/R12/V200R012C00/build/linux/kernel_project/build-fsl_e500mc/`.

### Broadcom BDE modules

`linux-kernel-bde.ko` + `linux-user-bde.ko` — Broadcom Device Environment, standard
SDK components shipped with BCM switch ASICs. The iProc reference
(`shbde_pci_iproc_version_get`) confirms a Trident2/Tomahawk-class ASIC with embedded
ARM Cortex-A9 management core.

`linux-user-bde.ko` exposes DMA memory to userspace. The default DMA buffer is 4MB.
Historical BDE versions have allowed privilege escalation when the DMA buffer is
accessible to non-root processes.

### Dopra RTOS

`taskDopra.ko` — Huawei's proprietary real-time scheduler loaded as an LKM on top of
Wind River Linux. Author: HUAWEI. License: GPL (declaration required for kernel module
loading; Dopra code itself is proprietary). Exports `callstack_kernel_version_get`.

The same Dopra architecture appears in MA5800 OLT (Linux 3.10.53-HULK2, ARM).
Two different Dopra kernel generations confirmed across the Huawei carrier portfolio.

### Flash partitions

Dual-redundancy flash scheme:
- `/mnt/nsysmain/` — primary system flash (bootloader, kernel, Hi1215 firmware)
- `/mnt/nsysback/` — backup system flash (same structure)

HiSilicon Hi1215 firmware blob path: `/mnt/nsysmain/hi1215_bootloader.bin`

### Security findings

| Finding | Severity | Detail |
|---|---|---|
| SSH/SFTP in bootloader recovery SquashFS | MEDIUM | `sftp`, `sftp.sh`, `sftpwd`, `ssh` present before VRP OS load; no RBAC/AAA |
| `supp_kernel_NoHeart.ko` watchdog suppressor | INFO | Intentional design; attack relevance bounded by CAP_SYS_MODULE requirement |
| Broadcom BDE DMA userspace interface | INFO | `linux-user-bde.ko` exposes 4MB DMA buffer; historical privilege escalation vector |

---

## Huawei CE6810EI Multi-SoC Container (RE findings)

**File:** `targets/huawei/ce6810_switch_re.py`

257MB datacenter switch firmware with three distinct CPU/SoC boot stacks packed into one
.cc image (VRP V200R019C10, codename DCTOR — Datacenter TOR).

### Container format (CE6810EI .cc — distinct from NE8000/MA5800)

```
0x00  4   Magic: 5A 00 00 03  (unique to CE series)
0x04  4   Entry count = 0x15 = 21
0x08  4   Version: "2.0\0"
...
0x02F3EEF4  SquashFS (xz, 206 MB, 19757 inodes, 489 modules)
```

No ELF files are present at the .cc top level — all code is nested inside the SquashFS.

### Multi-SoC hardware architecture (`hard-to-cpu.txt`)

| HWTYPE | CPU | SoC | Role |
|---|---|---|---|
| `0x1200060C/0D/02/05` | `ppc_e500mc` | Freescale P3041 (4-core e500mc) | MPU control board |
| `0x12000608/09` | `ppc_e500v2` | Freescale P2020 / MPC8572 (2-core) | LPU linecard |
| `0x1200061A/1B` | `arm` | ARM (SoC undetermined) | unknown |
| `CR55MPUB`, `CR56MPUC` | VRP V8 | CR55/CR56 core-router card | VRP V8 linecard |

HWTYPE prefix `0x12xxxxxx` = CE6810 chassis board (vs `0x4xxxxxxx` = ARM in MA5800, `0x1xxxxxxx` = x86 in MA5800). String HWTYPEs (CR55MPUB, CR56MPUC) = named router-on-card modules.

### Boot stacks (`oslist.ini`)

**P3041 MPU stack** (e500mc, configs 0x1200060C/0D/02/05):
- `uboot_ppc3041.bin` → `3041_tor_uImage.bin` (5MB kernel) + `rootfs_3041_tor.sqfs` (8.7MB) + `rootfs_3041_vrp.img` (31MB VRP app rootfs)
- `rcw_3041_tor_68.bin` (Reset Configuration Word #68)

**P2020 LPU stack** (e500v2, configs 0x12000608/09):
- `uboot_ppc2020.bin` → `dc2020_5810_uImage.bin` (4.4MB) + `rootfs_2020_5810.sqfs` (8.8MB) + `rootfs_2020_vrp.img` (22MB)
- `TOR_CE5810_48T4S_EI_CPLD.bin` (156KB CE5810 ToR CPLD firmware — **no .cms signature**)

**CR55/CR56 stack** (string HWTYPE):
- `DE51FCMA.bin` (4.5KB NPU/FPGA — **no .cms signature**)

### Security findings

| Finding | Severity | Detail |
|---|---|---|
| `dbg_server` + `dbg_agent` in production CPT (SYSTEMIC — 2nd platform) | MEDIUM | Cross-confirmed with MA5800 OLT V100R018; intentional across all VRP production builds |
| Python VM + gRPC in production | INFO | `pythonvm`, `python_pack`, `grpc` all in production CPT |
| CE5810 CPLD firmware without CMS signature | INFO | 156KB CPLD binary controls port electrical config; no adjacent .cms/.crl |
| DE51FCMA.bin (CR55/56) without CMS signature | INFO | Unlike NE8000 patch files which carry dual .cms+.pss.cms |
| 4-CPU-architecture attack surface | INFO | P3041/P2020/ARM/CR-card boot independently; LPU compromise may be invisible to MPU |

---

## Huawei VRP V600 Campus Switch Container (RE findings)

**File:** `targets/huawei/s6750_v600_re.py`

366MB campus switch firmware (S6750-H/S7400/S7500/S6800 family), VRP V600R024.
Same .cc format version as NE8000 (0x00000002). First VRP campus switch generation
using HiSilicon silicon exclusively (no Freescale, no Broadcom).

### Container structure

```
0x00  4   Format version: 0x00000002 (shared with NE8000 V800)
0x04  4   Entry count: 0x4C = 76
0x08    Version string: "V600R024C00SPC500"
0x1984  SquashFS 1 — 264MB xz — AArch64 VRP V8 application FS
0x10A69AE4  SquashFS 2 — 1.2MB xz — signed board filelists + SELinux labels
```

### AArch64 HiSilicon silicon (V600 transition)

| Generation | Management CPU | Data ASIC |
|---|---|---|
| V200/V100 (S6720EI, CE6810EI) | Freescale e500mc/e500v2 (PowerPC BE) | Broadcom BCM56xxx |
| V600 (S6750-H, S7400/S7500) | HiSilicon SA8009 (AArch64 LE) | HiSilicon SD5981 NSE + Hi1213 NSE |

HiSilicon chip library names: `libhs_sa8009.so`, `libhs_sd5981_nse.so`, `libhs_hi1213_nse.so`.
Clock driver: `clk_kernel_driver_8xx9.ko` (HiSilicon 8xx9 SoC clock domain).

### Multi-product HWTYPE map (catalog SquashFS)

13 board types across S6750/S7400/S7500/S7700/S9700/S6800: `0x10644_7500` through `0xC12921_6800`.
Product suffix: `_7500` = S7500, `_7400` = S7400, `_7C00` = S7000C, `_6800` = S6800.

### SELinux (first campus switch generation with MAC)

`selinux_labels_list.txt` in catalog SquashFS confirms SELinux present. Mode (Enforcing vs
Permissive) not determinable from static analysis.

### Security findings

| Finding | Severity | Detail |
|---|---|---|
| SELinux present (V600 first) — mode unknown | INFO | First VRP campus switch with MAC; enforcing mode unconfirmed |
| libsqlite3.so.0.8.6 — SQLite 3.8.6 known CVEs | LOW | CVE-2017-10989 + others in 3.8.x; requires SQL injection path |
| HiSilicon NSE drivers opaque (no public SDK) | INFO | SD5981/Hi1213 replace publicly-documented Broadcom BDE |

---

## Huawei Consumer/CPE Firmware Formats (RE findings)

**File:** `targets/huawei/consumer_router_re.py`

Kamchia HG231f (2011 MIPS) + Ufanet ISP-customized builds (WS319/WS880/HG232f/WS325).

### HG231f — U-Boot uImage (Kamchia, 2011)

Magic: `0x27051956` (U-Boot legacy uImage). Architecture: MIPS 32-bit big-endian, Linux
kernel, LZMA compressed. Build date: 2011-10-10. Load address: `0x80000000`. This is
the oldest device in the corpus (2011 MIPS) with no ASLR/SSP/PIE mitigations.

### WS319/WS880 — Huawei AP firmware format

Magic: `0x76543210` LE32 (bytes `10 32 54 76`). Header:

```
0x00  4   Magic: 0x76543210 LE32
0x04  10  Device name ("WS319\0\0...")
0x24  16  Version string ("V100R001C199B015")
0x78+ partition table entries: type(2) + index(2) + field_a(4) + field_b(4) + name
```

`C199` = Ufanet Russian ISP custom build.

### HG232f/WS325 — encrypted firmware (analysis blocked)

Entropy 7.94/8.0 from byte 0 = encrypted. No recognizable magic. Static analysis
blocked without the encryption key (stored in production bootloader).

---

## Huawei iBMC / iMana Server BMC Firmware (RE findings)

**File:** `targets/huawei/ibmc_server_re.py`

Three server BMC generations from the Chinese-Mirrors corpus.

### Generation evolution

| Generation | Era | Format | Signature |
|---|---|---|---|
| iMana (V2 servers) | ~2013 | Unknown (.rar archives) | None observed |
| iBMC 3.x (V3 servers) | ~2016-2020 | Standard IPMI HPM.1 (`PICMGFWU` magic) | Checksum only |
| iBMC 6.x (V5 servers) | ~2019+ | Huawei extended HPM.1 = manifest + CMS/PKCS#7 + HPM.1 | CMS/PKCS#7 |

### Standard HPM.1 (iBMC 3.x, RH1288V3 V3.97)

```
0x00  8   Magic: "PICMGFWU"
0x08  2   HPM.1 version: 0x01 0x01 = 1.1
...
0x38      Component name: "CONFIG"
```

Size: 42.6MB. Model UID: 0x00010F00. Active mode: Immediately (no BMC reboot required).
Package also contains: BIOS V521 (6.1MB, unknown format), 3 CPLD binaries.

### Huawei extended HPM.1 (iBMC 6.x, 2288HV5 V6.27)

Pre-pended manifest block:
```
"Manifest Version: 1.0\n"
"Create By: Huawei Technology Inc.\n"
"Name: rootfs_2288hv5.hpm\n"
"SHA256-Digest: ab610ea6...\n"
[CMS/PKCS#7 DER block, OID 1.2.840.113549.1.7.2]
[Standard PICMGFWU HPM.1 payload follows]
```

### Security findings

| Finding | Severity | Detail |
|---|---|---|
| Standard HPM.1 (V3 gen) no payload signature | MEDIUM | Pure HPM.1 = checksum only; arbitrary BMC flash via IPMI if HPM update reachable |
| V5 gen CMS uses same corpus-wide CA | INFO | Single Huawei CA covers all product lines |
| RH1288V3 CPLD binaries not individually signed | INFO | 3 CPLDs in ZIP without .cms/.crl |

---

## Huawei NE40E / NE20E Core Router VRP V800 (.cc and .PAT)

Source: `/media/cowboy/research/Huawei-Firmware/OpenX/Routers/` — NE40E-M2K-B V800R023/V800R024, NE20E V800R022, SPH122 patch.

Platform codename "M2": all packages named `M2V800R02{2,3,4}CxxSPCxxxBxxx.rpg`.

### Architecture transition: V800R022 → V800R023

| Feature | NE20E V800R022 | NE40E V800R023/024 |
|---|---|---|
| MPU SoC | Freescale P40xx (PowerPC) | HiSilicon Hi1610 (AArch64, 16-core) |
| Boot | U-Boot uImage (0x27051956) | UEFI + ARM64 Linux Image (MZ/0x4D5A0091) |
| NPU | Huawei CX68M (80 or 160 core) | Not present as separate entry |
| VRP rootfs | `vrp_ppc_rtos_mpu.img` | `vrp_arm64_mpu.img` |
| TPM | None | TPM 2.0 (`tpm_arm64.img`, `tpm2.0_arm64.img`) |
| Container entries | 33 | 34–35 |

### RPG container format (same as NE8000 version 0x00000002)

```
0x00  4   Format version: 0x00000002 (BE32)
0x04  4   Entry count: 33-35 (BE32)
0x08  N   Version string (null-padded to 28 bytes)
0x1C  4   Separator: 0xAA550000
0x20  N   Entry table (24 bytes per entry)
```

Per-entry (24 bytes):
```
[0:1]   1   Marker byte (encodes entry type; 0xFF=standard, 0xFE-0xFB=MPU boot stages, etc.)
[1:4]   3   HWTYPE (BE)
[4:8]   4   File offset (BE32) — absolute byte offset in .cc
[8:12]  4   Entry size (BE32) — includes 0x160-byte sub-header
[12:16] 4   Field C (unknown, possibly CRC)
[16:20] 4   Flags (BE32)
[20:24] 4   Padding
```

Payload starts at: `entry_file_offset + 0x160` (352-byte sub-header precedes each payload).

Sub-header notable fields:
```
[0:6]   zeros
[6:8]   inode/ref count
[96..]  null-terminated strings: codename, filename, description
        e.g. "M2V800R023C00SPC500B697.rpg\0V8_RPG.bin\0"
             "mpu base boot file!\0Image_hi1610_mpu.bin\0"
             "pnpp file for wang.guan!\0pnpp.7z.bin\0"  ← developer name OPSEC
```

### HWTYPE encoding (V800 series)

| HWTYPE | Meaning |
|---|---|
| 0x000040–0x000043 | P40xx/P30xx PowerPC MPU variants (V800R022 only) |
| 0x000050–0x000051 | Hi1610 AArch64 MPU variants (V800R023+) |
| 0x005638 | VRP V8 RPG SquashFS (0x56='V', 0x38='8') |
| 0xFF5638 | VRP V8 ASDK SquashFS (Application SDK) |
| 0x005637 | VRP V8 rlist (file integrity list) |
| 0x005678/0x005679 | Device lock file (hardware attestation) |
| 0x000009/0x00000A/0x00000B | Signature chain (filelist / CMS / CRL) |
| 0x000FF1/0x000FF2 | PSS signature chain (filelist / CMS) |
| 0xEE0001/0xEE0002 | Digest integrity manifests |

### Main SquashFS (NE40E V800R023)

Entry [14], HWTYPE 0x005638, offset 0x018BA72C, size 332MB:
- SquashFS LE at `+0x160` = 0x018BA88C
- Inodes: 47,146 | Compression: LZMA | Block size: 128KB | Version: 4.0
- Build date: 2023-09-04

### CX68M NPU (NE20E V800R022 — last PPC generation)

Huawei-custom network processor. No public documentation. Two configurations:
- 80-core: `bootargs_p40xx_cx68mnpu80.bin`
- 160-core: `bootargs_p40xx_cx68mnpu160.bin`
- Reset Config Word: `p30xx_cx68mnpu_rcw.bin`

Absent from V800R023+ — Hi1610 platform integrates or relocates forwarding plane.

### PAT patch format (SPH122)

```
0x00  32  Platform version (null-padded): "M2V800R024"
0x20  32  Patch name (null-padded): "SPH122"
0x40  ..  Binary fields (CRC, size)
Body:     SQFS catalog (0x2CA6) + multiple GZIP patch blobs + dual CMS signatures
          (0x17354A, 0x371BA9 — CAdES+PSS, same CA as corpus)
```

### Security findings

| Finding | Severity | Detail |
|---|---|---|
| Developer name "wang.guan" in PNPP sub-header (all versions) | OPSEC/INFO | "pnpp file for wang.guan!" in V800R022/023/024 production firmware |
| CX68M NPU opaque (NE20E V800R022) | INFO | Proprietary 80/160-core NPU; no public documentation |
| NE20E V800R022 has no TPM | INFO | TPM 2.0 added only with Hi1610 platform (V800R023); hardware-gated upgrade |
| Dual CAdES+PSS CMS on SPH122 patch | INFO | Same corpus-wide Huawei Signature Center CA |
| Device lock attestation mechanism | INFO | "device lock file for prevent steal!"; V800R024 adds _ex variant |

---

## Huawei NearLink / SparkLink IoT SoC Firmware (HiBurn .fwpkg)

Source: `/media/cowboy/research/Huawei-Firmware/NearLink/` — 18 `.fwpkg` packages for HiSilicon NearLink/SparkLink development boards (BS21/Hi2821, WS63/Hi3863, WS63E, Hi3863).

### HiBurn fwpkg format

```
Offset  Size  Field
0x00     4    Magic: 0xEFBEADDF LE32 (bytes DF AD BE EF — "DEADBEEF" in little-endian)
0x04     4    Field 1 LE32 (partition table total length or CRC)
0x08     4    Field 2 LE32 (total payload size ≈ file size)
0x0C     N    Partition table (52-byte entries, terminated by empty name)
```

Each partition table entry (52 bytes):
```
[0:32]   32  Partition name (null-padded, e.g. "flashboot_sign_a.bin\0...")
[32:36]   4  File offset of this partition within the .fwpkg (LE32)
[36:40]   4  Partition data size in bytes (LE32)
[40:44]   4  Target flash address (LE32; 0 if flags=0)
[44:48]   4  Target flash allocation size (LE32; may differ from data size)
[48:52]   4  Flags LE32: 0 = not directly flashed, 1 = flash mapped
```

### BS21 / Hi2821 partition map (491KB, bare-metal)

Flash base: 0x90100000 (AHB/AXI-mapped NOR flash)

| Partition | Flash addr | Size | Notes |
|---|---|---|---|
| loaderboot_sign.bin | — | 24KB | Programmer loader; not directly flashed (flags=0) |
| partition.bin | 0x90100000 | 1KB | Flash partition table |
| flashboot_sign_a.bin | 0x90101000 | 36KB | A copy flashboot (A/B redundancy) |
| flashboot_sign_b.bin | 0x9010B000 | 36KB | B copy flashboot (A/B redundancy) |
| application_sign.bin | 0x90115000 | 398KB | Main application (bare-metal or minimal RTOS) |
| bs21_all_nv.bin | 0x9017E000 | 4KB | Non-volatile config storage |

### WS63 / Hi3863 partition map (1.4MB, LiteOS)

Flash base: 0x200000 (QSPI NOR flash)

| Partition | Flash addr | Size | Notes |
|---|---|---|---|
| root_loaderboot_sign.bin | — | — | Root programmer loader; not directly flashed |
| root_params_sign.bin | 0x200000 | 1.8KB | Root parameters |
| ssb_sign.bin | 0x202000 | 21KB | Secure Secondary Boot (absent in BS21) |
| flashboot_sign.bin | 0x220000 | 49KB | Primary flashboot |
| flashboot_backup_sign.bin | 0x210000 | 49KB | Backup flashboot (A/B redundancy) |
| ws63_all_nv.bin | 0x5FC000 | 16KB | NV config |
| ws63_all_nv_backup.bin | 0x20C000 | 16KB | NV backup (A/B redundancy) |
| ws63-liteos-app-sign.bin | 0x230000 | 1.19MB | Full LiteOS application |

### SoC boot chain comparison

**BS21:** loaderboot → partition.bin → flashboot (A/B) → application  
**WS63:** root_loaderboot → root_params → SSB → flashboot (A/B) → LiteOS app

WS63 adds an explicit SSB (Secure Secondary Boot) stage and A/B NV redundancy that BS21 lacks. Every component ends in `_sign.bin` — per-partition signing before packaging. The fwpkg container has no CMS/PKCS#7 wrapper (unlike VRP, iBMC, HPM); package integrity relies on individual partition signatures.

### Security findings

| Finding | Severity | Detail |
|---|---|---|
| All partitions individually signed (_sign.bin naming) | INFO | Per-component signing prevents swapping; signing algorithm requires loaderboot analysis |
| A/B redundancy for flashboot and NV (OTA safety) | INFO | BS21: A/B flashboot; WS63: A/B flashboot + A/B NV |
| LiteOS core auditable but NearLink radio stack is proprietary | INFO | WS63 app = LiteOS + proprietary HiSilicon NearLink SLE stack |
| No CMS/PKCS#7 fwpkg wrapper (unlike VRP/iBMC/HPM) | INFO | Integrity via per-partition signing only |

---

## Huawei Go-Trex Campus Switch VRP V200R022 (.cc three-SquashFS format)

**Analyzed:** S5732-H_V200R022C00SPC500.cc (161MB), S6730-H_V200R022C00SPC500.cc (159MB), S5720EI-V200R019SPH3b0.pat (4.7MB)  
**Source module:** `targets/huawei/gotrex_switch_re.py`

### VRP V200R022 .cc format

This format is distinct from both the RPG v2 (.cc for NE40E/NE20E) and the CE6810EI format:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | 4 | Magic | 0x00000000 (no magic bytes — format-version discriminator) |
| 0x04 | 4 | Entry count BE32 | 0x7C=124 (S5732-H), 0x6B=107 (S6730-H) |
| 0x08 | N | Version string | Null-terminated: "V200R022C00SPC500" |
| 0x08+N | variable | Entry metadata | Binary-encoded (partially opaque) |

One ASCII string found in the header region before the first SquashFS: `linux file TYPE!`

The container holds exactly three SquashFS filesystems. There is no CMS/PKCS#7 wrapper. The header occupies ~13KB (S5732-H) or ~19KB (S6730-H) before the first SquashFS.

### Three-SquashFS layout

| SquashFS | Offset (S5732-H) | Offset (S6730-H) | Size | Inodes | Compression | Date | Layer |
|---|---|---|---|---|---|---|---|
| 1 | 0x000033D4 | 0x00004CBC | 114MB | 49 | XZ | 2022-11-09 | AI/ASIC platform |
| 2 | 0x0728EBC4 | 0x072904AC | 7MB | 119 | gzip | 2022-11-07 | BSP/CBB drivers |
| 3 | 0x07D5CF94 | 0x07D5E87C | 7MB | 717 | gzip | 2022-11-09 | NETCONF/YANG mgmt |

The 114MB SquashFS contains only 49 inodes — each "file" is a large binary blob (compiled ML model, shared library, or binary executable). The split ensures hardware-specific binaries (model-specific ASIC libs) are isolated from the common management stack (SquashFS 3).

### SquashFS 1: AI/ASIC platform layer (114MB, 49 inodes)

Both S5732-H and S6730-H carry the same 49-entry SquashFS 1 (identical NTID model files and AI binaries across both models).

**HiSilicon SD5875 + SD5981 NSE ASICs:**

| Binary | Description |
|---|---|
| `lib/libhs_sd5981_nse.so` | HiSilicon SD5981 NSE ASIC driver library |
| `lib/libhs_lsw_sd5875_armel.so` | SD5875 Layer Switch library (AArch64 EL) |
| `lib/libhs_lsw_sd5981_armel.so` | SD5981 Layer Switch library (AArch64 EL) |
| `lib/libenp5981_campus.so` | ENP5981 campus Elastic Network Platform API |
| `pre_init/np_pre_pcie5981.ko` | NP PCIe pre-init LKM (SD5981 connected via PCIe) |
| `pre_init/sdkpcie5981.ko` | SD5981 SDK PCIe LKM |

SD5981 is the same NSE ASIC family as S6750-H V600. The `armel` suffix indicates AArch64 execution level (EL). SD5981 is PCIe-connected to the management CPU — two LKMs handle initialization and SDK respectively.

**Atlas A10x AI chip:**

```
a10xbin/A0104_FW_V12_00_00_release.hdr   (dedicated AI accelerator chip firmware)
```

A dedicated Atlas 100-series NPU is embedded in the switch hardware, separate from the forwarding ASIC. `A0104` is a board variant code; `V12.00.00` indicates a mature release. The `.hdr` extension matches Huawei's signed firmware header format. This chip enables hardware-accelerated traffic classification without CPU overhead.

**NTID (Network Traffic Intelligence Detection) — on-device ML inference:**

| File | Role |
|---|---|
| `ntid.o` | NTID binary module |
| `lib/libsiteai_cml.so` | SiteAI Compiled ML Model inference library |
| `lib/libsiteai_util.so` | SiteAI utility library |
| `usr/local/etc/ntid/knn_model_csv/knn_model.cml` | Compiled KNN model |
| `usr/local/etc/ntid/knn_model_csv/pca_components.csv` | PCA decomposition components |
| `usr/local/etc/ntid/knn_model_csv/pca_mean.csv` | PCA mean vector |
| `usr/local/etc/ntid/knn_model_csv/standard.csv` | Feature standardization parameters |
| `usr/local/etc/ntid/knn_model_csv/class_gmd.csv` | Traffic class labels |
| `usr/local/etc/ntid/knn_model_csv/x_train_process_df.csv` | Training data preprocessing descriptor |

NTID pipeline: raw traffic → PCA dimensionality reduction (`pca_components.csv` + `pca_mean.csv`) → feature standardization → KNN classification (`knn_model.cml` via `libsiteai_cml.so`) → traffic type label. The model is trained externally, serialized to CSV+CML format, and deployed on-device for real-time inference.

**TLS/IP decryption and IPS:**

| Binary | Description |
|---|---|
| `decpt_ip.out` | On-switch TLS/IP decryption binary |
| `libdecpt_adp.so` | Decryption adapter library |
| `ips.so` | Intrusion Prevention System library |
| `nac.o` | Network Access Control module |

`decpt` = decrypt. The switch can perform inline TLS decryption for deep packet inspection, requiring TLS session keys to be held or injected by a centralized controller. Combined with `ips.so`, this is an inline TLS MitM + IPS architecture at the switch level.

**NGE (Network Graph Engine):**

| Binary | Description |
|---|---|
| `nge.out` | NGE binary (purpose requires binary analysis) |
| `nge.conf` | NGE configuration |
| `nge-version.zip` | NGE version archive |

### SquashFS 2: BSP/CBB driver layer (7MB, 119 inodes)

Kernel modules for physical switch hardware. Mixed-vendor silicon:

| Module | Vendor | Purpose |
|---|---|---|
| `ko/cbb/altera_cpldjtag_drv.ko` | Altera | CPLD JTAG programmer |
| `ko/cbb/altera_fpga_load_drv.ko` | Altera | FPGA bitstream loader |
| `ko/cbb/hisi_fpga_load_drv.ko` | HiSilicon | FPGA loader (alongside Altera) |
| `ko/cbb/bcm54219_phy_drv.ko` | Broadcom | BCM54219 1GbE PHY driver |
| `ko/cbb/ina220_power_drv.ko` | Texas Instruments | INA220 power monitor |
| `ko/cbb/can_bus.ko` | — | CAN bus (atypical for switch; likely inter-board management) |
| `etc/bootload_step1.sh`, `step2.sh` | — | Two-stage bootloader shell scripts |

14 CPLD driver variants total. The presence of `can_bus.ko` is unusual for a campus switch — likely used for inter-board management on modular chassis variants.

### SquashFS 3: NETCONF/YANG management stack (7MB, 717 inodes)

Python 3.9 NETCONF management plane with Redis-backed internal store:

| Component | Detail |
|---|---|
| Python 3.9 | `usr/bin/python3.9` |
| NETCONF plugins | `netconf_remote_plugin.py`, `netconf_ctrl.py`, `netconf_notification.py`, `netconf_patterns.py`, `netconf_pylibconf.py` |
| YANG models | 40+ protocols: AAA, BGP, BGP-L3VPN, BFD, Capture (!), EVPN, Interfaces, IP, L2VPN, LLDP, Free-Mobility, etc. |
| libhiredis.so | Redis C client — internal management-plane KV store |
| libredisapi.so | Redis API wrapper |
| libconf.so | Huawei configuration management library |
| libxml2.so.2.9.13 | XML parsing (2022-05-03 release) |

All YANG model plugins are plaintext Python (`.py` files) — extracting SquashFS 3 exposes the complete NETCONF API schema for static analysis.

### S5720EI V200R019 PAT patch format

Same header layout as NE40E SPH and NE8000 SPH patches:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0x00 | 32 | Platform version (null-padded) | "V200R019" |
| 0x20 | 32 | Patch name (null-padded) | "SPH3b0" |

Embedded version strings in the body: `V200R019C00SPC200B319` (from build) and `V200R019C00SPC500B327` (target build). "SPH3b0" is an alphanumeric version tag (not a pure decimal patch count).

### Security findings

| Finding | ID | Severity | Detail |
|---|---|---|---|
| On-switch TLS/IP decryption (decpt_ip.out + libdecpt_adp.so) | GOTREX_SEC_001 | MEDIUM | Inline DPI decryption; key storage requires binary analysis; compromise → all TLS sessions decryptable |
| YANG capture plugin — NETCONF packet capture API | GOTREX_SEC_002 | MEDIUM | `yang_huawei_capture.py` exposes NETCONF capture; plaintext plugins expose full API schema pre-auth |
| libxml2 2.9.13 — post-release CVE exposure | GOTREX_SEC_003 | LOW | CVE-2022-40303/40304, CVE-2023-28484/29469 may apply; Huawei patch level unconfirmed |
| All YANG plugins are plaintext Python in firmware | GOTREX_SEC_004 | INFO | Full NETCONF surface exposed via SquashFS 3 extraction |
| Atlas A10x AI chip embedded (A0104 V12.00.00) | GOTREX_SEC_005 | INFO | Dedicated AI NPU; opaque firmware; management CPU compromise → NPU reflash risk |
| Redis internal management store (libhiredis) | GOTREX_SEC_006 | INFO | Default Redis = no auth; NETCONF plugin RCE → Redis config store accessible |
