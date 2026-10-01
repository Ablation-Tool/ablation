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
