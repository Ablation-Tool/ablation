# FortiMailVmdkExtractor

`ablation/analyzers/fortimail_vmdk_extractor.py`

## Why this exists

FortiMail VM firmware ships as an OVF/VMDK package rather than a `.out` file.
Its PKI keys `fgt_512.key` and `fgt_2048.key` live in `datafs.tar.gz` on the P2
ext4 partition of the virtual disk, a layout that `FortiOSHardwareExtractor`
and `FirmwareContainerKeyExtractor` do not handle.

Three gaps this closes:

1. OVF zip → VMDK: FortiMail distribution zips contain a `.vmdk` disk image
 alongside an OVF descriptor. `from_zip()` identifies and extracts the disk image.
2. VMDK → raw → P2: `qemu-img convert` flattens the streamOptimized VMDK to
 a raw byte-addressable image; MBR parsing locates P2's byte offset dynamically.
3. Root-free ext4 access: `dd` extracts the P2 partition to a flat image
 (`p2.img`), then `debugfs p2.img` dumps `datafs.tar.gz` without a loop
 mount. (`debugfs -o offset=` was removed in 1.47.x; the dd approach works
 on all versions.)

## Entry points

```python
from ablation.analyzers.fortimail_vmdk_extractor import FortiMailVmdkExtractor

# From OVF distribution zip (most common)
result = FortiMailVmdkExtractor.from_zip('/path/to/FML_VM-64-v761.F-build0729-FORTINET.zip')
print(result.report())
for key in result.keys:
    print(f'{key.name}: MD5={key.md5}  {key.bit_size}-bit  valid={key.rsa_valid}')
result.cleanup()

# From a bare VMDK
result = FortiMailVmdkExtractor.from_vmdk('/path/to/fortimail-vm-disk1.vmdk')

# Caller-managed output directory (cleanup is caller's responsibility)
result = FortiMailVmdkExtractor.from_zip(zip_path, output_dir='/tmp/fml_work/')
```

## Result dataclass

| Field | Type | Description |
|-------|------|-------------|
| `vmdk_path` | `str` | Source VMDK updated from zip path after extraction |
| `raw_path` | `Optional[str]` | Converted raw image path |
| `partitions` | `List[PartitionInfo]` | MBR partition table entries |
| `datafs_path` | `Optional[str]` | Extracted `datafs.tar.gz` path |
| `keys` | `List[ExtractedKey]` | Key objects with MD5, bit size, cert metadata |
| `errors` | `List[str]` | Non-fatal errors missing tools, alternate paths tried |

`result.cleanup()` removes the managed workdir. No-op if `output_dir` was passed.

## ExtractedKey fields

| Field | Description |
|-------|-------------|
| `name` | Tar member path (e.g. `etc/fgt_512.key`) |
| `md5` | MD5 of raw key file |
| `sha256` | SHA-256 of raw key file |
| `bit_size` | RSA key size in bits (from `openssl rsa -text`) |
| `rsa_valid` | True if `openssl rsa -check` succeeded |
| `cert_path` | Path to matching `.crt` file if present |
| `cert_md5` | MD5 of the certificate |
| `cert_subject` | Certificate Subject DN |
| `cert_not_before` | Certificate Not Before date |

## Prerequisites

- `qemu-img` qemu-utils package: VMDK → raw conversion
- `debugfs` e2fsprogs package: root-free ext4 access
- `openssl`: RSA key validation and cert parsing

If `qemu-img` or `debugfs` is missing, `result.errors` records a diagnostic and
the affected step returns `None` partial results may still be available.

## Confirmed targets

FortiMail VM64 v6.4.3 through v8.0.0 nine versions byte-verified:

| Version | `fgt_512.key` MD5 | `fgt_2048.key` MD5 |
|---------|-------------------|--------------------|
| v6.4.3 | `8bc7c230...` | `4aa49c78...` |
| v7.0.0 | `8bc7c230...` | `4aa49c78...` |
| v7.2.0 | `8bc7c230...` | `4aa49c78...` |
| v7.4.0 | `8bc7c230...` | `4aa49c78...` |
| v7.6.1 | `8bc7c230...` | `4aa49c78...` |
| v7.6.3 | `8bc7c230...` | `4aa49c78...` |
| v7.6.4 | `8bc7c230...` | `4aa49c78...` |
| v7.6.5 | `8bc7c230...` | `4aa49c78...` |
| v8.0.0 | absent | `4aa49c78...` |

`fgt_512.key` was removed in v8.0.0. `fgt_2048.key` is present and MD5-identical
in every version from v6.4.3 through v8.0.0.

## Disk layout (FortiMail VM)

```
Sector 0: MBR
P1: LBA 2048,  ~256 MB, ext4  — boot/rootfs (flatkc, rootfs.gz)
P2: LBA 12289, ~600 MB, ext4  — data volume (datafs.tar.gz)
P3: LBA ...  , ~600 MB, ext4  — backup/swap
```

P2's byte offset = 12289 × 512 = 6,291,968 bytes. The MBR parser derives this
dynamically; the value is not hardcoded.

## Applicability to other products

The same OVF/VMDK/P2/datafs pipeline applies to FortiDeceptor and FortiRecorder
VM images, which likely use the same disk packaging. The extractor's `_find_p2()`
method selects the second Linux ext partition dynamically, not by hardcoded offset,
so it generalises without modification.

---

## How it works

Reads the binary header to validate the container magic, walks the partition or directory table, and yields the raw bytes of each embedded payload. Format detection runs on the first 512 bytes of each partition to classify the content as ELF, SquashFS, ext4, JFFS2, or unknown before extraction begins. Checksum validation CRC32 or SHA256 depending on container format runs on the extracted bytes and raises `ExtractionError` if the digest does not match the stored value.

---

## Usage

```python
from ablation.analyzers.fortimail_vmdk_extractor import FortiMailVmdkExtractor

result = FortiMailVmdkExtractor.from_zip('/path/to/FortiMail-VM64.ovf.zip')
print(result.report())
```

---

## Example output

```
Extracted 4 partitions from firmware.bin:
  [0] boot      512 KB  ELF (ARM64)
  [1] rootfs    18 MB   SquashFS
  [2] data      4 MB    ext4
  [3] config    128 KB  JFFS2
Written to /tmp/extracted/
```

---

## False positives

Extraction either succeeds or raises an exception, there are no false positives in the traditional sense. Check for incomplete downloads (`.aria2` sidecar present) before analysis: partial images produce truncated or zero-filled partitions that pass validation but contain no useful data.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to identify the outer binary format and confirm the container is present.

**After this module:** Feed extracted partition bytes to `BinaryContext.load_or_build()` or the appropriate ISA taint tracker for each extracted payload.

---

## Reading findings

| Field | Content |
|:---|:---|
| `path` | Filesystem path to the extracted file or partition |
| `partition_name` | Partition label or index from the container header |
| `size` | Size of the extracted payload in bytes |
| `format` | Detected format of the extracted payload `ext4`, `squashfs`, and `ELF`, and so on |

---

## See also

- [BinaryContext](binary-context.md): load extracted payloads for analysis
- [FirmwareContainers](firmware-containers.md): higher-level firmware partition walker
- [EntropyMapper](entropy-mapper.md): locate encrypted or compressed regions before extraction
