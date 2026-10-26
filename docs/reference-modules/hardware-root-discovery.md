# Hardware Root Discovery

Parse firmware container images with a plaintext partition table, identify partition payload types ELF, ext2/3/4, gzip, xz, SquashFS, JFFS2, extract component version strings and vendor metadata, and perform entropy-based section classification to locate keys, certificates, and compressed code regions: providing the hardware root of trust analysis baseline for firmware security assessment: via `ablation/core/firmware_analyzer.py` and `ablation/analyzers/firmware_container.py`.

---

## Why this exists

1. **`FirmwareContainer` parses proprietary firmware partition table formats** without requiring vendor tooling, it reads the fixed-layout container header `magic[8]`, `fw_version[8]`, `vendor_string[16]`, `product_string[16]`, `partition_table[n × 296 bytes]` and extracts each partition's payload type using `_detect_payload()`. The partition table structure is common across network equipment and embedded Linux devices using custom update formats. Extracting partitions without vendor tools is the prerequisite for all subsequent static analysis.

2. **`scan_firmware_file()` performs a complete static analysis pass** on a firmware image, it runs `scan_firmware_signatures()` to identify embedded filesystems, bootloaders, and archive types by magic bytes SquashFS `0x68737173`, JFFS2 `0x1985`, U-Boot `\x27\x05\x19\x56`, runs `analyze_firmware_entropy()` to classify 1KB blocks as code entropy 6.0–7.5, data entropy 3.0–6.0, compressed/encrypted entropy > 7.5, or zero-padded, and calls `extract_firmware_strings()` to surface hardcoded credentials, private key material, and configuration parameters.

3. **`extract_firmware_strings()` extracts printable strings by category**, it returns a structured dict with `credentials` username/password patterns, `urls` hardcoded management URLs and endpoints, `crypto_material` PEM headers, certificate subjects, key identifiers, `version_strings` software component versions and build timestamps, and `paths` filesystem paths revealing directory layout. This feeds directly into the vulnerability assessment without requiring filesystem mount access.

---

## How it works

```mermaid
flowchart TD
    A(["FirmwareContainer.parse(data) → FirmwareContainer\n  Read magic[8]: identify container format\n  fw_version, vendor_string, product_string\n  Partition table: n × 296-byte records\n    name[32], type[4], offset[8], size[8]\n    checksum[4], compression[4]\n  _detect_payload(data, offset, size):\n    SquashFS / JFFS2 / ext2-4 / gzip / xz / ELF\n  → List[FirmwarePartition{name, type, payload_type}]"]):::input --> B["scan_firmware_signatures(data) → list\n  Magic byte scan:\n    b'\\x27\\x05\\x19\\x56' → U-Boot image\n    b'sqsh' / b'hsqs' → SquashFS\n    b'\\x85\\x19' → JFFS2 LE / b'\\x19\\x85' BE\n    b'\\x1f\\x8b' → gzip\n  → [{signature_type, offset, description}]"]:::primary
    B:::primary --> C["analyze_firmware_entropy(data, block_size=1024) → list\n  Shannon entropy per 1KB block:\n    < 1.0 → zero padding\n    1.0-3.0 → structured data\n    3.0-6.0 → text/code\n    6.0-7.5 → packed binary\n    > 7.5 → compressed or encrypted\n  → [{block_offset, entropy, type}]"]:::secondary
    C:::secondary --> D(["extract_firmware_strings(data, min_length=8) → dict\n  Printable string extraction\n  Categories:\n    credentials: user=, pass=, admin, default\n    urls: http://, https://, ftp://\n    crypto_material: BEGIN CERTIFICATE, BEGIN RSA\n    version_strings: v[0-9]+, build-[0-9]+\n    paths: /etc/, /usr/, /var/\n  → {credentials, urls, crypto_material, versions, paths}"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from ablation.analyzers.firmware_container import FirmwareContainer
from ablation.core.firmware_analyzer import (
    scan_firmware_file,
    extract_firmware_strings,
    analyze_firmware_entropy
)

# Parse a firmware image
data = open('firmware.bin', 'rb').read()
container = FirmwareContainer.parse(data)
print(f"Vendor: {container.vendor_string}  Product: {container.product_string}")
for part in container.partitions:
    print(f"  {part.name}: {part.payload_type} @ {part.offset:#x} ({part.size} bytes)")

# Full static analysis pass
report = scan_firmware_file('firmware.bin')
for cred in report.get('credentials', []):
    print(f"  CREDENTIAL: {cred}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
FirmwareContainer: firmware.bin

Vendor: <vendor>  Product: <product>
Partitions:
  bootloader: ELF @ 0x0000 (<N> bytes)
  kernel: gzip @ 0x10000 (<N> bytes)
  rootfs: SquashFS @ 0x210000 (<N> bytes)

scan_firmware_signatures:
  SquashFS at 0x210000
  U-Boot at 0x0000

extract_firmware_strings:
  credentials: ['<user>:<password>', '<user>:<password>']
  crypto_material: ['-----BEGIN RSA PRIVATE KEY-----']
```

---

## False positives

**Entropy > 7.5 classified as encrypted**: firmware images using compression for code sections xz-compressed Linux kernel, lz4-compressed ramdisk produce entropy above 7.5 that is identical to encrypted blocks. Identify the actual compression format from the signature scan before concluding that a high-entropy block contains encryption material.

**Credential string extraction**: strings matching `admin` or `pass=` in binary data may be configuration template strings or debug messages rather than actual credentials. Verify by locating the string in the partition context bootloader vs. application vs. debug log.

---

## Pipeline position

Run firmware container parsing and entropy analysis as the first step on any firmware image. Partition layout establishes the analysis structure; string extraction identifies the most interesting regions for deeper investigation with `BinaryContext` and static analysis tools.

---

## Reading output

`FirmwareContainer(path)` (or `FirmwareContainer.from_path(path)`) parses in-place. Attributes after construction:

| Attribute | Content |
|:---|:---|
| `magic` | Container magic string |
| `fw_version` | Firmware version string |
| `vendor` | Vendor name from container header |
| `product` | Product name from container header |
| `language` | Language code from header |
| `partitions` | `List[FirmwarePartition]`: parsed partition entries |

Each `FirmwarePartition`:

| Attribute | Content |
|:---|:---|
| `index` | Partition index (0-based) |
| `version` | Partition version string |
| `name` | Partition name string |
| `offset` | Byte offset within the firmware image |
| `size` | Partition size in bytes |
| `destpath` | Destination path string from the partition table |
| `payload_type` | Detected payload type for example `'elf'`, `'ext2'`, `'squashfs'`, `'gzip'`, `'unknown'` |

---

## See also

- [Firmware Flasher Trust Checks](firmware-flasher-trust-checks.md): Authenticode signature verification analysis for firmware update PE binaries
- [Tandem Guardian PAK](tandem-guardian-pak.md): alternative proprietary archive format extraction
