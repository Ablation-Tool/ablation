# ZynqMpBootImage

**Module:** `ablation/analyzers/zynqmp_boot.py`

Strict, dependency-free parsing and raw partition extraction for Xilinx Zynq UltraScale+ MPSoC `BOOT.BIN` containers.

## Why this exists

ZynqMP boot images often contain PMU firmware, an FSBL, a PL bitstream, ARM Trusted Firmware, a device tree, and U-Boot. These are stored as raw load sections rather than necessarily retaining their original ELF wrappers. A generic embedded-ELF scan therefore misses most of the boot chain. This parser follows the boot, image-header, and partition-header tables directly and exposes the exact stored bytes for architecture-specific analysis.

## Usage

```python
from ablation.analyzers.zynqmp_boot import ZynqMpBootImage

image = ZynqMpBootImage.from_path("BOOT.BIN")
print(image.summary())

for partition in image.partitions:
    print(partition.name, hex(partition.offset), hex(partition.load_address))
    print("stored bytes:", len(partition.payload))

paths = image.extract_all("extracted-boot")
```

`from_bytes()` accepts an in-memory image. Header checksum validation is enabled by default; `validate_checksums=False` is available for forensic inspection of damaged headers, while structural bounds checks remain enforced.

## Result model

`ZynqMpBootImage` exposes:

- `images`: decoded image headers and original component names.
- `partitions`: stored partitions in boot order.
- `image_header_table_offset` and `partition_header_table_offset`.
- `boot_header_checksum_valid` and `iht_checksum_valid`.

Each `ZynqMpPartition` includes its source and header offsets, encrypted/unencrypted/total lengths, execution and load addresses, raw attributes, destination device and CPU, encryption/authentication flags, checksum type, and partition-header checksum status. `payload` returns the stored encrypted-length byte range; it does not decrypt, decompress, or reconstruct an ELF.

## Validation and safety

The parser checks:

- ZynqMP synchronization and identification words and IHT version.
- Boot-header, IHT, and every partition-header checksum.
- Agreement between boot/IHT partition-table offsets and image/IHT partition counts.
- Image-chain cycles, excessive table counts, invalid destinations, and inconsistent lengths.
- Every table and payload range before integer multiplication or slicing can escape the input.
- Image-name termination, word-wise name decoding, and ASCII encoding.

Inputs are capped at 512 MiB, 32 images, 32 partitions, and 255 encoded name bytes. Extraction prefixes every name with its partition index and replaces path separators and other unsafe filename characters.

## What this adds for the user

The parser turns a multi-stage boot container into named, bounded components that can be examined independently. It replaces manual table arithmetic and makes checksum status, load addresses, destination CPUs, and raw partition bytes available to scripts. This is a small ingestion layer that can feed ELF, device-tree, bitstream, or raw-code analysis as appropriate.

Its role is intentionally limited to container structure. A future boot-chain workflow could classify those components automatically, but it would still need separate evidence for decryption, authentication, and runtime behavior. The current reader remains useful because it does not conflate those questions with successful table parsing.

## Limitations

- The extractor returns raw stored partitions. A partition named after an ELF may contain one or more raw load sections, and a combined PMU/FSBL partition remains combined.
- Encryption and authentication flags are decoded, but payloads are not decrypted and authentication certificates or signatures are not cryptographically verified.
- Header checksums provide structural consistency, not authenticity or a security assessment.
- The parser supports the Zynq UltraScale+ format, not Zynq-7000 or Versal PDI containers.
- Slave-boot split images with rebased offsets are not currently supported.

## Example output

```text
Zynq UltraScale+ boot image: 9,034,776 bytes
  images=5 partitions=5 IHT=0x8c0 PHT=0x1100
  header checksums: boot=True IHT=True
  [0] zynqmp_fsbl.elf.0: offset=0x2800 size=0x38d00 ...
  [1] firmware.bit.0: offset=0x3b500 size=0x76fbbc device=PL ...
  [2] bl31.elf.0: offset=0x7ab0c0 size=0xc7b0 ...
  [3] system.dtb.0: offset=0x7b7880 size=0x9838 ...
  [4] u-boot.elf.0: offset=0x7c10c0 size=0xdcb58 ...
```

## Tests and FORGE

`tests/test_zynqmp_boot.py` covers valid parsing and extraction, encoded names, bad magic, truncation, checksum corruption, out-of-bounds payloads, cyclic image chains, unterminated names, and a real multi-stage boot image when the research artifact is available. The artifact-dependent test skips elsewhere.

The SAFE CODE 10-section review covers functional correctness, bounded parsing, extraction safety, integrity, resilience, and residual secure-boot limitations. `FORGE.audit_module()` passes with zero open findings.

## See also

- [Embedded ELF discovery](embedded-elf.md)
- [MicroBlaze decoder](microblaze-decoder.md)
- [Versal PDI/CDO parser](versal-pdi.md)
- [Xilinx Bootgen source](https://github.com/Xilinx/bootgen)
