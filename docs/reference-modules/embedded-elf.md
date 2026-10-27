# Embedded ELF discovery

**File:** `ablation/analyzers/embedded_elf.py`

## Why this exists

Firmware containers can include ELF payloads at arbitrary offsets. The four-byte `\x7fELF` signature alone is not enough: bitstreams and compressed data can contain the same bytes. `find_embedded_elf()` accepts only structurally valid images and returns their exact payloads.

## Usage

```python
from ablation.analyzers.embedded_elf import find_embedded_elf

for image in find_embedded_elf(container_bytes):
    print(image.offset, image.architecture, image.bits, image.byte_order)
    Path(f"payload-{image.offset:x}.elf").write_bytes(image.payload)
```

`VersalPdi.embedded_elf()` applies the same scan to a PDI:

```python
vp = VersalPdi.from_path("boot.pdi")
payloads = vp.embedded_elf()
```

## Result model

Each `EmbeddedElf` contains:

| Field | Meaning |
|---|---|
| `offset` | Byte offset of the ELF header in the source buffer |
| `architecture` | Validated `e_machine` name |
| `bits` | 32 or 64 |
| `byte_order` | `little` or `big` |
| `payload` | Exact ELF bytes through the last validated table, load segment, or section |

## Validation

The parser checks ELF class, byte order, ident and ELF versions, file type, machine, native header sizes, program/section table bounds, section-string index, load-segment file bounds, and non-`NOBITS` section bounds. Each payload is capped at 64 MiB, total extracted payloads at 256 MiB, and scans at 4,096 magic candidates.

Invalid or truncated candidates are skipped rather than emitted as valid images. A valid embedded ELF can coexist with unrelated bytes before or after it; trailing bytes are not included in `payload`.

## Limitations

- This is embedded-image discovery, not a complete PDI boot-partition parser. Boot header fields that remain opaque are not guessed.
- An empty result means no embedded ELF passed this strict scan. It does not prove that every possible compressed, encrypted, or raw firmware encoding is absent.
- The scanner does not decompress or decrypt candidate payloads.
- Structural validation does not prove that an ELF is safe, executable on the target, or free of malicious code.

## Validation and FORGE

Tests cover ELF32/64, both byte orders, exact extraction, invalid magic candidates, bad tables, truncation, total payload limits, and production PDI scans with no embedded ELF. `FORGE.audit_module()` and the SAFE CODE 10-section review pass with zero findings.

## See also

- [VersalPdi](versal-pdi.md)
- [Artifact inventory](artifact-inventory.md)
