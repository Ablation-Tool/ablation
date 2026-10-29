# bFLT v4 Executables

`BfltImage` parses version-4 binary Flat (`bFLT`) executables used by uClinux and other embedded Linux systems. It exposes a bounded, address-indexed flat memory image, text and data slices, and relocation bytes without executing the file.

---

## Why this exists

1. `BinaryContext` expects ELF or other container formats with richer metadata; it does not load bFLT directly.
2. bFLT has a big-endian header but may contain little-endian ARM code. Parsing instructions as big-endian data produces meaningless output.
3. Compressed images store relocation tables at physical file offsets, while `data_end` describes the uncompressed memory layout. Conflating these offsets truncates gzip input.
4. Flat images need explicit address bounds and resource limits before disassembly or string cross-reference analysis.

---

## Memory model

The 64-byte header is included at flat address zero. For an uncompressed image, initialized memory ends at `data_end`:

```text
0x00               64-byte header
0x40               text (entry normally points here)
entry..data_start   executable bytes
data_start..data_end initialized data
data_end..bss_end    zero-initialized BSS, not stored in memory_image
reloc_start         physical relocation table in the input file
```

For gzip-compressed input, the header and relocation table remain in the file. The compressed payload expands to `data_end - 64` bytes. `reloc_start` is then the physical offset of the relocation table, not the uncompressed data end.

---

## Usage

```python
from ablation.parsers.bflt import BfltImage

image = BfltImage.from_path('/path/to/tinyws')
print(image.metadata())
code = image.text_bytes
constants = image.data_bytes
word = image.read_memory(image.entry, 4)
```

`from_bytes()` is available for bytes recovered from a filesystem. `metadata()` reports ranges, entry, BSS end, flags, compression, relocation count, and trailing bytes. `read_memory()` enforces initialized-memory bounds.

The default input and BSS-memory limits are 64 MiB each. Malformed headers, invalid address ordering, unsupported flags, truncated relocations, malformed gzip streams, and size mismatches raise `BfltError`.

---

## Disassembly workflow

1. Parse and preserve the original file hash.
2. Confirm the ISA independently; bFLT does not identify ARM, MIPS, or another processor.
3. Disassemble `text_bytes` with the flat address of its first byte, normally `0x40`, rather than assuming an ELF virtual base.
4. Relocations are exposed as bytes but are not applied. Resolve target-specific relocation semantics before relying on absolute pointers.
5. Account for zero-filled BSS when interpreting globals; it is not included in `memory_image`.

---

## Limitations and false positives

- Only revision 4 is accepted. Revision is not an architecture identifier.
- RAM-style layouts and gzip (`0x08`) are supported. ROM (`0x02`), GOT-PIC (`0x04`), and gzip-exec (`0x10`) are rejected explicitly rather than assigned unverified address mappings.
- Relocations are not applied and no load address is invented for a runtime loader.
- Nonzero trailing bytes are counted, not silently treated as relocations or code.
- Valid bFLT structure does not prove that code or data is safe, complete, or suitable for a particular board.

---

## See also

- [JFFS2 Filesystem Reader](jffs2.md)
- [CAEN ASCII-Hex Firmware Containers](caen-ascii-hex.md)
- [WindowAnalyzer](window-analyzer.md)
