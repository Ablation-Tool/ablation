# bFLT v4 Executables

`BfltImage` reads version-4 binary Flat (`bFLT`) programs used by uClinux and other embedded Linux systems. It exposes text, initialized data, and an address-indexed memory image without running the program or requiring its original operating system.

---

## Why an executable needs its own loader

An analyst cannot reliably disassemble a file by treating every byte as an instruction. Executable files also contain headers, constants, pointers, relocation information, and descriptions of memory that should be created at runtime.

ELF loaders recover this structure for ELF programs, but embedded systems may use bFLT instead. bFLT stores a compact header followed by a flat text/data image. Its header uses big-endian integers even when the program contains little-endian ARM instructions. Assuming one byte order for both layers produces invalid addresses or nonsensical disassembly.

`BfltImage` supplies the missing boundary between recovered file bytes and architecture-specific analysis. It was added after six bFLT executables were recovered from the CAEN C111C JFFS2 image, including its web server and command services.

See [Firmware Parsing: From Artifacts to Analysis](firmware-parsing.md) for the surrounding pipeline.

---

## What “flat” means

Flat addresses in this API are offsets in an image whose first byte is the 64-byte bFLT header. They are not automatically physical addresses, ELF virtual addresses, or a runtime load base chosen by an operating system.

```text
0x00               64-byte header
0x40               text (entry normally points here)
entry..data_start   executable bytes
data_start..data_end initialized data
data_end..bss_end    zero-initialized BSS, not stored in memory_image
reloc_start         physical relocation table in the input file
```

Text and initialized data have stored bytes. BSS describes zero-initialized memory, so it has a range but no file payload. The relocation table belongs to the file layout, not to `data_bytes`.

This separation prevents common mistakes: reading a string from BSS as though it were stored in the file, disassembling the relocation table, or treating a flat address as a guaranteed hardware address.

---

## How the parser works

1. Read and unpack the 64-byte header with big-endian integer fields.
2. Require revision 4, zero reserved fields, supported flags, and coherent entry, text, data, BSS, and relocation ranges.
3. Enforce input and memory limits before constructing the flat image. Both default to 64 MiB.
4. For RAM-style images, copy the initialized image through `data_end`.
5. For gzip images, decompress exactly `data_end - 64` bytes after the unchanged header.
6. Use `reloc_start` as a physical file offset and validate the complete relocation table.
7. Expose bounded slices and reads. Preserve trailing-byte counts instead of silently classifying them.

Compressed input has two layouts at once. `data_end` describes the expanded memory image, while `reloc_start` points into the stored file. Confusing those coordinate systems can truncate the gzip stream or place the relocation table at a nonexistent memory address.

Malformed headers, unsupported flags, truncated relocations, invalid gzip streams, and output-size mismatches raise `BfltError`.

---

## Why this works

The bFLT header supplies lengths and offsets for each stored region. Once those values are checked, slicing produces the original text and initialized data, and decompression restores the same flat layout for compressed files. The address of a byte in `memory_image` remains its flat address.

No processor assumption is needed for this transformation. ISA selection happens afterward. Keeping format parsing separate from instruction decoding allows the same loader to serve ARM, MIPS, or another bFLT target when its layout is supported.

---

## Usage

```python
from ablation.parsers.bflt import BfltImage

image = BfltImage.from_path('/path/to/tinyws')
print(image.metadata())

code = image.text_bytes
constants = image.data_bytes
entry_word = image.read_memory(image.entry, 4)
assert code == image.memory_image[0x40:image.data_start]
```

`from_bytes()` accepts a program recovered from a filesystem. `metadata()` reports ranges, entry, BSS end, flags, compression, relocation count, and trailing bytes. `read_memory()` rejects reads beyond initialized memory.

For an ARM32 target whose ISA has been independently confirmed:

```python
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
decoder.skipdata = True
entry_offset = image.entry - 0x40
for insn in decoder.disasm(code[entry_offset:], image.entry):
    print(f'{insn.address:#x}: {insn.mnemonic} {insn.op_str}')
```

`skipdata` lets Capstone represent unrecognized or inline-data words without losing synchronization. It does not prove that every skipped word is data. Text can contain literal pools, and data can contain addresses requiring relocation analysis.

---

## What this adds for the user

The parser turns a previously manual loading exercise into a reusable, bounded API. A user can inspect service configuration and code in an embedded Linux filesystem without first rebuilding its runtime or writing a one-off header decoder.

This is a small enabling component, not a bFLT decompiler. It does not currently produce `BinaryContext`, apply relocations, discover functions, or infer an ISA. A future adapter could connect the memory image to those facilities; the parser would then serve as that adapter's format backend.

Such an adapter should be added only with relocation-aware tests. Extending the loader is preferable to guessing addresses that could make later security analysis look precise while being wrong.

---

## Disassembly checklist and limitations

1. Preserve the original file hash before analysis.
2. Confirm the ISA independently. bFLT revision 4 is not an architecture identifier.
3. Disassemble from flat address `image.entry`, not an assumed ELF virtual base.
4. Resolve target-specific relocation semantics before trusting absolute pointers. Relocations are exposed but not applied.
5. Account for zero-filled BSS when interpreting globals; it is not included in `memory_image`.
6. RAM layouts and gzip (`0x08`) are supported. ROM (`0x02`), GOT-PIC (`0x04`), and gzip-exec (`0x10`) fail explicitly.
7. Nonzero trailing bytes are counted, not silently treated as code or relocations.
8. A valid layout does not prove safe code, complete firmware, or suitability for a particular board.

---

## See also

- [Firmware Parsing: From Artifacts to Analysis](firmware-parsing.md)
- [JFFS2 Filesystem Reader](jffs2.md)
- [CAEN ASCII-Hex Firmware Containers](caen-ascii-hex.md)
- [WindowAnalyzer](window-analyzer.md)
