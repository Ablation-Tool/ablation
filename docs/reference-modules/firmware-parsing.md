# Firmware Parsing: From Artifacts to Analysis

A firmware download is not always a program. It may be a text representation of a program, a filesystem containing many programs, or an executable format that a general ELF loader does not understand. Parsing turns those outer representations into precise inputs for reverse engineering.

---

## The central idea

Reverse engineering starts with bytes, but bytes have different meanings at different layers. A printable hexadecimal character is not yet an instruction. A compressed filesystem fragment is not yet a file. An executable header is not part of its code, even when its fields and code share one address space.

A parser separates those layers. It answers three questions before deeper analysis begins:

1. **Where does each object begin and end?** This keeps headers, code, data, and padding distinct.
2. **Which address or name belongs to these bytes?** Instructions and files need their original context.
3. **Is the input internally consistent?** Lengths, checksums, versions, and resource limits must agree.

The result is not a vulnerability verdict. It is a defensible starting point for control-flow recovery, protocol analysis, and authorization review.

---

## One piece at a time

A complex firmware investigation can be decomposed into small transformations:

```text
CAEN update file
  -> ASCII-hex decoder
  -> ELF executable
  -> ARM instruction analysis

JFFS2 filesystem image
  -> directory and inode reconstruction
  -> file bytes
  -> bFLT loader
  -> relocation-aware BinaryContext
  -> instruction and literal analysis
```

Not every target uses every stage. The CAEN A1676 update contains an ELF after its wrapper is removed. The CAEN C111C image instead contains a JFFS2 filesystem with six bFLT programs. Reusing the right small parser avoids a custom extraction script for each investigation.

| Layer | Question answered | Ablation component |
|:---|:---|:---|
| Update container | Which bytes form the payload, and does its checksum agree? | `CaenHexFirmware` |
| Filesystem | Which files exist, and what are their current contents? | `Jffs2Image` |
| Executable | Where are text, initialized data, BSS, and relocations? | `BfltImage` |
| Instructions | What operations do the code bytes represent? | An independently selected ISA decoder |

A processor decoder cannot infer all of this from a raw byte stream. Conversely, a container parser cannot determine the processor architecture merely because its input is valid.

---

## What validation proves

A matching checksum or CRC supports internal consistency. It can catch truncation, accidental modification, and incorrect assumptions about the encoding. It does not prove that a vendor signed the artifact, that a bootloader will accept it, or that a device runs it.

Likewise, a reconstructed configuration file shows what is stored in the supplied image. It does not show whether a deployed device changed that configuration, exposes a service, or permits an unauthenticated operation. Those conclusions need separate code-level or runtime evidence.

Resource limits are a second kind of validation. Firmware is untrusted input, and declared sizes can be malformed or hostile. Input, file, memory, and expansion limits make malformed-input behavior explicit instead of allowing unbounded allocation.

---

## Why keep these components small?

These parsers are modest pieces of infrastructure, not independent reverse-engineering solutions. Their value is composability: one tested implementation can serve an interactive investigation, a batch sweep, or a later automated firmware pipeline.

That small scope also permits change. A future common loader could use these parsers as backends. A parser could remain a specialist utility, gain support for another observed variant, or be replaced if a better implementation becomes available. None of those possibilities requires every consumer to understand the underlying format.

The current APIs are intentionally explicit. They do not claim automatic format detection or a universal firmware extraction pipeline. Relocation is an explicit analysis step with a selected load base and recorded outcomes, not a silent side effect of parsing.

---

## Choose the next step

- [CAEN ASCII-Hex Firmware Containers](caen-ascii-hex.md): remove and validate the vendor update wrapper.
- [JFFS2 Filesystem Reader](jffs2.md): recover paths and file contents from a little-endian filesystem.
- [bFLT v4 Executables](bflt.md): obtain a bounded flat memory image for disassembly.
- [Relocation-Aware bFLT BinaryContext](bflt-context.md): apply supported relocations and recover functions, calls, strings, and literal references.
- [Strict Intel HEX Parser](intel-hex.md): preserve sparse addresses from record-oriented firmware text.

For architectural analysis after extraction, see [Understanding Ablation](../overview.md) and the [Tool Selection Guide](../guide-tool-selection.md).
