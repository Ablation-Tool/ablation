# bFLT ARM32 Link-Time References

`BfltArm32` resolves stored pointers and PC-relative ARM32 literal-pool references in a parsed bFLT v4 image. It is a small bridge between [bFLT loading](bflt.md) and instruction analysis, not a complete executable-analysis framework.

---

## Why this exists

A bFLT loader can tell you where text and data begin, but that alone does not explain how code refers to a string, global, or function.

Consider a common ARM32 sequence:

```text
0x40: ldr r0, [pc, #4]
0x44: ...
0x48: ...
0x4c: 00 02 00 00
```

In ARM state, the `pc` used by this instruction is `0x48`, eight bytes after its own address. The instruction therefore reads the word at `0x4c`. If that word is a big-endian pointer, its value is `0x00020000`. There are two separate hops:

```text
instruction at 0x40 → literal at 0x4c → stored value 0x20000
```

Treating the literal bytes as another ARM instruction loses the reference. Treating them as a native-endian integer can produce the wrong value. Treating `0x20000` as a final runtime address can be wrong for a different reason: a self-relocating bFLT program may add a load base later.

`BfltArm32` makes those layers explicit and keeps them separate.

---

## What it does

1. Accepts an already validated `BfltImage`. The caller must establish that the target is little-endian ARM32; bFLT itself does not identify the ISA.
2. Requires `pointer_byteorder="big"` or `"little"`. This is deliberately independent of instruction endianness.
3. Disassembles bounded, aligned text ranges with Capstone.
4. Recognizes supported `ldr`-family loads whose second operand is `[pc, displacement]`.
5. Computes the literal address using the ARM-state `instruction_address + 8 + displacement` rule.
6. Reads stored pointer values without applying a runtime load base.
7. Reports candidate aligned pointer words and two-level literal references.

The reader does not execute the image, mount a filesystem, infer a symbol, or invent a relocation result.

---

## API

```python
from ablation.analyzers.bflt_arm32 import BfltArm32
from ablation.parsers.bflt import BfltImage

image = BfltImage.from_path('/path/to/program')
context = BfltArm32(image, pointer_byteorder='big')

print(hex(context.read_pointer(0x4C)))
# 0x20000 for the example above

references = context.literal_references(0x20000)
for reference in references:
    print(
        hex(reference.instruction_address),
        hex(reference.literal_address),
        hex(reference.value),
    )
```

For the example, the result describes an instruction at `0x40`, a literal at `0x4C`, and a stored value of `0x20000`.

### Methods

- `instructions(start=0x40, end=None)` yields instructions from a bounded, four-byte-aligned range inside text.
- `read_pointer(address)` reads one 32-bit stored pointer using the explicitly selected byte order.
- `pointer_references(target, start=0x40, end=None)` returns aligned addresses containing `target` in initialized memory.
- `literal_references(target)` finds supported PC-relative loads whose stored pointer equals `target`.
- `literal_references(target, dereference=False)` instead finds loads whose literal-pool address itself equals `target`. In that mode, `value` is `None`.
- `literal_address(insn)` exposes the PC-relative calculation for a supported Capstone instruction.

`Arm32LiteralReference` preserves the instruction address, mnemonic, operands, literal address, and optional stored value.

---

## How to choose between the two searches

Use `pointer_references()` when you need every aligned word that might point at an object. This searches initialized text and data, including literal pools. It is intentionally a candidate scan.

Use `literal_references()` when you need an instruction-level connection through a supported ARM32 literal load. It performs both hops and avoids requiring you to manually join a pointer table to disassembly.

Use `dereference=False` when the question is “which instructions read this literal-pool slot?” rather than “which instructions load a pointer to this object?”

---

## What this provides the user

This is a small enabling component. It turns a repetitive manual calculation into a tested API that can support command-handler tracing, global-reference recovery, and later bFLT function analysis.

Its architectural role is the link-time reader behind [BfltBinaryContext](bflt-context.md). The adapter applies relocations and constructs the shared analysis context; this class remains useful when the question is specifically about stored pointers and literal pools. Keeping those responsibilities separate makes address provenance easier to audit.

The important user-facing distinction is that it provides **link-time references**, not relocated runtime addresses or proof that an instruction executes. For relocated images, use `BfltBinaryContext` rather than passing loaded bytes back to this class with file-endian assumptions.

---

## Verification and failure behavior

Tests cover explicit big- and little-endian reads, aligned pointer candidates, two-level literal resolution, direct literal-address searches, invalid targets, and out-of-text or unaligned ranges. Original C111C bFLT images provide an independent real-format check: their instructions are little-endian ARM while their pointer words are big-endian.

Invalid pointer byte orders, targets outside 32 bits, and invalid scan ranges raise `ValueError`. Passing an unparsed byte string instead of `BfltImage` raises `TypeError`. Memory reads retain the parser's bounds checks and resource limits.

Scanning is linear in the selected text or initialized-memory range. Returned matches are bounded by that input range; callers should use the parser's memory limits and focused ranges for very large images.

---

## Limitations

- Only little-endian ARM state is decoded. Thumb, big-endian ARM, and other ISAs are not inferred or selected automatically.
- No relocations are applied. Stored values are not promised to be final runtime addresses after a self-relocation stub runs.
- This is not a `BinaryContext`, function finder, CFG builder, taint tracker, or full C166-style semantic decoder.
- Capstone `skipdata` permits a linear walk to continue, but valid-looking data can still decode as instructions. Every security-relevant reference needs code-region and byte review.
- An aligned pointer match is a candidate, not proof of a code reference. Conversely, PC construction through arithmetic, register-relative tables, or unsupported load forms is outside this reader's current coverage.
- Missing references do not prove missing functionality. External scripts, alternate pointer construction, indirect calls, and absent filesystem partitions require separate evidence.

## See also

- [bFLT v4 Executables](bflt.md)
- [Relocation-Aware bFLT BinaryContext](bflt-context.md)
- [JFFS2 Filesystem Reader](jffs2.md)
- [WindowAnalyzer](window-analyzer.md)
- [Firmware Parsing: From Artifacts to Analysis](firmware-parsing.md)
