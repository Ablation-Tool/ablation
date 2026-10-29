<a id="ecuc28xdecoder"></a>
# TI TMS320C28x Decoding

`EcuC28xDecoder` decodes a control-flow-focused subset of TI TMS320C28x instructions from raw code bytes. It handles common 16- and 32-bit branches, calls, returns, loops, and direct-call function discovery. It is not a full C28x disassembler or pseudo-C decompiler.

## Why byte and word addresses are separated

C28x code addresses count 16-bit words, while host buffers and file offsets count bytes. Mixing those units produces incorrect targets even when every instruction decodes correctly. The API exposes that distinction directly so users can map raw sections without silently applying a byte-oriented assumption.

The decoder focuses on control flow because calls and branches are useful first landmarks when exploring a raw DSP image. Direct-call targets become candidate function entries, and unknown operations remain visible for manual review. This is a small navigation component that could feed a later CFG or data-flow implementation, but it does not provide one today. Correct COFF extraction, a word-addressed base, and independent validation of partial instruction coverage remain prerequisites.

## Usage

```python
from ablation.analyzers.ecu_c28x_decoder import EcuC28xDecoder

decoder = EcuC28xDecoder.from_bytes(code_bytes, base_va=0x3F8000)
for insn in decoder.disassemble(start=0, end=len(code_bytes)):
    print(insn)

starts = decoder.function_starts()
print([hex(va) for va in starts])
```

`from_path(path, base_va=...)` reads raw code bytes from a file. Extract a COFF code section before using it; passing an entire COFF container would decode headers as instructions.

The API distinguishes **byte offsets** from **word addresses**:

- `decode_one(byte_off)`, `insn_length(byte_off)`, and `disassemble(start, end)` use byte offsets in the supplied buffer.
- `base_va`, `C28xInsn.word_va`, and static `target` values use C28x 16-bit word addresses.
- The corresponding byte offset is `2 * (word_va - base_va)`.

## Instruction model

`C28xInsn` exposes `word_va`, `is_32bit`, `mnemonic`, `insn_type`, `raw`, optional `target`, condition, and immediate fields. The decoder recognizes direct and indirect `LC`, `LCR`, `FFC`, `LB`, branch conditions, common return forms, and loop instructions.

PC-relative branch offsets are word counts. For a two-word instruction, the decoder computes the target from `word_va + 2 + signed_offset`; absolute 22-bit calls and branches use their encoded word address.

`function_starts()` collects statically known direct call targets. It does not use prologue patterns and cannot recover targets that exist only in registers or tables.

## Limitations

- Instruction coverage is deliberately partial. Unimplemented operations decode as miscellaneous/unknown forms and must not be assigned invented semantics.
- A correct word-addressed `base_va` is essential; passing a byte address corrupts reported addresses and targets.
- Direct-call discovery is not complete function-boundary recovery.
- The decoder does not provide a CFG builder, taint tracker, or C-like lifter.
- TI COFF parsing and code-section extraction are separate prerequisites.

## Related workflows

- [Infineon C166 / C167 ROM Decoding](c166-c167-decoding.md)
- [Motorola M68K / CPU32 Decoding](ecu-m68k-decoder.md)
