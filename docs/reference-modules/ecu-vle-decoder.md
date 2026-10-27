<a id="ecuvledecoder"></a>
# PowerPC VLE Decoding

`EcuVLEDecoder` decodes NXP PowerPC Variable Length Encoding (VLE) instructions from raw automotive ROM images. It handles a defined set of 16-bit SE and 32-bit VLE encodings, classifies control flow, and proposes function starts from common prologues. It is a decoder and function-discovery aid, not a pseudo-C decompiler.

## Usage

```python
from ablation.analyzers.ecu_vle_decoder import EcuVLEDecoder

decoder = EcuVLEDecoder.from_path('/path/to/ecu.bin', base_va=0)
instructions = decoder.disassemble(start=0x2A000, end=0x2B000)
for insn in instructions:
    if insn.insn_type in {'CALL', 'BRANCH'}:
        print(insn)

starts = decoder.function_starts()
print([hex(va) for va in starts[:20]])
```

Construct directly with `EcuVLEDecoder(data, base_va=...)` when the bytes are already available. `base_va` is the virtual address of the first byte in the buffer. Decoded instruction offsets and statically resolved targets are expressed in that address space.

`decode_one(offset=...)` decodes one instruction at a buffer offset. `disassemble(start=..., end=...)` walks a byte range linearly. `function_starts()` scans for `e_stwu r1, -N(r1)` frame allocations and eligible `se_mflr` leaf-function patterns, suppressing the latter when it is part of an already detected prologue.

## Instruction model

Decoded objects expose the instruction VA, raw bytes, mnemonic, operands, instruction type, size, and optional static target. Types include `CALL`, `BRANCH`, `RETURN`, `LOAD`, `STORE`, `LR_SAVE`, `LR_RESTORE`, and `MISC`.

The implementation distinguishes 16- and 32-bit instructions using the VLE encoding rule, then decodes common moves, loads/stores, arithmetic, branches, calls, returns, and stack-frame operations. Unknown encodings are preserved as `se_unknown_*` or `vle32_op*` instructions rather than silently discarded.

Standard fixed-width PowerPC Book E and VLE can coexist in one ROM. Select the correct decoder for each known code region; a heuristic probe alone does not prove that an entire region uses one encoding.

## Limitations

- Instruction coverage is partial. Unknown instructions and unresolved indirect targets require manual review.
- `function_starts()` returns candidates, not authoritative boundaries. Data that resembles a prologue can create false starts, and leaf functions with other prologues can be missed.
- `base_va` must match the ROM mapping or every reported address and static target will be wrong.
- The decoder does not itself perform taint analysis or produce pseudo-C. Downstream consumers must understand VLE instructions; a Book-E-only tracker cannot be assumed to analyze VLE correctly.

## Related workflows

- [PowerPC Decompilation & Taint Analysis](ppc32-taint-tracker.md)
- [Motorola M68K / CPU32 Decoding](ecu-m68k-decoder.md)
