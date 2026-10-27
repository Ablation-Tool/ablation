<a id="ecuc166decoder"></a>
# Infineon C166 / C167 ROM Decoding

`EcuC166Decoder` decodes a useful subset of Infineon/Siemens C166 and C167 instructions in pure Python. It parses interrupt-vector entries, discovers direct `CALLS` targets, classifies memory and control-flow operations, and scans selected XRAM references. It is a decoder and ROM-analysis aid, not a pseudo-C decompiler.

## Usage

```python
from ablation.analyzers.ecu_c166_decoder import EcuC166Decoder

decoder = EcuC166Decoder.from_path('/path/to/c167.bin', base_pa=0)
vectors = decoder.parse_ivt()
starts = decoder.function_starts()

for insn in decoder.disassemble(starts[0], starts[1]):
    if insn.is_call or insn.is_branch:
        print(insn)
```

Use `from_bytes(data, base_pa=...)` for an in-memory image. `base_pa` is the physical address associated with the first byte. `resolve_pa(seg, addr)` applies the decoder's C166 segment/address mapping.

`disassemble(start_pa, end_pa)` accepts physical-address bounds and returns decoded `C166Insn` objects. `decode_one(byte_off)` and `insn_length(byte_off)` instead operate on a buffer byte offset. Keep those address domains distinct.

## Interrupt vectors and function starts

`parse_ivt(num_vectors=64)` returns `IVTEntry` objects containing the vector index, entry physical address, segment, code address, and resolved target. `function_starts()` combines valid IVT targets with direct `CALLS` targets found while scanning the ROM.

IVT targets are strong architecture-specific seeds when the image has the expected layout. `CALLS` patterns in data can still create false candidates; direct scanning does not recover every indirect or uncalled function.

## Instruction coverage

The decoder distinguishes two- and four-byte encodings and handles common register/immediate moves, arithmetic, comparisons, multiplication, shifts, pushes/pops, returns, relative jumps, absolute `JMPS`/`CALLS`, and selected loads/stores. `C166Insn` exposes raw bytes, mnemonic, instruction type, register/immediate/target fields, and `is_branch`, `is_call`, `is_load`, and `is_store` properties.

Unknown operations remain explicit `UNKNOWN_2B` or related placeholder forms. `scan_xram_loads()` and `scan_xram_stores()` locate references to a selected XRAM address for focused review.

## Limitations

- The ISA decoder is partial; unknown instructions do not prove invalid code.
- The implementation does not reconstruct complete C166 CFGs, C functions, or taint paths.
- Physical addresses, byte offsets, segments, and XRAM addresses must not be mixed.
- IVT parsing assumes a compatible ROM layout; function-start candidates require code-region validation.
- Verify security-relevant decode results against the C167 reference manual and raw bytes.

## Related workflows

- [TI TMS320C28x Decoding](ecu-c28x-decoder.md)
- [Infineon TriCore Taint Analysis](tricore-taint-tracker.md)
