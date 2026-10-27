<a id="m88kdecoder"></a>
# Motorola MC88100 COFF Disassembly

Parse Motorola 88000 BCS COFF executables and disassemble MC88100 instructions in pure Python. The stack consists of `ablation.core.coff_m88k_parser` for the container and `ablation.analyzers.insn_m88k.M88kDecoder` for instructions, candidate function starts, and data-reference recovery.

This capability is for MC88100, not M68K/CPU32. It currently provides disassembly, not `BinaryLifter` pseudo-C integration.

## Usage

```python
from ablation.core.coff_m88k_parser import parse
from ablation.analyzers.insn_m88k import M88kDecoder

binary = parse('/path/to/mc88100.coff')
decoder = M88kDecoder(binary)

for insn in decoder.disassemble_va(binary.entry, max_insns=40):
    print(insn)

print([hex(va) for va in sorted(decoder.function_starts())])
for code_va, data_va in sorted(decoder.string_refs().items()):
    print(f'{code_va:#x} -> {data_va:#x}')
```

Use `disassemble_bytes(data, base_va=...)` to decode a byte buffer directly. `disassemble_va()` reads through the parsed COFF section mapping.

## Container and instruction coverage

The parser handles the 88K BCS COFF layout, including its 44-byte section headers, sections, symbols, and entry metadata. The expected COFF magic is `0x016d`.

The decoder handles common immediate, load/store, branch, conditional branch, jump/call, and control-register instruction classes. `function_starts()` collects direct BSR/BSR.N targets. `string_refs()` recognizes `OR.U`/`OR` constant-construction pairs that resolve into data sections.

Triadic integer operations are only partially decoded: some emit placeholder mnemonics because their function-code field is not fully interpreted. Unknown words remain visible as unknown instructions rather than disappearing.

## Limitations

- This is not a complete MC88100 instruction-set implementation and not a decompiler.
- Direct-call targets provide candidate entries, not complete function boundaries. Indirect calls and static functions without callers can be missed.
- Data references are not automatically string uses or taint sources; inspect the referenced bytes and surrounding code.
- Placeholder triadic instructions must not be treated as recovered arithmetic semantics.
- There is no generic `BinaryLifter` `arch='m88k'` backend; use `M88kDecoder` directly.

## Related workflows

- [Motorola M68K / CPU32 Decoding](ecu-m68k-decoder.md)
- [Native Binary Lifting](binary-lifter.md)
