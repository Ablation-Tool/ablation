<a id="m88kdecoder"></a>
# Motorola MC88100 COFF and ELF Analysis

`ablation.m88k` parses Motorola 88000 BCS COFF and big-endian DG/UX ELF executables and decodes MC88100 instructions using only the Python standard library. The implementation uses ordered opcode masks and typed operand fields rather than filename patterns or partial mnemonic guesses.

## Why the container and decoder are separate

BCS COFF and DG/UX ELF use different section and dynamic-linkage layouts. `ablation.core.coff_m88k_parser` handles the COFF container, including its 44-byte section headers. `ablation.core.elf_m88k_parser` handles ELF32 big-endian sections, dynamic symbols, and DG/UX `.rela.gotp` imports. `M88kDecoder` then consumes the shared section model without conflating the two formats.

DG/UX `.rela.gotp` entries carry 12-byte `r_offset`, `r_info`, and `r_addend` fields. For observed import stubs, `r_addend - 0xC` is the PLT stub VA. The parser validates that each computed stub lies in `.plt`; unrelated or malformed entries are not assigned names.

## Usage

```bash
python3 -m ablation.m88k info INPUT
python3 -m ablation.m88k disassemble INPUT 0xSTART --maximum 40 --json
python3 -m ablation.m88k calls INPUT --json
python3 -m ablation.m88k functions INPUT --json
```

```python
from ablation.core.elf_m88k_parser import parse
from ablation.analyzers.insn_m88k import M88kDecoder

binary = parse('/path/to/mc88100.elf')
decoder = M88kDecoder(binary)
for insn in decoder.disassemble_va(binary.entry, max_insns=40):
    print(insn)
```

Use `ablation.core.coff_m88k_parser.parse` for BCS COFF. `function_starts()` collects direct BSR/BSR.N targets, and `string_refs()` recognizes `OR.U`/`OR` constant-construction pairs resolving into `.data`. `BinaryContext.load_or_build(path)` detects both M88K formats.

## Instruction and call semantics

All instructions are 32-bit big-endian words. The decoder covers immediate, indexed and scaled load/store, arithmetic, logical, floating-point, control-register, branch, conditional branch, jump, and subroutine classes. Unknown encodings remain `word` entries.

PC-relative operands use `target = pc + 4 * sign_extend(displacement)`. The earlier `pc + 4 + 4 * displacement` model was incorrect and is not used. BSR/BSR.N and JSR/JSR.N are calls; `jmp r1` is a return. Direct BSR targets are candidates, not complete function-boundary proof.

## Validated evidence

Both real samples decode completely:

- DG/UX `dg_gen`: 2,468 `.text` instructions with zero unknown encodings, 21 sections, and 15 imports.
- BCS COFF `moto_gen`: 10,000 `.text` instructions with zero unknown encodings, 126 direct-call function candidates, and 73 data references.

For `dg_gen`, function `0x102c30` subtracts `0x170` from `r31` and sets `r30 = r31 + 0x30`. It calls `gets(r30+0xD0)` at `0x102f28`; the next local is at `r30+0x110`, giving a 64-byte region (`0x110 - 0xD0`). This confirms an unbounded local stack write. No privilege boundary or remote reachability is established. The `system` call at `0x102f10` uses the fixed string `cat readme.txt`, so that site is not command injection.

## Limitations

- This is not a complete MC88100 emulator or decompiler.
- Indirect calls and static functions without direct callers can be missed.
- Data references are not automatically string uses or taint sources; inspect surrounding code and input provenance.
- DG/UX PLT recovery currently uses the observed `.rela.gotp` stub-plus-`0xC` convention. Other relocation layouts remain unsupported rather than being guessed.
- Generic ELF-only pseudo-C and semantic analyzers are not implied to support M88K.
