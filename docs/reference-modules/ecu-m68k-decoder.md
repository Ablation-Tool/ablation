<a id="ecum68kdecoder"></a>
# Motorola M68K / CPU32 Decoding

`EcuM68kDecoder` disassembles Motorola 68000-family code with Capstone and discovers likely function entries in flat CPU32 ROMs. It wraps instructions in a common typed model for downstream ECU analysis. It does not emit pseudo-C.

## Why wrap Capstone instead of duplicating it?

The main missing pieces for ECU triage are a consistent instruction model and candidate function entries, not another general-purpose M68K disassembler. The wrapper retains Capstone's decoding while adding prologue recognition, direct-target extraction, and typed control-flow classifications used by later analysis.

That division keeps the component small and replaceable: Capstone handles the base ISA, while ECU-specific heuristics can evolve without forking it. Users gain a practical way to locate calls and likely routines in a flat ROM before choosing deeper manual analysis. The function-start patterns are evidence, not boundary proofs, and the 68020 profile does not establish complete CPU32 semantics. A future lifter could consume the typed objects, but no such integration is claimed here.

## Usage

```python
from ablation.analyzers.ecu_m68k_decoder import EcuM68kDecoder

decoder = EcuM68kDecoder.from_path('/path/to/cpu32.bin', base_va=0)
starts = decoder.function_starts()

for insn in decoder.disassemble(start=0xB00, end=0x2000):
    if insn.insn_type in {'CALL', 'RETURN', 'PROLOGUE'}:
        print(insn)
```

Use `EcuM68kDecoder.from_bytes(data, base_va=...)` for an in-memory ROM or `EcuM68kDecoder(data, base_va=...)` directly. `base_va` is the address associated with the first byte of the buffer and must match the target ROM mapping.

`decode_one()` decodes a single instruction, `disassemble()` yields a linear range, and `insn_length()` returns the current instruction length. Function-start scanning can run without Capstone; accurate disassembly and instruction lengths require it.

## Function discovery

`function_starts()` recognizes negative-displacement `LINK.W A6` prologues and `MOVEM.L` callee-save patterns at even offsets. A `MOVEM.L` immediately following a detected `LINK.W` is treated as part of the same prologue rather than another function.

These are compiler-pattern heuristics, not authoritative boundaries. Other prologues, `LINK.L`, indirect-only functions, and data resembling instructions can change coverage.

## Instruction model

`M68kInsn` contains `offset`, `mnemonic`, `op_str`, `insn_type`, `raw`, `size`, and optional `target`. Instruction types include `RETURN`, `BRANCH`, `CALL`, `PROLOGUE`, and `MISC`. Direct static branch/call targets are recovered when Capstone supplies a parseable absolute operand; indirect targets remain `None`.

The Capstone profile is M68K 68020. CPU32 belongs to the same family but has instructions and behavior not represented by that generic mode.

## Limitations

- No C-like lifter is attached to this decoder. Downstream analysis must consume `M68kInsn` objects.
- Without Capstone, the `insn_length()` fallback of two bytes is not safe for accurate sequential disassembly.
- Incorrect `base_va` values invalidate all reported addresses.
- CPU32-specific semantics and unsupported instructions require manual verification.
- Candidate function starts must be checked against known code regions before being used as analysis seeds.

## Related workflows

- [Motorola MC88100 COFF Disassembly](m88k-decoder.md)
- [PowerPC VLE Decoding](ecu-vle-decoder.md)
