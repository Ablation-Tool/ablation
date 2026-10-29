<a id="hisiliconrv32extdecoder"></a>
# HiSilicon RV32 Extension Decoding

`HiSiliconRV32ExtDecoder` wraps Capstone for HiSilicon `riscv31`/HCC RV32 firmware and intercepts vendor instructions whose lengths or semantics stock Capstone does not model. Its primary purpose is to keep subsequent instruction boundaries correct and expose conservative register-taint metadata.

## Why an adapter is safer than a patchwork scan

One incorrectly sized vendor instruction shifts every following instruction boundary. A string or call scan can then miss the real handler or manufacture a false one. The adapter isolates vendor-specific decoding while delegating standard instructions to Capstone, so extension support does not require rewriting the base ISA implementation.

Known instruction lengths restore synchronization; explicit dependency metadata supplies conservative taint facts where semantics are incomplete. This gives users a practical bridge into existing RV32 analysis while keeping uncertainty visible. It is intentionally a small compatibility component: new observed opcodes can extend it, and a future upstream Capstone implementation could replace it without changing the tracker's public input model. Raw-byte verification remains necessary for security claims.

## Supported extension families

The decoder handles custom multi-register load/store, shift-fused arithmetic, branch-immediate, multiply-add, 48-bit `l.li`, selected 16-bit zero-extension operations, and custom-3 R-type encodings. The six-byte `l.li` instruction is especially important: treating it as a four-byte instruction misaligns the following stream.

This is a vendor-extension adapter, not a separate decompiler. Standard instructions are forwarded to Capstone's RV32 compressed-enabled disassembler. Unknown custom semantics are represented explicitly rather than treated as ordinary standard instructions.

## Disassembly

```python
from ablation.analyzers.hisi_rv32_ext import HiSiliconRV32ExtDecoder

decoder = HiSiliconRV32ExtDecoder(conservative=True)
for address, size, mnemonic, operands in decoder.disasm_lite(code, 0x10000):
    print(f'{address:#x}: {mnemonic} {operands}  # {size} bytes')

print(decoder.opcode_report(code, 0x10000))
```

`disasm_lite(code, base_va)` follows Capstone's `(address, size, mnemonic, op_str)` tuple contract. Custom results are `HisiInsn` objects internally; their `taint_sources` and `taint_dest` properties describe the register dependency model used by consumers.

Set `conservative=True` when unknown custom-3 instructions should propagate both source registers to the destination. This reduces missed taint at the cost of precision. `opcode_report()` summarizes recognized custom opcodes and is useful for checking whether the target actually needs this adapter.

## Use with RV32 taint analysis

```python
from ablation.analyzers.hisi_rv32_ext import HiSiliconRV32ExtDecoder
from ablation.analyzers.taint_tracker_riscv32 import RISCV32TaintTracker

extension_decoder = HiSiliconRV32ExtDecoder(conservative=True)
tracker = RISCV32TaintTracker.from_path(
    '/path/to/hisilicon.elf', ext_decoder=extension_decoder
)
findings = tracker.run()
```

The tracker accepts the adapter through `ext_decoder=`. Without it, stock Capstone can lose synchronization after a vendor instruction. `RISCV32TaintTracker.from_context(ctx, ext_decoder=...)` is also supported.

## Requirements and limitations

- Capstone is required for forwarded standard instructions; the custom decoder alone is not a complete RV32 disassembler.
- This profile targets HiSilicon RV32 extensions. Do not apply it to ARM, x86, RV64, or unrelated vendor extensions.
- Custom-3 conservative dependencies are over-approximations, not recovered semantics.
- Extension decoding preserves boundaries and dependencies; it does not create full RISC-V IR or pseudo-C by itself.
- Verify security-relevant decoded instructions against target documentation and raw bytes.

## Related workflows

- [RISC-V Decompilation & Taint Analysis](risc-v.md)
- [Native Binary Lifting](binary-lifter.md)
