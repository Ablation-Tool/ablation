# PPC64BECallScanner: brute-force BL call-site scanner for stripped PPC64 BE ELFv1

## Why this exists

Stripped PPC64 BE ELFv1 binaries have no symbol table. `callers_of()` returns an empty list because the call graph requires symbol-based function starts to build CFG edges. It also cannot resolve ELFv1 function descriptor indirection through the `.opd` section. The ROCm `libLLVMOffload.so` analysis in IBM-RE session 6 required a one-off brute-force BL word sweep. This module codifies that pattern.

Gap IDs: **IBM-LLVM-GAP-001**, **GPFS-CALLGRAPH-001**, **LOADL-CALLGRAPH-001**.

## Usage

```python
from ablation.analyzers.ppc64_be_call_scanner import PPC64BECallScanner

scanner = PPC64BECallScanner.from_path('/tmp/extract/usr/lib/libLLVMOffload.so')

# Find all callers of a specific PLT stub VA
callers = scanner.scan_calls_to(plt_va=0x9cbf0)
for va in callers:
    print(f"BL system() at 0x{va:x}")

# Find callers of all exec-class sinks at once
hits = scanner.scan_all_sinks()
for sink_name, call_vas in hits.items():
    for va in call_vas:
        print(f"BL {sink_name} at 0x{va:x}")
```

## How it works

The scanner reads every 4-byte-aligned word in `.text` and checks the PPC64 BL opcode mask.

A PPC64 BL instruction encodes as follows:

- Bits 0-5: opcode 18
- Bits 6-29: 24-bit signed branch offset divided by 4
- Bit 30: AA flag, 0 for relative addressing
- Bit 31: LK flag, 1 for branch-and-link

The mask is `0xFC000001` and the match is `0x48000001`. For each match, the scanner decodes the branch target as `insn_va + sign_extend(LI) * 4` and checks whether it equals the requested PLT stub VA.

## Pipeline position

**Before this module:** Identify the PLT stub VA for the target sink. Use `lief.parse(binary).pltgot_relocations` or `BinaryContext.plt` if symbols are available. For binaries with no symbol table, use `tiptoe` port scan output or RE session notes to find the PLT VA.

**After this module:** Pass the returned call-site VAs to `WindowAnalyzer.dump_caller_context()` to read the register state before each call. Then use `SinkArgClassifierPPC64` or manual disassembly to trace `r3`.

## Notes

`from_context(ctx)` accepts a BinaryContext and copies `ctx.plt` so the PLT table does not need to be rebuilt. Use `set_plt()` to register a PLT stub manually by name and VA when auto-detection is incomplete. This is common on stripped ELFv1 binaries where `pltgot_relocations` returns nothing.
