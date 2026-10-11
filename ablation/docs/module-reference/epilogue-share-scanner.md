# EpilogueShareScanner

## Why this exists

2 things that weren't possible before in Ablation:

1. **Phantom interprocedural taint paths on compiler-optimized TriCore firmware.** When a compiler merges the epilogue of several functions into one shared block and uses an unconditional jump to reach it, `run_interprocedural()` sees the shared block's address in `ctx.func_starts` and treats it as an independent function. The taint engine then follows a path that never exists at runtime, producing findings that byte-verify as false positives. Before this module there was no way to identify or exclude those phantom entry points.

2. **Automated function boundary classification for TriCore flat ROMs.** The taint trackers compute `func_end = next_func_start`, which means a shared epilogue block is indistinguishable from a real function. `EpilogueShareScanner` identifies which `func_starts` entries are landing pads for unconditional jumps rather than true function entries, so the interprocedural loop can skip them.

## What it does

Scans every function in a TriCore binary for unconditional jump instructions: `j`, `ja`, `jl`, and `jla`. For each jump, it checks whether the target VA lands strictly inside another function's address range. If it does, that target is a shared epilogue block.

After calling `inject(ctx)`, the set `ctx.shared_epilogues` contains all discovered target VAs and `ctx.name(va)` returns `shared_ep_<hex>` for each one. Any `run_interprocedural()` call can then skip entries in `ctx.shared_epilogues` to avoid following those phantom paths.

## Usage

```python
from ablation.analyzers.epilogue_share_scanner import EpilogueShareScanner

# From a BinaryContext. reads ctx.func_starts
scanner = EpilogueShareScanner.from_context(ctx)
hits = scanner.scan()
print(EpilogueShareScanner.report(hits))
scanner.inject(ctx)

# From a flat ROM blob
scanner = EpilogueShareScanner.from_bytes(
    data, base_va=0x80000000, func_starts=starts
)
hits = scanner.scan()

# After inject(), ctx.shared_epilogues is a set of VAs to skip
scanner.inject(ctx)
shared = ctx.shared_epilogues
for func_va in ctx.func_starts:
    if func_va in shared:
        continue
    # ... run engine on func_va
```

## Confirmed targets

- Bosch ME17 and Continental MG1 flat ROMs: TriCore TC1.6x, GCC-compiled at `-O2`
- Any TriCore firmware where `EpilogueShareScanner.scan()` returns hits

## Known limitations

- TriCore only. This scanner checks for `j`, `ja`, `jl`, and `jla` instructions, which are TriCore-specific.
- Function boundaries come from `ctx.func_starts` using next-start as end, so the last function in the image uses a 512-byte default end. Jumps from that function to beyond its estimated end may be missed.
- Intra-function jumps that happen to land at an address also in `func_starts` are correctly excluded because the target must be strictly inside another function, not at its entry.
