# EpilogueShareScanner

**File:** `ablation/analyzers/epilogue_share_scanner.py`

---

## Why this exists

Two things were not possible before in Ablation:

**1. Phantom interprocedural taint paths on compiler-optimized automotive ECU firmware.** When
a compiler merges the epilogue of several functions into one shared block and uses an
unconditional jump to reach it, `run_interprocedural()` sees the shared block's address in
`ctx.func_starts` and treats it as an independent function. The taint engine then follows a
path that does not exist at runtime, producing findings that byte-verify as false positives.
Before this module there was no way to identify or exclude those phantom entry points.

**2. Automated function boundary classification for flat ECU ROM images.** The taint trackers
compute `func_end = next_func_start`, which means a shared epilogue block is indistinguishable
from a real function. `EpilogueShareScanner` identifies which `func_starts` entries are landing
pads for unconditional jumps rather than true function entries, so the interprocedural loop can
skip them.

---

## What it does

Scans every function in the binary for unconditional jump instructions: `j`, `ja`, `jl`, and
`jla`. For each jump, it checks whether the target VA lands strictly inside another function's
address range. If it does, that target is a shared epilogue block.

After calling `inject(ctx)`, the set `ctx.shared_epilogues` contains all discovered target VAs
and `ctx.name(va)` returns `shared_ep_<hex>` for each one. Any `run_interprocedural()` call can
then skip entries in `ctx.shared_epilogues` to avoid following those phantom paths.

---

## Usage

```python
from ablation.analyzers.epilogue_share_scanner import EpilogueShareScanner

# From a BinaryContext: reads ctx.func_starts
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

---

## EpilogueShareHit fields

```python
@dataclass(frozen=True)
class EpilogueShareHit:
    from_func_va: int   # function that contains the jump
    jump_va: int        # VA of the jump instruction
    target_va: int      # VA the jump lands on
    host_func_va: int   # function whose body the target is inside
```

---

## Methods

| Method | Description |
|---|---|
| `from_context(ctx)` | Build from a BinaryContext; reads `ctx.binary_path` and `ctx.func_starts` |
| `from_bytes` | Build from a raw flat ROM blob; parameters: `data`, `base_va`, `func_starts` |
| `scan()` | Run the scan; returns `List[EpilogueShareHit]` |
| `inject(ctx)` | Add hit target VAs to `ctx.shared_epilogues`; name them `shared_ep_<hex>` via `ctx.set_name()`; returns count added |
| `report(hits)` | Static method; return a human-readable summary string |

---

## Interprocedural integration

`EpilogueShareScanner` runs before `TriCoreTaintTracker.run_interprocedural()`. The standard
integration:

```python
scanner = EpilogueShareScanner.from_context(ctx)
scanner.inject(ctx)

for func_va in ctx.func_starts:
    if func_va in ctx.shared_epilogues:
        continue
    chains = tracker.run_interprocedural(
        func_va=func_va,
        depth=3,
    )
```

The shared epilogue addresses are also named in BinaryContext, so any subsequent disassembly
or export step labels them as `shared_ep_<hex>` rather than `fn_<hex>`.

---

## Confirmed targets

Automotive flat ROM firmware, GCC-compiled at `-O2`. Any firmware where
`EpilogueShareScanner.scan()` returns hits.

---

## Limitations

- ISA-specific. The scanner searches for the unconditional jump mnemonics of the supported
 ISA: `j`, `ja`, `jl`, and `jla`. Other architectures are not currently supported.
- Function boundaries come from `ctx.func_starts` using next-start as end, so the last
 function in the image uses a 512-byte default end. Jumps from that function to beyond its
 estimated end may be missed.
- Intra-function jumps that happen to land at an address also in `func_starts` are correctly
 excluded because the target must be strictly inside another function, not at its entry point.

---

## How it works

`EpilogueShareScanner.from_context(ctx).scan()` iterates `ctx.func_starts` and disassembles each function with Capstone. For every unconditional jump `JMP` and `JMPF` on x86; `B` on ARM, it checks whether the target VA falls inside another known function's body: i.e., between that function's start VA and the next function's start VA. If so, it records an `EpilogueShareHit`. Tail-call sharing is the most common source: the compiler merges identical epilogue sequences across multiple functions.

---

## Example output

```
EpilogueShareHit  from_func=sub_0x00401200 (0x00401200)
  jump_va=0x00401248  target_va=0x004015c0
  host_func=handle_cleanup (0x004015a0)

EpilogueShareHit  from_func=parse_header (0x00402800)
  jump_va=0x00402870  target_va=0x004015c8
  host_func=handle_cleanup (0x004015a0)
```

---

## False positives

Jump tables in switch statements produce false hits if the jump target happens to fall inside another function's VA range. For `from_func` that contains a known switch, filter with `target_va` checks against `.rodata` jump table entries. Also: inlined functions where `ctx.func_starts` has two adjacent entries but the second is actually a continuation rather than a separate function.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` with `ctx.func_starts` populated. Used when function boundary analysis suggests incorrect splits overlapping or merged functions.

**After this module:** Use hits to merge `host_func_va` and `from_func_va` boundaries in `ctx` before running `TaintTracker`, or to confirm that tail-call-optimized wrappers share epilogue code with their callees.

---

## Reading output

`EpilogueShareScanner.from_context(ctx).scan()` returns `List[EpilogueShareHit]`:

| Attribute | Content |
|:---|:---|
| `from_func_va` | VA of the function that contains the unconditional jump |
| `jump_va` | VA of the jump instruction itself |
| `target_va` | VA the jump lands on |
| `host_func_va` | VA of the function whose body the target falls inside |

After scanning, all `target_va` values are added to `ctx.shared_epilogues` so that `run_interprocedural()` skips them as false function-start candidates.

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
