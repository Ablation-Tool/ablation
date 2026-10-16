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

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Example output

```
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `finding_type` | Scanner-specific category label |
| `va` | Virtual address of the call site or instruction in the binary |
| `func_va` | Virtual address of the containing function |
| `detail` | What was found and the specific condition that triggered it |
| `sink_name` | Name of the dangerous function reached (if applicable) |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
