# ARM64 Call Argument Annotation

`ARM64RegAnnotator` resolves arguments passed to `BL` and `BLR` calls in stripped AArch64 ELF binaries. It supplies the native backend used by `FuncProfiler` for ARM64 targets instead of the x86-64 annotator.

## Why this exists

AArch64 passes the first eight integer arguments in `x0`–`x7` and uses `BL` for direct calls and `BLR` for indirect calls. The generic `RegAnnotator` models x86-64 registers and instructions, so it cannot recover these call arguments. `ARM64RegAnnotator` returns the same `AnnotationResult`, `CallSite`, and `RegVal` types as the other architecture backends, preserving the existing profiling API.

## Usage

```python
from ablation.analyzers import BinaryContext, FuncProfiler

ctx = BinaryContext.load_or_build('/path/to/arm64-binary')
profile = FuncProfiler.from_context(ctx).profile(0x5fc0, end_va=0x6014)
print(profile.fmt())
```

Use the annotator directly when call traces are needed without sink classification:

```python
from ablation.analyzers import ARM64RegAnnotator

annotator = ARM64RegAnnotator.from_context(ctx)
result = annotator.annotate_calls(0x5fc0, 0x6014)
for call in result.calls:
    print(call.fmt(arg_regs=[f'x{i}' for i in range(8)]))
```

## Calling convention and propagation

- `x0`–`x7`: entry arguments; `x0` also holds a call's return value.
- `x0`–`x18`: invalidated after a call, except for the `x0` return marker.
- `x19`–`x28`: preserved across calls.
- `wN`: normalized to the corresponding `xN` state; `wzr` and `xzr` produce zero.
- Direct `BL` targets and constant-target `BLR` calls: named through `BinaryContext.plt`.
- Unresolved `BLR` calls: recorded explicitly as `blr xN` with target VA zero rather than omitted.

The linear pass tracks entry arguments, register copies, immediate values, `MOVZ`/`MOVN`/`MOVK`, `ADRP`+`ADD` string addresses, common arithmetic, byte reversal, and simple load/store provenance. It emits the shared value kinds `arg`, `const`, `string`, `copy`, `ret`, `zero`, `mem`, and `unknown`.

## Limitations and analysis handoff

The pass is intentionally bounded and linear. It does not explore alternate branches, prove loop invariants, or perform interprocedural pointer analysis. Complex memory expressions and unresolved writes produce `unknown`; treat those arguments as candidates for deeper analysis rather than proof of safety. Use `CFGBuilder` for branch and loop structure and `ARM64TaintTracker` for interprocedural source-to-sink feasibility. Unresolved indirect targets require vtable or dataflow analysis.

`from_path()` builds a `BinaryContext` automatically. Prefer `from_context(ctx)` when a context already exists so ELF parsing and PLT resolution are reused.

## Verification

`tests/test_arm64_reg_annotator.py` covers direct and indirect calls, PLT naming, argument propagation through preserved registers, caller-saved invalidation, `ADRP`+`ADD` string recovery, wide immediates, byte reversal, memory provenance, and end-to-end `FuncProfiler` integration. The tests use synthetic instruction bytes and do not require external firmware fixtures.
