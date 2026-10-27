<a id="riscvtainttracker"></a>
# RISC-V Decompilation & Taint Analysis

Lift RV32 and RV64 functions to structural pseudo-C, decode compressed instructions, and run either binary-oriented or labeled CFG dataflow analysis. HiSilicon's vendor-extended RV32 firmware uses a separate decoder adapter.

## Structural lifting

```python
from ablation.analyzers.binary_lifter import BinaryLifter

lifter = BinaryLifter.from_path('/path/to/riscv64.elf', arch='rv64')
print(lifter.lift_function(0x10430))
```

Use `arch='rv32'` for 32-bit input. The structural backend uses the RISC-V psABI `a0`–`a7` argument registers and handles common compressed `c.*` instructions through the native instruction model. It resolves calls and emits branches and returns; unmodeled semantics remain comments.

## Binary-oriented taint analysis

```python
from ablation.analyzers.taint_tracker_riscv64 import RISCV64TaintTracker

tracker = RISCV64TaintTracker.from_path('/path/to/riscv64.elf')
findings = tracker.run()
paths = tracker.run_interprocedural(depth=4)
print(tracker.report(findings))
```

For 32-bit input, use `RISCV32TaintTracker` from `ablation.analyzers.taint_tracker_riscv32`. Both trackers support `from_context(ctx)` and optional custom source/sink configuration through their constructors. The RV32 tracker also accepts `ext_decoder=` for a Capstone-compatible vendor extension decoder.

## Labeled instruction-stream analysis

```python
from ablation.analyzers.insn_riscv import from_listing
from ablation.analyzers.isa_riscv import Width
from ablation.analyzers.taint_tracker_riscv import TaintEngine

engine = TaintEngine(Width.RV64)
engine.taint_register('a0', 'user-input')
findings = engine.run(from_listing(objdump_text))
```

This API analyzes an instruction iterable rather than opening an ELF itself. The labeled model records provenance and can retain immediate-mask bounds. `ablation.analyzers.analysis_riscv.analyze_cfg()` provides the CFG fixpoint route when basic-block joins are required. It is a separate API from the binary-path trackers and has different result types and configuration.

## Vendor extensions

[HiSilicon RV32 Extension Decoding](hisi-rv32-ext.md) documents the adapter for HiSilicon `riscv31`/HCC instructions. Standard RISC-V and HiSilicon extended streams should not be assumed to decode identically in stock Capstone.

## Limitations

- Structural lifting is not full C recovery; the dedicated `lift_function_ir()` backend is not a RISC-V backend.
- Compressed instructions require correct 16-/32-bit boundary handling. Vendor instructions can misalign a stock decoder.
- Return-value taint does not automatically prove receive-buffer taint. Check memory propagation and argument positions.
- Missing imports, indirect calls, incomplete function boundaries, and interprocedural depth limits reduce coverage.
- A mask bound is an analysis fact, not a safety proof. Validate candidate paths and sink conditions manually.

## Related workflows

- [Native Binary Lifting](binary-lifter.md)
- [HiSilicon RV32 Extension Decoding](hisi-rv32-ext.md)
