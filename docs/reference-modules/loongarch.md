<a id="loongarch64tainttracker"></a>
# LoongArch64 Decompilation & Taint Analysis

Decode LoongArch64 instructions, lift functions to structural pseudo-C, and trace taint with the LP64 ABI. Additional support covers Linux syscall labels, DWARF unwind metadata, and KASAN/KCOV instrumentation filtering.

## Structural lifting

```python
from ablation.analyzers.binary_lifter import BinaryLifter

lifter = BinaryLifter.from_path('/path/to/loongarch64.elf', arch='la64')
print(lifter.lift_function(0x10430))
```

`loongarch64`, `loongarch_64`, and `loongarch-64` are aliases for `la64`. The structural backend uses the native decoder and CFG model, names `$a0`–`$a7` arguments, resolves available direct calls, and emits branches and returns. Unmodeled arithmetic and memory behavior remain comments; it is not a full C decompiler.

## Binary-oriented taint analysis

```python
from ablation.analyzers.taint_tracker_loongarch64 import LoongArch64TaintTracker

tracker = LoongArch64TaintTracker.from_path('/path/to/loongarch64.elf')
findings = tracker.run()
paths = tracker.run_interprocedural(depth=4)
print(tracker.report(findings))
```

`run()` returns `TaintFindingLA64` objects. The tracker models common loads, stores, arithmetic, immediate operations, direct and indirect call forms, and source/sink calls under the LP64 ABI. Interprocedural traversal is depth-limited.

`from_path_full()` is a separate constructor used by workflows that require complete context loading; choose it only when that behavior is needed. For instruction-stream analysis, the same module also exposes a lower-level `TaintEngine` with labeled `Finding` results; those APIs and result types are not interchangeable.

## Instrumented kernels

[LoongArch64 KASAN/KCOV Filtering](loongarch64-v2.md) documents `LoongArchDecoderV2`, which tags and removes recognized sanitizer call/preamble sequences. It is a preprocessing decoder, not another ISA and not a standalone decompiler. A kernel `System.map` supplies instrumentation symbol addresses.

## Limitations

- Correct ELF mapping, instruction decoding, and function boundaries are prerequisites for meaningful results.
- Indirect calls, unresolved GOT entries, missing symbols, and unmodeled vector or privileged operations can interrupt analysis.
- Source-return taint is not automatically proof that an entire input buffer is tracked.
- Sanitizer filtering depends on known instrumentation addresses and recognized preamble idioms; unrecognized sequences remain in the stream.
- Treat findings and pseudocode as review aids. Verify source reachability, sanitization, sink arguments, and raw instructions.

## Related workflows

- [Native Binary Lifting](binary-lifter.md)
- [LoongArch64 KASAN/KCOV Filtering](loongarch64-v2.md)
- [KASAN Finding Validation](../workflows/kasan-oracle.md)
