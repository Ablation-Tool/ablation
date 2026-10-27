<a id="tricoretainttracker"></a>
# Infineon TriCore Taint Analysis

`TriCoreTaintTracker` analyzes Infineon TriCore TC1.6x functions with Capstone, EABI-aware register state, and explicit handling for calls, returns, loads, stores, arithmetic, and indirect targets. It is a taint-analysis capability; there is no TriCore `BinaryLifter` pseudo-C backend.

## Analyze a flat ROM function

```python
from pathlib import Path
from ablation.analyzers.taint_tracker_tricore import TriCoreTaintTracker

rom = Path('/path/to/tricore.bin').read_bytes()
tracker = TriCoreTaintTracker.from_bytes(rom, base_va=0x80000000)
findings = tracker.scan_function(
    func_va=0x800ABA10,
    func_end=0x800ABB80,
    init_labels={'can_frame'},
    func_name='can_rx_handler',
)
print(tracker.report(findings))
```

Flat-ROM callers must provide accurate `base_va`, `func_va`, and `func_end` values. `init_labels` seeds the TriCore argument registers for the analysis; it does not establish that the source is attacker-controlled.

## Analyze ELF functions

```python
tracker = TriCoreTaintTracker.from_path('/path/to/tricore.elf')
findings = tracker.run()
paths = tracker.run_interprocedural(depth=3)
print(tracker.report(findings))
```

ELF loading uses LIEF or pyelftools. `run()` derives function boundaries from available symbols and text limits. `run_interprocedural()` returns `TaintFindingTriCore` objects as well, not a separate path dataclass.

`tc_mode=0` selects the implementation's default `CS_MODE_TRICORE_162` mode. Capstone with TriCore support is required.

## ABI and output

The model uses `D[4]`–`D[7]` and `A[4]`–`A[7]` for arguments, with `D[2]` and `A[2]` as return registers. It distinguishes caller-saved lower context from callee-saved upper context and recognizes `CALL`/`FCALL` and `RET`/`FRET` families. A hardware Context Save Area is not equivalent to an ordinary software push/pop sequence.

Findings include function and sink addresses, sink name, tainted arguments, labels, and severity. Tainted stores or indirect targets may be reported as candidates in addition to named library sinks.

## Limitations

- No TriCore pseudo-C decompiler is implemented in `BinaryLifter`.
- `scan_function()` is intraprocedural and requires explicit boundaries. `run()` depends on symbol coverage.
- The tracker is not a loop-fixpoint engine, and return-value aliasing across call chains is limited.
- CSA memory-dump operations, indirect targets, memory aliases, and unknown instructions can reduce precision.
- Conservative unknown-instruction propagation can over-taint; verify candidate paths against raw instructions and the actual calling convention.

## Related workflows

- [Infineon C166 / C167 ROM Decoding](c166-c167-decoding.md)
- [Renesas V850 / RH850 Lifting & Taint Analysis](v850-rh850.md)
