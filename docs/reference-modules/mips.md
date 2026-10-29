<a id="mips32tainttracker"></a>
# MIPS Decompilation & Taint Analysis

Lift MIPS32 and MIPS64 functions to structural pseudo-C with `BinaryLifter`, or trace network- and file-derived values to dangerous calls with the architecture-specific taint trackers. Big- and little-endian ELF inputs are supported by separate `arch=` tokens and tracker options.

## Why architecture selection matters

“MIPS” describes a family, not one byte encoding or calling convention. A 32-bit big-endian router image and a 64-bit little-endian userspace binary need different instruction decoding, register widths, and argument models. Selecting the wrong one can produce plausible-looking output from incorrect premises.

The lifter and trackers therefore expose those choices rather than hiding them. Structural lifting helps a reader navigate a function; the trackers model source-to-sink propagation under a selected ABI. This gives users reusable MIPS analysis paths while keeping width and endianness assumptions visible. Each backend can evolve independently as new instruction forms or relocation layouts are observed, but support for one MIPS variant is not evidence for all variants.

## Structural lifting

```python
from ablation.analyzers.binary_lifter import BinaryLifter

lifter = BinaryLifter.from_path('/path/to/mipsel.elf', arch='mips32el')
print(lifter.lift_function(0x400A00))
```

| Architecture | `arch=` values | ABI model |
|---|---|---|
| MIPS32 big-endian | `mips32`, `mips`, `mips-32`, `mipsbe` | o32 argument registers `$a0`–`$a3` |
| MIPS32 little-endian | `mips32el`, `mipsel`, `mips-32-el` | o32 argument registers `$a0`–`$a3` |
| MIPS64 big-endian | `mips64`, `mips-64`, `mipsn64` | n64 argument registers `$a0`–`$a7` |
| MIPS64 little-endian | `mips64el` | n64 argument registers `$a0`–`$a7` |
| nanoMIPS | `nanomips` | Dedicated variable-width decoder and structural backend |

The structural output resolves direct calls when symbols are available, emits branches and returns, and leaves unmodeled arithmetic as comments. It does not recover original C types or expressions. See [nanoMIPS Decoding & Taint Analysis](nanomips.md) for nanoMIPS-specific limitations.

## MIPS32 taint analysis

```python
from ablation.analyzers.taint_tracker_mips import MIPS32TaintTracker

tracker = MIPS32TaintTracker.from_path('/path/to/mips32.elf', endian='big')
findings = tracker.run()
paths = tracker.run_interprocedural(depth=4)
print(tracker.report(findings))
```

`endian` defaults to `little`; set it explicitly for big-endian firmware. The tracker uses the o32 ABI and models common MIPS register transfers, arithmetic, memory operations, calls, and delay-slot behavior. `run()` returns `MIPSTaintFinding` objects; `run_interprocedural()` returns `MIPSInterproceduralPath` objects.

## MIPS64 taint analysis

```python
from ablation.analyzers.taint_tracker_mips64 import MIPS64TaintTracker

tracker = MIPS64TaintTracker.from_path('/path/to/mips64.elf', endian='little')
findings = tracker.run()
paths = tracker.run_interprocedural(depth=4)
```

The MIPS64 tracker uses 64-bit register semantics and the n64 calling convention. `from_context(ctx, endian=...)` is also available for the MIPS64 tracker.

## Interpretation and limitations

- A source such as `read` or `recv` commonly returns a byte count. Register taint on that return value is not equivalent to taint on the entire destination buffer; verify buffer propagation separately.
- PLT/GOT resolution and function-start recovery determine which calls can be analyzed. Stripped or statically linked binaries may need target-specific names and boundaries.
- Indirect calls, unmodeled memory aliases, vendor wrappers, and depth limits can cause missed paths.
- Delay slots matter for classic MIPS, but MIPS Release 6 and nanoMIPS have different control-flow rules. Do not treat every MIPS-compatible ELF as the same instruction set.
- Findings are candidates for manual review, not confirmation of exploitability.

## Related workflows

- [Native Binary Lifting](binary-lifter.md)
- [nanoMIPS Decoding & Taint Analysis](nanomips.md)
- [MIPS Sink Argument Classification](sink-arg-classifier-mips.md)
