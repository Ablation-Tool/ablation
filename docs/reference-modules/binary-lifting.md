# Binary Lifting

Lift native binary instructions to annotated C pseudocode across 18 ISA variants, from typed register-tracking IR on ARM64/x86-64 to structural pseudocode on all other ablation-native decoder targets.

---

The full reference for this capability is in **[Binary Lifter](binary-lifter.md)**, which covers the complete `BinaryLifter` class API, all 18 ISA dispatch strings, the two completeness tiers (full vs structural), `NativeVal` dataclass, taint annotation integration, and output format by backend.

---

## Quick start

```python
from ablation.analyzers.binary_lifter import BinaryLifter

# ARM64 (full — register state machine + taint-ready)
lifter = BinaryLifter.from_path('/path/to/arm64.elf')
print(lifter.lift_function(0x12340))

# MIPS-32 (structural — calls resolved, arithmetic as comments)
lifter = BinaryLifter.from_path('/path/to/mips32.elf', arch='mips32')
print(lifter.lift_function(0x10430))

# Convenience one-liner
BinaryLifter.report('/path/to/binary', 0x12340, arch='ppc32')
```

## ISA → `arch=` string reference

| ISA | arch= |
|:---|:---|
| ARM64 | `arm64` (default) |
| x86-64 | `x86_64`, `amd64` |
| x86-32 | `x86_32`, `i386` |
| ARM32/Thumb | `arm32`, `thumb`, `thumb2` |
| MIPS-32 | `mips32`, `mips`, `mips32el` |
| MIPS-64 | `mips64`, `mips64el` |
| nanoMIPS | `nanomips` |
| PPC-32 | `ppc32`, `ppc`, `powerpc` |
| PPC-64 | `ppc64`, `powerpc64` |
| RISC-V 32/64 | `rv32`, `rv64`, `riscv32`, `riscv64` |
| LoongArch64 | `la64`, `loongarch64` |
| SH-2A | `sh2a`, `sh2` |
| ARC EM/HS | `arc`, `archs`, `arcem` |
| V850/RH850 | `v850`, `rh850`, `v850e2` |
| BEAM | `beam`, `erlang`, `elixir` |

---

## See also

- [Binary Lifter](binary-lifter.md) — full module reference: API, ISA table, output format, false positives
- [BinaryContext](binary-context.md) — session state; use `from_context()` to avoid re-parsing
- [TaintAnalysis](taint-analysis.md) — feed `TaintTracker` findings into `.with_taint()` for annotation
