<a id="binarylifter"></a>
# ARM & ARC Binary Lifting

`BinaryLifter` provides one interface for native pseudo-C lifting. ARM64 and x86-64 have the richest register-tracking backends; ARM32, Thumb, ARC, and the other native backends produce structural pseudocode that preserves calls, branches, returns, and unmodeled instructions as comments.

## Why one lifter has different backends

An analyst should not need a new top-level workflow for every instruction set. `BinaryLifter` supplies a common entry point while making the depth of each backend explicit. Full register tracking and structural presentation answer different questions: the first models selected values, while the second primarily organizes disassembly into readable control flow.

The approach works because ELF/PE address mapping and many calling conventions can be shared even when instruction semantics differ. It does not make unsupported semantics interchangeable. The value is a stable navigation layer in which a backend can be added, deepened, or replaced without rewriting every consumer. Start with structural output for orientation, then use an architecture-specific analyzer when a security claim depends on exact data flow.

## Usage

```python
from ablation.analyzers.binary_lifter import BinaryLifter

lifter = BinaryLifter.from_path('/path/to/firmware.elf', arch='arm32')
print(lifter.lift_function(0x00010400, max_insns=512))
```

Use `BinaryLifter.from_context(ctx, arch='arm32')` to reuse PLT and function-name information from a `BinaryContext`. `BinaryLifter.report(path, va, arch='arm32')` prints one function. The default architecture is `arm64`; always select the target explicitly.

<a id="arm-binary-lifting"></a>
## ARM Binary Lifting

| Input | `arch=` values | Behavior |
|---|---|---|
| ARM64 / AArch64 | `arm64` | CFG-based lifting with typed native values, register tracking, and optional taint annotations |
| ARM32 / A32 | `arm32`, `arm`, `arm-32` | Structural CFG walking with AAPCS `r0`–`r3` argument names |
| Thumb / Thumb-2 | `thumb`, `thumb2`, `arm-thumb` | ARM32 structural backend in Thumb mode |

For ARM64, `with_taint(findings)` copies the lifter and annotates registers referenced by compatible ARM64 taint findings. `lift_function_ir()` provides the IR-backed route only for Alpha and x86-64; ARM64 uses `lift_function()`.

<a id="arc-binary-lifting"></a>
## ARC Binary Lifting

ARC EM and ARC HS use the structural ARC backend. Select `arc`, `arcem`, `archs`, or `arc-32`.

```python
lifter = BinaryLifter.from_path('/path/to/arc.elf', arch='arc')
print(lifter.lift_function(0x1000))
```

This backend invokes `arc-elf32-objdump`; install a GNU ARC cross-toolchain and ensure that executable is on `PATH`. The lifter parses its listing and emits structural pseudo-C. It does not provide a native ARC instruction decoder or full semantic IR.

## Other supported backends

| Family | `arch=` examples | Output / requirement |
|---|---|---|
| x86 | `x86_64`, `x86_32` | x86-64 register tracking; x86-32 structural output |
| MIPS | `mips32`, `mips32el`, `mips64`, `mips64el`, `nanomips` | Structural output with endian- and ABI-specific register names |
| PowerPC | `ppc32`, `ppc64` | Structural output |
| RISC-V | `rv32`, `rv64` | Structural output |
| LoongArch | `la64`, `loongarch64` | Structural output |
| Renesas SH-2A | `sh2a` | Flat-ROM-capable structural output |
| V850 / RH850 | `v850`, `rh850` | Structural output; requires `v850-elf-objdump` |
| BEAM | `beam`, `erlang`, `elixir` | Module-level summary at `va=0`, not native-function pseudo-C |

An unsupported architecture token returns `// unsupported arch: ...` rather than raising an exception.

## Interpreting structural output

Structural backends are not full source decompilers. They resolve direct calls when names are available, label arguments according to the target ABI, preserve branch structure, and emit returns. Unmodeled arithmetic or memory semantics remain comments. Indirect calls, missing symbols, incorrect load addresses, and wrong architecture selection reduce output quality.

For ELF and PE files, function arguments are virtual addresses translated through the parsed section map. The SH-2A backend additionally supports flat ROM images whose virtual addresses equal file offsets.

## Related workflows

- [x86 Decompilation & Taint Analysis](x86.md)
- [MIPS Decompilation & Taint Analysis](mips.md)
- [RISC-V Decompilation & Taint Analysis](risc-v.md)
- [Renesas SH-2A Flat-ROM Lifting](binary-lifter-sh2a.md)
- [Erlang BEAM Analysis & Lifting](beam.md)
