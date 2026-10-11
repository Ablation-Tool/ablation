# ti-nnc-scanner

## Why this exists

3 things that weren't possible before in Ablation:

1. **No scanner could identify TI NNC inference artifacts in compiled firmware.** TVM's `tvmgen_*` naming convention — `tvmgen_default_run`, `tvmgen_default_inputs`, `tvmgen_default_outputs` — had no detection path. Ablation would see these as unnamed functions with two pointer arguments and no useful pattern match.

2. **No tool could surface the weak-symbol normalization override risk.** `tvmgen_default_bias_data`, `tvmgen_default_scale_data`, and `tvmgen_default_shift_data` are all declared `__attribute__((weak))` in the generated header. This is the documented behavior — it allows post-link parameter override — but it is also a supply-chain integrity surface that was invisible to any existing Ablation scanner.

3. **No scanner detected multi-model NPU contention patterns.** When multiple `tvmgen_*` modules target the hardware NPU accelerator, the NNC specification requires sequential execution with `tvmgen_X_finished` polling between calls. Missing this poll is a documented correctness hazard that static analysis can detect.

---

## What it does

`TiNNCScanner` parses firmware compiled by the TI Neural Network Compiler (NNC) v2.x and finds inference artifacts. The NNC is built on Apache TVM and compiles ONNX models into C libraries for TI MCU targets: F28P55x (C28x DSP), MSPM0 (Cortex-M0+), CC2745/AM13x (Cortex-M33), CC1352 (Cortex-M4), AM26x (Cortex-R5), and F29H85x (C29x).

Two binary formats are supported:
- **ARM ELF** (Cortex-M33/M4/R5/M0+, C29x): parsed via lief. Weak symbols detected via ELF `STB_WEAK` binding.
- **TI COFF2 / AR archive** (C28x F28P55x): parsed via `TiCoffLoader`. cl2000 emits COFF, not ELF. In TI COFF, `__attribute__((weak))` maps to storage class `C_UEXT = 19` (tentative external definition), which can be overridden by a `C_EXT` strong definition at link time.

The scanner operates entirely from symbol tables — no disassembly required for its primary findings.

**What it detects:**

- `tvmgen_*_run` entrypoints — the compiled model inference call
- Normalization parameter symbols (`bias_data`, `scale_data`, `shift_data` for NPU-QAT; `input_reciprocal_scale_data`, `input_zero_point_data` for CPU QDQ)
- Weak symbol binding on normalization arrays — override risk
- Hardware NPU mode vs software fallback (from `tvmgen_*_finished` volatile flag presence)
- Multi-model NPU contention when multiple modules target the hardware accelerator
- Skip-normalize compilation mode — caller must perform normalization manually

**Finding classes:**

| ID | Severity | Title |
|---|---|---|
| TINCC-001 | HIGH | Weak normalization symbol override risk |
| TINCC-002 | MEDIUM | NPU async completion flag — ordering hazard |
| TINCC-003 | MEDIUM | Multi-model NPU contention (sequential enforcement required) |
| TINCC-004 | INFO | Skip-normalize mode active — manual normalization required |

---

## Usage

```python
from ablation.analyzers.ti_nnc_scanner import TiNNCScanner

scanner = TiNNCScanner.from_path('/path/to/firmware.elf')
result = scanner.scan()

print(TiNNCScanner.report(result))

# Inspect modules
for mod in result.modules:
    print(mod.name, mod.execution_mode, mod.weak_norm_symbols)

# Inspect findings
for f in result.findings:
    print(f.severity, f.title, f.description)
```

---

## Normalization formula (NPU-QAT)

When `skip_normalize=true` is compiled in, the generated header documents:

```c
input_int = clip(((int32_t)((input_float + bias) * scale)) >> shift, min, max)
```

Where `bias`, `scale`, `shift` come from `tvmgen_default_bias_data[]`, `tvmgen_default_scale_data[]`, `tvmgen_default_shift_data[]`. All three arrays are `__attribute__((weak))`.

CPU QDQ format uses:

```c
input_int = clip(round(input_float * reciprocal_scale) + zero_point, min, max)
```

---

## Target ISA coverage

| Arch | NNC target flag | Scanner support |
|---|---|---|
| ARM Cortex-M33/M4/R5 | `--target-c-mcpu=cortex-m33/m4/r5` | Full (ELF) |
| ARM Cortex-M0+ (MSPM0) | `--target-c-mcpu=cortex-m0plus` | Full (ELF) |
| C29x (F29H85x) | `--target-c-mcpu=c29` | Full (ELF — c29clang emits ELF) |
| C28x (F28P55x) | `--target-c-mcpu=c28` | Full (TI COFF2/AR via TiCoffLoader; C_UEXT=weak) |

---

## Architecture note

The NNC is Apache TVM under the hood. `tvmc` is TVM's CLI frontend. The `tvmgen_<name>` naming convention, struct layout (`tvmgen_<name>_inputs`, `tvmgen_<name>_outputs`), and normalization symbol names are all deterministic from TVM's TI backend code generation. Multi-model compilation assigns one `mod_<name>.a` per model, each with its own `tvmgen_<name>.h` header. EdgeAI Studio calls Tiny ML ModelMaker which calls `tvmc` directly.
