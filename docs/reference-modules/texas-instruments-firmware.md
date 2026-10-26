# TI Embedded ML Models

Texas Instruments MCU toolchains produce a binary format called COFF2 — not ELF. Standard tools (`lief`, `BinaryContext`) cannot read it, so TI firmware has historically been a blind spot. This capability closes that gap, and goes one step further: TI's neural-network compiler embeds ML inference models directly into firmware, and those models carry a weak-symbol supply-chain risk that is invisible without symbol-table analysis.

Three components work together:

| Component | What it does |
|:---|:---|
| `TiCoffLoader` | Reads TI COFF2 `.obj` files and `.a` archives that `lief` cannot parse |
| `TiNNCScanner` | Finds embedded ML models and flags weak-symbol normalization override risk |
| TINCC-001–004 | The finding classes that surface from the scanner |

---

## Why this exists

1. **TI Code Generation Tools produce COFF2, not ELF.** `cl2000` (C28x), `c29clang` (C29x), and `tiarmclang` all emit object files with magic `0x00C2`. `BinaryContext.load_or_build()` calls `lief` for ELF loading and returns empty on COFF2. Without `TiCoffLoader`, any TI C28x or C29x firmware returns `plt=0`, `funcs=0` — not because it is empty, but because the parser cannot see it.

2. **TI's NNC compiler (built on Apache TVM) bakes ML inference models into firmware.** A `tvmgen_default_run` symbol in the binary means a compiled neural network is running on the MCU. The model's quantization parameters — the scale, bias, and shift values that map float input to int8 — are exported as `__attribute__((weak))` symbols. Any object file linked after `mod.a` can silently override them without a warning or error. The model still runs; it just quantizes using attacker-supplied parameters.

3. **C28x targets use COFF2; ARM targets use ELF.** TI NNC supports both. `TiNNCScanner` handles both through a unified interface: ELF via `lief`, COFF2 via `TiCoffLoader`. The caller does not need to know which format the target uses.

---

## TiCoffLoader

Parses TI COFF2 object files (`.obj`) and AR archives (`.a`). Extracts the symbol table with storage class, section binding, and value for every symbol in every archive member.

**TI COFF storage classes** differ from ELF:

| Class | Value | Meaning |
|:---|:---|:---|
| `C_EXT` | 2 | Strong global (equivalent to ELF `STB_GLOBAL`) |
| `C_STAT` | 3 | Static local (`STB_LOCAL`) |
| `C_EXTREF` | 5 | Undefined external reference |
| `C_UEXT` | 19 | **Tentative external — TI's encoding of `__attribute__((weak))`** |

`C_UEXT` is the key: it is how TI COFF represents weak symbols. Any `C_UEXT` symbol can be overridden by a `C_EXT` definition provided later in the link order.

```python
from ablation.analyzers.ti_coff_loader import TiCoffLoader

loader = TiCoffLoader.from_path('/path/to/mod.a')
for sym in loader.symbols():
    if sym.is_weak:
        print(f'WEAK  {sym.name}  section={sym.section_number}')
    elif sym.is_global and sym.is_defined:
        print(f'GLOBAL {sym.name}  va={sym.value:#010x}')
```

---

## TiNNCScanner

Scans TI MCU firmware — ELF or COFF2 — for embedded ML inference artifacts compiled by TI's Neural Network Compiler. Detection is entirely symbol-table based: no disassembly required.

**Supported targets:** F28P55x (C28x), MSPM0 (Cortex-M0+), CC2745/AM13x (Cortex-M33), CC1352 (Cortex-M4), AM26x (Cortex-R5), F29H85x (C29x).

```python
from ablation.analyzers.ti_nnc_scanner import TiNNCScanner

scanner = TiNNCScanner.from_path('/path/to/firmware.elf')   # ARM ELF
# or
scanner = TiNNCScanner.from_path('/path/to/mod.a')          # C28x COFF AR

result = scanner.scan()
print(TiNNCScanner.report(result))
```

**What the scanner finds:**

For each detected model (`tvmgen_<name>_run` present), it records:

- `execution_mode` — `npu_hw` if `TI_NPU_init` or `tvmgen_<name>_finished` is present; `npu_soft` otherwise
- `norm_symbols` — all normalization parameter symbols (`bias_data`, `scale_data`, `shift_data`, `input_reciprocal_scale_data`, etc.)
- `weak_norm_symbols` — the subset with WEAK binding (ELF) or `C_UEXT` storage class (COFF2)

---

## Security findings

### TINCC-001 — HIGH: Weak normalization symbol override

The normalization symbols (`tvmgen_<name>_bias_data`, `scale_data`, `shift_data`) are declared `__attribute__((weak))` by the NNC. Any object file or shared library linked **after** `mod.a` that provides a strong symbol of the same name silently replaces the quantization boundary. No compiler warning, no linker error, no runtime indication.

In a safety-critical system — motor control, medical device, automotive ADAS — this is a targeted adversarial input at the build stage rather than the inference stage. The model runs and produces output; the output is numerically wrong in a controlled way.

Triggered when any `norm_symbol` has `binding == 'WEAK'` (ELF) or `storage_class == C_UEXT` (COFF2).

### TINCC-002 — MEDIUM: NPU async completion ordering hazard

`tvmgen_<name>_finished` is a `volatile int32_t` that the hardware NPU sets to 1 when inference completes. The NNC spec requires the application to poll this flag before reading output tensors or invoking a second model. Missing or reordered polls read stale tensors from the previous inference.

Triggered when `execution_mode == 'npu_hw'` and `has_finished_flag` is true.

### TINCC-003 — MEDIUM: Multi-model NPU contention

Two or more models both target the hardware NPU. The NNC specification prohibits concurrent NPU execution; calling `tvmgen_Y_run()` before `tvmgen_X_finished == 1` corrupts NPU microcode state and invalidates results from both models.

Triggered when more than one module has `execution_mode == 'npu_hw'`.

### TINCC-004 — INFO: Skip-normalize mode

Normalization symbols are present, meaning the model was compiled with `skip_normalize=true`. The caller must manually quantize input to int8 before calling `run()`. Passing raw float input produces out-of-range integers and incorrect inference.

---

## Pipeline position

Run `TiNNCScanner` during initial triage on any TI MCU firmware. ML inference presence changes the attack surface assessment and directs deeper analysis toward the inference data path.

`TiCoffLoader` is called internally by `TiNNCScanner` for COFF2 targets; direct use is only needed for custom symbol analysis outside the NNC context.

For batch sweeping across a full TI SDK or TIRex package directory, use `sweeps/ti_sweep.py` — it handles artifact dispatch, nested zip extraction, and routes each file to the correct decoder chain.

---

## See also

- [TI COFF Archive Loading](ti-coff-archive-loading.md) — `TiCoffLoader` full reference: AR format, symbol table layout, string table resolution
- [TI Neural Network Artifact Detection](ti-neural-network-artifacts.md) — `TiNNCScanner` full reference: operator name parsing, tensor dimension extraction
- [TI SDK Package Sweeping](ti-sdk-package-sweeping.md) — `ti_sweep.py`: batch triage across a TI SDK directory
- [EcuC28xDecoder](ti-c28x-decoding.md) — C28x instruction disassembly for confirmed COFF2 findings
