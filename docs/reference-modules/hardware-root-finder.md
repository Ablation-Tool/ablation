# HardwareRootFinder

**File:** `modules/hardware_root_finder.py`

## Why this exists

Identifies hardware-assisted security feature usage in stripped firmware: ARM TrustZone SMC calls, x86 SGX instructions, IOMMU/SMMU bypass patterns, secure boot chain verification stubs, and TPM command sequences. Used for determining whether a firmware image has any meaningful hardware security integration or is relying purely on software controls.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Usage

```python
from ablation.analyzers.hardware_root_finder import HardwareRootFinder

results = HardwareRootFinder.from_context(ctx).run()
for r in results:
    print(r)
```

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

## Reading output

`HardwareRootFinder.from_context(ctx).find()` returns `List[HardwareRoot]`:

| Attribute | Content |
|:---|:---|
| `func_va` | Start VA of the function containing MMIO accesses |
| `accesses` | `List[HardwareAccess]` — each access to an MMIO address range |
| `call_spine` | `List[List[int]]` — caller paths leading to this hardware-access function |
| `mmio_labels` | Property returning unique MMIO range names across all accesses |

Each `HardwareAccess` has:

| Attribute | Content |
|:---|:---|
| `func_va` | Containing function start VA |
| `site_va` | VA of the individual MMIO read/write instruction |
| `mmio_addr` | The MMIO address referenced |
| `mmio_label` | Range label (e.g., `'STM32-APB/AHB'`) |
| `mnemonic` | Instruction mnemonic at `site_va` |
| `is_write` | `True` if this is a store to MMIO |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
