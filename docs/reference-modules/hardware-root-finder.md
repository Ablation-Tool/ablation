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

`HardwareRootFinder.from_context(ctx).find()` iterates `ctx.func_starts`, disassembles each function with Capstone, and flags memory accesses to known MMIO address ranges (device registers, peripheral memory maps). For each match, it builds a call spine (caller chain up to exported functions) to show how hardware access is reached from the API surface.

---

## Usage

```python
from modules.hardware_root_finder import HardwareRootFinder

finder = HardwareRootFinder.from_context(ctx)
roots = finder.find_roots(depth=2)
for root in roots:
    print(root.fmt())
```

---

## Example output

```
HardwareRoot  func_va=0x004010a0  (write_gpio_state)
  mmio_labels: ['GPIO_BASE', 'SPI_CTRL']
  accesses:
    0x004010b4  MOV [0xffe10004], eax  GPIO_BASE+0x4
    0x004010c8  MOV [0xffe30000], ecx  SPI_CTRL+0x0
  call_spine: main → board_init → write_gpio_state
```

---

## False positives

Constants in the MMIO address range that are used as local variables (not actual memory writes/reads) may produce false hits. Verify that the instruction is a memory operation targeting the MMIO range, not an arithmetic operation on an immediate that happens to fall in the range.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` with `ctx.func_starts` populated. Configure the MMIO range table for the target hardware platform.

**After this module:** For MMIO write functions, trace what values are written from the call spine to assess whether an attacker-controlled input can reach the hardware register.

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
