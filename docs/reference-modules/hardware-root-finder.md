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

`HardwareRootFinder.find_roots()` disassembles the entire `.text` section sequentially with Capstone. For each instruction, it applies `_IMM_RE` (regex `\b0x[0-9a-f]{6,16}\b`) to the operand string to extract hexadecimal immediates. Any immediate that falls in a known MMIO range (`_MMIO_RANGES`) is recorded as a `HardwareAccess`. Function boundaries are tracked by watching for `endbr64` / `push rbp` prologues; if a `BinaryContext` is supplied, `ctx.func_containing()` is used instead for more accurate attribution. Accesses are grouped by function VA into `HardwareRoot` objects. If a `BinaryContext` is provided, `find_roots(depth=N)` walks callers N hops back to build the call spine.

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
HardwareRoot func=0x4010a0
  MMIO ranges : STM32-APB/AHB
  accesses    : 2
    0x4010b4  WRITE  MMIO=0x40010004 (STM32-APB/AHB)  func=0x4010a0  [mov]
    0x4010c8  READ   MMIO=0x40030000 (STM32-APB/AHB)  func=0x4010a0  [ldr]
  callers (1 paths):
    0x401000 -> 0x401050 -> 0x4010a0
```

---

## False positives

Constants in the MMIO address range that are used as local variables not actual memory writes/reads may produce false hits. Verify that the instruction is a memory operation targeting the MMIO range, not an arithmetic operation on an immediate that happens to fall in the range.

---

## Pipeline position

**Before this module:** `HardwareRootFinder('/path/to/binary')` or `HardwareRootFinder.from_context(ctx)`. Configure `extra_ranges` if the target SoC is not in `_MMIO_RANGES` STM32, BCM, Qualcomm IPQ, Cavium OCTEON, Intel APIC/HPET are built in.

**After this module:** For MMIO write functions, trace what values are written from the call spine to assess whether an attacker-controlled input can reach the hardware register.

---

## Reading output

`HardwareRootFinder.from_context(ctx).find()` returns `List[HardwareRoot]`:

| Attribute | Content |
|:---|:---|
| `func_va` | Start VA of the function containing MMIO accesses |
| `accesses` | `List[HardwareAccess]`: each access to an MMIO address range |
| `call_spine` | `List[List[int]]`: caller paths leading to this hardware-access function |
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

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
