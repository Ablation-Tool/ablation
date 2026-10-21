# SinkArgClassifierPPC64ELFv2

Classify exec-class sink argument provenance on PPC64 LE ELFv2 ELFs — the little-endian POWER ABI used by RHEL/RHCOS ppc64le, IBM HMC management binaries, and PowerSC.

---

## Why this exists

1. **`sac_for_context()` dispatched ppc64le to the x86_64 classifier.** Before this module, any `BinaryContext` with `EI_DATA=1` (little-endian) and `e_machine=0x15` (EM_PPC64) was routed to the x86_64 `SinkArgClassifier`. That classifier disassembles ppc64le code as x86_64, producing garbage operands and returning 0 results on every binary.

2. **The gap affected a large target set.** HMC management binaries (`hmc.mgmt`, `hmc.common`, `hmc.svrmgmt`) contain 35+ ppc64le shared objects. All returned SAC=0 before this module existed. Affected binaries include every component that manages hardware management controller firmware upgrades.

3. **ELFv2 differs from ELFv1 in TOC discovery.** ELFv1 (big-endian POWER Linux, AIX) reads the TOC base from the `.opd` function descriptor. ELFv2 (ppc64le) uses `r2 = .got.virtual_address + 0x8000` (GNU ld ELFv2 ABI convention). These must not be mixed.

---

## How it works

```
SinkArgClassifierPPC64ELFv2.from_context(ctx)
         │
         ├── _init()
         │   ├── Scan LIEF sections for .rodata ranges
         │   ├── Build plt_rev from ctx.plt (or LIEF pltgot_relocations fallback)
         │   ├── Map snprintf/vsnprintf/sprintf PLT VAs to format arg positions
         │   └── Discover TOC: r2 = .got.virtual_address + 0x8000
         │
         └── classify_all()
             ├── _find_sink_plts(): map PLT VA → (sink_name, arg_pos)
             └── For each func_va in ctx.func_starts:
                 ├── _get_insns(): Capstone CS_MODE_64 | CS_MODE_LITTLE_ENDIAN
                 ├── _find_call_sites(): BL instructions targeting sink PLT VA
                 └── For each call site: _trace_arg(insns, call_idx, arg_reg)
```

**`_trace_arg` backward scan (up to `_LOOKBACK=80` instructions):**

The scan walks backward from the call site and classifies the last instruction that writes to the argument register:

| Instruction | Classification |
|:---|:---|
| `li rX, imm` | `RODATA_CONST` (immediate value) |
| `lis rX, HI; addi rX, rX, LO` | `RODATA_CONST` if computed address in `.rodata` |
| `lis rX, HI; ori rX, rX, LO` | `RODATA_CONST` if computed address in `.rodata` |
| `lis rX, HI; lwz rX, LO(rX)` | `RODATA_CONST` if `*ptr` in `.rodata` |
| `lis rX, HI; ld rX, LO(rX)` | `RODATA_CONST` if `*ptr` in `.rodata` |
| `mr rX, rY` (or `or rD, rA, rA`) | `ARG_PROPAGATED` if rY in `r3–r10`; recurse otherwise |
| `addi rX, r1, N` | Stack slot → snprintf back-track → `SNPRINTF_RODATA` or `ARG_PROPAGATED` |
| `ld/lwz rX, N(r1)` | Stack slot load → snprintf or entry-arg save check |
| `addis rX, r2, HI; addi rX, rX, LO` | TOC-relative address → `RODATA_CONST` if in `.rodata` |
| `addis rX, r2, HI; ld rX, LO(rX)` | TOC-relative pointer → `RODATA_CONST` if `*ptr` in `.rodata` |
| `ld rX, N(r2)` | Direct TOC slot dereference → `RODATA_CONST` if slot points to `.rodata` |
| Register unmodified in window | `ARG_PROPAGATED` if reg is in `r3–r10` (entry arg) |

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.sink_arg_classifier_ppc64_elfv2 import SinkArgClassifierPPC64ELFv2

ctx = BinaryContext.load_or_build('/path/to/hmc_mgmt_binary')
clf = SinkArgClassifierPPC64ELFv2.from_context(ctx)

# Register HMC-specific vendor sinks before classify_all
clf.add_sink('hmc_execute_command', arg_pos=0)

results = clf.classify_all()
print(clf.report(results))

flagged = [r for r in results if r.verdict not in ('RODATA_CONST', 'SNPRINTF_RODATA')]
```

**Typical output:**
```
SinkArgClassifierPPC64ELFv2: 18 results
  RODATA_CONST      system(arg0)    func=0x10000890 call=0x10000910  lis+addi r3 → 0x10020040 in .rodata
  ARG_PROPAGATED    system(arg0)    func=0x10004200 call=0x10004280  mr r3, r3 (entry arg)
  SNPRINTF_RODATA   popen(arg0)     func=0x10006100 call=0x100061c0  snprintf(r1+0x60) fmt=lis+addi '/bin/hmc %s'
  UNKNOWN           strcpy(arg0)    func=0x10008800 call=0x10008840  ld r3, 0x18(r1)

Summary: ARG_PROPAGATED=1 | RODATA_CONST=12 | SNPRINTF_RODATA=3 | UNKNOWN=2
Dead sinks (no stubs): execle, execlp
```

---

## Calling convention

```
r3   argument 0 / return value
r4   argument 1
r5   argument 2
r6   argument 3
r7   argument 4
r8   argument 5
r9   argument 6
r10  argument 7
r2   TOC pointer (.got + 0x8000 for ELFv2)
r1   stack pointer
LR   return address
```

---

## Limitations

**FPR arguments are not tracked.** Floating-point registers (`f1–f13`) pass to the first floating-point argument slots. Exec sinks that receive a command string through an FPR argument are out of scope.

**`_is_entry_arg_save` scans all function instructions.** The check that determines whether a stack slot holds a saved entry argument iterates the entire disassembled function without a window bound. On large functions near the `_MAX_FUNC_BYTES=65536` limit this is slow.

**Hardcoded Capstone fallback constants.** If Capstone is not installed, the module falls back to hardcoded integer constants for instruction IDs. If an upstream Capstone release changes those constants, the fallback silently misclassifies instructions.

---

## Pipeline position

**Architecture selection:** Use [sac-arch-dispatch](sac-arch-dispatch.md) to auto-select this module for `ctx.arch == 'ppc64le'` (ELFv2).

**After:** Filter out `RODATA_CONST`. Pass `ARG_PROPAGATED` and `UNKNOWN` to [PPC64 Taint Analysis](ppc64-taint-analysis.md).

---

## See also

- [SinkArgClassifierPPC64ELFv1](sink-arg-classifier-ppc64-elfv1.md) — same pipeline for big-endian ELFv1
- [SinkArgClassifier](sink-arg-classifier.md) — x86-64 baseline and full verdict reference
- [PPC64 Taint Analysis](ppc64-taint-analysis.md) — receives ARG_PROPAGATED findings
- [SAC Arch Dispatch](sac-arch-dispatch.md) — auto-selects the right SAC variant from BinaryContext arch
