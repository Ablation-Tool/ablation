# SinkArgClassifierPPC32: ppc32 BE exec-sink classifier

## Why this exists

PPC32 big-endian uses `r3` as the first argument register. The main `SinkArgClassifier` tracks x86-64 registers so it returns SAC=0 for every ppc32 binary. The ppc64 register tracker is close but decodes 64-bit instructions. This module adds the 32-bit instruction decode path for ppc32.

Gap IDs resolved: **CLSTRMGR-GAP-001**, **RMC-PPC32-001**, **DCV-PPC32-001**, **CD7200-001**.

Affected products in the IBM-RE collection: HACMP clstrmgr, RMC ppc32 daemons, DCV libGL.so, cd7200 bootfile.exe.

## Usage

```python
# Via factory (recommended):
from ablation.analyzers.sink_arg_classifier import sac_for_path
clf = sac_for_path('/tmp/extract/usr/es/sbin/cluster/clstrmgr')

# Direct:
from ablation.analyzers.sink_arg_classifier_ppc32 import SinkArgClassifierPPC32
clf = SinkArgClassifierPPC32.from_path('/tmp/extract/usr/es/sbin/cluster/clstrmgr')

for r in clf.classify_all():
    print(f"{r.sink_name}@0x{r.call_va:x}: {r.verdict}")
```

## How it works

The classifier builds a BinaryContext for the binary, then traces backward from each BL-to-sink call site in the PPC32 instruction stream. It tracks `r3` as arg0 and resolves the following patterns:

- `lis r3, HI; addi r3, r3, LO` addressing a `.rodata` section address: `RODATA_CONST`
- `mr r3, rN` where `rN` was loaded from a function parameter slot: `ARG_PROPAGATED`
- `addi r3, r1, N` where a prior `stw`/snprintf sequence wrote a rodata format string to the stack: `SNPRINTF_RODATA`
- anything else: `UNKNOWN`

## Notes

The BL opcode for ppc32 BE is the same as ppc64 BE. This module uses Capstone `CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN`. The `from_path()` classmethod builds a BinaryContext internally so callers do not need to construct one.
