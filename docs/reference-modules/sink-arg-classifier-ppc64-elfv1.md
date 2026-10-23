# SinkArgClassifierPPC64ELFv1

Classify exec-class sink argument provenance on PPC64 BE ELFv1 ELFs: the POWER Linux calling convention used by IBM LoadLeveler, iAccess for Linux, and POWER PE bundle binaries.

---

## Why this exists

1. **`SinkArgClassifier` hardcodes x86-64 CALL scanning.** The base `SinkArgClassifier` finds call sites by scanning for `0xE8` x86-64 CALL rel32. On PPC64 BE ELFv1 binaries it returns 0 results regardless of how many exec-class sinks are present.

2. **PPC64 BE ELFv1 uses TOC-relative inline stubs.** Rather than direct PLT stubs, callers reach imported functions through 7-instruction TOC-indirect stubs. The stub VA is mapped by `BinaryContext._extract_plt_ppc64be()` (gap ID: `LOADL-GAP-002`). Sink call sites emit `bl <stub_va>`; this module scans for those BL instructions.

3. **ELFv1 and ELFv2 differ in TOC discovery.** ELFv1 big-endian POWER Linux, AIX stores the TOC base as `r2 = .opd[8]` from the function descriptor. ELFv2 (little-endian ppc64le, OpenPOWER) uses `r2 = .got + 0x8000`. These must not be mixed.

---

## How it works

The scan is identical in structure to [SinkArgClassifierPPC64ELFv2](sink-arg-classifier-ppc64-elfv2.md) with three differences:

| Dimension | ELFv1 this module | ELFv2 |
|:---|:---|:---|
| Capstone mode | `CS_MODE_64 | CS_MODE_BIG_ENDIAN` | `CS_MODE_64 | CS_MODE_LITTLE_ENDIAN` |
| TOC discovery | Read `.opd` + 8 function descriptor slot 1 | `.got.virtual_address + 0x8000` |
| Pointer reads | `>Q` / `>I` big-endian | `<Q` / `<I` little-endian |

String-address load patterns handled:

| Pattern | Encoding | Classification |
|:---|:---|:---|
| `lis rX, HI; addi rX, rX, LO` | 32-bit signed address | `RODATA_CONST` if in `.rodata` |
| `lis rX, HI; ori rX, rX, LO` | 32-bit unsigned address | `RODATA_CONST` if in `.rodata` |
| `lis rX, HI; lwz rX, LO(rX)` | 32-bit indirect pointer | `RODATA_CONST` if `*ptr` in `.rodata` |
| `lis rX, HI; ld rX, LO(rX)` | 64-bit indirect pointer | `RODATA_CONST` if `*ptr` in `.rodata` |
| `li rX, imm` | Small immediate | `RODATA_CONST` |
| `mr rX, rY` | Register copy | Recurse on rY; `ARG_PROPAGATED` if rY in `r3–r10` |
| `addi rX, r1, N` | Stack slot address | `ARG_PROPAGATED` if snprintf back-track matches |
| `addis rX, r2, HI; addi rX, rX, LO` | TOC-relative address | `RODATA_CONST` if `toc_addr` in `.rodata` |
| `addis rX, r2, HI; ld rX, LO(rX)` | TOC-relative pointer | `RODATA_CONST` if `*toc_ptr` in `.rodata` |

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.sink_arg_classifier_ppc64_elfv1 import SinkArgClassifierPPC64ELFv1

ctx = BinaryContext.load_or_build('/path/to/LoadL_master')
clf = SinkArgClassifierPPC64ELFv1.from_context(ctx)

# Add vendor-specific sinks before calling classify_all
clf.add_sink('ll_spawn_process', arg_pos=0)

results = clf.classify_all()
print(clf.report(results))

# Triage: eliminate RODATA_CONST and parameterless SNPRINTF_RODATA
flagged = [r for r in results if r.verdict not in ('RODATA_CONST', 'SNPRINTF_RODATA')]
for r in flagged:
    print(f'0x{r.func_va:x}  {r.verdict}  {r.sink_name}  {r.detail}')
```

**Typical output:**
```
SinkArgClassifierPPC64ELFv1: 31 results
  RODATA_CONST      system(arg0)    func=0x10001234 call=0x100012a0  lis+addi r3 → 0x100a2040 in .rodata
  ARG_PROPAGATED    system(arg0)    func=0x10003400 call=0x100034c8  mr r3, r3 (entry arg)
  SNPRINTF_RODATA   popen(arg0)     func=0x10005600 call=0x100056e4  snprintf(r1+0x40) fmt=rdx='/bin/ls %s'
  UNKNOWN           system(arg0)    func=0x10007800 call=0x100078a4  lis r3: no paired second insn within 5

Summary: ARG_PROPAGATED=1 | RODATA_CONST=22 | SNPRINTF_RODATA=5 | UNKNOWN=3
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
r2   TOC pointer (read from .opd function descriptor)
r1   stack pointer
LR   return address
```

---

## Limitations

**TOC discovery requires an `.opd` section.** If the binary lacks `.opd` stripped or cross-compiled, `toc_va` defaults to 0 and all TOC-relative address patterns fail to resolve. In that case, `lis+addi` patterns that don't go through the TOC will still work correctly.

**FPR arguments are not tracked.** Floating-point registers (`f1–f13`) are not classified. Exec sinks that receive a format string through a floating-point argument are out of scope.

---

## Pipeline position

**Architecture selection:** Use [sac-arch-dispatch](sac-arch-dispatch.md) or `sac_for_context(ctx)` to automatically select this module for `ctx.arch == 'ppc64'` with `EI_DATA=2`.

**After:** Filter out `RODATA_CONST`. Pass `ARG_PROPAGATED` and `UNKNOWN` to [TaintTracker PPC64](ppc64-taint-analysis.md).

---

## See also

- [SinkArgClassifierPPC64ELFv2](sink-arg-classifier-ppc64-elfv2.md): same pipeline for ppc64le LE ELFv2
- [SinkArgClassifier](sink-arg-classifier.md): x86-64 baseline
- [PPC64 Taint Analysis](ppc64-taint-analysis.md): receives ARG_PROPAGATED findings
- [SAC Arch Dispatch](sac-arch-dispatch.md): auto-selects the right SAC variant from BinaryContext arch
