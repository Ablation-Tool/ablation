# PPC32PLTTracer

**File:** `ablation/analyzers/ppc32_plt_tracer.py`

Verified import caller finder for PPC32 BE position-independent `.so` files.
Finds every `BL` instruction in a binary that definitively calls a named
imported symbol (e.g. `system`, `popen`, `execl`) and eliminates the
false-positive class caused by multiple compilation units sharing a thunk VA.

Validated: Huawei CE6810 switch e500mc `.so` files (7 modules, 184 apparent
dangerous call sites reduced to 8 confirmed by r30 cross-check).

---

## Usage

```python
from ablation.analyzers.ppc32_plt_tracer import PPC32PLTTracer, batch_sweep, batch_scan

# Quick import surface scan (no call-site detail)
hits = batch_sweep('/tmp/ce6810_sqfs/module')
# -> {'libupdatelpu_e500mc.so': ['system'], 'semls.so': ['popen', 'system'], ...}

# Full verified scan: confirmed call sites only
results = batch_scan('/tmp/ce6810_sqfs/module')
# -> {'libupdatelpu_e500mc.so': {'system': [PLTCallSite(...), ...]}, ...}
# Files with zero confirmed callers are omitted.

# Per-binary query
tracer = PPC32PLTTracer.from_path('/tmp/ce6810_sqfs/module/libupdatelpu_e500mc.so')
sites = tracer.find_callers('system')
print(tracer.report(sites, sym_name='system'))

# Disassemble context around a confirmed call site
tracer.elf.print_disasm(sites[0].bl_va - 8*4, n=15, mark=sites[0].bl_va)
```

---

## PLTCallSite fields

| Field | Type | Description |
|---|---|---|
| `bl_va` | `int` | VA of the `BL` instruction |
| `thunk_va` | `int` | VA of the `LWZ+MTCTR+BCTR` thunk |
| `caller_r30` | `int` | Active r30 at the call site (verified) |
| `func_name` | `Optional[str]` | Nearest export name |

---

## PPC32ELF helper

`ppc32_plt_tracer` also exports `PPC32ELF`, a thin lief + capstone wrapper
used in workspace scripts:

```python
from ablation.analyzers.ppc32_plt_tracer import PPC32ELF

elf = PPC32ELF('/path/to/lib.so')
elf.print_disasm(va, n=20, mark=va)      # disassemble n insns, mark one
callers = elf.find_bl_callers(target_va)  # all BL→target in .text
slot = elf.plt_slot('system')            # PLT slot VA for imported symbol
```

`PPC32ELF.find_import_callers()` is the unverified predecessor — use
`PPC32PLTTracer.find_callers()` instead.

---

## How it works

### PPC32 BE .so calling model

In a PPC32 BE `.so`, imported symbol calls go through per-compilation-unit
thunks:

```asm
thunk:
    LWZ  rx, d(r30)   ; load PLT slot from r30 + displacement
    MTCTR rx
    BCTR
```

Each function's `r30` is established at entry:

```asm
BCL   20,31,+4          ; LR ← next-PC (= bcl_va + 4)
MFLR  r30               ; r30 ← LR
ADDIS r30, r30, hi      ; r30 += hi16(const)
ADDI  r30, r30, lo      ; r30 += lo16(const)
; now r30 = GOT2/PLT area base for this compilation unit
```

The displacement `d` uniquely identifies which PLT slot the thunk calls
**for a given r30 value**. Different compilation units use different r30
values, so the same thunk VA can call different symbols depending on who
calls it.

### Naive approach and its false positive class

A naive scan:
1. Collect all `r30` values from BCL preambles.
2. For each thunk, check if `plt_slot(target) - d` is in that set.
3. Return all `BL` callers of matching thunks.

This produces false positives: a thunk with displacement `d` may match
`plt_slot(system) - d = r30_A`, but callers whose active r30 is `r30_B ≠ r30_A`
will route through a different PLT slot (e.g. `snprintf_truncated_s`) from
that same thunk VA.

In practice, a 1.2 MB `.so` with 32 compilation units produced 58 false
positive "system()" call sites from one real system() caller.

### r30 cross-check (fix)

`PPC32PLTTracer.find_callers()` adds a per-caller verification step:

1. For each `BL caller_va → thunk_va`, scan backward from `caller_va` to
   find the nearest preceding BCL preamble and compute the r30 it establishes.
2. Accept the call site only if `actual_r30 == implied_r30 = plt_slot - d`.

This eliminates all cross-compilation-unit false positives without any
additional binary knowledge.

---

## Validation

Confirmed against CE6810 e500mc `.so` ground truth from sessions 28–31:

| Binary | Symbol | Session finding | `batch_scan` result |
|---|---|---|---|
| `libupdatelpu_e500mc.so` | `system` | SESSION_28: BL@0x12b98, BL@0x13708 | ✓ exact match |
| `libpythonvm.so` | `system` | SESSION_31: single caller = PVMA_System_Safe | ✓ exact match |
| `semls.so` | `system` | SESSION_29: BL@0x2dacc | ✓ exact match |
| `semls.so` | `popen` | SESSION_29: BL@0x7bad4 | ✓ exact match |

False positive reduction: libupdatelpu 9→2, libpythonvm 59→1 after r30 check.

---

## Assumptions and failure modes

**r30 = GOT2 register.** Standard SysV ABI PPC32. Non-standard toolchains
using r29 or another register will not match.

**BCL preamble within 8 KB.** Scan window is 8 KB backward from each BL.
Very large compilation units (unusual in firmware .so files) could exceed this.
Increase `max_scan` parameter to `_get_caller_r30` if needed.

**Thunk pattern = LWZ+MTCTR+BCTR.** Some compilers emit `BCTRL` (link bit set)
for PLT calls. This module handles `BCTR` only; extend `_find_thunks` if
`BCTRL`-based thunks appear.

**Static analysis only.** PLT slots contain on-disk placeholder values;
the loader patches them at runtime. This module uses symbol names from
`.rela.plt` (already present in the unloaded image), so no runtime state
is needed.
