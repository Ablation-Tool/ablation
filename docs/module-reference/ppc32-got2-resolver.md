# PPC32GOT2Resolver

**File:** `ablation/analyzers/ppc32_got2_resolver.py`

Resolves PPC32 indirect calls (`BCTRL` through CTR) to concrete function
addresses in stripped binaries that use the GOT2 position-independent calling
model. Turns 15,000+ question-mark call sites into named function addresses.

Tested: Huawei S6720EI bootload (V200R012C00, Freescale e500mc PPC32 BE).
**15120 / 15339 indirect calls resolved (98.6%). Zero unknowns.**

---

## Usage

```python
from ablation.analyzers.ppc32_got2_resolver import PPC32GOT2Resolver

# Auto-parse section layout via lief
resolver = PPC32GOT2Resolver.from_path('/path/to/bootload')
result = resolver.resolve()
print(result.report())

# Feed named symbols into BinaryContext
for r in result.resolved:
    if r.name:
        ctx.set_name(r.target, r.name, source="dynsym")

# Look up a specific BCTRL site
target = result.targets_for(0x10023884)  # → 0x10022ee0

# All callers of a target
callers = result.by_target()[0x10022ee0]  # list of GOT2ResolvedCall
```

If lief is unavailable, use `from_sections()` to supply section layout directly:

```python
resolver = PPC32GOT2Resolver.from_sections(
    data=open('bootload', 'rb').read(),
    text_va=0x10000000, text_size=0x13a578, text_file_off=0x0,
    data_va=0x1014b000, data_size=0x1ffa0, data_file_off=0x13b000,
    dynsym_va=0x10000564, dynsym_size=0x830,
    dynstr_va=0x10000d94, dynstr_size=0x505,
    got2_va=0x1013b000,  got2_size=0x2000,   # enables Fix 2 range check
)
result = resolver.resolve()
```

### Hardening options

Two optional parameters improve precision in stripped binaries:

**`fn_starts` (Fix 1 — per-function r30 floor):**

Pass a sorted list of function entry VAs (e.g. from `lief.parse(p).exported_functions`).
When provided, a BCL setup site that precedes the current function's entry VA is
rejected instead of inherited.  Useful when a small leaf function has no BCL preamble
of its own and sits immediately after a function from a different CU with a different r30.

```python
import lief
elf = lief.parse(path)
fn_starts = sorted(f.address for f in elf.exported_functions if f.address)
result = resolver.resolve(fn_starts=fn_starts)
```

**`got2_va` / `got2_size` (Fix 2 — GOT2 range validation):**

Supplied to `__init__` / `from_path` / `from_sections`.  When present, any computed
`entry_va = r30 + disp` that falls outside `[got2_va, got2_va + got2_size)` is
rejected with reason `entry_va_outside_got2`.  `from_path` extracts `.got2`
automatically via lief.

**Fix 3 — generalised r30 setup detection (automatic):**

`_find_r30_setups` now uses a sliding-window scan: up to 16 instructions after the BCL
for `MFLR r30`, up to 6 more for `ADDIS r30,r30,hi`, up to 6 more for `ADDI r30,r30,lo`.
Any instruction that writes to r30 (other than the three target instructions) aborts the
search.  This handles a third compiler variant found in Huawei CE6810 e500mc `.so` files
where up to 8 frame spill instructions appear between BCL and MFLR r30.  No parameters
needed — this is always-on.

---

## How it works

### Step 1: r30 assignment (compilation unit boundaries)

PPC32 PIC code establishes the GOT2 base register once per compilation unit:

```
BCL  20,31,+4        # LR ← next-PC (= bcl_va + 4)
MFLR r30             # r30 ← LR
ADDIS r30, r30, hi   # r30 += hi16(const)
ADDI  r30, r30, lo   # r30 += lo16(const)
```

The linker computes `hi`/`lo` so that `r30 = GOT2_section_address + bias`.
The resolver captures the computed value directly from the instruction stream —
no knowledge of the bias offset is required.

The resolver finds 2242 such setup sites in the S6720EI bootload and builds a
sorted lookup. For any BCTRL VA, the live r30 = the setup with the largest
`bcl_va ≤ bctrl_va`.

### Step 2: BCTRL source classification

For each BCTRL, the resolver scans backward from the MTCTR (max 20 insns) to
identify the source register, then backward from the MTCTR (max 25 insns) to
classify the load:

| Pattern | Kind | Resolution |
|---|---|---|
| `LWZ/LWZU rx, d(r30)` | `got2` | `target = u32(r30 + d)` |
| `ADDIS rx,0,hi + ADDI rx,rx,lo` | `direct` | inline constant |
| `LWZ/LWZU rx, d(ry≠r30)` | `dynamic` | runtime only |
| `LWZX rx, ra, rb` | `dynamic` | runtime only |

### Step 3: Resolution

- **got2:** `entry_va = r30 + disp`; `target = u32(entry_va)` from binary image.
- **direct:** target is the inline constant from the ADDIS/ADDI pair.
- **dynamic:** logged as unresolved with a reason string; not counted in stats.

---

## Output types

### `GOT2ResolvedCall`

| Field | Type | Description |
|---|---|---|
| `bctrl_va` | `int` | VA of the BCTRL instruction |
| `kind` | `str` | `"got2"` or `"direct"` |
| `target` | `int` | Resolved callee VA |
| `name` | `Optional[str]` | Symbol name from .dynsym, if matched |
| `in_text` | `bool` | Whether target is within .text |
| `r30_source` | `Optional[int]` | VA of the BCL that established r30 |
| `r30` | `Optional[int]` | r30 value at call site |
| `disp` | `Optional[int]` | Signed GOT2 displacement |
| `entry_va` | `Optional[int]` | GOT2 entry address (r30 + disp) |

### `GOT2UnresolvedCall`

| Field | Type | Description |
|---|---|---|
| `bctrl_va` | `int` | VA of the BCTRL instruction |
| `reason` | `str` | Why it could not be resolved |

### `GOT2ResolveResult`

- `.resolved` — `List[GOT2ResolvedCall]`
- `.unresolved` — `List[GOT2UnresolvedCall]`
- `.stats` — dict: total_bctrl, resolved, got2, direct, unresolved, dynamic
- `.targets_for(va)` — look up callee for a BCTRL VA
- `.by_target()` — dict mapping callee VA → list of callers
- `.report()` — one-line summary string
- `resolver.export_jsonl(result, out_path)` — write resolved calls as JSONL

---

## Assumptions and failure modes

**Assumption: r30 is the GOT2 register.** Standard SysV ABI PPC32 convention.
Non-standard toolchains using r29 or another register will not be resolved.

**Assumption: GOT2 entries are final addresses.** This resolver is for statically
built binaries or dynamically linked binaries where relocation is already applied.
It does not support runtime ASLR unless the caller supplies the loaded base.

**Assumption: enclosing CU = nearest preceding BCL.** Correct per PPC32 ABI.
Functions without their own BCL setup (small leaf functions are common) inherit
the previous CU's r30; this is the intended behavior.

**Scan window limit.** MTCTR lookback is 20 instructions; load lookback is 25.
Complex register sequences across basic-block boundaries require CFG analysis.
In practice this is not observed in the tested binary.

**Dynamic dispatch (219 calls in S6720EI).** LWZX indexed dispatch and non-r30
LWZ/LWZU loads (struct field access, function pointer arrays) are runtime-only.
These are correctly labeled `dynamic` and excluded from the resolution count.

---

## Validation

Confirmed against two manual RE entries from `targets/huawei/s6720_switch_re.py`:

| BCTRL VA | Expected target | Result |
|---|---|---|
| `0x10023884` | `0x10022ee0` (check_version_compat) | ✓ |
| `0x100238e8` | `0x100230ac` (flash_compat) | ✓ |
