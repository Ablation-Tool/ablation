# VtableDispatchMapper

- [Why this exists](#why-this-exists)
- [How it works](#how-it-works)
- [Class and method reference](#class-and-method-reference)
- [Usage](#usage)
- [Example output](#example-output)
- [False positives](#false-positives)
- [Pipeline position](#pipeline-position)
- [Reading findings](#reading-findings)
- [See also](#see-also)

---

## Why this exists

In stripped C++ firmware, `BinaryContext.call_edges` only captures static `CALL rel32` edges. Virtual method calls compile to `call *[reg+offset]` — no static target. A function like `CheckHip` can have **zero** entries in `call_edges` even though it is the hot path for every HIP check, because the real callers dispatch through a vtable pointer at runtime.

Three gaps this fills:

1. **Virtual callers are invisible to TaintTracker** — without knowing that `CheckHip` is at vtable slot 5, TaintTracker cannot trace the caller's object setup into `CheckHip`'s arguments.
2. **Zero-caller heuristic is polluted** — `CrossBinaryExportDetector` needs to exclude vtable-dispatched functions from its "no local callers" set; otherwise every vtable method appears to be a cross-binary export.
3. **Manual vtable recovery is error-prone** — the prior workflow was scanning `.rela.dyn` bytes by hand and counting 8-byte strides in a hex dump. This module automates that exactly.

---

## How it works

In a PIE ELF, the dynamic linker populates vtables at load time via `R_X86_64_RELATIVE` (type 8) relocations. Each reloc patches one pointer-sized slot in `.data.rel.ro` with `load_base + r_addend`. At link time (before loading), `r_addend` holds the raw function VA.

`VtableDispatchMapper` reads `.rela.dyn`, filters for type-8 relocs whose `r_addend` falls in the `.text` section (function pointers, not metadata), sorts by `r_offset`, and groups consecutive entries that differ by exactly 8 bytes (pointer width) into vtable blocks. Any run of ≥ `MIN_VTABLE_SLOTS` (default 2) consecutive entries is treated as a vtable.

The reverse map `_rev: {func_va → [VtableSlot]}` is built simultaneously, enabling O(1) lookup by function VA.

---

## Class and method reference

### `VtableDispatchMapper`

```python
class VtableDispatchMapper:
    from_path(path: str) -> VtableDispatchMapper
    from_context(ctx) -> VtableDispatchMapper
```

#### `callers_via_vtable(func_va: int) -> List[VtableSlot]`

Return all vtable slots containing `func_va`. Empty list if the function is not in any vtable. O(1).

#### `vtable_at(va: int) -> Optional[Vtable]`

Return the `Vtable` whose start VA matches exactly, or `None`.

#### `vtable_containing(va: int) -> Optional[Tuple[Vtable, int]]`

Return `(vtable, slot_index)` if `va` appears in any vtable slot, or `None`. Useful for checking membership without knowing the vtable start VA.

#### `all_vtables() -> List[Vtable]`

Return all recovered vtables in order of their VA.

#### `report(max_vtables: int = 20) -> str`

Human-readable summary: total vtable count, function count, TEXT range, and per-vtable slot listing.

### `Vtable`

```python
@dataclass
class Vtable:
    va:     int         # VA of first slot in .data.rel.ro
    slots:  List[int]   # ordered function VAs
    size:   int         # number of slots
    slot_of(func_va) -> Optional[int]
```

### `VtableSlot`

```python
@dataclass
class VtableSlot:
    vtable_va:   int   # VA of the vtable containing this slot
    slot_index:  int   # 0-based index
    func_va:     int   # function VA
```

---

## Usage

```python
from ablation.analyzers.vtable_dispatch_mapper import VtableDispatchMapper

mapper = VtableDispatchMapper.from_context(ctx)

# Is CheckHip called via vtable?
slots = mapper.callers_via_vtable(0x156210)
for s in slots:
    print(f"vtable @ {s.vtable_va:#x}  slot {s.slot_index}")

# Get the full vtable layout
vt = mapper.vtable_at(s.vtable_va)
for i, fn in enumerate(vt.slots):
    print(f"  [{i}] {fn:#x}  {ctx.name(fn)}")

# Print overview
print(mapper.report())
```

Pass to `CrossBinaryExportDetector.detect()` to exclude vtable methods:

```python
from ablation.analyzers.cross_binary_export_detector import CrossBinaryExportDetector
det = CrossBinaryExportDetector.from_context(ctx)
exports = det.detect(vtable_mapper=mapper)
```

---

## Example output

```
VtableDispatchMapper: PanGPS
  vtables found : 47
  functions in vtables: 312
  text range    : 0x00001000 – 0x004f2000

  vtable @ 0x00536e40  (8 slots)
    [ 0] 0x00155eb0
    [ 1] 0x00155f20
    [ 2] 0x00155f90
    [ 3] 0x00156210   ← CheckHip
    [ 4] 0x00156710
    [ 5] 0x00156e30
    [ 6] 0x00157020
    [ 7] 0x00157190
```

---

## False positives

**Metadata arrays mistaken for vtables.** A run of 8-byte-aligned TEXT pointers in `.data.rel.ro` could be a dispatch table, a function pointer array (e.g., signal handlers), or a computed goto table rather than a C++ vtable. At `MIN_VTABLE_SLOTS=2`, this risk is highest for pairs of adjacent function pointers. Raise to 3 if false positive rate is high.

**Non-TEXT function pointers.** Exception handler tables and unwind info sometimes include TEXT pointers in sections other than `.data.rel.ro`. These are filtered out by the TEXT range check — they won't appear as vtable slots.

---

## Pipeline position

```
BinaryContext.load_or_build()
    → VtableDispatchMapper          ← here (step 2.5 — before SemanticSearcher)
    → CrossBinaryExportDetector(vtable_mapper=mapper)
    → SemanticSearcher → FuncProfiler
    → SinkArgClassifier → [post-SAC filters] → TaintTracker → PathSolver
```

Run immediately after `BinaryContext.load_or_build()` for any C++ binary. Must run before `CrossBinaryExportDetector` (vtable exclusion) and before `SemanticSearcher` / `SinkArgClassifier` (ensures `callers_of()` is accurate for virtual functions).

---

## Reading findings

`callers_via_vtable()` returns an empty list for functions with zero vtable appearances. A non-empty result means:

- The function **is reachable** — it's not dead code, and not a cross-binary export candidate.
- The function is called via **virtual dispatch** — its callers set up an object and call through a vtable pointer. To trace taint into it, you must find what sets up the object that holds this vtable.
- The `slot_index` tells you which method in the class interface this function implements. Slot 0 is often the destructor or the first pure-virtual; slot ordering follows the vtable declaration in source.

---

## See also

- `CrossBinaryExportDetector` — uses vtable membership to filter zero-caller functions
- `TaintTracker` — trace argument provenance into vtable-dispatched functions once identified
- `SinkArgClassifier` — classify shell sink arguments in the identified function
- `BinaryContext.call_edges` — static CALL rel32 edges (complement to vtable dispatch)

[↑ Back to top](#vtable-dispatch-mapper)
