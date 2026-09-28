# x86-64 Vtable Analysis

Static C++ vtable reconstruction and dispatch reachability analysis for x86-64 shared
libraries (ET_DYN ELF). Solves the "all vtable entries are zero in the file" problem that
makes vtable analysis impossible with naive file-level inspection.

---

## ELFVtableReconstructor

**File:** `ablation/analyzers/elf_vtable_reconstructor.py`

Reconstructs the runtime virtual function table of a C++ class from `.rela.dyn` without
executing the binary. Works on any x86-64 ET_DYN ELF (shared libraries, PIE executables).

### Why vtable entries are zero in the file

Position-independent shared libraries store vtable entries as zero in the `.data.rel.ro`
section. The dynamic linker fills them at load time using two relocation types:

- **R_X86_64_RELATIVE (type 8)**: `*slot = load_base + addend`. Used for functions defined
  in the same library. The addend in `.rela.dyn` is the function VA relative to load base.
- **R_X86_64_64 (type 1)**: `*slot = sym_value + addend`. Used for exported symbols and
  cross-library function pointers. The symbol index in `.rela.dyn` identifies the function.

`ELFVtableReconstructor` reads both types from `.rela.dyn` and produces a complete
slot→function map without loading the library.

### Vtable layout reminder

```
vtable_va + 0x00:  offset-to-top  (0 for primary base)
vtable_va + 0x08:  RTTI pointer   (typeinfo object)
vtable_va + 0x10:  vfunc[0]       ← vtable_ptr (what the object's vptr holds)
vtable_va + 0x18:  vfunc[1]
...
```

The vtable_ptr stored in an object points to `vtable_va + 0x10`. Slot offsets used in call
instructions are relative to this pointer, so `call [rax+0x10]` dispatches `vfunc[1]`.

### Usage

```python
from ablation.analyzers.elf_vtable_reconstructor import ELFVtableReconstructor

rec = ELFVtableReconstructor.from_path('/path/to/lib.so')

# By class name (looks up _ZTV<N><name> in symbol table)
vtable_map = rec.reconstruct_class('MyClass')

# By known vtable VA
vtable_map = rec.reconstruct(0x92d540)

# Query individual slots
slot = vtable_map.get_slot(0x1f50)      # slot at vtable_ptr+0x1f50
fn_name = vtable_map.function_at(0x110) # name for slot_ptr+0x110

# All live (function) slots vs. RTTI/meta entries
live = vtable_map.live_slots()  # dict of slot_offset -> VtableSlot

# Full report
print(ELFVtableReconstructor.report(vtable_map))
```

### VtableMap fields

| Attribute | Type | Description |
|---|---|---|
| `vtable_va` | int | VA of vtable start (offset-to-top word) |
| `vtable_ptr` | int | `vtable_va + 0x10` — what the object's vptr holds |
| `slots` | dict | `{slot_offset: VtableSlot}` — all reconstructed entries |
| `class_name` | str | Class name (set when using `reconstruct_class`) |
| `live_slots()` | method | Filtered dict of function (non-RTTI) slots |
| `get_slot(offset)` | method | Single slot lookup by offset from vtable_ptr |
| `function_at(offset)` | method | Demangled function name at offset, or None |
| `slot_for_va(fn_va)` | method | Find slot containing a known function VA |

### VtableSlot fields

| Attribute | Type | Description |
|---|---|---|
| `slot_index` | int | Slot number (0-based, from vtable_ptr) |
| `slot_offset` | int | Byte offset from vtable_ptr |
| `abs_file_offset` | int | Absolute VA of the slot in the file |
| `function_va` | int | Resolved function VA |
| `function_name` | str | Demangled name (or `sub_0x...` if unnamed) |
| `is_rtti` | bool | True for RTTI/typeinfo entries, False for virtual functions |

### Multiple inheritance note

Classes with multiple inheritance have secondary vtable sub-sections. Each sub-section starts
with an offset-to-top word (negative value, locating the primary object) followed by an RTTI
pointer and secondary virtual functions. `ELFVtableReconstructor` reconstructs all entries
in a configurable range from `vtable_va`; secondary sub-sections appear as `is_rtti=True`
entries at negative `slot_offset` values (below the primary vtable_ptr).

---

## VtableDispatchScanner

**File:** `ablation/analyzers/vtable_dispatch_scanner.py`

Searches the executable sections of an x86-64 ELF for `call [reg+disp]` instructions
that dispatch a given set of vtable slot offsets. Determines which virtual methods are
actually called ("live") vs. never dispatched ("dead").

### Encoding coverage

The scanner handles all standard x86-64 indirect call encodings:

| Encoding | Example | Handled |
|---|---|---|
| `call [rax+disp32]` | `FF 90 xx xx xx xx` | Yes |
| `call [rcx+disp32]` | `FF 91 xx xx xx xx` | Yes |
| ... (all base regs) | ... | Yes |
| `call [r8+disp32]` | `41 FF 90 xx xx xx xx` | Yes (REX.B) |
| `call [r12+disp32]` | `41 FF 94 24 xx xx xx xx` | Yes (REX.B + SIB) |
| `call [rax+disp8]` | `FF 50 xx` | Yes (for offsets 0–127) |
| REX.W variants | `48 FF 90 ...` | Yes |
| REX.RB variants | `45 FF 90 ...` | Yes |

### Usage

```python
from ablation.analyzers.vtable_dispatch_scanner import VtableDispatchScanner

scanner = VtableDispatchScanner.from_path('/path/to/lib.so')

# Option 1: scan with a dict of name -> slot_offset
report = scanner.scan({'getUserByName': 0x4b0, 'getUserByNameWithHide': 0x24c8})

# Option 2: scan with a VtableMap from ELFVtableReconstructor
report = scanner.scan(vtable_map)  # uses live_slots() automatically

# Option 3: scan a list of offsets
report = scanner.scan_offset(0x1f50)  # single offset -> list of DispatchSites

# Query results
dead = report.dead()    # dict of names with zero dispatch sites
live = report.live()    # dict of names with one or more dispatch sites

# Full report
print(VtableDispatchScanner.report(report))
```

### Combined workflow

```python
from ablation.analyzers.elf_vtable_reconstructor import ELFVtableReconstructor
from ablation.analyzers.vtable_dispatch_scanner import VtableDispatchScanner

rec = ELFVtableReconstructor.from_path('/path/to/lib.so')
scanner = VtableDispatchScanner.from_path('/path/to/lib.so')

vtable = rec.reconstruct_class('MyDBClass')
report = scanner.scan(vtable)

# Dead methods — exist in vtable but never dispatched in this binary
for name in report.dead():
    print(f'dead: {name}')

# Live methods — find all call sites
for name, sites in report.live().items():
    for site in sites:
        print(f'{name}  called from {site.call_va:#010x} via [{site.register}+{site.slot_offset:#x}]')
```

### DispatchSite fields

| Attribute | Type | Description |
|---|---|---|
| `call_va` | int | VA of the `call` instruction |
| `register` | str | Base register (e.g. `'rax'`, `'r12'`) |
| `slot_offset` | int | Displacement used in the instruction |
| `encoding` | str | `'disp8'` or `'disp32'` |

### Limitations

- Scans only ELF sections marked `SHF_EXECINSTR`. Code in non-standard segments is missed.
- Does not follow cross-library call chains; a vtable method called only from another `.so`
  appears dead when scanning a single library.
- Does not handle `call [mem+reg*scale+disp]` (VSIB/complex SIB addressing) — rare in
  compiler-generated C++ vtable dispatch.
