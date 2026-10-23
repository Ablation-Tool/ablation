# ELF VTable Reconstructor

**File:** `modules/elf_vtable_reconstructor.py`

## Why this exists

Reconstructs C++ virtual dispatch tables from x86-64 ET_DYN ELF shared libraries without executing the binary. Walks `.rela.dyn` for R_X86_64_RELATIVE type 8, in-library functions and R_X86_64_64 type 1, exported symbol references relocation entries to build a slot-index → function-VA map. Uses pure-Python ELF parsing (`struct.unpack_from`), no lief, no Capstone dependency. Enables identifying polymorphic sinks without RTTI or debug symbols.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_ELF_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard in `__init__()` before `f.read()`; `_MAX_ELF_BYTES=256MB`. Pure-Python ELF parser, no lief.parse(). No HTTP reads. `c++filt` subprocess uses `timeout=2`.

---

## How it works

`ELFVtableReconstructor.from_path(path)` uses pyelftools to parse the ELF dynamic relocation table (`.rela.dyn`) and resolve PIE vtable slot values that are zero-initialized in the file but populated at load time. Handles `R_X86_64_RELATIVE` base + addend and `R_X86_64_64` sym_value + addend relocation types. No func_starts iteration: operates on relocation entries and symbol table only.

---

## Usage

```python
from modules.elf_vtable_reconstructor import ELFVtableReconstructor

recon = ELFVtableReconstructor.from_path('/path/to/target.so')
vtmap = recon.reconstruct(vtable_va=0x12000)
for va, slot in vtmap.slots.items():
    print(f"  {va:#x}: {slot.name or '<unknown>'}")
```

---

## Example output

```
ELFVtableReconstructor: lib.so  class=RequestHandler  slots=12
  +0x000  vfunc[0]  RequestHandler::~RequestHandler()
  +0x008  vfunc[1]  RequestHandler::handleRequest(HttpContext&)
  +0x010  vfunc[2]  RequestHandler::getRoutePrefix() const
```

---

## False positives

Secondary vtable sub-sections multiple inheritance appear as `is_rtti=True` entries at negative `slot_offset`; these are not virtual function slots. For classes with complex inheritance hierarchies, manually inspect entries near `slot_offset=0x00` for misclassification.

---

## Pipeline position

**Before this module:** Confirm the target is an ET_DYN x86-64 ELF with C++ content (look for `_ZTV` symbols in the symbol table).

**After this module:** Pass the `VtableMap` to `VtableDispatchScanner` to find live vs. dead virtual dispatch sites.

---

## Reading output

`ELFVtableReconstructor.from_path(path).reconstruct_class('ClassName')` returns a `VtableMap`. Access individual slots via `vtable_map.slots` (a `Dict[int, VtableSlot]` keyed by byte offset from `vtable_ptr`):

`VtableMap` attributes:

| Attribute | Content |
|:---|:---|
| `vtable_va` | VA of the vtable data in the binary |
| `vtable_ptr` | VA that class instances store as their vtable pointer |
| `class_name` | Demangled class name empty if not available |
| `slots` | `Dict[int, VtableSlot]` keyed by byte offset |

Each `VtableSlot`:

| Attribute | Content |
|:---|:---|
| `slot_index` | 0-based slot index |
| `slot_offset` | Byte offset from `vtable_ptr` |
| `abs_va` | Absolute VA of this slot entry in `.data.rel.ro` |
| `function_va` | Resolved target function VA |
| `function_name` | Demangled name, or `sub_0x...` fallback |
| `is_rtti` | `True` for RTTI/typeinfo slots |

Use `vtable_map.live_slots()` to filter out RTTI entries and zero-VA slots.

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
