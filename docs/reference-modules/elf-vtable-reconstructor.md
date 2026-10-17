# ELF VTable Reconstructor

**File:** `modules/elf_vtable_reconstructor.py`

## Why this exists

Reconstructs C++ virtual dispatch tables from x86-64 ET_DYN ELF shared libraries without executing the binary. Walks `.rela.dyn` for R_X86_64_RELATIVE (type 8, in-library functions) and R_X86_64_64 (type 1, exported symbol references) relocation entries to build a slot-index → function-VA map. Uses pure-Python ELF parsing (`struct.unpack_from`), no lief, no Capstone dependency. Enables identifying polymorphic sinks without RTTI or debug symbols.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_ELF_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard in `__init__()` before `f.read()`; `_MAX_ELF_BYTES=256MB`. Pure-Python ELF parser, no lief.parse(). No HTTP reads. `c++filt` subprocess uses `timeout=2`.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

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
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

---

## Reading output

`ELFVtableReconstructor.from_path(path).reconstruct_class('ClassName')` returns a `VtableMap`. Access individual slots via `vtable_map.slots` (a `Dict[int, VtableSlot]` keyed by byte offset from `vtable_ptr`):

`VtableMap` attributes:

| Attribute | Content |
|:---|:---|
| `vtable_va` | VA of the vtable data in the binary |
| `vtable_ptr` | VA that class instances store as their vtable pointer |
| `class_name` | Demangled class name (empty if not available) |
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

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
