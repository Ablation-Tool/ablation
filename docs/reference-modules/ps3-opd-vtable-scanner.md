# PS3 OPD Vtable Scanner

C++ vtable discovery for PS3 Cell PPU (PPC64) binaries. Resolves the two-level
OPD indirection and injects confirmed function names into BinaryContext.

---

## Why this exists

Three things weren't possible before in Ablation:

**1. Finding any C++ vtables in PS3 PPC64 binaries.** `CppVtableReconstructorAnalyzer`
scans for RELA relocations and direct 8-byte text pointers. PS3 Cell PPU binaries use
PPC64 ELF ABI v1 function descriptors (OPDs): every vtable slot is a 4-byte pointer
into the data segment that resolves to an 8-byte `{code_va, toc_va}` OPD entry. No
RELA section, no direct text pointers: zero vtables returned.

**2. Locating Demonware BD and other inline-linked C++ class dispatch tables in stripped
PS3 game binaries.** Without vtables there is no way to find `processPacket` or
`processRelayPacket` implementations short of exhaustive manual disassembly.

**3. Resolving two-level OPD indirection automatically.** `vtable_ptr → OPD entry →
code_va`. Once resolved, code VAs are injected into BinaryContext as confirmed function
names and cross-referenced with nearby string evidence to identify the owning class.

---

## Module

**File:** `ablation/analyzers/ps3_opd_vtable_scanner.py`

**Relationship to existing vtable modules:**

| Module | Arch | Discovery | OPD indirection | Naming | Injection |
|---|---|---|---|---|---|
| `ELFVtableReconstructor` | x86-64 | `.rela.dyn` | ✗ | ✗ | ✗ |
| `VtableResolver` | ARM64 | `.data.rel.ro` | ✗ | ✗ | BLR sites |
| **`PS3OPDVtableScanner`** | **PPC64 PS3** | **OPD dense-run scan** | **✓** | **string proximity** | **✓** |

---

## Usage

```python
from ablation.analyzers.ps3_opd_vtable_scanner import PS3OPDVtableScanner

# From BinaryContext (recommended)
scanner = PS3OPDVtableScanner.from_context(ctx)
vtables = scanner.scan(min_slots=3)
print(scanner.report(vtables, ctx))
scanner.inject_into_context(vtables, ctx)

# From path directly
scanner = PS3OPDVtableScanner.from_path('/path/to/eboot.elf')
vtables = scanner.scan()
print(scanner.report(vtables))

# Dual-TOC binary: scan each module separately
scanner_game = PS3OPDVtableScanner.from_context(ctx, toc=0xAD49B8)  # r2_game
scanner_bd   = PS3OPDVtableScanner.from_context(ctx, toc=0xAE4894)  # r2_BD
vtables = scanner_game.scan() + scanner_bd.scan()
```

---

## OPD format

Each OPD entry in the data segment at VA `p`:
```
code_va = u32 BE at p+0    (must be in text segment)
toc_va  = u32 BE at p+4    (constant per module)
```

Vtable slots are 4-byte data-VA values pointing to OPD entries. The scanner:
1. Walks the data segment in 4-byte strides
2. Treats each word as a potential OPD pointer
3. Validates: OPD target in data, `code_va` in text, `toc_va == toc`
4. Collects consecutive valid pointers into runs of `min_slots` or more

---

## Dual-TOC binaries

PS3 games that statically link multiple C++ modules have two TOC values. `_detect_toc()`
returns the majority TOC from the first 64 OPD entries near the ELF entry point. To
scan both modules, pass `toc=` explicitly for each and merge the results.

---

## API reference

### `PS3OPDVtableScanner`

**`from_context(ctx, toc=None)`**: preferred constructor. Reads path from ctx, detects
text/data layout, detects TOC and null stub automatically.

**`from_path(elf_path, toc=None)`**: build from raw path without BinaryContext.

**`scan(min_slots=3)`** → `List[OPDVtable]` sorted by VA. Lower `min_slots` catches more
single-method base classes at the cost of more false positives.

**`report(vtables, ctx=None, top_n=50, min_slots=0)`** → ASCII table sorted by slot count
descending.

**`inject_into_context(vtables, ctx)`** → `int`: injects `vtbl_<va>_s<N>` names for all
non-null, unnamed slots. Returns count of new names added.

**`find_by_method_name(vtables, name, ctx)`** → `List[(vtable, slot_idx, code_va)]`: locate which vtables contain a named method.

### `OPDVtable` dataclass

| Field | Type | Description |
|---|---|---|
| `va` | `int` | Data VA of first vtable slot |
| `slots` | `int` | Number of virtual method slots |
| `method_vas` | `List[int]` | Resolved code VAs per slot |
| `null_slots` | `List[int]` | Slot indices pointing to null/pure-virtual stub |
| `rtti_offset` | `int` | Bytes before `va` where RTTI header starts (8 or 0) |
| `class_hint` | `str` | Nearest string within 256 bytes, if any |

---

## Validated on

- GoldenEye 007: Reloaded (BLUS30755): 3185 vtables found; processPacket dispatch
 located via `find_by_method_name`; Demonware BD class hierarchy mapped

---

## Gaps and limitations

- Single `toc=` per scan: dual-TOC binaries require two separate scan calls
- Class hint is proximity-based (nearest string ≤256 bytes); accurate for well-laid-out
 data segments, unreliable when strings and vtables are interleaved
- RTTI header detection requires `offset-to-top == 0 or 0xFFFFFFFF`: non-standard
 compilers may use other values

---

## How it works

`PS3OPDVtableScanner.scan()` finds C++ vtables in PS3 Cell PPU (PPC64 BE) binaries. `CppVtableReconstructorAnalyzer` cannot handle PPC64 vtables because vtable slot entries are OPD pointers (pointing to a function descriptor in `.opd`, not directly to the function's code). This scanner first resolves the OPD section to build a `{opd_va: code_va}` map, then scans `.rodata` for arrays of OPD pointers that follow the `type_info` pointer pattern. Returns `List[PS3Vtable]` with slot VAs resolved to code addresses.

---

## Example output

```
# PS3OPDVtableScanner.report(vtables):
PS3 OPD vtable scan — 47 vtables found
  toc=0x80500000  null_stub=0x80401234

  VA              slots  null  hint                                      first_methods
  ----------------------------------------------------------------------------------------------------
  0x805a0200          9     0  CNetworkManager                           0x80412000  0x80412080  0x804120c0
  0x805a0240          6     1  CSocketBase                               0x8041b000  0x8041b100
  0x805a0280          4     0                                            0x80422000  0x80422040
```

---

## False positives

Symbol resolution errors produce phantom function boundaries. Verify any candidate VA against `ctx.func_starts` before analysis. Compiler-synthesized stubs (PLT entries, thunks) appear as functions in some loaders — `BinaryContext` filters known stub patterns but custom thunks may slip through.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` for symbol and import resolution. For stripped binaries, run `SemanticSearcher` first to identify candidate function VAs.

**After this module:** Pass resolved call edges and function VAs to `TaintTracker` or `SinkArgClassifier`.

---

## Reading output

`PS3OPDVtableScanner(binary).scan(min_slots=3)` returns `List[OPDVtable]`.

| Field | Type | Content |
|:---|:---|:---|
| `va` | `int` | Data-segment VA of the first vtable slot (past the RTTI header) |
| `slots` | `int` | Number of virtual method slots |
| `method_vas` | `List[int]` | Resolved code VAs per slot (in slot order) |
| `null_slots` | `List[int]` | Slot indices (not VAs) of null-stub (deleted/pure-virtual) slots |
| `rtti_offset` | `int` | Bytes before `va` where the RTTI header starts |
| `class_hint` | `str` | Nearest string evidence for class identity (empty if none found) |

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
