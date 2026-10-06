# C++ Vtable Reconstructor

Standalone three-layer pipeline for reconstructing C++ virtual dispatch from any ELF
binary. No IDA license. No relocation requirement. Runs at sweep scale.

---

## Why this exists

The standard Hex-Rays workflow for virtual dispatch: find the vtable, `set_type` the
producer function return, then manually `set_type` every consumer local that receives the
pointer — one variable at a time. The decompiler does not propagate struct types from a
producer's return value to the callers' locals automatically; every step in the chain must
be touched by hand.

`CppVtableReconstructorAnalyzer` replaces all three IDA steps with a single Python call:

1. **VtableScanner** — finds vtables in any ELF using RELA relocations (dynamic) or
   code-pointer scanning (static)
2. **VtableNamer** — names each slot from export symbols, BinaryContext function names,
   string literals, and callee patterns
3. **CppTypeTracker** — finds every call site that dispatches through any named slot;
   groups by enclosing function

Output: a JSON-serialisable result object **and** an IDAPython script that emits
`idc.parse_decls()` + `idc.set_cmt()` for the full producer→consumer chain in one pass.

---

## Module

**File:** `ablation/analyzers/cpp_vtable_reconstructor.py`

**Relationship to existing vtable modules:**

| Module | Arch | Discovery | Naming | Call sites | IDAPython |
|---|---|---|---|---|---|
| `ELFVtableReconstructor` | x86-64 only | `.rela.dyn` by class name or VA | ✗ | ✗ | ✗ |
| `VtableResolver` | ARM64 | `.data.rel.ro` RELATIVE relocs | ✗ | BLR sites | ✗ |
| `VtableDispatchScanner` | x86-64 | ✗ (takes slot map) | ✗ | `call [reg+disp]` | ✗ |
| **`CppVtableReconstructorAnalyzer`** | **any ELF** | **RELA + byte scan** | **✓** | **x86-64 + ARM64** | **✓** |

---

## Usage

```python
from ablation.analyzers.cpp_vtable_reconstructor import CppVtableReconstructorAnalyzer

# Minimum viable (no BinaryContext)
analyzer = CppVtableReconstructorAnalyzer.from_path('/path/to/lib.so')
result   = analyzer.scan()

print(CppVtableReconstructorAnalyzer.report(result))
print(CppVtableReconstructorAnalyzer.emit_ida_script(
          result.vtables, result.propagation))

# Full — with BinaryContext for slot naming
ctx      = BinaryContext.load_or_build('/path/to/lib.so')
analyzer = CppVtableReconstructorAnalyzer.from_context(ctx)
result   = analyzer.scan()
```

---

## Three-layer pipeline

### Layer 1 — `scan_vtables(min_slots=3)`

Extracts vtable specs from the binary.

**Primary method (RELA-based):** iterates all ELF relocations and collects entries whose
addend points into an executable section (a virtual function) and whose address is in a
data section (a vtable slot). Groups consecutive 8-byte-aligned entries into runs of
`min_slots` or more — each run is one vtable.

This approach works for all dynamic ELFs regardless of architecture: x86-64, ARM64,
LoongArch64, PPC64, etc. It requires no knowledge of the relocation type.

**Fallback method (byte scan):** when no RELA runs are found (static binary or non-PIE
executable), scans `.rodata` / `.data.rel.ro` / `.data` for runs of 8-byte values that
point into `.text`. Correct for PIE ELF where `virtual_address == file_offset` for all
sections.

Each `VtableSpec` records:
- `va` — the vtable pointer address (vfunc[0], what's stored in objects)
- `slots` — ordered `SlotSpec` list with index, byte offset, function VA, name
- `has_itanium_header` — True when the 16 bytes before `va` look like offset-to-top=0 +
  RTTI pointer (standard Itanium ABI vtable layout)
- `ctor_sites` — VAs in the binary that reference this vtable VA (from relocations or
  literal byte scan)

### Layer 2 — `name_slots(specs)`

Names each slot in place. Attempts in order:

1. **Export / symtab symbol** — direct match on `func_va`
2. **BinaryContext confirmed name** — from prior RE session `ctx.set_name()` calls
3. **String literal xref** — if the function body references a string like `"modexp"`,
   the slot is named `"modexp"` (filtered: no spaces, no `%`, 3–32 chars)
4. **Named callee** — if the function calls e.g. `BN_mod_exp`, the slot is named
   `"mod_exp"` after stripping the `BN_` prefix

The vtable type name is inferred from the longest common prefix of all named slots,
e.g., `rsa_init` / `rsa_free` / `rsa_compute` → `rsa_vtable`.

### Layer 3 — `trace_consumers(spec)`

Finds call sites that dispatch through any slot of `spec`.

**x86-64:** delegates to `VtableDispatchScanner` — pattern-matches all
`call [reg+slot_offset]` encodings (REX prefix variants, disp8/disp32, SIB r12/rsp).
Groups call sites by enclosing function using the binary's symbol table.

**ARM64:** delegates to `vtable_resolver.detect_blr_sites()` — finds
`LDR vptr / LDR slot / BLR` instruction windows.

**Other architectures:** `trace_consumers()` returns `[]` — vtable extraction and naming
work, call-site tracing is not yet implemented.

---

## IDAPython script

`emit_ida_script(specs, propagation)` generates a script that:

1. Calls `idc.parse_decls()` with a C struct definition for each vtable
2. Calls `idc.set_cmt()` at every ctor reference site (`"vptr → <type_name>"`)
3. Calls `idc.set_cmt()` at every resolved call site (`"<type>-><slot>(...)"`)

```python
script = CppVtableReconstructorAnalyzer.emit_ida_script(
    result.vtables, result.propagation)

# Write to file for IDA
with open('/tmp/vtable_types.py', 'w') as f:
    f.write(script)
```

Paste into IDA's Python console or run via **File → Script file**. After the struct is
declared, calling `idc.set_type()` on any producer function in IDA 8.x+ allows the
decompiler to auto-propagate the struct type to local variables through the call graph.

---

## Output format

```python
@dataclass
class VtableSpec:
    va: int                 # vtable_ptr VA (vfunc[0])
    slots: List[SlotSpec]   # ordered; slot_offset = slot_index * 8
    type_name: str          # inferred, e.g. 'rsa_alg_vtable'
    ctor_sites: List[int]   # VAs referencing this vtable in the binary
    has_itanium_header: bool

@dataclass
class SlotSpec:
    slot_index: int
    slot_offset: int        # = slot_index * 8
    func_va: int
    func_name: str          # '' if unresolved
    name_source: str        # 'export' | 'ctx_name' | 'string_xref' | 'callee_name' | 'unknown'

@dataclass
class TypePropSite:
    func_va: int
    func_name: str
    role: str               # 'consumer'
    slot_calls: List[Tuple[int, int, str]]
    # each entry: (call_pc, slot_index, slot_name)
```

---

## Example output

```
CppVtableReconstructorAnalyzer  /path/to/libossl.so
arch=x86_64  vtables=3  slots=18  named=14  call_sites=27

VTable  rsa_alg_vtable  @ 0x004a8200  [5 slots]  [Itanium ABI header]
  vptr refs: 0x9f120, 0xa0340
  slot  0  +0x000  0x00012340  init    [export]
  slot  1  +0x008  0x00012380  clone   [export]
  slot  2  +0x010  0x000124e0  free    [export]
  slot  3  +0x018  0x00013450  modexp  [callee_name]
  slot  4  +0x020  0x00013560  mul_mont[string_xref]

Call Sites:
  rsa_modexp_compute @ 0x00056780  [consumer]
    0x000568a0  slot 3  → modexp
    0x000568c4  slot 4  → mul_mont
```

---

## Limitations

- **ET_EXEC (non-PIE) binaries**: the byte scan fallback assumes `virtual_address ==
  file_offset`. For executables loaded at a high base (e.g., `0x400000`), the fallback
  will produce incorrect file offsets. The RELA-based method works correctly regardless.
- **Slot naming without ctx**: only export/symtab symbols are used. Pass a `BinaryContext`
  for string-xref and callee-name naming.
- **Consumer tracing on non-x86-64/ARM64**: returns empty; call-site tracing is not
  implemented for LoongArch64, MIPS, PPC, etc.
- **High FP rate on wide scan**: when `min_slots=1` and many vtables are in scope, the
  VtableDispatchScanner call-site count grows because offset 0x00 / 0x08 appear in many
  unrelated indirect calls. Restrict to a single vtable with `trace_consumers(spec)`.
- **Stripped anonymous vtables**: vtables without any context (no exports, no strings, no
  BinaryContext) remain as `vtable_XXXXXXXX` with unnamed slots. Run `name_slots()` again
  after accumulating confirmed function names via `ctx.set_name()`.

---

## Release notes

Added in v2.41.0.
