# ReloObjectContext

Parse ELF32 relocatable object files (.o): extract functions, call graph (via RELA), imports, and annotated disassembly.

---

## Why this exists

1. **BinaryContext fails on .o files.** `BinaryContext.load_or_build()` returns `base_va=0xffffffffffffffff` and zero `func_starts` for any ELF32 ET_REL input. It is designed for linked ELFs with PLTs and absolute virtual address spaces.
2. **VxWorks PPC32 firmware ships as static libraries.** `solidac.a` contains 666 PPC32 BE relocatable objects. All addresses are section-relative; all external calls use `lis rX / addi rX / mtctr rX / bctrl` with RELA annotations, not `bl <plt_va>`.
3. **RELA annotations pre-annotate every external call.** In a `.o` file, `R_PPC_ADDR16_HA` at `lis+2` names the external symbol. This is richer than a PLT stub — we know the symbol name directly from the RELA table, no reverse-lookup needed.

Gap ID: RELO-GAP-001 (solidDB VxWorks PPC440 solidac.a analysis).

---

## How it works

1. Parses the ELF32 header: endianness, architecture, section table.
2. Reads `.symtab`/`.strtab`: builds function list (STT_FUNC + named STT_NOTYPE with size>0 in `.text`).
3. Parses all `.rela.text` sections: builds `rela_map[insn_offset] = (sym_name, is_rodata)`.
   - R_PPC_ADDR16_HA (type 6): `insn_offset = r_offset - 2` (byte 2 of the `lis` instruction is patched).
   - R_PPC_REL24 (type 10): `insn_offset = r_offset` (full instruction for `bl` to local symbols).
   - `is_rodata = True` when the reloc's symbol section index points to a `.rodata*` section.
4. Infers function sizes from symbol table; fills zero-size entries from next-symbol distance.
5. Initializes capstone for PPC32 BE disassembly (optional; degrades gracefully without it).

---

## ReloObjectContext

```python
from ablation.analyzers.relo_object_context import ReloObjectContext

ctx = ReloObjectContext.from_path('/path/to/rpc0http.o')
# or from bytes:
ctx = ReloObjectContext(data=raw_bytes, path='<label>')
```

### Key methods

| Method | Returns | Description |
|:---|:---|:---|
| `functions()` | `List[ReloFunction]` | All functions defined in .text, sorted by offset |
| `function_names()` | `List[str]` | Just the names |
| `imports()` | `List[str]` | All external symbol names (SHN_UNDEF) |
| `exports()` | `List[str]` | All globally-defined symbol names |
| `has_import(sym)` | `bool` | Fast membership test |
| `calls_in(fn_name)` | `List[ReloCall]` | External/local calls within a function (from RELA) |
| `functions_calling(sym)` | `List[str]` | Function names that reference `sym` |
| `rela_map()` | `Dict[int, Tuple[str, bool]]` | Raw annotation map |
| `text_bytes(fn_name)` | `(bytes, int)` | Raw bytes + section-relative offset for a function |
| `disasm(fn_name, annotated=True)` | `str` | Annotated capstone disassembly |
| `summary()` | `str` | One-line summary |

### ReloFunction fields

| Field | Type | Description |
|:---|:---|:---|
| `name` | `str` | Symbol name |
| `offset` | `int` | Section-relative byte offset in `.text` |
| `size` | `int` | Size in bytes (inferred if zero in symtab) |
| `binding` | `str` | `'global'`, `'local'`, or `'weak'` |

---

## Usage

```python
from ablation.analyzers.relo_object_context import ReloObjectContext

ctx = ReloObjectContext.from_path('rpc0http.o')
print(ctx.summary())
# → ReloObjectContext(rpc0http.o): PPC32 BE, 3 functions, 8 imports, .text=3444B

for fn in ctx.functions():
    print(f'{fn.name}  +{fn.offset:#x}  {fn.size}B  [{fn.binding}]')

# Find all functions that call strcpy
for fn_name in ctx.functions_calling('strcpy'):
    print(f'  strcpy caller: {fn_name}')

# Detailed call list for a specific function
for call in ctx.calls_in('rpc_http_svc_get'):
    print(f'  +{call.insn_offset:#x} → {call.sym_name}')

# Annotated disassembly
print(ctx.disasm('rpc_http_svc_get'))
```

---

## Example output

```
ReloObjectContext(rpc0http.o): PPC32 BE, 3 functions, 8 imports, .text=3444B

rpc_http_svc_get  +0x70  1244B  [global]
getword           +0x000  112B   [local]
getline           +0x560  80B    [local]

; rpc_http_svc_get  +0x000070  size=1244  [global]
  000070  mflr       r0
  000074  stmw       r22, -0x28(r1)
  ...
  000148  lis        r9, 0           ← strcpy
  00014c  addi       r9, r9, 0
  ...
  00016c  bctrl

calls in rpc_http_svc_get:
  +0x148 → strcpy
  +0x180 → rpc_ses_read
  +0x208 → getword
```

---

## False positives

**None for `calls_in()`**: RELA annotations are authoritative — the linker will use them to patch the call target. Every entry in `calls_in()` corresponds to an actual external reference.

**STT_NOTYPE size=0 filtered**: Labels and jump table markers are excluded from `functions()` by the `st_size == 0` guard.

---

## Pipeline position

**Before:** Run `ArchiveContext.from_path()` to extract members from a `.a` file first.

**After:** Feed into `ReloSinkArgClassifier` for argument provenance, or use `calls_in()` directly for call-graph analysis.

---

## See also

- [ReloSinkArgClassifier](relo-sink-arg-classifier.md): classify exec-sink argument provenance in .o files
- [ArchiveContext](archive-context.md): cross-object queries across a static library
- [ar-archive-scanner](ar-archive-scanner.md): exec-class scan for linked ELFs inside .a archives
