# ti-coff-loader

## Why this exists

3 things that weren't possible before in Ablation:

1. **No parser could read TI COFF2 object files or AR archives.** The TI Code Generation
   Tools (cl2000, c29clang) produce COFF, not ELF. All existing Ablation binary loaders
   rely on lief, which does not support TI COFF. The C28x DSP target — used in F28P55x
   MCUs and compiled by the TI NNC for EdgeAI Studio deployments — was entirely opaque.

2. **The weak-symbol risk in NNC-generated C28x firmware was undetectable.** TI COFF
   has no `STB_WEAK` binding (ELF concept); instead, `__attribute__((weak))` maps to
   storage class `C_UEXT = 19` (tentative external definition). This storage class
   appears in the COFF symbol table and allows a strong `C_EXT` symbol of the same name
   to override it at link time. Without a COFF parser, `TiNNCScanner` could not surface
   this risk for C28x targets.

3. **AR archive traversal for COFF members was not implemented.** The TI NNC emits `mod.a`
   as a Unix AR archive containing COFF2 `.obj` members. Walking the archive, skipping
   the AR symbol-table members (`/` and `//` names), and correctly aligning to even-byte
   boundaries was not handled by any existing Ablation code path.

---

## What it does

`TiCoffLoader` parses Texas Instruments COFF2 object files and Unix AR archives whose
members are COFF2 objects. It extracts symbol table entries for all members, exposing
the name, value (address), section binding, and storage class of each symbol.

Primary consumer: `TiNNCScanner` — which uses `TiCoffLoader` to detect NNC inference
artifacts and normalization override risk in C28x firmware (TINCC-001 through TINCC-004).

**Supported formats:**

| Format | Detection |
|---|---|
| TI COFF2 standalone object | magic `0x00C2` at bytes 0-1 |
| TI COFF1 standalone object | magic `0x00C1` at bytes 0-1 |
| Unix AR archive (COFF2 members) | magic `!<arch>\n` at bytes 0-7 |

**Storage class semantics:**

| Class | Value | Meaning in TI COFF | ELF equivalent |
|---|---|---|---|
| `C_EXT` | 2 | Strong global definition | `STB_GLOBAL` |
| `C_STAT` | 3 | Static (local) symbol | `STB_LOCAL` |
| `C_EXTREF` | 5 | Undefined external reference | `STB_GLOBAL` (undefined) |
| `C_UEXT` | 19 | Tentative external — overrideable at link time | `STB_WEAK` |

There is no `C_WEAKEXT` in TI COFF. The cl2000 compiler maps `__attribute__((weak))`
to `C_UEXT` (confirmed from SPRAAO8 Table 18).

---

## Usage

```python
from ablation.analyzers.ti_coff_loader import TiCoffLoader, C_UEXT

loader = TiCoffLoader.from_path('/path/to/mod.a')   # AR archive
# or:
loader = TiCoffLoader.from_path('/path/to/tvmgen_default.obj')   # standalone COFF2

for sym in loader.symbols():
    print(sym.name, sym.storage_class_name, hex(sym.value), sym.is_weak)

# Inspect individual AR members
for obj in loader.objects():
    print(obj.member_name, obj.header.target_name)
    for sym in obj.symbols:
        if sym.is_weak:
            print(f'  WEAK: {sym.name}')
```

`from_path()` raises `FileNotFoundError`, `PermissionError`, or `OSError` if the file
cannot be read. The caller is responsible for catching these.

---

## Format reference

COFF2 file header (22 bytes, little-endian):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | `f_magic` | 0x00C2 for COFF2 |
| 2 | 2 | `f_nscns` | section count |
| 4 | 4 | `f_timdat` | timestamp |
| 8 | 4 | `f_symptr` | file offset to symbol table |
| 12 | 4 | `f_nsyms` | number of symbol entries |
| 16 | 2 | `f_opthdr` | optional header size |
| 18 | 2 | `f_flags` | flags |
| 20 | 2 | `f_target_id` | 0x009D = C28x |

Symbol table entry (18 bytes, little-endian):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `name` | inline or (0x00000000 + strtab offset) |
| 8 | 4 | `value` | address or size |
| 12 | 2 | `scnum` | section number (0=undef, -1=abs, 1+=section) |
| 14 | 2 | `type` | type bits |
| 16 | 1 | `sclass` | storage class |
| 17 | 1 | `numaux` | number of auxiliary entries following |

String table: immediately follows the symbol table at `sym_ptr + n_syms * 18`. First
4 bytes are the string table size. Long symbol names are stored as 8-byte `\x00\x00\x00\x00`
prefix + 4-byte string table offset.

---

## Target IDs

| `f_target_id` | Target |
|---|---|
| `0x009D` | TMS320C2800 (C28x — NNC F28x target) |
| `0x0099` | TMS320C6000 |
| `0x009C` | TMS320C5500 |
| `0x00A1` | TMS320C5500+ |
| `0x00A0` | MSP430 |

Reference: SPRAAO8 — TI Common Object File Format (April 2009).
