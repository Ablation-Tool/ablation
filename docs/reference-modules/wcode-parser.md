# WCodeParser

## Why this exists

Three numbered gaps in the IBM XLC RE workflow motivated this module:

1. **No W-Code record decoder.** `WcB_Lookup_Bif` in xlCentry 16.1.1.3 parses W-Code binary records using `lwbrx`/`lhbrx` (byte-reversed loads), confirming on-disk big-endian encoding. No Ablation tool handled this format.

2. **No builtin catalog loader.** The WCB table at `0x12601960` in xlCentry encodes 2000+ IBM POWER intrinsic descriptors with POWER-generation arch masks. Extracting it required understanding the table stride (0x28) and name-pointer layout, none of which was previously documented or automated.

3. **No hash function.** `WcB_Name_Hash` (0x11d88e40) implements `h = h*31 + c` via `sldi r7,r0,5; subf r0,r0,r7; add r0,r0,r8`. Ablation had no implementation of this idiom, blocking name-based catalog lookups.

---

## Format reference

### W-Code binary builtin record (big-endian on disk)

```
+0x00  uint32 BE   type_field_0    compared against WCB entry +0x00 via lwbrx
+0x04  uint32 BE   type_field_1    compared against WCB entry +0x08 via lwbrx
+0x08  uint16 BE   type_field_2    compared against WCB entry via lhbrx
+0x0a  char[]      builtin_name    null-terminated; leading underscores stripped
```

Short form: if record length ≤ 10, the 3-field header comparison is skipped.

### WCB table entry (little-endian in xlCentry memory, stride 0x28)

```
+0x00  uint64 LE   field_0 (type ID)
+0x08  uint64 LE   field_8 (parameter info)
+0x10  uint64 LE   name_ptr (→ null-terminated name in names pool at 0x11fe6010)
+0x18  uint32 LE   arch_mask (0=any POWER, 8=POWER8+, 9=POWER9+, ...)
+0x1c  uint32 LE   pad
+0x20  uint64 LE   field_20 (additional type info)
```

### Hash function

```python
def name_hash(name):
    h = 0
    for c in name.encode('ascii'):
        h = ((h * 31) + c) & 0xFFFFFFFF
    return h
```

Assembly: `sldi r7, r0, 5; subf r0, r0, r7; add r0, r0, r8` = `r0 = r0 - (r0<<5) + c = r0*(1-32) + c = r0*(-31) + c`, with `slwi r0, r0, 0` to truncate to 32 bits → `h*31 + c` mod 2³².

---

## xlCentry 16.1.1.3 constants

| Symbol | VA |
|---|---|
| WCB table base | `0x12601960` |
| WCB entry count | 2000+ |
| Names pool | `0x11fe6010` |
| Hash table descriptor | `0x126a96c0` (TOC + 0x416c0) |
| `WcB_Validate_Arch` | `0x11d84000` |
| `WcB_Lookup_Bif` | `0x11d88d00` |
| `WcB_Lookup_Bif2` | `0x11d88840` |
| `WcB_Name_Hash` | `0x11d88e40` |
| `WcB_Number_of_Fixed_Parameters` | `0x11d84460` |

---

## API

```python
from ablation.analyzers.wcode_parser import WCodeParser, WCodeBuiltinCatalog, WCodeRecord, WCBEntry
```

### `WCodeParser(xlcentry_path=None)`

Main entry point.

- `WCodeParser.decode_record(data, offset=0) → WCodeRecord | None`: decode one record from bytes
- `WCodeParser.name_hash(name) → int`: compute 32-bit hash for name lookup
- `parser.load_catalog() → WCodeBuiltinCatalog`: load WCB table from xlCentry binary
- `parser.scan(data) → List[WCodeRecord]`: best-effort scan of a byte stream
- `parser.report(records=None, data=None) → str`: human-readable summary

### `WCodeBuiltinCatalog`

- `WCodeBuiltinCatalog.from_binary(xlcentry_path) → WCodeBuiltinCatalog`: load from ELF binary
- `catalog.lookup(rec) → WCBEntry | None`: look up by WCodeRecord name
- `catalog.lookup_name(name) → WCBEntry | None`: look up by string name
- `catalog.arch_mask_to_name(arch_mask) → str`: decode arch_mask to POWER generation string
- `len(catalog)`: number of entries loaded

### `WCodeRecord` (dataclass)

Fields: `type_field_0`, `type_field_1`, `type_field_2`, `name`, `raw`, `short_form`

### `WCBEntry` (dataclass)

Fields: `index`, `name`, `arch_mask`, `field_0`, `field_8`, `field_20`, `name_ptr`

---

## Workflow position

```
SemanticSearcher → ... → WCodeParser (IBM W-Code IR files or XLC-compiled .o files)
```

Use after identifying a binary was compiled with IBM XLC (xlCentry/xlCcode toolchain marker).
Complements `wc2llvm` entry-point RE for full W-Code IR file format coverage (XLC-GAP-002).
