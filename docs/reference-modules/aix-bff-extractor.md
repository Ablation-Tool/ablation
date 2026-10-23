# AixBffExtractor / XCOFF32Info

Extract XCOFF binaries from AIX installp BFF archives by magic-scan, and enumerate dangerous imports directly from the XCOFF32 loader section: without needing AIX or a working `pax(1)`.

---

## Why this exists

1. **No standard Linux tool can extract AIX installp BFF archives.** `pax(1)` requires AIX. `restore(8)` requires AIX tape devices. GNU `tar` does not understand the BFF container format and fails silently. Before this module, every IBM AIX installp package (`.bff`) was opaque to the analysis chain. Trigger: gap ID `CSMSAMRD-GAP-002`.

2. **The outer BFF envelope does not need to be fully parsed.** BFF archives contain XCOFF binaries at 4-byte-aligned offsets. The XCOFF32 magic bytes (`0x01\xdf`) are reliably distinct. The module locates every XCOFF binary by magic scan, validates the `FILHDR`, computes the binary extent from section headers and symbol table layout, and returns raw XCOFF bytes. No BFF block-structure parser required.

3. **Dangerous import triage requires no AIX environment.** The XCOFF32 loader section (section type `0x0005`) contains an import ID table: null-separated `path/archive/member` strings, that names every dynamically linked function. `XCOFF32Info.dangerous_imports()` scans this table for exec-class and network-class function names. The entire pipeline runs on Linux.

4. **AixBffExtractor and aix_big_ar_extractor address different formats.** `aix_big_ar_extractor` handles AIX `<bigaf>` library archives (shared libraries distributed as `libc.a`, `libm.a`). This module handles AIX installp BFF packages OS components, management agents. Both embed XCOFF binaries; only the outer container differs.

---

## How it works

```
AixBffExtractor.from_path('/path/to/pkg.bff')
         │
         ├── Read raw bytes
         └── Magic scan loop:
             ├── Find next 0x01df (XCOFF32) or 0x01f7 (XCOFF64) at 4-byte-aligned offset
             ├── Validate FILHDR: nscns, f_symptr, f_nsyms
             ├── Compute binary extent:
             │   last_section_end = max(s_scnptr + s_size) across all section headers
             │   extent = max(last_section_end, f_symptr + f_nsyms × 18 + strtab_size)
             └── Yield (name, xcoff_bytes): name derived from XCOFF symbol table or offset

XCOFF32Info(xcoff_bytes)
         │
         ├── Parse FILHDR: f_nscns, f_symptr, f_nsyms, f_opthdr
         ├── Locate loader section (s_flags & 0x0005)
         ├── Parse loader header: l_nsyms, l_nimpid, l_impoff
         ├── Read import ID table: null-separated path/archive/member strings
         └── dangerous_imports(): filter by exec/net sink name set
```

---

## Usage

**Extract and triage a complete BFF package:**
```python
from ablation.analyzers.aix_bff_extractor import AixBffExtractor, XCOFF32Info

for name, xcoff_bytes in AixBffExtractor.from_path('/path/to/IBM.RecoveryRMd.bff'):
    info = XCOFF32Info(xcoff_bytes)
    dangerous = info.dangerous_imports()
    if dangerous:
        print(f'{name}: DANGEROUS imports → {dangerous}')
        info.save(f'/tmp/{name}')
    else:
        print(f'{name}: clean ({info.nsyms} symbols)')
```

**Find call-stub VAs and callers for a specific import:**
```python
from ablation.analyzers.aix_bff_extractor import XCOFF32Info

info = XCOFF32Info.from_path('/tmp/IBM.RecoveryRMd.aix')
stubs = info.import_stubs()         # {'.system': 0x10143d74, '.popen': 0x10143dc4, ...}
callers = info.callers_of(stubs['.system'])   # [0x10140e44, 0x1014a200, ...]

for va in callers:
    print(f'  system() called from 0x{va:x}')
```

**Integration with BinaryContext for full analysis:**
```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.aix_bff_extractor import AixBffExtractor, XCOFF32Info

for name, xcoff_bytes in AixBffExtractor.from_path('/path/to/pkg.bff'):
    info = XCOFF32Info(xcoff_bytes)
    if not info.dangerous_imports():
        continue

    # Save and load into BinaryContext
    path = f'/tmp/{name}'
    info.save(path)
    ctx = BinaryContext.load_or_build(path)

    # Populate names from .symtab
    from ablation.analyzers.xcoff_symtab_parser import XcoffSymtabParser
    XcoffSymtabParser.from_context(ctx).scan()
```

---

## XCOFF32Info fields and methods

| Method / Property | Return type | Content |
|:---|:---|:---|
| `dangerous_imports()` | `list[str]` | Import names matching exec/net sink sets |
| `import_stubs()` | `dict[str, int]` | Map of `.funcname` → stub VA in `.text` |
| `callers_of(va)` | `list[int]` | VAs of BL instructions targeting `va` |
| `save(path)` |: | Write the raw XCOFF bytes to a file |
| `nsyms` | `int` | Number of symbol table entries |

---

## Dangerous import detection

| Family | Functions checked |
|:---|:---|
| EXEC | `system`, `popen`, `fork`, `vfork`, `execve`, `execvp`, `execl`, `execle`, `execvpe`, `posix_spawn`, `posix_spawnp` |
| NET | `socket`, `bind`, `connect`, `recv`, `send`, `gethostbyname`, `getaddrinfo` |

The import ID table uses dotted names (`.system`, `.popen`). The scanner strips the leading dot before comparing.

---

## Limitations

**Incomplete BFF downloads produce false structure.** If a `.bff` file was incompletely downloaded (e.g., an `.aria2` partial-download file is present alongside it), the magic scan may locate partial XCOFF headers. Always check the IBM-RE download status table in `README.md` before analyzing an image: incomplete downloads are flagged with `.aria2` files in the research collection.

**XCOFF64 extent computation is approximate.** 64-bit XCOFF headers use a different field layout. The extent estimate for XCOFF64 binaries may be imprecise. Verify that extracted bytes produce a valid XCOFF64 header before passing to downstream tools.

**Symbol table name extraction is the `from_scan` path only.** When called via `AixBffExtractor.from_path()`, the binary name is derived from the XCOFF symbol table's first external symbol or from the file offset (`xcoff_at_0x{offset:x}`). The original installp path component from the BFF file list is not recovered.

---

## Pipeline position

**Before:** Verify download completeness (no `.aria2` alongside `.bff`). Run `AixBffExtractor.from_path()` as the first step on any `.bff` package file.

**After:** For each XCOFF with dangerous imports, save the binary and load with `BinaryContext.load_or_build()`. Then run `XcoffSymtabParser`, `Xcoff32Decompiler`, and `SinkArgClassifier` in sequence.

---

## See also

- [XcoffSymtabParser](xcoff-symtab-parser.md): populate BinaryContext with function names after extraction
- [Xcoff32Decompiler](xcoff32-decompiler.md): decompile XCOFF32 functions to pseudocode
- [BFF Extractor](bff-extractor.md): an alternative extractor with a different outer-format approach
- [AIX Big Archive Extractor](aix-big-ar-extractor.md): for `<bigaf>` shared library archives (libc.a)
