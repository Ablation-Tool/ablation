# pef-binary-analyzer

## Why this exists

Three things were not possible before in Ablation:

1. **PPC32TaintTracker cannot load PEF files.** It requires ELF. All PEF CFM PPC32 Mac Classic binaries PGPuam, PGPuam Server, Tool_Chest networking utilities required manual analysis because there was no PEF-aware loader in ablation.

2. **CFM import stub resolution was re-derived every session.** Each session re-computed the RTOC-offset formula (`sym[i]` → `i*4` from r2), manually identified stub VAs in the code section, and mapped them to symbol names. PEFBinaryAnalyzer produces the stub table in one call.

3. **No cross-binary PEF comparison.** Without a parser, each PEF target required full manual re-parsing of the loader section.

## What it does

Parses the PowerPC PEF Preferred Executable Format / CFM container. PEF is the native binary format for Mac OS 8/9 PowerPC executables: it is not ELF and has no dynamic linker. Imports are resolved via CFM TVect stubs in the code section that load function pointers from the TOC r2-relative.

PEF container structure:
```
Container header: 40 bytes
  +00: tag1="Joy!" (0x4A6F7921)
  +04: tag2="peff" (0x70656666)
  +08: architecture ("pwpc" or "m68k")
  +0C: formatVersion (= 1)
  +20: sectionCount (uint16)
  ... (timestamp, version fields)

Section headers: sectionCount × 28 bytes each
  +00: nameOffset     (4B, -1 = no name)
  +04: defaultAddress (4B, = base VA for this section)
  +08: totalSize      (4B)
  +0C: unpackedSize   (4B)
  +10: packedSize     (4B)
  +14: containerOffset(4B, = file offset of section data)
  +18: sectionKind    (1B): 0=code, 1=unpacked_data, 2=pattern_data, 3=constant,
                             4=loader, 5=debug, 6=exec_data, 7=exception, 8=traceback
  +19: shareKind      (1B)
  +1A: alignment      (1B, as power of 2)

Name table: immediately follows section headers

Loader section:
  Header (56B): main/init/term entry points, library+symbol counts, string table offset
  Library descriptors: importedLibraryCount × 24 bytes
  Symbol table: totalImportedSymbolCount × 4 bytes (class:8 | name_offset:24)
  String table: loader strings (NUL-terminated names)
```

CFM stub pattern (lwz rX, N(r2) where N = sym_index × 4):
```
lwz  rX, N(r2)    ; load TVect pointer from TOC
lwz  r0, 0(rX)    ; load function pointer from TVect
lwz  r2, 4(rX)    ; load new RTOC
mtctr r0           ; set CTR
bctr               ; branch to imported function
```

## Usage

```python
from ablation.analyzers.pef_binary_analyzer import PEFBinaryAnalyzer

pef = PEFBinaryAnalyzer.from_path('/path/to/PGPuam')
print(pef.report())

# Code section bytes for capstone / BinaryContext
code = pef.code_bytes()      # raw bytes
base = pef.code_base_va()    # defaultAddress (usually 0 for Mac Classic PEF)

# All CFM import stubs: {code_va: symbol_name}
stubs = pef.stubs()
for va, name in sorted(stubs.items()):
    print(f"  0x{va:06x} → {name}")

# Byte-verify a code-section VA
foff = pef.file_offset_of_code_va(0x1988c)

# Look up an import
imp = pef.import_by_name("BlockMoveData")   # rtoc_offset = 143 * 4 = 0x23C
imp2 = pef.import_by_rtoc_offset(0x6c)     # sym[27] = BlockMove
imp3 = pef.import_by_index(143)

# Check architecture
pef.is_powerpc()    # True for "pwpc"
pef.is_68k()        # True for "m68k"

# Detect PEF before parsing
PEFBinaryAnalyzer.is_pef(data)   # checks tag1/tag2
```

## Known limitations

- **Pattern-initialized data sections (kind=2) are not unpacked.** The packed representation is returned as-is; the run-length expand step is not implemented. Only code, constant, and unpacked-data sections are directly readable.
- **No export table parsing.** CFM exports are in the loader section after the import table; parsing them is straightforward but not yet implemented.
- **No PEF-native relocation application.** VAs returned are defaultAddress-relative (the same values you see in Capstone output with `base_va=0`).

---

## How it works

`PEFBinaryAnalyzer.from_path(path)` parses a Mac Classic / PEF (CFM) container: the format used by all pre-Intel Mac OS (8.x–9.x) and early Classic Mac OS X PPC applications. `PEFContainer._parse_sections()` extracts loader sections; `_resolve_imports()` walks the import symbol table to build the PLT equivalent. `PPC32TaintTracker` cannot load PEF files ELF only, so this module provides the PEF-specific binary loading layer so that taint tracking can run on Mac Classic PPC32 binaries.

---

## Example output

```
# PEFBinaryAnalyzer.report() header line + sections:
PEF  arch=pwpc  format_version=1  sections=4  imports=31

  sect[0]  code  va=0x00000000  sz=0x14200  file_off=0x68
  sect[1]  data  va=0x00014200  sz=0x2800   file_off=0x142a4
  sect[2]  pidata                            file_off=0x16ab0
  sect[3]  loader                            file_off=0x1a000
```

---

## False positives

**PPC32 only.** `PEFBinaryAnalyzer` loads the PEF container and builds a PLT for PPC32 targets only (`arch=pwpc`). M68K PEF containers (`arch=m68k`) are parsed but the import resolver is not wired to an M68K taint tracker.

---

## Pipeline position

**Before this module:** Confirm the binary is a PEF container (`file -b target` shows `Mac OS X PEF binary`).

**After this module:** Pass the resolved PLT to `PPC32TaintTracker.from_context()` by constructing a compatible context object from the `PEFBinaryAnalyzer` exports.

---

## Reading output

`PEFBinaryAnalyzer.from_path(path).analyze()` returns a `PEFAnalysis`.

| Field | Type | Content |
|:---|:---|:---|
| `architecture` | `int` | `PEF_ARCH_PWPC` (PowerPC) or `PEF_ARCH_M68K` (68K) |
| `format_version` | `int` | PEF container version |
| `sections` | `List[PEFSection]` | Code, data, and loader sections |
| `imports` | `List[PEFImport]` | Imported symbol references with library and symbol names |

Each `PEFSection`: `section_type, name, default_address, total_size, unpacked_size, packed_size, offset, alignment, sharing, data`.

Each `PEFImport`: `lib_name: str`, `sym_name: str`, `sym_class: int`.

---

## See also

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md): behavioral candidate search on the binary
