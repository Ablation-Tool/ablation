# XcoffSymtabParser

Parse the XCOFF32 or XCOFF64 `.symtab` section and populate `BinaryContext` with function names: bridging the gap where `BinaryContext` relies on `.loader` but many AIX firmware binaries have none.

---

## Why this exists

1. **`BinaryContext`'s symbol-name feed is gated on `.loader`.** `BinaryContext` calls `xcoff_parser` internally, but its name-population path requires the `.loader` section to be present and populated. Many AIX firmware executables extracted from BFF archives (especially `automountd`, `rlogind`, `ksh93`, `nfsd`) have a full `.symtab` but an absent, minimal, or incomplete `.loader` section. Without this module, `ctx.names_count()` returns 0 for those binaries and every `ctx.name(va)` call returns the raw VA hex string.

2. **The "Name everything" workflow rule cannot be met without it.** `ctx.set_name()` requires a known VA. Without `.symtab` names in context, every subsequent tool call: `SinkArgClassifier`, `TaintTracker`, `Xcoff32Decompiler`: produces output filled with raw hex addresses instead of function names.

3. **`xcoff_parser` helpers are not analyzers.** `xcoff_parser._parse_symtab32` and `_parse_symtab32_exe` are internal parse helpers. They are not exposed through the `from_context(ctx)` interface the RE workflow expects, and they do not call `ctx.set_names_bulk()`.

---

## How it works

```
BinaryContext.load_or_build()
         │
         │  ctx.names_count() == 0?
         ▼
XcoffSymtabParser.from_context(ctx)
         │
         ▼
    scan()
    ├── Read file header (magic check: 0x01df=XCOFF32, 0x01f7=XCOFF64)
    ├── Parse f_symptr → locate symbol table offset
    ├── Parse f_nsyms → entry count
    ├── Build section VA map: section_number → vaddr (STYP_TEXT sections only)
    ├── Read string table (follows symbol table at symptr + nsyms × 18)
    ├── For each symbol entry:
    │   ├── Decode name: inline 8-byte field or strtab reference
    │   ├── Filter: C_EXT and C_HIDEXT storage classes only
    │   ├── Strip leading dot: .frexp → frexp (dotted = code entry in XCOFF)
    │   └── Compute VA: sec_va[scnum] + value
    └── ctx.set_names_bulk(bulk) → populate BinaryContext
```

XCOFF uses dotted symbol names to distinguish code entry points from data descriptors. `.frexp` is the entry point; `frexp` (no dot) names the descriptor. The parser strips the dot so the resulting names match what you'd expect in disassembly and pseudocode output.

---

## Usage

```python
from ablation.analyzers.xcoff_symtab_parser import XcoffSymtabParser
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/automountd')
parser = XcoffSymtabParser.from_context(ctx)
result = parser.scan()
print(XcoffSymtabParser.report(result))
```

**Typical output:**
```
XcoffSymtabParser: 47 names added, 0 already present, 47 total symbols in .symtab
  Top symbols by VA:
    0x10000400  main
    0x10000620  setup_mounts
    0x10000800  parse_auto_line
    0x10000a40  nfs_mount
    0x10000c10  do_fork
    ...
```

**Integration with Xcoff32Decompiler:**
```python
from ablation.analyzers.xcoff_symtab_parser import XcoffSymtabParser
from ablation.analyzers.xcoff32_decompiler import Xcoff32Decompiler
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/automountd')

# Step 1: populate names from .symtab
XcoffSymtabParser.from_context(ctx).scan()

# Step 2: decompiler now uses named TOC loads and call targets
dec = Xcoff32Decompiler.from_context(ctx)
print(dec.decompile(0x10000800))
```

---

## Result fields

| Field | Type | Content |
|:---|:---|:---|
| `names_added` | `int` | Count of new names written into BinaryContext |
| `names_already_present` | `int` | Count of symbols where BinaryContext already had a name at that VA |
| `symbols` | `list[int, str]` | All `va, name` pairs found, sorted by VA |
| `error` | `str` | Non-empty if parsing failed; empty on success |

---

## Storage class filter

Only `C_EXT` (2) and `C_HIDEXT` (107) symbols are extracted. Internal compiler symbols (`C_FILE`, `C_STAT`, `C_FCN`, etc.) are skipped: they clutter the name table without adding RE value.

The filter has one consequence: if a known function in the binary has no name after parsing, check whether it carries a non-standard storage class in the raw symbol table. This happens occasionally with IBM XLC-compiled libraries that use `C_FUN` (142) for internal functions.

---

## Executable vs. archive-member semantics

XCOFF32 has two symbol value interpretations:

- **Archive member (`.o`):** Symbol value is a section-relative offset. VA = `sec_va[scnum] + value`.
- **Executable:** Symbol value is the absolute VA. The parser handles both cases by attempting the dotted-name path first archive convention, then falling back to scanning all text-section symbols directly executable convention if the first pass returns empty.

---

## Pipeline position

**Before:** `BinaryContext.load_or_build()`: provides `ctx.path`.

**After:** Anything that calls `ctx.name(va)`: `SinkArgClassifier`, `TaintTracker`, `Xcoff32Decompiler`, `WindowAnalyzer`. Run this as the second step on every XCOFF32 binary.

---

## See also

- [Xcoff32Decompiler](xcoff32-decompiler.md): decompiles XCOFF32 functions using the names this module populates
- [XCOFF Executable Analyzer](xcoff-executable-analyzer.md): higher-level XCOFF32/64 analysis
- [BFF Extractor](bff-extractor.md): extracts XCOFF32 binaries from AIX BFF archives run before this
