# XcoffParser

## Why this exists

Four things were not possible before in Ablation:

1. **Parse XCOFF32/XCOFF64 binaries.** LIEF returns `None` for XCOFF inputs. Calling `BinaryContext.load_or_build()` on any AIX binary produced a default `x86_64` context with no sections, no symbols, and no function starts. Every AIX analysis session was silently broken before this module.

2. **Extract loader-section symbols from stripped AIX binaries.** AIX production builds routinely have `nsyms=0` in the XCOFF file header (all symbol table entries stripped). The `.loader` section, keyed by flags `0x1000`, survives stripping and holds all import/export symbol names with their virtual addresses. This is the primary RE surface for stripped AIX network drivers and kernel extensions.

3. **Resolve PPC32 function descriptors to code VAs.** Exported functions on PPC32/PPC64 appear as 8-byte descriptors in `.data` (`[code_va(4), toc_va(4)]`), not as direct code-section pointers. The optional header `entry` field points to a descriptor, not raw code. Resolving the actual code VA requires reading `.data` at the descriptor address, which no prior ablation module attempted.

4. **Handle XCOFF32 and XCOFF64 in one parser.** Section headers are 40 bytes in XCOFF32 and 72 bytes in XCOFF64; the struct difference must be handled in a single module rather than two diverging tools.

## Format notes

XCOFF magic numbers (big-endian, first 2 bytes):
- `0x01DF` = XCOFF32 (AIX 4.x/5.x 32-bit, PPC32)
- `0x01EF` = XCOFF64 (AIX 5.x/6.x 64-bit, PPC64)

File layout (XCOFF32):
- File header: 20 bytes
- Optional header: 72 bytes (entry, toc at optional+28)
- Section headers: 40 bytes each
- Section data: at `scnptr` offsets
- `.loader` section: flags `0x1000`; contains loader header + symbols + import file table + string table

Loader symbol classification: `l_ifile > 0` = import; `l_ifile == 0` = export/defined.

Import file ID table: triple `path\0archive_member\0object_name\0`. Library name = archive member field.

PPC32 function descriptor: 8 bytes in `.data` at the export VA: `[code_va(4 BE), toc_va(4 BE)]`. Zero-filled in kernel extensions (patched by `kload` at load time).

Known gap: XCOFF64 optional header and loader symbols use 8-byte VAs and 32-byte symbol records; current parser uses the XCOFF32 layout for both. Not triggered by AIX 4.x (32-bit) targets.

Confirmed on: 36/36 XCOFF32 files from `bos.net.tcp.server.4.3.3.84.bff`.

## Usage

```python
from ablation.core.xcoff_parser import parse, XcoffBinary

# Parse from file path
binary = parse('/path/to/netintf')

# Parse from bytes (e.g. from BffExtractor)
binary = parse('netintf', data=entry_bytes)

print(binary.arch)   # 'ppc32' or 'ppc64'
print(f'entry={binary.entry:#010x}  toc={binary.toc_va:#010x}')

# Sections
text = binary.text
data = binary.data
ldr  = binary.section('.loader')

# Exports (defined symbols)
for sym in binary.exports:
    va = sym.code_va if sym.code_va else sym.va
    print(f'  {sym.name}  va={sym.va:#x}  code_va={sym.code_va:#x}')

# Imports
for sym in binary.imports:
    print(f'  {sym.name}  from={sym.lib}')
```

## Key API

| Symbol | Description |
|--------|-------------|
| `XCOFF32_MAGIC` | `0x01DF` |
| `XCOFF64_MAGIC` | `0x01EF` |
| `XcoffSection` | `name, vaddr, size, offset, flags, data`; `contains_va(va)` |
| `XcoffSymbol` | `name, va, lib, smclas, code_va`; `is_import` property |
| `XcoffBinary` | `arch, entry, toc_va, sections, exports, imports`; `text`, `data`, `section(name)` |
| `parse(path, data=None)` | Returns `XcoffBinary`; raises `ValueError` on bad magic, `struct.error` on truncation |

## FORGE audit

Gate: **PASSED** (0 HIGH, 0 CRITICAL). 2 MEDIUM findings for XCOFF64 path (wrong optional header format; wrong loader symbol size). Both are out of scope for AIX 4.x (32-bit) targets. Will be fixed when first XCOFF64 binary is available.

---

## How it works

`xcoff_parser.parse(path)` parses an IBM XCOFF32 or XCOFF64 binary (AIX PowerPC). XCOFF is the AIX variant of COFF with extensions for 64-bit, dynamic linking via a `.loader` section, and the CSECT (control section) subdivision within segments. The parser extracts: section headers and section data, the XCOFF symbol table (including `C_EXT` / `C_WEAKEXT` entries), the loader section (function imports and exports with VAs), and CSECT boundaries used as function-start candidates. Returns `XcoffBinary` with `sections`, `symbols`, `plt`, and `func_starts`.

---

## Example output

```python
# xcoff_parser.parse() returns XcoffBinary — attribute access:
b = parse('/firmware/aix/libservice.so')
b.arch           # 'ppc64'
hex(b.entry)     # '0x10001200'
hex(b.toc_va)    # '0x10010000'
len(b.sections)  # 6
b.plt            # {'strcpy': 0xd00b1c8, 'malloc': 0xd00a2b4, ...}
b.func_starts    # [0x10001200, 0x10001280, 0x10001300, ...]
```

---

## False positives

**XCOFF archive support.** `xcoff_parser.parse()` parses a single XCOFF file. AIX `.a` archive files contain multiple XCOFF members with an archive header. `parse()` raises `ValueError: not an XCOFF binary` on `.a` archive files. Extract members first with `ar x libfoo.a`.

---

## Pipeline position

**Before this module:** Confirm XCOFF magic with `struct.unpack('>H', data[:2])`: `0x01DF` (XCOFF32), `0x01F7` (XCOFF64), or `0x01EF` (XCOFF64 alt). Pass `data=` kwarg if already read to avoid double reads.

**After this module:** Pass `XcoffBinary.func_starts` to `PPC64BESinkClassifier` for PPC64 targets, or `XcoffBinary.plt` to `TaintTracker` for import resolution.

---

## Reading output

`parse(path)` returns an `XcoffBinary`.

`XcoffBinary` fields:

| Attribute | Type | Content |
|:---|:---|:---|
| `path` | `str` | Path to the analyzed binary |
| `arch` | `str` | `'ppc32'` or `'ppc64'` |
| `entry` | `int` | Entry point VA (descriptor VA on PPC32) |
| `text_start` | `int` | VA of the `.text` section |
| `data_start` | `int` | VA of the `.data` section |
| `toc_va` | `int` | TOC anchor VA |
| `sections` | `List[XcoffSection]` | All sections |
| `exports` | `List[XcoffSymbol]` | Defined symbols |
| `imports` | `List[XcoffSymbol]` | External references |

`XcoffSymbol` fields:

| Attribute | Type | Content |
|:---|:---|:---|
| `name` | `str` | Symbol name |
| `va` | `int` | Descriptor VA (functions) or data VA; 0 for imports |
| `lib` | `str` | Import library name; empty for exports |
| `smclas` | `int` | Storage mapping class |
| `code_va` | `int` | Resolved code entry point VA after descriptor resolution; 0 if unresolved |
| `is_import` | `bool` | Property: `True` when `lib` is non-empty |

`XcoffSection` fields: `name, vaddr, size, offset, flags, data`; properties `is_text, is_data, is_bss`.

---

## See also

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md): behavioral candidate search on the binary
