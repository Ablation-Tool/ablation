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

Reads the binary image and resolves the target-specific data structures (PLT, GOT, `.eh_frame`, symbol tables) to build a function and import index. Architecture-specific calling conventions and instruction encodings are applied to recover call edges, argument registers, and return value locations. Results are stored in the session `BinaryContext` so downstream tools can use resolved names and edges.

---

## Example output

```
Resolved 847 PLT entries
Recovered 312 function starts from .eh_frame
Named 28 functions from DWARF remnants

va=0x401200  name=verify_admin_token  confidence=HIGH
va=0x4015C0  name=process_http_request  confidence=HIGH
va=0x403A00  name=''  confidence=MEDIUM  (stripped)
```

---

## False positives

Symbol resolution errors produce phantom function boundaries. Verify any candidate VA against `ctx.func_starts` before analysis. Compiler-synthesized stubs (PLT entries, thunks) appear as functions in some loaders — `BinaryContext` filters known stub patterns but custom thunks may slip through.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` for symbol and import resolution. For stripped binaries, run `SemanticSearcher` first to identify candidate function VAs.

**After this module:** Pass resolved call edges and function VAs to `TaintTracker` or `SinkArgClassifier`.

---

## Reading findings

| Field | Content |
|:---|:---|
| `va` | Virtual address of the resolved symbol, function, or instruction |
| `name` | Recovered name if available, empty string if stripped |
| `detail` | What was resolved or decoded |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` — how certain the resolution is |

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
