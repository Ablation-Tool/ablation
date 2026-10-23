# xcoff_loader_symbols

## Why this exists

Three things were not possible before in Ablation:

1. **Parse XCOFF loader symbols without a full `xcoff_parser.parse()` call.** `xcoff_parser.parse()` loads the entire binary, resolves function descriptors from `.data`, and merges the main symtab. For a quick "what VA does this export map to" check during a session, the overhead is unnecessary. `loader_symbols()` reads only the `.loader` section and returns a `{name: va}` dict in milliseconds.

2. **Document the XCOFF32 LDSYM struct layout correctly.** The XCOFF32 `LDSYM` entry has `name[8]` FIRST, then `l_value[4]`. This is the opposite of the typical COFF assumption (value-before-name). Two failed implementations in the VIOS session both used the wrong field order. A standalone function with explicit per-field comments prevents this mistake on every new AIX target.

3. **Handle both XCOFF32 and XCOFF64 layouts in one call.** XCOFF64 LDSYM entries are 32 bytes (vs. 24 for XCOFF32) and always use a strtab index for the name (no inline 8-byte name). Callers previously had to choose between xcoff_parser (full parse) and nothing. `loader_symbols()` dispatches on the file header magic and handles both formats.

## Format notes

XCOFF32 LDSYM (24 bytes):
- `name[8]`: inline name if `name[0:4] != \x00\x00\x00\x00`, else strtab offset in `name[4:8]`
- `l_value[4]`: descriptor VA for exports, 0 for imports
- `l_scnum[2]`, `l_smtype[1]`, `l_smclas[1]`, `l_ifile[4]`, `l_parm[4]`

XCOFF64 LDSYM (32 bytes):
- `l_value[8]`: VA
- `l_scnum[2]`, `l_smtype[1]`, `l_smclas[1]`, `l_ifile[4]`, `l_parm[4]`
- `l_name[4]`: strtab offset (always; no inline name)
- `pad[8]`

## Usage

```python
from modules.xcoff_loader_symbols import loader_symbols, loader_imports

with open('/path/to/ioscli', 'rb') as f:
    data = f.read()

# Export symbols: {name: descriptor_va}
syms = loader_symbols(data)
for name, va in sorted(syms.items()):
    print(f'{name:40s}  {va:#010x}')

# Import symbols: {lib_name: [symbol_name, ...]}
imports = loader_imports(data)
for lib, names in sorted(imports.items()):
    print(f'{lib}: {len(names)} imports')
```

## Key API

| Symbol | Description |
|--------|-------------|
| `loader_symbols(data)` | `Dict[str, int]`. Export name to descriptor VA. |
| `loader_imports(data)` | `Dict[str, List[str]]`. Lib name to list of imported symbol names. |

Both functions accept raw bytes of any XCOFF32 or XCOFF64 binary. Returns `{}` if not an XCOFF file or if the `.loader` section is absent.

## Note on descriptor VAs

For XCOFF32 executables, `loader_symbols` returns the **descriptor VA** in `.data`, not the code VA in `.text`. To get the code VA, use `xcoff_parser.parse()` which resolves the `{code_va, toc, env_ptr}` descriptor. Use `loader_symbols` for quick membership tests; use `xcoff_parser` when you need a code VA for disassembly.

## Smoke-tested on

- VIOS ioscli (XCOFF32): 73 loader exports, 2758 imports across 1173 libraries.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings.

---

## How it works

`XcoffLoaderSymbols.resolve(path)` extracts the XCOFF loader symbol table from an AIX binary without requiring `BinaryContext` or a full `xcoff_parser.parse()` call. It reads the `.loader` section directly, parses the loader section header to locate the symbol table, and returns a `{va: name}` dict. Useful for ad-hoc session scripts where only the import table is needed: e.g., checking whether a stripped binary links against `strcpy` or `system`: without paying the cost of a full XCOFF parse and context build.

---

## Example output

```python
# loader_symbols() returns Dict[str, int] (symbol_name → VA):
from modules.xcoff_loader_symbols import loader_symbols
syms = loader_symbols(open('/firmware/aix/lina', 'rb').read())
# {'strcpy': 0xd00b1c8, 'malloc': 0xd00a2b4, 'printf': 0xd00c010, ...}
print(syms.get('strcpy', 'not linked'))
# 0xd00b1c8
```

---

## False positives

**Descriptor VA vs. code VA.** On XCOFF32 (PPC32 AIX), function symbols in the loader section point to the OPD function descriptor (in `.data`), not to the first code instruction (in `.text`). `loader_symbols()` returns descriptor VAs. Use `xcoff_parser.parse()` and its `_resolve_descriptors()` step to get code VAs.

---

## Pipeline position

**Before this module:** Read the raw XCOFF binary bytes. This function is a standalone call, no BinaryContext needed.

**After this module:** Use the returned `{name: va}` dict to check whether a target binary imports dangerous symbols (`strcpy`, `system`, `execve`) before committing to a full `xcoff_parser.parse()` call.

---

## Reading output

`loader_symbols(data)` returns `Dict[str, int]` mapping symbol name → text-section VA.

`loader_imports(data)` returns `Dict[str, List[str]]` mapping library archive member name → list of imported symbol names.

| Return value | Type | Content |
|:---|:---|:---|
| `loader_symbols` result key | `str` | Exported or defined symbol name |
| `loader_symbols` result value | `int` | VA of the symbol in the text section |
| `loader_imports` result key | `str` | Library archive member name (e.g., `/lib/libc.a(shr.o)`) |
| `loader_imports` result value | `List[str]` | Names of symbols imported from that library member |

---

## See also

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md): behavioral candidate search on the binary
