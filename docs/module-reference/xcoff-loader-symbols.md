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
from ablation.analyzers.xcoff_loader_symbols import loader_symbols, loader_imports

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
