# PDBSymbolIntegrator

## Why this exists

2 things that weren't possible before in Ablation:

1. **No PDB fetch or parse path.** Windows system binaries (ntdll, kernel32, lsass components) ship with matching PDB files on Microsoft's public symbol server. The GUID identifying the correct PDB is embedded in the PE's CodeView debug directory (`RSDS` record). Before this module, getting symbol names for a Windows binary in Ablation required an external tool (WinDbg, `symchk.exe`, or `llvm-pdbutil`) and then manually feeding names in. There was no automated path from a PE file on disk to a name-populated `BinaryContext`.

2. **No MSF/PDB public symbols parser.** Parsing the Multi-Stream File (MSF 7.0) container, navigating the DBI stream to find the public symbols stream index, and reading `S_PUB32` CodeView records to extract `{rva: name}` pairs is a multi-step binary format exercise. Before this module, Ablation had no Python-native implementation of this. `pefile` has no PDB support. `lief` reads the CodeView entry but does not parse the PDB file itself.

---

## What it does

`PDBSymbolIntegrator` has three responsibilities:

1. **PDB reference extraction.** Reads the `IMAGE_DEBUG_TYPE_CODEVIEW` entry from the PE debug directory to find the `RSDS` record containing the PDB GUID, age, and original PDB filename. Builds the Microsoft symbol server URL (`https://msdl.microsoft.com/download/symbols/<name>/<GUID><age>/<name>`).

2. **Symbol server fetch.** `fetch_pdb(out_dir=None)` downloads the PDB to disk using the symbol server URL, with caching (returns immediately if the file already exists).

3. **MSF/PDB parsing.** `load_pdb(pdb_path)` parses the MSF 7.0 container: reads the superblock, reconstructs the stream directory, and parses the public symbols stream for `S_PUB32` records (`type=0x110e`). Returns `{section_relative_offset: symbol_name}`.

4. **NameRegistry integration.** `inject_into_context(ctx)` calls `ctx.set_name(va, name, source='pdb')` for each extracted symbol, wiring PDB names into BinaryContext for `ctx.name(va)` lookups.

---

## Usage

```python
from ablation.analyzers.pdb_symbol_integrator import PDBSymbolIntegrator

integrator = PDBSymbolIntegrator.from_path('ntdll.dll')
info = integrator.pdb_info()
if info:
    print(f"PDB: {info.pdb_filename}")
    print(f"GUID: {info.guid_formatted}  age={info.age}")
    print(f"URL: {info.symbol_url}")

# Fetch from symbol server and inject into context
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('ntdll.dll')
count = integrator.inject_into_context(ctx)
print(f"Injected {count} names from PDB")

# Or use a local PDB
names = integrator.load_pdb('/path/to/ntdll.pdb')
print(f"Extracted {len(names)} symbols from PDB")
```

---

## Findings

| Severity | Category | Trigger |
|---|---|---|
| INFO | `pdb_info` | CodeView RSDS record found: reports GUID, age, symbol URL |
| INFO | `no_pdb` | No CodeView debug directory |

---

## Symbol server URL format

```
https://msdl.microsoft.com/download/symbols/{pdb_filename}/{GUID_NO_HYPHENS}{age}/{pdb_filename}
```

Example:
```
https://msdl.microsoft.com/download/symbols/ntdll.pdb/4CC77CF21B8000/ntdll.pdb
```

The GUID is formatted without hyphens (32 uppercase hex chars) followed by the decimal age integer.

---

## Dependencies

- `lief >= 0.14.0` (PE parsing, debug directory)
- Python standard library only for MSF parsing (`struct`, `urllib.request`)
- Network access required for `fetch_pdb()` (can be skipped with a local PDB path)

---

## Limitations

The MSF parser covers the public symbols stream (`S_PUB32` records). Private symbols (local variables, inlined functions, type information) require the full DBI module info streams and are not parsed. For most RE use cases, public symbols (exported functions and their addresses) are sufficient for `BinaryContext` name injection.
