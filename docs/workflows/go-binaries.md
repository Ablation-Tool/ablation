<a id="go-binary-re-workflow"></a>
# Go Binary Analysis

Recover function names and addresses from Go's runtime metadata, enrich semantic descriptions, and reconstruct command dispatch and message framing in supported Go binaries.

**Files:** `ablation/analyzers/go_pclntab.py` · `modules/go_binary_re.py`

---

## Why Go metadata matters

Go binaries normally retain `pclntab` after symbol stripping because the runtime uses it for stack traces and function metadata. It can provide a function list even when the ELF or Mach-O symbol table is absent.

This improves downstream analysis because descriptions can contain names such as `main.handleRequest` rather than `func_0x401200`. Names are evidence for retrieval and triage; they do not replace disassembly or establish safety.

Obfuscators can replace or alter names. Ablation does not recover the original plaintext names when an obfuscator has irreversibly removed them.

## Supported inputs

`GoFuncTable` scans raw bytes for known little-endian `pclntab` magic values:

| Version family | Magic |
|:---|:---|
| Go 1.20+ | `0xFFFFFFF1` |
| Go 1.16–1.19 | `0xFFFFFFFA` |
| Go 1.12–1.15 | `0xFFFFFFFB` |

The parser is architecture-independent at the metadata level. Version layouts differ, and malformed, packed, heavily obfuscated, or unsupported binaries can produce no table or incomplete names. `from_binary()` returns `None` when it cannot locate and parse a supported table.

`modules/go_binary_re.py` separately supports ELF and 64-bit little-endian Mach-O section parsing, x86-64 handler disassembly with Capstone, command-map reconstruction, and message-frame inference for supported vmnetd-style binaries.

## Extract names with GoFuncTable

```python
from pathlib import Path
from ablation.analyzers.go_pclntab import GoFuncTable

data = Path('/path/to/go-binary').read_bytes()
table = GoFuncTable.from_binary(data)

if table is None:
    print('No supported pclntab found')
else:
    print(table.go_version, table.n_funcs, len(table.names))
    for va, name in sorted(table.names.items()):
        print(f'0x{va:x}: {name}')
```

`names` maps recovered function virtual addresses to names. `n_funcs` is the table's declared function count; compare it with `len(names)` to identify incomplete recovery.

## Enrich function descriptions

`enrich_descriptions()` prepends recovered names to description dictionaries with `va` and `desc` fields:

```python
from ablation.analyzers.go_pclntab import enrich_descriptions

functions = [
    {'va': 0x401200, 'desc': 'calls: runtime_memmove strings: /api/v1/status'},
]

if table is not None:
    enrich_descriptions(functions, table)
    print(functions[0]['desc'])
```

Use these enriched descriptions when building semantic-search or review corpora. A matching address must use the same load-base convention as the analysis context; reconcile text slides before comparing results.

## Reconstruct handlers and message framing

`analyze()` combines section parsing, `pclntab` recovery, handler-map detection, and message-frame inference:

```python
from modules.go_binary_re import analyze

result = analyze(
    '/path/to/go-binary',
    disasm_handlers=True,
)

print(result.go_version, result.arch, result.num_functions)
print('handlers:', len(result.handlers))
print('errors:', result.errors)

for handler in result.handlers:
    print(handler.cmd_id, handler.func_name, hex(handler.func_va))

for name, frame in result.message_frames.items():
    print(name, frame)
```

`AnalysisResult` includes:

| Field | Meaning |
|:---|:---|
| `go_version` / `arch` | Detected format and Go version information. |
| `pclntab_magic` | Magic found in the selected metadata section. |
| `functions` / `num_functions` | Recovered `GoFunc` records and count. |
| `handlers` | Command IDs, function addresses, names, and argument hints recovered from supported registration patterns. |
| `message_frames` | Per-handler inferred framing details or errors. |
| `errors` | Load, section, metadata, disassembly, and optional-stage errors. |

Always inspect `errors`; partial results can still be useful. If Capstone is unavailable, disassembly-dependent stages are disabled and reported in `errors`.

## Optional live vmnetd workflow

`analyze_vmnetd(live_probe=False)` adds prior vmnetd-specific handler knowledge to static analysis. Setting `live_probe=True` sends commands to the local vmnetd socket and records responses.

Do not enable live probing against a production or otherwise unauthorized service. Use an isolated test instance, preserve its initial state, and review each command's effect before execution. Static analysis does not require live socket access.

## Limitations

- `pclntab` recovery can fail for unsupported versions, packed files, malformed offsets, and aggressive obfuscation.
- Handler reconstruction recognizes specific registration and calling patterns, not every Go HTTP or RPC framework.
- `go_binary_re.py` includes vmnetd-specific conventions and prior knowledge. Do not generalize its command IDs or message layouts to unrelated binaries.
- Address recovery depends on correct text-slide and section mapping. Verify addresses before using them in another tool.
- This workflow does not provide a general `os/exec` taint proof. Use function-specific disassembly and data-flow analysis to confirm attacker control and reachability.

## See also

- [Semantic Code Search](../reference-modules/semantic-code-search.md): ranks enriched function descriptions.
- [Function Identification & Naming](../reference-modules/function-identity-database.md): persists recovered names and metadata.
- [Binary Parsing & Hardening](../reference-modules/binary-format-and-platform-identification.md): identifies enclosing ELF and Mach-O formats.
