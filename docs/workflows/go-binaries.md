# Go Binary RE Workflow

The Go compiler always embeds the full function name table (`pclntab`) in the binary for
runtime stack traces -- even after `strip(1)`. Ablation extracts this table before BERT
encoding, lifting semantic search accuracy from roughly 0.20 to 0.70+ on stripped Go binaries.

---

## Overview

```
Go binary (stripped ELF)
        |
        v
[GoPclntab]      -- extract pclntab: VA -> function name (all Go versions)
        |
        v
[NameRegistry]   -- register all function names as overlay
        |
        v
[BinaryContext]  -- names appear in callee/caller output automatically
        |
        v
[SemanticSearcher] -- BERT sweep with named functions: accuracy ~0.70+
```

For garble-obfuscated builds where function names are hashed, use a different path:

```
Garble binary
        |
        v
[GoGarbleRe]     -- trace runtime bootstrap, find HTTP handler registration
                    via runtime.morestack / text section anchor patterns
        |
        v
[SemanticSearcher] -- query by behavioral description without name hints
```

---

## Step 1: Extract pclntab names

```python
from ablation.analyzers.go_pclntab import GoFuncTable
from ablation.analyzers.binary_context import BinaryContext

data = open('/path/to/go_binary', 'rb').read()

# Returns None if the binary is not a Go binary or pclntab is absent
ft = GoFuncTable.from_binary(data)

if ft:
    print(f"Go version: {ft.go_version}")
    print(f"Functions: {ft.n_funcs}")

    ctx = BinaryContext.load_or_build('/path/to/go_binary')
    for va, name in ft.names.items():
        ctx.set_name(va, name, source='pclntab')

    print(f"Registered {len(ft.names)} names from pclntab")
    print(ctx.names_table(limit=20))
```

### Supported pclntab formats

| Go version | Magic | Notes |
|---|---|---|
| 1.20+ | `0xFFFFFFF1` | 64-bit with separate `funcnametab` section |
| 1.16 - 1.19 | `0xFFFFFFFA` | 64-bit function table |
| 1.12 - 1.15 | `0xFFFFFFFB` | 32-bit function table |

Architecture-independent: works on x86-64, arm64, mips, and riscv64. All architectures use
the same pclntab structure.

---

## Step 2: Run semantic sweep (with names)

With function names registered, the BERT corpus descriptions change from generic
`func_0xABCD calls: runtime_memmove, runtime_mapassign` to
`main.handleWebsocketUpgrade calls: runtime_memmove, net_http_ServeHTTP`.

That change dramatically improves semantic search precision:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.xref_graph import XRefGraph
from ablation.analyzers.semantic_search import SemanticSearcher

ctx = BinaryContext.load_or_build('/path/to/go_binary')
cb = CorpusBuilder()
cb.build('/path/to/go_binary', product='my-go-app', version='1.0')

xg = XRefGraph.from_path('/path/to/go_binary').build()
searcher = SemanticSearcher('/path/to/go_binary', xg=xg)
searcher.build_corpus()

results = searcher.query(
    "HTTP handler that reads request body without size limit check",
    top_k=10
)
```

---

## Step 3: Dangerous callers scan

Go binaries frequently use `exec.Command` and `os/exec` for shell operations. Use
GoSubprocessScanner to find all call sites:

```python
from ablation.analyzers.go_subprocess_scanner import GoSubprocessScanner

scanner = GoSubprocessScanner('/path/to/go_binary')
hits = scanner.scan()
for h in hits:
    print(f"  0x{h.va:x}  {ctx.name(h.va)}: {h.call_type}  arg={h.arg_summary}")
```

**Scans for:** `os/exec.Command`, `exec.CommandContext`, `syscall.Exec`,
`os.StartProcess`, `syscall.RawSyscall` with SYS_EXECVE.

---

## Garble-obfuscated builds

[`mvdan/garble`](https://github.com/mvdan/garble) replaces pclntab function names with
hashes. GoFuncTable returns names like `a.b` or `$1a2b3c4d` -- not useful for semantic
search.

For garble builds, use GoGarbleRe to find handler registration:

```python
from ablation.analyzers.go_garble_re import GoGarbleRe

garble_re = GoGarbleRe('/path/to/garbled_binary')

# Trace Go runtime bootstrap to find the entry point
entry = garble_re.find_entry_point()
print(f"Entry: 0x{entry:x}")

# Find HTTP handler registration patterns (mux.HandleFunc)
handlers = garble_re.find_http_handlers()
for h in handlers:
    print(f"  route={h.route!r}  handler=0x{h.handler_va:x}")

# Find text section by VA-to-file-offset mapping
# (garble disrupts standard ELF layout)
text_va, text_offset = garble_re.find_text_section()
```

GoGarbleRe finds `runtime.morestack` -- always present and recognizable by its prologue
pattern -- as a ground-truth VA anchor, then maps VA to file offset from that anchor.

---

## Go string resolver

Go binaries use `runtime.concatstrings` for string concatenation rather than `.rodata`
references. GoStringResolver reconstructs string constants from `concatstrings` call sites:

```python
from ablation.analyzers.go_string_resolver import GoStringResolver

resolver = GoStringResolver('/path/to/go_binary')
strings = resolver.resolve()

for va, s in strings.items():
    print(f"  0x{va:x}: {s!r}")
```

This populates string context that BinaryContext's `.rodata` scan misses for Go binaries.
