# BinaryContext

## Why this exists

3 things that weren't possible before in Ablation without this module:

1. **No per-session symbol resolution.** Before `BinaryContext`, every analysis tool had to re-parse the ELF, rebuild the PLT map, re-extract strings, and re-compute the call graph from scratch. On a 15MB firmware binary that overhead ran 4–6 seconds per session. `BinaryContext` builds once (~2–5 seconds), serializes to `~/.ablation/cache/`, and reloads in under 100ms on every subsequent session.

2. **No cross-tool caller/callee queries.** Individual tools like `TaintTracker` and `SemanticSearcher` operated in isolation — there was no shared index for "what calls this symbol" or "what does this function call." `BinaryContext` builds `_callers_idx` and `_callees_idx` once and exposes them via `callers_of()` and `callees_of()`, making cross-tool queries O(1) lookups instead of per-session linear scans.

3. **No Windows PE support in the context layer.** All of Ablation's analysis tools — `SemanticSearcher`, `TaintTracker`, `WindowAnalyzer`, `FuncProfiler` — depend on `BinaryContext`. Before v2.45.0, loading a Windows PE or `.sys` driver silently returned an empty context, meaning every search and taint trace returned nothing. The v2.45.0 PE path populates all the same slots (IAT as PLT, exports, strings, func_starts, call_edges) so every tool works on PE files with no changes to calling code.

---

## What it does

`BinaryContext` is the pre-computed working context for a stripped binary. One build populates:

- `plt` — `{va: symbol_name}` — PLT stubs (ELF) or IAT entries (PE)
- `exports` — `{symbol_name: va}` — all globally exported functions
- `strings` — `{va: content}` — printable ASCII sequences ≥ 4 chars from read-only sections
- `func_starts` — sorted list of function entry VAs (DWARF `.eh_frame` for ELF; export VAs + prologue scan for PE)
- `call_edges` — `[(from_va, to_va, label)]` — flat call graph, vectorized numpy scan

Named function VAs are tracked in the overlay (`ctx.set_name(va, name)`) and persisted via `NameRegistry` across sessions.

---

## Supported formats

| Format | Arch support | func_starts source |
|---|---|---|
| ELF | x86_64, x86_32, arm64, arm32, ppc64, ppc32, mips64, mips32, riscv64, riscv32, loongarch64 | DWARF `.eh_frame` + exports + dynamic symbols |
| Windows PE / `.sys` | x86_64, x86_32 (arm64/arm32 no-op, safe) | Exports + prologue scan |

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext

# Works on both ELF and PE (load path auto-detects format)
ctx = BinaryContext.load_or_build('/path/to/target.exe')

print(ctx.summary())

# Caller/callee queries (ELF and PE)
ctx.callers_of('RpcServerRegisterIfEx')   # -> [(from_va, fn_name), ...]
ctx.callees_of(0x140001234)               # -> [(to_va, label), ...]

# String xrefs (ELF and PE x86_64)
ctx.strings_in_func(0x140001234)          # -> [(va, content), ...]
ctx.funcs_referencing_string(0x14000a000) # -> [va, ...]

# Name overlay (persisted across sessions)
ctx.set_name(0x140001234, 'parse_request', source='confirmed')
```

### PE-specific: combining with the Windows PE analyzers

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.rpc_server_analyzer import RPCServerAnalyzer

ctx = BinaryContext.load_or_build('/path/to/rpcss.dll')

# SemanticSearcher, TaintTracker, WindowAnalyzer, FuncProfiler all work now
from ablation.analyzers.semantic_searcher import SemanticSearcher
results = SemanticSearcher(ctx).query("unauthenticated RPC registration")

# Then hand off to the PE-specific analyzer for deep inspection
rpc = RPCServerAnalyzer.from_path('/path/to/rpcss.dll')
findings = rpc.scan()
```

---

## Cache

Cache lives at `~/.ablation/cache/<sha256[:16]>_<basename>.json`. Invalidated on SHA256 mismatch. Force rebuild with `force_rebuild=True`.

```python
ctx = BinaryContext.load_or_build(path, force_rebuild=True)
```

To load without the original binary (e.g. `/tmp` was cleared):

```python
ctx = BinaryContext.load_from_cache_file('~/.ablation/cache/abc123_target.json')
```
