# Persistent Analysis Context

Pre-computed, serialized binary context cache that captures ELF parsing results once and reloads in under 100ms on subsequent sessions — storing PLT stub mappings, export symbols, `.rodata` strings, function start VAs, and the flat call graph in `~/.ablation/cache/`, eliminating the 2–5 second per-session ELF parsing overhead.

---

## Why this exists

1. **ELF parsing (PLT resolution, `.eh_frame` FDE extraction, string table scan, call edge enumeration) takes 2–5 seconds per binary — on a firmware image with 40 shared libraries, that is 80–200 seconds of parsing overhead per session if re-parsed each time.** `BinaryContext.load_or_build()` builds the context once and serializes it to `~/.ablation/cache/<binary_hash>.pkl`; subsequent loads from cache take under 100ms regardless of binary size.

2. **`BinaryContext` is the single required input for every Ablation analyzer** — `CFGBuilder`, `TaintTracker`, `FuncProfiler`, `SinkArgClassifier`, `FormatStringScanner`, `RegAnnotator`, and all other analyzers accept `from_context(ctx)` and require only the pre-built `BinaryContext`. Building the context once at session start and passing it to all analyzers is the baseline usage pattern described in `CLAUDE.md`.

3. **`BinaryContext` closes the primary capability gap vs. Ghidra for LLM-assisted RE: knowing what strings a function references and who calls it.** `ctx.strings_in_func(va)` returns all `.rodata` strings the function loads via RIP-relative LEA; `ctx.callers_of(symbol)` returns all call sites to a named function. Both dramatically improve `SemanticSearcher` embedding quality and `FuncProfiler` output by providing richer function descriptions without manual disassembly.

---

## How it works

```mermaid
flowchart TD
    A["BinaryContext.load_or_build(path, force_rebuild)"] --> B{"Cache hit?\n  (~/.ablation/cache/<sha256>.pkl)"}
    B -- Yes --> C["load_from_cache_file() → ctx\n  Deserialize in <100ms"]
    B -- No --> D["BinaryContext.build(path):\n  ELF parsing via pyelftools:\n    plt: {va: symbol} from .plt/.plt.got\n    exports: {name: va} from .dynsym/.symtab\n    strings: {va: content} from .rodata (≥4 chars)\n    func_starts: from .eh_frame FDEs + callee augmentation\n    call_edges: [(from, to, label)] from disassembly"]
    D --> E["XRefGraph.build():\n  Build call graph + string xref index\n  Support: x86_64, arm64, arm32/Thumb\n  build_xref_index() → number of xrefs added"]
    E --> F["Serialize to cache\n  ~2-5s build time → <100ms reload"]

    G["ctx.callers_of(symbol_or_va) → List[Tuple[va, name]]\n  All call sites reaching this function"]
    H["ctx.callees_of(func_va) → List[Tuple[va, name]]\n  All callees (PLT + internal) from this function"]
    I["ctx.strings_in_func(func_va) → List[Tuple[va, str]]\n  All .rodata strings loaded in this function"]
    J["ctx.name(va) → str\n  Human-readable name: 'fn_0x<va>' if unnamed\n  ctx.set_name(va, name, source='confirmed')"]
    K["ctx.func_containing(va) → Optional[int]\n  Which function contains this VA"]
```

---

## Usage

```python
from ablation.analyzers.binary_context import BinaryContext

# Build once; reload from cache on subsequent calls
ctx = BinaryContext.load_or_build('/path/to/target.elf')
print(ctx.summary())

# Names table (if symbols present)
if ctx.names_count():
    print(ctx.names_table())

# PLT lookups
print(ctx.plt)                          # {va: symbol_name}
print(ctx.plt_name(0x401020))           # 'recv'

# Export lookups
va = ctx.export_va('http_request_handler')

# Call graph queries
callers = ctx.callers_of('system')
callees = ctx.callees_of(0x12340)

# String lookups
strings = ctx.strings_in_func(0x12340)  # strings referenced in this function
nearby = ctx.strings_near(0x12340, radius=128)

# Name management
ctx.name(0x12340)                        # 'fn_0x12340' (unnamed)
ctx.set_name(0x12340, 'parse_request', source='confirmed')
ctx.name(0x12340)                        # 'parse_request'

# Force rebuild (e.g., after injecting new function starts)
ctx2 = BinaryContext.load_or_build('/path/to/target.elf', force_rebuild=True)
```

---

## Example output

```
BinaryContext: /path/to/target.elf
  PLT entries:   <N>
  Exports:       <M>
  Strings:       <K>  (.rodata)
  Function starts: <J>  (from eh_frame + callee augmentation)
  Call edges:    <L>
  Cache: ~/.ablation/cache/<hash>.pkl  (reload in <100ms)
```

---

## False positives

**`func_starts` from `.eh_frame` FDE entries includes exception landing pads** — these appear as spurious function starts mid-function. They do not cause analysis errors but increase the number of functions `SemanticSearcher` and `CorpusBuilder` process. Use `ctx.func_containing(va)` to test whether a discovered start is within a known function before treating it as an independent function entry.

**Cache invalidation is manual** — if the binary changes on disk (e.g., a new version is downloaded to the same path), the cache retains the old binary's data. Use `force_rebuild=True` when the binary has changed or `ctx.summary()` shows unexpected values.

---

## Pipeline position

`BinaryContext.load_or_build()` is always step 2 in the RE workflow (CLAUDE.md): immediately after session start, before any analysis. Every other analyzer in the pipeline takes a `BinaryContext` input. Build the context once per binary per session; pass the same `ctx` object to all analyzers.

---

## See also

- [Control-Flow Graph Construction](control-flow-graph-construction.md) — `CFGBuilder(ctx)` uses the context for disassembly
- [Function Corpus Builder](function-corpus-builder.md) — `CorpusBuilder.build()` augments the context with `ANGR_INFERRED` records
- [Debug Metadata Recovery](debug-metadata-recovery.md) — `DwarfLoongArch64.inject_into_context()` adds DWARF/BTF data to the context
