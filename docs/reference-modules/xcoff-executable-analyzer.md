# XCOFFExecutableAnalyzer

## Why this exists

Three things were not possible before in Ablation:

1. **Provide a consistent analyzer interface for XCOFF32/64 binaries.** `xcoff_parser.parse()` returns an `XcoffBinary` dataclass. Session scripts repeatedly extracted exports, imports, and function starts from the raw dataclass, duplicating the same boilerplate in every AIX analysis script. `XCOFFExecutableAnalyzer` wraps `xcoff_parser` with convenience methods: `from_context`, `exports_table`, `imports_by_lib`, `func_starts`, and `section_at_va`.

2. **Abstract the XCOFF32 vs. XCOFF64 distinction for callers.** XCOFF32 `.o` files use section-relative offsets for symbols; XCOFF32 executables use absolute VAs resolved from function descriptors; XCOFF64 executables use 64-bit absolute VAs. `xcoff_parser` handles the dispatch, and `XCOFFExecutableAnalyzer.exports_table()` always returns absolute code VAs regardless of file type. Callers do not need to remember the descriptor indirection.

3. **Integrate with the `BinaryContext`-based tool pipeline.** Other analyzers including `SinkArgClassifier`, `TaintTracker`, and `FuncProfiler` accept `from_context(ctx)`. A raw `xcoff_parser` call required boilerplate that broke the tool-selection pipeline ordering. `XCOFFExecutableAnalyzer.from_context(ctx)` plugs into that pipeline without modification.

## Usage

```python
from modules.xcoff_executable_analyzer import XCOFFExecutableAnalyzer

a = XCOFFExecutableAnalyzer.from_path('/path/to/ioscli')
print(a.summary())
# arch=ppc32  entry=0x10000128  toc=0x20009590
# sections=4 [.text .data .bss .loader]
# exports=613  imports=2758

for name, code_va in a.func_starts()[:10]:
    print(f'{name:40s}  {code_va:#010x}')

# Section containing a VA
sec = a.section_at_va(0x10001668)
print(sec.name)   # .text

# From BinaryContext
a = XCOFFExecutableAnalyzer.from_context(ctx)
```

## Key API

| Symbol | Description |
|--------|-------------|
| `XCOFFExecutableAnalyzer(path)` | Constructor; lazy-loads on first access |
| `XCOFFExecutableAnalyzer.from_path(path)` | Construct and load immediately |
| `XCOFFExecutableAnalyzer.from_context(ctx)` | Construct from `BinaryContext` |
| `XCOFFExecutableAnalyzer.arch` | `'ppc32'` or `'ppc64'` |
| `XCOFFExecutableAnalyzer.entry` | Entry point VA |
| `XCOFFExecutableAnalyzer.exports_table()` | `Dict[str, int]`. Name to code VA. |
| `XCOFFExecutableAnalyzer.imports_by_lib()` | `Dict[str, List[str]]`. Lib name to symbol list. |
| `XCOFFExecutableAnalyzer.func_starts()` | `List[tuple[name, code_va]]` sorted by VA |
| `XCOFFExecutableAnalyzer.section_at_va(va)` | `XcoffSection` or `None` |
| `XCOFFExecutableAnalyzer.summary()` | Multi-line summary string |

## Smoke-tested on

- VIOS ioscli XCOFF32 ppc32: `arch=ppc32`, 613 exports, 2758 imports, `.text` va=0x10000128.

## Limits

| Constant | Value | Purpose |
|----------|-------|---------|
| `_MAX_XCOFF_BYTES` | 256 MB | `os.path.getsize()` guard in `_load()` before `xcoff_parser.parse()` |

## FORGE audit

Gate: **PASSED**. CWE-770 (unbounded `Path.read_bytes()` in `xcoff_parser.parse()`) fixed in `_load()` via `_MAX_XCOFF_BYTES=256MB` + `getsize()` check. No HIGH or CRITICAL findings remain.

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
