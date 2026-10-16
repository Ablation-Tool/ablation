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

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings.
