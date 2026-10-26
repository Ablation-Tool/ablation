# CrossBinaryExportDetector

- [Why this exists](#why-this-exists)
- [How it works](#how-it-works)
- [Class and method reference](#class-and-method-reference)
- [Usage](#usage)
- [Example output](#example-output)
- [False positives](#false-positives)
- [Pipeline position](#pipeline-position)
- [Reading findings](#reading-findings)
- [See also](#see-also)

---

## Why this exists

In multi-binary firmware suites, RE stops at the binary boundary. A function with zero `CALL rel32` callers in binary A might genuinely be dead code — or it might be the primary entry point from binary B. Treating these the same:

1. Inflates the apparent attack surface (dead stubs look like entry points).
2. Misses real entry points that are called cross-binary via exported symbol tables or dlopen.

Three gaps this fills:

1. **Zero-caller ambiguity** — `GetRoute_netstat`, `diff_files`, and `fork_and_exec` in PanGPS all have zero static callers in the binary, yet all three are real functions called from companion binaries (PanGPA, libwautils). Without this detector, they'd be silently deprioritized.
2. **Vtable methods already excluded** — functions dispatched via vtable also have zero `CALL rel32` callers. VtableDispatchMapper identifies those. CrossBinaryExportDetector excludes them to avoid double-counting.
3. **Heuristic precision** — canary + source-path xref filters out compiler-generated trampolines, exception landing pads, and hot-patch stubs that look like zero-caller functions but aren't real entry points.

---

## How it works

A function is tagged `CROSS_BINARY_EXPORT` when **all four** of these hold:

1. **Zero incoming `call_edges`** — no `CALL rel32` from any other function in the binary.
2. **Not in any vtable** — `VtableDispatchMapper` does not list it as a slot.
3. **Stack canary present** — `mov rax, fs:[0x28]` within 128 bytes of the function start. Compiler-generated trampolines and stub functions don't have canaries. Real entry points from real .cpp files almost always do.
4. **Source-path string xref** — a RIP-relative LEA within 512 bytes of the function start resolves to a null-terminated string matching `/path/to/file.cpp`. Debug builds embed `__FILE__` strings; stripped binaries retain them in `.rodata`. Compiler-generated helpers don't have these xrefs.

The detector scans `ctx.func_starts` and checks each candidate against the four criteria. It does not call any disassembler — all checks use raw byte patterns on the binary.

---

## Class and method reference

### `CrossBinaryExportDetector`

```python
class CrossBinaryExportDetector:
    from_context(ctx) -> CrossBinaryExportDetector
```

#### `detect(vtable_mapper=None, min_func_size: int = 16) -> List[CrossBinaryExport]`

Return all functions matching the cross-binary export heuristic.

- `vtable_mapper`: optional `VtableDispatchMapper`. When provided, vtable methods are excluded from results.
- `min_func_size`: skip functions smaller than this (bytes between func_start and next func_start). Filters out compiler-generated one-instruction stubs.

#### `report(exports: List[CrossBinaryExport]) -> str`

Human-readable summary with per-function detail.

### `CrossBinaryExport`

```python
@dataclass
class CrossBinaryExport:
    func_va:      int
    name:         str    # ctx.name() result or hex string
    canary:       bool   # always True in results (required by heuristic)
    debug_string: str    # first source-path string found near the function
    caller_count: int    # always 0

    fmt() -> str
    as_dict() -> dict
```

---

## Usage

```python
from ablation.analyzers.vtable_dispatch_mapper import VtableDispatchMapper
from ablation.analyzers.cross_binary_export_detector import CrossBinaryExportDetector

mapper  = VtableDispatchMapper.from_context(ctx)
det     = CrossBinaryExportDetector.from_context(ctx)
exports = det.detect(vtable_mapper=mapper)

for e in exports:
    print(e.fmt())
print(det.report(exports))
```

---

## Example output

```
CrossBinaryExportDetector: PanGPS
  candidates: 3

  [CROSS_BINARY_EXPORT]  GetRoute_netstat @ 0x001591f0  canary=True
    debug: '/src/pan/gp/routing/netstat_route.cpp'
  [CROSS_BINARY_EXPORT]  diff_files @ 0x0005f0f0  canary=True
    debug: '/src/pan/gp/util/diff_files.cpp'
  [CROSS_BINARY_EXPORT]  fork_and_exec @ 0x000667a0  canary=True
    debug: '/src/pan/gp/util/exec_util.cpp'
```

---

## False positives

**`__assert_fail` sites.** A function with a `__FILE__` string xref near its prologue that is actually an assertion handler, not a real entry point. These tend to be small (< 32 bytes) and are filtered by `min_func_size`. Raise `min_func_size` to 32 to reduce these.

**Inlined helpers.** If the compiler inlines a function from another TU but preserves the debug string, the containing function might have a source path from a different file. The canary check keeps this rare.

**Link-time optimization (LTO) artifacts.** Under LTO, functions that are used cross-TU may have both a canonical body (in one binary) and thin copies (in another). The thin copies may have no local callers but also no stack canaries — so they won't be reported.

---

## Pipeline position

```
BinaryContext.load_or_build()
    → VtableDispatchMapper
    → CrossBinaryExportDetector(vtable_mapper=mapper)   ← here (step 2.6)
    → SemanticSearcher → FuncProfiler
    → SinkArgClassifier → [post-SAC filters] → TaintTracker
```

Run after `VtableDispatchMapper` (step 2.5) to get accurate vtable exclusion. The results tell you which zero-caller functions are real entry points from companion binaries — treat them as taint entry points alongside network sources.

---

## Reading findings

A `CrossBinaryExport` result means:

- The function is **probably called from another binary** in the same firmware package.
- **Taint enters at the function boundary** — arguments passed from the companion binary are the initial taint source. Treat them as fully attacker-controlled unless you can prove otherwise.
- The `debug_string` is a hint for which source file to look at when correlating against a patched build or symbol-bearing binary.
- **Next step**: run `SinkArgClassifier` and `TaintTracker` on each cross-binary export to check if it reaches a shell sink with externally-controlled arguments.

---

## See also

- `VtableDispatchMapper` — required companion module for accurate vtable exclusion
- `SinkArgClassifier` — classify shell sink arguments in each identified cross-binary export
- `TaintTracker` — trace argument provenance from function entry to sink call
- `SnprintfVariableFilter` — post-process SAC results to catch injectable format strings

[↑ Back to top](#cross-binary-export-detector)
