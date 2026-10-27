<a id="kasan-oracle-workflow"></a>
# KASAN Finding Validation

Use a KASAN-instrumented debug kernel build to generate candidates, then independently verify each candidate in the corresponding stripped production build.

**Reference result:** during TencentOS 6.6.119 LoongArch64 kernel-module analysis, 14 `LA64MaxNotMinScanner` candidates in the KASAN build produced 11 production confirmations. Three candidates were eliminated because code generation differed between builds.

---

## Why use two builds?

KASAN changes instrumentation, register allocation, inlining, and surrounding control flow. Patterns that are difficult to see in an optimized production binary may be easier to isolate in a debug build. The same differences also mean a debug hit is **not automatically a production finding**: only production instructions and reachability can confirm that result.

## Prerequisites

Two builds from the same source tree and configuration baseline:

| Build | Typical input | Symbols | KASAN |
|:---|:---|:---|:---|
| Debug | `vmlinuz.elf` or debug `.ko` | System.map or debug symbols | Enabled |
| Production | Production `vmlinuz` or `.ko` | Possibly stripped | Disabled |

A version or configuration mismatch can invalidate function matching and produce misleading confirmations or eliminations.

## 1. Identify KASAN instrumentation

Use `LoongArchDecoderV2.from_system_map()` to collect `__asan_*` and `__kcov_*` addresses from the debug kernel's System.map:

```python
from ablation.analyzers.loongarch_decoder_v2 import LoongArchDecoderV2

decoder = LoongArchDecoderV2.from_system_map(
    '/boot/System.map-6.6.119+debug'
)
```

The decoder marks calls to those addresses as instrumentation, allowing analysis to distinguish sanitizer and coverage scaffolding from target logic. For an individual module, use symbols and addresses relocated into that module's context; do not assume unrelocated addresses from another image are directly interchangeable.

## 2. Scan the debug build

Load the scanner with `from_path()` and inject the KASAN-aware decoder:

```python
from ablation.analyzers.loongarch64_max_not_min_scanner import LA64MaxNotMinScanner

scanner = LA64MaxNotMinScanner.from_path('/path/to/debug-module.ko')
scanner.decoder = decoder
candidates = scanner.scan()
print(scanner.report(candidates))
```

For a symbolized `vmlinux` taint workflow, the LoongArch64 tracker also provides a System.map constructor:

```python
from ablation.analyzers.taint_tracker_loongarch64 import LoongArch64TaintTracker

tracker = LoongArch64TaintTracker.from_system_map(
    '/path/to/debug-vmlinux',
    '/path/to/debug-System.map',
)
findings = tracker.run_interprocedural()
```

Record each candidate's function address, pattern address, sink, and instruction context. Keep candidates with an empty or low-confidence classification separate from confirmed production findings.

## 3. Match functions into production

For each debug candidate:

1. Find the corresponding production function using trusted symbols where available, or structural/semantic matching when stripped.
2. Verify that the matched functions implement the same logic; similar control flow alone is insufficient.
3. Inspect the production comparison, arithmetic, and sink argument flow.
4. Record one of the outcomes below.

| Outcome | Meaning |
|:---|:---|
| Same pattern and data flow in production | **CONFIRMED** after byte-level and reachability review. |
| Related but different production pattern | Verify independently as a potentially different issue. |
| Pattern absent in production | **ELIMINATED** as a debug-only code-generation candidate. |
| Function absent in production | Exclude it from the production result and record the configuration difference. |

Rescan the production image and filter results for the matched function address:

```python
production = LA64MaxNotMinScanner.from_path('/path/to/production-module.ko')
production_hits = production.scan()
matched_hits = [f for f in production_hits if f.func_va == production_va]
print(production.report(matched_hits))
```

`LA64MaxNotMinScanner` exposes whole-image `scan()` rather than a public `scan_function()` method. A zero `func_va` means the enclosing function was not resolved and requires manual attribution.

## 4. Record the verification split

Preserve both confirmed and eliminated candidates so later reviews can understand the result:

```text
KASAN build:  14 candidates across 13 modules
Production:   11 confirmed, 3 eliminated
Eliminated:   mlxsw_i2c, iwlwifi, rpcrdma
Elimination rate: 21%
```

A high elimination rate is a reason to scrutinize build differences and matching quality; it is not by itself a scanner-quality metric.

## Debug-only patterns to review carefully

| Pattern | Likely cause | Verification action |
|:---|:---|:---|
| Shadow-address arithmetic around memory accesses | KASAN shadow mapping | Exclude instrumentation arithmetic from the target data-flow explanation. |
| Calls to `__asan_load*` / `__asan_store*` | Sanitizer bounds checks | Identify through the instrumentation VA set; do not report as target sinks. |
| `__kcov_trace_pc` at function entry | KCOV coverage tracing | Exclude from call-graph and function-role conclusions. |
| Function present only in debug | Configuration or dead-code difference | Check production configuration and linked module membership. |

## Limitations

- KASAN is an analysis aid, not an exploitability oracle.
- Production confirmation requires real instructions and a feasible runtime path, not only a matching function name.
- Stripped-function matching can be uncertain after heavy optimization or refactoring; record the matching evidence.
- When only one build exists, analyze that build directly and document its instrumentation and optimization context instead of simulating a two-build comparison.

## Related

- [LoongArch & nanoMIPS Analysis](../reference-modules/loongarch64-2.md): architecture decoding and KASAN-aware analysis.
- [Compiler & VxWorks Analysis](../reference-modules/compiler-defects.md): the max-not-min scanner and related compiler-defect checks.
- [Windows Driver Vulnerabilities](../reference-modules/kernel-drivers.md): kernel-module analysis and driver attack surfaces.
