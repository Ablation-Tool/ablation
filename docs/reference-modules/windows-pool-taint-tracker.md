# WindowsPoolTaintTracker

## Why this exists

Two things were not possible before in Ablation:

1. **No kernel pool allocation tracking.** `ExAllocatePool*` is the Windows kernel heap. A driver that allocates a pool buffer and then copies user-supplied data into it using `RtlCopyMemory` is the template for a kernel pool overflow. Before this module, Ablation's `HeapVulnScanner` tracked `malloc`/`calloc` on userland ELF binaries. It had no IAT-based path for Windows kernel PE drivers, no understanding of `ExAllocatePool*` vs `ExAllocatePool2`/`ExAllocatePool3`, and no concept of `RtlCopyMemory` as a copy sink.

2. **No allocation-to-copy taint pairing.** Even if you manually found an `ExAllocatePool` call site and a `RtlCopyMemory` call site in the same function, determining whether the *same size value* flowed from the allocation to the copy required register-level taint tracing through a window of instructions. The existing `TaintTracker` module targets x86-64 ELF and is built around userland sinks. There was no driver-focused, allocation-size-to-copy-size taint path.

---

## What it does

`WindowsPoolTaintTracker` works on x64 Windows PE kernel drivers. It:

1. Builds an IAT map for `ExAllocatePool`, `ExAllocatePoolWithTag`, `ExAllocatePool2`, `ExAllocatePool3`, and five other pool allocation variants.
2. Builds an IAT map for `RtlCopyMemory`, `memmove`, `memcpy`, `RtlMoveMemory`, `RtlCopyBytes`, `RtlCopyUnicodeString`, `ProbeAndReadBuffer`.
3. Scans all code sections with Capstone. For each allocation call site, extracts the size argument (second argument: `RDX` in x64 fastcall). For each copy call site, extracts the size argument (third argument: `R8`).
4. Pairs allocation sites with copy sites where the same register carries the size to both calls, within a forward instruction window of ~200 instructions same-function heuristic.
5. Reports unvalidated pairs as HIGH findings with CWE-122.

---

## Usage

```python
from ablation.analyzers.windows_pool_taint_tracker import WindowsPoolTaintTracker

tracker = WindowsPoolTaintTracker.from_path('driver.sys')
findings = tracker.scan()
print(WindowsPoolTaintTracker.report(findings))
```

To pair with `KernelDriverAnalyzer` for full driver triage:

```python
from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer
from ablation.analyzers.windows_pool_taint_tracker import WindowsPoolTaintTracker

kda = KernelDriverAnalyzer.from_path('driver.sys')
kda_report = kda.analyze()

tracker = WindowsPoolTaintTracker.from_path('driver.sys')
pool_findings = tracker.scan()
```

---

## Findings

| Severity | Category | Trigger |
|---|---|---|
| HIGH | `pool_overflow` | Allocation size register reaches copy sink size without intervening comparison |
| MEDIUM | `unvalidated_copy` | Allocation → copy pairing with some intervening code |
| INFO | `alloc_inventory` | Count of allocation and copy call sites |
| INFO | `no_pool` | No pool allocation imports |

CWE: CWE-122 Heap-based Buffer Overflow on HIGH/MEDIUM.

---

## Taint model

The tracker uses a conservative register-identity heuristic: it records which register holds the size argument at each call site and flags pairs where the same register ID appears at both. It does not perform full SSA-based dataflow but does handle the common case where the compiler loads `InputBufferLength` into a register and passes that register directly to both `ExAllocatePool` and `RtlCopyMemory`.

For deeper confirmation of a flagged pair, use `TaintTracker` or manual Capstone trace on the flagged function.

---

## Pool allocation function reference

| Function | Size arg position | Notes |
|---|---|---|
| `ExAllocatePool` | arg 1 (RDX) | Deprecated in Windows 10 21H2+ |
| `ExAllocatePoolWithTag` | arg 1 (RDX) | Standard tagged allocation |
| `ExAllocatePool2` | arg 1 (RDX) | Windows 10 2004+ replacement |
| `ExAllocatePool3` | arg 1 (RDX) | Extended params variant |

---

## Dependencies

- `lief >= 0.14.0` PE parsing, IAT, section headers
- `capstone >= 5.0` x64 call site scanning, register argument extraction

---

## How it works

Seeds the worklist with every call site of each configured source function. For each seeded location, a linear Capstone disassembly pass applies the taint lattice rules instruction by instruction, propagating taint through register moves, arithmetic, and memory operations. When a call instruction targets a PLT stub that resolves to a sink function and the relevant argument register is tainted, a `TaintFinding` is emitted. Internal calls push a new entry onto the worklist so taint follows the call graph interprocedurally up to `max_depth` levels.

---

## Example output

```
[CRITICAL] system() at 0x4023A0
  source:   recv() at 0x401F00
  arg:      rdi (arg 0)
  chain:    recv→rdi → strcpy buf → system rdi
  path:     [0x401F00, 0x4020C0, 0x4023A0]
  severity: CRITICAL (exec sink, externally controlled argument)
```

---

## False positives

The most common false positive is taint surviving a zero-clear instruction (`xor rax, rax`). The `CLR` rule in the taint lattice clears taint unconditionally on self-XOR, but some architectures use different clearing idioms. Use `SinkArgClassifier` to pre-filter `RODATA_CONST` call sites before running the taint tracker, these are not findings regardless of register state.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`, then `SinkArgClassifier.classify_all()` to eliminate `RODATA_CONST` call sites. Only pass `ARG_PROPAGATED` and `UNKNOWN` sinks to the taint tracker.

**After this module:** `PathSolver` to confirm path feasibility. `FindingRegistry.register()` to record confirmed findings.

---

## Reading findings

| Field | Content |
|:---|:---|
| `sink_name` | Name of the dangerous function reached |
| `sink_va` | Virtual address of the call site |
| `source_name` | Name of the taint source (e.g., `recv`, `read`) |
| `arg_index` | Which argument to the sink carries taint 0-indexed |
| `chain` | `[va, register, operation]` steps from source to sink |
| `path` | `[caller_va, ...]` function VAs traversed interprocedurally |
| `severity` | `CRITICAL` for exec sinks, `HIGH` for memory sinks |

---

## See also

- [TaintAnalysis](taint-analysis.md): multi-architecture taint tracking reference
- [SinkArgClassifier](sink-arg-classifier.md): pre-filter RODATA_CONST sinks before taint
- [PathSolver](path-solver.md): confirm path feasibility after a taint hit
- [SinkPropagator](sink-propagator.md): extend sink coverage across wrappers
