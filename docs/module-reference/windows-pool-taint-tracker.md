# WindowsPoolTaintTracker

## Why this exists

2 things that weren't possible before in Ablation:

1. **No kernel pool allocation tracking.** `ExAllocatePool*` is the Windows kernel heap. A driver that allocates a pool buffer and then copies user-supplied data into it using `RtlCopyMemory` is the template for a kernel pool overflow. Before this module, Ablation's `HeapVulnScanner` tracked `malloc`/`calloc` on userland ELF binaries. It had no IAT-based path for Windows kernel PE drivers, no understanding of `ExAllocatePool*` vs `ExAllocatePool2`/`ExAllocatePool3`, and no concept of `RtlCopyMemory` as a copy sink.

2. **No allocation-to-copy taint pairing.** Even if you manually found an `ExAllocatePool` call site and a `RtlCopyMemory` call site in the same function, determining whether the *same size value* flowed from the allocation to the copy required register-level taint tracing through a window of instructions. The existing `TaintTracker` module targets x86-64 ELF and is built around userland sinks. There was no driver-focused, allocation-size-to-copy-size taint path.

---

## What it does

`WindowsPoolTaintTracker` works on x64 Windows PE kernel drivers. It:

1. Builds an IAT map for `ExAllocatePool`, `ExAllocatePoolWithTag`, `ExAllocatePool2`, `ExAllocatePool3`, and five other pool allocation variants.
2. Builds an IAT map for `RtlCopyMemory`, `memmove`, `memcpy`, `RtlMoveMemory`, `RtlCopyBytes`, `RtlCopyUnicodeString`, `ProbeAndReadBuffer`.
3. Scans all code sections with Capstone. For each allocation call site, extracts the size argument (second argument — `RDX` in x64 fastcall). For each copy call site, extracts the size argument (third argument — `R8`).
4. Pairs allocation sites with copy sites where the same register carries the size to both calls, within a forward instruction window of ~200 instructions (same-function heuristic).
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

CWE: CWE-122 (Heap-based Buffer Overflow) on HIGH/MEDIUM.

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

- `lief >= 0.14.0` (PE parsing, IAT, section headers)
- `capstone >= 5.0` (x64 call site scanning, register argument extraction)
