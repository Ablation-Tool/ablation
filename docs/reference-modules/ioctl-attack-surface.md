# IOCTL Attack Surface

**File:** `ablation/analyzers/ioctl_attack_surface.py`

Maps the complete IOCTL dispatch surface of a Windows kernel driver and flags METHOD_NEITHER codes before manual review begins. An integer-overflow path from a user-supplied length to a kernel allocation is a HIGH finding. Unprobed METHOD_NEITHER dereferences are CRITICAL.

Grounded in TAOSSA Chapter 12 (Windows IPC, DeviceIoControl, IRP dispatch model) and Windows Internals Part 1 Chapter 6 (I/O Manager, IRP, IO_STACK_LOCATION layout).

---

## Why this exists

Three gaps existed before this module:

1. **METHOD_NEITHER codes required manual identification.** Drivers with METHOD_NEITHER IOCTL handlers pass raw user-mode pointers directly to kernel code, no buffer copy, no length check. Locating these codes across a dispatch table required pattern-matching each handler by hand.

2. **ProbeForRead/ProbeForWrite coverage was untracked.** METHOD_NEITHER handlers that call ProbeForRead before dereferencing are protected; those that do not are immediately exploitable. The module classifies each handler so manual review starts at the unprotected ones.

3. **User-length → kernel-allocation paths were invisible.** Drivers that read `InputBufferLength` from the IRP stack location and pass it directly to `ExAllocatePoolWithTag` without bounds checking are vulnerable to integer-overflow heap allocation. The module traces this path statically without a running driver.

---

## IOCTL transfer method classification

| Method | Value | User buffer handling |
|---|---|---|
| `METHOD_BUFFERED` | 0 | I/O Manager copies; kernel sees `SystemBuffer` |
| `METHOD_IN_DIRECT` | 1 | MDL locked; read-only access |
| `METHOD_OUT_DIRECT` | 2 | MDL locked; write access |
| `METHOD_NEITHER` | 3 | Raw user pointer; **no kernel copy, no probe by default** |

`METHOD_NEITHER` handlers receive `Type3InputBuffer` directly: a raw user-mode address the kernel does not validate. Any dereference without a prior `ProbeForRead`/`ProbeForWrite` is a CRITICAL finding.

---

## IO_STACK_LOCATION offsets (x64)

| Offset | Field | Width |
|---|---|---|
| +0x08 | `OutputBufferLength` | ULONG |
| +0x10 | `InputBufferLength` | ULONG |
| +0x18 | `IoControlCode` | ULONG |
| +0x20 | `Type3InputBuffer` | PVOID (METHOD_NEITHER only) |
| +0x70 | `SystemBuffer` | PVOID (METHOD_BUFFERED) |

---

## Usage

```python
from modules.ioctl_attack_surface import IoctlAttackSurfaceGenerator

# Full surface map
gen = IoctlAttackSurfaceGenerator('/path/to/driver.sys')
surface = gen.analyze()
print(surface.fmt())

# Summary counts
print(surface.summary())
# {'binary': ..., 'total_ioctls': 12, 'critical': 2, 'high': 3, 'method_neither': 4}

# CRITICAL handlers only (METHOD_NEITHER without ProbeForRead)
for profile in surface.critical:
    print(f"CRITICAL 0x{profile.ioctl_code:08x}  method={profile.method_name}")
    for pattern in profile.patterns:
        print(f"  [{pattern.severity}] {pattern.description}")

# Reuse an existing KernelDriverReport to avoid re-parsing
from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer
report = KernelDriverAnalyzer.from_path('/path/to/driver.sys').analyze()
gen = IoctlAttackSurfaceGenerator('/path/to/driver.sys', kda_report=report)
surface = gen.analyze()
```

---

## Finding fields

### `IoctlHandlerProfile`

| Field | Description |
|---|---|
| `ioctl_code` | Raw IOCTL code (32-bit) |
| `method` | Transfer method: 0–3 |
| `method_name` | `METHOD_BUFFERED` / `METHOD_IN_DIRECT` / `METHOD_OUT_DIRECT` / `METHOD_NEITHER` |
| `device_type` | Upper 16 bits of IOCTL code |
| `function_code` | Bits [13:2] of IOCTL code |
| `access` | Bits [15:14] of IOCTL code |
| `handler_va` | VA of the dispatch handler function |
| `patterns` | `list[IoctlHandlerPattern]`: security-relevant patterns found in the handler |
| `has_probe` | `True` if `ProbeForRead`/`ProbeForWrite` appears in the handler |
| `risk_level` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |

### `IoctlHandlerPattern`

| Field | Description |
|---|---|
| `pattern_type` | `METHOD_NEITHER_DEREF` / `UNGUARDED_COPY` / `ALLOC_USER_LEN` / `MISSING_PROBE` |
| `offset` | File offset in the binary |
| `description` | Human-readable description of the pattern |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |

---

## Severity logic

| Condition | Severity |
|---|---|
| METHOD_NEITHER handler with no ProbeForRead/ProbeForWrite | CRITICAL |
| METHOD_NEITHER handler with probe present | HIGH |
| `InputBufferLength` → `ExAllocatePool*` without bounds check | HIGH |
| Fixed-size stack buffer copy with user-supplied length | HIGH |
| `RtlCopyMemory`/`memcpy` call in handler | MEDIUM |
| METHOD_BUFFERED handler (generally safe) | INFO |

---

## Pair with `KernelDriverAnalyzer`

`IoctlAttackSurfaceGenerator` builds on `KernelDriverAnalyzer`. Run both on the same driver: `KernelDriverAnalyzer` provides CFG bypass exports, SafeSEH gaps, COM registration gaps, and pool overflow findings; `IoctlAttackSurfaceGenerator` maps the IOCTL dispatch surface. Together they cover the full Windows kernel driver attack surface before manual review begins.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `_MAX_DRIVER_BYTES=64MB`; `Path.stat().st_size` guard in `__init__()` before `read_bytes()`. `lief.parse()` in `try/except Exception`. No HTTP reads.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Example output

```
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `finding_type` | Scanner-specific category label |
| `va` | Virtual address of the call site or instruction in the binary |
| `func_va` | Virtual address of the containing function |
| `detail` | What was found and the specific condition that triggered it |
| `sink_name` | Name of the dangerous function reached (if applicable) |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
