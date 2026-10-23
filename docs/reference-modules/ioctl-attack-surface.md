# IOCTL Attack Surface

**File:** `modules/ioctl_attack_surface.py`

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
    print(f"CRITICAL 0x{profile.ioctl_raw:08x}  method={profile.method_name}")
    for pattern in profile.dangerous_patterns:
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
| `ioctl_raw` | Raw IOCTL code (32-bit) |
| `method` | Transfer method: 0–3 |
| `method_name` | `METHOD_BUFFERED` / `METHOD_IN_DIRECT` / `METHOD_OUT_DIRECT` / `METHOD_NEITHER` |
| `device_type` | Upper 16 bits of IOCTL code |
| `function_code` | Bits [13:2] of IOCTL code |
| `access` | Bits [15:14] of IOCTL code |
| `handler_va` | VA of the dispatch handler function |
| `dangerous_patterns` | `list[IoctlHandlerPattern]`: security-relevant patterns found in the handler |
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

`IoctlAttackSurfaceGenerator(driver_path).analyze()` reads the driver binary with LIEF, then uses Capstone to disassemble the IOCTL dispatch handler. It decodes `IoControlCode` fields from `IO_STACK_LOCATION` offsets (`+0x18`) found in the disassembly, extracting each raw IOCTL code and its transfer method (bits `[1:0]`). For each decoded code, it traces the corresponding handler to record: whether `ProbeForRead`/`ProbeForWrite` is called, whether `InputBufferLength` reaches an allocation call, and whether any copy or dangerous API is present. File size is capped at `_MAX_DRIVER_BYTES = 64 MB`. An optional `kda_report` (pre-built `KernelDriverReport`) can be supplied to avoid re-parsing.

---

## Example output

```
[ioctl_attack_surface] driver.sys
  driver_type=WDM  signed=True
  pdb_path=N/A
  3 IOCTL codes: 1 CRITICAL, 0 HIGH, 1 METHOD_NEITHER

  IOCTL 0x00222003  DevType=0x0022  Func=0x0800  METHOD_NEITHER  [CRITICAL]  USER-DEFINED
    handler_va=0x19a40
    flags: reads_input_len, has_alloc
    *** METHOD_NEITHER without ProbeForRead/Write: raw user pointer deref = arbitrary kernel R/W ***

  IOCTL 0x00222007  DevType=0x0022  Func=0x0801  METHOD_BUFFERED  [INFO]
    handler_va=0x19a40
    flags: reads_input_len, reads_output_len, has_copy
```

---

## False positives

IOCTL codes decoded from data sections (jump tables, pool tags) that coincidentally match the `CTL_CODE` pattern. The scanner applies an ASCII-filter (`decode_ioctl_code` rejects all-printable 4-byte values) but this does not eliminate all false positives. Verify each `METHOD_NEITHER` finding against the actual dispatch handler before reporting.

---

## Pipeline position

**Before this module:** Nothing required: `from_path(path)` is self-contained.

**After this module:** For `METHOD_NEITHER` IOCTLs without ProbeForRead, trace `Type3InputBuffer` dereferences in the handler manually. Use `KernelDriverAnalyzer` to extend the analysis with MSR/CR patterns.

---

## Reading output

`IoctlAttackSurfaceGenerator.from_path(path).generate()` returns an `IoctlAttackSurface`:

| Attribute | Content |
|:---|:---|
| `binary_path` | Path of the analyzed driver binary |
| `driver_type` | Detected driver class (e.g., `'WDM'`, `'WDF'`) |
| `is_signed` | `True` if the driver has an Authenticode signature |
| `pdb_path` | PDB symbol path string from the PE header, or `None` |
| `profiles` | `List[IoctlHandlerProfile]`: one entry per decoded IOCTL code |

Each `IoctlHandlerProfile` key fields:

| Attribute | Content |
|:---|:---|
| `ioctl_raw` | Raw IOCTL code value |
| `method_name` | Transfer method string: `'METHOD_BUFFERED'` / `'METHOD_NEITHER'` / etc. |
| `risk_level` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` (derived property) |
| `has_probe` | `True` if handler calls `ProbeForRead`/`ProbeForWrite` |
| `handler_va` | VA of the dispatch handler function (0 if not located) |
| `dangerous_patterns` | `List[IoctlHandlerPattern]`: specific dangerous patterns found |

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
