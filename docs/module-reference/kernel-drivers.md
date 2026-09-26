# Windows Kernel Driver Analysis

Two cooperating modules for Windows kernel driver RE: `KernelDriverAnalyzer` for
attack surface mapping and `BYOVDDetector` for identifying drivers with exploitable
capabilities. Run `KernelDriverAnalyzer` first. `BYOVDDetector` consumes its output.

---

## KernelDriverAnalyzer

**File:** `ablation/analyzers/kernel_driver_analyzer.py`

Full attack surface mapping for Windows kernel drivers (`.sys` files). Classifies
driver framework, recovers the IRP dispatch table, decodes every IOCTL code, audits
the kernel API surface, and flags dangerous byte patterns.

### What it maps

- **Driver framework:** WDM / KMDF / minifilter classification
- **DriverEntry** VA and the `MajorFunction` dispatch table (IRP_MJ_* handlers)
- **IOCTL codes:** all `CTL_CODE` values found in the binary, decoded
- **Kernel API surface audit:** 40+ dangerous API patterns across 8 risk classes
- **Dangerous byte patterns:** MSR writes (`WRMSR`), CR0/CR4 manipulation, `HLT`
- **PDB path** from RSDS debug directory
- **Authenticode** signature presence check
- **Pool tags** and pool operation extraction

### Usage

```python
from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer

kda = KernelDriverAnalyzer.from_path('/path/to/driver.sys')
report = kda.analyze()
print(report.fmt())
```

### IOCTL decoder (standalone)

```python
from ablation.analyzers.kernel_driver_analyzer import decode_ioctl_code

ic = decode_ioctl_code(0x222003, site_va=0)
print(ic.fmt())
# 0x00222003  DevType=0x0022  Func=0x800  METHOD_NEITHER          FILE_ANY_ACCESS *** NEITHER (raw user ptr)
```

### IOCTL CTL_CODE layout

| Bits | Field | Notes |
|---|---|---|
| 31:16 | DeviceType | 0x0001-0x7FFF system; 0x8000-0xFFFF user-defined |
| 15:14 | Access | FILE_ANY_ACCESS / FILE_READ_ACCESS / FILE_WRITE_ACCESS |
| 13:2 | Function | 0x000-0x7FF system; 0x800-0xFFF user-defined |
| 1:0 | Method | BUFFERED=0 / IN_DIRECT=1 / OUT_DIRECT=2 / NEITHER=3 |

`METHOD_NEITHER` (method=3) is the most dangerous: no buffer copy occurs, and a raw
user-mode pointer is passed directly into the dispatch handler.

### Risk classification

| Risk class | Representative APIs |
|---|---|
| Physical memory R/W | `MmMapIoSpace`, `MmMapIoSpaceEx`, `HalTranslateBusAddress`, `MmGetPhysicalAddress` |
| Process termination | `ZwTerminateProcess`, `NtTerminateProcess` |
| Token manipulation | `PsInitialSystemProcess`, `PsLookupProcessByProcessId`, `SeQueryInformationToken` |
| Memory write | `ZwWriteVirtualMemory`, `ZwProtectVirtualMemory` |
| Driver load | `ZwLoadDriver`, `IoCreateDriver` |
| Callback removal | `PsRemoveLoadImageNotifyRoutine`, `ObUnRegisterCallbacks` |
| DKOM | `ObReferenceObjectByHandle`, `KeStackAttachProcess` |
| APC injection | `KeInitializeApc`, `KeInsertQueueApc` |

---

## BYOVDDetector

**File:** `ablation/analyzers/byovd_detector.py`

Identifies signed kernel drivers that carry exploitable capabilities across 8 BYOVD
capability classes. Used to determine whether a driver is a viable BYOVD candidate:
a legitimate Authenticode-signed binary that an attacker can abuse to bypass EDR
controls, manipulate kernel objects, or escalate to ring-0.

### What BYOVD is

Attackers load a legitimate, Authenticode-signed driver with dangerous built-in
capabilities and exploit those capabilities to bypass endpoint detection or escalate
privileges. The signed driver legitimizes the load; the capability provides the primitive.
Reference: [loldrivers.io](https://www.loldrivers.io/) for known-vulnerable driver samples.

### Detection strategy

1. **Static signature:** identify dangerous capability imports from the import table
2. **IOCTL surface scan:** find IOCTLs that accept physical addresses or process handles and trace them to the dangerous APIs
3. **String evidence:** device path names, known vulnerable driver strings, `\Device\PhysicalMemory` access

### Capability classes

| Class | Severity | What it enables |
|---|---|---|
| `PHYS_MEM_RW` | CRITICAL | Map physical memory from user-controlled address → arbitrary kernel R/W |
| `TOKEN_STEAL` | CRITICAL | `PsInitialSystemProcess` + token copy pattern → privilege escalation |
| `DKOM` | CRITICAL | Direct `_EPROCESS` manipulation via `ObReferenceObjectByHandle` |
| `APC_INJECT` | CRITICAL | Code execution in another process via APC queue |
| `MSR_WRITE` | CRITICAL | `WRMSR` via IOCTL passthrough → modify `LSTAR`/`STAR`/`SYSENTER` |
| `DRIVER_LOAD` | HIGH | `ZwLoadDriver` / `IoCreateDriver` → load additional unsigned modules |
| `CALLBACK_REMOVE` | HIGH | Remove EDR load-image / thread-notify callbacks → blind detection |
| `PROCESS_KILL` | HIGH | `ZwTerminateProcess` with elevated privilege → kill EDR processes |

### Usage

```python
from ablation.analyzers.byovd_detector import BYOVDDetector

detector = BYOVDDetector.from_path('/path/to/driver.sys')
result = detector.detect()
print(result.fmt())

# Summary: is this a BYOVD candidate?
if result.is_byovd_candidate:
    print(f"BYOVD candidate — capabilities: {result.capability_classes}")

# Check for specific capability
if 'PHYS_MEM_RW' in result.capability_classes:
    print("Physical memory R/W capability confirmed")
```

### Composing with KernelDriverAnalyzer

`BYOVDDetector` reuses `KernelDriverAnalyzer` output to avoid re-parsing the PE:

```python
from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer
from ablation.analyzers.byovd_detector import BYOVDDetector

kda = KernelDriverAnalyzer.from_path('/path/to/driver.sys')
driver_report = kda.analyze()
print(driver_report.fmt())

detector = BYOVDDetector.from_driver_report(driver_report)
byovd_result = detector.detect()
print(byovd_result.fmt())
```

### Known-vulnerable driver strings detected

The detector flags strings associated with confirmed BYOVD samples: `\Device\PhysicalMemory`,
`GIO` (Giga I/O), `MHYPROT` (miHoYo anti-cheat), `dbutil` (Dell BIOS driver), and others
from the loldrivers.io database. A string match elevates the finding confidence even when
the import table is stripped.
