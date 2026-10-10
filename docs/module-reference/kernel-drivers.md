# Windows Kernel Driver Analysis

Two cooperating modules for Windows kernel driver RE: `KernelDriverAnalyzer` for
attack surface mapping and `ByovdDetector` for identifying drivers with exploitable
capabilities. Run `KernelDriverAnalyzer` first. `ByovdDetector` consumes its output.

---

## KernelDriverAnalyzer

**File:** `ablation/analyzers/kernel_driver_analyzer.py`

Full attack surface mapping for Windows kernel drivers (`.sys` files). Classifies
driver framework, recovers the IRP dispatch table, decodes every IOCTL code, audits
the kernel API surface, and flags dangerous byte patterns.

### Architecture support

`KernelDriverAnalyzer` detects PE machine type on construction:
- **x86 (IMAGE_FILE_MACHINE_I386, 0x014c):** uses Capstone `CS_MODE_32`; recovers `MajorFunction` from `DRIVER_OBJECT+0x38` (4-byte slots); uses prologue-seeded disassembly for IOCTL extraction and pattern scanning (see below)
- **x64 (IMAGE_FILE_MACHINE_AMD64, 0x8664):** uses Capstone `CS_MODE_64`; recovers `MajorFunction` from `DRIVER_OBJECT+0x70` (8-byte slots); uses `.pdata`-bounded disassembly

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

### IoctlCascadeDecoder

MSVC-compiled `switch(IoControlCode)` handlers emit a cascade of register subtractions
rather than a jump table. The decoder reconstructs every `CTL_CODE` in the cascade,
including those derived via a **stride register** loaded with `push imm; pop reg` (a
3-byte MSVC optimizer idiom that saves 2 bytes over `sub reg, imm32` per arm):

```
MOV  ECX, EAX              ; ECX = IoControlCode
SUB  ECX, 0x1a2504         ; base (first IOCTL)
JE   handler_0
PUSH 4
POP  EAX                   ; stride = 4 loaded into EAX
SUB  ECX, EAX              ; derive 0x1a2508
JE   handler_1
SUB  ECX, EAX              ; derive 0x1a250c
JE   handler_2
```

Used internally by `KernelDriverAnalyzer._extract_ioctl_codes`. Exported for standalone use:

```python
from ablation.analyzers.kernel_driver_analyzer import IoctlCascadeDecoder
import capstone

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
cs.detail = True
decoder = IoctlCascadeDecoder(cs, image_base=0x10000)
codes = decoder.decode_section(section_code_bytes, section_va)
```

### Boundary-safe disassembly

x86 WDM drivers embed function pointer tables at the start of `.text` and `INIT`
sections. The byte `0x67` (address-size override prefix) appears as a ModRM byte in
those tables; Capstone stops generating instructions when it encounters this sequence.
`KernelDriverAnalyzer` avoids this by scanning for `55 8B EC` (PUSH EBP; MOV EBP, ESP)
prologues and disassembling only from known function starts.

For x64, `UNWIND_INFO` data is sometimes embedded after function bodies inside `.text`.
The `.pdata` exception directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`) gives
`[BeginAddress, EndAddress)` ranges for each function; only those ranges are disassembled.

### IOCTL decoder (standalone)

```python
from ablation.analyzers.kernel_driver_analyzer import decode_ioctl_code

ic = decode_ioctl_code(0x222003, site_va=0)
print(ic.fmt())
# 0x00222003  DevType=0x0022  Func=0x800  METHOD_NEITHER          FILE_ANY_ACCESS *** NEITHER (raw user ptr)
```

`decode_ioctl_code` rejects 32-bit values where every byte falls in the printable ASCII range
(0x20-0x7E). MSVC embeds 4-byte ASCII debug strings such as pool tags and format strings in
`.text`; without this filter, strings like `"acid"` (0x64696361) decode as plausible IOCTLs.
Real `CTL_CODE` values cannot have all four bytes printable because the high word encodes a
device-type constant whose upper byte is almost always zero or 0x80.

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

### Zero-IAT drivers

Some WDM drivers (notably XP-era touchscreen controllers such as eGalaxTouch) set
`ImportDirectory.VirtualAddress = 0` and resolve every kernel API at runtime by calling
`MmGetSystemRoutineAddress(L"ApiName")`. The import table is empty, so the normal IAT scan
produces no API findings.

`KernelDriverAnalyzer` detects this class by falling back to a UTF-16LE string search of
the entire binary when the IAT scan returns zero findings. Every API in `KERNEL_APIS` that
appears as a wide string literal in the driver shows up in the report tagged `[dynamic-resolve]`
instead of a DLL name.

### Dangerous patterns

In addition to the MSR-write and CR-register patterns, `analyze()` reports two new pattern
codes:

**`WRITABLE_VTABLE_IN_DATA`** — the analyzer scans writable, non-executable PE sections for
runs of three or more consecutive aligned pointers into executable sections. A vtable stored
in `.data` is mutable at runtime. Any kernel write primitive that reaches the vtable converts
to an IRP dispatch hijack: overwrite one function pointer slot and every IRP that hits that
handler executes attacker code.

**`NEITHER_IOCTL_NO_PROBE`** — the analyzer checks every `METHOD_NEITHER` IOCTL code against
the driver's IAT and its UTF-16LE string table. When neither `ProbeForRead` nor `ProbeForWrite`
appears anywhere in the binary, every dereference of `Type3InputBuffer` is an unvalidated
kernel read or write path (CWE-822). The finding lists all METHOD_NEITHER IOCTL codes found.

---

## ByovdDetector

**File:** `ablation/analyzers/byovd_detector.py`

### Why this exists

3 things that weren't possible before in Ablation:

1. **Capability taxonomy for BYOVD triage** — `KernelDriverAnalyzer` flags dangerous API
   imports but returns a flat list with no BYOVD classification. Deciding whether a driver
   is a viable BYOVD candidate (vs. just a driver that happens to call `ZwTerminateProcess`)
   required a manual cross-reference against loldrivers.io and the 8 capability classes.
   Now it's a single `detect()` call with `report.is_byovd_capable`.

2. **Known-vulnerable driver string matching** — strip a driver's import table and
   `KernelDriverAnalyzer` loses most of its signal. Strings like `\\Device\\PhysicalMemory`,
   `MHYPROT`, `dbutil`, `RTCore64` survive stripping; checking for them was a per-engagement
   manual step. `ByovdDetector` folds this into the same pass and elevates confidence even
   when imports are absent.

3. **Composition without re-parsing** — running `KernelDriverAnalyzer` then `ByovdDetector`
   on the same `.sys` parsed the PE twice, doubling I/O on large driver batches. The
   `kda_report=` constructor argument passes an existing `KernelDriverReport` directly,
   eliminating the second parse.

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
from ablation.analyzers.byovd_detector import ByovdDetector

detector = ByovdDetector.from_path('/path/to/driver.sys')
result = detector.detect()
print(result.fmt())

if result.is_byovd_capable:
    for cap in result.capabilities:
        print(f"  {cap.capability_class}: {cap.api_name}")

# Check for a specific capability class
if any(c.capability_class == 'PHYS_MEM_RW' for c in result.capabilities):
    print("Physical memory R/W capability confirmed")
```

### Composing with KernelDriverAnalyzer

`ByovdDetector` accepts an existing `KernelDriverReport` to avoid re-parsing the PE:

```python
from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer
from ablation.analyzers.byovd_detector import ByovdDetector

kda = KernelDriverAnalyzer.from_path('/path/to/driver.sys')
driver_report = kda.analyze()
print(driver_report.fmt())

detector = ByovdDetector('/path/to/driver.sys', kda_report=driver_report)
byovd_result = detector.detect()
print(byovd_result.fmt())
```

### Known-vulnerable driver strings detected

The detector flags strings associated with confirmed BYOVD samples: `\Device\PhysicalMemory`,
`GIO` (Giga I/O), `MHYPROT` (miHoYo anti-cheat), `dbutil` (Dell BIOS driver), and others
from the loldrivers.io database. A string match elevates the finding confidence even when
the import table is stripped.
