<a id="windows-pe-security-analysis"></a>
# Windows Binary Analysis

Seven security analyzers in one pass over a Windows PE binary. Covers CFG, SafeSEH, ETW, RPC, COM, kernel pool overflows, and BYOVD capabilities.

---

## Why this exists

Two things were not possible before the Windows PE stack:

**1. A single-call security audit across the full Windows PE attack surface.**
Each analyzer previously required a separate tool with a separate output format and separate manual interpretation. Running them in sequence meant context-switching between tools and manually correlating findings. Ablation runs all seven in one session startup with consistent finding format and severity levels.

**2. BYOVD capability classification on signed drivers.**
Identifying that a driver has physical memory read/write, token stealing, or callback removal capability required manual reading of import tables and disassembly of `DriverEntry`. `ByovdDetector` classifies eight capability classes from the kernel API surface of any `.sys` file in seconds.

---

## How the seven analyzers fit together

```mermaid
flowchart TD
    A(["Windows PE binary (.exe / .dll / .sys)"]):::input --> B["KernelDriverAnalyzer (.sys files only)\nPE machine type: 0x014c (x86) or 0x8664 (x64)\nDriver framework: WDM / KMDF / minifilter\nDriverEntry VA and MajorFunction dispatch table\nIOCTL codes from IRP_MJ_DEVICE_CONTROL handler\nKernel API surface: 40+ patterns across 8 risk classes\nDangerous byte patterns: WRMSR, CR0/CR4 write\nPDB path from RSDS debug directory"]:::primary

    B:::primary --> C["CFGBypassDetector\nGuardFlags bits 8/9/28-31\nCFG function table\nexport xref check"]:::secondary
    B:::primary --> D["ByovdDetector\n8 capability classifiers\nimport table + disassembly\n(phys mem / token steal / callback removal)"]:::tertiary
    B:::primary --> E["WindowsPoolTaintTracker\nExAllocatePool size\n→ RtlCopyMemory size\nCWE-122 detection"]:::tertiary

    C:::secondary --> F["SEHChainAnalyzer\nx86-32 only\npush-handler / push-FS:[0]\nSafeseh registration check"]:::tertiary
    C:::secondary --> G["ETWProviderExtractor\nEventRegister → provider GUID\nEventWrite call count\nDetection gap finding"]:::tertiary
    C:::secondary --> H["RPCServerAnalyzer\nRpcServerRegisterIf*\nauth level check\nRPC_C_AUTHN_LEVEL_NONE → HIGH"]:::tertiary
    C:::secondary --> I["COMAttackSurfaceMapper\nDllGetClassObject presence\nCLSID enumeration\nIStream marshal check"]:::tertiary

    F:::tertiary --> J(["results.fmt()"]):::output
    G:::tertiary --> J:::output
    H:::tertiary --> J:::output
    I:::tertiary --> J:::output
    D:::tertiary --> J:::output
    E:::tertiary --> J:::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#6a1b9a,stroke-width:2px
    linkStyle 7 stroke:#6a1b9a,stroke-width:2px
    linkStyle 8 stroke:#2e7d32,stroke-width:3px
    linkStyle 9 stroke:#2e7d32,stroke-width:3px
    linkStyle 10 stroke:#2e7d32,stroke-width:3px
    linkStyle 11 stroke:#2e7d32,stroke-width:3px
    linkStyle 12 stroke:#2e7d32,stroke-width:3px
    linkStyle 13 stroke:#2e7d32,stroke-width:3px
```

---

## CFGBypassDetector

Microsoft Control Flow Guard (CFG) records all valid indirect call targets in a bitmap embedded in the PE. When the binary loads, the OS enforces that indirect calls only target entries in that bitmap. `CFGBypassDetector` reads `IMAGE_LOAD_CONFIG.GuardFlags` and the CFG function table.

```
  GuardFlags bit layout (IMAGE_LOAD_CONFIG_DIRECTORY):
    bit 8  (0x100):  CF_INSTRUMENTED: CFG enabled
    bit 9  (0x200):  CFW_INSTRUMENTED: export suppression enabled
    bits 28-31:      CF_FUNCTION_TABLE_SIZE_MASK: entry stride extra bytes

  CFG function table entry stride:
    base  = 4 bytes (VA offset, 4-byte aligned relative to image base)
    extra = GuardFlags >> 28     (0 for most binaries)
    total = 4 + extra bytes per entry
```

| Finding | Severity | Condition |
|---|---|---|
| `cfg_disabled` | HIGH | bit 8 of GuardFlags == 0 |
| `cfg_table_absent` | HIGH | No CFG function table in load config |
| `no_export_suppression` | MEDIUM | bit 9 of GuardFlags == 0 |
| `export_not_in_table` | MEDIUM | Exported function missing from CFG table |

An exported function absent from the CFG table is an indirect call target an attacker can use to bypass CFG because the guard only checks entries in the table.

---

## SEHChainAnalyzer

Structured Exception Handling (SEH) is an x86-32 mechanism that stores exception handler addresses on the stack. Without SafeSEH, an attacker who overwrites a stack frame's SEH record can redirect execution to an arbitrary address at exception time. `SEHChainAnalyzer` audits SafeSEH registration and scans for unregistered handler installations. x86-32 only: x64 uses table-based exception handling (`.pdata`) which is not vulnerable to this attack class.

```
  IMAGE_LOAD_CONFIG_DIRECTORY (x86-32):
    SEHandlerTable:  VA of the SafeSEH handler table
    SEHandlerCount:  number of registered handlers

  Scan: find push-handler / push-FS:[0] sequences in .text:
    PUSH <handler_va>
    PUSH DWORD PTR FS:[0]   (install SEH frame on stack)

  For each found handler_va:
    is handler_va in SEHandlerTable?
      NO → MEDIUM: handler_not_in_table (CWE-755)
```

| Finding | Severity | Condition |
|---|---|---|
| `safesh_disabled` | HIGH | SEHandlerTable == 0 or SEHandlerCount == 0 |
| `handler_not_in_table` | MEDIUM | Handler installed but not registered in SafeSEH table |

---

## ETWProviderExtractor

Event Tracing for Windows (ETW) is the kernel telemetry channel that security products EDRs, AV, audit logging use for real-time event streams. A driver that registers an ETW provider but never calls `EventWrite` may be suppressing security telemetry.

```mermaid
flowchart TD
    A(["Find all EventRegister call sites"]):::input --> B["Extract provider GUID from first argument\nx64: RCX points to 16-byte GUID\nx86: first pushed arg points to GUID"]:::primary

    B:::primary --> C["Compare against table of\n15 known security provider GUIDs\n(Windows Defender, AMSI, ETW kernel security, ...)"]:::secondary

    C:::secondary --> D["Count EventWrite call sites\nin the same binary"]:::tertiary

    D:::tertiary --> E{"Zero EventWrite calls\n+ registered security provider GUID?"}:::neutral
    E:::neutral -->|Yes| F(["MEDIUM: detection_gap\nProvider registered but never writes\nSuggests ETW hooking or\nchannel silencing"]):::output
    E:::neutral -->|No| G(["Normal telemetry path"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#546e7a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

---

## RPCServerAnalyzer

RPC server interfaces registered without authentication expose every operation they implement to unauthenticated callers.

```
  Find RpcServerRegisterIf* call sites:
    RpcServerRegisterIf
    RpcServerRegisterIfEx  (third arg = auth level)
    RpcServerRegisterIf2

  RPC_C_AUTHN_LEVEL values:
    0x01  RPC_C_AUTHN_LEVEL_NONE     (NO authentication: HIGH severity)
    0x02  RPC_C_AUTHN_LEVEL_CONNECT  (connection-level only)
    0x04  RPC_C_AUTHN_LEVEL_PKT      (per-packet)
    0x06  RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
    0x08  RPC_C_AUTHN_LEVEL_PKT_PRIVACY
```

`ana.endpoint_strings()` returns named pipe and port strings for the RPC endpoints, ready for use in a PoC that tests reachability.

---

## COMAttackSurfaceMapper

COM servers registered in a PE expose an attack surface through their class factories. An attacker who can influence which COM server handles a CLSID can redirect `CoCreateInstance` to a malicious DLL.

```
  Presence check:
    DllGetClassObject export present?
    YES → this binary is a COM server

  CLSID enumeration:
    scan .rdata and .data for GUID patterns
    match against registry-registered CLSIDs

  CoCreateInstance call sites:
    resolve CLSID argument
    CLSID used in calls but not registered in this binary?
    YES → MEDIUM: com_hijack_risk (CWE-426)

  IStream scan:
    IStream serialization near COM factory?
    YES → MEDIUM: com_marshal (CWE-502)
```

---

## WindowsPoolTaintTracker

Finds unvalidated `ExAllocatePool` size arguments flowing into `RtlCopyMemory` (CWE-122). This is the kernel equivalent of a heap overflow: allocation size and copy size use the same register without a bounds check between them.

```mermaid
flowchart TD
    A(["Find all ExAllocatePool* call sites\n(ExAllocatePool / ExAllocatePoolWithTag / ExAllocatePool2)"]):::input --> B["For each call site:\nTrack size_register forward"]:::primary

    B:::primary --> C{"size_register used as\nsize arg to RtlCopyMemory?"}:::neutral
    C:::neutral -->|No| D(["No finding"]):::output
    C:::neutral -->|Yes| E{"Bounds check\n(CMP + conditional branch)\nbetween them?"}:::neutral
    E:::neutral -->|Yes: guarded| D:::output
    E:::neutral -->|No bounds check| F(["HIGH: unvalidated propagation (CWE-122)"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#546e7a,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#546e7a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
```

Combine with `KernelDriverAnalyzer` to avoid re-parsing the PE: `WindowsPoolTaintTrackerpath, kda_report=existing_report`.

---

## Usage

Run all seven in sequence. Pass `kda_report` to avoid re-parsing the PE for BYOVD and pool analysis:

```python
from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer
from ablation.analyzers.byovd_detector import ByovdDetector
from ablation.analyzers.cfg_bypass_detector import CFGBypassDetector
from ablation.analyzers.seh_chain_analyzer import SEHChainAnalyzer
from ablation.analyzers.etw_provider_extractor import ETWProviderExtractor
from ablation.analyzers.rpc_server_analyzer import RPCServerAnalyzer
from ablation.analyzers.com_attack_surface_mapper import COMAttackSurfaceMapper
from ablation.analyzers.windows_pool_taint_tracker import WindowsPoolTaintTracker

path = '/path/to/target.sys'

kda   = KernelDriverAnalyzer.from_path(path).analyze()
byovd = ByovdDetector(path, kda_report=kda).detect()
cfg   = CFGBypassDetector.from_path(path).scan()
seh   = SEHChainAnalyzer.from_path(path).scan()    # x86-32 only
etw   = ETWProviderExtractor.from_path(path).scan()
rpc   = RPCServerAnalyzer.from_path(path).scan()
com   = COMAttackSurfaceMapper.from_path(path).scan()
pool  = WindowsPoolTaintTracker(path, kda_report=kda).scan()
```

For user-mode DLLs and EXEs, skip `KernelDriverAnalyzer`, `ByovdDetector`, and `WindowsPoolTaintTracker`. Run `CFGBypassDetector`, `ETWProviderExtractor`, `RPCServerAnalyzer`, and `COMAttackSurfaceMapper`.

---

## Architecture support

| Analyzer | x86-32 | x86-64 |
|---|---|---|
| CFGBypassDetector | yes | yes |
| SEHChainAnalyzer | yes | no (SafeSEH is x86-32 only) |
| ETWProviderExtractor | yes | yes |
| RPCServerAnalyzer | yes | yes |
| COMAttackSurfaceMapper | yes | yes |
| WindowsPoolTaintTracker | no | yes |
| KernelDriverAnalyzer | yes | yes |
| ByovdDetector | yes | yes |

---

## How it works

Each of the seven PE analyzers described on this page operates independently on a Windows PE binary. They share the `from_path(path)` or `from_context(ctx)` constructor pattern but produce different finding types. Refer to the individual **How it works** section for each analyzer below.

---

## Example output

See the **Reading findings** section below for each analyzer's return type and the individual module reference page for example output.

---

## False positives

False positive rates vary by analyzer. See each analyzer's individual reference page for false-positive guidance.

---

## Pipeline position

**Before any PE analyzer:** `BinaryContext.load_or_build()` for the target PE binary.

**After each analyzer:** Register confirmed findings with `FindingRegistry`. For taint-class findings, run `TaintTracker` to confirm propagation from network input.

---

## Reading findings

Each of the seven analyzers returns its own typed finding list. For full field references:

| Analyzer | Return type | Reference page |
|:---|:---|:---|
| `CFGBypassDetector` | `List[CFGBypassFinding]` | [cfg-bypass-detector](cfg-bypass-detector.md) |
| `SEHChainAnalyzer` | `List[SEHFinding]` | [seh-chain-analyzer](seh-chain-analyzer.md) |
| `ETWProviderExtractor` | `List[ETWFinding]` | [etw-provider-extractor](etw-provider-extractor.md) |
| `RPCServerAnalyzer` | `List[RPCFinding]` | [rpc-server-analyzer](rpc-server-analyzer.md) |
| `COMAttackSurfaceMapper` | `List[COMFinding]` | [com-attack-surface-mapper](com-attack-surface-mapper.md) |
| `HeapUAFScanner` | `List[HeapFinding]` | [heap-uaf-scanner](heap-uaf-scanner.md) |
| `IoctlAttackSurfaceGenerator` | `IoctlAttackSurface` | [ioctl-attack-surface](ioctl-attack-surface.md) |

`CFGBypassFinding`, `SEHFinding`, `ETWFinding`, `RPCFinding`, and `COMFinding` share `severity`, `category`, `title`, `location`, `description`, and `va` fields. `HeapFinding` uses `binary`, `func_va`, `func_name`, `site_va`, `kind`, `description`, `severity`. `IoctlAttackSurface` uses `binary_path`, `driver_type`, `is_signed`, `profiles`.

---

## See also

- [BinaryContext](binary-context.md): function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md): eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md): confirm propagation from source to flagged sink
- [PathSolver](path-solver.md): verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md): record confirmed findings
