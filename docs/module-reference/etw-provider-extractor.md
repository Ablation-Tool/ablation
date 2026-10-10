# ETWProviderExtractor

## Why this exists

2 things that weren't possible before in Ablation:

1. **No ETW provider inventory.** ETW (Event Tracing for Windows) is the primary telemetry layer that EDR products and Windows security features depend on. A binary that imports `EventRegister` but whose provider GUID you don't know is invisible to any GUID-based filtering or suppression tool. Before this module, Ablation had no way to extract provider GUIDs from `EventRegister` call sites or cross-reference them against the table of known security-relevant providers. `pe_sweep.py` flagged ETW imports at the IAT level but did nothing with the GUIDs.

2. **No detection gap identification.** A binary that registers an ETW provider but never calls `EventWrite` is producing no telemetry: either by design (broken instrumentation) or by intent (registration without writes is a common technique to appear compliant while emitting nothing). Finding that case required counting `EventWrite` call sites manually. Now `write_site_count()` does it in one call, and the `scan()` method automatically flags the gap.

---

## What it does

`ETWProviderExtractor` works on both x86 and x64 PE binaries. It:

1. Builds an IAT map for `EventRegister`, `EventRegisterEx`, `EventWrite*`, and `EventUnregister`.
2. Scans code sections for `EventRegister` call sites with Capstone. For x64, it reads the GUID pointer from `RCX` (via `lea rcx, [rip+offset]` or `mov rcx, imm64`). For x86, it reads the first push before the call.
3. Reads 16 bytes at the GUID pointer as a `bytes_le` UUID.
4. Cross-references each extracted GUID against a table of 15 known security-relevant Windows ETW providers (Security-Auditing, PowerShell, Antimalware-Engine, RPC, DCOM, etc.).
5. Counts `EventWrite*` call sites independently. Flags a detection gap if providers are registered but `EventWrite` is never called.

---

## Usage

```python
from ablation.analyzers.etw_provider_extractor import ETWProviderExtractor

ext = ETWProviderExtractor.from_path('lsass.exe')
findings = ext.scan()
print(ETWProviderExtractor.report(findings))

for p in ext.providers():
    known = p.known_name or '(unknown provider)'
    print(f"{p.guid}  {known}  registrations={p.registration_count}")

print(f"EventWrite call sites: {ext.write_site_count()}")
```

---

## Findings

| Severity | Category | Trigger |
|---|---|---|
| MEDIUM | `detection_gap` | Providers registered, zero `EventWrite` calls found |
| MEDIUM | `detection_gap` | `EventRegister` imported but no GUIDs resolved |
| INFO | `known_security_provider` | Provider GUID matches a known security/EDR provider |
| INFO | `provider_inventory` | Provider count + write site count summary |
| INFO | `no_etw` | No ETW imports at all |

---

## Known providers table

The built-in table covers 15 providers including:

- `Microsoft-Windows-Security-Auditing`
- `Microsoft-Windows-Kernel-Process` / `Kernel-General` / `Kernel-Audit-API-Calls`
- `Microsoft-Windows-PowerShell`
- `Microsoft-Antimalware-Engine`
- `Microsoft-Windows-RPC`
- `Microsoft-Windows-DCOM-Server`
- `Microsoft-Windows-CAPI2`
- `Microsoft-Windows-DNS-Client`

Extend by adding entries to `_KNOWN_PROVIDERS` in the module source.

---

## Dependencies

- `lief >= 0.14.0` (PE parsing, IAT)
- `capstone >= 5.0` (call site scanning, argument extraction)
