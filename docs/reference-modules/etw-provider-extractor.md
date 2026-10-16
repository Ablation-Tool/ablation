# ETWProviderExtractor

## Why this exists

Two things were not possible before in Ablation:

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
