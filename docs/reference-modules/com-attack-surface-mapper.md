# COMAttackSurfaceMapper

## Why this exists

Three things were not possible before in Ablation:

1. **No COM server detection.** A DLL that exports `DllGetClassObject` is a COM server; any registered CLSID it provides is an activation target. If that CLSID is registered under `HKCU\Software\Classes\CLSID` (user-writable) rather than `HKLM`, any process running as the same user can hijack it by writing their own in-process server path. Before this module, finding COM server DLLs and their CLSID references required manual export inspection plus string search.

2. **No CoCreateInstance call site analysis.** A binary that calls `CoCreateInstance` is activating a COM object at runtime. If the CLSID it passes resolves to a machine-writable registry key (a key under `HKCU` or under a user-writable `HKLM` path), an attacker can redirect that activation to their own DLL. Extracting the CLSID argument from a `CoCreateInstance` call site (distinguishing a hardcoded GUID constant from a computed one) required manual disassembly. There was no automated path.

3. **No COM marshaling / IDispatch surface inventory.** `CoMarshalInterface` and `CoUnmarshalInterface` enable cross-process and cross-machine COM calls. If marshaled data is attacker-influenced, the deserialization path (`IStream`, `IMoniker`) is an exploitation vector. `IDispatch.Invoke` makes a COM object scriptable via OLE automation. Neither of these import categories was tracked in Ablation's Windows PE analysis.

---

## What it does

`COMAttackSurfaceMapper` works on x86 and x64 PE binaries. It:

1. Checks PE exports for `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `DllCanUnloadNow` to identify COM servers.
2. Scans `.rdata` and `.data` sections for GUID strings in `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` format.
3. Scans code sections for `CoCreateInstance*` call sites with Capstone and extracts the first argument (CLSID pointer) to read the binary GUID.
4. Checks IAT for `CoMarshalInterface`, `CoUnmarshalInterface`, `CoMarshalInterThreadInterfaceInStream` (COM marshaling) and `Invoke`/`GetIDsOfNames` (IDispatch OLE automation).
5. Reports COM servers with CLSID references as a hijacking surface and CoCreateInstance sites as activation targets.

---

## Usage

```python
from ablation.analyzers.com_attack_surface_mapper import COMAttackSurfaceMapper

mapper = COMAttackSurfaceMapper.from_path('shdocvw.dll')
findings = mapper.scan()
print(COMAttackSurfaceMapper.report(findings))

print(f"Is COM server: {mapper.is_com_server()}")
print(f"CLSID references: {mapper.referenced_clsids()}")
sites = mapper.cocreate_sites()
for va, clsid in sites:
    print(f"  0x{va:x}  {clsid or '(unresolved)'}")
```

---

## Findings

| Severity | Category | Trigger |
|---|---|---|
| MEDIUM | `com_hijack_risk` | COM server with CLSID string references (CWE-426) |
| MEDIUM | `com_marshal` | `CoMarshalInterface*` imported (CWE-502) |
| INFO | `com_server` | Binary exports `DllGetClassObject` |
| INFO | `com_create` | `CoCreateInstance*` call sites found |
| INFO | `clsid_inventory` | CLSID strings found in data sections |
| INFO | `idispatch` | `Invoke`/`GetIDsOfNames` imported |
| INFO | `no_com` | No COM surface found |

---

## COM hijacking background

COM hijacking works when a DLL is loaded via a CLSID registered under `HKCU\Software\Classes\CLSID`, which any user process can write. Windows searches `HKCU` before `HKLM` for COM activation. A COM server binary with `DllGetClassObject` and CLSID references is the victim side of this class of attack. An attacker who knows the CLSID writes a redirect key pointing to a malicious DLL.

---

## Dependencies

- `lief >= 0.14.0` (PE parsing, exports, IAT)
- `capstone >= 5.0` (CoCreateInstance call site scanning)

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
