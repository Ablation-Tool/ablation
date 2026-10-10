# COMAttackSurfaceMapper

## Why this exists

3 things that weren't possible before in Ablation:

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
