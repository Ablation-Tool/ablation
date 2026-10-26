# COMAttackSurfaceMapper

## Why this exists

Three things were not possible before in Ablation:

1. **No COM server detection.** A DLL that exports `DllGetClassObject` is a COM server; any registered CLSID it provides is an activation target. If that CLSID is registered under `HKCU\Software\Classes\CLSID` user-writable rather than `HKLM`, any process running as the same user can hijack it by writing their own in-process server path. Before this module, finding COM server DLLs and their CLSID references required manual export inspection plus string search.

2. **No CoCreateInstance call site analysis.** A binary that calls `CoCreateInstance` is activating a COM object at runtime. If the CLSID it passes resolves to a machine-writable registry key (a key under `HKCU` or under a user-writable `HKLM` path), an attacker can redirect that activation to their own DLL. Extracting the CLSID argument from a `CoCreateInstance` call site distinguishing a hardcoded GUID constant from a computed one required manual disassembly. There was no automated path.

3. **No COM marshaling / IDispatch surface inventory.** `CoMarshalInterface` and `CoUnmarshalInterface` enable cross-process and cross-machine COM calls. If marshaled data is attacker-influenced, the deserialization path `IStream` and `IMoniker` is an exploitation vector. `IDispatch.Invoke` makes a COM object scriptable via OLE automation. Neither of these import categories was tracked in Ablation's Windows PE analysis.

---

## What it does

`COMAttackSurfaceMapper` works on x86 and x64 PE binaries. It:

1. Checks PE exports for `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `DllCanUnloadNow` to identify COM servers.
2. Scans `.rdata` and `.data` sections for GUID strings in `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` format.
3. Scans code sections for `CoCreateInstance*` call sites with Capstone and extracts the first argument CLSID pointer to read the binary GUID.
4. Checks IAT for `CoMarshalInterface`, `CoUnmarshalInterface`, `CoMarshalInterThreadInterfaceInStream` COM marshaling and `Invoke`/`GetIDsOfNames` IDispatch OLE automation.
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

- `lief >= 0.14.0` PE parsing, exports, IAT
- `capstone >= 5.0` (CoCreateInstance call site scanning)

---

## How it works

`COMAttackSurfaceMapper.from_path()` opens the PE with LIEF. The five analysis steps match the "What it does" section above:

1. Export scan: checks the PE export table for `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `DllCanUnloadNow` using LIEF's `binary.exported_functions`. Any of these marks the DLL as a COM server.
2. GUID string scan: walks `.rdata` and `.data` sections for the regex `{[0-9A-F]{8}-[0-9A-F]{4}-...}` to collect CLSID string references. Each unique GUID is stored in the CLSID inventory.
3. CoCreateInstance call site scan: Capstone disassembles each code section; for each `call CoCreateInstance*` instruction, the preceding `lea` or `mov` loading the first argument `rcx` on x64 and stack push on x86 is backtracked to extract the CLSID binary value (16 bytes at the pointed-to address in `.rdata`).
4. IAT import scan: checks the PE import table for `CoMarshalInterface`, `CoUnmarshalInterface`, `CoMarshalInterThreadInterfaceInStream`, `Invoke`, `GetIDsOfNames` using LIEF `binary.imports`.
5. Finding emission: emits a `COMFinding` per category. `com_hijack_risk` is emitted only when both COM server exports AND CLSID references are found together.

---

## Example output

The following illustrates `report()` output format. Actual values are binary-specific.

```
COMAttackSurfaceMapper: shdocvw.dll

[MEDIUM] com_hijack_risk
  COM server with 4 CLSID reference(s) — hijacking surface
  location: shdocvw.dll
  cwe: CWE-426
  {E8CF3E55-F919-49D9-ABC0-948E6CB34B9F} registered under HKCU would be hijackable

[INFO] com_server
  COM server: exports DllGetClassObject, DllRegisterServer

[INFO] clsid_inventory
  4 CLSID references found in .rdata
```

---

## False positives

**`com_hijack_risk` requires manual registry check**: the scanner identifies that the DLL is a COM server with CLSID references, but does not query the registry. Whether the CLSIDs are registered under `HKCU` hijackable vs `HKLM`-only not directly hijackable must be checked separately with `reg query HKCU\Software\Classes\CLSID\{...}`.

**`CoCreateInstance` call site with unresolved CLSID**: when the CLSID pointer is computed at runtime loaded from a global, allocated on the heap, the scanner cannot extract the binary GUID. These are reported as `com_create` findings with `va` set but `clsid=None` in `cocreate_sites()` output. Not all `CoCreateInstance` calls are hijackable.

---

## Pipeline position

**Before this module:** No `BinaryContext` required: `from_path()` uses LIEF directly. Use on any Windows PE that may be a COM server (DLLs exporting `DllGetClassObject`) or a COM client (binaries importing `CoCreateInstance`).

**After this module:** For `com_hijack_risk` findings, check registry registration of each identified CLSID under `HKCU` on the target system. For `com_create` findings, verify whether the activated CLSID's server DLL path is writable by the target user.

---

## Reading findings

`COMAttackSurfaceMapper.from_path(path).scan()` returns `List[COMFinding]`:

| Attribute | Content |
|:---|:---|
| `severity` | `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `category` | `com_server` / `com_create` / `com_hijack_risk` / `com_marshal` / `clsid_inventory` / `idispatch` |
| `title` | Short description of the COM attack surface exposure |
| `location` | Human-readable location string CLSID, export name, or registry key path |
| `description` | Detailed explanation of the attack vector |
| `va` | VA of the relevant instruction 0 if not applicable |
| `cwe` | CWE identifier such as `CWE-284` and `CWE-346` |

---

## See also

- [CFG Bypass Detector](cfg-bypass-detector.md): companion Windows PE scanner for CFG bypass surface analysis
- [PE Sweep](pe-sweep.md): coarse Windows PE security feature check DEP, ASLR, and SafeSEH
- [FindingRegistry](registry.md): register confirmed COM hijacking findings
