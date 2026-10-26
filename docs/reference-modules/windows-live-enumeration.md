# Windows Live Enumeration

Enumerate COM hijacking candidates HKCU vs. HKLM CLSID delta, active RPC endpoints, ETW session consumers, named pipe surfaces, service DLL hijacking paths, autoruns, token privileges, and system security feature status CFG, DEP, ASLR policies: providing a complete Windows live-system attack surface map: via `modules/windows_enum.py` `WindowsEnumerator`.

---

## Why this exists

1. `WindowsEnumerator.com_hijack_candidates()` identifies COM classes that can be hijacked via HKCU override: Windows COM resolution checks `HKCU\Software\Classes\CLSID\` before `HKLM\SOFTWARE\Classes\CLSID\`. Any COM class registered in HKLM but absent from HKCU can be overridden by a low-privilege user: writing a new `InprocServer32` entry under HKCU pointing to an attacker DLL causes the DLL to execute whenever a privileged process instantiates that class. `com_hijack_candidates()` computes the delta between HKLM and HKCU registrations for the current user.

2. `rpc_endpoints()` enumerates active RPC endpoint mapper registrations: RPC servers registered with the endpoint mapper often expose privileged functionality without requiring Windows authentication when accessed from the local system. `rpc_endpoints()` queries `ncacn_ip_tcp`, `ncalrpc`, and `ncacn_np` transport bindings and flags endpoints bound to `\pipe\svcctl`, `\pipe\samr`, or interfaces associated with known lateral movement primitives `IWbemServices`, task scheduler.

3. `system_security_features()` enumerates mitigation policy status: Control Flow Guard (CFG) enforcement policy, Data Execution Prevention (DEP) policy (AlwaysOn vs. OptIn vs. OptOut), ASLR mandatory randomization, SEHOP Structured Exception Handling Overwrite Protection, and Credential Guard / Device Guard status. This is the Windows equivalent of `host-platform-inventory`, it determines which exploit mitigation bypasses are necessary before attempting memory corruption.

---

## How it works

```mermaid
flowchart TD
    A(["WindowsEnumerator()\n  enumerate_all() → dict[str, list[Finding]]\n    keys: com, rpc, etw, pipes, secfeatures,\n          servicedll, autoruns, token, modules"]):::input --> B["com_hijack_candidates() → list[Finding]\n  HKLM SOFTWARE\\Classes\\CLSID → all CLSIDs\n  HKCU Software\\Classes\\CLSID → user CLSIDs\n  Delta: HKLM CLSIDs absent in HKCU with writable InprocServer32 path\n  Finding(severity, category='com', title, detail, evidence)"]:::primary
    B:::primary --> C["rpc_endpoints() → list[Finding]\n  rpcping / Win32_DCOMApplication\n  Parse ncacn_* transport endpoints\n  Flag: SAMR, SVCCTL, IWbemServices, TaskScheduler\n  Finding(severity, category='rpc', title, detail, evidence)\n\netw_sessions() → list[Finding]\n  logman query -ets\n  NT Kernel Logger, threat-detection session consumers\n  Finding(severity, category='etw', title, detail, evidence)"]:::secondary
    C:::secondary --> D["named_pipes() → list[Finding]\n  \\\\.\\pipe\\\\ enumeration\n  Flag: writable pipes not owned by SYSTEM\n  Finding(severity, category='pipes', title, detail, evidence)\n\nservice_dlls() → list[Finding]\n  HKLM SYSTEM\\CurrentControlSet\\Services\\*/Parameters/ServiceDll\n  Flag: DLL path in user-writable directory\n  Finding(severity, category='servicedll', title, detail, evidence)"]:::tertiary
    D:::tertiary --> E(["token_privileges() → list[Finding]\n  whoami /priv\n  Flag: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege\n  Finding(severity, category='token', title, detail, evidence)\n\nsystem_security_features() → list[Finding]\n  CFG, DEP, ASLR policy reads via NtQuerySystemInformation\n  Finding(severity, category='secfeatures', title, detail, evidence)"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from modules.windows_enum import WindowsEnumerator

enumerator = WindowsEnumerator()
# enumerate_all() returns dict with keys: 'com', 'rpc', 'etw', 'pipes',
# 'secfeatures', 'servicedll', 'autoruns', 'token', 'modules'
results = enumerator.enumerate_all()

# COM hijacking candidates
# Finding attributes: severity, category, title, detail, evidence
for f in results.get('com', []):
    print(f"  [{f.severity}] {f.title}: {f.detail}")
    if f.evidence:
        print(f"    evidence: {f.evidence}")

# Token privileges (impersonation escalation)
for f in results.get('token', []):
    if 'SeImpersonatePrivilege' in f.detail or 'SeImpersonate' in f.title:
        print(f"  [{f.severity}] {f.title}: {f.detail}")

# Print full report
print(WindowsEnumerator.report(results))
```

---

## Example output

The following illustrates Windows live enumeration output format.

```
WindowsEnumerator:

COM hijack candidates:
  {ABC12345-...}: HKLM=C:\Windows\System32\comsvcs.dll  → HKCU writable

RPC endpoints:
  ncalrpc:\pipe\svcctl  (Service Control Manager — unauthenticated local access)

Service DLL hijacking:
  svc_helper: C:\ProgramData\vendor\helper.dll  (writable by Users)

Token privileges:
  SeImpersonatePrivilege: Enabled  → Potato escalation path

system_security_features:
  CFG: Enabled  DEP: AlwaysOn  ASLR: MandatoryASLR  SEHOP: Enabled
```

---

## False positives

**`com_hijack_candidates()` writability check**: the module checks whether the DLL path stored in the HKLM CLSID entry points to a directory writable by the current user. Some enterprise environments add ACLs that prevent writable-path detection via standard API calls. Verify write access manually by attempting to create a test file.

**`named_pipes()` writable pipe detection**: writable named pipes not owned by SYSTEM are unusual but not always exploitable. A writable pipe requires a privileged process to connect to it for impersonation to succeed. Cross-reference with `service_dlls()` to find services that connect to user-accessible pipes.

---

## Pipeline position

Run `WindowsEnumerator` after gaining low-privilege access to a Windows host. COM hijacking and service DLL paths provide the most reliable privilege escalation candidates; token privileges determine whether impersonation attacks are immediately available.

---

## Reading findings

`WindowsEnumerator().enumerate_all()` returns `Dict[str, List[Finding]]`: section name → findings:

| Section key | Content |
|:---|:---|
| `'com'` | COM server HKCU hijack candidates |
| `'rpc'` | Accessible local RPC endpoints |
| `'servicedll'` | Service DLLs in writable directories |
| `'autoruns'` | Autorun entries |
| `'etw'` | Active ETW session consumers |
| `'pipes'` | Named pipe surfaces |
| `'token'` | Token privilege information |

Each `Finding` has `severity: str`, `category: str`, `title: str`, `detail: str`, and `evidence: str`.

---

## See also

- [Linux Privilege Escalation Triage](linux-privilege-escalation-triage.md): equivalent Linux escalation enumeration
- [Windows Artifact Discovery](windows-artifact-discovery.md): filesystem and registry timeline artifacts for forensic analysis
