# WindowsEnumerator

**File:** `modules/windows_enum.py`

## Why this exists

Three gaps existed before this module:

1. **Live Windows enumeration was session-scripted.** COM hijack candidates, RPC endpoints, ETW sessions, named pipes, and UAC/Credential Guard status each required separate reg.exe queries or PowerShell one-liners per session. WindowsEnumerator wraps all nine sections into one `enumerate_all()` call with structured output.

2. **COM hijack detection required manual HKCU vs. HKLM comparison.** The module compares HKCU\\Software\\Classes\\CLSID against HKLM\\SOFTWARE\\Classes\\CLSID, identifying CLSIDs where a user-controlled HKCU registration shadows a machine-level one, an active COM hijack if InprocServer32 differs.

3. **Security feature state (UAC, Secure Boot, Credential Guard, PPL) was not enumerable from one place.** `system_security_features()` reads EnableLUA, DeviceGuard, RunAsPPL, and DisableAntiSpyware in a single pass, producing HIGH/MEDIUM findings for disabled controls.

## Usage

```python
from modules.windows_enum import WindowsEnumerator

w = WindowsEnumerator()
results = w.enumerate_all()
print(w.report(results))

# JSON output
import json
print(w.to_json(results))

# Specific sections only
results = w.enumerate_all(sections=['com', 'token', 'secfeatures'])
```

## Sections

| Section | Method | Description |
|---|---|---|
| `com` | `com_hijack_candidates()` | HKCU/HKLM CLSID delta: COM hijack surface |
| `rpc` | `rpc_endpoints()` | Active RPC endpoints via netstat |
| `etw` | `etw_sessions()` | Active ETW sessions and consumers |
| `pipes` | `named_pipes()` | `\\.\pipe\*` named pipe surface |
| `secfeatures` | `system_security_features()` | UAC, Secure Boot, VBS, LSA PPL, Defender |
| `servicedll` | `service_dlls()` | svchost-hosted service DLLs from registry |
| `autoruns` | `autoruns()` | Common persistence registry locations |
| `token` | `token_privileges()` | Current process token privileges |
| `modules` | `loaded_modules()` | Loaded DLLs with PDB path hints |

## FORGE audit

Gate: **PASSED**. No code changes needed.

- No file reads: all data from subprocess stdout. No CWE-770 concerns.
- No bare `except:`: `_run()` uses `except FileNotFoundError:`, `except subprocess.TimeoutExpired:`, `except Exception as e:`; `enumerate_all()` uses `except Exception as e:` for section isolation.
- No lief.parse(). No HTTP reads. No network I/O.
- All subprocess calls use `_run()` which enforces `timeout=15` (default) and catches all exceptions.
- All PowerShell calls use `_ps()` which wraps `_run()` with `timeout=20`.
- PowerShell invoked with `-NoProfile -NonInteractive`.
- COM CLSID per-GUID InprocServer32 queries capped at 30 (prevents timeout on large registries).
- Degrades gracefully on non-Windows hosts: each section returns an INFO finding instead of raising.

---

## How it works

`WindowsEnumerator().enumerate_all()` runs each registered enumeration section (`com`, `rpc`, `etw`, `pipes`, `secfeatures`, `servicedll`, `autoruns`, `token`, `modules`) and returns `dict[str, list[Finding]]`. Each `Finding` is a dataclass with `{severity, category, title, detail, evidence}`. On non-Windows hosts each section returns an INFO finding stub instead of raising.

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
WindowsEnumerator.enumerate_all():

results['com']:
  Finding(severity='HIGH', category='COM Hijacking', title='CLSID {some-guid} shadowed in HKCU',
          detail='HKCU\\...\\InprocServer32 = C:\\Users\\user\\AppData\\Local\\dll.dll',
          evidence='HKLM copy exists — user-writable HKCU override present')

results['token']:
  Finding(severity='HIGH', category='Token Privileges',
          title='SeDebugPrivilege enabled', detail='Process has SeDebugPrivilege — can open any process', evidence='')
```

---

## False positives

**`com_hijack_candidates()` on developer machines** — developer tools (Visual Studio, build systems) legitimately register per-user COM objects in HKCU that shadow HKLM entries. Confirm the CLSID is associated with an application and not a persistence mechanism by checking the registered InprocServer32 DLL path.

**`token_privileges()` reporting `SeDebugPrivilege`** — administrators and debuggers legitimately hold SeDebugPrivilege. This is a HIGH finding on service accounts and restricted users, but expected on admin sessions.

---

## Pipeline position

Run `WindowsEnumerator` on a live Windows host from an unprivileged shell after gaining initial access. Run `com_hijack_candidates()` to identify persistence opportunities and `token_privileges()` to enumerate privilege escalation paths.

---

## Reading findings

Returns `dict[str, list[Finding]]`. `Finding` fields:

| Field | Content |
|:---|:---|
| `severity` | `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `category` | Section name (e.g., `COM Hijacking`, `Token Privileges`, `Named Pipes`) |
| `title` | Short description of the specific finding |
| `detail` | Full detail string |
| `evidence` | Supporting evidence string (may be empty) |
| `endpoint` | URI, port, or service address where the finding was observed |
| `detail` | What was found and why it matters |
| `evidence` | Response excerpt or protocol trace that confirms the finding |

---

## See also

- [FindingRegistry](registry.md) — record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md) — chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md) — port and service fingerprinting
