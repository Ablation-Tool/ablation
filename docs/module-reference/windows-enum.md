# WindowsEnumerator

**File:** `modules/windows_enum.py`

## Why this exists

Three gaps existed before this module:

1. **Live Windows enumeration was session-scripted.** COM hijack candidates, RPC endpoints, ETW sessions, named pipes, and UAC/Credential Guard status each required separate reg.exe queries or PowerShell one-liners per session. WindowsEnumerator wraps all nine sections into one `enumerate_all()` call with structured output.

2. **COM hijack detection required manual HKCU vs. HKLM comparison.** The module compares HKCU\\Software\\Classes\\CLSID against HKLM\\SOFTWARE\\Classes\\CLSID, identifying CLSIDs where a user-controlled HKCU registration shadows a machine-level one — an active COM hijack if InprocServer32 differs.

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
| `com` | `com_hijack_candidates()` | HKCU/HKLM CLSID delta — COM hijack surface |
| `rpc` | `rpc_endpoints()` | Active RPC endpoints via netstat |
| `etw` | `etw_sessions()` | Active ETW sessions and consumers |
| `pipes` | `named_pipes()` | `\\.\pipe\*` named pipe surface |
| `secfeatures` | `system_security_features()` | UAC, Secure Boot, VBS, LSA PPL, Defender |
| `servicedll` | `service_dlls()` | svchost-hosted service DLLs from registry |
| `autoruns` | `autoruns()` | Common persistence registry locations |
| `token` | `token_privileges()` | Current process token privileges |
| `modules` | `loaded_modules()` | Loaded DLLs with PDB path hints |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings.

- No file reads. No HTTP reads. No lief.parse().
- All subprocess calls use `_run()` which enforces `timeout=15` (default) and catches all exceptions.
- All PowerShell calls use `_ps()` which wraps `_run()` with `timeout=20`.
- Degrades gracefully on non-Windows hosts: each section returns an INFO finding instead of raising.
