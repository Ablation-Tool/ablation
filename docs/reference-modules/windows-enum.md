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

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Example output

```
[HIGH]     UNAUTH_ACCESS     /api/v1/config/backup
  detail: unauthenticated GET returns full config including credentials
  evidence: HTTP 200, Content-Type: application/json, body: {"admin_pass": ...}

[MEDIUM]   INFO_DISCLOSURE   /status
  detail: version string exposed without authentication
  evidence: X-Version: FortiOS 7.2.1 build 1254
```

---

## False positives

Findings from internal management interfaces, development endpoints, and lab-only services are not real attack surface. Filter by comparing discovered endpoints against the product's documented management plane. Authentication-required findings are lower severity unless a pre-auth bypass is confirmed separately.

---

## Pipeline position

**Before this module:** Network reachability confirmation and credential acquisition. `BinaryContext` is not required; this module works from a live target or captured traffic.

**After this module:** Feed findings to `FindingRegistry.register()` and review with `LLMAnalyst` for chaining opportunities.

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `finding_type` | Category (e.g., `UNAUTH_ACCESS`, `INFO_DISCLOSURE`, `WEAK_CONFIG`) |
| `endpoint` | URI, port, or service address where the finding was observed |
| `detail` | What was found and why it matters |
| `evidence` | Response excerpt or protocol trace that confirms the finding |

---

## See also

- [FindingRegistry](registry.md) — record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md) — chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md) — port and service fingerprinting
