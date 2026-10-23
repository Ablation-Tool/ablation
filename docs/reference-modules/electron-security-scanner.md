# Electron Security Scanner

**File:** `ablation/analyzers/electron_security_scanner.py`

## Why this exists

FortiFone Desktop v8.0 build 67 is an Electron/Chromium SIP phone client. Manual source review of the extracted `app.asar` produced seven confirmed findings that required reading the Electron security model from scratch each engagement, no automated scanner existed. The same patterns (nodeIntegration, IPC without sender check, server-controlled loadURL) appear in every Electron app.

Gap closed: 2026-10-16. All confirmed FFO findings re-detected automatically in validation run on FortiFone main.js.

---

## Finding classes

| Class | CWE | Severity | Pattern | Confirmed finding |
|---|---|---|---|---|
| `NODE_INTEGRATION` | CWE-693 | CRITICAL | `nodeIntegration:true` + `contextIsolation:false` in ±5 lines | FFO-NI-1 |
| `CONTEXT_ISOLATION_DISABLED` | CWE-693 | MEDIUM | `contextIsolation:false` without `nodeIntegration:true` nearby |: |
| `IPC_NO_SENDER_CHECK` | CWE-940 | HIGH/MEDIUM | `ipcMain.handle/on` without `event.sender` check; HIGH if handler returns sensitive data | FFO-COOKIE-1, FFO-IPC-1 |
| `SERVER_URL_IN_WINDOW` | CWE-601 | HIGH/MEDIUM | `loadURL(var)` where var appears server-derived; HIGH if NI:true present in file | FFO-OAUTH-1 |
| `DEVTOOLS_IN_PROD` | CWE-489 | MEDIUM | `openDevTools()` without `isDev`/`NODE_ENV===development` guard | FFO-DEVTOOLS-1 |
| `DEEP_LINK_NO_VALIDATION` | CWE-601 | MEDIUM | Protocol URL handler uses argument in `loadURL`/login without scheme/domain check | FFO-DEEPLINK-1 |
| `TLS_BYPASS` | CWE-295 | CRITICAL/HIGH | `certificate-error` handler calls `callback(true)` (CRITICAL); `rejectUnauthorized:false` (HIGH) | FFO-CERTBYP-1, FFO-UPDATE-1 |
| `CONTEXT_BRIDGE_MISSING` | CWE-693 | HIGH | Preload script assigns `ipcRenderer` to `window`/`global` without `contextBridge` |: |

## Key API

```python
from ablation.analyzers.electron_security_scanner import ElectronSecurityScanner

# Directory tree (extracted asar contents)
findings = ElectronSecurityScanner.from_path('/tmp/app_src/').scan()
print(ElectronSecurityScanner.report(findings))

# Single file
findings = ElectronSecurityScanner.scan_file('/tmp/app_src/main.js')

# Filter to critical/high only
critical = [f for f in findings if f.severity in ('CRITICAL', 'HIGH')]
```

## Extraction prerequisite

The scanner requires extracted JavaScript source. For `.asar` bundles:

```bash
npx asar extract resources/app.asar /tmp/app_src
```

Or use ablation's built-in asar reader (see `ablation/analyzers/source_audit_compressor.py`).

## IPC severity escalation

`IPC_NO_SENDER_CHECK` starts at MEDIUM and escalates to HIGH when the handler body (next 15 lines) contains keywords: `cookie`, `session`, `cert`, `key`, `token`, `password`, `credential`, `global.`, `sharedObject`, `require(`, `exec`, `spawn`, `readFile`, `writeFile`.

## Detection limitations

- `SERVER_URL_IN_WINDOW`: URL variable provenance traced back 20 lines. If server-config injection is 21+ lines earlier, it may be missed.
- `IPC_NO_SENDER_CHECK`: body window is 15 lines; long handlers may have sender checks outside the window.
- `DEEP_LINK_NO_VALIDATION`: checks for `loadURL`/login in next 25 lines of handler: misses multi-function dispatch.
- `CONTEXT_BRIDGE_MISSING`: uses filename heuristic (`preload`) plus `ipcRenderer` presence: may false-positive on non-preload files that import ipcRenderer.

## Validation results (FortiFone v8.0 b67)

On the 205KB `main.js` extracted from `app.asar`:
- Total: 68 findings: 12 CRITICAL, 24 HIGH, 32 MEDIUM
- NODE_INTEGRATION: 10 instances (all BrowserWindow definitions)
- IPC_NO_SENDER_CHECK: 42 handlers
- SERVER_URL_IN_WINDOW: 13 loadURL calls
- TLS_BYPASS: 2 (certificate-error accept-all + rejectUnauthorized:false)
- DEVTOOLS_IN_PROD: 1

## FORGE audit

Gate: **PASSED**. No subprocess, eval, shell=True, or network I/O. All file reads use `errors="replace"`. OSError guarded. All loop bounds use `min(len(ls),...)`. Regex compiled at module level. No shared mutable state between scan calls.

---

## How it works

Parses the runtime-specific binary format (APK, DEX, `.mpy`, BEAM, Go ELF) to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

---

## Usage

```python
from ablation.analyzers.electron_security_scanner import ElectronSecurityScanner

findings = ElectronSecurityScanner.from_path('/path/to/electron_app_src/').scan()
for f in findings:
    print(f.fmt())
```

---

## Example output

```
[HIGH] DANGEROUS_CALL   Runtime.exec() in com.example.CommandHandler:42
  detail: argument constructed from user-supplied intent extra
  evidence: exec(getIntent().getStringExtra("cmd"))

[MEDIUM] UNTRUSTED_INPUT   eval() in main.js:118
  detail: JSON.parse result passed directly to eval
```

---

## False positives

Standard library calls that resemble dangerous patterns (e.g., `exec` used for shell completions, `eval` used for template rendering with static input) are not findings. Confirm that the argument reaching the dangerous call is user-controlled before escalating. Obfuscated code (Garble-compiled Go, ProGuard-stripped Android) produces incomplete call graphs: findings from incomplete graphs carry lower confidence.

---

## Pipeline position

**Before this module:** Confirm the target binary format (APK, `.mpy`, BEAM, Go ELF) before loading. `BinaryContext` is not required for all runtime analyzers.

**After this module:** Feed dangerous call findings to `TaintTracker` or `FindingRegistry` for confirmed findings.

---

## Reading findings

`ElectronSecurityScanner.from_path(root).scan()` returns `List[ElectronFinding]`:

| Attribute | Content |
|:---|:---|
| `path` | Absolute path to the file containing the finding |
| `rel_path` | Source file path relative to the app root |
| `lineno` | Line number of the finding |
| `finding_class` | Finding code (e.g., `'node-integration-rce'`, `'tls-bypass'`, `'context-isolation-disabled'`) |
| `severity` | `'CRITICAL'` / `'HIGH'` / `'MEDIUM'` / `'LOW'` |
| `cwe` | CWE identifier (e.g., `'CWE-78'`, `'CWE-295'`) |
| `title` | Short description of the misconfiguration |
| `detail` | Extended explanation of the security impact |

---

## See also

- [BinaryContext](binary-context.md): native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md): trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md): record confirmed findings
