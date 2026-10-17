# BrowserExtensionAuditor

## Why this exists

**Gap closed:** TG-FPAM-1, no ablation module for browser extension security analysis.

FortiClient EMS ships the FPAM browser extension (Chrome/Edge). Manual analysis of its
`manifest.json` and background service worker confirmed FPAM-EXT-1: `externally_connectable`
with `https://*/*` exposes the Chrome messaging API to any HTTPS page. The service worker
processes request payloads before validating `sender.url`, turning it into a confused-deputy
port-scan oracle. Without a scanner, each browser extension audit required re-reading the
Chrome extension security model from scratch.

This module applies to all Fortinet browser-resident agents: FPAM, FSSO browser plugin,
FIDO2 extension, VPN extension.

## Constructor

```python
from ablation.analyzers.browser_extension_auditor import BrowserExtensionAuditor

# From directory (manifest.json + all .js/.ts/.mjs)
auditor = BrowserExtensionAuditor.from_path('/tmp/fpam-ext/')

# Single file
findings = BrowserExtensionAuditor.scan_file('/tmp/fpam-ext/background.js')
```

## Key methods

| Method | Returns | Notes |
|--------|---------|-------|
| `from_path(path)` | `BrowserExtensionAuditor` | Recursively collects JS/TS/MJS + manifest.json |
| `scan()` | `List[ExtFinding]` | Runs all checks; sorted by severity |
| `scan_file(path)` | `List[ExtFinding]` | Single-file scan (no manifest audit) |
| `report(findings, min_severity=None)` | `str` | Human-readable summary with counts |

## Finding classes

| Class | Severity | CWE | Description |
|-------|----------|-----|-------------|
| `EXT_CONN_BROAD` | HIGH | CWE-346 | `externally_connectable.matches` contains `*://*/*`, `https://*/*`, `<all_urls>`, or `https://*.tld/*` |
| `EXT_CONN_MISSING` | MEDIUM | CWE-346 | `content_scripts` declared but no `externally_connectable`; window.postMessage relay path |
| `MSG_HANDLER_PREAUTH` | HIGH | CWE-285 | `onMessage`/`onMessageExternal` handler uses request payload before `sender.id`/`sender.url` check |
| `CONTENT_SCRIPT_DOM_HOOK` | MEDIUM | CWE-200 | Content script overwrites `window.fetch`, `XMLHttpRequest`, or `document.cookie` |
| `WEBSOCKET_BUS` | HIGH | CWE-284 | Background creates or connects to `ws://` WebSocket: bypasses Chrome sender validation |
| `NATIVE_MSG_NO_ALLOWLIST` | HIGH | CWE-284 | `sendNativeMessage`/`connectNative` without surrounding `sender.id` guard |
| `PERSISTENT_DATA_CLEAR` | LOW | CWE-362 | `chrome.storage.*.clear()` inside message handler before sender check |

## Usage pattern

```python
findings = BrowserExtensionAuditor.from_path('/tmp/fpam-ext/').scan()
print(BrowserExtensionAuditor.report(findings))

# Filter to HIGH+
print(BrowserExtensionAuditor.report(findings, min_severity='HIGH'))
```

## CLI

```sh
python3 -m ablation.analyzers.browser_extension_auditor /path/to/ext/
python3 -m ablation.analyzers.browser_extension_auditor /path/to/ext/ --severity HIGH
```

## Scope and limitations

- Manifest V2 and V3 both supported
- Pre-filter: JS/TS files must contain a Chrome extension API signal to be scanned
 (avoids false positives on third-party bundled JS)
- Message handler pre-auth check uses a 50-line lookahead window: deeply nested handlers
 may be missed
- Does not analyze compiled/minified bundles (no AST); source maps not followed
- Does not validate native messaging host manifests (separate JSON on the OS install path)

---

## How it works

Parses the runtime-specific binary format (APK, DEX, `.mpy`, BEAM, Go ELF) to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

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

Standard library calls that resemble dangerous patterns (e.g., `exec` used for shell completions, `eval` used for template rendering with static input) are not findings. Confirm that the argument reaching the dangerous call is user-controlled before escalating. Obfuscated code (Garble-compiled Go, ProGuard-stripped Android) produces incomplete call graphs — findings from incomplete graphs carry lower confidence.

---

## Pipeline position

**Before this module:** Confirm the target binary format (APK, `.mpy`, BEAM, Go ELF) before loading. `BinaryContext` is not required for all runtime analyzers.

**After this module:** Feed dangerous call findings to `TaintTracker` or `FindingRegistry` for confirmed findings.

---

## Reading findings

`BrowserExtensionAuditor.scan_dir(path)` returns `List[ExtFinding]`:

| Attribute | Content |
|:---|:---|
| `path` | Absolute path to the file containing the finding |
| `rel_path` | Path relative to the extension root |
| `lineno` | Line number of the finding |
| `finding_class` | Finding code (e.g., `'EXT_CONN_BROAD'`, `'MSG_HANDLER_PREAUTH'`, `'NATIVE_MSG_NO_ALLOWLIST'`) |
| `severity` | `'HIGH'` / `'MEDIUM'` |
| `cwe` | CWE identifier (e.g., `'CWE-346'`, `'CWE-285'`) |
| `title` | Short description of the vulnerability |
| `detail` | Extended explanation |
| `snippet` | Source code snippet at the finding line |
| `evidence` | Additional evidence string (e.g., the broad match pattern) |

---

## See also

- [BinaryContext](binary-context.md) — native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md) — trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md) — record confirmed findings
