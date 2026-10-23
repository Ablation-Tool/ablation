# Apache Module Analyzer

**File:** `ablation/analyzers/apache_module_analyzer.py`

## Why this exists

FortiAnalyzer v7.6.3 ships a custom Apache module `mod_extension.so` that bypasses MFA via a session skip flag FAZ-CVE22572 / CVE-2026-22572. Manual disassembly was required because no ablation tool could:
- Reconstruct the `ap_hook_handler` call graph register_hooks → handler function
- Track APR table get/set patterns Cookie header → session decrypt
- Identify session skip flag accessor calls in the handler

Gap closed: 2026-10-16. All confirmed FAZ-CVE22572 findings detected automatically in validation.

---

## Finding classes

| Class | CWE | Severity | Pattern |
|---|---|---|---|
| `HANDLER_REGISTRATION` | CWE-0 | INFO | `ap_hook_handlerfn, NULL, NULL, APR_HOOK_MIDDLE` in register_hooks |
| `AUTH_TABLE_ACCESS` | CWE-522 | HIGH | `apr_table_get(r->..., "Cookie"/"Authorization")` in handler |
| `SESSION_SKIP_FLAG` | CWE-287 | HIGH | Call to `session_get_adminuser_skip` / `session_get_admin_prof` / pattern-match |
| `AUTH_BYPASS_SURFACE` | CWE-287 | **CRITICAL** | Cookie read + decrypt + session skip flag all in same handler |
| `APR_TABLE_WRITE` | CWE-20 | MEDIUM | `apr_table_set/add` on auth-relevant header/notes key |

## AUTH_BYPASS_SURFACE composite

The CRITICAL `AUTH_BYPASS_SURFACE` finding fires when three conditions hold in the same request handler function:
1. `apr_table_get(r->..., "Cookie")`, attacker-controlled session input
2. `decrypt_and_auth()` or `session_from_string()`, session is decrypted/parsed 
3. `session_get_adminuser_skip()` or equivalent, skip flag is read

No single condition is critical alone. The combination means a forged or RC4-decrypted cookie can set the skip flag, bypassing MFA.

## Key API

```python
from ablation.analyzers.apache_module_analyzer import ApacheModuleAnalyzer

# From path
findings = ApacheModuleAnalyzer.from_path('/path/to/mod_extension.so').analyze()
print(ApacheModuleAnalyzer.report(findings))

# With BinaryContext
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/mod.so')
findings = ApacheModuleAnalyzer.from_context(ctx).analyze()
```

## Analysis phases

1. **Build PLT**, maps stub VAs to symbol names from `.rela.plt`
2. **Build rodata index**, maps VAs to string literals for header key identification
3. **Find register_hooks**, scans `.text` for `jmp`/`call` to any `ap_hook_*` PLT stub; walks backwards to function start
4. **Extract handler registrations**, disassembles register_hooks to find `lea rdi, [rip+N]` before the hook call; resolves handler function VA
5. **Analyze handler**, tracks `rsi` string loads before `apr_table_get` calls; detects session/auth symbols; fires composite finding
6. **Fallback scan**, if handler discovery fails, scans all of `.text` for session skip flag calls directly

## Architecture support

- **x86-64** (ELF): full support RIP-relative addressing, PLT stub format
- **ARM64**: basic support (BL instruction scanning for hook registration; `_analyze_handler` uses generic Capstone pass)
- **x86-32**: not supported 32-bit ELF PLT format differs

## FORGE audit

Gate: **PASSED**. No subprocess, eval, shell=True, network I/O. All struct unpacks bounds-checked. lief.parse() wrapped in try/except. `_read_va()` guards on VA range. All loop bounds use `range(0, len(data) - N)` to prevent OOB reads.

## Validation (mod_extension.so, FortiAnalyzer v7.6.3)

```
[CRITICAL] AUTH_BYPASS_SURFACE — Cookie → decrypt_and_auth → session_get_adminuser_skip (0x123b)
[HIGH]     AUTH_TABLE_ACCESS   — apr_table_get(r, 'Cookie')                             (0x1293)
[HIGH]     SESSION_SKIP_FLAG   — session_get_admin_prof()                                (0x13c5)
[HIGH]     SESSION_SKIP_FLAG   — session_get_adminuser_skip()                            (0x1417)
[MEDIUM]   AUTH_TABLE_ACCESS   — decrypt_and_auth()                                      (0x133e)
[MEDIUM]   AUTH_TABLE_ACCESS   — session_from_string()                                   (0x13b3)
[MEDIUM]   AUTH_TABLE_ACCESS   — session_from_string()                                   (0x13e5)
[INFO]     HANDLER_REGISTRATION — ap_hook_handler(0x123b, APR_HOOK_MIDDLE)               (0x1236)
```

FAZ-CVE22572 MFA bypass via session skip flag confirmed via CRITICAL composite finding.

---

## How it works

Parses the runtime-specific binary format (APK, DEX, `.mpy`, BEAM, Go ELF) to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

---

## Usage

```python
from ablation.analyzers.apache_module_analyzer import ApacheModuleAnalyzer

analyzer = ApacheModuleAnalyzer.from_context(ctx)
findings = analyzer.analyze()
for f in findings:
    print(f)
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

`ApacheModuleAnalyzer.from_path(path).analyze()` returns `List[ApacheFinding]`:

| Attribute | Content |
|:---|:---|
| `binary` | Path of the analyzed Apache module `.so` |
| `finding_class` | `HANDLER_REGISTRATION` / `AUTH_TABLE_ACCESS` / `SESSION_SKIP_FLAG` / `AUTH_BYPASS_SURFACE` / `APR_TABLE_WRITE` |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `cwe` | CWE identifier (e.g., `CWE-284`, `CWE-200`) |
| `va` | VA of the instruction or call site |
| `title` | Short description of the vulnerability |
| `detail` | Detailed explanation of the attack vector |
| `symbol` | PLT symbol involved (e.g., `apr_table_get`): present on table-access findings |
| `header` | Header key string for table-access findings |

---

## See also

- [BinaryContext](binary-context.md): native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md): trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md): record confirmed findings
