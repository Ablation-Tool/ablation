# Go Binary RE

**File:** `modules/go_binary_re.py`

## Why this exists

Go binary reverse engineering for Mach-O and ELF targets (Go 1.16+): pclntab function table parsing, command dispatch map reconstruction, message frame format inference from bufio.Reader call chains, and RIP-relative pointer resolution.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |
| `_MAX_RESP_BYTES` | 16 MB | HTTP response body cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. HTTP reads capped at `_MAX_RESP_BYTES=16MB`. No lief.parse().

---

## How it works

Parses the runtime-specific binary format (APK, DEX, `.mpy`, BEAM, Go ELF) to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

---

## Usage

```python
from modules.go_binary_re import analyze

result = analyze('/path/to/go_binary')
for fn in result.get('functions', []):
    print(f"{fn.va:#x}  {fn.name}")
for h in result.handlers:
    print(f"[handler] cmd={h.cmd_id:#x}  {h.func_name}  ({h.args_hint})")
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

## Reading output

`analyze(binary_path)` (module-level function) returns an `AnalysisResult`:

| Attribute | Content |
|:---|:---|
| `binary_path` | Path of the analyzed Go binary |
| `go_version` | Go toolchain version string extracted from pclntab (e.g., `'go1.21.5'`) |
| `arch` | Target architecture string |
| `pclntab_magic` | Pclntab magic value (identifies pclntab format version) |
| `num_functions` | Total number of functions recovered from pclntab |
| `functions` | `List[GoFunc]`: each with `va`, `fileoff`, `name`, `nameoff` |
| `handlers` | `List[HandlerEntry]`: command dispatch handlers with `cmd_id`, `func_va`, `func_name` |
| `errors` | `List[str]`: parse errors encountered |

---

## See also

- [BinaryContext](binary-context.md): native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md): trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md): record confirmed findings
