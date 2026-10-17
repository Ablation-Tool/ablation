# Go Garble RE

**File:** `modules/go_garble_re.py`

## Why this exists

Reverse engineering of garble-obfuscated Go binaries: deobfuscates symbol names using hash correlation against known Go stdlib and common import paths, reconstructs pclntab when name hashes have been overwritten, and identifies garbled type assertion patterns.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `f.read()`; `_MAX_BINARY_BYTES=256MB`. No lief.parse(). No HTTP reads.

---

## How it works

Parses the runtime-specific binary format (APK, DEX, `.mpy`, BEAM, Go ELF) to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

---

## Usage

```python
from ablation.analyzers.go_garble_re import GoGarbleRE

results = GoGarbleRE.from_context(ctx).run()
for r in results:
    print(r)
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

Standard library calls that resemble dangerous patterns (e.g., `exec` used for shell completions, `eval` used for template rendering with static input) are not findings. Confirm that the argument reaching the dangerous call is user-controlled before escalating. Obfuscated code (Garble-compiled Go, ProGuard-stripped Android) produces incomplete call graphs — findings from incomplete graphs carry lower confidence.

---

## Pipeline position

**Before this module:** Confirm the target binary format (APK, `.mpy`, BEAM, Go ELF) before loading. `BinaryContext` is not required for all runtime analyzers.

**After this module:** Feed dangerous call findings to `TaintTracker` or `FindingRegistry` for confirmed findings.

---

## Reading output

`analyze_go_garble_binary(binary_path)` returns a dict:

| Key | Content |
|:---|:---|
| `binary` | Path string of the analyzed binary |
| `file_size` | Hex+MB formatted file size string |
| `errors` | `List[str]` — any parse or load errors |
| `elf` | ELF header metadata dict (`entry_va`, `load_segs`, etc.) |
| `pclntab` | pclntab parse results (`magic`, `go_version`, `num_funcs`, `funcs`) |
| `bootstrap` | Bootstrap function analysis results |
| `string_xrefs` | Dict mapping string values to lists of referencing function VAs |
| `decrypt_stubs` | List of identified garble string-decryption stub VAs |
| `findings` | `List[dict]` — each with `severity`, `category`, `title`, `description`, `va` |

---

## See also

- [BinaryContext](binary-context.md) — native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md) — trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md) — record confirmed findings
