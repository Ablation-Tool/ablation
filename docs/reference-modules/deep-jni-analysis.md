# DeepJNIAnalysis

**File:** `modules/deep_jni_analysis.py`

## Why this exists

Deep disassembly analysis of JNI functions: vtable dispatch patterns, structure field accesses, and internal state management. Goes beyond surface-level JNI registration to trace how native methods interact with Java objects via JNIEnv.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_LIB_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `f.read()`; `_MAX_LIB_BYTES=256MB`. No lief.parse(). No HTTP reads.

---

## How it works

Parses the runtime-specific binary format (APK, DEX, `.mpy`, BEAM, Go ELF) to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

---

## Usage

```python
from modules.deep_jni_analysis import (
    analyze_structure_accesses,
    analyze_call_targets,
    analyze_vtable_patterns,
)

with open('/path/to/libnative.so', 'rb') as f:
    data = f.read()

struct_hits = analyze_structure_accesses(data)
call_hits   = analyze_call_targets(data)
vtable_hits = analyze_vtable_patterns(data)

for h in struct_hits + call_hits + vtable_hits:
    print(h)
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

The module-level functions `analyze_structure_accesses(data)`, `analyze_immediate_constants(data)`, `analyze_call_targets(data)`, and `analyze_vtable_patterns(data)` each return text output printed to stdout. There is no typed finding dataclass.

For structured output, call `java_decompiler.JavaDecompiler(path).analyze()` which returns a dict:

| Key | Content |
|:---|:---|
| `path` | Absolute path to the analyzed file |
| `classes` | `List[dict]`: per-class analysis (name, methods, fields) |
| `security` | Security audit result string |
| `findings` | `List[dict]`: individual findings with `severity`, `title`, `description` |

---

## See also

- [BinaryContext](binary-context.md): native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md): trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md): record confirmed findings
