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
from ablation.analyzers.deep_jni_analysis import DeepJNIAnalysis

results = DeepJNIAnalysis.from_context(ctx).run()
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

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `finding_type` | Runtime-specific category (e.g., `DANGEROUS_CALL`, `UNTRUSTED_INPUT`, `OBFUSCATED_CODE`) |
| `location` | Class, method, or file offset where the finding was observed |
| `detail` | What was found and why it matters for the native attack surface |

---

## See also

- [BinaryContext](binary-context.md) — native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md) — trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md) — record confirmed findings
