# AnalyzeAllJNI

**File:** `modules/analyze_all_jni.py`

## Why this exists

Analyzes the 10 JNI functions in `libhijoyptt.so` (HiJoy PTT Android SO) using ARM32 symbolic execution. Generates a per-function summary of argument writes, protocol buffer reads, call graph edges, and vtable calls. Produces a Markdown surface report with an attack surface section.

## Key API

| Symbol | Description |
|---|---|
| `analyze_all_functions(lib_path)` | Load SO, run symbolic analysis on all 10 hardcoded JNI VAs, return results dict |
| `classify_function(name, summary)` | Name + behavior heuristic classification → dict with type/complexity/has_io |
| `generate_report(results, output_path)` | Write Markdown surface report to output_path |
| `JNI_FUNCTIONS` | Dict of 10 hardcoded function names → VAs for libhijoyptt.so |

`analyze_all_functions()` returns:
```python
{
  'functions': {name: {'addr': str, 'summary': FuncSummary, 'classification': dict}},
  'call_graph': [{'caller': str, 'target': str, 'args_symbolic': str}],
  'protocol_ops': [],
  'io_operations': [],
}
```

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `_MAX_LIB_BYTES=256MB`; `os.path.getsize()` guard before `open().read()` (L45-47). No lief, binary loaded as raw bytes via `open(lib_path, 'rb').read()` and passed to `ARMSymbolicAnalyzer`. No HTTP reads. No subprocess.

---

## How it works

Parses the runtime-specific binary format (APK, DEX, `.mpy`, BEAM, Go ELF) to extract the class/function/module structure, import graph, and callable inventory. Dangerous API calls are identified by matching against a curated sink list for the runtime. For runtimes that support decompilation, a pseudo-code representation is generated for each dangerous call site to assist manual review.

---

## Usage

```python
from ablation.analyzers.analyze_all_jni import AnalyzeAllJNI

results = AnalyzeAllJNI.from_context(ctx).run()
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
