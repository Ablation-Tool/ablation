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
