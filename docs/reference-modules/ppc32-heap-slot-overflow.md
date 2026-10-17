# PPC32 heap-slot overflow

Detect fixed-slot allocation followed by supported unbounded string-copy patterns.

---

## What it does

Detect fixed-slot allocation followed by supported unbounded string-copy patterns.

---

## Implementation

- [`sscanf_sink_classifier.py`](../../ablation/analyzers/sscanf_sink_classifier.py)
- [`deprecated_func_scanner.py`](../../ablation/analyzers/deprecated_func_scanner.py)

---

## See also

- [Deprecated Func Scanner](deprecated-func-scanner.md) — module-level reference with constructor patterns and usage examples
