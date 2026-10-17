# scanf-family overflow candidates

Identify unbounded string conversion specifications at supported formatted-input call sites.

---

## What it does

Identify unbounded string conversion specifications at supported formatted-input call sites.

---

## Implementation

- [`sscanf_sink_classifier.py`](../../ablation/analyzers/sscanf_sink_classifier.py)
- [`deprecated_func_scanner.py`](../../ablation/analyzers/deprecated_func_scanner.py)

---

## See also

- [Deprecated Func Scanner](deprecated-func-scanner.md) — module-level reference with constructor patterns and usage examples
