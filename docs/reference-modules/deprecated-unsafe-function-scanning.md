# Deprecated unsafe-function scanning

Flag imported inherently unsafe functions such as gets/mktemp/tmpnam/getwd as review candidates.

---

## What it does

Flag imported inherently unsafe functions such as gets/mktemp/tmpnam/getwd as review candidates.

---

## Implementation

- [`sscanf_sink_classifier.py`](../../ablation/analyzers/sscanf_sink_classifier.py)
- [`deprecated_func_scanner.py`](../../ablation/analyzers/deprecated_func_scanner.py)

---

## See also

- [Deprecated Func Scanner](deprecated-func-scanner.md) — module-level reference with constructor patterns and usage examples
