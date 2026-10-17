# Cross-Library Analysis

Resolve imports and exports across a firmware library set and propagate supported argument taint across library boundaries.

---

## What it does

Resolve imports and exports across a firmware library set and propagate supported argument taint across library boundaries.

---

## Implementation

- [`cross_binary_taint.py`](../../ablation/analyzers/cross_binary_taint.py)
- [`lib_graph.py`](../../ablation/analyzers/lib_graph.py)

---

## See also

- [Taint Analysis](taint-analysis.md) — module-level reference with constructor patterns and usage examples
