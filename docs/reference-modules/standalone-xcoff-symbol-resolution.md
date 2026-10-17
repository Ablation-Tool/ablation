# Standalone XCOFF symbol resolution

Recover library imports and exported code addresses without a full BinaryContext session.

---

## What it does

Recover library imports and exported code addresses without a full BinaryContext session.

---

## Implementation

- [`xcoff_parser.py`](../../ablation/core/xcoff_parser.py)
- [`xcoff_executable_analyzer.py`](../../modules/xcoff_executable_analyzer.py)

---

## See also

- [Xcoff Parser](xcoff-parser.md) — module-level reference with constructor patterns and usage examples
