# Fork/exec classification

Distinguish worker-child, exec-after-fork and exit-in-child patterns in supported x86-64 functions.

---

## What it does

Distinguish worker-child, exec-after-fork and exit-in-child patterns in supported x86-64 functions.

---

## Implementation

- [`chunk_walker_validator.py`](../../modules/chunk_walker_validator.py)
- [`epilogue_share_scanner.py`](../../ablation/analyzers/epilogue_share_scanner.py)

---

## See also

- [Chunk Walker Validator](chunk-walker-validator.md) — module-level reference with constructor patterns and usage examples
