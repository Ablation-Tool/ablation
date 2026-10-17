# Shared-epilogue detection

Detect tail blocks shared through jumps so analysis can account for compiler-merged epilogues.

---

## What it does

Detect tail blocks shared through jumps so analysis can account for compiler-merged epilogues.

---

## Implementation

- [`chunk_walker_validator.py`](../../modules/chunk_walker_validator.py)
- [`epilogue_share_scanner.py`](../../ablation/analyzers/epilogue_share_scanner.py)

---

## See also

- [Chunk Walker Validator](chunk-walker-validator.md) — module-level reference with constructor patterns and usage examples
