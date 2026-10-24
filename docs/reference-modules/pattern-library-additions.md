# PatternLibrary: fuzzy_similarity

## Why this addition exists

Two gaps motivated this addition:

1. `PatternLibrary.sweep()` uses semantic embedding similarity, which requires a built corpus. When comparing two function byte sequences directly without a corpus, no similarity method existed.
2. Compiler variants of the same function produce byte sequences that are not identical but are similar enough to confirm the same vulnerability. Variants arise from different optimization flags or minor source changes. A byte-level fuzzy similarity score enables cross-version homolog detection without re-running the full semantic pipeline.

## fuzzy_similarity

A `@staticmethod` on `PatternLibrary`. Returns a float from 0.0 to 1.0. Higher means more similar. Returns 0.0 for empty inputs.

```python
from ablation.analyzers.pattern_library import PatternLibrary

confirmed_bytes = open_func_bytes(ctx, confirmed_va)
candidate_bytes = open_func_bytes(ctx2, candidate_va)

score = PatternLibrary.fuzzy_similarity(confirmed_bytes, candidate_bytes)
if score > 0.7:
    print(f"High similarity: {score:.3f} — likely compiler variant")
```

## Methods

| method | Algorithm | Package required | Notes |
| ------ | --------- | ---------------- | ----- |
| `'tlsh'` | TLSH locality-sensitive hash | `tlsh` | Best for firmware function diffing |
| `'ssdeep'` | Context-triggered piecewise hash | `ssdeep` | Good for larger functions |
| `'byte'` | 4-gram Jaccard similarity | None | Always available; no package needed |

Both `tlsh` and `ssdeep` fall back to `'byte'` if the package is not installed.

## Thresholds

Suggested score thresholds for function-level byte comparison:

| Score range | Interpretation |
| ----------- | -------------- |
| 0.85 to 1.0 | Same function, different build |
| 0.65 to 0.84 | Likely compiler variant; verify with TaintTracker |
| 0.40 to 0.64 | Structural similarity; manual review required |
| below 0.40 | Not the same function |

These thresholds are empirical for stripped ARM64 firmware. Adjust per target.

## Input constraints

TLSH requires inputs of at least 50 bytes. Inputs shorter than 50 bytes return 0.0 via TLSH (TNULL) and fall back to the `'byte'` method. The `'byte'` method requires inputs of at least 4 bytes for 4-gram extraction.

Pass function-level byte sequences only. Do not pass full binary data: the 4-gram Jaccard fallback creates a set of all 4-byte substrings and will use excessive memory on inputs above roughly 64 KB.
