# Version Delta Fine-Tune

**File:** `modules/version_delta_finetune.py`

## Why this exists

Self-supervised fine-tuning of the MiniLM-L6-v2 embedding model using structural Jaccard similarity to generate ground-truth homolog pairs across firmware versions. Fixes the model collapse problem where opcode n-gram descriptions cluster identically regardless of function size changes. Bootstraps the semantic layer from the structural layer that already works.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No file reads. No HTTP reads. No subprocess. No lief.parse(). Operates entirely on in-memory function description strings and numpy/torch tensors.

---

## How it works

Provides the session state, indexing, and utility functions that other Ablation modules depend on. The implementation details vary by class; see the class-level docstrings and the relevant workflow docs for specifics.

---

## Usage

```python
from ablation.analyzers.version_delta_finetune import VersionDeltaFineTune

results = VersionDeltaFineTune.from_context(ctx).run()
for r in results:
    print(r)
```

---

## Example output

```
# Output varies by module. See Usage section for representative examples.
```

---

## False positives

Core infrastructure modules do not emit security findings directly. False positives in downstream scanners are addressed at the scanner level, not here.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to build the analysis session.

**After this module:** Results feed directly into the analysis pipeline: `SemanticSearcher`, `TaintTracker`, or output modules depending on the task.

---

## Reading findings

| Field | Content |
|:---|:---|
| `result` | Module-specific output; see the class docstring for the exact type |

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
- [FindingRegistry](registry.md) — persistent finding storage
