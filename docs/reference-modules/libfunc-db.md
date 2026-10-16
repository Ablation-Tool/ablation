# LibFuncDB: PLT Slot Classifier

**File:** `modules/libfunc_db.py`

## Why this exists

Classifies PLT slots in stripped ARM64 binaries without symbol names. Profiles each PLT stub via ABI-visible call-site behavior (argument kinds, return usage) and scores against a `LibFuncSummary` database to identify common libc/libstdc++ functions. Needed when BinaryContext has no imports and SemanticSearcher needs to know whether a call site targets `memcpy` vs. `malloc` vs. `strcmp`.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `os.path.getsize()` guard before `lief.parse()`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.

---

## How it works

Provides the session state, indexing, and utility functions that other Ablation modules depend on. The implementation details vary by class; see the class-level docstrings and the relevant workflow docs for specifics.

---

## Usage

```python
from ablation.analyzers.libfunc_db import LibFuncDB:PLTSlotClassifier

results = LibFuncDB:PLTSlotClassifier.from_context(ctx).run()
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
