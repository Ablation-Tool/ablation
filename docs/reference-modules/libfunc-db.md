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
from modules.libfunc_db import classify, ObservedSlotProfile

# Build a profile from observed call behavior at one PLT slot
profile = ObservedSlotProfile(
    stub_va=0x401020,
    name_hint='',
    num_callsites=7,
    arg_kinds={0: 'ptr', 1: 'int'},
    max_args=2,
    ret_kind='ptr',
    null_on_fail=True,
    neg_on_fail=False,
    used_as_heap_base=True,
)
name, score, top3 = classify(profile, min_score=4)
print(f"  {name}  score={score}  top3={top3}")
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

## Reading output

`classify(profile, min_score)` returns `Tuple[Optional[str], int, List[Tuple[str, int]]]` — matched function name (or `None`), confidence score, and list of `(candidate_name, score)` alternatives.

`LIB_DB` entries are `LibFuncSummary`:

| Attribute | Content |
|:---|:---|
| `name` | Standard function name (e.g., `'malloc'`, `'memcpy'`) |
| `min_args` / `max_args` | Argument count range |
| `arg_roles` | Tuple of `ArgRole` — role tag and direction per argument position |
| `ret_role` | `RetRole` — return value role (pointer, size, status, etc.) |
| `effect` | Effect category: `'alloc'` / `'dealloc'` / `'copy'` / `'compare'` / `'lock'` / `'unlock'` / `'zero'` / `'misc'` |

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
- [FindingRegistry](registry.md) — persistent finding storage
