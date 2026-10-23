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

For each function in `LIB_DB`, `_score(profile, summary)` accumulates integer score points: argument count range match, per-position argument kind match (`ptr` / `int` / `float`), return kind match, null-on-fail and neg-on-fail flags, and `used_as_heap_base` for allocators. `classify()` builds a ranked list of `(name, score)` pairs from all `LIB_DB` entries, returns the top match if its score meets `min_score`, and always returns the full `top3` list for inspection. The `ObservedSlotProfile` is built by the caller from observed call-site behavior: `num_callsites`, `arg_kinds`, `ret_kind`, and usage-pattern flags: typically by driving disassembly of all call sites for a given PLT stub VA with Capstone.

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
classify(profile)
  top match : malloc  score=9
  top3 : [('malloc', 9), ('operator_new', 7), ('realloc', 4)]

classify(profile_recv)
  top match : recv  score=11
  top3 : [('recv', 11), ('read', 8), ('recvfrom', 6)]

classify(profile_ambiguous)
  top match : None  (best score 3 < min_score 4)
  top3 : [('memcpy', 3), ('memmove', 3), ('memset', 2)]
```

---

## False positives

**Wrong match when PLT stubs share an ABI pattern**: `malloc`, `operator_new`, and `calloc` have similar argument kind profiles. If the profile is built from only a few call sites (low `num_callsites`) the `used_as_heap_base` and `null_on_fail` flags may not be observable, reducing the discriminating signal. Verify the returned `top3` list: if the top two scores are within 2 points, treat the classification as ambiguous and fall back to `SigLibrary` description-based matching.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to identify PLT stubs without symbol names. Capstone disassembly of all call sites for each unnamed PLT stub to build the `ObservedSlotProfile`.

**After this module:** Pass the matched function name to `ctx.set_name(stub_va, name, source='libfunc_db')`. Named PLT stubs then appear in `SemanticSearcher` corpus descriptions and `TaintTracker` sink matching.

---

## Reading output

`classify(profile, min_score)` returns `Tuple[Optional[str], int, List[Tuple[str, int]]]`: matched function name (or `None`), confidence score, and list of `(candidate_name, score)` alternatives.

`LIB_DB` entries are `LibFuncSummary`:

| Attribute | Content |
|:---|:---|
| `name` | Standard function name (e.g., `'malloc'`, `'memcpy'`) |
| `min_args` / `max_args` | Argument count range |
| `arg_roles` | Tuple of `ArgRole`: role tag and direction per argument position |
| `ret_role` | `RetRole`: return value role (pointer, size, status, etc.) |
| `effect` | Effect category: `'alloc'` / `'dealloc'` / `'copy'` / `'compare'` / `'lock'` / `'unlock'` / `'zero'` / `'misc'` |

---

## See also

- [BinaryContext](binary-context.md): session foundation for all analysis
- [SemanticSearch](semantic-search.md): function candidate identification
- [FindingRegistry](registry.md): persistent finding storage
