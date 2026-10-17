# Structural Similarity

**File:** `modules/structural_sim.py`

## Why this exists

PLT-call Jaccard, the original cross-version matching signal. It only works on functions with two or more external PLT calls. That covers roughly 12% of functions in typical stripped firmware. The other 88% had no automated matching mechanism.

`structural_sim.py` replaces that with a five-signal weighted composite that operates on all functions:

1. **Opcode category histogram**, 12-category frequency vector (DATA/ARITH/BIT/CMP/BRANCH/CALL/RET/FLOAT/SIMD/MEMOP/FRAME/OTHER); cosine similarity. Always available.
2. **Immediate value Jaccard**, shared integer constants ≥ 0x100 (struct offsets, magic bytes, buffer sizes). RIP-relative operands filtered (position-dependent). Available when either function has qualifying immediates.
3. **PLT call overlap**, external call set match (the original signal, retained at lower weight). Available when either function has PLT calls.
4. **Branch density proximity**, branch-insn fraction as a control-flow shape indicator. Always available.
5. **Size proximity**, instruction count ratio clamped to [0,1]. Always available.

Weights are normalized at pair time based on signal availability, the composite is always well-defined.

## Key constants

None, operates entirely on pre-built `FunctionFingerprint` objects passed from the caller. No file I/O, no network.

## Key API

```python
from modules.structural_sim import (
    extract_fingerprint,
    fingerprint_sim,
    find_structural_orphans,
    score_distribution,
    FunctionFingerprint,
)

# Build a fingerprint from disassembly output
fp = extract_fingerprint(
    va=0x401234,
    insns=["mov rdi, rsp", "call 0x4010a0", "ret"],  # "mnemonic op_str" strings
    calls=["malloc"],  # PLT-resolved names
)

# Compare two fingerprints → [0.0, 1.0]
score = fingerprint_sim(fp_a, fp_b)

# Find functions in version B with no good match in version A (> threshold)
orphans = find_structural_orphans(
    fps_a=fps_version_a,
    fps_b=fps_version_b,
    threshold=0.65,
    bucket_size=10,
)

# Similarity score distribution over a sample
dist = score_distribution(query_fps, corpus_fps, sample_size=500, bucket_size=10)
print(dist['percentiles'])  # {'p05': 0.12, 'p50': 0.41, ...}
```

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No file reads. No network I/O. No subprocess. No lief.parse(). No bare `except:`. Pure in-memory computation on `FunctionFingerprint` NamedTuples. numpy cosine similarity uses `np.linalg.norm` with explicit zero-denominator guard (`if na > 0 and nb > 0 else 0.0`). `find_structural_orphans` uses bucket-based O(n) search bounded by input size.

---

## How it works

Provides the session state, indexing, and utility functions that other Ablation modules depend on. The implementation details vary by class; see the class-level docstrings and the relevant workflow docs for specifics.

---

## Usage

```python
from modules.structural_sim import extract_fingerprint, fingerprint_sim, find_structural_orphans

# Build fingerprints from disassembly
fp_a = extract_fingerprint(va=0x401234, insns=["mov rdi, rsp", "call 0x4010a0", "ret"], calls=["malloc"])
fp_b = extract_fingerprint(va=0x402000, insns=["push rbx", "call 0x4010a0", "pop rbx", "ret"], calls=["malloc"])

# Compare → float [0.0, 1.0]
score = fingerprint_sim(fp_a, fp_b)
print(f"Similarity: {score:.3f}")

# Find functions in version B with no match in version A
orphans = find_structural_orphans(fps_a=fps_old, fps_b=fps_new, threshold=0.65)
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

`extract_fingerprint(va, insns, calls)` returns a `FunctionFingerprint`:

| Attribute | Content |
|:---|:---|
| `va` | Virtual address of the function |
| `n_insns` | Total instruction count |
| `opcode_hist` | `dict` — category → fraction of total instructions (12 categories: DATA/ARITH/BIT/CMP/BRANCH/CALL/RET/FLOAT/SIMD/MEMOP/FRAME/OTHER) |
| `immediates` | `frozenset[int]` — integer constants ≥ 0x100 from operands (struct offsets, magic bytes, buffer sizes) |
| `calls` | `list[str]` — PLT-resolved call names |
| `branch_density` | Float — branch instruction count divided by total instruction count |

`fingerprint_sim(fp_a, fp_b)` returns a float in `[0.0, 1.0]` — weighted composite similarity across available signals.

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
- [FindingRegistry](registry.md) — persistent finding storage
