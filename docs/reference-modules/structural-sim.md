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

`extract_fingerprint()` classifies each instruction's mnemonic into one of 12 categories and records its fraction of the total instruction count as the opcode histogram. Immediate operands ≥ 0x100 are collected into a frozenset; RIP-relative values are excluded because they are position-dependent and change between binary versions. `fingerprint_sim()` computes up to five partial scores — opcode cosine, immediate Jaccard, PLT Jaccard, branch density delta, and size ratio — normalizes the weights based on which signals are available for both fingerprints, and returns a weighted sum in [0.0, 1.0]. `find_structural_orphans()` uses a bucket-based scan: it sorts fingerprints by `n_insns`, then for each function in `fps_b` checks the `bucket_size` nearest-by-size functions in `fps_a`, keeping any pair whose similarity exceeds `threshold`. Functions with no match above threshold are returned as orphans.

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

```python
>>> fingerprint_sim(fp_a, fp_b)
0.847

>>> dist = score_distribution(query_fps, corpus_fps, sample_size=500, bucket_size=10)
>>> print(dist['percentiles'])
{'p05': 0.12, 'p25': 0.29, 'p50': 0.41, 'p75': 0.63, 'p90': 0.79, 'p95': 0.86}

>>> orphans = find_structural_orphans(fps_old, fps_new, threshold=0.65)
>>> print(f"{len(orphans)} orphans in new version (no structural match > 0.65)")
47 orphans in new version (no structural match > 0.65)
```

---

## False positives

**High similarity score for semantically different functions** — two small wrapper functions (10–15 instructions, no PLT calls, one conditional branch) can produce a similarity score above 0.80 purely from opcode histogram and branch density alignment, even if they have completely different purposes. When using `fingerprint_sim()` to match version-delta candidates, always follow a high-score pair with a semantic check: SemanticSearcher query of both functions or manual disasm comparison.

**Orphan detection with too-small `bucket_size`** — `find_structural_orphans()` only compares each function in `fps_b` to `bucket_size` candidates in `fps_a` (the nearest by instruction count). A function that grew significantly between versions may land outside the bucket, producing a false orphan. Increase `bucket_size` (default 10) to 25–50 for binaries with large refactors.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` for both versions, then `extract_fingerprint()` on the function sets you want to compare. Typically used after `DTWMatcher` identifies candidate homologs for version delta analysis.

**After this module:** High-similarity pairs from `fingerprint_sim()` are candidates for the same function at a different VA. Confirm with `SemanticSearcher` or manual disassembly, then `ctx.set_name()` under the new VA. Orphans from `find_structural_orphans()` are new or heavily changed functions — candidates for taint analysis and finding registration.

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
