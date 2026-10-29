<a id="structural-analysis-modules"></a>
# Structural Function Matching

Compare functions with weighted structural fingerprints, identify functions without a close match in another build, and calibrate match thresholds against a corpus.

**File:** `modules/structural_sim.py`

---

## Why structural matching is useful

Addresses and raw instruction bytes change across compilers and builds, but opcode mixtures, selected constants, calls, and branch density can retain useful resemblance. A weighted fingerprint lets users search for likely correspondences before spending time on instruction-level diffing.

The method works as a ranking heuristic because several weak signals can be combined and normalized over whatever evidence is present. It does not recover function semantics or homology by itself. This is a small comparison component that can be reused by release diffing and corpus research, with thresholds calibrated per corpus. New signals can be added or the matcher replaced without turning an orphan into proof of new, removed, or malicious code.

## What this module provides

The public API is function-based; there is no `StructuralSim` class.

- `extract_fingerprint()` builds a `FunctionFingerprint` from disassembly strings and resolved calls.
- `fingerprint_sim()` returns a weighted similarity score from 0.0 to 1.0.
- `find_structural_orphans()` finds target functions whose best baseline match falls below a threshold.
- `score_distribution()` samples best-match scores to help select that threshold.

The comparison is structural and behavioral, not a direct raw-byte hash. It can retain useful signals across compiler versions and architectures, but it does not prove that two functions are homologous.

## Fingerprint signals

| Signal | Base weight | Availability rule |
|:---|---:|:---|
| Opcode-category histogram cosine | 0.35 | Always included. |
| Immediate-value Jaccard | 0.30 | Included only when both fingerprints contain retained immediates. |
| PLT-call overlap | 0.20 | Included when either side has a named call. |
| Branch-density proximity | 0.10 | Always included. |
| Instruction-count proximity | 0.05 | Always included. |

Weights are normalized over available signals, so a pair without immediate or named-call evidence is not automatically assigned zero for those components.

`extract_fingerprint()` retains immediate values from `0x100` through `0xFFFFFFFF`, excludes branch/call targets and RIP-relative operands, records named calls, and computes branch density. Input instructions should be strings in `mnemonic operands` form.

## Compare two functions

```python
from modules.structural_sim import extract_fingerprint, fingerprint_sim

fp_a = extract_fingerprint(
    0x1000,
    ['mov rdx, 0x200', 'call memcpy', 'ret'],
    ['memcpy'],
)
fp_b = extract_fingerprint(
    0x2000,
    ['cmp rcx, 0x200', 'ja error_path', 'call memcpy', 'ret'],
    ['memcpy'],
)

score = fingerprint_sim(fp_a, fp_b)
print(f'Similarity: {score:.3f}')
```

A high score is review evidence, not a confirmation threshold universal to every corpus. Short functions, wrappers, shared library stubs, and common compiler idioms can score high while remaining unrelated.

## Find structural orphans

```python
from modules.structural_sim import find_structural_orphans

orphans = find_structural_orphans(
    corpus_a=baseline_fingerprints,
    corpus_b=target_fingerprints,
    threshold=0.40,
    min_insns=20,
    progress=True,
)

for item in orphans:
    print(
        hex(item['va']),
        item['best_score'],
        item['best_match_va'],
        item['calls'],
    )
```

Each target function is compared with baseline candidates in nearby instruction-count buckets. Results are sorted from lowest best score upward and include address, instruction count, best score and match, named calls, retained immediates, branch density, and whether immediate evidence exists.

An orphan means **no close structural match was found**, not that the function is new, malicious, or absent from the baseline. Refactoring, inlining, different compiler settings, and missing candidate functions can create orphans.

## Calibrate the threshold

```python
from modules.structural_sim import score_distribution

distribution = score_distribution(
    corpus_a=baseline_fingerprints,
    corpus_b=target_fingerprints,
    sample_n=500,
    min_insns=20,
    seed=42,
)

print(distribution['mean'])
print(distribution['percentiles'])
```

The result includes sampled count, mean, percentiles, and sorted scores. Use a corpus with at least one function meeting `min_insns`; an empty eligible sample is not a valid calibration input. Choose thresholds from representative same-vendor and cross-vendor comparisons rather than treating `0.40` as a universal cutoff.

## Limitations

- The fingerprints lose instruction order, operand roles, calling context, and path feasibility.
- Immediate filtering improves portability but removes potentially meaningful small constants and address-independent values outside the retained range.
- Missing PLT names change weight normalization and can make comparisons depend more heavily on opcode structure.
- Function splitting, inlining, and optimizer transformations can reduce scores even when behavior is preserved.
- `numpy` is required for histogram and distribution calculations.

## See also

- [Binary Diffing & Patch Tracking](../workflows/cross-version.md): CFG, Jaccard, and semantic homolog matching across releases.
- [Sequence-Based Function Matching](dtw-matrix-profile-similarity.md): ordered opcode-sequence comparison and patch localization.
- [Function Identification & Naming](function-identity-database.md): persists confirmed identities after manual review.
