# Cross-Version Function Tracking

Track a specific function across binary versions using a three-stage homolog matching pipeline — structural pre-filter, mnemonic 4-gram Jaccard similarity, and semantic tiebreaker — then localize exactly which instructions changed using `difflib.SequenceMatcher` on normalized instruction lines.

---

## Why this exists

1. **After identifying a vulnerable function in one firmware version, the analyst needs to confirm it is patched in a later version — and verify the patch actually addresses the root cause.** `version_delta.py` tracks a seed function VA across versions by finding its homolog in the target binary using three progressively more expensive stages, then diffs the instruction sequences to show exactly what changed. This was the primary tool for confirming CVE-2022-0778 / RADIUS overflow remediation.

2. **Stripped firmware has no symbol names — homolog matching cannot rely on function names.** Stage 1 (structural pre-filter: basic block count ±2, edge count ±30%) eliminates candidates quickly. Stage 2 (mnemonic 4-gram Jaccard similarity on the top-10 structural matches) identifies the best match by instruction sequence. Stage 3 (SemanticSearcher tiebreaker when top-2 candidates are within 0.05 Jaccard) uses semantic embeddings to break ties that mnemonic similarity cannot distinguish.

3. **`HomologMatch.callee_changed` identifies when a patch introduced a new safety callee** — for example, a stack overflow patch that adds a call to `check_buffer_size()` before the dangerous `strcpy()`. This is a higher-confidence signal of a real patch than instruction-sequence changes alone, because adding a callee is a structural change that cannot be coincidental.

---

## How it works

```mermaid
flowchart TD
    A["version_delta: seed_binary + seed_va → target_binary"] --> B["BinaryClassification.from_path(target)\n  ELF32/ELF64, arch detection"]
    B --> C["FuncFeatures.from_disasm_lines(disasm) for each target function\n  Stage 1: structural pre-filter\n    block_count ±2, edge_count ±30% of seed function"]
    C --> D["Stage 2: mnemonic 4-gram Jaccard\n  Keep top-10 structural candidates\n  Rank by Jaccard(seed.ngrams, candidate.ngrams)"]
    D --> E{"top-2 within 0.05?"}
    E -->|"Yes"| F["Stage 3: SemanticSearcher tiebreaker\n  semantic_score breaks the tie"]
    E -->|"No"| G["Accept top-1 candidate"]
    F --> G
    G --> H["compute_patch_delta(features_a, features_b) → PatchDelta\n  difflib.SequenceMatcher on normalized instruction lines\n  added, removed, context, ratio"]
    H --> I["HomologMatch:\n  va, name, jaccard, semantic_score\n  confidence: HIGH/MEDIUM/LOW\n  delta: PatchDelta\n  new_callees: List[str]\n  removed_callees: List[str]\n  callee_changed: bool"]
    I --> J["DeltaReport:\n  era_confirmed → Optional[int]\n  summary() → str\n  match.delta.unified_diff()"]
```

---

## Usage

```python
from ablation.analyzers.version_delta import (
    BinaryClassification, FuncFeatures, compute_patch_delta, DeltaReport
)
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.dtw_matcher import DTWMatcher

# Track function across versions
ctx_old = BinaryContext.load_or_build('/path/to/daemon_v6.2.bin')
ctx_new = BinaryContext.load_or_build('/path/to/daemon_v7.4.bin')

dtw = DTWMatcher.from_context(ctx_old)
seed_va = 0x12340  # known vulnerable function in old version

# Find homolog in new version via DTW first (fast)
matches = dtw.score_functions([seed_va], ctx_new)
best = max(matches, key=lambda m: m.score)

print(f"Homolog: {best.va:#x}  score={best.score:.2f}  confidence={best.confidence}")

# Then compute instruction-level patch delta
feat_old = FuncFeatures.from_disasm_lines(ctx_old.disasm_lines(seed_va))
feat_new = FuncFeatures.from_disasm_lines(ctx_new.disasm_lines(best.va))
delta = compute_patch_delta(feat_old, feat_new)

print(f"Patched: {delta.is_patched}  similarity: {delta.ratio:.3f}")
print(delta.unified_diff('v6.2', 'v7.4'))
```

---

## Example output

The following illustrates the patch delta output format. Actual instruction sequences are binary-specific.

```
HomologMatch:
  va=<va>  jaccard=0.89  semantic_score=0.91  confidence=HIGH
  callee_changed: True
  new_callees: ['check_buf_len']
  removed_callees: []

PatchDelta: ratio=0.94  (patched)
--- v6.2
+++ v7.4
-  mov    eax, [rbp-0x10]
-  call   strcpy
+  call   check_buf_len
+  test   eax, eax
+  jz     <error_exit>
+  call   strncpy
```

---

## False positives

**Jaccard similarity of 0.05 at stage-2 tiebreaker boundary** — when two candidates have nearly identical mnemonic 4-gram Jaccard scores, the semantic tiebreaker is used. If the semantic model has low confidence for both (e.g., a small utility function), `HomologMatch.confidence` is `LOW`. Treat `LOW` confidence matches as requiring manual verification.

**`compute_patch_delta()` uses normalized instruction lines** — normalization strips immediate values and addresses to make sequence comparison register-independent. A function where only an immediate constant changed (e.g., buffer size) will show `delta.ratio` close to 1.0 but `delta.is_patched = True` with the changed constant visible in `unified_diff()`.

---

## Pipeline position

Run `version_delta` after `DTWMatcher` identifies a candidate homolog to verify patch confirmation. Use `DeltaReport.era_confirmed` for anchor-based era confirmation, and `HomologMatch.callee_changed` as the primary patch signal. Reference this module in `MatrixProfileDiff.is_likely_patched()` workflow for full patch analysis.

---

## See also

- [DTW Function Homolog Matching](dtw-function-homolog-matching.md) — Stage 2 DTW matching that feeds into version delta
- [Matrix Profile Patch Diff](matrix-profile-patch-diff.md) — complementary patch localization approach
- [Generic Vulnerability Profile Sweeps](generic-vulnerability-profile-sweeps.md) — SemanticSearcher used in stage 3 tiebreaker
