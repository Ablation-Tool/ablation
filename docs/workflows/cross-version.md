# Cross-Version Diffing Workflow

Track a confirmed vulnerable function across firmware patch releases. Verify the patch is real, find the new VA, port the name overlay, and detect regressions in subsequent releases.

---

## When to use this workflow

- A vendor releases a security advisory. You need to find the patched function and verify the fix is real, not cosmetic.
- You have confirmed findings in firmware v1.0 and want to check whether they were silently fixed in v1.1 without a CVE assignment.
- You are building a delta report for a vendor advisory: which exact instructions changed between the vulnerable and fixed version.

---

## How VersionDelta finds the homolog

The three-stage pipeline works without symbol names or stable VAs:

```
  func_va_v1
       |
       v
  [Stage 1] Structural pre-filter
    basic_block_count ±2 AND edge_count ±30%
    → reduces N=thousands to N~tens
       |
       v
  [Stage 2] Mnemonic 4-gram Jaccard
    normalize: strip addresses, normalize immediates
    build 4-gram sets from mnemonic sequence
    Jaccard(A,B) = |A ∩ B| / |A ∪ B|
    keep top-10 candidates
       |
       v (only if top-2 within 0.05 of each other)
  [Stage 3] BERT semantic tiebreaker
    SemanticSearcher encoding for both functions
    cosine similarity in 768-dim space
    breaks structural ties
       |
       v
  result.va_v2  result.confidence  result.stage
```

---

## Step 1: Identify the function in v1

Start from your confirmed finding. You need the function VA in v1 and the binary path.

```python
from ablation.analyzers.binary_context import BinaryContext

ctx_v1 = BinaryContext.load_or_build('/path/to/firmware_v1.so')
print(ctx_v1.names_table())   # confirm the function is named in the overlay
```

---

## Step 2: Track it in v2

```python
from ablation.analyzers.version_delta import VersionDelta

vd = VersionDelta(
    binary_v1='/path/to/firmware_v1.so',
    binary_v2='/path/to/firmware_v2.so',
)

result = vd.track(func_va_v1=0x1000)

print(f"Homolog VA in v2: 0x{result.va_v2:x}")
print(f"Confidence: {result.confidence:.2f}")
print(f"Stage resolved at: {result.stage}")   # structural / 4gram / bert
```

| Confidence | Meaning |
|---|---|
| >= 0.90 | Near-certain match |
| 0.70 - 0.90 | Likely match: verify with strings_in_func |
| 0.50 - 0.70 | Possible match: verify manually |
| < 0.50 | Ambiguous: function may have been split, merged, or removed |

---

## Step 3: Inspect the patch diff

```python
print(result.patch_diff)
```

Output is a normalized instruction diff. Addresses and RIP-relative immediates are stripped so the logic change is visible without address noise:

```diff
  movzx  eax, word ptr [rcx + 0x4]
  bswap  eax
  shr    eax, 0x10
+ cmp    eax, 0x8          # PATCH: minimum header size check added
+ jb     <error_path>      # PATCH: jump to error if too small
  add    rcx, rax
  cmp    rcx, rbx
  jb     <loop_top>
```

This diff is disclosure-quality evidence that the patch addressed the specific root cause.

For long insertions or deletions (e.g., an entire authentication block added), use `MatrixProfileDiff` instead. The STOMP algorithm finds the most-changed subsequence across the two function bodies:

```python
from ablation.analyzers.matrix_profile_diff import MatrixProfileDiff

diff = MatrixProfileDiff()
result = diff.compare_functions(
    insns_v1=v1_insns,
    insns_v2=v2_insns,
)
print(result.anomaly_region)   # (start_idx, end_idx)
print(result.change_score)     # 0.0 = identical, 1.0 = completely different
```

---

## Step 4: Port the name overlay to v2

```python
ctx_v2 = BinaryContext.load_or_build('/path/to/firmware_v2.so')
ctx_v2.set_name(result.va_v2, 'proto_parse_message', source='confirmed')
print(ctx_v2.names_table())
```

---

## Step 5: Check for regression in v3+

Once you have the v2 homolog VA, run VersionDelta again from v2 to v3. If the function diverges significantly (confidence below 0.70), the vendor may have refactored the parsing logic. That refactor can introduce new bugs adjacent to the fix.

```python
vd_23 = VersionDelta(
    binary_v1='/path/to/firmware_v2.so',
    binary_v2='/path/to/firmware_v3.so',
)
result_23 = vd_23.track(func_va_v1=result.va_v2)
print(result_23.patch_diff)   # empty if no further changes
```

---

## Batch delta: all changed functions

Get a ranked list of every function that changed between two firmware versions. Useful for advisory analysis when you need to triage all moved functions at once:

```python
changed = vd.changed_functions(top_n=50)
for fn in changed:
    print(f"0x{fn.va_v1:x} -> 0x{fn.va_v2:x}  "
          f"change_score={fn.change_score:.3f}  "
          f"{ctx_v1.name(fn.va_v1)}")
```

Functions with `change_score >= 0.20` had meaningful code changes. Combine with semantic sweep results to prioritize which changed functions deserve manual inspection.

---

## Cross-vendor similarity with StructuralSim

For fine-grained comparison of two specific functions across vendors (not just across versions), use StructuralSim directly. A composite score >= 0.70 across two vendors means the functions share a common ancestor: the same open-source library or standard protocol implementation.

```python
from ablation.analyzers.structural_sim import StructuralSim

sim = StructuralSim(
    binary_a='/path/to/vendor_a.so',
    binary_b='/path/to/vendor_b.so',
)

score = sim.compare(func_va_a=0x1000, func_va_b=0x2000)
print(f"Composite: {score.composite:.3f}")
print(f"  opcode_hist  = {score.opcode_hist:.3f}")
print(f"  imm_jaccard  = {score.imm_jaccard:.3f}")
print(f"  plt_overlap  = {score.plt_overlap:.3f}")
```

When one vendor's version has a confirmed vulnerability and the composite score predicts a shared ancestor, run the same taint analysis on the second vendor's binary to confirm whether the flaw is present there too.
