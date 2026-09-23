# Cross-Version Diffing Workflow

Track a confirmed vulnerable function across firmware patch releases. Verify the patch was
applied. Find the new VA. Port the named function overlay to the updated binary.

---

## When to use this workflow

- A vendor releases a security advisory. You need to find the patched function and verify the
  fix is real, not cosmetic.
- You have confirmed findings in firmware v1.0 and want to check whether they were silently
  fixed in v1.1 without a CVE assignment.
- You are building a delta report for a vendor advisory: which exact instructions changed
  between the vulnerable and fixed version.

---

## Step 1: Identify the function in v1

Start from your confirmed finding. You need two things:

- The function VA in v1: e.g., `0x1000` (your named function in the v1 binary)
- The binary path for v1: `/path/to/firmware_v1.so`

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
print(f"Stage resolved at: {result.stage}")   # "structural", "4gram", or "bert"
```

**Confidence interpretation:**

| Confidence | Meaning |
|---|---|
| >= 0.90 | Near-certain match |
| 0.70 - 0.90 | Likely match -- verify with strings_in_func check |
| 0.50 - 0.70 | Possible match -- manual verification recommended |
| < 0.50 | Ambiguous -- function may have been split, merged, or removed |

---

## Step 3: Inspect the patch diff

```python
print(result.patch_diff)
```

Output is a normalized instruction diff. Addresses and RIP-relative immediates are stripped
so the logic change is visible without address noise:

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

---

## Step 4: Port the name overlay to v2

```python
ctx_v2 = BinaryContext.load_or_build('/path/to/firmware_v2.so')
ctx_v2.set_name(result.va_v2, 'proto_parse_message', source='confirmed')
print(ctx_v2.names_table())
```

---

## Step 5: Check for regression in v3+

Once you have the v2 homolog VA, run VersionDelta again from v2 to v3. If the function
diverges significantly (confidence below 0.70), the vendor may have refactored the parsing
logic -- which can introduce new bugs adjacent to the fix.

```python
vd_23 = VersionDelta(
    binary_v1='/path/to/firmware_v2.so',
    binary_v2='/path/to/firmware_v3.so',
)
result_23 = vd_23.track(func_va_v1=result.va_v2)
print(result_23.patch_diff)   # empty if no further changes
```

---

## Batch delta: all changed functions between two versions

Get a ranked list of all changed functions between two firmware versions. Useful for advisory
analysis when you want to triage everything that moved:

```python
changed = vd.changed_functions(top_n=50)
for fn in changed:
    print(f"  0x{fn.va_v1:x} -> 0x{fn.va_v2:x}  "
          f"change_score={fn.change_score:.3f}  "
          f"{ctx_v1.name(fn.va_v1)}")
```

Functions with `change_score >= 0.20` had meaningful code changes, not just recompilation
address shifts. Combine with semantic sweep results to prioritize which changed functions
deserve manual inspection.

---

## Cross-vendor similarity with StructuralSim

For fine-grained comparison of two specific functions across vendors (not just across
versions), use StructuralSim directly:

```python
from ablation.analyzers.structural_sim import StructuralSim

sim = StructuralSim(
    binary_a='/path/to/vendor_a.so',
    binary_b='/path/to/vendor_b.so',
)

score = sim.compare(func_va_a=0x1000, func_va_b=0x2000)
print(f"Composite similarity: {score.composite:.3f}")
print(f"  opcode_hist  = {score.opcode_hist:.3f}")
print(f"  imm_jaccard  = {score.imm_jaccard:.3f}")
print(f"  plt_overlap  = {score.plt_overlap:.3f}")
```

A composite score of 0.70 or above between two different vendors' binaries means the functions
share a common ancestor -- the same open-source library or standard protocol implementation.
When one vendor's version has a confirmed vulnerability, that score predicts whether the other
vendor carries the same flaw.
