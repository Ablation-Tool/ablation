# Structural Analysis Modules

Cross-version function tracking, C++ vtable reconstruction, and binary diffing.

---

## VersionDelta

**File:** `ablation/analyzers/version_delta.py`

Finds the homolog of a known function in a patched firmware binary using a three-stage
pipeline. VersionDelta tracks how a vulnerable function changes across patch releases without
relying on symbol names or static VAs.

When a vendor patches a vulnerability, the fixed function moves. Its VA changes. Its binary
name is gone. VersionDelta finds the function by its shape.

### Three-stage pipeline

**Stage 1: Structural pre-filter**
Eliminates candidates that differ too much in size: `basic_block_count +/- 2`,
`edge_count +/- 30%`. Reduces the candidate pool from thousands to tens.

**Stage 2: Mnemonic 4-gram Jaccard**
Computes instruction sequence similarity using 4-gram overlap on normalized mnemonic
sequences (addresses stripped, immediates normalized). Keeps the top-10 candidates.

**Stage 3: Semantic tiebreaker (BERT)**
When the top-2 candidates are within 0.05 Jaccard of each other, runs SemanticSearcher to
break the tie using behavioral fingerprint similarity.

After finding the homolog: patch localization via `difflib.SequenceMatcher` on normalized
instruction lines reveals the exact instructions that changed between versions.

### Usage

```python
from ablation.analyzers.version_delta import VersionDelta

vd = VersionDelta(
    binary_v1='/path/to/firmware_v1.so',
    binary_v2='/path/to/firmware_v2.so',
)

result = vd.track(func_va_v1=0x1000)
print(f"Homolog in v2: 0x{result.va_v2:x}  (confidence={result.confidence:.2f})")
print(result.patch_diff)   # unified diff of changed instructions
```

### Anchor scan (implementation variant classification)

For large binary corpora (e.g., 28 different builds of the same firmware component),
VersionDelta includes masked byte-pattern anchors that classify the implementation variant of
a function. This distinguishes ELF32 vs ELF64 calling conventions and register-allocation
differences between major versions:

```python
from ablation.analyzers.version_delta import AnchorScanResult, ERA_DISCRIMINATOR_ANCHORS

result = vd.run_anchor_scan('/path/to/binary')
for anchor_name, scan_result in result.items():
    if scan_result.found:
        print(f"  {anchor_name}: impl_v{scan_result.era} at offset 0x{scan_result.hit_offset:x}")
```

---

## StructuralSim

**File:** `ablation/analyzers/structural_sim.py`

Weighted five-signal composite similarity for cross-version matching. Replaces PLT-call
Jaccard with a composite that works on all functions, not just the roughly 12% that have two
or more external PLT calls.

### Five signals

| Signal | Weight | Description |
|---|---|---|
| Opcode category histogram | High | Cosine similarity of 12-category frequency vectors (DATA, ARITH, BIT, CMP, BRANCH, CALL, RET, FRAME, MEMOP, FLOAT, SIMD, OTHER) |
| Immediate value Jaccard | High | Shared integer constants (struct offsets, magic bytes, buffer sizes). RIP-relative offsets are filtered (position-dependent). |
| PLT call overlap | Medium | Shared external function call set |
| Branch density proximity | Low | Control flow shape: linear / switch / loop-heavy |
| Size proximity | Low | Instruction count ratio |

**Why immediates unlock matching:** Struct field offsets, magic constants, and buffer sizes
survive recompilation. A `mov eax, 0x10` (16-byte minimum header) or `cmp rax, 0x1000`
(4KB limit check) is a fingerprint that persists across versions and optimization levels.

```python
from ablation.analyzers.structural_sim import StructuralSim

sim = StructuralSim('/path/to/binary_v1.so', '/path/to/binary_v2.so')
score = sim.compare(func_va_v1=0x1000, func_va_v2=0x1200)
print(f"Similarity: {score.composite:.3f}")
print(f"  opcode_hist={score.opcode_hist:.3f}")
print(f"  imm_jaccard={score.imm_jaccard:.3f}")
print(f"  plt_overlap={score.plt_overlap:.3f}")
```

---

## VtableResolver

**File:** `ablation/analyzers/vtable_resolver.py`

Static vtable reconstruction and BLR indirect call resolution for stripped ARM64 binaries.

ARM64 C++ binaries dispatch virtual method calls via `BLR xN` -- a branch to a register whose
value was loaded from a vtable. In a stripped binary, these appear as opaque indirect calls
with no symbol information. VtableResolver reconstructs the vtable layout and maps each `BLR`
call site to its target function set.

### Four-phase algorithm

**Phase 1: Vtable candidate extraction**
Scans `.rodata` for runs of code pointers (addresses that fall within `.text`). Candidate
vtables are sequences of N or more consecutive 8-byte code pointers.

**Phase 2: Constructor vptr detection**
Finds `ADRP + ADD + STR` sequences in `.text` that store a vtable pointer into an object
field. Each such sequence identifies: "this constructor initializes objects with vtable at
VA X."

**Phase 3: BLR site detection**
Finds `LDR vptr / LDR slot_N / BLR xN` sequences -- the pattern for virtual method dispatch:
load object pointer, load vtable pointer, load function pointer at slot N, branch.

**Phase 4: Resolution**
Maps each `BLR@slot-k` to the function pointer at slot k in the vtable identified in Phase 2.
Produces a resolved call graph for all indirect calls.

### Usage

```python
from ablation.analyzers.vtable_resolver import VtableResolver

resolver = VtableResolver('/path/to/libwechatnetwork.so')
result = resolver.resolve()

for vt in result.vtables:
    print(f"  vtable at 0x{vt.va:x}: {len(vt.slots)} slots")
    for i, slot_va in enumerate(vt.slots):
        print(f"    slot[{i}] -> 0x{slot_va:x}")

for blr in result.resolved_blr:
    print(f"  BLR@0x{blr.site:x} slot={blr.slot} -> "
          f"targets={[hex(t) for t in blr.targets]}")
```

Useful for ARM64 binaries where C++ virtual dispatch accounts for a large fraction of indirect
calls -- resolves `BLR xN` sites to their concrete target function sets.

---

## Cross-Version Fine-Tuning (ZIM-BERT)

**File:** `ablation/analyzers/version_delta_finetune.py`

Self-supervised fine-tuning for cross-version binary similarity. When MiniLM-L6-v2 collapses
stripped binary function descriptions to the same embedding neighborhood — every function gets
cosine > 0.65 against every other regardless of size or behavior — this module bootstraps
better separation from structural signal that already works.

The problem is concrete: opcode n-gram descriptions like `push sub mov call ret` are nearly
universal. The semantic layer has nothing to distinguish functions with different behaviors but
the same instruction mix. The fix is to build ground-truth homolog pairs from Jaccard
similarity on PLT call sets, then fine-tune on those pairs.

### Standard fine-tuning

```python
from ablation.analyzers.version_delta_finetune import (
    FunctionMeta, generate_structural_pairs, finetune_model, evaluate_separation
)

# Build FunctionMeta objects from your two binary versions
corpus_a = [FunctionMeta(va=..., n_insns=..., calls=[...], desc=...) for ...]
corpus_b = [FunctionMeta(va=..., n_insns=..., calls=[...], desc=...) for ...]

train_pairs, eval_pairs = generate_structural_pairs(corpus_a, corpus_b)
model = finetune_model(train_pairs, eval_pairs, output_path='~/ablation/models/mymodel')

# Measure separation quality
results = evaluate_separation(model, homolog_pairs, nonhomolog_pairs)
print(f"separation ratio: {results['separation_ratio']:.3f}x")  # target: > 1.30
```

**When to use:** You have two builds of the same binary and want to improve VersionDelta's
semantic tiebreaker for that specific product family. The fine-tuned model trains PLT call
pattern → embedding alignment that vanilla MiniLM never learned.

### ZIM-BERT distillation

ZIM-BERT extends the standard training with mpnet teacher knowledge. It adds two losses on
top of MultipleNegativesRankingLoss:

**L_KL_output** — KL divergence on batch pairwise cosine similarity distributions. The
teacher (mpnet, 768-dim) has already learned which functions are similar across a wide
firmware corpus. Forcing the student's similarity structure to match the teacher's pulls the
student away from the opcode-collapse attractor.

**L_value** — MSE on value projection vectors from corresponding encoder layers. Teacher
layers {0,2,4,6,8,10} map to student layers {0,1,2,3,4,5}. Value vectors encode what
information each attention head selects from the input; matching them transfers the teacher's
attention routing to the student without requiring identical architecture depth.

```
L_total = L_MNR + 10.0 * L_KL_output + 0.5 * L_value
```

```python
from ablation.analyzers.version_delta_finetune import zimbert_finetune, evaluate_separation

model = zimbert_finetune(
    train_pairs=train_pairs,
    eval_pairs=eval_pairs,
    teacher_name='sentence-transformers/all-mpnet-base-v2',   # default
    student_name='sentence-transformers/all-MiniLM-L6-v2',    # default
    output_path='~/ablation/models/zimbert_v1',
    alpha=10.0,   # weight for L_KL_output
    beta=0.5,     # weight for L_value
    epochs=4,
    batch_size=16,
    device='cpu',
)

results = evaluate_separation(model, homolog_pairs, nonhomolog_pairs)
print(f"separation ratio: {results['separation_ratio']:.3f}x")
```

**When to use:** You have enough training pairs (500+) and want to squeeze additional
separation improvement on top of standard fine-tuning. The mpnet teacher is already cached by
SemanticSearcher so no extra download is needed.

### Separation ratio target

| Model | Separation ratio | Notes |
|---|---|---|
| Vanilla MiniLM-L6-v2 (lina x86-64) | 2.248x | baseline on lina eval set |
| ZIM-BERT lina v1 | 2.521x | trained on lina 9.12.4 x86-64; **do not use on other targets** |
| Vanilla MiniLM-L6-v2 (FAP_221E ARM32) | 1.124x | baseline on FAP_221E eval set |
| ZIM-BERT arm32 v1 | 1.083x | **REGRESSION** — do not deploy; training data too homogeneous (Jaccard mean=0.994) |

Use `evaluate_separation()` to measure ratio before and after any training run. Do not swap
in a new model unless it beats the current checkpoint's ratio on the same eval set.

**ARM32 lesson:** ZIM-BERT training requires a corpus where Jaccard mean < 0.80. When two
firmware versions are nearly identical (same codegen, minor patches), the KL divergence loss
collapses nonhomolog separation. Use firmware versions that are at least one major release apart,
or mix multiple products in the training corpus.

### Using ZIM-BERT with VersionTracker and FuncMatcher

A trained ZIM-BERT model replaces the Stage 3 semantic encoder in both `VersionTracker` and
`FuncMatcher`. Use the `with_zimbert()` classmethod on whichever class you instantiate:

```python
from ablation.analyzers.version_delta import VersionTracker

# Engagement-level: track lina homologs across versions with ZIM-BERT
tracker = VersionTracker.with_zimbert(
    binaries={
        '9.12.4': '/path/to/lina_9.12.4',
        '9.14.1': '/path/to/lina_9.14.1',
    }
)
reports = tracker.track(seed_binary='9.12.4', seed_va=0x4a1234)
```

```python
from ablation.analyzers.version_delta import FuncMatcher

# Lower-level: use ZIM-BERT in a single FuncMatcher call
matcher = FuncMatcher.with_zimbert()
match = matcher.find_homolog(seed_func, target_funcs)
```

Both classmethods load from `~/ablation/models/zimbert_lina_v1` by default. Pass
`model_path=` to override.

**Scope note:** `zimbert_lina_v1` was trained on Cisco lina (x86-64, 9.12.x). It improves
separation on lina-family binaries (2.521x vs 2.248x baseline). It degrades on
out-of-distribution targets (C17 dcerpc on libips.so: rank 158 → 1225, 8x regression). Do not
use it as a general-purpose `SemanticSearcher` replacement. Use it for lina VersionDelta tasks.

---

## MatrixProfileDiff

**File:** `ablation/analyzers/matrix_profile_diff.py`

Matrix Profile-based sequence anomaly detection for binary diffing. Finds the most changed
subsequence between two function instruction sequences using the STOMP algorithm. Complements
VersionDelta's diff output when the changed region is a long insertion or deletion rather than
a point substitution.

```python
from ablation.analyzers.matrix_profile_diff import MatrixProfileDiff

diff = MatrixProfileDiff()
result = diff.compare_functions(
    insns_v1=[(va, mnem, op) for va, mnem, op in func_v1_insns],
    insns_v2=[(va, mnem, op) for va, mnem, op in func_v2_insns],
)
print(result.anomaly_region)    # (start_idx, end_idx) of most-changed subsequence
print(result.change_score)      # 0.0 (identical) to 1.0 (completely different)
```
