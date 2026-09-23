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
    binary_v1='/path/to/libips.so.new.v8.0.0',
    binary_v2='/path/to/libips.so.new.v8.0.1',
)

result = vd.track(func_va_v1=0x17b660)
print(f"Homolog in v2: 0x{result.va_v2:x}  (confidence={result.confidence:.2f})")
print(result.patch_diff)   # unified diff of changed instructions
```

### Anchor scan (implementation variant classification)

For large binary corpora (e.g., 28 different `lina` builds across all ASA versions),
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
score = sim.compare(func_va_v1=0x17b660, func_va_v2=0x18a940)
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

Primary target in the current corpus: `libwechatnetwork.so` (WeChat 8.0.56 ARM64) -- resolves
the `BLR` at 0x112050 that passes `&gILinkKey` as `x1`.

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
