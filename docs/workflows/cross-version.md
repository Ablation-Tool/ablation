<a id="cross-version-diffing-workflow"></a>
# Binary Diffing & Patch Tracking

Find the corresponding function across binary releases, inspect normalized instruction changes, and carry reviewed names forward only when the match is credible.

**File:** `ablation/analyzers/version_delta.py`

---

## When to use this

- Locate a vulnerable function after a vendor update changes its address.
- Check whether a patch changes the relevant comparison, allocation, call, or validation logic.
- Compare one function across several registered releases.
- Diff two disassembly snippets directly without loading a full binary project.

A homolog match is a candidate correspondence, not proof that two functions are identical or that a patch closes a vulnerability.

## Matching pipeline

`VersionTracker` applies several evidence layers:

1. **Optional era anchors:** `structural_anchor_scan()` searches for configured byte patterns before loading a CFG. `era_only=True` can stop after an anchor identifies a release family.
2. **Structural candidates:** `FuncMatcher` compares function size and CFG features to reduce the candidate set.
3. **Mnemonic 4-gram Jaccard:** normalized instruction sequences rank the remaining candidates.
4. **Semantic tiebreaking:** close candidates can be scored with the same semantic infrastructure used elsewhere in Ablation. The standard semantic-search model uses 384-dimensional embeddings.

`DeltaReport.match` contains a `HomologMatch` or `None`. A match includes the target address and name, Jaccard and semantic scores, a `HIGH`/`MEDIUM`/`LOW` confidence category, a `PatchDelta`, and added/removed callees.

## Prerequisites

Full binary tracking uses `angr` and Capstone through the full analysis dependencies:

```bash
pip install 'ablation-tool[full]'
```

Install only in the environment used for offline analysis. Large CFG builds can be expensive; register only the versions needed and reuse one tracker so its CFG cache is shared.

## Track a function across releases

```python
from ablation.analyzers.version_delta import VersionTracker

tracker = VersionTracker(
    binaries={
        '1.0': '/path/to/firmware-v1.0.so',
        '1.1': '/path/to/firmware-v1.1.so',
        '1.2': '/path/to/firmware-v1.2.so',
    }
)

reports = tracker.track(
    seed_binary='1.0',
    seed_va=0x1000,
    seed_name='parse_request',
)

for report in reports:
    print(report.summary())
    if report.match is not None:
        match = report.match
        print(match.confidence, match.jaccard, match.semantic_score)
        print(match.delta.unified_diff(
            report.seed_binary,
            report.target_version,
        ))
        print('new callees:', match.new_callees)
        print('removed callees:', match.removed_callees)
```

The seed version is not included in the returned reports. Other versions appear in registration order. `skip_versions=['1.2']` excludes selected releases. If the seed function cannot be found, `track()` raises `ValueError`.

## Inspect patch evidence

`PatchDelta` contains:

| Field | Meaning |
|:---|:---|
| `added` | Normalized instructions added in the target. |
| `removed` | Normalized instructions removed from the seed. |
| `context` | Unchanged surrounding instructions. |
| `ratio` | `SequenceMatcher` similarity from 0.0 to 1.0. |
| `is_patched` | Whether any added or removed instructions exist. |

`callee_changed` on a `HomologMatch` reports whether external calls changed. These signals localize review; they do not determine whether the security issue is fixed. Recheck source control, reachability, validation, and sink behavior on the production target.

## Diff two disassembly snippets directly

`diff_functions()` does not require angr:

```python
from ablation.analyzers.version_delta import diff_functions

old_asm = [
    'mov rdx, rcx',
    'call memcpy',
]
new_asm = [
    'cmp rcx, 0x100',
    'ja error_path',
    'mov rdx, rcx',
    'call memcpy',
]

delta = diff_functions(
    old_asm,
    'parse_request_v1',
    new_asm,
    'parse_request_v2',
    callees_a=['memcpy'],
    callees_b=['memcpy'],
    version_a='1.0',
    version_b='1.1',
)

print(delta.unified_diff('1.0', '1.1'))
```

For a numeric mnemonic-sequence comparison, `jaccard_similarity(old_asm, new_asm)` returns the 4-gram Jaccard score.

## Port names cautiously

After manually confirming a homolog:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx_v2 = BinaryContext.load_or_build('/path/to/firmware-v1.1.so')
ctx_v2.set_name(match.va, 'parse_request', source='confirmed')
```

Do not port names automatically from low-confidence matches. Keep the matching evidence with the session record so later releases can reassess the correspondence.

## What this workflow adds

The tracker reduces a release comparison from “find the same bytes at a new address” to a sequence of reviewable evidence steps. Users can identify candidate homologs, inspect normalized changes and callee deltas, then carry a name forward only after confirming the correspondence. Snippet diffing remains available when a full CFG project is unnecessary.

This is a workflow composed of replaceable matching stages rather than a patch-correctness oracle. Better anchors or semantic models can improve ranking without changing the required final review. A changed instruction sequence shows where to look; it does not establish that a vulnerability was fixed, introduced, or remains reachable.

## Limitations

- Heavy optimization, inlining, function splitting, and refactoring can prevent a reliable match.
- Structural and semantic similarity does not establish vulnerability presence, absence, or exploitability.
- An instruction diff shows change, not intent. Added bounds checks may be incomplete or applied to a different value.
- Era anchors identify configured families only; an anchor miss is inconclusive, not evidence that a version is unrelated.
- Full tracking requires valid function recovery in every analyzed build. Incorrect CFG recovery propagates into matching results.

## See also

- [Sequence-Based Function Matching](../reference-modules/dtw-matrix-profile-similarity.md): DTW matching and localized matrix-profile differences.
- [Structural Function Matching](../reference-modules/structural.md): weighted structural fingerprints and structural-orphan discovery.
- [AI-Guided Analysis](../reference-modules/llm-analyst-loop.md): reviews two verified disassembly versions for a patch hypothesis.
