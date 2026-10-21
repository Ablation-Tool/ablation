# BwtEulerianReconstructor

Recover the full BWT text for IBM AIX installp entries where the standard LF-map traversal from `bwt_index` is incomplete due to multiple disjoint BWT cycles (K < 256 entries).

---

## Why this exists

IBM's installp multi-cycle BWT (K < 256) leaves part of the original text T_step4 unrecoverable when following the LF-map from the recorded `bwt_index`. For `automountd` (U828079.bff, K=56, n=199,196):

- 19 disjoint cycles; `bwt_index=794` lies in the main cycle (111,380 bytes)
- T_step4[0..87815] are unrecoverable by LF-map traversal alone

An Eulerian circuit on the K-node directed multigraph of the BWT last-column visits every row exactly once and produces a valid candidate ordering for the full text. The circuit is guaranteed to exist because every node (byte value) has equal in-degree and out-degree in the transition graph.

---

## Theory

```
L = bwt_last (last column of BWT matrix, length n)
F_byte[r] = sorted(L)[r]  ← F-column byte value (NOT the LF-map)

Directed multigraph:
  Nodes: byte values in {0..255} that appear in L
  Edges: (L[r], F_byte[r]) for each row r

Eulerian circuit on this graph visits every row exactly once
→ produces a valid candidate T_step4 ordering
```

---

## Usage

```python
from ablation.core.bwt_eulerian_reconstructor import BwtEulerianReconstructor, EdgePolicy

rec = BwtEulerianReconstructor(bwt_last_bytes, K=56)

# Try different edge selection policies
for policy in EdgePolicy:
    circuit = rec.reconstruct(policy)
    match_pct = rec.verify_against_known_segment(circuit, known_bwt_buf)
    print(f'{policy.value}: {match_pct:.1%} match with known segment')
```

---

## Edge selection policies

| Policy | Description |
|:---|:---|
| `GREEDY` | First available edge (adjacency list order) |
| `NON_MAIN_FIRST` | Prefer edges leaving non-main-cycle nodes |
| `BWT_INDEX_FIRST` | Start from the known `bwt_index` node before circuit build |

**Empirical results** (automountd K=56, n=199,196): GREEDY and NON_MAIN_FIRST both produce T_step4[87816]=0x6e ≠ bwt_buf[0]=0x01. IBM's exact cycle ordering requires `liblpp.a` and cannot be derived from BWT data alone.

---

## Limitations

**Produces A valid Eulerian circuit, not IBM's.** The IBM proprietary cycle ordering in `liblpp.a` is not derivable from the BWT data. This module explores the ordering space empirically; `verify_against_known_segment` reports alignment with any known partial segment.

**Requires numpy.** The multigraph and Hierholzer's algorithm implementation uses `numpy` for adjacency list representation.

---

## Pipeline position

**When to use:** Check if `AixInstallpDecompressor.decompress()` produces fewer bytes than `uncompressed_size`. If under-recovery, the entry has multiple BWT cycles — run this module to attempt full text recovery.

---

## See also

- [AIX Installp Decompressor](aix-installp-decompressor.md) — upstream; step 3 BWT inverse
- [AIX Installp Step4 Multilevel](aix-installp-step4-multilevel.md) — handles rare bytes with j ≥ K-1
