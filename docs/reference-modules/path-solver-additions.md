# PathSolver: chain_depth_weight

## Why this addition exists

Two gaps motivated this addition:

1. Finding lists returned by a sweep produced a flat severity ordering. Two co-located MEDIUM findings on the same function were not distinguished from two MEDIUM findings in unrelated functions, even though the co-located case is a stronger exploitation signal.
2. Deep call-graph paths inflate the apparent risk of a finding by appearing connected to many callers. A depth penalty corrects for this by reducing priority as path length grows past three hops.

## chain_depth_weight

Computes a float priority weight for a list of co-occurring findings. Higher weight means higher combined priority.

```python
from modules.path_solver import chain_depth_weight

# Three MEDIUM findings co-located on the same function at call depth 2
weight = chain_depth_weight(findings, path_length=2)

# Compare findings from different functions
weight_a = chain_depth_weight(func_a_findings, path_length=1)
weight_b = chain_depth_weight(func_b_findings, path_length=5)
# Prioritize by weight_a > weight_b
```

## Formula

```
base         = sum of per-severity scores for all findings
               CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0.5

chain_bonus  = 0.5 * max(0, len(findings) - 1)

depth_penalty = 0               for path_length <= 3
              = 0.5 * (path_length - 3)  for path_length > 3

weight = max(0.0, base + chain_bonus - depth_penalty)
```

## Examples

| Findings | path_length | weight |
| -------- | ----------- | ------ |
| 1x HIGH | 0 | 3.0 |
| 3x MEDIUM | 0 | 7.0 |
| 3x MEDIUM | 5 | 6.0 |
| 1x CRITICAL + 1x HIGH | 2 | 8.5 |

## Inputs

`findings`: list of objects or dicts with a `severity` attribute or key. Unknown severity values are treated as LOW.

`path_length`: number of call-graph hops from the entry point. Pass 0 if the path length is unknown.

## Severity and triage

Use `chain_depth_weight()` to rank candidate functions returned by `SemanticSearcher` or `PatternLibrary.sweep()`. Do not use the weight as a severity score. It is a triage ordering signal only.
