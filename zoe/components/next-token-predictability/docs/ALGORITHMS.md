# Unified algorithm catalog

Zoe exposes **17 mathematical operations** through one workbench. The [verification evidence](../evidence/workbench/verification.json) records **17/17 passing checks**. These checks exercise each operation against explicit expected results; they do not imply universal guarantees or validate every possible model.

## Forecasts and distributions

| Identifier | Purpose | Boundary |
|:---|:---|:---|
| `volume/strict@v1` | Strict accessible volume, normalized volume, and complement | Nicholas's original equation, created March 6, 2026. Measures breadth, not correctness. |
| `forecast/measure@v1` | Entropy, maximum probability, top-ten mass, optional log loss and Brier score | Different properties of a distribution remain distinct. |
| `volume/adaptive@v1` | Threshold based on a floor and fraction of maximum probability | Retained for comparison; selected rule transferred worse on held-out BioBERT cases. |
| `volume/joint@v1` | Multi-horizon continuation counts | Complete vectors give exact counts; restricted candidates give lower bounds only. |
| `volume/momentum@v1` | Change in accessible-volume count | Equal counts do not imply identical probabilities or set membership. |
| `distribution/temperature@v1` | Normalize probabilities raised to `1/T` | Reshapes a distribution without retraining or establishing creativity. |
| `sample/categorical@v1` | Seeded categorical sampling with generator identity | A sampled outcome is not evidence of correctness or authorization. |
| `process/markov-step@v1` | Apply one transition matrix step | Requires complete normalized state and transition vocabularies. |
| `process/continuation@v1` | Exact bounded Markov continuation enumeration | A defined toy, not a completed real-language-model benchmark. |

## Belief, geometry, and time

| Identifier | Purpose | Boundary |
|:---|:---|:---|
| `bayes/binary@v1` | Explicit binary Bayesian update with likelihood-ratio and log-odds history | Posterior is conditional on supplied likelihoods; dependent evidence needs adjustment. |
| `timing/rmse@v1` | Timing errors and root-mean-square error | Deterministic comparison of supplied onsets, not a probability distribution. |
| `geometry/procrustes@v1` | Similarity, rigid, or affine alignment and residuals | Landmark alignment does not establish whole-shape or semantic correctness. |
| `heuristic/inspection-priority@v1` | Rank investigations by value, expected information gain, and effort | A heuristic for attention, not a probability, reward, or authorization rule. |

## Causal repertoires

| Identifier | Purpose | Boundary |
|:---|:---|:---|
| `causal/repertoire@v1` | Normalize `K(x1|x0) μ(x0)` into an explicit causal posterior | Requires a causal model and intervention distribution; not inferred from a forecast. |
| `causal/q-arrow@v1` | Preserve effective information, volume change, and entering/exiting states | Proposed Accessible Q-Volume annotation. Does not replace Φ or γ. |
| `causal/two-way@v1` | Record accessible causal pasts and accessible forecast futures | Requires an explicitly supplied forecast and context; no automatic internal-state mapping. |

## Mirrored brain

`brain/mirror@v1` pairs forward and retrograde observations at the same index, then records:

- Accessible volume and complement for each direction.
- Forward-minus-retrograde volume difference.
- Whether the selected category agrees.
- Correctness, entropy, maximum probability, and negative log probability separately.
- A recommendation for the next inspection, with `executed=False`.

Both distributions are preserved. There is no implicit mixture, causal reversal, or consciousness score. The [full mirrored-pair test](../evidence/workbench/verification.json) covers **1,920 pairs**. The [GEM source](https://github.com/Ablation-Tool/graphics-environment-manager) retains the latest 128 paired observations and one lazy HELEN artifact.

## Run an operation

```bash
python -m gem workbench list
python -m gem workbench check --output workbench-verification.json

cat > baseline.json <<'JSON'
{"probabilities": [0.70, 0.20, 0.08, 0.02], "tau": 0.05}
JSON
python -m gem workbench run \
  volume/strict@v1 --input baseline.json --output baseline-result.json
```

Every output marks `executed=False`. Equations can also be registered through the existing Python API without `eval`. The mirrored operation uses stored categorical evidence; it does not require a transformer or model runtime.
