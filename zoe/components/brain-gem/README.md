# BRAIN GEM

BRAIN GEM is a standalone Bayesian field notebook and chambered-memory engine. It organizes questions, competing claims, explicit evidence updates, deterministic and stochastic chambers, and next-test decisions in one inspectable, append-only history.

The core epistemic boundary is:

```text
measurement ≠ evidence ≠ belief update ≠ action
```

## What works

- Questions with optional context and multiple independent binary claims.
- Priors, current posteriors, falsifiers, and lifecycle statuses.
- Bayesian updates through user-supplied `P(evidence | claim)` and `P(evidence | not claim)`.
- Belief diffs with previous posterior, new posterior, likelihood ratio, log likelihood ratio, prior and posterior log-odds, and evidence source.
- Evidence families that block repeated updates by default. Dependent evidence requires explicit acknowledgment and adjusted likelihoods.
- Deterministic chambers for reproducible measurements and stochastic chambers for forecasts, transitions, transforms, and seeded sampling.
- Active, experimental, rejected, and quarantined chamber states. Rejected methods remain inspectable; quarantined chambers cannot run.
- A replaceable equation registry with 13 sections and custom Python registration without `eval`.
- Exact joint counts and explicitly labeled lower bounds for restricted candidate sets.
- Append-only canonical-JSON SHA-256 event chains with sequence numbers and previous-event hashes.
- Complete load-time verification, including edited or reordered event detection.
- Human-readable JSON saved without overwriting existing files.
- Complete small probability vectors and length/SHA-256 digests for vectors longer than 64 values.
- Next-test ranking through decision value, expected information gain, and effort. Decisions remain review-required and `executed=False`.

Posteriors are conditional on the supplied likelihood model. They are not objective truth scores. The hash chain supplies tamper evidence, not authentication.

## Install and launch

Requires Python 3.10 or newer. Basic notebook and scene export have no mandatory dependencies.

```bash
python -m pip install /path/to/brain-gem
brain-gem field
```

The native field notebook requires GTK3 and Cairo. Headless SVG and GEM VDI export work without GTK:

```bash
brain-gem field --output field.svg
brain-gem notebook --output field-memory.json
brain-gem notebook field-memory.json --output field-memory.svg
```

`zoe`, `master`, `brain`, and `atlas` are accepted aliases for the native field launcher.

## Initial equation sections

1. Binary Bayesian posterior updates
2. Strict accessible volume, normalized volume, and complements
3. Forecast measurement with entropy, maximum probability, top-ten mass, optional log loss, and Brier score
4. Adaptive accessible-volume thresholds, labeled with the held-out negative-transfer result
5. Multi-horizon joint accessible volume
6. Accessible momentum
7. Temperature transformations
8. Seeded categorical sampling with generator identification
9. Markov-chain state transitions
10. Exact bounded Markov continuation enumeration
11. Timing errors and RMSE
12. Similarity, rigid, and affine Procrustes alignment
13. Inspection prioritization using decision value, expected information gain, and effort

Restricted joint candidate sets are explicitly reported as lower bounds with missing probability mass. They are not mislabeled as exact counts.

## Native controls

The field module supports loading the worked GEM example or an empty notebook, adding questions, adding competing claims and falsifiers, applying explicit Bayesian updates, adjusting thresholds and random seeds, running deterministic measurements and stochastic samples, saving and reloading memory, and exporting SVG, PNG, and GEM VDI scenes.

The worked example uses DEMOMENU evidence from the 1986 *Programmer's Guide to GEM*. It demonstrates supporting evidence, counterevidence, posterior history, chamber state, and next-test selection.

## Development and verification

```bash
python -m unittest discover -s tests -v
```

The test suite covers Bayesian arithmetic and belief histories, dependent-evidence barriers, deterministic/stochastic separation, seeded samples, quarantine enforcement, exact and restricted joint counts, large-vector digests, memory roundtrips and tamper detection, native question/claim/evidence workflows, JSON/SVG/GEM VDI exports, and existing HELEN, Groove, Nightingale, and Zoe conformance behavior.

The `brain_gem` package includes HELEN's compressed seed-7 artifact for 1,920 stored predictions per condition. Groove and Nightingale evidence can be loaded from an optional next-token-predictability checkout through `--research-root` or `MASTER_GEM_RESEARCH_ROOT`.

## Boundaries

- Likelihoods are explicit user assessments, not learned calibration.
- Measurements and sampled outcomes never update posteriors automatically.
- MASTER GEM observations can be preserved without becoming evidence for a claim.
- No autonomous agent, external execution, synchronization, encryption, or multi-user collaboration is implemented.
- Custom next tests and decisions currently use the Python API rather than dedicated native controls.
- Global novelty is not claimed; the novelty is the particular architecture and combination of capabilities.
- No stability or consciousness claim is made for Zoe, its users, or its forecasts.
