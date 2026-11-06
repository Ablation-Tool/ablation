# Zoe — living geometry, inspectable futures

Zoe unifies **GEM HELEN + MASTER GEM + BRAIN GEM** inside Ablation's native GEM host. HELEN supplies lightweight creative geometry and stored categorical predictions. next-token-predictability supplies research evidence and numerical conformance. Ablation supplies native GTK, Spatial IR, Lab integration, VDI replay, and evidence export. BRAIN is the deterministic observation and recommendation layer; it is not a consciousness claim or an autonomous agent.

![Zoe native BRAIN after a real HELEN observation](images/zoe-brain.png)

## Launch

From the Ablation source checkout:

```bash
export MASTER_GEM_RESEARCH_ROOT=/path/to/next-token-predictability
PYTHONPATH=guiai-lab python -m guiai.gem zoe
```

`gem master` and `gem brain` are equivalent aliases. In GUIAI Lab, use **Chart → GEM → Zoe / MASTER GEM**. The existing `gem-helen` launcher remains the lightweight standalone creative mode.

## Functional modules

- **BRAIN:** observe HELEN's actual stored forward or retrograde distributions by index or in sequence. Zoe computes top-1 correctness when a target exists, negative log probability, entropy, maximum probability, strict accessible volume, complement, and accessible momentum. The recommendation identifies the next module to inspect; it never executes an action.
- **Field notebook:** organize questions, competing binary claims, explicit Bayesian evidence updates, deterministic and stochastic chambers, next-test priorities, and decisions in one append-only hash-chained memory. BRAIN observations are preserved without automatically changing belief. The equation registry includes strict, normalized, adaptive, joint, momentum, temperature, Markov, timing, geometry, and categorical-sampling sections; custom equations can be registered without `eval`.

![Zoe Bayesian field notebook](images/zoe-field-notebook.png)

- **Cognitive Field:** encode sourced observations into bounded FIFO working memory, explicitly store active representations, retrieve them with provenance and revision checks, match declared procedural tags, and prepare review-required performance proposals. No rule is executable code and no measurement updates a posterior automatically. Open **Zoe · Cognitive Field** in the native module selector or run `PYTHONPATH=guiai-lab python -m guiai.gem cognitive --output cognitive-field.png`. See the [instrument guide](COGNITIVE.md).

![Zoe Cognitive Field](images/zoe-cognitive-field.png)

<details>
<summary>Five Zoe mechanisms in pictures</summary>

1. **Epistemic firewall:** measurement, evidence, belief updates, and action remain distinct.
   ![Zoe epistemic firewall](images/zoe-visuals/01-epistemic-firewall.png)
   [SVG](images/zoe-visuals/01-epistemic-firewall.svg)

2. **Belief diff:** priors become posteriors only through explicit evidence, with every likelihood and source retained.
   ![Zoe belief diff](images/zoe-visuals/02-belief-diff.png)
   [SVG](images/zoe-visuals/02-belief-diff.svg)

3. **Deterministic and stochastic chambers:** reproducible measurements and seeded forecasts have distinct identities and lifecycles.
   ![Zoe deterministic and stochastic chambers](images/zoe-visuals/03-chambers.png)
   [SVG](images/zoe-visuals/03-chambers.svg)

4. **Append-only memory:** sequence-linked hashes support replay and tamper detection without claiming authentication.
   ![Zoe append-only memory](images/zoe-visuals/04-memory-chain.png)
   [SVG](images/zoe-visuals/04-memory-chain.svg)

5. **Next useful test:** decision support ranks attention while human review controls execution.
   ![Zoe next useful test](images/zoe-visuals/05-next-test.png)
   [SVG](images/zoe-visuals/05-next-test.svg)

</details>

- **Geometry:** drag or keyboard-move landmarks and evaluate similarity, rigid, or affine alignment. Ellipse, parabola, circle, clock, and graph modules remain available.
- **Forecast:** inspect complete categorical distributions, thresholds, complements, observations, momentum, and target bands.
- **Onset:** run the original seeded synthetic experiment and compare forward and retrograde metrics.
- **Multi-Horizon:** enumerate every continuation of a defined two-state Markov toy and count those above a joint-probability threshold. This is exact toy evidence, not a real language-model benchmark. Full-vocabulary enumeration grows as \(|O|^h\).
- **Research:** inspect hash-checked Groove and Nightingale reports. Individual Groove distributions load on demand from the 98 MB NPZ only when requested. Nightingale entries are explicitly aggregate-only.
- **Qualia:** explore five visual lenses for Balduzzi & Tononi's 2009 IIT geometry and the proposed Accessible Q-Volume annotation. The [Zoetic field guide](QUALIA.md) separates philosophical qualia, IIT's theoretical constructs, and Zoe's actual software behavior. `gem qualia --output accessible-q-volume.json` checks and saves the two-way toy. This is not a general IIT calculator or a consciousness measurement.

![Zoe's five-panel qualia field guide](images/zoe-qualia.png)

Every module exports the current Spatial IR scene as SVG, PNG, or real little-endian GEM VDI. BRAIN exports also advance the evidence-export state without changing `executed=False`.

## Headless export

GTK is not required for SVG or GEM VDI export:

```bash
PYTHONPATH=guiai-lab python -m guiai.gem zoe --module brain --output zoe.svg
PYTHONPATH=guiai-lab python -m guiai.gem zoe --module field --output field.svg
PYTHONPATH=guiai-lab python -m guiai.gem zoe --module horizon --output horizon.gem
PYTHONPATH=guiai-lab python -m guiai.gem notebook --output field-memory.json
PYTHONPATH=guiai-lab python -m guiai.gem notebook field-memory.json --output field-memory.svg
PYTHONPATH=guiai-lab python -m guiai.gem zoe \
  --module research --research-root /path/to/next-token-predictability \
  --output research.svg
```

PNG requires the existing Cairo backend. The research module uses the repository's `evidence/master-gem/conformance.json` contract and verifies report and source hashes before exposing evidence. The full Groove NPZ hash is checked before its first observation is loaded.

## HELEN artifact

`guiai/gem/data/onset-seed7.json.gz` is the 12 KB compressed HELEN artifact. It contains 1,920 held-out predictions per condition and loads lazily using the Python standard library. Its SHA-256 is:

```text
e94671b50c4063900ee248559677402af602839edc1349bda70eb16514de8da9
```

Normal BRAIN use does not import a transformer, tokenizer, model runtime, scikit-learn, or KMeans. Recomputing the original Onset experiment remains a separate optional operation with its documented dependencies.

## Evidence boundaries

- Accessible volume measures forecast breadth, not correctness, safety, or human surprise.
- Synthetic HELEN evidence is not real musical performance. Groove and Nightingale have their own distinct real-MIDI results and preprocessing scopes.
- Backward-matched Groove evaluation is distinct from direct reversal transfer.
- HOP and deterministic extrapolation supply no categorical accessible-volume measurement; HOP remains a rejected baseline.
- Multi-horizon toy enumeration is not a real language-model benchmark. Bounded approximations require their own error analysis.
- Recommendations are not automatic actions. The user decides what to inspect or execute.
- Field-notebook posteriors are conditional on user-supplied priors and likelihoods; they are not objective truth scores. Dependent evidence requires an explicit acknowledgment and adjusted likelihoods.
- Chamber measurements and sampled outcomes never update claims automatically. Quarantined chambers remain inspectable but cannot run.
- The notebook hash chain provides tamper evidence, not authentication. Large probability vectors are represented by hashes rather than embedded in memory.
- The Cognitive Field is a bounded software memory instrument, not ACT-R or a consciousness model. Storage, retrieval, matching, and review-required performance are explicit operations; no rule or measurement authorizes execution. Its JSON and visual exports never overwrite existing files.
- Zoe's name and "living" tagline are creative metaphors, not claims of sentience. The Qualia guide's references to life, consciousness, and redness are artistic or philosophical context, not measurements of Zoe.
- The Qualia module computes the documented COPY, silent-AND, and Accessible Q-Volume toy comparisons. The complete continuous filtration has an exact reconstruction identity; finite sweeps remain approximate. It does not search minimum partitions, calculate general Φ or γ, infer causal repertoires from forecasts, map a brain, or update notebook beliefs.

## Implementation map

```text
guiai/gem/brain.py         Observation state, recommendations, exact continuations
guiai/gem/field.py         Bayesian memory, chamber registry, equations, notebook scene
guiai/gem/cognitive.py     Bounded memory operations, Cognitive Field scene, safe exports
guiai/gem/qualia.py        Five-lens IIT guide, causal threshold filtrations, and two-way toy
guiai/gem/helen_onset.py   Lazy HELEN artifact and temperature transforms
guiai/gem/research.py      Hash-checked research evidence and conformance
guiai/gem/atlas.py         Module registry and headless scene builders
guiai/gem/atlas_view.py    Native GTK controls and host integration
guiai/gem/cli.py           gem zoe / gem master / gem brain / gem atlas / gem notebook / gem cognitive
guiai/gem/data/            Packaged HELEN prediction artifact
stress/zoe_stress.py       Core, evidence, CLI, and native integration tests
stress/cognitive_stress.py Cognitive Field core, exports, and native workflow tests
```

## Verification

From the Ablation source root, with the research dependencies configured:

```bash
PYTHONPATH=guiai-lab:/home/cowboy/security-tools/lib/python3.14/site-packages \
  python guiai-lab/stress/zoe_stress.py

PYTHONPATH=guiai-lab:/home/cowboy/security-tools/lib/python3.14/site-packages \
  guiai-lab/stress/nested_x11.sh \
  python guiai-lab/stress/zoe_stress.py

PYTHONPATH=guiai-lab:/home/cowboy/security-tools/lib/python3.14/site-packages \
  guiai-lab/stress/nested_x11.sh \
  python guiai-lab/stress/gem_stress.py
```

The integration suite covers sequential HELEN observations, real Groove loading, all 17 research conformance checks, exact continuation counts, Bayesian belief diffs, dependent-evidence guards, deterministic and stochastic chambers, quarantine enforcement, memory roundtrips and tamper detection, notebook JSON/SVG/VDI exports, native question/claim/evidence workflows, and the GUIAI host launch. Qualia coverage includes all six lens choices, causal-repertoire normalization, both threshold crossings, entering and exiting states, strict equality, coarse and fine labeled sweeps, custom threshold pairs, two-way JSON evidence, installed-package execution, and unchanged notebook observations. The broader GUIAI stress suite also contains unrelated investigation-CLI and saved-layout checks; those are separate from Zoe's focused integration results.
