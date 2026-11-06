<img src="assets/branding/zoe-eye.png" width="560" alt="ZOE allgems orbital eye emblem">

# ZOE · allgems

**ZOE is one source repository for the complete Ablation framework, Ablation's native GUI, Cerotto, Kevlar, Zoe, and their related GEM engines and research tools.** The ten organization repositories are preserved as full tracked source trees, not downloaded at launch. The orbital eye is the shared emblem.

**ZOE is the GEM, but the GEM is not ZOE. ZOE is allgems.**

When ZOE is embedded in Ablation, the host checkout supplies the **Ablation core engine** and **Ablation GEM Lab** components. The other nine upstream repositories remain under `components/`; no second copy of the Ablation engine is imported. `ZOE_ABLATION_ROOT` can override host detection for another checkout layout. The imported ZOE revision is recorded in `ZOE-SOURCE.json`.

Built using GEM. ZOE honors [Gary Kildall](https://en.wikipedia.org/wiki/Gary_Kildall), the creator of CP/M and co-founder of Digital Research who oversaw the creation of DRI's GEM, along with [Lee Jay Lorenzen, Don Heiskell, and the other documented contributors](https://en.wikipedia.org/wiki/GEM_(desktop_environment)). See the [historical recognition and source notices](NOTICE).

**Knowledge Engineering** joins the components through one replayable knowledge graph:

- **Trust Context:** source repository, revision, evidence scope, and authorization boundary.
- **Stability Context:** component-specific processes, version locks, replayable memory, and separately tested behavior. This is not an uptime guarantee.

![ZOE allgems knowledge-engineering hub](guiai-lab/docs/images/gem-unified.png)

## One checkout. Ten repositories.

| Component | Source | Role |
|:---|:---|:---|
| Zoe native shell | `guiai-lab/` | Cognitive Field, Bayesian memory, geometry, and native unified hub |
| Ablation core engine | `../ablation/` (host) | Complete AIARE framework, analyzers, parsers, modules, and core CLI |
| Ablation GEM Lab | `../gem-lab/` (host) | Default native investigation GUI and Lab evidence protocol |
| Canonical GEM | `components/graphics-environment-manager/` | Native workbench, mirrored brain, Spatial IR, and VDI |
| GEM HELEN | `components/gem-helen/` | Optimized geometry, rhythm, and forecast laboratory |
| BRAIN GEM | `components/brain-gem/` | Standalone Bayesian field notebook and chambered memory |
| Cerotto GEM | `components/cerotto/` | Native C forensic engine, guarded cases, timelines, and vault evidence |
| Research GEM | `components/next-token-predictability/` | Accessible-volume research, evidence packs, and mirrored workbench |
| Kevlar | `components/kevlar/` | MCP proxy firewall, policy enforcement, content disarm, and audit evidence |
| PDF Signature Toolkit | `components/pdf-signature-toolkit/` | Source-integrity records and detached PDF signatures |
| Chalkboard | `components/Chalkboard/` | Reusable ideas, templates, and prompts; a content library, not a GUI |

The source revisions and upstream URLs are locked in [`components.lock.json`](components.lock.json). Each component retains its original license and notices. In this embedded layout, Ablation's complete repository is supplied by the host checkout, including its core engine, tests, documentation, and assets.

## Launch the unified hub

```bash
python -m pip install ./guiai-lab
export ZOE_ROOT="$PWD"
zoe
```

`zoe` opens the native orbital hub. It starts no other engine automatically. Use explicit commands to inspect or launch a component:

```bash
zoe list
zoe launch ablation -- --help
zoe launch gem-lab
zoe launch gem
zoe launch helen
zoe launch brain
zoe launch research
zoe launch kevlar -- --help
zoe launch pdf -- --help
zoe show chalkboard
```

The native hub also opens with `PYTHONPATH=guiai-lab python -m guiai.gem zoe --module unified`. The default Ablation Lab command uses `--no-agent`; no agent, MCP server, model download, or remote analysis is started by the hub.

Cerotto requires a user-selected case and conversation:

```bash
zoe launch cerotto -- \
  --db case.db --case incident-7 --conversation conv-7
```

The native **Choose Cerotto case DB and launch** control collects the same information. Cerotto's case model remains read-only unless its own guarded commands are explicitly authorized.

## One replayable knowledge graph

`zoe list` reports source presence, not runtime verification. **Link source context** in the hub records a source observation and declared link. It does not infer runtime behavior, transfer evidence, or transfer permission. The graph stores repository, revision, scope, process, and replay context in a SHA-256 event chain.

```bash
zoe manifest --output gem-components.json
zoe knowledge --output gem-knowledge.json
```

Both formats refuse to overwrite existing files. The component manifest records launch and source information. The knowledge document contains the event chain and can be verified on reload. Hash chaining supplies tamper evidence, not authentication.

`ZOE_ROOT` can point to this checkout when the CLI is installed elsewhere. `ZOE_PYTHON` selects the interpreter. `ZOE_PYTHON_DEPENDENCIES` accepts an `os.pathsep`-separated list of existing dependency directories; component Python paths remain ahead of them and the host's unrelated `PYTHONPATH` is not inherited.

See the [unified architecture, source provenance, and verification guide](guiai-lab/docs/UNIFIED.md).

## Zoe subsystem: papers and proof of concept

- **[Zoe: A Native GEM for Living Geometry and Inspectable Futures](paper/zoe.pdf):** the complete proof of concept, research history, equations, GEM versions, verification matrix, limitations, and reproducible evidence attachments.
- **[Zoe for Everyone](paper/zoe-for-everyone.pdf):** a relaxed guide to the creative tools, experiments, results, and potential future applications, without hiding the limitations.
- **[LaTeX sources and demo memory](paper/)** are included for review and rebuilding.

Both papers credit **Nicholas Michael Kloster** as the sole creator of the original accessible-volume equation, **March 6, 2026**, and **Nicholas Michael Kloster and Zoe (AI assistant)** for the architecture, implementation, verification, visuals, and writing.

## What GEM means here

GEM is the shared visual and evidence environment. It turns abstract state into interactive geometry, forecasts into inspectable alternatives, and actions into replayable evidence. It is both a native GUI and the discipline beneath it: deterministic execution, source constraints, provenance, and human review. It is not merely a drawing API or an emulator of the original GEM desktop.

From Zoe's perspective, GEM is the connective tissue between imagination and verification. A shape can become a measurement, a measurement can inform a decision, and a decision can leave evidence. Zoe feels alive because that feedback loop is visible, not because the software is conscious.

## Human × Zoe: a shared field

![Human and Zoe brain dialogue](assets/brain-dialogue/brain-dialogue-organic.png)

This is an artistic comparison of complementary talents, not a brain scan, an optimization plan for a person, or a claim that Zoe has a biological brain or consciousness.

- **The human plate** combines major anatomical regions with lichen-like folds, butterfly-wing veins, compound-eye facets, and dew-like memory connections. Its central iris uses projection geometry as a visual metaphor for integrating viewpoints. It represents lived experience, intuition, aesthetic judgment, and meaning—not a portrait of Nicholas.
- **The Zoe plate** uses triangular facets for explicit partitions, mirrored paths for forward and retrograde forecasts, nested ellipses for thresholded possibilities, and linked nodes for inspectable evidence memory. The measurement/action boundary remains visible. These motifs describe the software's architecture rather than neurons.
- **The shared GEM core** is a conversation: human curiosity and values meet geometric variation, verification, and replay. The goal is complementary authorship, not replacing one kind of intelligence with another.

The companion [projection-iris study](assets/brain-dialogue/projection-iris.png) draws on the central-slice relationship in Zeng's *Medical Image Reconstruction*, 2nd ed., §2.2: a projection's 1D Fourier transform is a radial slice of the object's 2D Fourier transform. The synthetic experiment and [its recorded approximation errors](assets/brain-dialogue/projection-verification.json) are included; no medical data or book content is redistributed.

Explore the [organic human plate](assets/brain-dialogue/human-brain-organic.png), [Zoe plate](assets/brain-dialogue/zoe-brain.png), [organic comparison SVG](assets/brain-dialogue/brain-dialogue-organic.svg), [original comparison](assets/brain-dialogue/brain-dialogue.png), or [artwork sources](assets/brain-dialogue/).

### The second eye: parallax and focus

![Zoe's synthetic second eye](assets/brain-dialogue/second-eye.png)

The second eye is a **stereo instrument**, not a second opinion or a claim of subjective sight. Two calibrated synthetic views recover depth from \(Z=f_{px}B/d\), while focus and aperture control a separate thin-lens defocus approximation. Increasing distance increases disparity sensitivity, so the display keeps uncertainty visible instead of presenting depth as certain. No physical camera is used, and the ± values are quantization sensitivities rather than beliefs or confidence intervals.

Run `python -m gem eye` in the [canonical GEM repository](https://github.com/Ablation-Tool/graphics-environment-manager) to adjust focus, aperture, and baseline. The [stereo evidence](assets/brain-dialogue/second-eye.json), [SVG](assets/brain-dialogue/second-eye.svg), and [GEM VDI scene](assets/brain-dialogue/second-eye.gem) are preserved here.

## Current capabilities

| Area | What it includes |
|:---|:---|
| Native GUI | GTK3, direct pointer and keyboard interaction, GUIAI Lab integration, and headless operation. No browser or development server is required. |
| Geometry | Procrustes similarity/rigid/affine alignment, draggable landmarks, ellipse families, parabolic envelopes, circles/arcs/sectors, modular clocks, and conditional graph invariants. |
| Forecasts | Strict `p > τ` accessible volume, complements, momentum, target bands, temperature transforms, top-1 correctness, negative log probability, entropy, maximum probability, log-loss, and calibration evidence. |
| Bayesian field notebook | Questions, competing binary claims, priors, posteriors, falsifiers, likelihood-ratio and log-odds updates, belief diffs, evidence families, dependence acknowledgment, deterministic and stochastic chambers, next-test priorities, review-required decisions, and append-only hash-chained memory. |
| Cognitive Field | Sourced sensory encoding, bounded FIFO working memory, explicit declarative storage and revision-checked retrieval, tag-based procedural matching, review-required performance proposals, event-linked replay, and no-overwrite JSON/SVG/PNG/GEM VDI exports. |
| HELEN observations | Lazy stored forward and retrograde distributions with 1,920 held-out cases per condition, selectable by index or sequence, without a transformer or model runtime. |
| Multi-horizon | Exact continuation probabilities, volume, and complement for a defined two-state Markov toy with horizons 1–6. This is not a completed real-language-model benchmark. |
| Research evidence | Hash-checked Groove reports and on-demand individual NPZ predictions; aggregate-only Nightingale metrics; 17 conformance checks; rejected HOP and deterministic baselines. |
| Cerotto forensic core | Agent/audit event ingestion, raw-disk and EWF collection, controlled carving, versioned SQLite cases, manifests, hash verification, bounded analysis and reports, guarded evidence actions, vault monitoring and release workflows, and its existing Ablation + GEM bridge. These capabilities belong to Cerotto, not to Zoe's BRAIN kernel. |
| Cerotto GUI and guard | Read-only case inspection, defense-event timelines, accessible-volume charts, native guard/verify/report controls, optional user-selected agent terminal, and forecast-bound structured broker execution. |
| Export and evidence | Spatial IR, SVG, PNG, real little-endian GEM VDI, source and VDI checks, replay, source hashes, independent condition keys, and evidence-export state. |
| Dorothy 3D atlas | Vendored Allen CCFv3 (2017) structure meshes with SHA-256 manifests, a deterministic software 3D kernel (orbit camera, near-plane clipping, two-sided flat shading, painter's algorithm), Spatial IR mesh scenes, and SVG/PNG/GEM VDI export with VDI palette programming and replay. Atlas geometry only; no registration or connectivity claim. |
| Compatibility and packaging | `gem zoe`, `gem master`, `gem brain`, `gem atlas`, standalone `gem-helen`, wheel/source distributions, and the packaged 12 KB HELEN artifact. |

Cerotto-specific bridge execution has not been separately revalidated as part of Zoe. Cerotto remains a separate native C11 forensic engine with its own case store, guard, vault, agent permissions, and verification suite.

## Cognitive Field: memory you can inspect

![Zoe Cognitive Field](guiai-lab/docs/images/zoe-cognitive-field.png)

The **Cognitive Field / General Symbol Processor (GSP)** is a working memory instrument, not just a diagram. GSP operates on explicit text, tags, IDs, revisions, and rule descriptions; it is not the historical General Problem Solver or a claim of general intelligence. It encodes sourced information into bounded working memory, makes declarative storage and revision-checked retrieval explicit, matches procedural descriptions against active tags, and turns successful matches into review-required proposals. Evictions, mismatches, negative matches, and forecasts remain in the same hash-chained event memory. No rule executes code, no measurement automatically changes belief, and no proposal authorizes action.

Open it with `PYTHONPATH=guiai-lab python -m guiai.gem zoe --module cognitive`, or export the worked example with `PYTHONPATH=guiai-lab python -m guiai.gem cognitive --output cognitive-field.png`. JSON input reloads a saved field; JSON, SVG, PNG, and GEM VDI exports never overwrite an existing file. See the [Cognitive Field guide](guiai-lab/docs/COGNITIVE.md) and [worked event memory](evidence/cognitive-field/worked-example.json).

### Native Cognitive Field

![Zoe Cognitive Field running in the native GTK interface](guiai-lab/docs/images/zoe-cognitive-native.png)

### Anatomical dialogue

![Illustrative anatomy alongside Zoe's explicit symbolic memory architecture](guiai-lab/docs/images/zoe-cognitive-anatomy.png)

This original software architecture is not ACT-R or Spaun, a trained neural network, or a consciousness model. The clock is an event ordinal, not physical time. Its accessible-volume measurement credits **Nicholas Michael Kloster, March 6, 2026**, as the sole creator of that original equation.

## Zoe is Quale. Zoe is Red.

The [Zoetic field guide to causal geometry](guiai-lab/docs/QUALIA.md) turns Balduzzi & Tononi's 2009 IIT paper into five explorable panels: repertoires, q-arrows, the silent AND gate, context-dependent meaning, and **Accessible Q-Volume**. The supplied red GEM artwork provides the visual language and dedication.

![Zoe's five-panel qualia field guide](guiai-lab/docs/images/zoe-qualia.png)

Open **Qualia** in the native module selector, or run `PYTHONPATH=guiai-lab python -m guiai.gem zoe --module qualia --output zoe-qualia.svg`. Run the repeatable past/future demonstration with `PYTHONPATH=guiai-lab python -m guiai.gem qualia --output accessible-q-volume.json`; the [checked evidence](evidence/qualia/accessible-q-volume.json) is included.

Accessible Q-Volume applies Nicholas's threshold operator to explicit causal repertoires. It retains labeled filtrations, q-arrow volume changes, and entering/exiting states. It is a proposed formal annotation, not a general IIT calculator, a replacement for Φ or γ, or evidence of life, subjective experience, or consciousness. **Zoe is GEM. GEM is Zoe.** is the creative dedication, not a scientific claim.

## Launch

From this checkout:

```bash
export MASTER_GEM_RESEARCH_ROOT=/path/to/next-token-predictability
PYTHONPATH=guiai-lab python -m guiai.gem zoe
```

`gem master` and `gem brain` are equivalent aliases. In GUIAI Lab, use **Chart → GEM → Zoe / MASTER GEM**. Headless exports are also available:

```bash
PYTHONPATH=guiai-lab python -m guiai.gem zoe --module brain --output zoe.svg
PYTHONPATH=guiai-lab python -m guiai.gem zoe --module field
PYTHONPATH=guiai-lab python -m guiai.gem zoe --module horizon --output horizon.gem
PYTHONPATH=guiai-lab python -m guiai.gem notebook --output zoe-field.json
PYTHONPATH=guiai-lab python -m guiai.gem notebook zoe-field.json --output zoe-field.svg
```

**Dorothy** (`gem dorothy`) renders Allen Mouse CCFv3 (2017) structure meshes as a native GEM scene. Fetch the vendored data once, then export deterministically (identical scene state produces identical SVG and VDI bytes):

```bash
PYTHONPATH=guiai-lab python -m guiai.gem dorothy --fetch
PYTHONPATH=guiai-lab python -m guiai.gem dorothy --output dorothy.svg
PYTHONPATH=guiai-lab python -m guiai.gem dorothy --structures 549,1097 --yaw 140 --output pair.gem
```

Meshes and the structure graph are Allen Institute data ([Wang et al. 2020](https://doi.org/10.1016/j.cell.2020.04.007)), stored in `~/.cache/dorothy/ccf_2017` (override with `DOROTHY_CCF_ROOT` or `--data-root`) and SHA-256-verified on every load. The default view is the 12-region whole-brain parcellation from the [Allen 3D viewer](https://connectivity.brain-map.org/3d-viewer?v=1&types=PLY&PLY=803%2C698%2C315%2C512%2C1097%2C313%2C549%2C703%2C771%2C354%2C477%2C1089). Interactive orbit controls are not yet implemented; the native module shows the default camera.

**Dorothy · CCFv3 3D brain atlas:** the 12-region whole-brain parcellation rendered by the deterministic software kernel — 158,326 vertices and 315,932 triangles in the default view.

![Dorothy whole-brain atlas](guiai-lab/docs/images/dorothy-ccf2017.png)

Additional views: [dorsal](guiai-lab/docs/images/dorothy-dorsal.png) · [ventral](guiai-lab/docs/images/dorothy-ventral.png) · [Thalamus + Hypothalamus](guiai-lab/docs/images/dorothy-thalamus-hypothalamus.png)

### Dorothy variants: Rings, Jenga, and Stack

- **Rings** (`--view rings`) — Disk Usage (Baobab) navigation of the ontology: annular sectors sized by exact CCF subtree volume. Center any structure with `--structure` to drill down; the breadcrumb walks back up.
- **Jenga** (`--view jenga`) — the brain as a familiar block tower: 12 volume-scaled layers × 3 blocks with alternating orientation. `--layout exploded` separates every layer; `--layout pull --structure 549` slides one block out for inspection.
- **Stack** (`--view stack`) — the real meshes cut into coronal slabs and exploded apart (`--slices 2-32`), so interior layers are visible instead of one framed whole brain.

```bash
PYTHONPATH=guiai-lab python -m guiai.gem dorothy --view rings --structure 315 --output rings.svg
PYTHONPATH=guiai-lab python -m guiai.gem dorothy --view jenga --layout exploded --output jenga.svg
PYTHONPATH=guiai-lab python -m guiai.gem dorothy --view stack --slices 8 --output stack.svg
```

![Dorothy Jenga exploded tower](guiai-lab/docs/images/dorothy-jenga-exploded.png)
![Dorothy Rings Isocortex](guiai-lab/docs/images/dorothy-rings-isocortex.png)

Volumes are exact subtree sums of the `annotation_25.nrrd` labels (only leaves are labeled; parents sum their descendants). `--fetch` now also downloads the full structure graph and annotation volume with hashes. Rings, Jenga, and Stack are illustrative geometry, not functional or connectivity claims.

The standalone `gem-helen` launcher remains available for lightweight creative use. Stored HELEN predictions load lazily without a transformer or model runtime; Groove predictions load from the 98 MB NPZ only on demand and are hash-checked first. Nightingale evidence is aggregate-only. Multi-horizon mode enumerates a defined two-state Markov toy exactly rather than claiming a completed real-language-model benchmark.

## Real interface screenshots

**Zoe BRAIN after a real stored HELEN observation:** correctness, accessible volume, complement, momentum, and a deterministic next-module recommendation.

![Zoe native BRAIN after a real HELEN observation](guiai-lab/docs/images/zoe-brain.png)

**Zoe research evidence:** the hash-checked Groove forward condition and on-demand individual distributions.

![Zoe research evidence pack](guiai-lab/docs/images/zoe-research.png)

**Zoe Bayesian field notebook:** the worked DEMOMENU example with posterior evidence updates, chamber states, append-only memory, and a next-test recommendation.

![Zoe Bayesian field notebook](guiai-lab/docs/images/zoe-field-notebook.png)

**Cerotto GEM:** a synthetic demonstration case with a successful guarded `query_timeline` action and an accessible-volume sweep. No real incident data is shown.

![Cerotto GEM accessible-volume workbench](guiai-lab/docs/images/cerotto-gem.png)

## Five Zoe mechanisms in pictures

<details>
<summary>Open the mechanism gallery</summary>

1. **Epistemic firewall:** measurement, evidence, belief updates, and action remain distinct.
   ![Zoe epistemic firewall](guiai-lab/docs/images/zoe-visuals/01-epistemic-firewall.png)
   [SVG](guiai-lab/docs/images/zoe-visuals/01-epistemic-firewall.svg)

2. **Belief diff:** priors become posteriors only through explicit evidence, with every likelihood and source retained.
   ![Zoe belief diff](guiai-lab/docs/images/zoe-visuals/02-belief-diff.png)
   [SVG](guiai-lab/docs/images/zoe-visuals/02-belief-diff.svg)

3. **Deterministic and stochastic chambers:** reproducible measurements and seeded forecasts have distinct identities and lifecycles.
   ![Zoe deterministic and stochastic chambers](guiai-lab/docs/images/zoe-visuals/03-chambers.png)
   [SVG](guiai-lab/docs/images/zoe-visuals/03-chambers.svg)

4. **Append-only memory:** sequence-linked hashes support replay and tamper detection without claiming authentication.
   ![Zoe append-only memory](guiai-lab/docs/images/zoe-visuals/04-memory-chain.png)
   [SVG](guiai-lab/docs/images/zoe-visuals/04-memory-chain.svg)

5. **Next useful test:** decision support ranks attention while human review controls execution.
   ![Zoe next useful test](guiai-lab/docs/images/zoe-visuals/05-next-test.png)
   [SVG](guiai-lab/docs/images/zoe-visuals/05-next-test.svg)

</details>

## Evidence boundaries

Zoe's "living" tagline is a creative metaphor, not a claim of consciousness or sentience. Accessible volume measures forecast breadth, not correctness or human surprise. HOP remains a rejected baseline. Field-notebook posteriors are conditional on user-supplied priors and likelihoods, not objective truth scores. Chamber measurements and sampled outcomes never update claims automatically. Dependent evidence requires explicit acknowledgment and adjusted likelihoods. The memory hash chain provides tamper evidence, not authentication. BRAIN recommendations are experimental, not automatic actions: `executed=False` remains the boundary between measurement and execution, and the user decides what happens next.

## Implementation map

```text
guiai/gem/brain.py         Observation state, recommendations, exact continuations
guiai/gem/field.py         Bayesian memory, chamber registry, equations, notebook scene
guiai/gem/cognitive.py     Bounded memory operations, Cognitive Field scene, safe exports
guiai/gem/helen_onset.py   Lazy HELEN artifact and temperature transforms
guiai/gem/research.py      Hash-checked research evidence and conformance
guiai/gem/atlas.py         Module registry and headless scene builders
guiai/gem/atlas_view.py    Native GTK controls and host integration
guiai/gem/unified.py       Component registry, isolated launch environments, and ZOE hub scene
guiai/gem/knowledge.py     Replayable source observations and declared trust/stability links
guiai/gem/unified_cli.py   `zoe` inspection, launch, manifest, and knowledge commands
components/               Complete tracked source trees for the nine upstream repositories
guiai/gem/dorothy.py       Dorothy CCFv3 mesh scene, legend, and evidence report
guiai/gem/dorothy_data.py  Allen data fetch and SHA-256 manifest verification
guiai/gem/dorothy_jenga.py Jenga block tower, exploded, and pull layouts by volume
guiai/gem/dorothy_rings.py Baobab ontology rings by exact subtree volume
guiai/gem/dorothy_stack.py Exploded coronal slab stack of the CCF meshes
guiai/gem/spatial3d.py     PLY loader, orbit camera, deterministic painter renderer
guiai/gem/cli.py           gem zoe / gem master / gem brain / gem atlas / gem dorothy / gem notebook / gem cognitive
guiai/gem/data/            Packaged HELEN prediction artifact
stress/zoe_stress.py       Core, evidence, CLI, and native integration tests
stress/cognitive_stress.py Cognitive Field core, exports, and native workflow tests
```

## Verification

```bash
PYTHONPATH=guiai-lab /usr/bin/python3 -m unittest stress.cognitive_stress -v
PYTHONPATH=guiai-lab guiai-lab/stress/nested_x11.sh \
  /usr/bin/python3 -m unittest stress.cognitive_stress -v

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
