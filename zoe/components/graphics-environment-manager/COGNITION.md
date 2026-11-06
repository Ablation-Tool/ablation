# Unified analytical and generative engine

GEM has one integration point for live forecasts, saved distributions, evidence memory, advisory policies, spatial alignment, generated hypotheses, and guarded proposals. It is a model-assisted investigation environment, not a claim of consciousness or autonomous understanding.

## One measurement kernel

`gem.measurement` owns the shared behavior:

- bounded, finite, normalized probability validation;
- strict accessible-volume thresholds and complementary counts;
- entropy, maximum probability, and top-ten probability mass;
- accessible momentum and target-volume suggestions;
- optional observed-token correctness, log loss, and Brier score;
- exact accessible volume over supplied multi-horizon joint distributions;
- canonical document hashes and forecast-context binding.

The providers are:

- `gem.prediction.OnnxPredictor`: live local DistilGPT2 ONNX inference for the selected Lab context.
- `gem.volume.VolumeBridge`: saved distributions with independent current and previous keys, feedback from the latest observation, and model identity preserved from NPZ metadata when available.

Existing `predict`, `steer`, and `tournament` commands retain their interfaces while using the same kernel. Landmarks remain a separate spatial-analysis capability through `gem.landmarks` and `gem landmarks`.

## Multi-horizon measurement

For a horizon \(h\), an autoregressive model defines a conditional joint probability over complete candidate continuations:

\[
P_h(a_{1:h}\mid C_t)=\prod_{j=1}^{h}p(a_j\mid C_{t+j-1},a_{<j})
\]

Accessible volume counts the continuations whose joint probability strictly exceeds a threshold:

\[
A^{(h)}_\tau(C_t)=\sum_{a_{1:h}\in O^h}\mathbf 1[P_h(a_{1:h}\mid C_t)>\tau]
\]

The complement is \(|O|^h-A^{(h)}_\tau(C_t)\).

`measure_joint_distribution` accepts a flat joint vector or an array with exactly \(h\) equal vocabulary dimensions. It verifies the outcome-space shape, vocabulary, normalization, and optional previous distribution. It reports `horizon`, `vocabulary_size`, `joint_outcome_space`, and `approximate: false`.

A one-step distribution is not a genuine joint distribution. GEM does not manufacture one by assuming independence. Supply the learned joint distribution from the model or experiment. Exact enumeration is bounded to eight horizons and 1,000,000 candidate continuations; larger experiments need explicitly identified approximations rather than an exact-count claim.

```bash
gem volume joint.npz \
  --key joint_probabilities \
  --horizon 2 --vocabulary-size 2 \
  --session /path/to/session
```

## Outcomes and calibration

`gem.evaluation` evaluates observed outcomes independently of forecast breadth:

- accuracy and mean confidence;
- log loss and Brier score when supplied;
- expected calibration error over 1–100 bins;
- AUROC and AUPRC for ranking correct outcomes by maximum forecast probability;
- artifact hashes and explicit metric scope.

```bash
gem calibrate measurement-1.json measurement-2.json \
  --bins 10 --output calibration.json
```

Calibration reports require an `outcome` object with a boolean `correct` field. Undefined one-class AUROC is reported as `null`, not as a successful separation. Accessible volume remains a breadth measurement and is not substituted for these outcome metrics.

## Optional state estimation

`gem.estimation.ExtendedKalmanFilter` provides an optional state estimator for callers with an explicit process and measurement model. It is not an assumed model of thought, token distributions, or the Lab.

The prediction step is

\[
x^-_k=F_kx_{k-1}+B_ku_k,\qquad P^-_k=F_kP_{k-1}F_k^T+Q_k
\]

The update uses innovation \(y_k=z_k-h(x^-_k)\), innovation covariance \(S_k=H_kP^-_kH_k^T+R_k\), and gain \(K_k=P^-_kH_k^TS_k^{-1}\). Covariance is updated with the Joseph form:

\[
P_k=(I-K_kH_k)P^-_k(I-K_kH_k)^T+K_kR_kK_k^T
\]

`linear_filter` applies the linear special case to a sequence of observations. Direct EKF callbacks can define nonlinear process or measurement functions and their Jacobians. Dimensions and covariance matrices are checked, and singular innovation covariances are rejected.

```bash
gem estimate state-space.json --output estimation.json
```

The JSON input supplies `observations`, process and observation matrices and covariances, and the initial state and covariance. Optional controls use `control_matrix` and `controls`. The caller is responsible for validating the dynamics. Filtering does not establish correctness, learning, or action authorization.

## Analytical cycle and action guard

1. **Observe:** read the selected Lab context or a saved distribution.
2. **Measure:** record accessible volume, complement, entropy, momentum, and available outcome metrics.
3. **Advise:** run heuristic steering or equation-sensitivity experiments. Recommendations do not authorize actions.
4. **Generate:** optionally create bounded hypotheses with the deterministic baseline or an external JSON generator.
5. **Bind:** connect each forecast to the exact target, selected event, revision, proposal, and action ID.
6. **Review or approve:** deny invalid or stale proposals. Valid proposals remain review-only unless `--approve` is present.
7. **Record:** retain forecast artifacts, generated candidates, decisions, execution receipts, and separate Lab evidence.

The guard supports only:

| Command | Required proposal fields | Effect when approved |
|---|---|---|
| `snapshot` | `command` | Read the current GEM snapshot. |
| `resolve` | `command`, `reference` | Resolve an object in the current snapshot. |
| `begin_selected_work` | `command`, `expected_id`, `expected_revision`, optional `note` | Begin work on the exact selected event. |
| `export` | `command`, `expected_revision` | Export and verify current investigation geometry. |

Other commands, arbitrary shell execution, stale revisions, unknown references, duplicate JSON fields, duplicate action IDs, and mismatched forecast contexts are rejected. Approval never converts a failed execution into a successful receipt.

## Generative side

`gem generate` supports two proposal sources:

- **Deterministic baseline:** up to four bounded candidates covering snapshot, resolve, begin-selected-work, and export. This is an offline contract test and planning baseline, not an intelligence claim.
- **External generator:** an explicit agent command receives a bounded prompt containing the current context, exact selected ID, revision, and proposal schema. `{prompt}` is replaced in the command, or the prompt is sent on standard input.

The external response must be raw JSON with no Markdown fence:

```json
{
  "hypotheses": [
    {
      "statement": "bounded hypothesis",
      "proposal": {"command": "snapshot"},
      "rationale": "short explanation"
    }
  ]
}
```

Each candidate may contain only `statement`, `proposal`, and `rationale`. Self-reported scores and extra fields are rejected. Generation is limited to eight candidates, a 1 MiB prompt, a 1 MiB response, and the existing agent timeout and process cleanup.

```bash
gem generate \
  --session /path/to/session \
  --distribution current.npz \
  --count 4
```

Use an external JSON generator:

```bash
gem generate \
  --session /path/to/session \
  --generator-command 'your-agent {prompt}' \
  --count 4 --timeout 120
```

Every unique proposal is sent to `review_proposal` with `approve=False`. Duplicate candidates are removed. Generated statements are stored as `hypothesis` events, not verified evidence. `generate` has no approval option and never executes a candidate. Reusing the generator later produces fresh action IDs rather than overwriting earlier reviews.

## Direct proposal review

```bash
gem guard proposal.json \
  --action-id proposal-001 \
  --session /path/to/session \
  --distribution current.npz
```

Add `--approve` only when a human explicitly intends to execute a valid proposal. A valid unapproved review returns zero. A denial or failed execution returns status 2. Guard reports are retained under `cognition-runs/`; generation reports are retained under `generation-runs/`.

## Mirrored brain and unified workbench

The unified Zoe work is implemented in this repository's `gem` package, not in `guiai-lab`. `gem.mirror` pairs forward and retrograde HELEN forecasts at the same held-out index. `gem.forecast` measures each direction independently; there is no implicit probability mixture or claim of time-reversed causation. `gem.mirror_view` provides the native GTK window for the mirrored brain, library, and field notebook.

The packaged `gem/assets/onset-seed7.json.gz` contains the stored seed-7 categorical forecasts, so these observations do not download model weights. NumPy is required and is included in the `predict` dependency set. Loading an observation is not an evidence event and cannot update a field-notebook posterior or authorize an action.

```bash
python -m gem os
python -m gem workbench list
python -m gem workbench check --output workbench-verification.json
```

`gem.workbench` registers **17 runnable operations**: 13 original equation sections, causal-repertoire normalization, q-arrow annotation, two-way accessible records, and mirrored observation. It includes strict accessible volume, adaptive volume, exact joint counts, temperature, categorical sampling, Markov continuations, timing RMSE, Procrustes alignment, and a labeled inspection-priority heuristic. The catalog gives each operation's evidence scope; the verification command checks all 17 against expected results and reports failures rather than converting them into successes.

The mirrored evaluation covers **1,920 matched pairs**, preserves correctness and accessible-set membership separately, and caps its history at the latest **128 pairs**. `executed=False` describes the measurement boundary; it is not a permission token.

To call an operation, supply a JSON object in a file, for example:

```json
{"probabilities": [0.70, 0.20, 0.08, 0.02], "tau": 0.05}
```

```bash
python -m gem workbench run volume/strict@v1 --input probabilities.json
```

## Manual library and field memory

`gem.library` builds an explicitly requested, local SQLite index of PDF, HTML, TXT, and Markdown sources. It stores source hashes, returns literal-phrase matches with page references, and opens existing indexes read-only. HTML markup and script/style text are removed before indexing. Existing databases are not overwritten, unsupported archives and binaries are not executed, and book content is never a command source.

```bash
python -m gem library index --root /path/to/GEM/Books --database /path/to/gem-manuals.sqlite
export GEM_LIBRARY=/path/to/gem-manuals.sqlite
python -m gem library search --database "$GEM_LIBRARY" --query VDI
python -m gem os --module library
```

`gem.field` retains the epistemic firewall: measurement is not evidence, a belief update, or an action. Only explicit evidence changes a posterior. Hash-chained JSON memory detects edited or reordered events but does not authenticate its writer. The native window supports questions, competing claims, evidence updates, deterministic and stochastic chambers, save/load, and SVG/PNG/GEM VDI export.

```bash
python -m gem notebook --output zoe-field.json
python -m gem notebook zoe-field.json --output zoe-field.svg
python -m gem os --module field --output zoe-field.gem
```

The supplied 358-document scan contains 13,023 text-bearing pages out of 16,720 total pages. Eighteen documents have no text layer, and 755 unsupported files were excluded. These are index-coverage measurements, not proof that the manuals support a scientific claim. See [the library guide](docs/LIBRARY.md) and [its extraction record](evidence/library/index-summary.json).

## Second eye: parallax and depth of field

`gem.eye` is a synthetic stereo instrument, not a claim of human vision or a second opinion from a model. It creates two parallel pinhole views with a known baseline \(B\), focal length \(f\), sensor width \(s\), and image width \(W\). With \(f_{px}=fW/s\), a point at depth \(Z\) has horizontal disparity \(d=f_{px}B/Z\). The depth estimate is

\[
Z=\frac{f_{px}B}{d}.
\]

For disparity quantized by \(q\) pixels, the display shows the first-order sensitivity \(\sigma_q\), not a posterior or confidence interval:

\[
\sigma_q=\frac{Z^2q}{f_{px}B}.
\]

This makes the tradeoff visible: depth uncertainty grows approximately with \(Z^2\), while a larger baseline or more precise correspondence reduces it. Correspondence failures, occlusion, calibration errors, and real-camera noise are outside this synthetic experiment.

Defocus is separate from depth. `EyeModel.circle_of_confusion` uses the thin-lens approximation

\[
c=\frac{f^2|Z-Z_0|}{NZ(Z_0-f)},
\]

where \(Z_0\) is focus distance and \(N\) is the f-number. `depth_of_field` computes approximate hyperfocal, near, and far limits using a **30µm** acceptable circle of confusion. Unit pupil magnification is assumed; macro optics and a physical point-spread function are not modeled. Display rings visualize the computed radius rather than simulating optical blur. Aperture examples follow the supplied depth-of-field chart without treating it as a calibration for the virtual 50mm lens.

```bash
python -m gem eye
python -m gem eye --focus 2.2 --aperture 11 --baseline .08 --output second-eye.svg
python -m gem eye --output second-eye.json
```

The native `gem.eye_view` window provides focus, aperture, and baseline controls and JSON/SVG/PNG/GEM VDI export. `gem.eye` produces the same scene and report without accessing a camera. `tools.test_eye` checks known geometry, depth sensitivity, defocus, unbounded far depth of field, scene/VDI constraints, no-overwrite exports, and native controls. The preserved default measurement is [`evidence/eye/synthetic-stereo.json`](evidence/eye/synthetic-stereo.json).

## Halo Field: projection and competing templates

`gem.halo` is an original, bounded six-parameter pose experiment over a synthetic non-anatomical cloud of 450 points. It is not a medical reconstruction, physical X-ray simulator, diagnostic tool, encryption construction, or model of human sight. NumPy is available through the `halo` package extra; no deep-learning framework or PETSc installation is used.

A pose uses Euler rotations \(R=R_zR_yR_x\) and a translation. For view angle \(\theta\), a transformed point \((x,y,z)\) supplies

\[
u_\theta=x\cos\theta-y\sin\theta,\qquad d_\theta=x\sin\theta+y\cos\theta.
\]

The projection bins \((z,u_\theta)\) into a 48×48 image with weights \(e^{-0.35d_\theta}\). Separable `[1,2,1]` smoothing and normalization follow. The default target contains views at 0° and 65°. Optional bounded noise is added only to those fixed observations; candidate projections remain noise-free.

The pixel metric is the sum over views of mean squared normalized-pixel differences. The independent **Walsh template** performs the following lossy transformation:

1. Mean-pool a projection to a 4×4 grid.
2. Set each Boolean value by \(b_k=\mathbf 1[\bar P_k>0.35\max(\bar P)]\).
3. Compute the signed Walsh coefficients \(W(a)=\sum_x(-1)^{b_x}(-1)^{a\cdot x}\).
4. Take absolute values, L2-normalize the 16 coefficients, and sort them.
5. Compare two templates by mean absolute difference and sum over the two views.

Sorting discards coefficient identity. This is intentionally an inspectable baseline, not a claim that a Walsh descriptor is rotation-invariant or sufficient for pose recovery. The mathematical self-check uses \(x_0x_1\oplus x_2x_3\): all 16 Walsh coefficients have magnitude 4 and its standard four-variable nonlinearity is \(2^3-4/2=6\). That bent-function identity verifies the transform; it does not validate pose estimation.

Each metric independently ranks 24 starts (identity plus 23 seeded starts) by image moments, then retains three bounded coordinate-descent searches. Rotation steps are 12, 6, 3, 1.5, 0.75, and 0.25 degrees; translation steps are the corresponding values divided by 60. Rotations are bounded to ±75° and translations to ±0.45. The synthetic truth \((17,-21,27,0.10,-0.08,0.09)\) is not an optimizer start. Three local candidates and their within-metric score gaps are retained.

The default deterministic run has these measured outcomes:

- **L2:** translation error 0.0028477739, rotation error 4.2650°, best score \(6.50247\times10^{-8}\), next-score gap \(1.04127\times10^{-6}\).
- **Walsh template:** translation error 0.0821079546, rotation error 79.6067°, best score 0.0625, next-score gap 0; all three retained candidates tie.
- The truth's Walsh score is 0, below the search result. The search therefore stalls on a plateau; this negative result neither validates the Walsh search nor rules out other spectral representations or optimizers.
- The independently selected poses differ by 79.7266° of rotation. Their scores use different units and are never averaged or compared as if they were calibrated probabilities.

The boundary exchange is limited to complete candidate summaries in the report. There is no distributed solver. Score gaps and ties indicate ambiguity among retained local searches, not posteriors or confidence intervals. One successful L2 case is not evidence of universal recovery, noisy robustness, medical utility, or superiority over learned models. No CNN, regression forest, or ridge baseline is trained here.

The scene uses original broken elliptical traces, a circled Z, and deliberate negative space. The March 1984 *DR Draw User's Guide* circle construction and Zoe's existing circled mark motivated the composition; no source figure is copied into the repository. `gem halo` opens controls for metric, view angle, observation noise, and seed. `--output` exports JSON, SVG, PNG, or GEM VDI without overwriting existing files. The complete default report is [`evidence/halo/experiment.json`](evidence/halo/experiment.json).

## Bounded Tetris probability field

`gem.tetris` is an original deterministic 10×20 game model with normalized four-cell tetromino rotations. It is not an official Tetris implementation or a full guideline clone. Juliano Fernandes's MIT-licensed `julianolf/tetris` supplied the behavioral reference; its use of `random.choice` and lack of seed injection motivated explicit alternatives rather than copied code.

The `uniform` model assigns each type probability \(1/7\) independently. The `bag` model shuffles one of each type and samples without replacement. Current and next pieces are both drawn at initialization. Snapshots include the PRNG state, so replay is exact.

Generalized Tetris decision problems can be NP-complete, with hardness depending on the board, rules, and objective. This engine does not solve board clearing, survival, optimal placement, or approximation problems. Its fixed 10×20 state space is finite, and exact randomizer arithmetic is not a claim about computational hardness.

For next-piece probabilities \(p_i\),

\[
A_\tau(S)=\sum_{i=1}^{7}\mathbf 1[p_i>\tau].
\]

For \(r\) remaining pieces, a bag has \(r\) equally likely next outcomes. Two-piece sequences have support \(r(r-1)\), with each ordered sequence assigned probability \(1/(r(r-1))\). Uniform draws instead have \(7^h\) sequences at horizon \(h\). Joint outcomes are enumerated exactly through three pieces, including bag refills. Accessible and complement counts use strict \(p_i>\tau\), never posterior probabilities or predictions of winning.

The initial preserved report has five remaining pieces and 20 ordered two-piece sequences at probability 1/20. Thus \(A_{0.02}=20\) and \(A_{0.05}=0\). An equal-prior candidate comparison assigns posterior 0.9939173263 to the bag after one observation of every type, but that does not identify an unknown implementation's RNG.

`gem.tetris_view` supplies movement, rotation, soft/hard drop, pause, single-step, deterministic reset, model switching, and JSON/SVG/PNG/GEM VDI export. VR is inactive and no headset is accessed. Any future adapter must justify itself through bodily interaction or spatial audio rather than decoration. See [`docs/TETRIS.md`](docs/TETRIS.md) and [`evidence/tetris/experiment.json`](evidence/tetris/experiment.json).

`gem.feed` is a separate black-box experiment for chronological binary observations. It compares independence, first-order, and second-order conditional models with symmetric Dirichlet smoothing. Expanding training windows never include later test observations. It evaluates whether history improves held-out log loss, Brier score, or accuracy; it does not reveal TikTok internals or establish causation. The alternating synthetic result is 0.693147 for independence, 0.114625 for first order, and 0.198193 for second order. See [`evidence/feed/report.json`](evidence/feed/report.json).

A possible passive-RC biological experiment belongs outside this game model. Ohm's law alone is not a universal model of neural activity, and sensor potentials do not uniquely determine internal brain impulses. No biological or clinical claim is made.

## Verification and remaining limits

```bash
python stress/run_stress.py
python stress/native_stress.py
python stress/gem_stress.py
python -m unittest tools.test_workbench tools.test_library tools.test_unlock_guard tools.test_eye tools.test_halo tools.test_tetris tools.test_feed

stress/nested_x11.sh env PYTHONPATH=. \
  /usr/bin/python3 -m unittest tools.test_workbench tools.test_library tools.test_unlock_guard tools.test_eye tools.test_halo tools.test_tetris tools.test_feed
```

The nested X11 wrapper isolates native checks from the live desktop. System GTK/Cairo and `pdftotext` are external requirements; PNG export needs Cairo. The manual index is a local artifact and is not bundled in the package.

## Limits

Accessible volume describes forecast breadth, not correctness, safety, maliciousness, authorization, creativity, or understanding. Observed-token scoring requires the actual token and vocabulary mapping. A DistilGPT2 distribution is not automatically the embedded agent's distribution or a distribution over permitted actions.

Advisory modes and target bands are inspectable heuristics. Equation tournaments measure sensitivity, not superiority. Multi-horizon counts do not guarantee correct future tokens. Generated text is not evidence of reasoning, and no model weights are trained or updated.

The HOP geometric predictor remains a rejected baseline. Its saved negative result is preserved, but full HOP inference was not rerun during this migration because the original extracted `learn-music-theory/004_Chapter_1.html` and `classical-geometry-euclidean/007_c01.htm.html` corpus files are missing from this host. This limitation does not change the mirrored HELEN evaluation, which uses its packaged categorical artifact.

Rhythm and other domain experiments can supply NPZ forecasts but are not proof of general reasoning. Books and historical artifacts can inform algorithms and provenance, but they do not validate a policy by themselves. Verified outcomes, approximation errors, and negative results must be preserved before claiming improvement or a complete brain.
