# GEM (Graphics Environment Manager)

> Canonical master reference copied from Ablation. For this repository's standalone distribution, follow [README.md](README.md). Distribution-specific statements below describe the canonical Ablation master.

**GEM (Graphics Environment Manager)** is Ablation's standard graphical execution environment. It converts bounded JSON drawing programs into native Cairo/SVG previews and real signed little-endian GEM VDI metafiles, then evaluates spatial assertions directly against the geometry. The Lab remains the investigation workbench: the tree, real agent terminal, selection, evidence states, and session history are preserved.

## One Ablation + GEM distribution

Ablation + GEM (Graphics Environment Manager) is one product and one default download, not two independent frameworks. Ablation supplies the required analysis framework and evidence model; GEM (Graphics Environment Manager) supplies the native UI, shared Lab, Spatial IR, graphical execution, verification, and replay. Ablation works CLI-only; GEM's complete investigation workflows require Ablation. The former GUIAI is obsolete.

The agent follows a transactional cycle: `gem state` reads the exact selected object and revision; `gem begin` rejects stale work; Ablation performs real analysis; `gem emit` or `gem emit-many` records supported results. The Lab updates from the same event history used by the human. Generated geometry and verifier reports remain tool evidence, not human confirmation or vulnerability proof. Visual architecture notes are linked from the README's Capabilities section.

The name refers to this project's **Graphics Environment Manager** and its GEM VDI output. It is not an emulator or a replacement for the original GEM desktop.

## Stochastic agent, deterministic environment

“Bicameral operating system” is an architectural metaphor here, not a claim that GEM owns a kernel, CPU, memory, or devices. The AI Agent proposes actions stochastically; the human supplies direction and judgment; Ablation and GEM execute constrained operations, preserve evidence, and verify results deterministically.

Next-token accessible volume measures breadth, not correctness:

\[
A_\tau(S)=\sum_{a\in O}\mathbf{1}[P(a\mid h_T(S))>\tau]
\]

Here \(S\) is the model context and \(O\) is its output vocabulary. In a Lab, context can include the current request, event history, selection, and evidence. At the structured-action level, permitted accessible actions can be distinguished with a second indicator:

\[
B_\tau(S)=\sum_{a\in O}\mathbf{1}[P(a\mid S)>\tau]\cdot\mathbf{1}[a\in\operatorname{Allow}(S)]
\]

The operational sequence is `proposal → constrained action gate → deterministic execution → evidence on disk → verification/replay`. This reduces unbounded and uninspectable action; it does not eliminate stochastic variation or prove safety. Accessible volume must not be presented as a correctness, autonomy, or safety score. Current interactive agent CLIs do not expose token probabilities, so GEM does not calculate either score for them. A provider exposing suitable logits and complete structured actions would be required before making such a measurement.

The standalone distribution adds an optional local provider path for the token-level equation. `gem predict` runs hash-checked `distilgpt2-ONNX` inference on the current Lab context, preserves the complete distribution and threshold sweep, and records scoped evidence. `gem steer` adds an inspectable heuristic advisory and trend comparison. These measure the local model only—not the embedded interactive agent or a distribution over complete actions. Advisories can recommend gathering evidence, human review, or verification, but never authorize execution or permission escalation. `gem tournament` compares fixed and adaptive equations on identical distributions and attacked contexts, recording advisory flips without inferring an equation winner. `gem landmarks` applies least-squares Procrustes alignment to supplied correspondences, exports native Spatial IR/VDI, replays the geometry, and links scoped alignment evidence into the Lab.

## Environment and hosted Lab

GEM is the outer environment; GEM Lab is its investigation application. The migration preserves the existing native shell while moving shared operations behind `GemLabHost` and `GemCommandBroker` rather than performing a big-bang rewrite.

- `gem lab TARGET --session SESSION` opens the existing native Lab through the GEM entry point. Agent and toolkit options delegate to the same Lab application protocol.
- `gem lab-state --session SESSION` exposes authoritative investigation state and the derived spatial projection as inspectable JSON.
- `investigation:ID` addresses real event objects. `spatial:SCENE:OBJECT` addresses generated graphical objects and links them back to `event_id` where applicable.
- The broker supports snapshot, resolve, revision-checked select/begin, and replayed export operations. GTK export and the host use the same service code.

![Unified Memory Architecture: human, AI Agent, Ablation, and GEM](../assets/demos/gem-unified-memory-architecture.png)

**Authoritative state** remains investigation events, evidence, selections, statuses, agent actions, and verifier results. **Derived visual state** includes trees, rings, treemaps, Spatial IR, Cairo output, VDI commands, and layouts. Derived scenes never replace or become the source of investigation truth; they can be regenerated and replayed.

## Native Lab workflow

Open **Chart** and select **GEM** beside **Rings** and **Treemap**. The chart is derived from the same live investigation events as the other visualizations:

- Rectangles are Lab nodes; connectors join visible parents and children.
- Clicking a rectangle selects the real Lab node. Enter activates the selected node and Home selects the chart root.
- The caption reports source-constraint results. Failed objects receive dashed outlines and diagnostic tooltips.
- The layout displays at most 24 nodes through depth 3. Its title records when display limits omit nodes; omission is not analysis coverage.
- **Export GEM + VDI** writes a new run under `gem-runs/` in the current session, replays the files, and emits a stable `evidence:gem:DIGEST` node through the normal session protocol.

A successful evidence node is `complete_scoped` only for the stated source/VDI/device checks. It does not mean human confirmation, correct reverse engineering, or complete target coverage. Failed or constraint-free exports remain partial. Detailed agent attempts belong in `trajectory.jsonl`, not the high-level investigation history.

## CLI

After installing `gem-lab`, the `gem` command is available. `python3 -m gem` is equivalent when running from a source checkout with `gem-lab` on `PYTHONPATH`.

Export and verify the built-in house example:

```bash
gem demo --output runs/house
gem replay runs/house
```

Verify JSON and its VDI roundtrip, or render an individual artifact:

```bash
gem verify runs/house/scene.json --vdi
gem render runs/house/scene.json --output house.svg
gem render runs/house/scene.json --output house.png
gem render runs/house/scene.json --output house.gem
```

SVG and VDI use the Python standard library. PNG and the native chart require the existing optional Cairo/GTK bindings; the core engine does not import GTK. A missing PNG backend produces an error rather than silently substituting another renderer.

Generate and repair a scene with an installed external agent:

```bash
gem solve 'Draw a house with a touching roof, a contained door, and symmetric windows.' \
  --agent-command 'kimi -p {prompt}' \
  --attempts 3 --timeout 120 --output runs/agent-house
```

Kimi Pro supplies the account and inference; GEM supplies the bounded prompt, process management, and deterministic verifier. No credentials are bundled. `{prompt}` is replaced as an argument without invoking a shell. If the placeholder is omitted, the prompt is sent on standard input. Each process has a timeout, runs in its own process group, and is killed as a group on timeout. Prompts and output are size-bounded. The response must be one Spatial IR document, optionally fenced as JSON; validation diagnostics are included in the next repair prompt. Tests use a local fake agent and do not require live inference.

`--constraints required.json` supplies a JSON array of constraints the agent must preserve. A final export can fail even when source geometry passes if VDI recovery or a device invariant fails; its reports and trajectory are retained.

## Spatial IR

Schema version 1 supports `rectangle`, `polygon`, `polyline`, `line`, `ellipse`, and `text`. A minimal scene is:

```json
{
  "schema_version": 1,
  "id": "example",
  "canvas": {"width": 10000, "height": 6000},
  "objects": [
    {"id": "body", "type": "rectangle", "bounds": [2000, 2000, 8000, 5000], "fill": "white", "stroke": "black", "width": 20},
    {"id": "door", "type": "rectangle", "bounds": [4500, 3500, 5500, 5000], "fill": "yellow", "stroke": "black", "width": 20}
  ],
  "constraints": [
    {"type": "contains", "outer": "body", "inner": "door"},
    {"type": "inside_canvas", "object": "*"}
  ]
}
```

Coordinates are finite numbers within the signed VDI coordinate range. Object count, total points, constraints, identifiers, labels, prompts, JSON size, and agent responses have explicit limits. Unknown fields, object types, constraints, and references are rejected.

Available assertions:

- `contains`: inner axis-aligned bounds are within outer bounds.
- `touches`: axis-aligned bounding-box boundaries make contact within tolerance.
- `symmetric`: two centers are mirrored around an x/y value and both bounding-box dimensions match. Coincident equal objects satisfy this predicate; use `nonoverlap` separately when required.
- `aligned`: named bounds or center coordinates match.
- `inside_canvas`: one object or `*` has bounds inside the canvas.
- `nonoverlap`: positive-area bounding-box intersections are rejected; touching edges are allowed.
- `connected`: a line endpoint matches a named object anchor.

`contains`, `touches`, `symmetric`, `aligned`, and `nonoverlap` deliberately use axis-aligned bounds, not general computational-geometry proofs. Text bounds estimate width as `0.62 × size × character count`. Default tolerance is one thousandth of the smaller canvas dimension; a constraint can specify a nonnegative `epsilon`. “Verified” means direct deterministic numeric checks without an LLM image judge, not a proof of arbitrary shape semantics or visual quality.

## VDI and replayable runs

The writer emits actual VDI records, including `v_pline`, `v_gtext`, `v_fillarea`, `v_bar`, `v_rbox`, `v_ellipse`, `vst_height`, and drawing attributes. User-defined metadata records preserve object IDs and Lab roles for roundtrip recovery. Text uses CP437 with replacement for unrepresentable characters, and the classic VDI color palette is narrower than Cairo's RGB support. Arbitrary third-party metafiles and the full VDI API are outside this first version.

A successful run contains:

```text
scene.json                 Source Spatial IR
scene.gem                  Source-coordinate VDI metafile
scene-cga.gem              320 × 200 variant
scene-vga.gem              640 × 480 variant
scene-ndc.gem              32767 × 32767 variant
preview.svg                Inspectable vector preview
source-report.json         Source geometry results
vdi-report.json            Recovered-VDI geometry results
device-report.json         Per-device source/VDI and identity invariants
trajectory.jsonl           Export or generate/verify/repair records
run.json                   Scene identity, scope, and artifact SHA256 hashes
```

Replay validates artifact hashes, regenerates the device files, reconstructs scenes from VDI, recomputes every constraint, and compares the results with the recorded reports. It does not trust the manifest's `passed` flag. Existing nonempty run directories are not overwritten by default.

## Scope and related work

Geometric validation and vector-program generation have prior art, including GeoSVG-RL, SGP-GenBench, GeoGramBench, VGBench, and CADCodeVerify. This implementation does not claim those ideas are new. Its specific integration is native agent-generated GEM visualization, source and VDI-roundtrip checks, cross-device invariants, and evidence-linked agent trajectories in one Lab workflow.

## Validation

```bash
python3 stress/gem_stress.py
PYTHON=/usr/bin/python3 stress/nested_x11.sh /usr/bin/python3 stress/gem_stress.py
PYTHON=/usr/bin/python3 stress/nested_x11.sh /usr/bin/python3 stress/gtk_stress.py GtkCase.test_gem_shared_selection_export_and_evidence
```

The focused suite covers successful and failing constraints, malformed input, long Lab identifiers, VDI corruption, source/device roundtrips, replay tamper detection, real Cairo output, prompt delivery, fake-agent repair, timeouts, CLI calls, native hit-testing, and evidence export. Use the nested X11 launcher for isolated widget tests; it does not certify host graphics hardware or every external VDI consumer.
