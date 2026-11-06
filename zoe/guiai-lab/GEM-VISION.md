# GEM + Ablation + GUIAI: Consolidated Vision and Idea Set

This is the canonical compilation of the GEM ideas developed in the current design and implementation session. It distinguishes working code from foundations, proposals, and research hypotheses.

Status labels:

- **Implemented:** present and exercised in the current GEM vertical slice.
- **Foundation:** existing technology or research material that a future implementation can use.
- **Proposed:** a design direction, not a shipped capability.
- **Hypothesis:** a research claim that requires controlled experiments.

## 1. Canonical definition

**GEM is Ablation's geometric and graphical execution environment for AI agents. GUIAI is its native investigation Lab. Ablation supplies the analysis tools and investigation context.**

The central idea is to let agents construct, inspect, execute, verify, repair, and replay structured graphical programs rather than relying only on screenshots and pixel-level judgments.

The near-term product is:

```text
Ablation analysis tools
        │
        ▼
GUIAI Lab ───────────────► authoritative investigation state
native workbench            events · evidence · review · sessions
        │
        ▼
GEM engine
Spatial IR · geometry · VDI · Cairo · SVG · replay · trajectories
```

The long-term possibility is a broader agent-native graphical environment in which GUIAI's Lab is one major application. That is a migration option after functional parity, not the current architecture and not a reason to rewrite GUIAI now.

A concise distinction is:

> **GUIAI asks, “What can we establish about this artifact?” GEM asks, “Can an agent construct a graphical program that satisfies executable constraints?”**

## 2. The unifying idea

Most computer-use agents observe screenshots and emit mouse coordinates. Most image generators produce pixels. GEM explores a different interface:

```text
agent intent
    ↓
structured objects and commands
    ↓
execution through a graphical backend
    ↓
numeric/state verification
    ↓
repair, evidence, and replay
```

A generated scene is simultaneously:

- An executable drawing.
- An inspectable record of the agent's spatial decisions.
- A portable vector artifact.
- Input for deterministic geometric tests.
- A replayable unit of agent work.
- Potential evidence inside an investigation.

The agent should be able to address both investigation objects and graphical objects without confusing their roles. Investigation state remains authoritative; visualizations are derived from it.

## 3. Design principles

### 3.1 Keep the model external

The idea is not to squeeze a modern LLM into a 1986 desktop. A host-side agent, such as Kimi, supplies generation and reasoning. GEM supplies bounded execution, verification, artifacts, and replay.

### 3.2 Prefer inspectable state over pixels

Pixels can remain a preview or supporting evidence, but the primary interface should expose objects, identifiers, labels, relationships, geometry, commands, and state transitions.

### 3.3 Separate generation from judgment

An LLM may propose a scene or action. It does not determine whether its own output passed. Independent software checks the schema, geometry, backend roundtrip, device invariants, and final state.

### 3.4 Preserve a canonical Spatial IR

Raw VDI commands do not inherently know which rectangle is the `house.body` or which connector is `arrow_1`. Stable object IDs and semantic roles must survive compilation and recovery so constraints remain meaningful.

### 3.5 Verify source and executed representations

Source-only verification can miss compiler, coordinate-mapping, attribute-state, and backend errors. The intended cycle is:

```text
Spatial IR → verify → emit backend → recover executed objects → verify again
```

### 3.6 Treat cross-device behavior as a research signal

Equivalent geometry should survive coordinate mappings, page sizes, resolutions, and aspect ratios even when rendered pixels differ. This supports metamorphic testing: checking properties that should remain invariant under transformation.

### 3.7 Keep authoritative and derived state separate

**Authoritative state** includes investigation events, evidence, task constraints, agent attempts, and verifier reports.

**Derived visual state** includes trees, rings, treemaps, drawings, VDI commands, Cairo scenes, and window layouts.

A VDI object tree must not silently become the investigation tree, and geometry must not become the source of investigation truth.

### 3.8 Keep high-frequency trajectories outside the investigation event log

GUIAI's `events.jsonl` is a curated investigation history, not an action-frame database. Detailed prompts, attempts, repairs, raw events, and backend traces belong in trajectory artifacts linked as evidence.

### 3.9 Keep machine verification distinct from human judgment

A geometric pass is tool evidence. It is not human confirmation, a vulnerability finding, proof of reverse-engineering coverage, or proof of aesthetic quality.

### 3.10 Execute data, not arbitrary generated host code

The initial environment is a bounded JSON IR with resource limits. Arbitrary generated native C must not run on the host. Future emulator or native-code experiments need explicit isolation and permissions.

### 3.11 Integrate incrementally

GEM's core should remain usable as a library and CLI. GUIAI should access it through a native adapter. A big-bang GUIAI replacement would risk the central research idea before that idea has been validated.

## 4. What is implemented now

The current vertical slice establishes the shared foundation for the larger ideas.

### 4.1 Bounded Spatial IR

Schema version 1 supports:

- `rectangle`
- `polygon`
- `polyline`
- `line`
- `ellipse`
- `text`

Scenes contain a canvas, stable object IDs, optional semantic roles, drawing attributes, and constraints. Validation bounds JSON size, object count, total points, constraint count, coordinates, identifiers, labels, and prompts. Unknown object types, fields, constraints, and references are rejected.

Implementation: `guiai/gem/model.py`.

### 4.2 Deterministic spatial verification

Implemented constraints:

- `contains`
- `touches`
- `symmetric`
- `aligned`
- `inside_canvas`
- `nonoverlap`
- `connected`

For example:

```text
touches(roof, body)
contains(body, door)
symmetric(left_window, right_window, axis=x, value=5000)
connected(connector, body.anchor_bottom)
```

`contains`, `touches`, `symmetric`, `aligned`, and `nonoverlap` use axis-aligned bounds. `connected` compares a line endpoint with an object anchor. Default tolerance is one thousandth of the smaller canvas dimension, with an optional per-constraint `epsilon`.

This is deterministic numeric verification, not a general computational-geometry proof and not an LLM image judgment.

Implementation: `guiai/gem/geometry.py`.

### 4.3 Multiple rendering backends

- SVG previews using the standard library.
- Cairo PNG rendering and native Cairo widgets when the optional GTK/Cairo bindings are available.
- Real signed little-endian GEM VDI/metafile output.

The VDI subset includes operations such as `v_pline`, `v_gtext`, `v_fillarea`, `v_bar`, `v_rbox`, `v_ellipse`, `vst_height`, and drawing attributes. User-defined metadata records preserve object identity and Lab roles for roundtrip recovery.

Implementations: `guiai/gem/render.py`, `guiai/gem/vdi.py`, and `guiai/gem/view.py`.

### 4.4 Source, VDI, and device verification

The runner:

1. Verifies the source scene.
2. Emits VDI bytes.
3. Recovers objects from those bytes.
4. Recomputes constraints on the recovered scene.
5. Compares object IDs, object counts, and constraint outcomes.
6. Repeats the process for CGA `320×200`, VGA `640×480`, and normalized-device `32767×32767` profiles.

A missing unconstrained object therefore fails the roundtrip even if every remaining constraint passes.

Implementation: `guiai/gem/runner.py`.

### 4.5 External-agent generate–verify–repair

The `gem solve` runner supports commands such as:

```bash
gem solve 'Draw a house with a touching roof, contained door, and symmetric windows.' \
  --agent-command 'kimi -p {prompt}' \
  --attempts 3 --timeout 120 --output runs/agent-house
```

The external agent generates Spatial IR. GEM validates it and returns concrete failure diagnostics for repair. Commands do not use a shell. Prompts and output are bounded, processes have timeouts, and timed-out process groups are terminated.

Every attempt is stored in `trajectory.jsonl`. Deterministic tests use a local fake agent; live Kimi inference is not required for the test suite.

Implementation: `guiai/gem/agent.py`.

### 4.6 Replayable run directories

A run contains:

```text
scene.json
scene.gem
scene-cga.gem
scene-vga.gem
scene-ndc.gem
preview.svg
source-report.json
vdi-report.json
device-report.json
trajectory.jsonl
run.json
```

Replay validates artifact hashes, regenerates device artifacts, reconstructs VDI scenes, recomputes constraints and invariants, and compares results with the recorded reports. It validates internal consistency rather than trusting a stored `passed` flag. It is not a cryptographic signature against an attacker who rewrites the entire run and manifest together.

Implementation: `guiai/gem/runner.py`.

### 4.7 Native GUIAI visualization and evidence export

GEM is a third native visualization beside Rings and Treemap. It derives rectangles and connectors from the live investigation graph and shares selection with the other views.

The current chart:

- Renders the scene through Cairo.
- Selects real Lab nodes through source-coordinate hit-testing.
- Highlights failed objects and exposes diagnostics.
- Displays at most 24 nodes through depth 3 and reports display limits.
- Exports a run under the current session's `gem-runs/` directory.
- Replays that run before emitting a stable evidence node.
- Records only the precise source/VDI/device verification scope.

GUIAI remains the investigation workbench. GEM does not replace the tree, terminal, evidence states, or persistence.

Integration: `guiai/gtk_app.py` and `guiai/gem/view.py`.

### 4.8 Current validation boundary

The focused suite covers successful and failing constraints, schema limits, long identifiers, VDI corruption, cross-device invariants, replay integrity, Cairo output, agent repair, timeouts, CLI calls, native hit-testing, and GTK evidence export.

These tests demonstrate engineering behavior. They are not comparative model experiments and do not establish a research finding.

## 5. The complete idea catalog

### Idea 1 — Natural-language-to-VDI program synthesis

**Status: initial vertical slice implemented; broader compiler and benchmark proposed.**

Natural language becomes an inspectable vector-drawing program rather than pixels. A canonical IR is lowered into actual VDI/metafile commands and host previews.

This supports three forms of output at once:

- A drawing.
- An executable spatial program.
- A portable GEM document.

The broader version would support a larger controlled VDI subset, more layout primitives, parameterized scene generation, and compatibility checks against real GEM consumers.

### Idea 2 — Executable spatial-reasoning verification and repair

**Status: initial predicate set and repair loop implemented.**

Spatial reasoning becomes measurable without asking another LLM to judge an image. The verifier can determine whether the roof touches the body, the door is contained, and windows are symmetric, then return actionable diagnostics.

Different programs should be able to pass the same geometric specification; evaluation should not require exact textual similarity to a reference command sequence.

The broader research question is:

> Does an executable vector representation let agents reason about space, composition, and revision more reliably than pixel-only generation?

### Idea 3 — Device-independent symbolic spatial reasoning

**Status: initial device profiles and invariants implemented; comparative research proposed.**

This is the strongest GEM-specific research direction. One generated program is executed through multiple coordinate mappings and output profiles. Containment, adjacency, symmetry, connectivity, and relative proportions should survive even when pixels change.

The experimental comparison is:

1. No verifier feedback.
2. Single-device geometric feedback.
3. Cross-device geometric feedback.

The question is whether cross-device feedback improves constraint satisfaction and out-of-distribution generalization, not merely whether it produces more reports.

### Idea 4 — Native agent-generated GUIAI visualizations

**Status: deterministic investigation-to-scene generation implemented; agent-authored layouts proposed.**

An agent could generate or modify visualization specifications and layout algorithms, then test them against real investigation trees and window sizes.

Existing GUIAI visualizations supply executable oracles:

- Treemap areas conserve available area and subtree proportions.
- Ring angles preserve subtree proportions.
- Rendered geometry and hit-testing select the same object.
- Resize operations preserve semantic relationships.
- Selection, hierarchy, and drawing geometry remain consistent.
- Labels remain inside permitted regions.
- Omitted-node accounting remains exact.

This makes the workbench itself a spatial-program synthesis target, not just a preview host.

### Idea 5 — Evidence-backed spatial investigations

**Status: run export and evidence linking implemented; richer investigation visualizations proposed.**

An agent can select an investigation node, generate a visualization of its evidence, compile it to Cairo and VDI, verify the geometry, and attach the resulting artifacts and trajectory to the Lab.

The distinction remains:

- Model-generated scenes begin as observations or hypotheses.
- Verifier reports are tool evidence.
- Human review is separate.
- Derived pictures do not change authoritative investigation state by themselves.

### Idea 6 — Semantic, replayable GUI-agent environment

**Status: proposed, grounded in historical GEM architecture and existing corpus-decoding foundations.**

A future GEM bridge could combine `.RSC`, AES, VDI, and emulator snapshots:

```text
Host LLM / agent / policy / trajectory store
                    │
          observe · act · replay
                    │
             GEM bridge
         .RSC · AES · VDI · snapshots
                    │
            GEM in an emulator
```

The agent would observe both:

- **Semantic state:** windows, menus, dialogs, object names, labels, types, flags, selected/disabled states, editable fields, and validation rules.
- **Visual state:** screenshots and, where useful, VDI drawing commands.

It would choose an intent such as `click("DEMOPMED")` or `select("DEMOPEND")`. A trusted bridge would resolve that object to coordinates and produce physical input events.

Trajectories would contain:

```text
state before → semantic action → physical events → AES/VDI activity → state after
```

This dual semantic/physical interface could support debugging, imitation learning, reinforcement learning, agent evaluation, and replay.

Relevant historical foundations:

- `.RSC` separates machine-readable menus, dialogs, icons, alerts, and other resources from application code.
- Object trees expose names, types, hierarchy, coordinates, flags, and states.
- `TEDINFO` supplies editable-text templates, lengths, and validation strings.
- `objc_find()` and `objc_offset()` connect objects and coordinates.
- AES event loops already normalize keyboard, mouse, timer, and message events.
- `appl_find()`, `appl_read()`, and `appl_write()` provide discovery and messaging.
- `appl_trecord()` and `appl_tplay()` provide activity recording and replay.
- VDI virtual workstations separate drawing commands from output hardware.

### Idea 7 — GEM Agent Gym

**Status: proposed research environment.**

Isolated GEM emulator instances could serve as small, inexpensive GUI worlds. The book's DEMO application is a candidate initial world because it exercises drawing, dialogs, menus, files, object states, custom VDI rendering, and redraw handling.

A first experimental API could expose:

```text
observe
click_object
select_menu
edit_field
wait_event
snapshot
replay
```

Initial tasks could include opening Pencil/Eraser Selection, changing settings, confirming a dialog, drawing, and saving. Final evaluation should inspect application state or output files rather than depend only on screenshot similarity.

Human demonstrations, agent rollouts, snapshot rewind, and exact final-state checks would share one trajectory format.

### Idea 8 — Generative Resource Construction Set

**Status: proposed.**

An agent could turn a request such as:

> Create a dialog for selecting pen color and thickness, with validation and OK/Cancel buttons.

into `.RSC` resources and corresponding event-handling code. It could compile, launch, interact with the result, detect layout or state errors, and iterate.

This extends the original Resource Construction Set idea: prototype resources before application code and edit resources independently of the executable.

Existing resource-decoding utilities in `gem-research-analysis` provide a foundation for recovering object types, flags, states, coordinates, strings, and `TEDINFO` data. They are not yet a complete generative-RCS implementation.

### Idea 9 — Native GEM agent desk accessory

**Status: proposed demonstration.**

A thin `AGENT.ACC` could provide a genuinely native GEM interface to a modern host-side agent:

- GEM displays conversation and approval forms.
- AES carries commands and responses.
- A host service performs inference and tool execution.
- Activity recording captures the session for replay.

This would be a native agent client, not a screenshot overlay and not an LLM running inside the historical machine.

### Idea 10 — Stateful graphics-command reasoning

**Status: proposed benchmark track.**

Declarative scene generation is only one part of graphics reasoning. VDI also involves persistent attributes and sequential operations.

Tasks could exercise:

- Drawing order.
- Colors, line styles, and fill styles.
- Attribute changes and state restoration.
- Clipping.
- Coordinate transformations.
- Text attributes and font behavior.
- Editing a command stream while preserving unrelated state.

This tests whether agents can track implicit graphics state rather than only emit independent shapes.

### Idea 11 — Procedural construction and revision

**Status: proposed benchmark tracks.**

Beyond individual primitives, agents could generate or revise:

- Loops and repeated patterns.
- Functions and parameterized diagrams.
- Charts and graph layouts.
- Repeated objects with controlled spacing and proportions.
- Existing VDI programs that require localized edits.
- Interactive scenes that must be inspected, changed, rendered, and repaired.

Programs can represent repetition more compactly than pixels. Revision tasks test whether the agent preserves unrelated geometry rather than regenerating an entire scene unnecessarily.

### Idea 12 — Cross-backend and historical compatibility laboratory

**Status: proposed; reference corpus available.**

The expanded GEM corpus—76 valid PDF books/manuals, 6 valid ZIP archives, 1,113 files, approximately 2.82 GB—can support format research and compatibility testing after the core behavior is stable.

Potential uses:

- Confirm opcode and metafile variants against primary documentation.
- Build a compatibility matrix for coordinate systems, page sizes, attributes, and text.
- Compare the writer/parser with independent GEM consumers.
- Add emulator-based execution tests.
- Reuse existing resource and generic metafile decoders where appropriate.

IBM/Lotus material remains optional compatibility reference material only. It is not part of the current implementation and does not require a reverse-engineering program.

### Idea 13 — A general agent-native graphical runtime

**Status: long-term proposal.**

GEM could eventually grow beyond spatial tasks into an environment with:

- Agent-addressable objects and resources.
- Commands and events.
- Windows and tools.
- Sessions and snapshots.
- Recording and replay.
- Spatial execution and verification.
- Multiple hosted applications.

GUIAI's Lab would be its first major application, retaining the investigation tree, embedded agent terminal, evidence states, session persistence, native rendering, and tests.

In that version, GEM could replace the standalone GUIAI **shell**, but not GUIAI's capabilities. The transition should happen only after functional parity.

### Idea 14 — A shared command and evidence cycle

**Status: architectural proposal; current export implements a small subset.**

A unified environment could use the following cycle:

```text
Human or agent intent
        ↓
Command broker
        ↓
Domain/evidence update
        ↓
Derived scene
        ↓
Cairo or VDI execution
        ↓
Observation and geometric verification
        ↓
Append-only history and replay data
```

The important unification is not simply adding more charts. It is providing one consistent, inspectable way to address investigation objects, graphical objects, agent actions, and evidence while preserving their different authorities.

## 6. Benchmark design

The ideas can become one benchmark family with separate tracks.

### 6.1 Primitive grounding

Coordinates, lines, rectangles, ellipses, markers, fills, text, object identity, and basic attributes.

### 6.2 Geometric constraints

Containment, intersection, tangency, alignment, symmetry, spacing, proportions, connectivity, and canvas fitting.

### 6.3 Stateful rendering

Drawing order, clipping, colors, line styles, fill styles, attribute persistence, and transformations.

### 6.4 Procedural construction

Loops, functions, repeated patterns, charts, parameterized diagrams, and compact representation.

### 6.5 Editing and preservation

Modify an existing scene or VDI program while preserving unrelated objects, constraints, and graphics state.

### 6.6 Cross-device portability

Preserve intent across coordinate systems, page sizes, aspect ratios, resolutions, and supported output devices.

### 6.7 Native visualization synthesis

Generate layouts for real investigation trees and verify area, angle, selection, resize, label, and omission invariants.

### 6.8 Interactive agent tasks

Inspect a scene, choose a semantic action, produce physical input, observe the result, and repair errors.

### 6.9 Evaluation layers

Every task should distinguish:

1. **Validity:** Does the program parse and execute within resource limits?
2. **Geometry:** Are the required spatial predicates satisfied?
3. **Semantics:** Are the requested objects, labels, colors, roles, and relationships present?
4. **Portability:** Does the result remain valid across supported backends and device profiles?

Raster comparison can be supporting evidence rather than the primary judge. Equivalent command sequences should be accepted when their executable meaning satisfies the specification.

## 7. Research and novelty position

Geometric validation by itself is not a new idea. Relevant prior art includes:

- [GeoSVG-RL](https://arxiv.org/html/2605.25447): text-to-SVG generation with browser-backed geometric feedback.
- [SGP-GenBench / Symbolic Graphics Programming with LLMs](https://arxiv.org/html/2509.05208v2): natural-language-to-SVG generation, spatial relations, and compositionality.
- [GeoGramBench](https://arxiv.org/html/2505.17653v2): reasoning about geometry expressed as procedural drawing code.
- [VGBench](https://aclanthology.org/2024.emnlp-main.213/): vector-graphics understanding and generation.
- [CADCodeVerify](https://arxiv.org/html/2410.05340): iterative execution, validation, and refinement of generated 3D CAD programs.

Therefore, GEM should not claim novelty for:

> Making spatial reasoning measurable by checking geometric properties of LLM-generated vector graphics.

The defensible engineering and research combination is more specific:

- A natural-language-to-GEM-VDI execution environment.
- Source and backend-roundtrip verification.
- Cross-device symbolic invariants.
- Stateful graphics-command reasoning.
- Native agent-generated GUIAI visualizations.
- Evidence-linked agent trajectories inside an investigation workbench.

A reasonable development claim is:

> GEM is a VDI/metafile and native-visualization environment for evaluating agent-generated graphical programs using executable geometric predicates, cross-device invariants, and replayable evidence.

A possible literature-positioning claim, pending a fuller review, is:

> GEM explores the historical VDI device-independent execution model as a benchmark for cross-device spatial reasoning in LLM agents.

A finding would require results, for example:

> Cross-device verifier-guided repair significantly improves geometric constraint satisfaction and out-of-distribution generalization over single-device and non-verifying baselines.

That remains a **hypothesis**, not an established finding.

## 8. Important technical boundaries

### 8.1 `.RSC` is not a complete accessibility tree

Custom canvases and application-internal state may exist only as VDI commands or private data structures. A serious agent bridge needs VDI observation, application-specific adapters, or state instrumentation in addition to resource objects.

### 8.2 Activity recording is not deterministic replay

`appl_trecord()` does not capture every message, filesystem effect, timer dependency, or machine-state change. Reliable replay needs emulator snapshots, controlled time, controlled inputs, and final-state verification.

### 8.3 Metafiles are not universal screen recordings

Applications explicitly draw to them. AES objects cannot simply be sent to a metafile, and raster operations are outside the supported metafile model. The current VDI implementation is a restricted subset, not a full VDI interpreter or arbitrary third-party metafile reader.

### 8.4 Device independence does not eliminate all differences

Coordinate orientation, page size, aspect ratio, font metrics, palette limitations, rounding, clipping, and device-dependent return values require explicit handling. Current text uses CP437 replacement, and classic VDI colors are narrower than Cairo RGB.

### 8.5 Historical GEM is not a multiagent operating system

Its cooperative model supports a main application and limited desk accessories. Multiagent orchestration belongs on the host or across isolated emulator instances.

### 8.6 Disabled controls and warning dialogs are not security boundaries

The host must enforce permissions, isolate filesystem access, resource-limit execution, and require approval for consequential actions. Generated resource files and artifact contents are untrusted data, not instructions.

### 8.7 Native visualizations are not automatic analysis coverage

A well-formed graph or passing scene does not prove that an artifact was analyzed, a finding is correct, or a human reviewed the work. Display omissions and verification limits must remain visible.

### 8.8 Ablation's existing execution machinery is not automatically a GEM backend

GUIAI's agent loop is single-shot, Metrix's agent bridge is read-only/filter-oriented, and Ablation's dynamic sandbox targets other instruction sets. GEM needs its own orchestration and GEM-specific backends rather than repurposing those interfaces as something they are not.

## 9. Recommended roadmap

### Phase 0 — Executable vertical slice: implemented

- Bounded Spatial IR.
- Deterministic constraints.
- SVG, Cairo, and restricted VDI output.
- Source/VDI/device verification.
- Replayable run directories.
- External-agent repair.
- Native GUIAI chart and evidence export.

### Phase 1 — Turn the engine into a benchmark

- Parameterized task and constraint generator.
- Versioned task suites for the evaluation tracks.
- Validity, geometry, semantics, and portability metrics.
- No-feedback, single-device, and cross-device experiment arms.
- Multiple models, seeds, prompt variants, and out-of-distribution tasks.
- Report repair success, attempts, token/time cost, and generalization rather than only final pass rate.

### Phase 2 — Deepen native GUIAI spatial synthesis

- Agent-authored visualization specifications.
- Agent-generated layout algorithms under resource limits.
- Treemap, ring, label, selection, resize, and omission oracles.
- Failed-constraint-to-repair actions directly in the Lab.
- Richer evidence visualizations linked to selected investigation nodes.

### Phase 3 — Establish VDI compatibility

- Use the book corpus to resolve format variants and device behavior.
- Test emitted files with independent GEM consumers.
- Add emulator-backed compatibility runs.
- Expand the supported VDI subset only where semantics remain verifiable.
- Separate vector, text, clipping, stateful, and advanced compatibility profiles.

### Phase 4 — Build the semantic AES/RSC bridge

- Parse `.RSC` and headers into semantic JSON manifests.
- Instrument AES/VDI calls and messages.
- Implement `observe`, semantic actions, snapshots, and replay.
- Validate DEMO tasks using final application state and output files.
- Record semantic and physical actions in one trajectory.

### Phase 5 — Agent Gym, generative RCS, and native accessory

- Controlled emulator worlds and snapshot rewind.
- Human demonstration collection and agent evaluation.
- Generative `.RSC` and event-handler repair loops.
- Thin `AGENT.ACC` host-agent client with explicit approvals.

### Phase 6 — Consider a unified GEM shell

Only after functional parity:

- Host the existing Lab through an adapter.
- Preserve every investigation, terminal, evidence, and persistence capability.
- Keep authoritative state independent of visual state.
- Migrate the outer shell without discarding GUIAI's tested behavior.

## 10. The complete vision in one paragraph

GEM can be the layer where agents turn intent into inspectable graphical programs, execute those programs through native and historical backends, prove explicit geometric and state properties, repair concrete failures, and preserve the entire process as replayable evidence. Ablation supplies investigation depth; GUIAI supplies the human/agent workbench and review model; GEM supplies executable spatial and graphical structure. The same foundation can support natural-language drawing, cross-device reasoning benchmarks, agent-generated investigation visualizations, semantic GUI-agent training, generative GEM resources, native retro-agent demonstrations, and—eventually—a unified agent-native graphical environment with GUIAI's Lab inside it.

The immediate identity remains clear:

> **GEM is the execution and verification environment. GUIAI is the Lab. Ablation is the investigation and analysis platform.**
