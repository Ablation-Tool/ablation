# HELEN architecture

GEM HELEN is an independent repository for the creative, exploratory side of the local GEM ecosystem. It does not replace Ablation, Cerotto, or the standalone Graphics Environment Manager. Its scope is interactive geometry, categorical forecast breadth, and reproducible rhythm experiments.

## Design goal

HELEN optimizes the path from opening the application to inspecting an experiment. It avoids loading a full investigation workbench, model runtime, tokenizer, transformer, or clustering dependency when those are not needed.

The implementation separates four small layers:

```text
helen_gem/core.py    Mathematics, bounded scenes, VolumeBridge
helen_gem/onset.py   Lazy compressed experiment data and distribution transforms
helen_gem/render.py  SVG, JSON, and optional Cairo rendering
helen_gem/ui.py      Native GTK window and direct pointer interaction
```

The CLI and native window use the same scene builders. There is no duplicate browser renderer and no development server.

## Precomputed rhythm artifact

`helen_gem/data/onset-seed7.json.gz` contains the complete held-out categorical predictions, targets, threshold curves, metrics, and provenance for the supplied seed-7 experiment. It is 12,014 bytes compressed and about 681 KB as JSON text.

The artifact is loaded only when the Onset module is selected. It preserves 1,920 predictions for each of the forward and retrograde conditions. It does not contain a trained transformer or claim to be one.

Regeneration is explicit through `tools/precompute_onset.py`, using Ablation's tested `guiai.gem.onset` implementation. Normal HELEN use does not import Ablation, NumPy, scikit-learn, or KMeans.

## Optimization choices

- Standard-library geometry and accessible-volume calculations.
- No mandatory package dependencies.
- Lazy GTK imports for native use and lazy Onset artifact loading.
- Cached `OnsetData` after the first read.
- Precomputed baseline metrics and curves at temperature 1.
- Bounded scene objects, landmarks, display probabilities, ellipse counts, and ruled segments.
- Existing-output rejection in the CLI.
- Scene SHA-256 digests and artifact provenance for inspectable exports.

A local development measurement gave approximately 3.5 ms for core import and 11.7 ms for the first lazy Onset load. These are environment-specific observations, not guaranteed benchmarks.

## Deliberate tradeoffs

HELEN is smaller than the other GEMs because it omits their case management and execution surfaces:

- No forensic case database or encrypted vault.
- No autonomous agent or command broker.
- No real MIDI ingestion yet.
- No transformer inference or HOP execution.
- No GEM VDI writer in this first version. HELEN exports SVG, PNG, and its own schema-version-1 scene JSON.
- No live retraining. A new synthetic experiment requires explicit artifact regeneration.

The fixed artifact makes startup fast and reproducible, but it also means the displayed experiment is fixed until a new artifact is generated. Temperature changes are explicit probability transforms, not retraining or music generation.

## Interpretation boundaries

Accessible volume is defined only for complete categorical distributions with strict `p > tau`. Deterministic point forecasts, including HOP and linear extrapolation, have no accessible-volume measurement in HELEN. Forecast breadth is not correctness, authorization, safety, or human surprise.

The native graph module preserves two readings of ambiguous crossings rather than choosing one without evidence. The Onset experiment remains synthetic and is not a human-music or MIDI result.

## Repository independence

HELEN has its own Git repository, Python package, entry point, and documentation. Shared ideas do not require shared mutable state. Future interoperability should use explicit artifacts and conformance checks rather than importing every GEM implementation into one process.
