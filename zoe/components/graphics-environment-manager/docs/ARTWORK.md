# Visual studies and provenance

This gallery distinguishes original executable scenes, atlas-derived illustrations, and user-supplied screenshots. No source document is executed, and no book figure is copied.

## Original generated studies

- `halo-field.{png,svg,gem}` — synthetic point cloud, orthographic projection, independent L2 and Walsh metrics, and measured optimizer disagreement.
- `walsh-template-explained.{png,svg}` — actual 4×4 pooled Halo mask and all 16 Walsh patterns with signed coefficients.
- `bounded-tetris.{png,svg,gem}` — the deterministic 10×20 game and exact next-outcome support.
- `layered-field.{png,svg,gem}` — original exploded blocks with side scale \(L/L_{\max}\) and volume scale \((L/L_{\max})^3\). Illustrative geometry, not an anatomical model.
- `projection-dialogue.{png,svg,gem}` — original synthetic six-pose projection, similarity metric, and bounded optimizer. It uses a point cloud, not a clinical reconstruction or X-ray simulation.
- `proportional-field.{png,svg,gem}` — exact golden-ratio geometry with \(\varphi=(1+\sqrt5)/2\), nested rectangles, and an explicit warning that proportion does not guarantee beauty. The user-supplied [Mathematics and architecture](https://en.wikipedia.org/wiki/Mathematics_and_architecture) reference motivates the spatial ratios.
- `cognitive-field.{png,svg,gem}` — original information-flow study with sensory encoding, bounded working memory, declarative/procedural boundaries, layered state transitions, and an epistemic firewall. This illustration is not an ACT-R implementation or a consciousness model; the working instrument is Zoe's Cognitive Field module.

These scenes use the existing GEM Spatial IR and were checked with `gem.geometry.verify` and `gem.runner.verify_vdi` before export.

## Allen CCF anatomical illustrations

The following existing Zoe works are included with their atlas provenance:

- `dorothy-ccf2017.png`
- `dorothy-dorsal.png`
- `dorothy-ventral.png`
- `dorothy-thalamus-hypothalamus.png`
- `dorothy-rings-isocortex.png`
- `dorothy-jenga-exploded.png`
- `dorothy-jenga-pull.{png,svg,gem}`

The source is the **Allen Mouse Common Coordinate Framework v3 (2017)**, using `annotation_25.nrrd` and hash-checked public structure metadata. Citation: Wang et al. (2020), *Cell* 180(5):936-953.e20, [DOI](https://doi.org/10.1016/j.cell.2020.04.007).

The Jenga geometry is illustrative: each region is represented by three blocks, sorted by annotated voxel volume, with side scale proportional to the cube root of relative volume. The pull view contains **36 blocks and 432 triangles**. It is a visualization of an atlas, not a diagnostic or clinical reconstruction.

## User-supplied screenshots

- `inspiration/orbital-sketch.png` — supplied as `Screenshot From 2026-11-05 02-35-39.png`.
- `inspiration/zoe-ellipses-mobile.png` — supplied as `Screenshot From 2026-11-05 03-08-50 (Edited).png`.

These are retained as visual references rather than represented as newly generated geometry.

## Source boundaries

The Allen files and the supplied screenshots are preserved as static images. No atlas, ROM, medical record, book scan, or executable document is run by this gallery. The synthetic projection is not a medical model, the feed evaluator is not TikTok internals, and generalized Tetris complexity claims are kept separate from exact randomizer arithmetic.
