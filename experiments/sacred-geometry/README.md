# Sacred geometry experiment

This directory contains an immutable image dataset and a reproducible geometry experiment built from it. The eight archive images add functions, modular arithmetic, angle units, summation/product notation, and circle formulas. A derived hub-loop source adds eight `h` nodes and four `v` nodes around a central hub. The landmark-alignment example uses the composite drawing `Untitled drawing (1).png`.

## Rebuild

```bash
python tools/build_sacred_geometry_dataset.py
python tools/build_landmark_alignment.py
```

The first command creates `dist/`; the second creates `dist/alignment/`. Run them in that order so the main manifest also records the alignment artifacts.

## Source identity

- Archive SHA-256: `9f511506d8566e4a6744daa2eb8d03c6debcbc9749cdc39447b21005611bbff2`
- `source-manifest.json` records every source hash.
- `source/hub-loop.svg` and `source/hub-loop.png` are derived sources, not archive files.
- `source/Untitled drawing (1).png` is a 960×720 composite, not the inline chapter page, but contains the same landmark diagram.

## Dataset contents

- `dist/manifest.json` — dataset inventory, source identities, math content, pixel-vector metadata, and the scene/alignment links.
- `dist/math-content.json` — curated exact mathematical transcription for all eight archive images.
- `dist/measurements.json` — dimensions, background RGBA, exact palettes, foreground pixel counts, and connected-component bounds, areas, and component hashes for every image.
- `dist/ocr/image_01.txt` through `dist/ocr/image_09.txt` — raw Tesseract OCR. Use the curated math file for formula fidelity.
- `dist/pixel-vectors.npz` — lossless `uint8` RGBA arrays for all nine images, with shape, stride, dtype, and per-array SHA-256 metadata in `dist/manifest.json`.
- `dist/preview.png` — rendered nested-circle, woven-diamond, hub-loop, arc, formula, and measurement scene.
- `dist/run/` — Spatial IR scene, real GEM VDI metafiles, CGA/VGA/NDC variants, source and device reports, and replay manifest.
- `dist/verification.json` — dataset counts and VDI replay result, including alignment checks when present.
- `dist/SHA256SUMS.txt` — hashes for every generated file. All generated hashes are verified during the build.

## Landmark alignment

The measured correspondences are:

- \(p_1=(101,114)\mapsto q_1=(345,35)\)
- \(p_2=(285,159)\mapsto q_2=(500,205)\)

The SVD Procrustes solution uses centered point sets, \(H=P^TQ=U\Sigma V^T\), \(R=VU^T\), \(s=\sum\sigma_i/\sum\|p_i\|^2\), and \(t=\bar q-sR\bar p\). A proper-rotation constraint ensures determinant \(+1\) and yields:

- scale: `1.2145018039`
- rotation: `33.8997475549°` in screen coordinates
- area scaling: `1.4750146317`
- translation: `(320.40759734, -148.33337978)`
- landmark error after alignment: zero, verified numerically to `1e-8` pixels

A separate full affine least-squares fit is included. Two point pairs provide four equations for six unknowns, so the least-norm solution is **not unique** and has nullity 2. Exact landmark alignment does not imply the different animal outlines coincide or that different-length segments can be aligned exactly by a rigid transform.

## NPZ VolumeBridge

`gem volume` provides a deterministic distribution-to-measurement-to-guidance feedback loop:

```bash
gem volume current.npz --previous earlier.npz --tau 0.05 --output momentum.json
```

It computes accessible volume and its complement, monotonic elapsed time, source/probability hashes, momentum, and target-band guidance. Feedback reports never overwrite existing files. A session can also store a separate `tool` evidence event. No action is authorized or executed.

## Interpretation boundaries

Accessible volume describes forecast breadth, not correctness. Complementary volume is not an algebraic inverse. Momentum and candidate concentration provide advisory guidance only. DistilGPT2 measurements do not measure the interactive agent, and ordinary next-token distributions do not provide a complete structured-action distribution. The HOP and rhythm experiments should be read as evidence about predictor quality, not as a claim that circles, confidence, correctness, or safety are interchangeable.
