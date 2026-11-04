# Accessible Volume

## Why this exists

1. A selected token or generated response records an outcome, not the shape of the forecast that produced it.
2. Lab selections and evidence need a reproducible breadth measurement that can be compared across time without claiming correctness or safety.
3. Proposed actions need separate evaluation and concentration deltas rather than an implicit assumption that a confident-looking response is the best action.
4. Raw probabilities and the measurement provenance must remain inspectable evidence, not a hidden score in the UI.

## What it measures

For context \(S\), output vocabulary \(O\), and threshold \(\tau\), accessible volume counts the alternatives strictly above that threshold:

\[
A_\tau(S)=\sum_{a\in O}\mathbf{1}[P(a\mid h_T(S))>\tau]
\]

Tokens exactly at the threshold are excluded. A smaller count means a more concentrated forecast; a larger count means more alternatives remain above the cutoff. The default sweep is `0.02, 0.05, 0.10, 0.15, 0.30, 0.50`.

The report also includes the complementary volume \(A^c_\tau(S)=|O|-A_\tau(S)\), which counts alternatives at or below the threshold. This is a well-defined complement, not an inverse: many distributions and contexts can produce the same count, so the original probabilities and input cannot be recovered from it.

The current provider is `onnx-community/distilgpt2-ONNX`. It measures DistilGPT2's next-token distribution for the recorded Lab context. It does **not** measure Kimi, Claude, Codex, correctness, safety, or action quality. Ordinary next-token probabilities also cannot supply the complete structured-action distribution required for the permitted-action variant.

## Optional dependencies

The measurement is optional and does not download a model during installation. Install the inference dependencies once:

```bash
python -m pip install 'gem-lab[measurement]'
```

The first measurement downloads the public DistilGPT2 ONNX model, tokenizer, and configuration from Hugging Face. GEM verifies their SHA-256 values before inference. No API credentials are required.

## CLI usage

Measure the current selection and recent evidence in an existing session:

```bash
gem measure --session /path/to/session
```

Emit the full JSON report:

```bash
gem measure --session /path/to/session --json
```

Use a custom threshold sweep:

```bash
gem measure --session /path/to/session --threshold 0.02 --threshold 0.10 --threshold 0.25
```

Evaluate proposed future actions independently:

```bash
gem measure --session /path/to/session \
  --candidate "Inspect the selected binary" \
  --candidate "Review the current evidence before choosing an action"
```

Each candidate receives a separate forward pass and strict-threshold counts. At most 16 candidates are accepted per measurement, and every candidate is validated before the present-context forward pass. The report includes deltas against the present context and a most-concentrated candidate for human review. Candidate concentration is advisory only: it is not a recommendation, correctness judgment, safety decision, or execution instruction.

## Accessible momentum

Consecutive measurements also expose per-threshold momentum:

\[
M_\tau(t)=A_\tau(S_t)-A_\tau(S_{t-1})
\]

Positive momentum means the forecast is broadening; negative momentum means it is narrowing. The default target band is `1`. Within that band, GEM suggests proceeding within the target band; larger positive deltas suggest broadening context, and larger negative deltas suggest narrowing context. Use `--momentum-band N` to change the band. A zero delta proceeds within the target band, while a smaller nonzero delta lets the current trend continue.

Momentum and its suggestion are advisory only. `executed` remains `false`, and no action is authorized or run. The first report has no momentum until another measurement exists.

## GUI usage

Open **Settings → Accessible Volume**. The measurement runs in the background so the workbench remains responsive. When it finishes, GEM saves and selects the separate evidence event, expands its details, and reports the count at the decision threshold. Subsequent measurements also display their momentum guidance beside the count.

## Evidence and reproducibility

Each measurement writes under the session's `accessible-volume/` directory:

- A JSON report containing the selected node and revision, model identity and artifact hashes, token count, threshold counts, complementary counts, normalized counts, top tokens, candidate deltas, previous report path, per-threshold momentum, target-band guidance, and the evidence event ID.
- An NPZ archive containing the present input IDs and full probability vector, plus candidate inputs and probability vectors when present.
- A separate `tool` evidence event linked to the selected Lab node, with status `partial` and an explicit scope that no interactive agent is measured and no action is authorized or executed.

Repeated measurements of identical context and candidates use a stable digest, making evidence idempotent. Changed selections, revisions, or candidate actions produce a different digest.

## NPZ VolumeBridge

`gem volume` replays a full-vocabulary NPZ distribution through `VolumeBridge`:

```bash
gem volume current.npz --previous earlier.npz --tau 0.05 --output momentum.json
```

The bridge has three stages: forward measurement, backward momentum guidance, and feedback into the next observation. It records UTC observation timestamps, monotonic elapsed nanoseconds, source/probability hashes, and no-overwrite feedback reports. Existing output files are never replaced. Supplying `--session` also emits a separate `tool` evidence event. `--key` and `--previous-key` select arrays independently; `--min-volume` and `--max-volume` add advisory target-volume steering without executing it.

Use `gem volume --probabilities current.npz --output artifact.json` for a standalone artifact report without session feedback. This interface requires `--output` and accepts the same independent key and target-volume options.

The [sacred-geometry experiment](../../experiments/sacred-geometry/README.md) adds an immutable image dataset, raw OCR, curated math transcription, component measurements, exact pixel vectors, a replayable Spatial IR scene, and a Procrustes landmark-alignment example.

## Limits

- The measurement describes forecast breadth only. It does not say which action is correct, safe, authorized, or worth executing.
- DistilGPT2's distribution is not the interactive agent's distribution and is not evidence of the agent's future correctness.
- A most-concentrated candidate is only the candidate with the smallest count at the decision threshold. It is not automatically the best candidate.
- Candidate actions are never run by the measurement path. Steering real actions requires a separate provider with complete permitted-action probabilities and a deterministic policy and human review.
- The structured-action variant \(B_\tau(S)\) remains unimplemented for interactive agents; it is not inferred from ordinary token probabilities.
