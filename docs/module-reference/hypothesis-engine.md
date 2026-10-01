# Hypothesis Engine

Active hypothesis-driven orchestration for binary reverse engineering.

**Modules:**
- `ablation.analyzers.hypothesis_models` — data model + JSON persistence
- `ablation.analyzers.evidence_scorer` — confidence scoring + state transitions
- `ablation.analyzers.probe_ranker` — probe candidate generation + ranking
- `ablation.analyzers.hypothesis_engine` — session lifecycle + orchestration

---

## Purpose

The hypothesis engine maintains competing explanations for an observation,
scores evidence against each, and selects the most discriminating probe to run
next. It replaces ad-hoc manual analysis with an auditable, reproducible process.

This is Phase 2 of the Active Architecture Tomography plan. BinaryLifter
(Phase 1) feeds evidence into the engine. QEMU dynamic probing (Phase 3) will
extend it with runtime behavioral evidence.

---

## Quick start

```python
from ablation.analyzers.hypothesis_engine import HypothesisEngine

engine = HypothesisEngine.from_binary('/path/to/binary', architecture='arm64')

# Seed competing hypotheses
h_yes, h_no = engine.seed(
    kind='indirect_call_target',
    subject={'call_site_va': '0x401920'},
    claims=[
        {'target_va': '0x4026c0'},
        {'target_va': '0x403110'},
    ],
    prior=0.5,
)

# Record evidence from existing analyzers
engine.add_evidence(
    analyzer='ARM64TaintTracker',
    family='data_flow',
    subject={'va': '0x4026c0'},
    observation={'source_to_sink': True, 'path_length': 3},
    relation='supports',
    hypothesis_ids=[h_yes.id],
    strength=0.80,
)

# Plan next probes (dry run)
print(engine.plan())

# Get full report
print(engine.report())

# Save session to ~/.ablation/sessions/
engine.save()
```

---

## Confidence states

| State | Meaning |
|---|---|
| `UNTESTED` | No meaningful evidence |
| `PLAUSIBLE` | Weak or single-family support |
| `SUPPORTED` | Multiple independent families agree |
| `CONFIRMED` | Decisive test or trusted ground truth |
| `UNRESOLVED` | Two or more hypotheses observationally equivalent |
| `REJECTED` | Hard contradiction invalidates the claim |

`CONFIRMED` requires: confidence ≥ 0.75 + at least one structural/data_flow/behavioral
evidence item + two independent families + no hard contradiction.

---

## Evidence families and weights

| Family | Weight | Examples |
|---|---|---|
| `behavioral` | 1.00 | Runtime traces, emulator output |
| `data_flow` | 0.90 | Taint paths, use-def chains |
| `structure` | 0.75 | CFG, instruction boundaries |
| `cross_reference` | 0.65 | Strings, PLT, callers/callees |
| `version` | 0.60 | Jaccard, DTW, structural homologs |
| `manual` | 0.50 | Analyst observation with provenance |
| `semantic` | 0.25 | Embeddings, function similarity |

Evidence from the same family uses diminishing returns: each additional item
from the same family contributes `1 / (1 + ln(count))` of its base weight.

---

## Hypothesis kinds

```
code_region          data_region          function_entry
function_boundary    indirect_call_target memory_region
input_source         security_sink        source_to_sink_path
version_homolog      architecture_mode
```

---

## API reference

### HypothesisEngine

```python
# Constructors
engine = HypothesisEngine.from_binary(binary_path, architecture='arm64')
engine = HypothesisEngine.load('~/.ablation/sessions/S-abc123.json')

# Seed hypotheses
hypotheses = engine.seed(kind, subject, claims=[...], prior=0.5)
hypothesis  = engine.seed_one(kind, subject, claim, prior=0.5)

# Add evidence (updates confidence immediately)
ev = engine.add_evidence(
    analyzer, family, subject, observation,
    relation='supports'|'contradicts'|'neutral',
    hypothesis_ids=[...],
    strength=0.5..1.0,
)
ev = engine.add_hard_contradiction(analyzer, family, subject, observation, hypothesis_ids, explanation)

# Planning (no execution)
plan_str = engine.plan(top_n=5)
probe    = engine.next_probe()

# Stepping (Milestone 3 will execute; now records probe for analyst)
probe = engine.step(kind='cfg', approved=True)
steps = engine.run_until_stable(max_steps=8)

# Reporting
report_str = engine.report()
engine.save()
engine.export_report('/path/to/output.json')
```

### HypothesisRecord

```python
h = HypothesisRecord.create(kind, subject, claim, prior=0.5, notes='')
# Fields: id, kind, subject, claim, status, prior, confidence,
#         support_score, contradiction_score, evidence_ids, ...
```

### EvidenceRecord

```python
ev = EvidenceRecord.create(
    analyzer, family, subject, observation, relation,
    hypothesis_ids, strength=0.5, reliability=None,
    artifact_hashes=[], parameters={}, source_location=None,
)
# contribution() = strength * reliability * independence_factor
```

### ProbeRecord

```python
p = ProbeRecord.create(
    kind, target_hypothesis_ids, analyzer, parameters={},
    estimated_cost=1.0, observability=0.8, predicted_disagreement=0.5,
)
# expected_information_gain = disagreement * observability / cost
p.mark_executed(evidence_ids)
```

### EvidenceScorer

```python
scorer = EvidenceScorer(configuration={'family_weights': {...}})
confidence, status, contradiction_notes = scorer.score(hypothesis, evidence_items)
scorer.update_hypothesis(hypothesis, evidence_items)  # writes scores back in place
print(score_report(hypothesis, evidence_items))
```

### ProbeRanker

```python
ranker = ProbeRanker()
probes = ranker.generate(hypotheses, executed_kinds=[], max_candidates=10)
probe  = ranker.top_probe(hypotheses)
print(ranker.plan_report(hypotheses, top_n=5))
```

---

## Probe kinds

| Kind | Analyzer | Cost | Observability |
|---|---|---|---|
| `disassembly` | Capstone | 0.5 | 0.95 |
| `xref` | XRefGraph | 0.8 | 0.85 |
| `cfg` | CFGBuilder | 1.0 | 0.90 |
| `lifter` | BinaryLifter | 1.5 | 0.80 |
| `semantic` | SemanticSearcher | 2.0 | 0.60 |
| `version` | DTWMatcher | 2.5 | 0.70 |
| `taint` | ARM64TaintTracker | 3.0 | 0.80 |
| `manual` | analyst | 10.0 | 1.00 |

---

## Session persistence

Sessions are saved to `~/.ablation/sessions/<session_id>.json` by default.
They contain the full binary hash, all hypotheses, all evidence (with
provenance), and all probes. Sessions are reproducible from the binary
and the probe parameter set.

```python
engine.save()
engine2 = HypothesisEngine.load('~/.ablation/sessions/S-abc123.json')
```

---

## Design notes

The scoring formula uses explicit deterministic weights, not an ML model.
`CONFIRMED` is a state transition rule, not a confidence threshold crossing.
Contradictions are hard-faulted (strength ≥ 0.80 immediately REJECTS).
Semantic evidence (embeddings) carries 0.25 weight — useful for prioritization,
insufficient for confirmation.

See `active-hypothesis-engine-plan.md` in `docs/` for the full design spec.
