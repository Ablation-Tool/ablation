# Cross-Target Learning

Every confirmed finding becomes a semantic search pattern. The tool gets sharper with each engagement without any manual pattern management.

---

## Why this exists

Two things went wrong before the flywheel existed:

**1. Confirmed findings did not carry forward.**
After confirming a heap overflow in Fortinet firmware, the next engagement on a different vendor's MIPS32 binary started from zero. The query that found the Fortinet bug was sitting in a session transcript, not in any searchable form. Repeating the same class of vulnerability on a new target required rediscovering the right query from memory.

**2. Pattern management was manual.**
`PatternLibrary` existed but required explicit `pl.add()` calls to register each pattern. After a long engagement with 30 confirmed findings, backfilling 30 pattern entries was a tax on closing out the work. `ingest_from_registry()` eliminates that: one call at the start of any engagement pulls in every confirmed finding from every prior target.

---

## How it works

### Full flywheel pipeline

```
  Engagement N (e.g., Fortinet ASA, x86-64)
          |
          | TaintTracker confirms heap overflow in auth_radius_parse
          v
  ┌────────────────────────────────────────────────────────────┐
  │  FindingRegistry.register(                                 │
  │    vendor='fortinet', product='fortigate', version='7.4.1',│
  │    title='RADIUS overflow in auth_radius_parse',           │
  │    description='recv output used as memcpy size without    │
  │                 upper bound check',                        │
  │    cwe_class='CWE-122',                                    │
  │    severity='CRITICAL',                                    │
  │    embedding=model.encode(description),   <- BERT vector   │
  │    func_addr=0x4000,                                       │
  │    binary='/path/to/lina',                                 │
  │  )                                                         │
  └───────────────────────────┬────────────────────────────────┘
                              |
                              v
  ~/.ablation/findings.db  (SQLite, persists forever)
    table: findings
      id, vendor, product, version, title, description,
      cwe_class, severity, func_addr, binary,
      embedding BLOB (768 float32 values, all-mpnet-base-v2)


  Engagement N+1 (e.g., Huawei VRP, different vendor, different arch)
          |
          v
  ┌────────────────────────────────────────────────────────────┐
  │  PatternLibrary.ingest_from_registry(reg)                  │
  │                                                            │
  │  reg.export_patterns():                                    │
  │    for each row in findings.db:                            │
  │      yield {query: title + '. ' + description,             │
  │             tag: cwe_to_tag[cwe_class]}                    │
  │                                                            │
  │  CWE-to-tag mapping (auto-applied):                        │
  │    CWE-122 → 'heap_overflow'                               │
  │    CWE-77  → 'command_injection'                           │
  │    CWE-134 → 'format_string'                               │
  │    CWE-416 → 'use_after_free'                              │
  │    CWE-120 → 'buffer_overflow'                             │
  │                                                            │
  │  idempotent: hashes each (query, tag) pair before adding   │
  │  skips any pattern already in patterns.json                │
  └───────────────────────────┬────────────────────────────────┘
                              |
                              v
  ~/.ablation/patterns.json  (grows with every engagement)
    [
      {"query": "RADIUS overflow ...", "tag": "heap_overflow"},
      {"query": "command injection via ...", "tag": "command_injection"},
      ...
    ]
          |
          v
  ┌────────────────────────────────────────────────────────────┐
  │  PatternLibrary.sweep(searcher, top_k=8, min_score=0.30)   │
  │                                                            │
  │  for each pattern in patterns.json:                        │
  │    q_vec = model.encode(pattern.query)                     │
  │    scores = corpus_matrix @ q_vec    (cosine similarity)   │
  │    top_k  = np.argpartition(scores, -top_k)[-top_k:]       │
  │    → candidates ranked by similarity to this pattern       │
  │                                                            │
  │  output: {pattern_tag: [(score, func_id, func_name), ...]} │
  │    one ranked list per pattern                             │
  └───────────────────────────┬────────────────────────────────┘
                              |
                              v
  PatternLibrary.fmt_sweep(results, binary_name)
    format ranked candidates per CVSS score
    CVSS >= 7.0 → highlighted for immediate triage
```

### How embeddings enable cross-vendor matching

The BERT embedding (all-mpnet-base-v2, 768 dimensions) encodes the semantic meaning of a function description rather than its literal text. Two descriptions that say the same thing in different words produce similar vectors. A Fortinet finding described as "recvfrom output length used as strcpy size argument without validation" and a Huawei finding described as "network read byte count flows to string copy operation as size parameter" produce vectors with cosine similarity above 0.80 after PCA whitening. The semantic sweep surfaces the Huawei function as a candidate because the underlying vulnerability pattern is the same, even though no word is shared between the two descriptions.

This is the core of cross-target pattern reuse: vulnerability classes map to regions of embedding space, and those regions are consistent across vendors because the description of a heap overflow in Fortinet firmware is semantically close to the description of a heap overflow in Huawei firmware.

### FindingRegistry similarity search

```python
similar = reg.find_similar(new_embedding, top_k=8, min_sim=0.60)
```

`find_similar` loads all embeddings from `findings.db`, computes cosine similarity against `new_embedding`, and returns the top-k rows above `min_sim`. This lets you ask: "What confirmed findings from prior engagements look like this new candidate?" The result guides manual triage: if the top match is a CWE-122 heap overflow confirmed in TencentOS, the candidate deserves the same level of scrutiny before ruling it out.

---

## Pattern storage

```
  ~/.ablation/patterns.json     user-local; not committed to git
  ~/.ablation/findings.db       SQLite; all confirmed findings and embeddings
  ablation/data/seed_corpus.json  ships with Ablation; published CVEs as seed patterns
```

The seed corpus provides signal on the first engagement against any binary class (network daemons, BMC firmware, kernel drivers). Engagement findings supplement and refine it over time.

---

## Engagement start recipe

```python
from ablation.analyzers.finding_registry import FindingRegistry
from ablation.analyzers.pattern_library import PatternLibrary
from ablation.analyzers.semantic_search import SemanticSearcher

reg      = FindingRegistry()
pl       = PatternLibrary()
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Pull in all prior confirmed findings
n = pl.ingest_from_registry(reg)
print(f"{n} new patterns ingested from {reg.count()} total findings")

# Sweep the new binary with every confirmed pattern from every prior target
results = pl.sweep(searcher, top_k=8, min_score=0.30)
print(pl.fmt_sweep(results, binary_name='target.so'))
```

Running this at the start of every engagement means the tool's accumulated knowledge from all prior targets is applied to the new binary in one pass, before any manual analysis begins.
