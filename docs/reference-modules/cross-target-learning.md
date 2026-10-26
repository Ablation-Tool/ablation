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

### The flywheel pipeline

```mermaid
flowchart TD
    A(["Engagement N\nTaintTracker confirms heap overflow\nin auth_radius_parse (Fortinet, x86-64)"]):::input --> B["FindingRegistry.register()\nvendor='fortinet' · product='fortigate'\ncwe_class='CWE-122' · severity='CRITICAL'\nembedding = model.encode(description)\n← BERT vector, 768 dims"]:::primary

    B:::primary --> C["~/.ablation/findings.db\nSQLite: persists forever\nfields: vendor · product · title\ndescription · cwe_class · severity\nfunc_addr · binary · embedding BLOB"]:::secondary

    C:::secondary --> D["Engagement N+1\nNew vendor, different architecture\n(e.g., Huawei VRP, MIPS32)"]:::tertiary

    D:::tertiary --> E["PatternLibrary.ingest_from_registry(reg)\nreg.export_patterns():\n  for each row → yield query + tag\nCWE-to-tag: CWE-122 → heap_overflow\nIdempotent: hashes (query, tag) pairs\nSkips patterns already present"]:::tertiary

    E:::tertiary --> F["~/.ablation/patterns.json\nGrows with every engagement\n[{query, tag}, ...]"]:::tertiary

    F:::tertiary --> G["PatternLibrary.sweep(searcher, top_k=8, min_score=0.30)\nFor each pattern: q_vec = model.encode(query)\nscores = corpus_matrix @ q_vec  (cosine similarity)\ntop_k = argpartition(scores, -top_k)"]:::tertiary

    G:::tertiary --> H(["Output: {tag: [(score, func_id, name), ...]}\nCVSS ≥ 7.0 highlighted for immediate triage"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
```

### How embeddings enable cross-vendor matching

The BERT embedding all-mpnet-base-v2, 768 dimensions encodes the semantic meaning of a function description rather than its literal text. Two descriptions that say the same thing in different words produce similar vectors.

A Fortinet finding described as "recvfrom output length used as strcpy size argument without validation" and a Huawei finding described as "network read byte count flows to string copy operation as size parameter" produce vectors with cosine similarity above 0.80 after PCA whitening. The semantic sweep surfaces the Huawei function as a candidate because the underlying vulnerability pattern is the same, even though no word is shared between the two descriptions.

This is the core of cross-target pattern reuse: vulnerability classes map to regions of embedding space. Those regions are consistent across vendors because the description of a heap overflow in Fortinet firmware is semantically close to the description of a heap overflow in Huawei firmware.

### FindingRegistry similarity search

```python
similar = reg.find_similar(new_embedding, top_k=8, min_sim=0.60)
```

`find_similar` loads all embeddings from `findings.db`, computes cosine similarity against `new_embedding`, and returns the top-k rows above `min_sim`. This lets you ask: "What confirmed findings from prior engagements look like this new candidate?" If the top match is a CWE-122 heap overflow confirmed in TencentOS, the candidate deserves the same scrutiny before ruling it out.

---

## Pattern storage

| Path | Purpose |
|---|---|
| `~/.ablation/patterns.json` | User-local; not committed to git; grows with each engagement |
| `~/.ablation/findings.db` | SQLite; all confirmed findings with embeddings |
| `ablation/data/seed_corpus.json` | Ships with Ablation; published CVEs as seed patterns |

The seed corpus provides signal on the first engagement against any binary class network daemons, BMC firmware, kernel drivers. Engagement findings supplement and refine it over time.

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

---

## Usage

```python
from ablation.analyzers.cross_binary_taint import CrossBinaryTaintTracker

tracker = CrossBinaryTaintTracker.from_lib_graph(lib_graph, entry_binary='/path/to/main', max_hops=6)
chains = tracker.run()
for chain in chains:
    print(chain)
```

---

## Example output

```
pl.ingest_from_registry(reg)
  28 new patterns ingested (3 already present, skipped)
  total patterns: 31

pl.sweep(searcher, top_k=8, min_score=0.30)
  heap_overflow (CWE-122):
    0.84  fn_0x2a100  (auth_radius_parse)
    0.71  fn_0x31400  (process_dhcp_option)
    0.68  fn_0x44200  (parse_snmp_varbind)
  command_injection (CWE-78):
    0.79  fn_0x58000  (exec_cli_command)
  [2 patterns: no hits above 0.30]
```

---

## False positives

**High sweep scores on non-vulnerable functions**: `PatternLibrary.sweep()` uses a minimum score threshold default 0.30 that is intentionally low. Many functions that score above 0.30 will not have the targeted vulnerability; the sweep produces candidates for manual review, not confirmed findings. Raise `min_score` to 0.50–0.60 if the candidate list is too large for triage.

**Patterns that over-match a broad function class**: a confirmed finding described with generic terms for example "reads from network socket into buffer" will match many network-receive functions. Descriptions that include the specific error pattern for example "reads attacker-controlled byte count into fixed-size stack buffer without bounds check" produce more targeted patterns and fewer false candidates.

---

## Pipeline position

**Before this module:** `CorpusBuilder.build()` to build the function corpus DB, and `SemanticSearcher.build_corpus()` to load the embedding matrix. `FindingRegistry` must have at least one confirmed finding before `ingest_from_registry()` adds any patterns.

**After this module:** `PatternLibrary.sweep()` results feed directly into candidate prioritization. High-score functions above 0.60 proceed to `FuncProfiler.profile()` and then `TaintTracker.run()`. Low-score functions can be deprioritized without losing confirmed findings from prior engagements.

---

## Reading output

`PatternLibrary.sweepsearcher, top_k, min_score` returns `dict[str, list[tuple[float, int, str]]]`: tag → list of `score, func_id, name` tuples sorted by descending score:

| Element | Content |
|:---|:---|
| `score` | Float: cosine similarity between the pattern query embedding and the function's corpus embedding |
| `func_id` | Integer corpus DB row ID for the matched function |
| `name` | Function name from the corpus overlay name, export, PLT, or hex VA string |

`FindingRegistry.find_similarembedding, top_k, min_sim` returns `list[dict]`: each dict is a row from `findings.db`:

| Key | Content |
|:---|:---|
| `vendor` | Target vendor name |
| `product` | Target product name |
| `title` | Finding title |
| `cwe_class` | CWE identifier |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `similarity` | Float: cosine similarity to the query embedding |

---

## See also

- [BinaryContext](binary-context.md): session foundation for all analysis
- [SemanticSearch](semantic-search.md): function candidate identification
- [FindingRegistry](registry.md): persistent finding storage
