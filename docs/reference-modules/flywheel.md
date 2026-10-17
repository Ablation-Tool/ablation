# The Flywheel

Every confirmed finding becomes a search pattern. Every new engagement runs all prior confirmed findings automatically.

---

## Why this exists

Two things went wrong before the flywheel existed:

**1. Confirmed findings died at the end of an engagement.** After a long engagement with 30 confirmed findings, none of that work carried forward. The next binary started from zero. `PatternLibrary` existed but required explicit `pl.add()` calls to register each pattern, and backfilling 30 entries at close-out was a tax on finishing the work. `ingest_from_registry()` eliminates that: one call at the start of any engagement pulls every confirmed finding from every prior target.

**2. Cross-architecture pattern reuse was not possible.** A heap overflow confirmed in an ARM32 router looks completely different at the opcode level from the same class of bug in an x86-64 BMC. Without normalization, a confirmed pattern gave zero signal on a different architecture. BinFuse opcode categorization maps both to the same category sequence so a pattern confirmed on one vendor replays on a completely different architecture without any manual re-authoring.

---

## How it works

The flywheel has two halves: storage and replay.

**Storage** happens when you confirm a finding. `FindingRegistry.register()` writes the finding to a local SQLite database at `~/.ablation/findings.db`. Each record carries the vendor, product, version, title, description, CWE class, severity, function address, and an optional BERT embedding vector.

**Replay** happens at the start of each new engagement. `PatternLibrary.ingest_from_registry()` reads every confirmed finding from the database and adds it as a semantic search pattern. `sweep()` then runs all patterns against the new binary. Confirmed findings from one vendor run against a completely different vendor's binary. Confirmed findings from x86-64 run against ARM32. The tool gets sharper with each engagement.

```mermaid
flowchart LR
    A["Confirm finding\nFindingRegistry.register()"] --> B[("~/.ablation/findings.db\nSQLite · all vendors · all targets")]
    B --> C["Next engagement\nPatternLibrary.ingest_from_registry()"]
    C --> D["pl.sweep(searcher)\nAll confirmed patterns run\nagainst the new binary"]
    D --> E["New confirmed finding\nFindingRegistry.register()"]
    E --> B
```

---

## The pipeline

### Step 1: Register a confirmed finding

```python
from ablation.analyzers.finding_registry import FindingRegistry

reg = FindingRegistry()

reg.register(
    vendor='example_vendor',
    product='example_product',
    version='1.0.0',
    binary='httpd',
    title='Pre-auth SQL injection via Bearer token',
    description='PROTOCOL_PARSER | role=bearer_token_handler | calls: sqlite3_exec | '
                'vuln: unsanitized token value reaches SQL sink without bounds check',
    cwe_class='CWE-89',
    severity='CRITICAL',
    func_addr=0x4a1c30,
    embedding=func_embedding_vector,
)
```

### Step 2: Load confirmed patterns at engagement start

```python
from ablation.analyzers.finding_registry import FindingRegistry
from ablation.analyzers.pattern_library import PatternLibrary
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.binary_context import BinaryContext

reg = FindingRegistry()
pl  = PatternLibrary()
ctx = BinaryContext.load_or_build('/path/to/new_binary.so')

# Pull all confirmed findings into the pattern library (idempotent)
n = pl.ingest_from_registry(reg)
print(f"{n} new patterns loaded from confirmed findings")

# Build the semantic corpus for the new binary
searcher = SemanticSearcher.from_context(ctx)

# Sweep: confirmed patterns from every prior engagement run automatically
results = pl.sweep(searcher)
for tag, hits in results.items():
    for va, score in hits:
        print(f"  [{tag}] {ctx.name(va)} @ {va:#x}  score={score:.3f}")
```

`ingest_from_registry()` is idempotent. Calling it again at the start of a later session adds only findings registered since the previous call.

### Step 3: Find structurally similar prior findings

```python
# Query the registry directly for a function embedding
embedding = searcher.embed_function(va)
hits = reg.find_similar(embedding, top_k=8, min_sim=0.60)
for h in hits:
    print(f"  {h.vendor}/{h.product} {h.version}  {h.title}  ({h.severity})")
```

---

## Cross-architecture normalization

BinFuse maps opcodes to 11 behavioral categories before encoding. The category sequence for a heap overflow confirmation in ARM32 (`ARITHMETIC_OP->COMPARISON_OP->CONDITIONAL_OP->MEMORY_OP`) is the same as the sequence for the same class in x86-64 BMC firmware. The BERT embedding trained on these normalized sequences produces similar vectors for structurally similar functions regardless of ISA, so `find_similar()` returns cross-architecture matches without any ISA-specific handling.

---

## Seed corpus

`ablation/data/seed_corpus.json` ships pre-loaded with patterns derived from published CVEs. These seed the flywheel on first install so the pattern library is not empty on a fresh engagement. Confirmed findings from your own work layer on top of the seeds.

---

## Storage

| Path | Contents |
|---|---|
| `~/.ablation/findings.db` | SQLite database of all confirmed findings. User-local, not committed to git. |
| `~/.ablation/pattern_library.json` | Ingested patterns from confirmed findings. Auto-updated by `ingest_from_registry()`. |
| `ablation/data/seed_corpus.json` | Published-CVE seed patterns shipped with the tool. |

---

## API reference

| Call | Description |
|---|---|
| `FindingRegistry.register(...)` | Store a confirmed finding |
| `FindingRegistry.find_similar(embedding, top_k, min_sim)` | Retrieve structurally similar prior findings |
| `FindingRegistry.export_patterns()` | Return all confirmed findings as `[{query, tag}]` dicts for manual `pl.add()` |
| `FindingRegistry.stats()` | Finding count by vendor, product, and CWE class |
| `FindingRegistry.list_findings(vendor=None)` | List all findings, optionally filtered |
| `PatternLibrary.ingest_from_registry(reg)` | Pull all confirmed findings into the pattern library (idempotent) |
| `PatternLibrary.sweep(searcher)` | Run all confirmed patterns against the current binary |
| `PatternLibrary.record_hit(tag, binary, va, confirmed=True)` | Mark a sweep hit as confirmed |

See [Registry Modules](registry.md) for the full `FindingRegistry` and `NameRegistry` API.

---

## Usage

```python
from ablation.analyzers.engine_pattern_library import EnginePatternLibrary

lib = EnginePatternLibrary.default()
labels = lib.label_binary(ctx)
for va, label in sorted(labels.items()):
    if label.confidence >= 0.80:
        print(f"  {va:#x}  {label.engine}  conf={label.confidence:.2f}")
```

---

## Example output

```
# Output varies by module. See Usage section for representative examples.
```

---

## False positives

Core infrastructure modules do not emit security findings directly. False positives in downstream scanners are addressed at the scanner level, not here.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` to build the analysis session.

**After this module:** Results feed directly into the analysis pipeline: `SemanticSearcher`, `TaintTracker`, or output modules depending on the task.

---

## Reading output

The flywheel has no single output type — it is an operational loop between three modules:

1. `EnginePatternLibrary.label_binary(ctx)` → `Dict[int, EngineLabel]` — engine-code labels stripped from the target
2. `PatternLibrary.sweep(ctx)` → confirmed and unconfirmed finding candidates from prior session patterns
3. `FindingRegistry.register(...)` → persists confirmed findings as new search patterns

See [Cross-Target Learning](cross-target-learning.md) for `EngineLabel` field details and [Finding Validation](finding-validation.md) for `PathResult` details.

---

## See also

- [BinaryContext](binary-context.md) — session foundation for all analysis
- [SemanticSearch](semantic-search.md) — function candidate identification
- [FindingRegistry](registry.md) — persistent finding storage
