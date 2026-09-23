# Semantic Search

Behavioral fingerprint search over stripped binaries. No symbols required.

---

## SemanticSearcher

**File:** `ablation/analyzers/semantic_search.py`

Run this first on every new binary or new vulnerability class. SemanticSearcher encodes every
function as a behavioral fingerprint -- what it calls, what strings it references, what its
call-graph neighbors look like -- then matches queries in plain English.

Two functions performing the same operation (for example, "copy packet data into a fixed-size
buffer without length check") produce similar BERT embeddings even when they have different
opcodes, different VAs, and come from different firmware vendors. That cross-vendor matching
is the core capability.

### Build corpus and search

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher

ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Step 1: build behavioral descriptions into func_id.db
cb = CorpusBuilder()
n = cb.build('/path/to/binary.so', product='my-product', version='1.0')
print(f"  {n} functions described")

# Step 2: build BERT embeddings from the DB
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()   # ~35s for 19,000 functions on CPU; cached after first run

# Step 3: query
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  score={r.score:.3f}  {r.name or hex(r.va)}")
```

**Build time:** ~35 seconds for 19,000 functions on CPU.
**Query time:** under 1 second after corpus is built (cosine similarity over precomputed embeddings).
**Cache:** embeddings cached at `~/.ablation/cache/<sha256>_embeddings.npy`.

### Writing effective queries

Queries follow a structured format that steers BERT toward the right functional cluster:

```
<ROLE_HINT> | role=<function_role> | calls: <extern_calls> | vuln: <vuln_description>
```

| Part | Purpose | Example |
|---|---|---|
| Role hint | Cluster anchor -- limits search to protocol parsers, memory managers, etc. | `AV_PARSER`, `PROTOCOL_PARSER`, `OBJECT_MANAGER` |
| `role=` | Specific function role within the cluster | `tlv_advance`, `buffer_copy`, `allocation` |
| `calls:` | External functions this function calls | `memcpy memmove malloc free` |
| `vuln:` | The specific vulnerability in plain English | `zero-length field causes infinite loop` |

**Example queries:**

```python
# DoS: infinite loop on zero-length field
"PROTOCOL_PARSER | role=tlv_advance | calls: memcpy memmove | "
"vuln: TLV pointer advance loop with no minimum length check; "
"zero-length field causes infinite loop"

# DoS: record decode without minimum size check
"PROTOCOL_PARSER | role=record_decoder | calls: memcpy memmove | "
"vuln: record pointer advance without minimum record length check"

# Memory: stack buffer overflow
"AV_SCANNER | role=string_copy | calls: strcpy strcat sprintf | "
"vuln: strcpy or sprintf into fixed-size stack buffer without length check"

# Memory: integer overflow before allocation
"AV_SCANNER | role=allocation | calls: malloc realloc calloc | "
"vuln: integer multiplication or addition before malloc without overflow check"
```

### Score interpretation

| Score | Interpretation |
|---|---|
| >= 0.55 | Strong match -- triage immediately |
| 0.40 - 0.55 | Plausible match -- worth a quick callee and string check |
| 0.30 - 0.40 | Weak match -- skip unless no better candidates exist |
| < 0.30 | Noise |

Default threshold: 0.30. Raise to 0.40 on large binaries (>15,000 functions) to reduce noise.

---

## CorpusBuilder

**File:** `ablation/analyzers/corpus_builder.py`

Builds the behavioral description database (`func_id.db`) that SemanticSearcher encodes. Each
function record captures: PLT calls made, strings referenced, exported name if any, call-graph
neighbors, and size.

```python
from ablation.analyzers.corpus_builder import CorpusBuilder

cb = CorpusBuilder()

# Build for one binary
n = cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Build for an entire firmware image directory
n = cb.build_dir('/path/to/rootfs/', product='my-target', version='1.0',
                 extensions=['.so'])
```

**Output:** `~/.ablation/func_id.db` (SQLite). SemanticSearcher reads this on `build_corpus()`.

---

## PatternLibrary

**File:** `ablation/analyzers/pattern_library.py`

Every confirmed finding from any engagement registers a semantic query. On any future binary,
those queries replay automatically. The library grows with every engagement.

### Record a confirmed pattern

```python
from ablation.analyzers.pattern_library import PatternLibrary

pl = PatternLibrary()

pl.record_hit(
    query="TLV pointer advance loop with no minimum length check",
    binary_sha="<sha256_of_binary>",
    va=0x1000,
    confirmed=True,
    vuln_class="infinite_loop",
    cvss=7.5,
    notes="confirmed finding -- protocol parser",
)
```

### Sweep a new binary with all confirmed patterns

```python
pl_results = pl.sweep(searcher, top_k=8, min_score=0.30)
print(pl.fmt_sweep(pl_results, binary_name='target.so'))
```

Output shows each confirmed pattern, its CVSS score, and the top candidates in the new binary.
Patterns with CVSS >= 7.0 are highlighted for immediate triage.

### Pattern storage

Patterns are stored at `~/.ablation/patterns.json`. They are user-local and not committed to
git. `ablation/data/seed_corpus.json` ships pre-loaded patterns from published CVEs as a
starting corpus on first install.

### Running a sweep

Use the CLI or the `sweeps/base_sweep.py` entry point:

```bash
ablation sweep /path/to/target.so
ablation sweep /path/to/target.so --min-score 0.35 --top-k 10
ablation sweep /path/to/target.so --sarif results.sarif
```

Extend `VULN_PROFILES` in `sweeps/base_sweep.py` before sweeping against a new vulnerability
class.
