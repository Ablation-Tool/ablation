# Semantic Search

Behavioral fingerprint search over stripped binaries. No symbols required.

---

## Why this exists

Three things that weren't possible before in Ablation:

**1. Vulnerability class triage without symbols** -- On a stripped binary you had no function names
to grep, no type information, and no call-graph labels. Triage meant reading disassembly for every
function that might be relevant, which on a 19,000-function binary is not a triage -- it is
the whole job. SemanticSearcher lets you describe the vulnerability in English and get back the
5-10 functions most structurally similar to that description, before reading any disassembly.

**2. Cross-architecture pattern reuse** -- A heap overflow in an ARM32 MIPS router and the same
class of bug in an x86-64 BMC management daemon look completely different at the opcode level.
Without normalization, a pattern confirmed on one binary gives zero signal on another. The BinFuse
opcode categorization maps both to the same category sequence -- `ARITHMETIC_OP->COMPARISON_OP->
CONDITIONAL_OP` -- so a confirmed pattern from one vendor replays meaningfully on a different
architecture.

**3. Calibrated similarity scores** -- Raw BERT cosine similarity between unrelated functions runs
0.6-0.9 because BERT embeddings cluster near the mean of their manifold. That makes every function
look like every other function. The PCA whitening transform fixes this: after whitening, unrelated
pairs drop to 0.4-0.6 and true structural matches stay above 0.8, so the score threshold table
below is meaningful rather than arbitrary.

`SemanticSearcher` resolves all three with a single `query()` call after a one-time corpus build.

---

## How it works

The pipeline has five stages.

### Stage 1 -- The function database

The foundation is a SQLite database at `~/.ablation/func_id.db`. `CorpusBuilder` populates it
with one row per function, capturing: virtual address, name (if any), role, call targets (PLT
imports the function calls), string xrefs, and struct accesses. Only functions with
`confidence IN ('CONFIRMED', 'ANGR_INFERRED')` are indexed for semantic search; `CANDIDATE`
functions are excluded to avoid dead-code stubs and linker padding in the results.

### Stage 2 -- Assembly normalization

Before embedding, each function's disassembly is normalized to strip build-specific artifacts:

```
0x7ffff000    ->  <ADDR>      addresses vary per build / relocation
4096          ->  <IMM>       large immediates vary by compiler
rax / x0 / r3 ->  <REG>      register allocation varies by optimization level
```

Each opcode is then mapped to one of 11 semantic categories from the BinFuse taxonomy
(Chang et al., TrustCom 2025). The full table:

| Category | Representative opcodes |
|---|---|
| `ARITHMETIC_OP` | add, sub, mul, imul, udiv, sdiv, fadd, fsub, madd |
| `DATA_TRANSFER_OP` | mov, ldr, str, lea, push, pop, adrp, movz, ldp, stp |
| `COMPARISON_OP` | cmp, test, tst, fcmp, cmn |
| `LOGIC_OP` | and, or, xor, eor, bic, orn, andn, mvn |
| `BIT_SHIFT_OP` | shl, shr, sar, lsl, lsr, asr, ror |
| `UNCONDITIONAL_OP` | jmp, b, bl, call, ret, blr, bx, blx |
| `CONDITIONAL_OP` | je/jne, beq/bne, cbz/cbnz, tbz/tbnz |
| `MEMORY_MGMT_OP` | rep/movs/stos, prefetch, clflush, nop, mfence |
| `PROCESSOR_STATE_OP` | pushf/popf, cpuid, rdtsc, mrs/msr, svc, hlt |
| `SYNCHRONIZATION_OP` | lock/xadd, cmpxchg, dmb/dsb/isb, ldaxr/stlxr |
| `VECTOR_MGMT_OP` | vmovdqu, vpaddb, vpcmpeq, ld1/st1 (ARM NEON) |

This makes the encoding cross-architecture. x86's `mov rax, [rbp-8]` and ARM64's
`ldr x0, [sp, #8]` both produce `DATA_TRANSFER_OP`. A network parser written for MIPS32 and
the same parser recompiled for AArch64 produce the same category sequence.

After per-instruction mapping, a Markov transition string is appended:

```python
# Top-5 most frequent adjacent-category transitions
pairs = Counter(f"{cats[i]}->{cats[i+1]}" for i in range(len(cats)-1))
# Output: "DATA_TRANSFER_OP->ARITHMETIC_OP(12) ARITHMETIC_OP->COMPARISON_OP(7) ..."
```

The transitions capture behavioral rhythm. A bounds-checking loop has a distinctive
`ARITHMETIC_OP->COMPARISON_OP->CONDITIONAL_OP` cycle that raw instruction sequence does not
encode as compactly. A memcpy-style loop looks like `DATA_TRANSFER_OP->ARITHMETIC_OP->
CONDITIONAL_OP` repeating. Two functions with the same transition profile are structurally
similar regardless of which registers or immediates they use.

### Stage 3 -- Description construction

The normalized assembly is not fed to the model alone. It is combined with the function's
metadata into a single text string:

```
{name} role={role} | calls: {call_targets[:12]} | strings: {string_xrefs[:8]} | asm: {normalized_asm}
```

The `calls:` and `strings:` fields carry the most signal on stripped binaries. A function that
calls `malloc`, `strcpy`, and `syslog` and references `"auth failed"` is described as exactly
that, regardless of its own opcode mix. For deeply stripped binaries with no string xrefs, the
normalized assembly category sequence and Markov transitions carry the full load.

Operand type normalization follows BinDeep (Tian et al., 2020): keeping memory reference
patterns (`MEM[REG]`, `MEM[REG+IMM]`) alongside category labels adds approximately 1.2% F1
over opcode-only encoding (BinDeep Table 3).

### Stage 4 -- Embedding and whitening

The model is `sentence-transformers/all-mpnet-base-v2` (768 dimensions). Every description in
the corpus is encoded once at build time:

```python
vectors = model.encode(descriptions, normalize_embeddings=True, batch_size=64)
```

`normalize_embeddings=True` places every embedding on the unit sphere, so similarity is a dot
product -- which is fast. But raw BERT embeddings are anisotropic: they cluster near the mean
of the embedding manifold, which causes unrelated sentences to score 0.6-0.9 cosine similarity.
Without correction, nearly every function in a large corpus looks similar to every query.

The `WhiteningTransform` class corrects this using PCA whitening (Su et al., 2021):

```python
# Fit on the corpus's own embedding matrix (N x 768)
cov = np.cov(embeddings.T)
vals, vecs = np.linalg.eigh(cov)              # eigendecomposition of covariance
W = vecs @ np.diag(1.0 / np.sqrt(vals))       # whitening matrix

# Apply: subtract mean, rotate, rescale, re-normalize to unit sphere
whitened = (embeddings - mean) @ W
whitened /= np.linalg.norm(whitened, axis=-1, keepdims=True)
```

After whitening, the distribution is isotropic -- the same variance in every direction. Generic
pairs drop to 0.4-0.6 and true structural matches stay above 0.8. This is what makes the score
threshold table meaningful.

The whitened vectors and metadata are cached as a pickle at
`~/.ablation/func_semantic_cache_{hash}.pkl`, keyed on the SHA-256 of `func_id.db`. The cache
invalidates automatically when the database changes.

### Stage 5 -- Query

```python
def query(self, description: str, top_k: int = 5):
    q = model.encode(description, normalize_embeddings=True)
    scores = self._vectors @ q                         # matrix-vector dot product
    idx = np.argpartition(scores, -top_k)[-top_k:]    # O(N) -- no full sort needed
    idx = idx[np.argsort(scores[idx])[::-1]]           # sort only the top-k slice
    return [SimilarFunction(...) for i in idx]
```

`np.argpartition` is O(N) rather than O(N log N) because it only guarantees the top-k positions
are in place -- it does not sort the rest of the array. For a 10,000-function corpus this takes
roughly 10ms on CPU. The full sort is then applied only to the top-k slice, which is cheap.

You query with natural language:

```python
results = searcher.query(
    "RADIUS packet length field copied to fixed stack buffer without bounds check"
)
```

The model maps the English description to the same embedding space as the normalized assembly
descriptions. The corpus entries most structurally similar to your description -- by callee
fingerprint, string xrefs, opcode category sequence, and Markov transitions -- surface at the top.

---

## SemanticSearcher

**File:** `ablation/analyzers/semantic_search.py`

Run this first on every new binary or new vulnerability class. Two functions performing the same
operation produce similar embeddings even when they have different opcodes, different VAs, and
come from different vendors. That cross-vendor matching is the core capability.

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

### Ingest confirmed findings from FindingRegistry (flywheel)

`ingest_from_registry()` pulls every confirmed finding from a `FindingRegistry` and adds it
as a pattern. Call this at the start of each engagement to pull in all past confirmed findings
without any manual `pl.add()` calls.

```python
from ablation.analyzers.finding_registry import FindingRegistry
from ablation.analyzers.pattern_library import PatternLibrary

reg = FindingRegistry()
pl  = PatternLibrary()

n = pl.ingest_from_registry(reg)  # idempotent -- only adds findings not already present
print(f"{n} new patterns ingested")

pl_results = pl.sweep(searcher, top_k=8, min_score=0.30)
print(pl.fmt_sweep(pl_results, binary_name='target.so'))
```

`ingest_from_registry()` accepts any object with an `export_patterns()` method -- no hard
import of `finding_registry` at module level, so `PatternLibrary` remains independently
usable.

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
