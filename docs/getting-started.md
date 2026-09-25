# Getting Started

Go from install to your first vulnerability candidate in 15 minutes. Any stripped ELF binary
works.

---

## Install

**Requirements:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

With LLM features:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

From source:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Verify the install:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Step 1: Load your binary

`BinaryContext` is the entry point for all analysis. Pass any stripped ELF binary:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**First run:** 0.5 to 5 seconds depending on binary size. Ablation builds and caches to
`~/.ablation/cache/<sha256>_<name>.json`.

**Every subsequent run:** 110 ms. The cache is keyed by SHA256 -- a different build of the
same binary name rebuilds automatically.

Example output:

```
BinaryContext: libservice.so
  sha256     : fdfaceccdc740d82...
  base_va    : 0x0
  func_starts: 19024
  exports    : 14
  plt entries: 187
  strings    : 44821
  call_edges : 58903
  str_xrefs  : 218440 pairs indexed
  named funcs: 0 (overlay)
```

---

## Step 2: Run a semantic sweep

The sweep is the core workflow. It encodes all functions as BERT behavioral fingerprints and
queries by vulnerability description in plain English. Use `sweeps/base_sweep.py` as a
template, or build your own:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Build behavioral description corpus into func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Build BERT embeddings (~35s for 19k functions on CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Query by vulnerability description
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Expected run time:** 35 to 60 seconds for 19,000 functions on CPU. Subsequent queries
against the same corpus run in under one second -- embeddings are cached.

---

## Step 3: Triage candidates

For each high-scoring candidate, get its context:

```python
va = 0x1000  # candidate VA from sweep results

# What does this function call?
print("callees:", ctx.callees_of(va))

# What strings does it reference?
print("strings:", ctx.strings_in_func(va))

# What calls into it?
print("callers:", ctx.callers_of(va))
```

Most candidates take two to three minutes to triage this way. If the callee list contains
memory functions (`memcpy`, `malloc`, `free`) and the caller chain reaches a network entry
point, proceed to manual trace.

---

## Step 4: Name confirmed functions

When you identify a function's purpose, register its name. Names persist across sessions and
appear in all subsequent analysis output:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Names appear everywhere:
print(ctx.callees_of(0x1000))   # labels instead of hex addresses
print(ctx.names_table())           # all named functions in this binary
```

Names are stored at `~/.ablation/function_names.json`, keyed by binary SHA256. They survive
session restarts, binary moves, and system reboots.

---

## Step 5: Register confirmed patterns

When you confirm a real vulnerability, register the query that found it. It replays on future
binaries automatically:

```python
from ablation.analyzers.pattern_library import PatternLibrary

pl = PatternLibrary()
pl.record_hit(
    query="TLV pointer advance loop with no minimum length check",
    binary_sha="fdfaceccdc740d82",
    va=0x1000,
    confirmed=True,
    vuln_class="infinite_loop",
    cvss=7.5,
)
```

On any future sweep -- different firmware version, different vendor -- `pl.sweep(searcher)`
runs all confirmed patterns automatically.

---

## Resume a session

Ablation is designed for multi-session research. Session state is written to
`targets/<vendor>/SESSION_<target>.md`. At the start of any session:

```python
# Load context (110ms -- uses cache)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Surface all previously named functions
print(ctx.names_table())

# Review confirmed findings
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Next steps

- [Vulnerability hunting workflow](workflows/vuln-hunting.md) -- full loop from sweep to
  disclosure-ready finding
- [Module reference](module-reference/) -- all 50+ analyzers with parameters and examples
- [CONTRIBUTING.md](../CONTRIBUTING.md) -- how to add patterns, sweeps, and analyzer modules
