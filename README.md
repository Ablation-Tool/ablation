<div align="center">

<h1>Ablation</h1>

<p><strong>Semantic firmware analysis for vulnerability researchers.</strong></p>

<p>
Find vulnerable functions in stripped binary firmware in seconds, not hours.<br>
No symbols. No source. No setup.
</p>

<p>
<a href="docs/INDEX.md">Documentation</a> &nbsp;|&nbsp;
<a href="PITCH.md">What it does</a> &nbsp;|&nbsp;
<a href="docs/getting-started.md">Quick Start</a>
</p>

</div>

---

## Install

```bash
pip install ablation
```

Optional LLM features (automated function naming via Claude):

```bash
pip install ablation[llm]
```

---

## In 30 seconds

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.xref_graph import XRefGraph

# Load binary -- 0.5s first run, 110ms from cache
ctx = BinaryContext.load_or_build('/path/to/firmware.so')
print(ctx.summary())

# Build behavioral corpus and sweep for vulnerability patterns
cb = CorpusBuilder()
cb.build('/path/to/firmware.so', product='my-target', version='1.0')

xg = XRefGraph.from_path('/path/to/firmware.so').build()
searcher = SemanticSearcher('/path/to/firmware.so', xg=xg)
searcher.build_corpus()

results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)
for r in results:
    print(f"  {ctx.name(r.va):<50s}  score={r.score:.3f}")
```

35 seconds for 19,000 functions on CPU. No pre-built database.

---

## What it is

A Python framework for rapid vulnerability research on stripped binary firmware. Designed to
answer one question before opening a disassembler: **which of these 19,000 functions is worth
looking at?**

Three analysis tracks:

- **Vectorized scan** -- NumPy call graph and RIP-relative xref scan finds every string
  cross-reference in an 18 MB binary in one O(N) pass. No sequential disassembly.
- **BERT semantic search** -- query in plain English against behavioral fingerprints of every
  function. Finds vulnerability patterns across vendors without symbol names.
- **Self-improving pattern library** -- every confirmed finding registers as a semantic pattern
  that replays automatically on future binaries.

---

## Real results

| Finding | Target | CVSS |
|---|---|---|
| Diameter AVP zero-length infinite loop | FortiGate 7000F (FortiOS 8.0.0) | 7.5 |
| DCE/RPC record zero-length infinite loop | FortiGate 7000F (FortiOS 8.0.0) | 7.5 |
| Pre-auth JSON-RPC route exposure | FortiManager 8.0.0 | 9.1 |

All three found via semantic sweep before any manual disassembly.

---

## Documentation

| Document | |
|---|---|
| [Getting Started](docs/getting-started.md) | Install and first analysis in 15 minutes |
| [Vulnerability Hunting](docs/workflows/vuln-hunting.md) | Full sweep-to-disclosure workflow |
| [Cross-Version Diffing](docs/workflows/cross-version.md) | Track functions across patch releases |
| [Go Binary RE](docs/workflows/go-binaries.md) | pclntab recovery, garbled builds |
| [Crypto Analysis](docs/workflows/crypto.md) | Encrypted firmware, XOR keys, JWT cracking |
| **Module Reference** | |
| [Core Analyzers](docs/module-reference/core.md) | BinaryContext, XRefGraph, CFGBuilder, TaintTracker |
| [Semantic Search](docs/module-reference/semantic-search.md) | SemanticSearcher, CorpusBuilder, PatternLibrary |
| [Registry](docs/module-reference/registry.md) | NameRegistry, FindingRegistry |
| [Crypto](docs/module-reference/crypto.md) | EntropyMapper, XorSolver, CryptoAudit |
| [Structural](docs/module-reference/structural.md) | VersionDelta, StructuralSim, VtableResolver |
| [LLM Analyst](docs/module-reference/llm.md) | ReAct agent loop for automated naming |
---

## Requirements

- Python 3.10+
- `capstone`, `numpy`, `lief`, `sentence-transformers`, `pyelftools`
- Optional: `anthropic` for LLM analyst features

---

## License

Commercial license required for commercial use. Source available for non-commercial research
use. Contact for licensing.
