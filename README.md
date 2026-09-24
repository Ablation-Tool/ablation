<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

Ablation is a semantic firmware analysis framework for vulnerability researchers. It finds
vulnerable functions in stripped binary firmware in seconds -- no symbols, no source, no
pre-built database required.

Given a stripped ELF binary, Ablation builds a behavioral corpus from call graph structure and
RIP-relative string cross-references, encodes every function as a BERT embedding, and lets you
query in plain English: *"TLV parser that advances a pointer without a bounds check."* It
returns ranked candidates with cosine similarity scores. A 19,000-function binary takes 35
seconds on CPU.

The pattern library compounds across engagements. Every confirmed vulnerability registers as a
semantic pattern that replays automatically on future binaries, regardless of vendor or
architecture.

## Install

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Optional LLM features (automated function naming via Claude):

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

## Quick start

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher

cb = CorpusBuilder()
cb.build('/path/to/firmware.so', product='my-target', version='1.0')

searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)
for r in results:
    print(f"  0x{r.va:x}  {r.name:<50s}  score={r.score:.3f}")
```

Or from the CLI:

```bash
ablation corpus /path/to/firmware.so --product my-target --version 1.0 --sigs
ablation sweep  /path/to/firmware.so --json results.json
ablation search /path/to/firmware.so "TLV parser without length check"
ablation cfg    /path/to/firmware.so 0xfa00 --insns
ablation taint  /path/to/firmware.so
ablation findings --sarif findings.sarif
```

## Features

- **Vectorized corpus build** -- one O(N) pass over call graph + RIP-relative xrefs.
  18 MB binary in 35 seconds on CPU.
- **BERT semantic search** -- query in plain English against behavioral fingerprints.
  Finds vulnerability patterns across vendors without symbol names.
- **30 sweep patterns** -- buffer overflow, heap overflow, format string, integer overflow,
  UAF, double-free, race condition, DoS, info-leak, auth-bypass, crypto misuse, and more.
- **Signature matching** -- 40 behavioral signatures auto-name stripped `fn_0x*` functions
  (memcpy, malloc, recv, SSL_read, system, execve, ...) at 0.62 cosine threshold.
- **Self-improving pattern library** -- confirmed findings seed future sweeps automatically.
- **SARIF 2.1.0 export** -- results feed directly into GitHub Code Scanning.
- **CFG and taint analysis** -- control-flow graph and data-flow tracing from network read
  sinks to dangerous callees.
- **Claude Code integration** -- invoke CLI with `!` prefix inside a Claude Code session.
  Claude interprets output, suggests manual follow-up VAs, traces taint paths.
- **Binary Ninja plugin** -- auto-renames matched functions on binary open.

## Real results

All findings below were identified via semantic sweep before any manual disassembly.

| Vuln class | Technique |
|---|---|
| Zero-length loop DoS in protocol parser | Semantic sweep, CFG loop detection |
| Zero-length loop DoS, second protocol variant | Semantic sweep, pattern replay |
| Pre-auth management API route exposure | Semantic sweep, taint trace |

## Export

```bash
ablation sweep  firmware.so --sarif results.sarif
ablation sweep  firmware.so --json  results.json
ablation findings --sarif findings.sarif

# Upload to GitHub Code Scanning
gh api repos/<owner>/<repo>/code-scanning/sarifs \
    -f commit_sha=$(git rev-parse HEAD) \
    -f ref=refs/heads/main \
    -f sarif=$(gzip -c results.sarif | base64 -w0) \
    -f tool_name=ablation
```

## Documentation

| Document | |
|---|---|
| [Getting Started](docs/getting-started.md) | Install and first analysis in 15 minutes |
| [Vulnerability Hunting](docs/workflows/vuln-hunting.md) | Full sweep-to-disclosure workflow |
| [Cross-Version Diffing](docs/workflows/cross-version.md) | Track functions across patch releases |
| [Go Binary RE](docs/workflows/go-binaries.md) | pclntab recovery, garbled builds |
| [Crypto Analysis](docs/workflows/crypto.md) | Encrypted firmware, XOR keys |
| **Module Reference** | |
| [Core Analyzers](docs/module-reference/core.md) | BinaryContext, XRefGraph, CFGBuilder, TaintTracker |
| [Semantic Search](docs/module-reference/semantic-search.md) | SemanticSearcher, CorpusBuilder, PatternLibrary |
| [Signature Matching](docs/module-reference/sig-library.md) | SigLibrary, auto-naming fn_0x* functions |
| [Export Formats](docs/module-reference/export.md) | SARIF 2.1.0, JSON, GitHub Code Scanning |
| [Registry](docs/module-reference/registry.md) | NameRegistry, FindingRegistry |
| [Crypto](docs/module-reference/crypto.md) | EntropyMapper, XorSolver, CryptoAudit |
| [Structural](docs/module-reference/structural.md) | VersionDelta, StructuralSim, VtableResolver |
| [LLM Analyst](docs/module-reference/llm.md) | ReAct agent loop for automated naming |
| **Integrations** | |
| [Claude Code](docs/integrations/claude-code.md) | Using Ablation inside a Claude Code session |
| [Binary Ninja](docs/integrations/binja.md) | Plugin installation and commands |

## Requirements

- Python 3.10+
- `capstone`, `numpy`, `lief`, `sentence-transformers`, `pyelftools`
- Optional: `anthropic` for LLM analyst features

## Author

Built by **Nicholas Michael Kloster** -- independent security researcher specializing in
binary firmware vulnerability research.

## License

Copyright (c) 2026 Nicholas Michael Kloster. All Rights Reserved.

Commercial license required for commercial use. Source available for non-commercial research
use. Contact for licensing.
