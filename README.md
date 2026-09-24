<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

Ablation finds vulnerable functions in stripped binary firmware in seconds, without symbols, source code, or a pre-built database.

Given a stripped ELF binary, Ablation builds a behavioral corpus from call graph structure and RIP-relative string cross-references. It encodes every function as a BERT embedding, then lets you query in plain English: *"TLV parser that advances a pointer without a bounds check."* Ranked candidates return with cosine similarity scores. A 19,000-function binary takes 35 seconds on CPU.

The pattern library improves with each engagement. Every confirmed vulnerability seeds a new semantic pattern that replays automatically on future binaries, regardless of vendor or architecture.

## Install

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Optional LLM features (automated function naming via Claude):

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

## Quick Start

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

- **Vectorized build**: one O(N) pass over call graph and RIP-relative xrefs; 35 seconds for a 19,000-function binary on CPU
- **BERT semantic search**: query functions in plain English; finds vulnerability patterns across vendors without symbol names
- **30 sweep patterns**: buffer overflow, heap overflow, format string, integer overflow, UAF, double-free, race condition, DoS, info-leak, auth-bypass, crypto misuse, and more
- **Signature matching**: 40 behavioral signatures auto-name stripped `fn_0x*` functions at 0.62 cosine threshold
- **Self-improving pattern library**: confirmed findings seed future sweeps automatically
- **SARIF 2.1.0 export**: results feed directly into GitHub Code Scanning
- **CFG and taint analysis**: traces user-controlled data from network read functions to dangerous callees
- **Claude Code integration**: invoke the CLI with `!` inside a Claude Code session; Claude interprets output, suggests follow-up addresses, and traces taint paths
- **Binary Ninja plugin**: renames matched functions on binary open

## Results

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

## Autonomous reverse engineering

Ablation runs autonomously inside a Claude Code session. Hand over a binary path and Claude executes the full workflow without further instruction.

Claude builds the corpus, sweeps for vulnerable functions across all 30 patterns, queries specific behaviors by name, pulls CFG and taint traces for top candidates, and interprets every result. The researcher reviews findings. The tool does the triage.

The `CLAUDE.md` in this repo contains the full command reference and standard workflow. Claude reads it at session start and operates Ablation as a first-class tool. No context-switching, no manual command sequencing, no intermediate steps handed back to the researcher.

See [Claude Code integration docs](docs/integrations/claude-code.md) for the full session walkthrough.

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

Built by **Nicholas Michael Kloster**, independent security researcher specializing in binary firmware vulnerability research.

## License

Copyright (c) 2026 Nicholas Michael Kloster. All Rights Reserved.

Licensed for authorized security research and educational use. Commercial use requires written permission. See [LICENSE](LICENSE) for full terms.
