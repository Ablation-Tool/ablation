<p align="center"><img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION"></p>

<p align="center"><strong>Semantic firmware analysis for vulnerability researchers.</strong></p>

<p align="center">
Find vulnerable functions in stripped binary firmware in seconds, not hours.<br>
No symbols. No source. No setup.
</p>

<p align="center">
<a href="docs/INDEX.md">Documentation</a> &nbsp;|&nbsp;
<a href="PITCH.md">What it does</a> &nbsp;|&nbsp;
<a href="docs/getting-started.md">Quick Start</a>
</p>

---

## Install

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Optional LLM features (automated function naming via Claude):

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

---

## In 30 seconds

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher

# Load binary -- 0.5s first run, 110ms from cache
ctx = BinaryContext.load_or_build('/path/to/firmware.so')
print(ctx.summary())

# Build behavioral corpus (stored in ~/.ablation/func_id.db)
cb = CorpusBuilder()
cb.build('/path/to/firmware.so', product='my-target', version='1.0')

# Query in plain English
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
ablation corpus /path/to/firmware.so --product my-target --version 1.0
ablation search /path/to/firmware.so "TLV parser without length check" --top-k 10
ablation sweep  /path/to/firmware.so
ablation cfg    /path/to/firmware.so 0xfa00 --insns
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

All findings below were identified via semantic sweep before any manual disassembly.

| Vuln class | Technique |
|---|---|
| Zero-length loop DoS in protocol parser | Semantic sweep, CFG loop detection |
| Zero-length loop DoS, second protocol variant | Semantic sweep, pattern replay |
| Pre-auth management API route exposure | Semantic sweep, taint trace |

---

## Export

Sweep results and confirmed findings export to SARIF 2.1.0 (GitHub Code Scanning) or flat JSON:

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

---

## Signature matching

Auto-name stripped `fn_0x*` functions using 40 behavioral signatures:

```bash
ablation corpus firmware.so --sigs          # build corpus and auto-name in one step
ablation sigs   firmware.so --dry-run       # preview names without writing
```

Ships 40 signatures: `memcpy`, `malloc`, `recv`, `SSL_read`, `system`, `execve`, and more.
Threshold 0.62 cosine similarity. Names written as `likely:memcpy` in the corpus DB.

---

## Claude Code integration

Ablation is designed to work alongside Claude Code. Put this in your project's `CLAUDE.md`
or invoke the CLI directly from a Claude Code session with `!`:

```bash
! ablation corpus /path/to/firmware.so --product my-target
! ablation sweep  /path/to/firmware.so
! ablation search /path/to/firmware.so "parser reads user-controlled length"
! ablation cfg    /path/to/firmware.so 0xfa00 --insns
```

Claude interprets the output, suggests manual follow-up VAs, and helps trace taint paths
through CFG output -- combining pattern-matched candidates with LLM-guided analysis.

See [Claude Code integration docs](docs/integrations/claude-code.md) for the full workflow.

---

## Binary Ninja plugin

Install `ablation/integrations/binja_plugin.py` to your Binary Ninja plugins directory.
On binary open, the plugin checks `~/.ablation/func_id.db` for an existing corpus
and renames matched functions automatically. Adds sweep results as bookmarks.

See [Binary Ninja integration docs](docs/integrations/binja.md).

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
| [Signature Matching](docs/module-reference/sig-library.md) | SigLibrary, auto-naming fn_0x* functions |
| [Export Formats](docs/module-reference/export.md) | SARIF 2.1.0, JSON, GitHub Code Scanning |
| [Registry](docs/module-reference/registry.md) | NameRegistry, FindingRegistry |
| [Crypto](docs/module-reference/crypto.md) | EntropyMapper, XorSolver, CryptoAudit |
| [Structural](docs/module-reference/structural.md) | VersionDelta, StructuralSim, VtableResolver |
| [LLM Analyst](docs/module-reference/llm.md) | ReAct agent loop for automated naming |
| **Integrations** | |
| [Claude Code](docs/integrations/claude-code.md) | Using Ablation inside a Claude Code session |
| [Binary Ninja](docs/integrations/binja.md) | Plugin installation and commands |
---

## Requirements

- Python 3.10+
- `capstone`, `numpy`, `lief`, `sentence-transformers`, `pyelftools`
- Optional: `anthropic` for LLM analyst features

---

## License

Commercial license required for commercial use. Source available for non-commercial research
use. Contact for licensing.
