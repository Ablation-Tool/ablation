<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

Ablation finds vulnerable functions in stripped binary firmware in seconds, without symbols, source code, or a pre-built database. Hand it to Claude Code and the entire reverse engineering workflow runs autonomously.

Given a stripped ELF binary, Ablation builds a behavioral corpus from call graph structure and RIP-relative string cross-references. It encodes every function as a BERT embedding, then lets you query in plain English: *"TLV parser that advances a pointer without a bounds check."* Ranked candidates return with cosine similarity scores. A 19,000-function binary takes 35 seconds on CPU.

Inside a Claude Code session, Claude builds the corpus, sweeps all 30 vulnerability patterns, queries specific behaviors, pulls CFG and taint traces for top candidates, and interprets every result. The researcher reviews findings. The tool does the triage. Drop the repo's `CLAUDE.md` into your project and hand over a binary path to start.

The pattern library improves with each engagement. Every confirmed vulnerability seeds a new semantic pattern that replays automatically on future binaries, regardless of vendor or architecture.

## Pipeline

```
stripped binary (ELF · no symbols)
        │
        ▼
╔══════════════════════════════════════════════════════╗
║  BinaryContext                                       ║
║  PLT · exports · strings · call graph                ║  0.5s first run · 110ms reload
║  SHA256-keyed cache at ~/.ablation/cache/            ║
╚══════════════════════════════════════════════════════╝
        │
        ▼
╔══════════════════════════════════════════════════════╗
║  XRefGraph                                           ║
║  .eh_frame FDE → function starts                     ║  O(N) · no full disassembly
║  CALL rel32 NumPy scan · RIP-relative xref index     ║
╚══════════════════════════════════════════════════════╝
        │
        │  all functions (e.g. 19,000)
        ▼
╔══════════════════════════════════════════════════════╗
║  SemanticSearcher + PatternLibrary                   ║  ← first, before any CFG work
║                                                      ║
║  BinFuse 11-category opcode normalization            ║  x86-64 and ARM64
║  BERT all-mpnet-base-v2 embeddings                   ║  ~35s on CPU
║  30-pattern sweep · plain-English query              ║
╚══════════════════════════════════════════════════════╝
        │
        │  top candidates (5–10)
        ▼
┌───────────────────────────────────────────────────────┐
│  per-candidate deep analysis                          │
│                                                       │
│  CFGBuilder ──────── basic blocks · branch edges      │
│       │                                               │
│       ▼                                               │
│  TaintTracker ─────── source → sink data flow         │
│       │               MFP worklist · interprocedural  │
│       ▼                                               │
│  PathSolver ──────── Z3 feasibility                   │
│                                                       │
│  FuncProfiler ─────── strings · calls · sinks         │
│  RegAnnotator ─────── call-site arg values            │
│  IPRegAnnotator ───── cross-binary arg chains         │
└───────────────────────────────────────────────────────┘
        │
        ▼
╔══════════════════════════════════════════════════════╗
║  DTWMatcher · MatrixProfileDiff                      ║  cross-version patch analysis
║  PatternLibrary.record_hit()                         ║  confirmed findings seed future sweeps
╚══════════════════════════════════════════════════════╝
```

## How it differs from IDA Pro, Ghidra, and Binary Ninja

IDA Pro and Ghidra are disassemblers. They build a complete database of every instruction in the binary before you can search anything. On a 50 MB stripped network appliance image, that initialization takes one to four hours. Ablation makes one O(N) pass over the `.text` segment, builds a behavioral index, and is ready in 35 seconds.

**Search by meaning, not text.** IDA searches for instruction mnemonics, string literals, and function names. None of those exist in a stripped binary. Ablation searches by behavioral meaning: the query *"memcpy called with a length from an untrusted packet field"* matches functions that do exactly that, regardless of instruction names, register choices, or compiler output. The BinFuse opcode normalization makes the same query work on x86-64 and ARM64 without modification.

**Not a decompiler.** Ablation does not generate C pseudocode or an interactive disassembly view. It is the tool you run before opening a disassembler to identify which of 19,000 functions is worth an hour of manual work.

**Not an MCP server, a plugin, or a protocol layer.** Ablation is a Python library and CLI that runs locally. The Claude Code integration uses the standard `!` command prefix: Claude calls the CLI, reads the output, and reasons about the results. There is no MCP server, no tool-calling protocol, no browser extension, and no network service involved.

## Autonomous reverse engineering

Drop `CLAUDE.md` from this repo into your project directory and open a Claude Code session. Then tell Claude to reverse engineer the firmware:

```bash
cp CLAUDE.md /your/project/CLAUDE.md
```

```
"Reverse engineer this firmware and find vulnerabilities."
```

That is the entire instruction. Claude reads the command reference at session start, locates the binary, and drives the full workflow without further input: corpus build, pattern sweep, targeted searches, CFG and taint traces on top candidates, and result interpretation. No binary path. No command flags. No manual steps.

The workflow Claude follows:

```
corpus -> sweep -> search -> cfg -> taint -> findings
```

See [Claude Code integration docs](docs/integrations/claude-code.md) for a step-by-step session walkthrough.

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
- **Cross-architecture**: BinFuse opcode normalization maps x86-64 and ARM64 to the same category space; queries work on both without modification
- **30 sweep patterns**: buffer overflow, heap overflow, format string, integer overflow, UAF, double-free, race condition, DoS, info-leak, auth-bypass, crypto misuse, and more
- **Signature matching**: 40 behavioral signatures auto-name stripped `fn_0x*` functions at 0.62 cosine threshold
- **Self-improving pattern library**: confirmed findings seed future sweeps automatically
- **SARIF 2.1.0 export**: results feed directly into GitHub Code Scanning
- **CFG and taint analysis**: traces user-controlled data from network read functions to dangerous callees
- **Cross-version diffing**: DTW homolog matching and Matrix Profile patch localization track functions across firmware releases
- **Structural similarity**: weighted Jaccard composite over PLT call sets, opcode 4-grams, and immediate values scores function pairs without symbols
- **Claude Code integration**: invoke the CLI with `!` inside a Claude Code session; Claude interprets output, suggests follow-up addresses, and traces taint paths
- **Binary Ninja plugin**: renames matched functions on binary open

## Analysis methods

| Method | Where used |
|---|---|
| **BERT all-mpnet-base-v2** | Semantic function embeddings; cosine similarity for query ranking |
| **BinFuse opcode normalization** | Maps x86-64/ARM64 instructions to 11 behavioral categories; enables cross-architecture queries |
| **BinDeep memory patterns** | Reference pattern encoding for load/store/branch behavior |
| **Markov opcode transitions** | Captures behavioral sequences across opcode categories for pattern matching |
| **Jaccard similarity** | Scores structural similarity via PLT call sets and opcode 4-gram overlap |
| **DTW (Dynamic Time Warping)** | Warp-invariant cross-version homolog matching; handles inserted/removed basic blocks |
| **Matrix Profile (STUMPY)** | AB-join distance profile over opcode sequences; localizes exactly where code changed between firmware versions |
| **Structural composite scoring** | Weighted combination of Jaccard, immediate value overlap, and call set intersection for stripped binary pairing |
| **Timing oracle detection** | Statistical analysis of response time deltas to detect non-constant-time comparisons in crypto code |

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
