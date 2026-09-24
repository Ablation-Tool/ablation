<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

**Autonomous LLM-driven reverse engineering framework for enterprise firmware.**

---

Ablation gives Claude Code the tools to autonomously reverse engineer stripped binary firmware and find exploitable vulnerabilities. Point it at an enterprise firmware image, tell it to find vulnerabilities, and walk away. It builds the analysis corpus, sweeps every function against 30 vulnerability patterns, traces call graphs and data flow paths, and surfaces confirmed exploitable findings.

No manual disassembly. No symbol names. No pre-built database.

We built this to audit real enterprise firmware: network appliances, IPS engines, management platforms. Binaries with 19,000+ stripped functions, no debug info, and no source. Claude Code drives the full workflow autonomously from a single instruction.

---

## How it works in practice

Open a Claude Code session. Say:

> *Reverse engineer this firmware and find vulnerabilities.*

Claude reads the CLAUDE.md command reference included in this repo, locates the binary, and runs:

```
corpus  →  sweep  →  search  →  cfg  →  taint  →  findings
```

It builds a behavioral fingerprint for every function (35 seconds for 19,000 functions on CPU), sweeps all 30 vulnerability patterns, runs targeted semantic searches for specific behaviors, pulls control-flow graphs and taint traces on every top candidate, and interprets the results. Confirmed findings export to SARIF for GitHub Code Scanning.

You review the findings. The tool does the triage.

---

## What we've found

These findings were confirmed in production enterprise firmware using Ablation running autonomously in a Claude Code session. Manual disassembly began only after Ablation narrowed the candidate list.

| Vulnerability | How it was found |
|---|---|
| Zero-length loop DoS in enterprise protocol parser | Semantic sweep, CFG loop analysis |
| Second DoS variant in same binary, different protocol | Automatic pattern replay -- no new query written |
| Pre-auth management API route exposure (CVSS 9.1) | Semantic sweep, taint trace to unauthenticated handler |

The second DoS was found automatically. After confirming the first, Ablation registered the vulnerability pattern. The next sweep replayed it and surfaced the second variant without any additional input.

---

## The semantic search layer

IDA Pro and Ghidra need a complete disassembly pass before you can search anything. On a 50 MB stripped network appliance image that takes one to four hours. Ablation makes one O(N) pass over the binary and is ready in 35 seconds.

More importantly: IDA searches by instruction names, string literals, and symbol names. None of those exist in a stripped binary. Ablation searches by behavioral meaning.

```python
searcher.query(
    "TLV parser that advances a pointer without checking minimum field length",
    top_k=10
)
```

That query matches functions that do exactly that, regardless of register names, compiler output, or architecture. BinFuse normalization maps x86-64 and ARM64 instructions to the same 11 behavioral categories, so the same query runs on both without modification.

Ablation does disassemble. CFGBuilder runs recursive disassembly on every candidate. WindowAnalyzer dumps annotated instruction output with inline PLT labels and string cross-references. TaintTracker traces data flow at the instruction level. The difference from IDA and Ghidra is sequencing: semantic search narrows 19,000 functions to fewer than ten first, then full disassembly and taint analysis run on those candidates automatically. No waiting four hours before the first search.

---

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
        │  all functions  (e.g. 19,000)
        ▼
╔══════════════════════════════════════════════════════╗
║  SemanticSearcher + PatternLibrary                   ║  ← runs before any CFG work
║                                                      ║
║  BinFuse 11-category opcode normalization            ║  x86-64 and ARM64
║  BERT all-mpnet-base-v2 embeddings                   ║  ~35s on CPU
║  30-pattern sweep · plain-English query              ║
╚══════════════════════════════════════════════════════╝
        │
        │  top candidates  (5–10)
        ▼
┌───────────────────────────────────────────────────────┐
│  per-candidate deep analysis                          │
│                                                       │
│  CFGBuilder ──────── basic blocks · branch edges      │
│       │                                               │
│       ▼                                               │
│  TaintTracker ─────── source → sink · MFP worklist    │
│       │               interprocedural BFS             │
│       ▼                                               │
│  PathSolver ──────── Z3 feasibility                   │
│                                                       │
│  FuncProfiler ─────── strings · calls · sinks         │
│  RegAnnotator ─────── call-site arg values            │
│  IPRegAnnotator ───── cross-library arg chains        │
└───────────────────────────────────────────────────────┘
        │
        ▼
╔══════════════════════════════════════════════════════╗
║  DTWMatcher · MatrixProfileDiff                      ║  cross-version patch analysis
║  PatternLibrary.record_hit()                         ║  confirmed findings seed future sweeps
╚══════════════════════════════════════════════════════╝
```

---

## Install

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

With LLM analyst features:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

---

## Quick start

```bash
ablation corpus firmware.so --product my-target --version 1.0 --sigs
ablation sweep  firmware.so --json results.json
ablation search firmware.so "TLV parser that advances pointer without bounds check"
ablation cfg    firmware.so 0x17b660 --insns
ablation taint  firmware.so
ablation findings --sarif findings.sarif
```

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher

cb = CorpusBuilder()
cb.build('firmware.so', product='my-target', version='1.0')

searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)
for r in results:
    print(f"  0x{r.va:x}  {r.name:<50s}  score={r.score:.3f}")
```

---

## Features

- **Autonomous Claude Code integration**: one instruction drives corpus build, pattern sweep, CFG analysis, taint tracing, and findings
- **35-second corpus build** on 19,000-function binaries, no full auto-analysis pass
- **Plain-English semantic search** via BERT all-mpnet-base-v2 behavioral fingerprints
- **Cross-architecture**: BinFuse 11-category normalization covers x86-64 and ARM64 with identical queries
- **30 sweep patterns**: buffer overflow, heap overflow, format string, integer overflow, UAF, double-free, race condition, DoS, info-leak, auth-bypass, crypto misuse, path traversal, and more
- **Self-improving pattern library**: confirmed findings replay automatically on future binaries across vendors
- **Static taint analysis**: x86-64 source-to-sink; MFP worklist; interprocedural BFS; custom sinks
- **Cross-version diffing**: DTW homolog matching and Matrix Profile patch localization
- **Structural similarity**: Jaccard composite over PLT call sets, opcode 4-grams, and immediate values
- **Signature matching**: 40 behavioral signatures auto-name stripped functions
- **SARIF 2.1.0 export** for GitHub Code Scanning
- **Binary Ninja plugin**

---

## Analysis methods

| Method | Used for |
|---|---|
| BERT all-mpnet-base-v2 | Semantic function embeddings; cosine similarity ranking |
| BinFuse opcode normalization | Maps x86-64 and ARM64 to 11 behavioral categories |
| BinDeep memory patterns | Load/store/branch reference pattern encoding |
| Markov opcode transitions | Behavioral sequence matching across opcode categories |
| Jaccard similarity | Structural scoring via PLT call sets and opcode 4-gram overlap |
| DTW (Dynamic Time Warping) | Warp-invariant cross-version homolog matching |
| Matrix Profile (STUMPY) | AB-join over opcode sequences; localizes changed code regions |
| Timing oracle detection | Statistical response-time analysis for non-constant-time crypto |

---

## Export

```bash
ablation sweep firmware.so --sarif results.sarif
ablation findings --sarif findings.sarif

gh api repos/<owner>/<repo>/code-scanning/sarifs \
    -f commit_sha=$(git rev-parse HEAD) \
    -f ref=refs/heads/main \
    -f sarif=$(gzip -c results.sarif | base64 -w0) \
    -f tool_name=ablation
```

---

## Documentation

| | |
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

---

## Requirements

- Python 3.10+
- `capstone`, `numpy`, `lief`, `sentence-transformers`, `pyelftools`
- Optional: `anthropic` for LLM analyst features

---

## Author

Built by **Nicholas Michael Kloster**, independent security researcher specializing in binary firmware vulnerability research.

---

## License

Copyright (c) 2026 Nicholas Michael Kloster. All Rights Reserved.

Licensed for authorized security research and educational use. Commercial use requires written permission. See [LICENSE](LICENSE) for full terms.
