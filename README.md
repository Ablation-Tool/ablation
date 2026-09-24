<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

**Semantic vulnerability scanner for stripped binary firmware. Fully autonomous with Claude Code.**

---

You have a stripped binary with 19,000 functions and no symbols. IDA Pro takes four hours to load it. Ablation returns the five functions worth looking at in 35 seconds.

Query in plain English. Ablation encodes every function as a behavioral fingerprint and ranks candidates by how closely they match. No symbol names. No disassembly database. No prior knowledge of the binary required.

Give it to Claude Code with one instruction and the entire reverse engineering workflow runs without you: corpus build, pattern sweep, CFG traces, taint analysis, findings. The researcher reviews results. The tool does the triage.

---

## What it looks like

```
$ ablation sweep firmware.so

[*] BinaryContext     19,247 functions  PLT 312  strings 8,841
[*] Building corpus   35.2s
[*] Sweeping 30 patterns...

[dos-loop]
  score=0.83  0x17b660  fn_0x17b660    advances pointer by wire-length; zero terminates loop
  score=0.69  0x20dd40  fn_0x20dd40    record-length loop without minimum field check

[buffer-overflow]
  score=0.81  0x1fa00   fn_0x1fa00     strcpy into fixed-size stack buffer, no length gate
  score=0.74  0x21340   fn_0x21340     sprintf with externally sourced format argument

[integer-overflow]
  score=0.78  0x2a1c0   fn_0x2a1c0     field-width * bpp before malloc, no overflow check
  score=0.71  0x31000   fn_0x31000     TLV length used directly as allocation size, no cap
```

```
$ ablation search firmware.so "TLV parser that advances pointer without minimum length check"

  0x17b660  fn_0x17b660    advances ptr by field_len, no floor check    score=0.834
  0x20dd40  fn_0x20dd40    record pointer loop, no minimum record len    score=0.791
  0x1fa00   fn_0x1fa00     copies TLV value with fixed dest buffer       score=0.743
```

---

## Autonomous with Claude Code

Drop `CLAUDE.md` from this repo into your project. Open Claude Code. Say:

> *Reverse engineer this firmware and find vulnerabilities.*

That is the entire instruction. Claude reads the command reference at session start, locates the binary, and drives the full workflow without further input.

```
corpus  →  sweep  →  search  →  cfg  →  taint  →  findings
```

Claude builds the corpus, sweeps all 30 vulnerability patterns, queries specific behaviors, pulls CFG and taint traces on every top candidate, and interprets each result. You review findings. The tool does the triage.

Not an MCP server. Not a plugin. Not a protocol layer. Ablation is a standard Python CLI. Claude calls it with `!` commands inside a session, reads the output, and reasons about it. No network service. No browser extension.

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
│  IPRegAnnotator ───── cross-binary arg chains         │
└───────────────────────────────────────────────────────┘
        │
        ▼
╔══════════════════════════════════════════════════════╗
║  DTWMatcher · MatrixProfileDiff                      ║  cross-version patch analysis
║  PatternLibrary.record_hit()                         ║  confirmed findings seed future sweeps
╚══════════════════════════════════════════════════════╝
```

SemanticSearcher runs first, on all functions, before CFG or taint analysis begins. It narrows 19,000 candidates to fewer than ten. Everything below that box runs only on those candidates. That is where the 35-second figure comes from.

---

## Real results

All three findings below were identified via semantic sweep before any manual disassembly. In each case the sweep returned the exact function. Manual analysis began only after Ablation narrowed the candidate list.

| Vulnerability class | How found |
|---|---|
| Zero-length loop DoS in protocol parser | Semantic sweep, CFG loop detection |
| Zero-length loop DoS, second protocol variant | Semantic sweep, pattern replay on same binary |
| Pre-auth management API route exposure | Semantic sweep, taint trace to unauthenticated handler |

The pattern library replays confirmed findings automatically. The second DoS above was found by replaying the pattern from the first.

---

## Install

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

With LLM analyst features (automated function naming via Claude):

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

---

## Quick start

```bash
# Build corpus (run once per binary)
ablation corpus firmware.so --product my-target --version 1.0 --sigs

# Sweep all 30 vulnerability patterns
ablation sweep  firmware.so --json results.json

# Targeted query
ablation search firmware.so "TLV parser that advances pointer without bounds check"

# CFG for a candidate
ablation cfg    firmware.so 0x17b660 --insns

# Taint trace from network sources to dangerous callees
ablation taint  firmware.so

# Export confirmed findings
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

## Why not IDA Pro, Ghidra, or Binary Ninja

IDA Pro and Ghidra are disassemblers. They build a complete instruction database before you can search anything. On a 50 MB stripped network appliance image that takes one to four hours. Ablation makes one O(N) pass, builds a behavioral index, and is ready in 35 seconds.

**The search model is different.** IDA searches by instruction mnemonics, string literals, and function names. None of those exist in a stripped binary. Ablation searches by behavioral meaning. The query *"memcpy called with a length from an untrusted packet field"* matches functions that do that, regardless of instruction names, register choices, or compiler variant. BinFuse normalization makes the same query work on x86-64 and ARM64 without modification.

**Ablation is not a replacement for a disassembler.** It does not decompile. It does not generate pseudocode. It does not provide an interactive disassembly view. It is the tool you run before opening a disassembler to find which of 19,000 functions deserves an hour of manual work.

---

## Features

- **35-second corpus build**: one O(N) NumPy pass over call graph and RIP-relative xrefs; no full auto-analysis
- **Plain-English semantic search**: BERT all-mpnet-base-v2 over behavioral fingerprints; cross-vendor without symbol names
- **Cross-architecture**: BinFuse 11-category opcode normalization covers x86-64 and ARM64 with the same queries
- **30 sweep patterns**: buffer overflow, heap overflow, format string, integer overflow, UAF, double-free, race condition, DoS, info-leak, auth-bypass, crypto misuse, path traversal, and more
- **Self-improving pattern library**: every confirmed finding registers a semantic pattern that replays on future binaries automatically
- **Static taint analysis**: x86-64 source-to-sink data flow; MFP worklist over CFG; interprocedural BFS; custom sinks
- **CFG builder**: recursive disassembly with basic block decomposition and branch analysis
- **Cross-version diffing**: DTW homolog matching and Matrix Profile patch localization across firmware releases
- **Structural similarity**: Jaccard composite over PLT call sets, opcode 4-grams, and immediate values
- **Signature matching**: 40 behavioral signatures auto-name stripped `fn_0x*` functions
- **SARIF 2.1.0 export**: results feed directly into GitHub Code Scanning
- **Binary Ninja plugin**: renames matched functions on binary open
- **Autonomous Claude Code integration**: one plain-English instruction drives the full RE workflow

---

## Analysis methods

| Method | Used for |
|---|---|
| BERT all-mpnet-base-v2 | Semantic function embeddings; cosine similarity ranking |
| BinFuse opcode normalization | Maps x86-64 and ARM64 to 11 behavioral categories; cross-architecture queries |
| BinDeep memory patterns | Load/store/branch reference pattern encoding |
| Markov opcode transitions | Behavioral sequence matching across opcode categories |
| Jaccard similarity | Structural scoring via PLT call sets and opcode 4-gram overlap |
| DTW (Dynamic Time Warping) | Warp-invariant cross-version homolog matching; handles inserted and removed basic blocks |
| Matrix Profile (STUMPY) | AB-join distance over opcode sequences; localizes changed code regions between versions |
| Timing oracle detection | Statistical response-time analysis for non-constant-time comparisons in crypto code |

---

## Export

```bash
ablation sweep firmware.so --sarif results.sarif
ablation findings --sarif findings.sarif

# Upload to GitHub Code Scanning
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
