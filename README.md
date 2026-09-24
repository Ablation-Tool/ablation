<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

**Hand it any binary. It reverse engineers it.**

---

## What we use it for

Hand Ablation any binary: stripped firmware, enterprise applications, shared libraries, Go binaries, Windows PE files, macOS Mach-O, embedded images. Tell Claude Code to find vulnerabilities. It takes apart the binary using disassembly, call graph construction, taint analysis, semantic search across every function, cross-binary analysis, and version diffing. No symbols required. No source required. No prior knowledge of the binary required.

Claude runs the semantic sweep across all functions, identifies top candidates by vulnerability class, pulls CFG and taint traces on each one, reasons about the results, and returns specific functions, specific vulnerability classes, and specific disassembly showing exactly why they are vulnerable. Confirmed findings before opening a disassembler.

We have found real bugs this way. DoS vulnerabilities in production network appliance firmware. Pre-auth API exposure in a management platform rated CVSS 9.1. The second finding came automatically: after confirming the first DoS, Ablation registered the vulnerability pattern and replayed it on the next sweep without a new query.

---

## How it works

**Two levels of LLM integration.**

The first is Claude Code driving the full RE workflow autonomously. Copy `CLAUDE.md` from this repo into your project and tell Claude:

> *Reverse engineer this firmware and find vulnerabilities.*

Claude reads the command reference, locates the binary, builds the behavioral corpus, sweeps all 30 vulnerability patterns, runs targeted semantic queries, pulls CFG and taint analysis on every top candidate, and interprets the results. No binary path. No command flags. No manual steps.

The second is Ablation's own embedded LLM analyst. `LlmAnalyst` runs a ReAct agent loop using `claude-sonnet-5` directly via the Anthropic API for automated function naming. It pre-fetches callee names, string cross-references, and RAG-retrieved prior findings before each analysis call, then drives the loop until it has a confident name or exhausts its tool budget. This runs inside Ablation itself, independent of Claude Code.

---

## Real results

| Vulnerability | How it was found |
|---|---|
| Zero-length loop DoS in enterprise protocol parser | Semantic sweep, CFG loop analysis |
| Second DoS variant in same binary, different protocol | Automatic pattern replay from first finding |
| Pre-auth management API route exposure (CVSS 9.1) | Semantic sweep, taint trace to unauthenticated handler |

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

## Capabilities

**Semantic search and pattern sweep**

Behavioral fingerprints for every function: PLT callees, string cross-references, opcode category sequences, Markov transitions. BERT all-mpnet-base-v2 with PCA whitening for calibrated similarity scores. 30 default patterns covering buffer overflow, heap overflow, format string, integer overflow, UAF, double-free, race conditions, DoS loops, info-leak, auth bypass, crypto misuse, path traversal, Tcl injection, command execution, and more. Ships with a CVE seed corpus so the pattern library has prior knowledge from day one.

**Disassembly and control flow**

CFGBuilder runs iterative recursive disassembly (Andriesse PBA ch. 8.2.4) per candidate function: basic block decomposition, branch analysis, successor edges. WindowAnalyzer dumps a 1536-byte annotated window centered on any VA with inline PLT labels and string cross-references. One call returns everything an LLM needs to reason about a function.

**Taint analysis**

x86-64 static taint from network receive sources to dangerous sinks. libdft policy: XFER, ALU, CLR, LEA, CALL rules. Full rbp-relative and rsp-relative stack model. MFP worklist over CFG handles loops and merge points. Interprocedural BFS follows taint across function and library boundaries. Custom sinks and seeded entry analysis for CLI handler functions where input arrives via argv rather than network reads. Z3 path feasibility confirms whether a taint path is reachable.

**Cross-binary analysis**

LibGraph builds a unified import/export matrix over every shared library in a firmware directory. IPRegAnnotator follows call chains N hops across library boundaries, carrying full register value provenance. One query surfaces every library that calls a dangerous function anywhere in the firmware, with the argument values at each call site.

**Cross-version tracking**

VersionDelta: three-stage pipeline (structural pre-filter, Jaccard 4-gram, semantic tiebreaker) tracks a function across firmware releases without source. DTWMatcher: warp-invariant homolog matching handles inserted and removed basic blocks. MatrixProfileDiff: STUMPY AB-join over opcode sequences localizes exactly which instruction regions changed between versions. Confirms whether a CVE was actually patched.

**Automated function naming**

SigLibrary matches stripped functions against 40 behavioral signatures at 0.62 cosine threshold and renames `fn_0x<va>` to `likely:memcpy` and similar. LlmAnalyst drives a full ReAct agent loop with `claude-sonnet-5`, pre-loading callee names, string xrefs, and RAG-retrieved prior findings before the first LLM call to minimize tool call count.

**Multi-format and multi-architecture**

ELF (x86-64, ARM64), PE (Windows), Mach-O (macOS/iOS). Go binary support: pclntab parsing for all Go versions, function name recovery from garbled builds, subprocess/exec injection surface enumeration. FortiOS hardware firmware extraction with XOR key recovery. Entropy mapping for encrypted and packed sections. ARM64 C++ vtable reconstruction and indirect call resolution.

**Pre-auth route auditing**

PreAuthRouteAuditor automates the 4-step flatui pre-auth route discovery workflow: scan route init for permission-bypass routes, extract handler class names, cross-reference handler factories, run FuncProfiler on each handler. PocGenerator produces curl commands for each confirmed pre-auth route.

**Crypto analysis**

CryptoAudit covers JWT/SAML token analysis, TLS version and cipher auditing, embedded key material scanning, and timing oracle detection via statistical response-time delta analysis.

---

## Analysis methods

| Method | Used for |
|---|---|
| BERT all-mpnet-base-v2 | Semantic function embeddings |
| PCA whitening (Su et al. 2021) | Calibrates BERT cosine similarity; fixes anisotropy |
| BinFuse opcode normalization | Maps x86-64 and ARM64 to 11 behavioral categories |
| BinDeep memory patterns | MEM[REG], MEM[REG+IMM] operand type encoding |
| Markov opcode transitions | Behavioral sequence structure over category sequences |
| Jaccard similarity | PLT call sets and opcode 4-gram structural scoring |
| DTW (Dynamic Time Warping) | Warp-invariant cross-version homolog matching |
| Matrix Profile (STUMPY) | AB-join over opcode sequences; instruction-level patch diff |
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
