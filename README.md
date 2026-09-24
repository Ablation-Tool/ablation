<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

**Binary RE platform for stripped firmware. Disassembly, taint analysis, semantic search, and autonomous LLM-driven analysis. Built from scratch.**

---

## What we use it for

We load stripped enterprise firmware binaries -- network appliances, IPS engines, management platforms -- with 19,000+ functions, no symbols, no debug information. We open Claude Code, tell it to find vulnerabilities, and walk away.

Claude runs the semantic sweep across all functions, identifies top candidates by vulnerability class, pulls CFG and taint traces on each one, reasons about the results, and comes back with specific functions, specific vulnerability classes, and specific disassembly showing exactly why they are vulnerable. Confirmed findings before opening a disassembler.

We have found real bugs this way. DoS vulnerabilities in production network appliance firmware. Pre-auth API exposure in a management platform rated CVSS 9.1. The second finding came automatically: after confirming the first DoS, Ablation registered the vulnerability pattern and replayed it on the next sweep without a new query.

---

## How it works

**Two levels of LLM integration.**

The first is Claude Code driving the full RE workflow autonomously. Copy `CLAUDE.md` from this repo into your project and tell Claude:

> *Reverse engineer this firmware and find vulnerabilities.*

Claude reads the command reference, locates the binary, builds the behavioral corpus, sweeps all 30 vulnerability patterns, runs targeted semantic queries, pulls CFG and taint analysis on every top candidate, and interprets the results. No binary path. No command flags. No manual steps.

The second is Ablation's own embedded LLM analyst. `LlmAnalyst` runs a ReAct agent loop using `claude-sonnet-5` directly via the Anthropic API for automated function naming. It pre-fetches callee names, string cross-references, and RAG-retrieved prior findings before each analysis call, then drives the loop until it has a confident name or exhausts its tool budget. This runs inside Ablation itself, independent of Claude Code.

---

## Pipeline

```
stripped binary (ELF · PE · Mach-O · Go)
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
║  XRefGraph + CorpusBuilder                           ║
║  .eh_frame FDE → function starts                     ║  O(N) · no full disassembly
║  CALL rel32 NumPy scan · RIP-relative xref index     ║
║  Role inference: HEAP_ALLOC · NETWORK_IO · TCL_INTERP║
╚══════════════════════════════════════════════════════╝
        │
        │  all functions  (e.g. 19,000)
        ▼
╔══════════════════════════════════════════════════════╗
║  SemanticSearcher + PatternLibrary + FindingRegistry ║  ← runs before any CFG work
║                                                      ║
║  BinFuse 11-category opcode normalization            ║  x86-64 and ARM64
║  BERT all-mpnet-base-v2 · PCA whitening              ║  ~35s on CPU
║  30-pattern sweep · plain-English query              ║
║  CVE seed corpus · prior confirmed findings          ║
╚══════════════════════════════════════════════════════╝
        │
        │  top candidates  (5–10)
        ▼
┌───────────────────────────────────────────────────────┐
│  per-candidate deep analysis                          │
│                                                       │
│  CFGBuilder ──────── recursive disasm · basic blocks  │
│  WindowAnalyzer ──── annotated disasm · inline xrefs  │
│       │                                               │
│       ▼                                               │
│  TaintTracker ─────── source → sink · MFP worklist    │
│       │               interprocedural BFS             │
│       ▼                                               │
│  PathSolver ──────── Z3 feasibility                   │
│                                                       │
│  FuncProfiler ─────── strings · calls · sinks         │
│  RegAnnotator ─────── call-site arg values            │
│  IPRegAnnotator ───── N-hop cross-library arg chains  │
│  LlmAnalyst ──────── ReAct loop · claude-sonnet-5     │
└───────────────────────────────────────────────────────┘
        │
        ▼
╔══════════════════════════════════════════════════════╗
║  DTWMatcher · MatrixProfileDiff                      ║  cross-version patch analysis
║  PatternLibrary.record_hit() · FindingRegistry       ║  findings seed future sweeps
╚══════════════════════════════════════════════════════╝
```

SemanticSearcher runs first, across all functions, before any CFG or disassembly work begins. It narrows 19,000 candidates to fewer than ten. Everything below that box runs only on those candidates.

---

## Coverage vs Ghidra, IDA Pro, and Binary Ninja

Ablation was built from scratch. It does not wrap or call Ghidra, IDA Pro, or Binary Ninja. Every capability listed below is implemented directly in Python against raw binaries using capstone, lief, numpy, and the Anthropic API.

### vs Ghidra

| Capability | Ghidra | Ablation |
|---|---|---|
| Disassembly | Full upfront auto-analysis; 1-4h on 50 MB image | CFGBuilder: per-candidate recursive disasm, on-demand; WindowAnalyzer: annotated dumps with inline PLT labels and string xrefs |
| Call graph | Yes, post auto-analysis | XRefGraph: single O(N) CALL rel32 scan; LibGraph: unified cross-binary matrix across all shared libraries at once |
| Cross-reference analysis | Code and data xrefs, post auto-analysis | RIP-relative xref index built in 2s; BinaryContext.strings_in_func(), funcs_referencing_string() |
| String extraction | Yes | BinaryContext indexes all .rodata strings with function linkage in 0.5s |
| Function identification | FunctionID (hash-based signatures) | SigLibrary: 40 BERT behavioral signatures; matches functions that were recompiled, renamed, or inlined |
| Symbol / import / export | Yes | BinaryContext: PLT (.plt/.plt.sec/.plt.got) and .dynsym exports |
| Data flow / taint | Limited; no source-to-sink | TaintTracker: x86-64 static taint; libdft policy; full stack model; MFP worklist; interprocedural BFS to dangerous sinks |
| Binary diffing | Via BinExport / Kaiju plugin | DTWMatcher, MatrixProfileDiff, VersionDelta: Jaccard + DTW + semantic tiebreaker; instruction-level patch localization |
| Scripting | Java API; Python via Ghidrathon | Full Python library; every module is a direct import |
| YARA generation | Via external plugin | yara_generator.py: direct rule generation from findings |
| Semantic / behavioral search | Not available | SemanticSearcher: plain-English queries against BERT behavioral fingerprints |
| Self-improving patterns | Not available | PatternLibrary: confirmed findings auto-replay on future binaries |
| LLM analysis | Not available | LlmAnalyst: ReAct loop with claude-sonnet-5; RAG-augmented function naming |
| Autonomous workflow | Not available | Claude Code drives full workflow from one instruction |
| Initialization time | 1-4 hours (50 MB binary) | 35 seconds (19,000 functions) |
| Installation | Java GUI application | `pip install` |

### vs IDA Pro

| Capability | IDA Pro | Ablation |
|---|---|---|
| Disassembly | Industry standard; full upfront analysis | CFGBuilder + WindowAnalyzer; per-candidate on-demand; annotated with inline context |
| Decompilation | Hex-Rays: gold standard C pseudocode | LlmAnalyst: behavioral reasoning via ReAct loop; no C pseudocode but reasons directly about vulnerability impact |
| Function signatures | FLIRT: hash-based library matching | SigLibrary: BERT behavioral matching; matches recompiled / inlined / custom functions FLIRT cannot |
| Taint analysis | Very limited; plugin-dependent | TaintTracker: full static taint source-to-sink; MFP worklist; interprocedural; full stack model |
| Cross-binary analysis | Per-binary; manual linking | LibGraph: unified import/export matrix across all firmware libraries; IPRegAnnotator N-hop cross-library arg provenance |
| Binary diffing | BinDiff plugin | DTWMatcher + MatrixProfileDiff + VersionDelta |
| Scripting | IDAPython | Full Python library |
| Semantic / behavioral search | Not available | SemanticSearcher |
| Self-improving patterns | Not available | PatternLibrary |
| LLM analysis | Not available | LlmAnalyst + Claude Code |
| Autonomous workflow | Not available | Claude Code drives full workflow |
| Cost | $3,000+ per seat | Open source |
| Initialization time | Minutes to hours | 35 seconds |

### vs Binary Ninja

| Capability | Binary Ninja | Ablation |
|---|---|---|
| Disassembly | Multi-architecture; LLIL/MLIL/HLIL IR | CFGBuilder + WindowAnalyzer |
| Decompilation | HLIL pseudocode; SSA-based data flow | LlmAnalyst: behavioral reasoning; no pseudocode |
| Data flow / value analysis | SSA-based value set analysis | TaintTracker: source-to-sink taint; PathSolver Z3 feasibility |
| Function signatures | FLIRT-style signatures | SigLibrary: BERT behavioral signatures |
| Cross-binary analysis | Per-binary | LibGraph: unified cross-binary matrix |
| Binary diffing | Via plugins | DTWMatcher + MatrixProfileDiff + VersionDelta |
| Scripting | Python API; headless mode | Full Python library |
| Semantic / behavioral search | Not available | SemanticSearcher |
| Self-improving patterns | Not available | PatternLibrary |
| LLM analysis | Not available | LlmAnalyst + Claude Code |
| Autonomous workflow | Not available | Claude Code drives full workflow |
| Initialization time | Minutes on large binaries | 35 seconds |

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

CFGBuilder runs iterative recursive disassembly (Andriesse PBA ch. 8.2.4) per candidate function: basic block decomposition, branch analysis, successor edges. WindowAnalyzer dumps a 1536-byte annotated window centered on any VA with inline PLT labels and string cross-references -- one call returns everything an LLM needs to reason about a function.

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
