<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

**Hand it any binary. It reverse engineers it.**

Ablation is an autonomous software reverse engineering framework for stripped binaries. Give it firmware, a PE, a Mach-O, a Go binary, or a shared library — no symbols, no source, no prior knowledge — and it builds a behavioral corpus, searches it in plain English, and deep-analyzes the functions that look vulnerable.

It is not a Ghidra/IDA/Binary Ninja wrapper. The pipeline is implemented in Python on Capstone, LIEF, NumPy, sentence-transformers, and (optionally) the Anthropic API.

---

## What it is for

Typical workflow: drop in a binary, sweep 30 vulnerability patterns, then inspect the 5–10 functions that score highest.

```bash
ablation corpus firmware.so --product my-target --version 1.0 --sigs
ablation sweep  firmware.so --json results.json
ablation search firmware.so "TLV parser that advances pointer without bounds check"
ablation cfg    firmware.so 0x17b660 --insns
ablation taint  firmware.so
ablation findings --sarif findings.sarif
```

The author reports using this path to find a zero-length-loop DoS in a production protocol parser, an automatic replay of that pattern into a second DoS in the same binary, and a pre-auth management API route rated CVSS 9.1.

Two ways to drive it:

1. **Claude Code.** Copy `CLAUDE.md` into a project and say: *Reverse engineer this firmware and find vulnerabilities.* Claude locates the binary, builds the corpus, sweeps patterns, pulls CFG/taint on candidates, and writes up why each finding is a finding.
2. **Embedded `LlmAnalyst`.** A ReAct loop via `claude-sonnet-5` that names stripped functions. It preloads callee names, string xrefs, and RAG-retrieved prior findings, then spends a tool budget until it has a name. This runs inside Ablation and does not require Claude Code.

Deep analysis (CFG, annotated windows, taint, Z3) runs only on the shortlist. Semantic search runs first, over every function.

---

## Pipeline

```
stripped binary (ELF · PE · Mach-O · Go)
        │
        ▼
┌──────────────────────────────────────────────────────┐
│  BinaryContext                                       │
│  PLT · exports · strings · call graph                │
│  SHA256 cache at ~/.ablation/cache/                  │
│  ~0.5s first build · ~110ms reload                   │
└──────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────┐
│  XRefGraph + CorpusBuilder                           │
│  .eh_frame FDEs → function starts                    │
│  vectorized CALL rel32 scan · RIP-relative xrefs     │
│  role inference: HEAP_ALLOC · NETWORK_IO · …         │
└──────────────────────────────────────────────────────┘
        │
        │  all functions (e.g. 19,000)
        ▼
┌──────────────────────────────────────────────────────┐
│  SemanticSearcher + PatternLibrary + FindingRegistry │
│  BinFuse 11-category opcodes · x86-64 and ARM64      │
│  BERT all-mpnet-base-v2 + PCA whitening              │
│  30-pattern sweep · plain-English query              │
│  CVE seed corpus · confirmed prior findings          │
│  ~35s on CPU for 19k functions, then cached          │
└──────────────────────────────────────────────────────┘
        │
        │  top candidates (5–10)
        ▼
┌──────────────────────────────────────────────────────┐
│  CFGBuilder        recursive disasm · basic blocks   │
│  WindowAnalyzer    annotated window · inline xrefs   │
│  TaintTracker      source → sink · MFP · interproc   │
│  PathSolver        Z3 feasibility                    │
│  FuncProfiler      strings · calls · sinks           │
│  RegAnnotator      call-site arg values              │
│  IPRegAnnotator    N-hop cross-library arg chains    │
│  LlmAnalyst        ReAct · claude-sonnet-5           │
└──────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────┐
│  DTWMatcher · MatrixProfileDiff · VersionDelta       │
│  PatternLibrary.record_hit() seeds the next sweep    │
└──────────────────────────────────────────────────────┘
```

---

## Install

Python 3.10+.

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

LLM naming / analyst extras:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

From a clone:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
# or: pip install -e ".[llm]"
```

Verify:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

Optional extra `full` also pulls `angr`. LLM features need an Anthropic API key available to the process.

Cache and state live under `~/.ablation/`:

| Path | What |
|---|---|
| `~/.ablation/cache/` | SHA256-keyed `BinaryContext` |
| `~/.ablation/func_id.db` | function embeddings |
| `~/.ablation/function_names.json` | persistent VA → name overlay |
| `~/.ablation/findings.db` | confirmed findings across targets |

---

## Python API

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher

cb = CorpusBuilder()
cb.build("firmware.so", product="my-target", version="1.0")

searcher = SemanticSearcher("~/.ablation/func_id.db")
searcher.build_corpus()

for r in searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10,
):
    print(f"  0x{r.va:x}  {r.name:<50s}  score={r.score:.3f}")
```

Load a binary without building embeddings:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build("/path/to/binary.so")
print(ctx.summary())
```

CLI entry points from `pyproject.toml`: `ablation`, `ablation-sweep`, `ablation-search`, `ablation-taint`, `ablation-cfg`, `ablation-sigs`.

---

## Capabilities

**Semantic search and pattern sweep.** Each function is fingerprinted from PLT callees, string xrefs, opcode-category sequences, and Markov transitions. Embeddings use `all-mpnet-base-v2` with PCA whitening. Thirty default patterns cover buffer/heap overflow, format string, integer overflow, UAF, double-free, races, DoS loops, info-leak, auth bypass, crypto misuse, path traversal, Tcl injection, command execution, and related classes. A CVE seed corpus is included; confirmed hits register as new queries and replay on later binaries.

**Disassembly and CFG, on demand.** `CFGBuilder` does iterative recursive disassembly per candidate (Andriesse, *Practical Binary Analysis*, §8.2.4). `WindowAnalyzer` returns a 1536-byte annotated window around any VA with inline PLT labels and string xrefs. One call is meant to be enough context for an LLM.

**Taint.** x86-64 static taint from network receive sources to dangerous sinks, using a libdft-style policy (XFER, ALU, CLR, LEA, CALL), rbp/rsp-relative stack model, MFP worklist over the CFG, and interprocedural BFS across libraries. Custom sinks and argv-seeded entry analysis cover CLI handlers. `PathSolver` checks reachability with Z3.

**Cross-binary.** `LibGraph` builds an import/export matrix over every shared library in a firmware tree. `IPRegAnnotator` follows call chains N hops and keeps register-value provenance, so one query can list every library that reaches a dangerous sink and what was in the argument registers.

**Cross-version.** `VersionDelta` tracks a function across releases with a structural pre-filter, Jaccard 4-grams, and a semantic tiebreaker. `DTWMatcher` matches homologs when blocks were inserted or deleted. `MatrixProfileDiff` (STUMPY AB-join on opcode sequences) localizes the instructions that changed, useful for checking whether a CVE was actually patched.

**Naming stripped functions.** `SigLibrary` matches against 40 behavioral signatures at cosine 0.62 and rewrites `fn_0x<va>` to names like `likely:memcpy`. `NameRegistry` persists the overlay by binary SHA256. `LlmAnalyst` does the ReAct naming loop described above.

**Formats and architectures.** ELF (x86-64, ARM64), PE, Mach-O. Go via pclntab (all Go versions), including garbled builds and subprocess/exec surface enumeration. FortiOS image extraction with XOR-key recovery. Entropy maps for packed/encrypted sections. ARM64 C++ vtable reconstruction and indirect-call resolution.

**Specialized auditors.** `PreAuthRouteAuditor` walks a four-step pre-auth route discovery flow (route-init bypasses → handler classes → factories → `FuncProfiler`); `PocGenerator` emits curl commands for confirmed routes. `CryptoAudit` covers JWT/SAML, TLS versions/ciphers, embedded key material, and timing-oracle checks from response-time deltas.

---

## Methods

| Method | Role |
|---|---|
| BERT `all-mpnet-base-v2` | function embeddings |
| PCA whitening (Su et al., 2021) | calibrated cosine similarity |
| BinFuse | x86-64 / ARM64 → 11 behavioral opcode categories |
| BinDeep | `MEM[REG]` / `MEM[REG+IMM]` operand encoding |
| Markov transitions | structure over category sequences |
| Jaccard | PLT-call sets and opcode 4-grams |
| DTW | warp-invariant cross-version matching |
| Matrix Profile (STUMPY) | instruction-level patch localization |
| Timing deltas | non-constant-time crypto |

---

## Compared with interactive RE tools

Ablation does not replace a decompiler. It is built to avoid hours of upfront auto-analysis on large stripped images: index first, disassemble only the functions that matter.

| | Typical GUI RE tool | Ablation |
|---|---|---|
| First look at a 50 MB image | full auto-analysis, often 1–4 h | context build in ~0.5 s; embeddings ~35 s for ~19k functions |
| Function ID | hash / FLIRT-style signatures | BERT behavioral signatures; survives rename, recompile, some inlining |
| Search | name, string, byte, type | plain-English behavioral queries |
| Taint | limited or plugin-dependent | static x86-64 source→sink with interprocedural BFS |
| Diffing | BinDiff / BinExport-style plugins | DTW + matrix profile + semantic tiebreak |
| Persistence | per-database | findings and names reuse across binaries |
| Automation | scripts after the DB exists | Claude Code one-shot workflow + Python library |
| Install | heavy native / Java app | `pip install` |

It does **not** emit Hex-Rays-quality C. Use IDA, Ghidra, or Binary Ninja when you need a decompiler; there is a Binary Ninja integration documented under `docs/integrations/binja.md`.

---

## Export

SARIF 2.1.0 and JSON, including GitHub Code Scanning:

```bash
ablation sweep firmware.so --sarif results.sarif
ablation findings --sarif findings.sarif

gh api repos/<owner>/<repo>/code-scanning/sarifs \
    -f commit_sha="$(git rev-parse HEAD)" \
    -f ref=refs/heads/main \
    -f sarif="$(gzip -c results.sarif | base64 -w0)" \
    -f tool_name=ablation
```

---

## Documentation

| Doc | Topic |
|---|---|
| [Getting Started](docs/getting-started.md) | install and first analysis |
| [Vulnerability Hunting](docs/workflows/vuln-hunting.md) | sweep → confirmation → disclosure |
| [Cross-Version Diffing](docs/workflows/cross-version.md) | track functions across patches |
| [Go Binary RE](docs/workflows/go-binaries.md) | pclntab, garbled builds |
| [Crypto Analysis](docs/workflows/crypto.md) | encrypted firmware, XOR keys |
| [Core Analyzers](docs/module-reference/core.md) | `BinaryContext`, `XRefGraph`, `CFGBuilder`, `TaintTracker` |
| [Semantic Search](docs/module-reference/semantic-search.md) | searcher, corpus, pattern library |
| [Signature Matching](docs/module-reference/sig-library.md) | auto-naming `fn_0x*` |
| [Export Formats](docs/module-reference/export.md) | SARIF, JSON, Code Scanning |
| [Registry](docs/module-reference/registry.md) | names and findings |
| [Crypto](docs/module-reference/crypto.md) | entropy, XOR, `CryptoAudit` |
| [Structural](docs/module-reference/structural.md) | version delta, vtables |
| [LLM Analyst](docs/module-reference/llm.md) | ReAct naming loop |
| [Claude Code](docs/integrations/claude-code.md) | driving Ablation from a Claude session |
| [Binary Ninja](docs/integrations/binja.md) | plugin install and commands |

Also see `CLAUDE.md` (agent command reference), `PITCH.md`, and `CHANGELOG.md` (current release: **1.8.0**).

---

## Requirements

- Python ≥ 3.10
- `capstone`, `numpy`, `lief`, `sentence-transformers`, `pyelftools`
- Optional: `anthropic` (`[llm]`), `angr` (`[full]`)

---

## Author

Built by **Nicholas Michael Kloster**, independent researcher working on binary firmware vulnerability analysis.

---

## License

Copyright (c) 2026 Nicholas Michael Kloster. All Rights Reserved.

Licensed for authorized security research and educational use. Commercial use requires written permission. See [LICENSE](LICENSE) for terms.

Use this only on binaries you are authorized to analyze. Findings are candidates until a human confirms them.
