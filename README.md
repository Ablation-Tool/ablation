<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

**Hand it any binary. It reverse engineers it.**

Ablation is an autonomous reverse engineering framework for stripped binaries. Give it firmware, a PE, a Mach-O, a Go binary, or a shared library. No symbols required. No source required. No prior knowledge required. It builds a behavioral corpus, searches it in plain English, disassembles candidates on demand, traces taint, and decompiles functions via LLM reasoning.

It is not a Ghidra/IDA/Binary Ninja wrapper. The pipeline runs in Python on Capstone, LIEF, NumPy, sentence-transformers, and (optionally) the Anthropic API.

---

## What it is for

Drop in a binary, sweep 30 vulnerability patterns, inspect the top functions that score highest.

```bash
ablation corpus firmware.so --product my-target --version 1.0 --sigs
ablation sweep  firmware.so --json results.json
ablation search firmware.so "TLV parser that advances pointer without bounds check"
ablation cfg    firmware.so 0x17b660 --insns
ablation taint  firmware.so
ablation findings --sarif findings.sarif
```

Real findings on this path: a zero-length-loop DoS in a production protocol parser, a second DoS in the same binary found by automatic pattern replay, and a pre-auth management API route rated CVSS 9.1.

Two ways to drive it:

1. **Claude Code.** Copy `CLAUDE.md` into a project and say: *Reverse engineer this firmware and find vulnerabilities.* Claude locates the binary, builds the corpus, sweeps patterns, pulls CFG and taint on candidates, and explains why each result is a finding. No binary path. No command flags.
2. **Embedded `LlmAnalyst`.** A ReAct loop using `claude-sonnet-5` for automated function naming and decompilation. It preloads callee names, string xrefs, and RAG-retrieved prior findings, then spends a tool budget until it produces a confident result. This runs inside Ablation independently of Claude Code.

Semantic search runs first, over every function. Deep analysis runs only on the top candidates.

---

## Coverage vs Ghidra, IDA Pro, and Binary Ninja

Ablation was built from scratch. It does not wrap or call Ghidra, IDA Pro, or Binary Ninja. Every capability listed below is implemented directly in Python using capstone, lief, numpy, and the Anthropic API against any binary you hand it.

### vs Ghidra

| Capability | Ghidra | Ablation |
|---|---|---|
| Disassembly | Full upfront auto-analysis; 1 to 4 hours on a 50 MB image | CFGBuilder: per-candidate recursive disasm on demand; WindowAnalyzer: annotated dumps with inline PLT labels and string xrefs |
| Decompilation | Built-in decompiler lifting to C pseudocode | LlmAnalyst: LLM-driven decompilation via ReAct loop with claude-sonnet-5; works on stripped binaries with no symbols |
| Call graph | Yes, post auto-analysis | XRefGraph: single O(N) CALL rel32 scan; LibGraph: unified cross-binary matrix across all shared libraries |
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
| LLM analysis | Not available | LlmAnalyst: ReAct loop with claude-sonnet-5; RAG-augmented decompilation and naming |
| Autonomous workflow | Not available | Claude Code drives full workflow from one instruction |
| Initialization time | 1 to 4 hours (50 MB binary) | 35 seconds (19,000 functions) |
| Installation | Java GUI application | `pip install` |

### vs IDA Pro

| Capability | IDA Pro | Ablation |
|---|---|---|
| Disassembly | Industry standard; full upfront analysis | CFGBuilder + WindowAnalyzer; per-candidate on demand; annotated with inline context |
| Decompilation | Hex-Rays: C pseudocode via compiler IR lift | LlmAnalyst: LLM-driven decompilation via ReAct loop; works on stripped binaries without Hex-Rays license |
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
| Decompilation | HLIL pseudocode; SSA-based data flow | LlmAnalyst: LLM-driven decompilation via ReAct loop with claude-sonnet-5 |
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

The optional `full` extra also pulls `angr`. LLM features require an Anthropic API key in the environment.

Cache and state live under `~/.ablation/`:

| Path | What |
|---|---|
| `~/.ablation/cache/` | SHA256-keyed `BinaryContext` |
| `~/.ablation/func_id.db` | function embeddings |
| `~/.ablation/function_names.json` | persistent VA to name overlay |
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

CLI entry points: `ablation`, `ablation-sweep`, `ablation-search`, `ablation-taint`, `ablation-cfg`, `ablation-sigs`.

---

## Capabilities

**Semantic search and pattern sweep.** Each function is fingerprinted from PLT callees, string xrefs, opcode-category sequences, and Markov transitions. Embeddings use `all-mpnet-base-v2` with PCA whitening. Thirty default patterns cover buffer/heap overflow, format string, integer overflow, UAF, double-free, races, DoS loops, info-leak, auth bypass, crypto misuse, path traversal, Tcl injection, command execution, and related classes. A CVE seed corpus is included. Confirmed hits register as new queries and replay on later binaries.

**Disassembly and CFG, on demand.** `CFGBuilder` runs iterative recursive disassembly per candidate (Andriesse, *Practical Binary Analysis*, §8.2.4): basic block decomposition, branch analysis, successor edges. `WindowAnalyzer` returns a 1536-byte annotated window around any VA with inline PLT labels and string xrefs. One call gives an LLM everything it needs to reason about a function.

**Decompilation.** `LlmAnalyst` drives a ReAct loop with `claude-sonnet-5`. It loads the annotated disassembly window, callee names, string xrefs, and RAG-retrieved prior findings, then reasons through the function to produce a behavioral description. This is LLM-based decompilation: it works on fully stripped binaries and does not require a Hex-Rays license.

**Taint.** x86-64 static taint from network receive sources to dangerous sinks. Uses a libdft-style policy (XFER, ALU, CLR, LEA, CALL), rbp/rsp-relative stack model, MFP worklist over the CFG, and interprocedural BFS across libraries. Custom sinks and argv-seeded entry analysis cover CLI handlers. `PathSolver` checks reachability with Z3.

**Cross-binary.** `LibGraph` builds an import/export matrix over every shared library in a firmware tree. `IPRegAnnotator` follows call chains N hops and keeps register-value provenance, so one query lists every library that reaches a dangerous sink and what the argument registers held.

**Cross-version.** `VersionDelta` tracks a function across releases with a structural pre-filter, Jaccard 4-grams, and a semantic tiebreaker. `DTWMatcher` matches homologs when blocks were inserted or deleted. `MatrixProfileDiff` (STUMPY AB-join on opcode sequences) localizes the instructions that changed between versions. Use it to confirm whether a CVE was patched.

**Naming stripped functions.** `SigLibrary` matches against 40 behavioral signatures at cosine 0.62 and rewrites `fn_0x<va>` to names like `likely:memcpy`. `NameRegistry` persists the overlay by binary SHA256.

**Formats and architectures.** ELF (x86-64, ARM64), PE, Mach-O. Go via pclntab (all Go versions), including garbled builds and subprocess/exec surface enumeration. FortiOS image extraction with XOR-key recovery. Entropy maps for packed/encrypted sections. ARM64 C++ vtable reconstruction and indirect-call resolution.

**Specialized auditors.** `PreAuthRouteAuditor` walks a four-step pre-auth route discovery flow: route-init bypass scan, handler class extraction, factory cross-reference, and `FuncProfiler` per handler. `PocGenerator` emits curl commands for confirmed routes. `CryptoAudit` covers JWT/SAML, TLS versions/ciphers, embedded key material, and timing-oracle checks from response-time deltas.

---

## Analysis methods

| Method | Role |
|---|---|
| BERT `all-mpnet-base-v2` | function embeddings |
| PCA whitening (Su et al., 2021) | calibrated cosine similarity |
| BinFuse | x86-64 / ARM64 to 11 behavioral opcode categories |
| BinDeep | `MEM[REG]` / `MEM[REG+IMM]` operand encoding |
| Markov transitions | structure over category sequences |
| Jaccard | PLT-call sets and opcode 4-grams |
| DTW | warp-invariant cross-version matching |
| Matrix Profile (STUMPY) | instruction-level patch localization |
| Timing deltas | non-constant-time crypto |

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
| [Vulnerability Hunting](docs/workflows/vuln-hunting.md) | sweep to confirmation to disclosure |
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
| [LLM Analyst](docs/module-reference/llm.md) | ReAct decompilation and naming loop |
| [Claude Code](docs/integrations/claude-code.md) | driving Ablation from a Claude session |

Also see `CLAUDE.md` (agent command reference), `PITCH.md`, and `CHANGELOG.md` (current release: **1.8.0**).

---

## Requirements

- Python >= 3.10
- `capstone`, `numpy`, `lief`, `sentence-transformers`, `pyelftools`
- Optional: `anthropic` (`[llm]`), `angr` (`[full]`)

---

## License

Commercial license required for commercial use. Non-commercial research use permitted. See [LICENSE](LICENSE) for full terms.

Use this only on binaries you are authorized to analyze. Findings are candidates until a human confirms them.
