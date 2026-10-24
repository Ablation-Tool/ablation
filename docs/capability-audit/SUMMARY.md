# Ablation Capability Audit — Executive Summary

**Version:** 2.86.0 (`ablation/__init__.py`; pyproject.toml lags at 2.81.0; CLAUDE.md still says 2.57.0)
**Audit date:** 2026-10-24
**Scope:** Full codebase — 407 code files, 536 reference docs, 402 capability records across 20 audit units.

---

## 1. Verified Headline Numbers

| Metric | README/Docs Claim | Verified Reality | Source |
|--------|-------------------|-----------------|--------|
| Taint tracker architectures | "18+" | **24 files / 19 distinct ISA implementations** + 5 labeled variants | DISCREPANCIES.md #11 |
| Vulnerability scanners | "25+" | **~46 vuln-relevant** (53 `*_scanner.py` total; 7 are utility/func-discovery) | DISCREPANCIES.md #13 |
| ISA decoders / lifters | "31" | **~30–31 ISA variants** by count; 41 ISA-related files — roughly accurate | DISCREPANCIES.md #12 |
| Capability categories | "27" | **10 groups, 402 documented capabilities** across 20 units | taxonomy.md |
| Undocumented capabilities | — | **+6 files** (cli.py, loongarch_decoder_v2.py, export/, integrations/) | UNMAPPED.md |
| Code files (non-test, non-`__init__`) | — | **407** | COVERAGE.md |
| Test files | 71 (prior estimate) | Zero dedicated test files confirmed for most units | COVERAGE.md; DISCREPANCIES.md D-27 |
| Reference docs | — | **536** in `docs/reference-modules/` | DOC_CODE_MAP.md |
| INDEX.md coverage | — | **147 of 536 docs listed (27%)** — 389 undiscoverable by index | DOC_CODE_MAP.md |
| Doc/code mismatches confirmed | — | **19+ recorded; 8 rated HIGH RAG-risk** | DISCREPANCIES.md |
| CWEs with no scanner | — | **17 of 35** in corpus_miner.py _CWE_COVERAGE map to `None` | DISCREPANCIES.md #7 |

---

## 2. Capability Groups (10)

| # | Group | Caps | Representative tools |
|---|-------|-----:|---------------------|
| 1 | Binary Parsing & Session Infrastructure | 36 | BinaryContext, ELFParser, PEParser, DisasmEngine, XRefGraph |
| 2 | Control Flow & ISA Models | 39 | CFGBuilder×10 ISAs, ISA/ABI models, dataflow engine, func discovery |
| 3 | Taint Analysis | 38 | TaintTracker×19 ISAs, cross-binary taint, BSS taint, source taint |
| 4 | Sink Classification | 17 | SinkArgClassifier×8 arches, SanitizerDetector, NetworkSinkFinder |
| 5 | Vulnerability Scanners | 100 | Format string, heap, cmd-inject, BYOVD, kernel driver, supply chain … |
| 6 | Firmware Extraction & Decryption | 19 | FortiOS extractor, AIX BFF, XorSolver, FirmwareContainer key extractor |
| 7 | Platform-Specific Analysis | 88 | ECU/automotive×7 ISAs, Android/DEX/ARK, Go RE, IBM PS3/XCOFF, C++ vtable |
| 8 | Semantic Search & Learning | 30 | SemanticSearcher, CorpusBuilder, PatternLibrary, HypothesisEngine, LLM agent |
| 9 | Host & Network Enumeration | 18 | Docker/K8s, Cisco IOS/NX-OS/HyperFlex, SIP, lateral movement, forensics |
| 10 | Session Management & Tooling | 17 | FORGE gate, WorkflowDocument, ScanResultVersionCache, sweeps×10, VendorProfile |
|   | **Total** | **402** | |

---

## 3. Ten Most Important Capabilities

| # | Capability | Why it matters |
|---|-----------|----------------|
| 1 | **BinaryContext** (`binary_context.py`) | Parse-once cache; required entry point for all sessions; every downstream tool depends on it. |
| 2 | **TaintTracker** (x86-64 + 18 ISA variants) | Source-to-sink dataflow — the core analytical confirmation step after SAC triage. |
| 3 | **SinkArgClassifier** — `from_context(ctx)` only | Eliminates RODATA_CONST sinks before taint runs; eliminates most false positives. `from_path()` returns ~22 results on stripped binaries — do not use. |
| 4 | **SemanticSearcher** + **CorpusBuilder** | Sentence-embedding sweep over all functions; mandatory first pass on any new binary. Uses `BAAI/bge-small-en-v1.5` (fastembed) — not the model named in the docstring. |
| 5 | **PathSolver** (`modules/path_solver.py`) | Z3-backed feasibility confirmation; final gate before CONFIRMED. |
| 6 | **FORGE gate** (`forge.py`) | AI audit quality gate; required before every commit. Cache keyed with `blake2b(digest_size=8)` — not SHA-256 as forge.md claims. |
| 7 | **PatternLibrary** | Replay confirmed patterns across engagements (flywheel). Central to analyst leverage. |
| 8 | **HypothesisEngine** | Probe selection and scoring; drives the LLM analyst; highest-confidence evidence tier (family weight 1.0). |
| 9 | **NetworkSinkFinder** (`network_sink_finder.py`) | Identifies network-reachable exec sinks; primary entry for remote attack-surface analysis. |
| 10 | **LoongArchDecoderV2** (`loongarch_decoder_v2.py`) | Two-pass KASAN/KCOV instrumentation stripper for LoongArch64 debug kernels (TencentOS 6.6.119). Unique in the codebase. Currently undocumented and not wired into CLI. |

---

## 4. Biggest Gaps and Weak Spots

### Stubs and broken code

| Module | Issue | Severity |
|--------|-------|----------|
| `disasm_engine.py` — `find_functions()`, `analyze_cfg()` | Uses `CS_GRP_JUMP` group API removed in Capstone 5.x; raises `AttributeError` at runtime; 0% test coverage | HIGH |
| `pe_analyzer.py` — `_analyze_imports()` | Body is `pass`; no import analysis performed despite docs describing it as working | MED |
| `corpus_miner.py` | 17 of 35 tracked CWEs map to `None` (UAF, hardcoded creds, cert bypass, auth bypass, SSRF, race, NULL deref, uninitialized mem, and 9 others) | HIGH |
| `EcuC28xDecoder` | `.text` section harvest explicitly "not implemented"; only C_UEXT symbols extracted | HIGH |

### Untested modules

Zero dedicated test files confirmed for most audit units (A01–A14, C01, M01–M04, S01). No unit has a test that would catch a regression in taint tracking, sink classification, or the FORGE cache-key algorithm.

### Undocumented capabilities

- **`ablation/cli.py`** (1317 lines, 30+ subcommands): the package's entire public CLI surface has no reference doc. The embedded `_RECENT_UPDATES` string (lines 401–581) is the only per-version changelog.
- **`loongarch_decoder_v2.py`** (348 lines): no reference doc, no CLI wiring; reachable programmatically only.
- **`ablation/export/`** (`json_export.py`, `sarif.py`): `write_sarif()` in json_export is identical to `write_json()` — not a SARIF validator.
- **`ablation/integrations/binja_plugin.py`**: module docstring claims auto-annotation on binary open; not implemented.

### Misleading docs (top 3 by analyst impact)

1. **`forge.md`** (lines 64, 110, 153): Claims SHA-256 cache keys. Code uses `blake2b(digest_size=8)`. Any agent reading forge.md constructs keys that will never hit — forces full re-audits every run.
2. **`DOC_CODE_MAP.md:245` / `S01.md:271`**: References `TaintTracker.trace()`. Method does not exist. Actual API: `trace_function()` (x86-64) / `run()` (ARM64, RISC-V). Raises `AttributeError` mid-workflow.
3. **`dynamic-sandbox.md` line 15**: States "behavioral strength 1.0". DynamicSandbox outputs 0.40–0.75. The 1.0 is the HypothesisEngine family weight, not the sandbox output. Conflating them miscalibrates finding confidence.

### Architecture coverage gaps

- **MIPS explicitly skipped** in `fortinet_sweep.py` Phase 2 — significant gap for older FortiGate hardware.
- **No SinkArgClassifierARM64** — ARM64 binaries silently fall through to the x86-64 handler, producing wrong results.
- **`pe_sweep.py`**: no taint analysis, no SinkArgClassifier — semantic similarity only.
- **`SinkSanitizerFilter`**: silently no-ops on non-x86-64 binaries; `fortinet_sweep.py` applies it to all arches.

---

## 5. Top 3 Discrepancies to Fix Before Next README Update

| # | File | Claim | Reality | Fix |
|---|------|-------|---------|-----|
| 1 | `forge.md` lines 64, 110, 153 | SHA-256 cache keys | `blake2b(digest_size=8)` | Replace all `sha256` refs with `blake2b(…, digest_size=8)` |
| 2 | `DOC_CODE_MAP.md:245`, `S01.md:271` | `TaintTracker.trace()` | `trace_function()` (x86-64) / `run()` (ARM64, RISC-V) | Update both files; document the inter-arch inconsistency |
| 3 | `corpus_builder.py` docstring + `semantic-search.md` | `all-mpnet-base-v2` (768-dim) | `BAAI/bge-small-en-v1.5` (384-dim) via fastembed; sweeps use `all-MiniLM-L6-v2` | Align all docs on the actual model per context |

---

*Full evidence: `DISCREPANCIES.md` (35 items), `DOC_CODE_MAP.md` (536 docs reconciled), `COVERAGE.md` (407 files mapped), `notes/taxonomy.md` (10 groups, 402 caps), `notes/UNMAPPED.md` (+6 files). Raw records: `capabilities.json`.*
