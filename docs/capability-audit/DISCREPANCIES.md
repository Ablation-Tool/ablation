# DISCREPANCIES.md — Ablation Capability Audit

Evidence-based discrepancy table comparing README/docs claims against code reality.
Compiled from direct code reads during Phase 1. Only confirmed discrepancies are listed;
"unverified" items are marked separately.

**Legend:** CRITICAL = likely to mislead LLM analyst via RAG | HIGH = significant
factual error | MEDIUM = minor or partially correct | LOW = cosmetic

---

## 1. Embedding model inconsistency — two models in production

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL (RAG-misleading) |
| **Claim location** | `ablation/analyzers/corpus_builder.py` docstring (module-level) |
| **Claim** | "Encodes functions with `sentence-transformers/all-mpnet-base-v2`" |
| **Code reality** | `SemanticSearcher` (used by corpus builder downstream) loads `BAAI/bge-small-en-v1.5` via `fastembed` + `WhiteningTransform`. The docstring names a different model entirely. |
| **Additional context** | `sweeps/base_sweep.py`, `sweeps/fortinet_sweep.py`, `sweeps/pe_sweep.py`, `sweeps/win16_sweep.py` use `SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")` — a third model not named in corpus_builder.py. Three distinct model names exist in the codebase: `all-mpnet-base-v2` (docs only), `all-MiniLM-L6-v2` (sweep code), `BAAI/bge-small-en-v1.5` (SemanticSearcher). |
| **Evidence** | `corpus_builder.py` line 1 docstring; `sweeps/base_sweep.py` SentenceTransformer import; `ablation/analyzers/semantic_searcher.py` fastembed import + WhiteningTransform |
| **Recommended fix** | corpus_builder.py docstring must be updated to name `BAAI/bge-small-en-v1.5` (fastembed). Reference docs for corpus_builder and SemanticSearcher must align on one model. |

---

## 2. FORTIOS_PROFILES count — docstring says 7, code has 8

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Claim location** | `sweeps/fortinet_sweep.py` — function/constant docstring |
| **Claim** | "7 FortiOS CVE-class profiles" |
| **Code reality** | FORTIOS_PROFILES list contains 8 entries: fortios_path_traversal, fortios_fgfm_heap, fortios_sslvpn_heap, fortios_httpsd_injection, fortios_saml_bypass, fortios_format_string_log, fortios_fwupdate_intovf, fortios_json_type_confusion |
| **Evidence** | `sweeps/fortinet_sweep.py` FORTIOS_PROFILES definition — counted by read |
| **Recommended fix** | Update docstring to say 8 FortiOS-specific profiles. |

---

## 3. Version number inconsistency — CLAUDE.md vs package

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Claim location** | `ablation/CLAUDE.md` line 6 |
| **Claim** | "Version: 2.57.0" |
| **Code reality** | Recent commits reference version 2.86.0 (from compaction session summary). These cannot both be current. |
| **Evidence** | CLAUDE.md "Version: 2.57.0"; session compaction summary context "version 2.86.0" |
| **Recommended fix** | CLAUDE.md version field must match `pyproject.toml`/`setup.py` version string. |

---

## 4. base_sweep.py prologue scanner — misses -fomit-frame-pointer

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Claim location** | `sweeps/base_sweep.py` prologue scan implementation |
| **Claim** | (implicit) — sweep finds function prologues |
| **Code reality** | Prologue scan looks for `push rbp; mov rbp,rsp` (bytes 0x55 0x48 0x89). This pattern is only present when compiled without `-fomit-frame-pointer`. Modern firmware is typically compiled with frame pointer omission. This is a significant false-negative source for function discovery on hardened firmware. |
| **Evidence** | `sweeps/base_sweep.py` prologue detection logic |
| **Recommended fix** | Document limitation in known-anomalies. Consider supplementing with eh_frame-based function discovery (which fortinet_sweep.py already does as fallback). |

---

## 5. MIPS explicitly skipped in fortinet_sweep

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Claim location** | `sweeps/fortinet_sweep.py` Phase 2 arch routing |
| **Claim** | (implicit) — fortinet_sweep supports FortiOS analysis |
| **Code reality** | MIPS is explicitly skipped with printed message "No taint tracker for arch ARCH.MIPS". Many FortiOS images (older FortiGate hardware) use MIPS. Phase 3 SinkArgClassifier and VendorProfile are also x86-64 only. |
| **Evidence** | `sweeps/fortinet_sweep.py` arch routing in Phase 2: `x86→TaintTracker, arm32→ARM32TaintTracker, arm64→ARM64TaintTracker, ppc→PPC32/64TaintTracker` — no MIPS branch |
| **Recommended fix** | Add explicit "MIPS not supported" note to fortinet_sweep docstring and README. |

---

## 6. ti_sweep C28x .text section harvest not implemented

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Claim location** | `sweeps/ti_sweep.py` Phase 4 description |
| **Claim** | C28x decoder phase processes TI C2000 binaries |
| **Code reality** | `EcuC28xDecoder` only harvests C_UEXT (weak/external) symbols. `.text` section instruction harvest is explicitly noted as "not implemented" in comments. |
| **Evidence** | `sweeps/ti_sweep.py` Phase 4 comment; `EcuC28xDecoder` limitation |
| **Recommended fix** | Document as partial implementation in C28x reference doc. |

---

## 7. corpus_miner.py — 17 of 35 CWEs have no scanner

| Field | Value |
|-------|-------|
| **Severity** | HIGH (coverage gap) |
| **Claim location** | `sweeps/corpus_miner.py` `_CWE_COVERAGE` dict |
| **Claim** | (implicit) — covers 35 CWEs |
| **Code reality** | 17 of 35 CWEs map to `None` (no scanner): CWE-416 (UAF), CWE-321 (hardcoded key), CWE-798 (hardcoded creds), CWE-295 (cert bypass), CWE-287 (auth bypass), CWE-319 (cleartext creds), CWE-328 (weak hash), CWE-347 (sig verify), CWE-610 (externally controlled ref), CWE-494 (code download no integrity), CWE-426 (untrusted search path), CWE-611 (XXE), CWE-918 (SSRF), CWE-200 (info disclosure), CWE-362 (race), CWE-476 (NULL deref), CWE-908 (uninitialized mem). These are tracked but have no scanner — gap CWEs. |
| **Evidence** | `sweeps/corpus_miner.py` `_CWE_COVERAGE` dictionary with None entries |
| **Recommended fix** | Mark gap CWEs in COVERAGE.md. Each `None` entry is a known capability gap. |

---

## 8. proto_fsm.py — hardcoded WeChat seeds, not general-purpose

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Claim location** | `modules/proto_fsm.py` module docstring |
| **Claim** | "Static MMTLS handshake FSM extractor" (implies general capability) |
| **Code reality** | Default seeds are hardcoded for libwechatnetwork.so WeChat 8.0.56 ARM64 (6 specific VAs: 0x111f98, 0x305020, etc.). BSS bounds fallback is also hardcoded to 0x3d0000+0x20000. INSERT_FN=0x2ec280, DELETE_FN=0x304d64 are WeChat-specific. No general seed discovery exists. |
| **Evidence** | `modules/proto_fsm.py` DEFAULT_SEEDS, INSERT_FN, DELETE_FN constants; _bss_bounds fallback |
| **Recommended fix** | Docstring should state "hardcoded for libwechatnetwork.so WeChat 8.0.56; use --seed for other targets". |

---

## 9. pe_sweep.py — no taint analysis, no SinkArgClassifier

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Claim location** | `sweeps/pe_sweep.py` code comments |
| **Claim** | (implicit from sweep framework) — pe_sweep provides vulnerability analysis |
| **Code reality** | pe_sweep.py explicitly has no taint analysis ("ELF-only") and no SinkArgClassifier ("ELF-only"). The PE sweep is limited to semantic similarity scoring only — no dataflow confirmation. `_check_firmware_auth_bypass()` checks for missing WinVerifyTrust (CWE-347) but is labeled GAP-015. |
| **Evidence** | `sweeps/pe_sweep.py` comments for taint and SinkArgClassifier phases |
| **Recommended fix** | README and pe_sweep docstring should state "semantic similarity only; no taint tracker for PE/x86-32". |

---

## D-26: `PlatformDetector` doc describes binary detection but code detects host machine

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Claim location** | `docs/reference-modules/binary-format-and-platform-identification.md` |
| **Claim** | Describes `PlatformDetector` as identifying binary artifacts (ELF arch, PE machine, Mach-O cputype) |
| **Code reality** | `ablation/core/platform_detect.py`: `PlatformDetector.detect()` reads `/etc/os-release`, `platform.machine()`, `uname` — it detects the **host** OS and CPU, not any input binary |
| **Evidence** | `ablation/core/platform_detect.py` read in C01; binary detection is handled by `binary_parser.py` + `elf_parser.py` / `pe_parser.py`, not `PlatformDetector` |
| **Recommended fix** | Rename to `HostPlatformDetector`; correct reference doc to describe host detection use case |

---

## D-27: `DisasmEngine.find_functions()` broken on Capstone 5.x+

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Claim location** | `ablation/core/disasm_engine.py` (documented as working) |
| **Claim** | `DisasmEngine.find_functions()` and `analyze_cfg()` methods identify functions and build CFGs |
| **Code reality** | Both methods use `capstone.CS_GRP_JUMP` / `CS_GRP_CALL` group membership checks removed from Capstone 5.x public API; calling these on Capstone 5.x raises `AttributeError` |
| **Evidence** | `ablation/core/disasm_engine.py` read in C01; COVERAGE.md test-coverage table shows 0% test coverage on `disasm_engine.py` |
| **Recommended fix** | Update to use `insn.group(CS_GRP_JUMP)` method call pattern valid in Capstone 5.x; add regression test |

---

## D-28: `PEAnalyzer._analyze_imports()` is a stub with `pass` body

| Field | Value |
|-------|-------|
| **Severity** | MED |
| **Claim location** | `ablation/core/pe_analyzer.py`; docs describe import analysis as working |
| **Claim** | PE import table analysis extracts DLL imports and flags suspicious IAT patterns |
| **Code reality** | `_analyze_imports()` body is `pass`; no import analysis is performed |
| **Evidence** | `ablation/core/pe_analyzer.py` read in C01 |
| **Recommended fix** | Implement or mark explicitly as not-yet-implemented in docstring |

---

## 10. README category count — "27 capability categories"

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Claim location** | `README.md` + `CAPABILITIES.md` |
| **Claim** | "27 capability categories" |
| **Code reality** | CAPABILITIES.md rows 23 and 24 are missing (noted in the task spec itself). The real number of meaningfully distinct categories from code analysis is approximately 8-12 when properly grouped (see Phase 4 taxonomy). Many of the 27 are redundant subcategories or aspirational. |
| **Evidence** | CAPABILITIES.md — verified missing rows 23-24; task spec confirming the gap |
| **Recommended fix** | Produce the corrected taxonomy in Phase 4 output. Update README to use verified count. |

---

## 11. README claim — "18+ taint tracker architectures"

| Field | Value |
|-------|-------|
| **Severity** | ACCURATE (UNDERSTATED) |
| **Claim location** | `README.md` capability docs / prior audit notes (not an explicit README count) |
| **Claim** | "18+ architectures" for taint tracking |
| **Code reality** | `ls ablation/analyzers/taint_tracker*.py` yields 24 files: base `taint_tracker.py` (x86-64), plus arc, arm32, arm64, i386, loongarch64, mips, mips64, nanomips, ppc32, ppc64, rh850, riscv, riscv32, riscv64, tricore, v850, x86, x86_32 (19 distinct ISA implementations) plus 5 labeled variants (arc_labeled, arm32_labeled, mips_labeled, ppc_labeled, x86_labeled). Total: 24 tracker files. 0 in modules/. "18+" is a floor — actual count is 19 basic ISA implementations, 24 files total. |
| **Evidence** | `ls ~/ablation/ablation/analyzers/taint_tracker*.py` — 24 files confirmed |
| **Status** | UNDERSTATED — "18+" is accurate as a minimum but the true count is 24 files / 19 distinct ISA implementations |
| **Recommended fix** | README-adjacent docs should say "24 taint tracker files across 19 architectures (plus 5 labeled-taint variants)". |

---

## 12. README claim — "31 decompilers, lifters, and ISAs"

| Field | Value |
|-------|-------|
| **Severity** | ROUGHLY ACCURATE (borderline) |
| **Claim location** | `README.md` section header — "31 Decompilers, Lifters & ISAs" |
| **Claim** | "31 Decompilers, Lifters & ISAs" |
| **Code reality** | Code file count: 10 `isa_*.py` + 10 `insn_*.py` + 10 `*_decoder.py` in analyzers/ + 5 `*_lifter.py` + 3 `*_decompiler.py` + 3 modules (isa_8051, mpy_lifter, obfuscated_string_decoder) = 41 ISA-related files. The README table counts ISA *variants* (not files): Native CPUs 19–20 variants, Automotive ECUs 7, VMs & Runtimes 3–4. Total ISA variant count from the table is 30–31 depending on whether "ARC EM/HS" and "Dalvik · ART" each count as 1 or 2. One isa_arc.py file covers both EM and HS. The 31 figure is achievable by counting ARC EM and ARC HS separately. Note: C166/C167 appears in ECU Decoders capability description but not in the ISA table count. |
| **Evidence** | README.md ISA table; `ls` of isa_*.py, insn_*.py, *_decoder.py, *_lifter.py, *_decompiler.py files |
| **Status** | ROUGHLY ACCURATE — count is 30–31 by variant counting; slightly inflated if single-file ISAs count as 1 |
| **Recommended fix** | No urgent fix. SUPPORT_MATRIX.md should list each ISA with file name and confirmed-working status. |

---

## 13. README claim — "25+ vulnerability scanners"

| Field | Value |
|-------|-------|
| **Severity** | UNDERSTATED |
| **Claim location** | `README.md` capability docs / prior audit notes (not stated as an explicit count in the README text itself) |
| **Claim** | "25+ vulnerability scanners" |
| **Code reality** | `ls ablation/analyzers/*_scanner.py` yields 33 files; `ls modules/*_scanner.py` yields 20 files = 53 scanner files total. Deducting function-discovery and utility scanners (arm32_function_scanner, static_elf32_func_start_scanner, flat_binary_func_start_scanner, go_x86_strip_scanner, i386_absolute_xref_scanner, nested_archive_scanner, ar_archive_scanner) still leaves 46 vulnerability-relevant scanner files. "25+" is significantly understated. |
| **Evidence** | `ls ~/ablation/ablation/analyzers/*_scanner.py | wc -l` → 33; `ls ~/ablation/modules/*_scanner.py | wc -l` → 20 |
| **Status** | UNDERSTATED — actual count is ~46 vulnerability-relevant scanners, not "25+" |
| **Recommended fix** | Update to "46+ vulnerability scanners" or enumerate by category. |

---

## 14. func_id_db.py ROLES — Cisco-specific taxonomy used as generic

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Claim location** | `ablation/analyzers/func_id_db.py` ROLES constant |
| **Claim** | ROLES set used in `match_by_role()` for all targets |
| **Code reality** | ROLES contains 18 entries that are Cisco-specific: AAA_DISPATCH, RADIUS_PARSER, etc. These roles will never match in non-Cisco firmware. `match_by_role()` will always return empty for non-Cisco targets unless custom roles are added via CorpusBuilder. |
| **Evidence** | `func_id_db.py` ROLES definition |
| **Recommended fix** | Document in FuncDB reference doc that built-in ROLES are Cisco-specific. |

---

## 15. AgentLoop (LLM Analyst) — hardcoded model name

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Claim location** | `ablation/analyzers/llm_analyst.py` or `agent_loop.py` (from context summary) |
| **Claim** | (implicit) — LLM analyst uses configurable model |
| **Code reality** | `claude-sonnet-5` is hardcoded as the model name in AgentLoop. Any reference doc describing the analyst as "model-agnostic" or "configurable" would be incorrect. |
| **Evidence** | Session summary: "AgentLoop: ReAct loop using Claude (claude-sonnet-5 hardcoded)" |
| **Recommended fix** | Note hardcoded model in llm_analyst reference doc and consider adding a config parameter. |

---

## 16. SinkArgClassifier.from_path() false negative

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL (misleads analyst) |
| **Claim location** | CLAUDE.md line 66 (already documented) |
| **Claim** | `SinkArgClassifier(from_path())` works for analysis |
| **Code reality** | `from_path()` returns ~22 func_starts on stripped binaries (confirmed in CLAUDE.md). Only `from_context(ctx)` should be used. If a reference doc shows `from_path()` as the constructor, the analyst will silently get grossly incomplete results. |
| **Evidence** | CLAUDE.md explicit warning; session context summary |
| **Recommended fix** | All SinkArgClassifier reference docs must show `from_context(ctx)` as the only valid constructor. from_path() should be deprecated or raise a warning for stripped binaries. |

---

## 17. CLAUDE.md version vs README version

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Claim location** | `CLAUDE.md` |
| **Claim** | "Version: 2.57.0" |
| **Code reality** | Git commit history and recent development places version at 2.86.0. CLAUDE.md has not been updated. |
| **Evidence** | CLAUDE.md line 6; session summary notes version 2.86.0 |
| **Recommended fix** | Update CLAUDE.md version field; automate from pyproject.toml. |

---

## 18. llm_behavior_security_probes.py placement

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (doc-RAG risk) |
| **Claim location** | `modules/llm_behavior_security_probes.py` docstring |
| **Claim** | "These are definitions only — not runtime probing tools. Designed for use with a deployed agent endpoint, not static analysis." |
| **Code reality** | The module is in `modules/` alongside scanner classes, which a RAG-retrieval system may present as a callable scanner. The docstring correctly warns against this, but placement in `modules/` is misleading. If a reference doc (if one exists) describes it as a "scanner", that would be incorrect. |
| **Evidence** | `modules/llm_behavior_security_probes.py` docstring; module location |
| **Recommended fix** | If a reference doc exists, it must prominently state "data definitions, not a scanner". Consider moving to a `resources/` or `data/` directory. |

---

## 19. Corpus builder CorpusBuilder stores truncated data

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Claim location** | `ablation/analyzers/corpus_builder.py` (implicit in docs) |
| **Claim** | (implicit) — corpus captures function context |
| **Code reality** | call_targets stored as `[:16]` (first 16 only) and string_xrefs stored as `[:12]` (first 12 content strings only). For functions with many callees or string references, only a partial picture is stored. SemanticSearcher query precision is capped by this truncation. |
| **Evidence** | `corpus_builder.py` — `.build()` method truncation slices |
| **Recommended fix** | Document truncation limits in corpus_builder reference doc. |

---

## Summary table

| # | Severity | Location | Claim | Reality |
|---|----------|----------|-------|---------|
| 1 | CRITICAL | corpus_builder.py docstring | all-mpnet-base-v2 | BAAI/bge-small-en-v1.5 (fastembed) |
| 2 | MEDIUM | fortinet_sweep.py docstring | 7 FortiOS profiles | 8 profiles |
| 3 | LOW | CLAUDE.md | Version 2.57.0 | 2.86.0 |
| 4 | HIGH | base_sweep.py prologue scan | finds prologues | misses -fomit-frame-pointer |
| 5 | HIGH | fortinet_sweep.py Phase 2 | FortiOS support | MIPS explicitly skipped |
| 6 | HIGH | ti_sweep.py Phase 4 | C28x decoder | .text harvest not implemented |
| 7 | HIGH | corpus_miner.py | 35 CWEs tracked | 17 have no scanner (None) |
| 8 | MEDIUM | proto_fsm.py docstring | general MMTLS extractor | hardcoded WeChat 8.0.56 seeds |
| 9 | HIGH | pe_sweep.py | vulnerability analysis | semantic similarity only; no taint |
| 10 | HIGH | README.md + CAPABILITIES.md | 27 categories | rows 23-24 missing; real ~8-12 |
| 11 | UNDERSTATED | README capability docs | 18+ taint architectures | 24 files / 19 ISA implementations — UNDERSTATED |
| 12 | ROUGHLY ACCURATE | README section header | 31 Decompilers/Lifters/ISAs | ~30–31 by variant count; 41 code files |
| 13 | UNDERSTATED | README capability docs | 25+ scanners | 53 scanner files; ~46 vuln-relevant — UNDERSTATED |
| 14 | MEDIUM | func_id_db.py ROLES | generic roles | Cisco-specific taxonomy |
| 15 | MEDIUM | agent_loop.py | configurable model | claude-sonnet-5 hardcoded |
| 16 | CRITICAL | SinkArgClassifier | from_path() usable | returns ~22 results on stripped |
| 17 | LOW | CLAUDE.md | Version 2.57.0 | 2.86.0 |
| 18 | MEDIUM | llm_behavior_security_probes | data definitions | placement in modules/ misleads RAG |
| 19 | MEDIUM | corpus_builder.py | full function context | call_targets[:16], xrefs[:12] |

| 20 | HIGH | yara-generator.md | YaraGenerator class | Module does not exist; import fails |
| 21 | HIGH | streaming-and-windowed-disassembly.md | streaming_enum.py (live network) | Actually documents WindowAnalyzer (binary disassembly) — wrong module |
| 22 | HIGH | semantic-search.md + corpus_builder.py docstring | all-mpnet-base-v2 (768-dim) | SemanticSearcher loads BAAI/bge-small-en-v1.5 (384-dim); sweeps use all-MiniLM-L6-v2; three model names in production, none match docs |
| 23 | HIGH | CLAUDE.md line 1 | Version 2.57.0 | Package is 2.86.0 — stale by 29 minor versions |
| 24 | MED | calling-convention-and-syscall-models.md | Assigned to A12/LLM analyst | Actually documents ARM32RegAnnotator (A14/function discovery) |

**CRITICAL items (2): #1, #16** — most likely to cause analyst to use wrong tool or get wrong results via RAG.
**HIGH items (11): #4, #5, #6, #7, #9, #20, #21, #22, #23, #31, #33** — significant capability gaps, broken modules, or false negatives.

---

## 20. ppc64-taint-analysis.md — labeled model claim is wrong

| Field | Value |
|-------|-------|
| **Severity** | HIGH (RAG-misleading) |
| **Claim location** | `docs/reference-modules/ppc64-taint-analysis.md` |
| **Claim** | "provides the same labeled-taint model as TaintTrackerARM64" |
| **Code reality** | `TaintTrackerPPC64` uses `Dict[str, bool]` boolean taint — `tainted=True/False` only. Labeled taint with `Taint(labels, bound)` is in the separate `taint_tracker_ppc_labeled.py` class. |
| **Recommended fix** | Rewrite `ppc64-taint-analysis.md` to accurately describe boolean Dict[str,bool] taint. |

---

## 21. ppc32-taint-tracker.md — register attribution wrong

| Field | Value |
|-------|-------|
| **Severity** | HIGH (RAG-misleading) |
| **Claim location** | `docs/reference-modules/ppc32-taint-tracker.md` |
| **Claim** | "tracker taints r3 from the return value, not the buffer contents" |
| **Code reality** | Code taints the buffer argument register (r4 for recv/read; r3 for fgets). The byte count is also tainted in some cases, but the primary taint seed is the buffer register, not the return value. |
| **Recommended fix** | Correct the register description. |

---

## 22. insn-models.md — field names wrong, frozen=True wrong

| Field | Value |
|-------|-------|
| **Severity** | HIGH (RAG-misleading) |
| **Claim location** | `docs/reference-modules/insn-models.md` |
| **Claim** | `Insn` is frozen and has fields named `operands` and `va` |
| **Code reality** | The `Insn` class is NOT frozen; fields are named `ops` (not `operands`) and `address` (not `va`). Any agent passing `insn.va` or `insn.operands` will get `AttributeError`. |
| **Recommended fix** | Fix `insn-models.md`: field names `ops`/`address`, frozen=False. |

---

## 23. CLAUDE.md VersionTracker.find_homolog() — method does not exist

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Claim location** | `CLAUDE.md` (cross-version patch analysis section) |
| **Claim** | "`VersionTracker.find_homolog()`: where did it move?" |
| **Code reality** | The method is on `FuncMatcher`, not `VersionTracker`. `VersionTracker.track()` calls `FuncMatcher.find_homolog()` internally. Calling `VersionTracker.find_homolog()` raises `AttributeError`. |
| **Recommended fix** | Fix CLAUDE.md: replace `VersionTracker.find_homolog()` with `VersionTracker.track()`. |

---

## 24. isa-models.md — only lists 4 of 10 ISA models

| Field | Value |
|-------|-------|
| **Severity** | HIGH (RAG-misleading) |
| **Claim location** | `docs/reference-modules/isa-models.md` |
| **Claim** | Lists arc, arm32, arm64, ppc explicitly |
| **Code reality** | 10 ISA models exist: arc, arm32, arm64, loongarch64, m88k, mips, ppc, riscv, v850, x86. Missing from doc: loongarch64, m88k, mips, riscv, v850, x86. |
| **Recommended fix** | Expand `isa-models.md` to list all 10 ISA models. |

---

## 25. live-virtual-dispatch-slots.md — wrong content

| Field | Value |
|-------|-------|
| **Severity** | HIGH (completely wrong content) |
| **Claim location** | `docs/reference-modules/live-virtual-dispatch-slots.md` |
| **Claim** | Should document `VtableDispatchScanner` live dispatch slot analysis |
| **Code reality** | File actually contains Android Binder IPC scanner (BinderScanner / APK DEX analysis) documentation. Completely wrong content. |
| **Recommended fix** | Replace content with VtableDispatchScanner documentation, or rename file. |

---

## 26. SinkArgClassifier.from_context() — no ARM64 dispatch

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Claim location** | `ablation/analyzers/sink_arg_classifier.py` dispatch table |
| **Claim** | (implicit) — from_context() supports all major ISAs |
| **Code reality** | No `SinkArgClassifierARM64` exists. ARM64 binaries silently fall through to the x86-64 handler, which will produce wrong results. ARM64 is one of the primary FortiOS architectures. |
| **Recommended fix** | Implement SinkArgClassifierARM64 or add explicit ARM64 guard with NotImplementedError. |

---

## 27. SinkSanitizerFilter and SanitizerDetector — x86-64 only, no guard

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Claim location** | `sweeps/fortinet_sweep.py` Phase 3 sanitizer step |
| **Claim** | (implicit) — sanitizer validation applied to all arch findings |
| **Code reality** | These classes exist but silently do nothing on non-x86-64 binaries. fortinet_sweep.py applies them to all arches — sanitizer validation is silently skipped for ARM32/ARM64/PPC findings. |

---

## 28. taint_tracker_v850.py uses labeled model, not Dict[str, bool]

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Claim location** | (implicit in V850/RH850 docs) |
| **Code reality** | V850 and RH850 use the `Taint(labels, bound)` labeled model (same as ARM64). PPC32/PPC64/MIPS32 use boolean `Dict[str, bool]`. Reference docs do not make this distinction explicit. Callers assuming uniform taint type will get runtime errors. |

---

## 29. Duplicate EcuArchDetector docs

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Files** | `docs/reference-modules/ecu-arch-detector.md` AND `docs/reference-modules/ecu-architecture-detector.md` |
| **Code reality** | Two separate docs for `EcuArchDetector` with different scope and content. RAG retrieval gets one or the other; they may contradict each other. |

---

## 30. wcode-parser.md — partial wrong content

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Claim location** | `docs/reference-modules/wcode-parser.md` |
| **Code reality** | "How it works" paragraph describes firmware partition extraction, not W-Code IR. Rest of doc appears correct. |

---

## 31. forge.md claims SHA-256 cache keys; code uses BLAKE2b

| Field | Value |
|-------|-------|
| **Severity** | HIGH (analyst will construct wrong cache keys; invalidation logic will fail) |
| **Claim location** | `docs/reference-modules/forge.md` lines 64, 110, 153 |
| **Claim** | `sha256(system_prompt)[:16] + ":" + sha256(file_bytes)[:16]` — cache key uses SHA-256 |
| **Code reality** | `ablation/analyzers/forge.py` lines 121, 142–143: `hashlib.blake2b(system.encode(), digest_size=8).hexdigest()` and `hashlib.blake2b(Path(file_path).read_bytes(), digest_size=8).hexdigest()`. The algorithm is BLAKE2b with `digest_size=8` (16 hex chars), not SHA-256. The cache key format is also different: the code says `blake2b(system_prompt, digest_size=8) + ":" + blake2b(file_bytes, digest_size=8)` |
| **Evidence** | `forge.py` lines 121, 142–143; `forge.md` lines 64, 110, 153 |
| **Status** | STALE — doc was written before BLAKE2b was adopted; any agent reading the doc will construct an incompatible cache key |
| **Recommended fix** | Replace all `sha256` references in `forge.md` with `blake2b(…, digest_size=8)`. |

---

## 32. dynamic-sandbox.md says "behavioral strength 1.0" but DynamicSandbox outputs 0.40–0.75

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (misleads RAG about what confidence value to expect from DynamicSandbox) |
| **Claim location** | `docs/reference-modules/dynamic-sandbox.md` line 15 |
| **Claim** | "behavioral strength 1.0" — presented in the context of what DynamicSandbox provides |
| **Code reality** | `ablation/analyzers/dynamic_sandbox.py` lines 567, 569: `strength = 0.40` (PLT calls interrupted) and `strength = 0.75` (consistent behavior observed). The `dynamic-sandbox.md` table at lines 110–116 correctly shows 0.40/0.60/0.75. The "1.0" at line 15 is the Hypothesis Engine's *family weight* for behavioral evidence — not the DynamicSandbox output strength. The doc does not make this distinction explicit, so an RAG-retrieval agent will expect strength=1.0 from DynamicSandbox and will be confused when it sees 0.40–0.75. |
| **Evidence** | `dynamic_sandbox.py` lines 567/569; `dynamic-sandbox.md` line 15 vs lines 110–116 |
| **Status** | MISLEADING — "1.0" and "0.40–0.75" refer to different quantities; the doc conflates them |
| **Recommended fix** | Change line 15 to "Before DynamicSandbox, the highest-strength *data_flow* evidence was 0.9 (Hypothesis Engine family weight). DynamicSandbox provides behavioral evidence at 0.40–0.75 depending on execution depth (see table below)." |

---

## 33. TaintTracker API inconsistency: DOC_CODE_MAP uses .trace(); code uses .trace_function() or .run()

| Field | Value |
|-------|-------|
| **Severity** | HIGH (AttributeError in agent workflows) |
| **Claim location** | `docs/capability-audit/DOC_CODE_MAP.md` line 245; `docs/capability-audit/notes/S01.md` line 271 |
| **Claim** | `TaintTracker.trace(func_va, source_va, source_reg, sink_patterns)` |
| **Code reality** | `ablation/analyzers/taint_tracker.py` line 127: the method is `trace_function()`. ARM64/RISC-V trackers (taint_tracker_arm64.py:253, 1011) use `run()`. No TaintTracker class has a `.trace()` method. Calling `.trace()` raises `AttributeError`. Reference docs in `docs/reference-modules/` correctly use `trace_function()`. The discrepancy is confined to the capability-audit notes and S01 workflow doc. |
| **Evidence** | `ablation/analyzers/taint_tracker.py:127` (`def trace_function`); `taint_tracker_arm64.py:253,1011` (`def run`); `DOC_CODE_MAP.md:245` (`.trace()`) |
| **Status** | STALE in DOC_CODE_MAP.md and S01.md — reference docs are correct |
| **Recommended fix** | Update DOC_CODE_MAP.md line 245 and S01.md line 271: `trace_function(func_va, ...)` (x86-64) or `run()` (ARM64, RISC-V). Document the inconsistency between architectures. |

---

## 34. Package version split: __init__.py 2.86.0 vs pyproject.toml 2.81.0

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Claim location** | `ablation/__init__.py` and `pyproject.toml` |
| **Claim** | Both files should agree on the package version |
| **Code reality** | `ablation/__init__.py`: `__version__ = "2.86.0"`. `pyproject.toml`: `version = "2.81.0"`. Five minor versions apart. `pip show ablation-tool` will report 2.81.0 from pyproject.toml; `import ablation; ablation.__version__` returns "2.86.0". CLAUDE.md reports 2.57.0 (a third value — already tracked in items 3/17/23). |
| **Evidence** | `grep version ~/ablation/ablation/__init__.py` → 2.86.0; `grep version ~/ablation/pyproject.toml` → 2.81.0 |
| **Status** | STALE — pyproject.toml not updated with each version bump |
| **Recommended fix** | Sync pyproject.toml to 2.86.0; automate version bumps via a single source of truth (e.g., `hatch version`). |

---

## 35. tls_analyzer.py is a live-host network prober, not a binary analyzer

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (placement in binary-analysis section misleads users) |
| **Claim location** | `README.md` Cryptography section; `docs/reference-modules/tls-certificate-and-protocol-probing.md` |
| **Claim** | Listed alongside binary analyzers in the README capability table; README description says "Inspect certificates/DH parameters, verify HSTS/mTLS/CT policy posture" |
| **Code reality** | `ablation/core/tls_analyzer.py` opens TCP sockets and performs live TLS handshakes (`import socket, ssl, urllib.request`). It requires a running service on the network. It cannot analyze firmware binaries or PE/ELF files. There is no static analysis of TLS code in binaries — this module only works against live hosts. |
| **Evidence** | `tls_analyzer.py` lines 1–80: `import socket`, `import ssl`, `import urllib.request`; live connection logic |
| **Status** | ACCURATE in README labeling ("probing") but placement in a section that is otherwise static-analysis tools will mislead users expecting binary analysis |
| **Recommended fix** | Add explicit "live host only — requires running service" note in the README capability row and in the reference doc. |

---

## Phase 6 Verification Summary (added by direct code audit)

| # | Severity | Location | Claim | Code Reality | Status |
|---|----------|----------|-------|--------------|--------|
| 11 | UNDERSTATED | README capability docs | 18+ taint architectures | 24 tracker files, 19 distinct ISA implementations | UNDERSTATED |
| 12 | ROUGHLY ACCURATE | README section header | 31 Decompilers/Lifters/ISAs | ~30–31 ISA variants in table; 41 ISA-related files in code | ROUGHLY ACCURATE |
| 13 | UNDERSTATED | README capability docs | 25+ vulnerability scanners | 53 *_scanner.py files total; ~46 vulnerability-relevant | UNDERSTATED |
| 31 | HIGH | forge.md | SHA-256 cache keys | forge.py uses BLAKE2b digest_size=8 | STALE |
| 32 | MEDIUM | dynamic-sandbox.md line 15 | behavioral strength 1.0 | DynamicSandbox outputs 0.40–0.75; 1.0 is Hypothesis Engine family weight | MISLEADING |
| 33 | HIGH | DOC_CODE_MAP.md + S01.md | TaintTracker.trace() | actual methods: trace_function() (x86-64) and run() (ARM64/RISC-V) | STALE |
| 34 | LOW | __init__.py vs pyproject.toml | version consistency | __init__.py=2.86.0, pyproject.toml=2.81.0 | STALE |
| 35 | MEDIUM | README Cryptography section | tls_analyzer.py capability | live network probe only; no binary analysis | ACCURATE label, misleading placement |

**Top 3 most important to fix (by analyst-impact):**
1. **Item 31 (FORGE SHA-256 vs BLAKE2b)** — any agent reading forge.md will construct cache keys that will never hit; effectively disabling the FORGE cache and forcing full re-audits every time.
2. **Item 33 (TaintTracker.trace())** — agent workflows in S01 that call `.trace()` raise AttributeError and silently fail. HIGH severity because taint analysis is the core confirmation step.
3. **Item 32 (DynamicSandbox evidence strength)** — an analyst instructed to "use behavioral evidence (strength 1.0)" will be confused when DynamicSandbox returns 0.40; they may misclassify findings or incorrectly accept lower-confidence results.

---

## 36. isa-8051.md says "planned module, not yet implemented" — module is fully implemented

| Field | Value |
|-------|-------|
| **Severity** | HIGH (capability invisible to LLM analyst) |
| **Claim location** | `docs/reference-modules/isa-8051.md` |
| **Claim** | Module is planned/not yet implemented |
| **Code reality** | `modules/isa_8051.py` is fully implemented with `Mcs51Decoder`, `IntelHexLoader`, and `Cc254xBankResolver`. The capability exists and works but is never invoked by the LLM analyst because the reference doc says it doesn't exist. |
| **Evidence** | `modules/isa_8051.py` — class definitions confirmed by A07.md and M04.md unit notes |
| **Recommended fix** | Rewrite `isa-8051.md` as a proper capability doc: constructor, key methods, scope, example usage. Remove the "planned" language entirely. |

---

## 37. analysis-engine.md claims 3 architecture analysis engines; 9 are implemented

| Field | Value |
|-------|-------|
| **Severity** | HIGH (6 architectures invisible to LLM analyst) |
| **Claim location** | `docs/reference-modules/analysis-engine.md` |
| **Claim** | 3 architecture analysis engines exist |
| **Code reality** | 9 analysis engines implemented: x86-64, x86-32, arm32, arm64, loongarch64, mips, riscv, v850, plus a generic fallback. The 6 omitted architectures (arm32, arm64, loongarch64, mips, riscv, v850) are never used by the LLM analyst for CFG/analysis tasks because the doc implies they don't exist. |
| **Evidence** | A02.md unit notes; `ablation/analyzers/cfg_*.py` directory listing |
| **Recommended fix** | Update `analysis-engine.md` to document all 9 ISA-specific analysis engines with their constructor patterns and dispatch logic. |
