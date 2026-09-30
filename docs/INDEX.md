# Ablation Document Library

Semantic firmware analysis for vulnerability researchers.

---

## Getting Started

| Document | Description |
|---|---|
| [Getting Started](getting-started.md) | Install, first binary, first sweep -- 15 minutes |

---

## Workflows

Step-by-step guides for common research tasks.

| Document | Description |
|---|---|
| [Vulnerability Hunting](workflows/vuln-hunting.md) | Full loop: sweep to confirmed finding to disclosure |
| [Cross-Version Diffing](workflows/cross-version.md) | Track a function across firmware patch releases |
| [Go Binary RE](workflows/go-binaries.md) | Stripped Go binaries: pclntab recovery, garbled builds |
| [Crypto Analysis](workflows/crypto.md) | Encrypted firmware, XOR key recovery, JWT cracking |
| [Source Code Audit](workflows/source-code-audit.md) | Compress a repo → rank files → confirm findings; full worked example |

---

## Source Code Audit

Audit any large codebase for security vulnerabilities, faster than reading it linearly and without missing coverage.

| Document | Covers |
|---|---|
| [Source Analyzers](module-reference/source-audit.md) | SourceContext, SourceAuditCompressor, SourceEntryClassifier, SourceSinkScanner, SourceIsolationChecker, SourceTaintTracker |
| [Source Code Audit Workflow](workflows/source-code-audit.md) | Clone → compress → priority reads → batch close → log findings |

---

## Module Reference

| Document | Covers |
|---|---|
| [Core Analyzers](module-reference/core.md) | BinaryContext, XRefGraph, CFGBuilder, TaintTracker, ARM64TaintTracker, PathSolver, CrossBinaryTaintTracker |
| [Semantic Search](module-reference/semantic-search.md) | SemanticSearcher, CorpusBuilder, PatternLibrary |
| [Vulnerability Scanners](module-reference/vuln-scanners.md) | FormatStringScanner, HeapVulnScanner (INT_OVERFLOW, UAF, double-free, off-by-one), SqlSinkScanner (mysql_query/sqlite3 injection) |
| [Windows Kernel Drivers](module-reference/kernel-drivers.md) | KernelDriverAnalyzer, ByovdDetector: IOCTL surface, 8 capability classes |
| [Erlang / BEAM](module-reference/beam.md) | BeamContext: exports, imports, atoms, literals, dangerous import sweep |
| [Signature Matching](module-reference/sig-library.md) | SigLibrary, auto-naming fn_0x* functions |
| [Export Formats](module-reference/export.md) | SARIF 2.1.0, JSON, GitHub Code Scanning |
| [Registry](module-reference/registry.md) | NameRegistry, FindingRegistry, `export_patterns()`, `ingest_from_registry()` flywheel |
| [Crypto](module-reference/crypto.md) | CryptoAudit, XorSolver, EntropyMapper |
| [Structural](module-reference/structural.md) | VtableResolver (ARM64), VersionDelta, StructuralSim, ZIM-BERT fine-tuning |
| [x86-64 Vtable Analysis](module-reference/vtable-x86-64.md) | ELFVtableReconstructor (.rela.dyn slot reconstruction), VtableDispatchScanner (dead/live method detection) |
| [Firmware Containers](module-reference/firmware-containers.md) | FirmwareContainer (partitioned image parser + payload detection), VideoContainerAnalyzer (MP4/MKV/AVI forensics) |
| [Android / APK](module-reference/android.md) | APKParser (AXML+DEX), DexAnalyzer, JniBridgeScanner (JNI_OnLoad/Java_*/opaque peer), BinderScanner (exported services, AIDL Stubs, onTransact) |
| [LLM Analyst](module-reference/llm.md) | LlmAnalyst ReAct agent loop |

---

## Integrations

| Document | |
|---|---|
| [Claude Code](integrations/claude-code.md) | Using Ablation inside a Claude Code session |
| [Binary Ninja](integrations/binja.md) | Plugin installation and commands |

---

## Release Notes

See [CHANGELOG.md](../CHANGELOG.md) for full version history.

| Version | Summary |
|---|---|
| v2.14.5 | ZIM-BERT wired into `VersionTracker`: `with_zimbert()` classmethod, `model=` pass-through to `FuncMatcher` |
| v2.14.4 | ZIM-BERT integration in `FuncMatcher`: `with_zimbert()` classmethod, `model` override, `_get_encoder()` helper |
| v2.14.3 | `BinaryContext` kernel-space VA fix: `_va_to_i64()` / `_va_arr_to_i64()` ctypes bit-cast helpers; 6 call sites fixed |
| v2.14.1–2 | FindingRegistry/PatternLibrary flywheel hardening: 13 bugs fixed (thread safety, lock upgrade, tag filter, double-save, Unicode edge cases) |
| v2.13.0 | ZIM-BERT distillation: teacher-student fine-tuning for cross-version binary similarity |
| v2.12.0 | ELFVtableReconstructor (.rela.dyn slot reconstruction), VtableDispatchScanner (dead/live virtual method detection) |
| v2.11.0 | BmpKeyExtractor: BMP LSB steganography, Lagrange secret sharing key recovery |
| v2.10.0 | DEXLifter: pseudo-Java IR lifter with type inference, field dot-notation, invoke formatting, if/else labels |
| v2.9.0 | DEXDisasm: all 17 DEX instruction formats, smali output, full reference annotation from DEX flat tables |
| v2.8.0 | SqlSinkScanner: MySQL C API / SQLite3 SQL injection detection in ELF binaries |
| v2.7.0 | APKParser (AXML+DEX+ACC_NATIVE), JniBridgeScanner (JNI_OnLoad/Java_*/opaque peer), BinderScanner (exported services, AIDL Stubs, onTransact), android_sweep.py |
| v2.6.0 | FirmwareContainer partitioned image parser, VideoContainerAnalyzer MP4/MKV/AVI forensics |
| v2.5.0 | FormatStringScanner fortify variants, IoctlAttackSurfaceGenerator, CrossBinaryTaintTracker, BYOVDDetector PDB fingerprints |
| v2.4.0 | MIPS32TaintTracker, HeapVulnScanner (INT_OVERFLOW/UAF/double-free/off-by-one) |
| v2.3.0 | BYOVDDetector 8-path scoring, SSDT/CR0/CR4/token-steal/APC primitives |
| v2.0.0 | KernelDriverAnalyzer: IRP/IOCTL dispatch, 40+ API risk classes, SMEP/CR0 scan |
| v1.8.0 | NameRegistry overlay, FindingRegistry, PatternLibrary self-improvement loop |
| v1.7.0 | LlmAnalyst ReAct agent, TaintTracker x86-64, PathSolver |
| v1.6.0 | VtableResolver ARM64, VersionDelta CFG shape diffing |
| v1.5.0 | BERT semantic search (SemanticSearcher), CorpusBuilder |
| v1.4.0 | XRefGraph, vectorized RIP-relative xref index in BinaryContext |
| v1.3.0 | Installable package (ablation.analyzers.*), BinaryContext SHA256 cache |
